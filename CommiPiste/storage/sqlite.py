"""SQLite-backed signature storage (aiosqlite).

Schema realises `hash -> paths -> commits` with two levels of deduplication:

  - ref membership: instead of one row per (ref, path, blob), there is one `observations` row per
    (path, blob) carrying the *set* of refs in which that file-version appears, varint-delta encoded.
    An unchanged file across N releases is one row with N refs, not N rows.
  - blob identity: the git blob OID is stored inline in `observations` as a short prefix (the first
    `_OID_PREFIX` bytes) in a WITHOUT ROWID table, rather than via a separate `blobs` table + its
    unique index (which stored every OID twice). The prefix is scoped to a single (project, path) —
    where only a handful of distinct blobs ever occur — so a 12-byte (96-bit) prefix is collision-free
    in practice (verified: 0 collisions across the whole corpus). We never need the full OID back from
    the DB (the target supplies it at scan time), so truncation is lossless for matching.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

import aiosqlite

from ..models import Ref
from .base import ProjectMeta

_SCHEMA = """
CREATE TABLE IF NOT EXISTS projects (
    id                    INTEGER PRIMARY KEY,
    name                  TEXT NOT NULL UNIQUE,
    repo_url              TEXT NOT NULL,
    github_commit_url_tpl TEXT NOT NULL,
    kind                  TEXT NOT NULL DEFAULT 'core',
    parent                TEXT
);

CREATE TABLE IF NOT EXISTS refs (
    id             INTEGER PRIMARY KEY,
    project_id     INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    sha            TEXT NOT NULL,
    tag            TEXT,
    committed_date TEXT,
    is_release     INTEGER NOT NULL DEFAULT 0,
    UNIQUE(project_id, sha)
);

CREATE TABLE IF NOT EXISTS paths (
    id         INTEGER PRIMARY KEY,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    rel_path   TEXT NOT NULL,
    UNIQUE(project_id, rel_path)
);

-- One row per (path, blob): the set of refs sharing that exact file content. The git blob
-- OID is stored inline as its first _OID_PREFIX bytes (`oidp`); WITHOUT ROWID keeps the row data in
-- the PK b-tree (no duplicate rowid table + index, no separate blobs table/index).
CREATE TABLE IF NOT EXISTS observations (
    project_id INTEGER NOT NULL,
    path_id    INTEGER NOT NULL REFERENCES paths(id) ON DELETE CASCADE,
    oidp       BLOB NOT NULL,         -- first _OID_PREFIX bytes of the git blob OID
    refs       BLOB NOT NULL,         -- varint-delta-encoded sorted ref ids
    PRIMARY KEY (project_id, path_id, oidp)
) WITHOUT ROWID;
-- No separate (project_id, path_id) index: the PK above is a left-prefix index, so it already
-- serves every (project_id) and (project_id, path_id) lookup (incl. as a covering index for the
-- discriminator GROUP BY).

CREATE TABLE IF NOT EXISTS discriminators (
    project_id INTEGER NOT NULL,
    path_id    INTEGER NOT NULL,
    score      REAL NOT NULL,
    PRIMARY KEY (project_id, path_id)
);
"""


# --------------------------------------------------------------------------- #
# ref-set codec: sorted ref ids -> varint deltas (small, since a file's refs   #
# are usually a contiguous run of releases)                                    #
# --------------------------------------------------------------------------- #


def encode_refs(ref_ids: Iterable[int]) -> bytes:
    out = bytearray()
    prev = 0
    for r in sorted(set(ref_ids)):
        delta = r - prev
        prev = r
        while True:
            b = delta & 0x7F
            delta >>= 7
            if delta:
                out.append(b | 0x80)
            else:
                out.append(b)
                break
    return bytes(out)


def decode_refs(buf: bytes) -> set[int]:
    out: set[int] = set()
    val = 0
    cur = 0
    shift = 0
    for byte in buf:
        cur |= (byte & 0x7F) << shift
        if byte & 0x80:
            shift += 7
        else:
            val += cur
            out.add(val)
            cur = 0
            shift = 0
    return out


# Bytes of the git blob OID stored inline per (project, path). 12 bytes = 96 bits, scoped to a
# single path (a handful of distinct blobs), so collisions are astronomically unlikely.
_OID_PREFIX = 12


def _oid_prefix(oid_hex: str) -> bytes:
    return bytes.fromhex(oid_hex)[:_OID_PREFIX]


class SqliteStorage:
    """Concrete :class:`CommiPiste.storage.base.Storage` backed by SQLite."""

    def __init__(self, db_path: Path | str) -> None:
        self._db_path = str(db_path)
        self._conn: Optional[aiosqlite.Connection] = None

    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("storage not initialised; call init() first")
        return self._conn

    async def init(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self._db_path)
        await self._conn.execute("PRAGMA foreign_keys = ON")
        await self._conn.execute("PRAGMA journal_mode = WAL")
        await self._migrate_blobs_inline()
        await self._conn.executescript(_SCHEMA)
        await self._conn.commit()

    async def _migrate_blobs_inline(self) -> None:
        """One-off: fold the legacy `blobs` table into an inline OID prefix on `observations`.

        Old schema kept observations.blob_id -> blobs(id, oid UNIQUE), storing every OID twice
        (table + unique index). Rewrites in place (no re-clone needed) to the WITHOUT ROWID schema.
        """
        row = await self._fetchone(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='blobs'"
        )
        if row is None:
            return  # already migrated / fresh DB
        await self._conn.execute("PRAGMA foreign_keys = OFF")
        await self._conn.executescript(
            f"""
            CREATE TABLE observations_new (
                project_id INTEGER NOT NULL,
                path_id    INTEGER NOT NULL,
                oidp       BLOB NOT NULL,
                refs       BLOB NOT NULL,
                PRIMARY KEY (project_id, path_id, oidp)
            ) WITHOUT ROWID;
            INSERT INTO observations_new (project_id, path_id, oidp, refs)
                SELECT o.project_id, o.path_id, substr(b.oid, 1, {_OID_PREFIX}), o.refs
                FROM observations o JOIN blobs b ON b.id = o.blob_id;
            DROP TABLE observations;
            DROP TABLE blobs;
            ALTER TABLE observations_new RENAME TO observations;
            """
        )
        await self._conn.commit()
        await self._conn.execute("VACUUM")
        await self._conn.commit()
        await self._conn.execute("PRAGMA foreign_keys = ON")

    async def close(self) -> None:
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    # -- projects ----------------------------------------------------------- #

    async def upsert_project(
        self,
        name: str,
        repo_url: str,
        github_commit_url_tpl: str,
        kind: str = "core",
        parent: Optional[str] = None,
    ) -> int:
        await self.conn.execute(
            """
            INSERT INTO projects (name, repo_url, github_commit_url_tpl, kind, parent)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                repo_url = excluded.repo_url,
                github_commit_url_tpl = excluded.github_commit_url_tpl,
                kind = excluded.kind,
                parent = excluded.parent
            """,
            (name, repo_url, github_commit_url_tpl, kind, parent),
        )
        await self.conn.commit()
        row = await self._fetchone("SELECT id FROM projects WHERE name = ?", (name,))
        return int(row[0])

    async def get_project(self, name: str) -> Optional[ProjectMeta]:
        row = await self._fetchone(
            "SELECT id, name, repo_url, github_commit_url_tpl, kind, parent "
            "FROM projects WHERE name = ?",
            (name,),
        )
        return self._project_meta(row) if row else None

    async def list_projects(self) -> list[ProjectMeta]:
        async with self.conn.execute(
            "SELECT id, name, repo_url, github_commit_url_tpl, kind, parent FROM projects "
            "ORDER BY name"
        ) as cur:
            return [self._project_meta(r) async for r in cur]

    async def project_stats(self, project_id: int) -> dict[str, int]:
        return {
            "refs": await self._scalar(
                "SELECT COUNT(*) FROM refs WHERE project_id = ?", (project_id,)
            ),
            "paths": await self._scalar(
                "SELECT COUNT(*) FROM paths WHERE project_id = ?", (project_id,)
            ),
            "signatures": await self._scalar(
                "SELECT COUNT(*) FROM observations WHERE project_id = ?", (project_id,)
            ),
            "blobs": await self._scalar(
                "SELECT COUNT(DISTINCT oidp) FROM observations WHERE project_id = ?",
                (project_id,),
            ),
        }

    # -- indexing ----------------------------------------------------------- #

    async def ref_exists(self, project_id: int, sha: str) -> bool:
        row = await self._fetchone(
            "SELECT 1 FROM refs WHERE project_id = ? AND sha = ?", (project_id, sha)
        )
        return row is not None

    async def add_ref(
        self,
        project_id: int,
        sha: str,
        tag: Optional[str],
        committed_date: Optional[str],
        is_release: bool,
    ) -> int:
        await self.conn.execute(
            """
            INSERT INTO refs (project_id, sha, tag, committed_date, is_release)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(project_id, sha) DO UPDATE SET
                tag = COALESCE(excluded.tag, refs.tag),
                committed_date = COALESCE(excluded.committed_date, refs.committed_date),
                is_release = excluded.is_release
            """,
            (project_id, sha, tag, committed_date, int(is_release)),
        )
        await self.conn.commit()
        row = await self._fetchone(
            "SELECT id FROM refs WHERE project_id = ? AND sha = ?", (project_id, sha)
        )
        return int(row[0])

    async def record_signatures(
        self,
        project_id: int,
        items: Iterable[tuple[str, str, list[int]]],
    ) -> None:
        """Bulk-write collapsed signatures: (rel_path, oid_hex, ref_ids) -> one observation row."""
        items = list(items)
        if not items:
            return
        rel_paths = {p for p, _, _ in items}

        await self.conn.executemany(
            "INSERT OR IGNORE INTO paths (project_id, rel_path) VALUES (?, ?)",
            [(project_id, p) for p in rel_paths],
        )
        path_ids = await self._id_map(
            "SELECT rel_path, id FROM paths WHERE project_id = ?", (project_id,), rel_paths
        )

        await self.conn.executemany(
            """
            INSERT INTO observations (project_id, path_id, oidp, refs)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(project_id, path_id, oidp) DO UPDATE SET refs = excluded.refs
            """,
            [
                (project_id, path_ids[p], _oid_prefix(o), encode_refs(refs))
                for p, o, refs in items
            ],
        )
        await self.conn.commit()

    async def append_ref_files(
        self,
        project_id: int,
        ref_id: int,
        files: Iterable[tuple[str, str]],
    ) -> None:
        """Add one ref's (rel_path, oid) files to the collapsed store (incremental updates)."""
        files = list(files)
        if not files:
            return
        rel_paths = {p for p, _ in files}
        await self.conn.executemany(
            "INSERT OR IGNORE INTO paths (project_id, rel_path) VALUES (?, ?)",
            [(project_id, p) for p in rel_paths],
        )
        path_ids = await self._id_map(
            "SELECT rel_path, id FROM paths WHERE project_id = ?", (project_id,), rel_paths
        )

        for rel_path, oid in files:
            pid, oidp = path_ids[rel_path], _oid_prefix(oid)
            row = await self._fetchone(
                "SELECT refs FROM observations WHERE project_id=? AND path_id=? AND oidp=?",
                (project_id, pid, oidp),
            )
            refs = decode_refs(row[0]) if row else set()
            refs.add(ref_id)
            await self.conn.execute(
                """
                INSERT INTO observations (project_id, path_id, oidp, refs)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(project_id, path_id, oidp) DO UPDATE SET refs = excluded.refs
                """,
                (project_id, pid, oidp, encode_refs(refs)),
            )
        await self.conn.commit()

    # -- matching ----------------------------------------------------------- #

    async def indexed_paths(self, project_id: int) -> set[str]:
        async with self.conn.execute(
            "SELECT rel_path FROM paths WHERE project_id = ?", (project_id,)
        ) as cur:
            return {r[0] async for r in cur}

    async def refs_for_file(self, project_id: int, rel_path: str, oid: str) -> set[int]:
        row = await self._fetchone(
            """
            SELECT o.refs
            FROM observations o
            JOIN paths p ON p.id = o.path_id
            WHERE o.project_id = ? AND p.rel_path = ? AND o.oidp = ?
            """,
            (project_id, rel_path, _oid_prefix(oid)),
        )
        return decode_refs(row[0]) if row else set()

    async def refs_having_path(self, project_id: int, rel_path: str) -> set[int]:
        out: set[int] = set()
        async with self.conn.execute(
            """
            SELECT o.refs
            FROM observations o
            JOIN paths p ON p.id = o.path_id
            WHERE o.project_id = ? AND p.rel_path = ?
            """,
            (project_id, rel_path),
        ) as cur:
            async for (buf,) in cur:
                out |= decode_refs(buf)
        return out

    async def known_refs(self, project_id: int) -> dict[int, Ref]:
        async with self.conn.execute(
            "SELECT id, sha, tag, committed_date, is_release FROM refs WHERE project_id = ?",
            (project_id,),
        ) as cur:
            return {
                r[0]: Ref(sha=r[1], tag=r[2], committed_date=r[3], is_release=bool(r[4]))
                async for r in cur
            }

    # -- discriminators ----------------------------------------------------- #

    async def recompute_discriminators(self, project_id: int) -> None:
        # Each (path, blob) is one row, so the count of rows for a path is exactly the number of
        # distinct blob OIDs that path takes across history — its discriminating power.
        await self.conn.execute(
            "DELETE FROM discriminators WHERE project_id = ?", (project_id,)
        )
        await self.conn.execute(
            """
            INSERT INTO discriminators (project_id, path_id, score)
            SELECT project_id, path_id, COUNT(*) * 1.0
            FROM observations
            WHERE project_id = ?
            GROUP BY project_id, path_id
            """,
            (project_id,),
        )
        await self.conn.commit()

    async def top_discriminators(self, project_id: int, limit: int) -> list[str]:
        async with self.conn.execute(
            """
            SELECT p.rel_path
            FROM discriminators d
            JOIN paths p ON p.id = d.path_id
            WHERE d.project_id = ?
            ORDER BY d.score DESC, p.rel_path ASC
            LIMIT ?
            """,
            (project_id, limit),
        ) as cur:
            return [r[0] async for r in cur]

    # -- helpers ------------------------------------------------------------ #

    @staticmethod
    def _project_meta(row) -> ProjectMeta:
        return ProjectMeta(
            id=int(row[0]),
            name=row[1],
            repo_url=row[2],
            github_commit_url_tpl=row[3],
            kind=row[4],
            parent=row[5],
        )

    async def _fetchone(self, sql: str, params: tuple = ()):
        async with self.conn.execute(sql, params) as cur:
            return await cur.fetchone()

    async def _scalar(self, sql: str, params: tuple = ()) -> int:
        row = await self._fetchone(sql, params)
        return int(row[0]) if row and row[0] is not None else 0

    async def _id_map(self, sql: str, params: tuple, wanted: set[str]) -> dict[str, int]:
        out: dict[str, int] = {}
        async with self.conn.execute(sql, params) as cur:
            async for key, _id in cur:
                if key in wanted:
                    out[key] = _id
        return out


async def open_storage(db_path: Path | str) -> SqliteStorage:
    """Open and initialise a SQLite storage."""
    store = SqliteStorage(db_path)
    await store.init()
    return store

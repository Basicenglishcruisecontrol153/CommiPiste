"""Match observed file hashes against the signature DB.

For each observed (rel_path, oid) we look up the set of refs where that path has exactly that
content. Resolving a version from those per-file ref-sets uses a layered strategy:

  1. **Exact intersection.** Intersect the ref-sets of all matched files. A non-empty result means
     every served file agrees — usually a single commit (exact), sometimes a tight equivalence
     class (e.g. an rc and its release share identical assets).

  2. **Anchor resolution.** If the intersection is empty, the deployment is inconsistent (patched,
     themed, or serving mixed-version assets — e.g. core is v27 but translations are v30). Flat
     plurality voting fails here because noisy auxiliary files (l10n) outnumber the few reliable
     ones. Instead we resolve the headline version from *anchor* files — the registry's curated
     ``probe_files`` (core bundles like server.css). They pin the core software version while the
     diverging files become the "modified" signal.

  3. **Support fallback.** If no anchors matched, fall back to the refs supported by the most files.

When the result is not a single exact commit we also report ``version_range`` — the span of
releases the evidence covers — so a mixed deployment is visible rather than collapsed to one
(possibly wrong) version.
"""

from __future__ import annotations

from collections import Counter

from ..models import Discrepancy, FileEvidence, Finding, MatchConfidence, Ref
from ..storage import ProjectMeta, Storage


def _pick_best(candidates: set[int], known_refs: dict[int, Ref]) -> int | None:
    """Prefer a tagged release, then the most recent commit, deterministically."""
    if not candidates:
        return None
    return sorted(
        candidates,
        key=lambda rid: (
            known_refs[rid].is_release,
            known_refs[rid].committed_date or "",
            known_refs[rid].sha,
        ),
        reverse=True,
    )[0]


def _nearest_version(candidates: set[int], known_refs: dict[int, Ref]) -> str | None:
    """A version label if the candidates' release tags agree."""
    tags = {
        known_refs[rid].tag
        for rid in candidates
        if known_refs[rid].is_release and known_refs[rid].tag
    }
    if len(tags) == 1:
        return next(iter(tags))
    return None


def _max_support(pairs: list[set[int]]) -> set[int]:
    """Refs contained in the most ref-sets (plurality support)."""
    votes: Counter[int] = Counter()
    for refs in pairs:
        votes.update(refs)
    if not votes:
        return set()
    best = max(votes.values())
    return {rid for rid, v in votes.items() if v == best}


def _release_span(refsets: list[set[int]], known_refs: dict[int, Ref]) -> str | None:
    """The earliest..latest release tag covered by any matched file (evidence spread)."""
    rids: set[int] = set()
    for refs in refsets:
        rids |= refs
    releases = [
        known_refs[r] for r in rids if known_refs[r].is_release and known_refs[r].tag
    ]
    if len(releases) < 2:
        return None
    releases.sort(key=lambda r: (r.committed_date or "", r.tag))
    lo, hi = releases[0].tag, releases[-1].tag
    return None if lo == hi else f"{lo} … {hi}"


def _resolve(
    matched: list[tuple[set[int], str]],
    anchors: set[str],
) -> tuple[set[int], str]:
    """Resolve candidate refs and the basis used. See module docstring for the layers."""
    refsets = [refs for refs, _ in matched]

    full = set.intersection(*refsets) if refsets else set()
    if full:
        return full, "exact"

    # Inconsistent deployment: prefer anchor (curated core) files.
    anchor_sets = [refs for refs, path in matched if path in anchors]
    if anchor_sets:
        anchor_inter = set.intersection(*anchor_sets)
        return (anchor_inter or _max_support(anchor_sets)), "anchor"

    # No anchors matched: refs supported by the most files.
    return _max_support(refsets), "support"


async def match_project(
    store: Storage,
    project: ProjectMeta,
    software_name: str,
    observed: dict[str, str],
    *,
    detected_by: str,
    missing: list[str] | None = None,
    anchors: set[str] | None = None,
    alt_hashes: dict[str, list[str]] | None = None,
) -> Finding:
    """Build a :class:`Finding` for one software unit from its observed file hashes.

    `anchors` are rel_paths trusted to indicate the core version (the project's probe_files); they
    break ties when files disagree. `alt_hashes` maps a rel_path to extra OIDs to accept if the
    served OID misses (e.g. the CRLF→LF-normalized OID for releases that ship CRLF newlines).
    """
    anchors = anchors or set()
    alt_hashes = alt_hashes or {}
    known_paths = await store.indexed_paths(project.id)
    known_refs = await store.known_refs(project.id)

    discrepancies: list[Discrepancy] = []
    matched: list[tuple[set[int], str]] = []
    files_probed = 0

    for rel_path, oid in observed.items():
        if rel_path not in known_paths:
            discrepancies.append(
                Discrepancy(rel_path=rel_path, kind="unexpected", detail="served but not in repo")
            )
            continue
        files_probed += 1
        refs = await store.refs_for_file(project.id, rel_path, oid)
        for alt in alt_hashes.get(rel_path, []):
            if refs:
                break
            refs = await store.refs_for_file(project.id, rel_path, alt)
        if refs:
            matched.append((refs, rel_path))
        else:
            discrepancies.append(Discrepancy(rel_path=rel_path, kind="unknown_hash", detail=oid))

    for rel_path in missing or []:
        if rel_path in known_paths:
            discrepancies.append(
                Discrepancy(rel_path=rel_path, kind="missing", detail="expected but not served")
            )

    candidates, basis = _resolve(matched, anchors) if matched else (set(), "exact")

    files_matched = len(matched)
    exact = basis == "exact" and len(candidates) == 1
    inconsistent = basis != "exact"
    best = _pick_best(candidates, known_refs)

    confidence = MatchConfidence(
        files_probed=files_probed,
        files_matched=files_matched,
        candidate_count=len(candidates),
        score=(files_matched / files_probed) if files_probed else 0.0,
        exact=exact,
    )

    finding = Finding(
        software=software_name,
        detected_by=detected_by,
        match_basis=basis,
        confidence=confidence,
        discrepancies=discrepancies,
        modified=inconsistent or any(d.kind == "unknown_hash" for d in discrepancies),
    )

    if best is not None:
        best_ref = known_refs[best]
        finding.commit_sha = best_ref.sha
        finding.commit_url = project.commit_url(best_ref.sha)
        finding.version = (
            best_ref.tag if best_ref.is_release else _nearest_version(candidates, known_refs)
        )
        if not exact:
            finding.commit_range = sorted(known_refs[rid].sha for rid in candidates)
            finding.version_range = _release_span([r for r, _ in matched], known_refs)
            finding.candidate_versions = _candidate_labels(candidates, known_refs)
            finding.key_files = _key_files(matched, candidates)

    finding.files = _file_evidence(observed, matched, missing or [], known_paths, project, best, known_refs)
    return finding


# Order files in the report: confirmed matches first (most discriminating on top), then mismatches.
_STATUS_ORDER = {"match": 0, "unknown_hash": 1, "missing": 2, "unexpected": 3}


def _file_evidence(
    observed: dict[str, str],
    matched: list[tuple[set[int], str]],
    missing: list[str],
    known_paths: set[str],
    project: ProjectMeta,
    best: int | None,
    known_refs: dict[int, Ref],
) -> list[FileEvidence]:
    """Per-file evidence behind the finding (what we checked, where it points, link on the host)."""
    best_sha = known_refs[best].sha if best is not None else None
    matched_refs = {path: refs for refs, path in matched}
    files: list[FileEvidence] = []
    for rel_path, oid in observed.items():
        if rel_path not in known_paths:
            files.append(FileEvidence(rel_path=rel_path, oid=oid, status="unexpected"))
            continue
        url = project.file_url(best_sha, rel_path) if best_sha else None
        refs = matched_refs.get(rel_path)
        if refs is not None:
            files.append(
                FileEvidence(rel_path=rel_path, oid=oid, status="match", pin=len(refs), url=url)
            )
        else:
            files.append(FileEvidence(rel_path=rel_path, oid=oid, status="unknown_hash", url=url))
    for rel_path in missing:
        if rel_path in known_paths:
            files.append(FileEvidence(rel_path=rel_path, status="missing"))
    files.sort(key=lambda fe: (_STATUS_ORDER.get(fe.status, 9), fe.pin, fe.rel_path))
    return files


def _candidate_labels(candidates: set[int], known_refs: dict[int, Ref]) -> list[str]:
    """Human labels (tag, else short sha) for the candidate refs, oldest-first."""
    refs = sorted(
        candidates, key=lambda rid: (known_refs[rid].committed_date or "", known_refs[rid].sha)
    )
    return [known_refs[rid].tag or known_refs[rid].sha[:12] for rid in refs]


def _key_files(matched: list[tuple[set[int], str]], candidates: set[int]) -> list[str]:
    """Top files that match ONLY the candidate versions (ref-set ⊆ candidates).

    These are the strongest evidence for the candidate set: they appear in those versions and no
    others. Ranked by how tightly they pin (smallest ref-set first)."""
    only = [(len(refs), path) for refs, path in matched if refs and refs <= candidates]
    only.sort(key=lambda x: (x[0], x[1]))
    return [path for _, path in only[:3]]

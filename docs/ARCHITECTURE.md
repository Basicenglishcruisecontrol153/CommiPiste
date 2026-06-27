# CommiPiste — Architecture & internals

OSINT tool that fingerprints the **exact git commit / release** of open-source web software on a
perimeter by matching the **git blob OIDs** of served static files against a prebuilt
`hash → paths → commits` database. See `CATALOG.md`
for the full software list + coverage caveats.

## 1. Core idea & canonical hash

The canonical hash is the **git blob OID**: `sha1("blob " + len + "\0" + content)`.

- **Repo side (indexing):** OIDs come straight from `git ls-tree -r <ref>` — blob *content* is never
  read. This is why a **blobless clone** (`git clone --bare --filter=blob:none`) suffices and is
  ~25× smaller (phpMyAdmin 2.4 GB → 94 MB).
- **Target side (scanning):** the same OID is reproduced from the bytes downloaded over HTTP
  (`CommiPiste/hashing.py::git_blob_hash`), so served files match index entries directly with no
  transformation.

Consequence: indexing never needs file content from git; only the SVN/wporg backend does (SVN has
no blob OIDs — see §6).

## 2. Pipeline

```
INDEX (offline):   clone/fetch ─▶ detect public dir ─▶ collect refs (tags [+touching commits])
                   ─▶ ls-tree each ref ─▶ collapse (path,blob)→{refs} ─▶ Signature DB
SCAN  (online):    detect software (banner/-s)
                   ├─ git-blob:   pick probe files ─▶ fetch+hash (web-root norm) ─▶ match
                   │              (intersection→anchor→support) ─▶ finding (+dependents)
                   └─ [--active]  version_probe: query endpoint ─▶ version (+commit) ─▶ finding
                   ─▶ [--cve] NVD+OSV enrichment ─▶ JSON / human / HTML report
```

## 3. Module map (`CommiPiste/`)

- `models.py` — pydantic types. **Project** (registry definition) and **Finding/ScanResult** (output).
- `config.py` — `Settings`; data dir `~/.CommiPiste` (override `COMMIPISTE_HOME`); holds
  `signatures.db`, `repos/` (bare clones), `registry/` (local project YAMLs).
- `hashing.py` — `git_blob_hash(bytes, algo="sha1")`.
- `registry/` — `loader.py` loads builtin (`registry/builtin/platforms.yaml` — a `defaults:` +
  `platforms:` file) + local per-file YAMLs into `Project`s.
- `storage/` — `base.py` (`ProjectMeta`), `sqlite.py` (the aiosqlite store + ref-set varint codec).
- `indexer/` — `repo.py` (`GitRepo`, `clone_or_open`), `wporg.py` (`WpOrgRepo`, the SVN/HTTP
  backend), `walker.py` (`collect_refs`, `IndexRef`),
  `builder.py` (`index_project` orchestration, discriminator selection, collapse).
- `detector/` — `banner.py` (software detection), `fetcher.py` (async fetch + web-root
  normalization), `matcher.py` (the matching algorithm), `dependents.py` (plugin/dependent scan),
  `active.py` (opt-in version probing from endpoints, `--active`), `scan.py` (`scan_target`
  orchestration).
- `vuln/` — optional vulnerability enrichment: `nvd.py` (NVD API 2.0, by CPE+version), `osv.py`
  (OSV.dev, by git commit), `cvss.py` (CVSS-vector→score), `merge.py` (dedup/merge across sources),
  `__init__.py` (`enrich_result`/`enrich_results` — attach a merged `VulnSummary`, online).
- `report.py` — human (rich) + JSON rendering. `report_html.py` — self-contained interactive HTML.
- `cli.py` — Typer CLI.

## 4. Data model (SQLite, `storage/sqlite.py`)

Realises `hash → paths → commits` with two dedup levels:

- `projects(id, name, repo_url, github_commit_url_tpl, kind, parent)` — note the column keeps the
  legacy name but stores the generic `commit_url_tpl`.
- `refs(id, project_id, sha, tag, committed_date, is_release)` — indexed history points.
- `paths(id, project_id, rel_path)` — web-root-relative file paths.
- `observations(project_id, path_id, oidp BLOB, refs BLOB)` — **one row per (path,blob)**, `WITHOUT
  ROWID`, PK `(project_id, path_id, oidp)`. `oidp` is the **first 12 bytes of the git blob OID**
  (inline, no separate `blobs` table); `refs` is the **varint-delta-encoded sorted set of ref ids**
  sharing that exact content.
- `discriminators(project_id, path_id, score)` — score = #distinct blobs that path takes across
  refs (how finely it splits versions); used to pick probe files.

**Why this schema:** the naive one-row-per-(ref,path,blob) had ~20× redundancy (a file unchanged
across N releases). Collapsing to one row per (path,blob) + ref-set blob removed it. A second pass
removed structural overhead: the redundant `(project_id,path_id)` index (covered by the PK prefix),
and the `blobs(id, oid UNIQUE)` table — which stored every OID twice (table + unique index) — folded
into a 12-byte inline `oidp` in a WITHOUT-ROWID `observations`. 12 bytes (96-bit), scoped per
(project,path), is collision-free in practice (0 across the corpus) and we never need the full OID
back from the DB (the target supplies it at scan time). Net: the deduped schema is **~45% smaller**
than the naive one, lossless for matching. Legacy DBs auto-migrate in place on open (no re-clone). `refs_for_file()`
decodes the ref-set; the public
Storage interface is unchanged so the matcher is agnostic to this.

## 5. Indexing (`indexer/builder.py::index_project`)

1. **Source dispatch:** `git` (default) → `clone_or_open` (blobless, full-clone fallback);
   `wporg` → `WpOrgRepo` (§6).
2. **public_paths:** from the project YAML (or `--public-path`).
   `repo_subdir` maps a repo subdir to the web root (e.g. phpBB `phpBB/`, pfSense
   `src/usr/local/www`) — prepended for ls-tree, **stripped** from stored paths so they match URLs.
3. **collect_refs (`walker.py`):** all tags/releases + (unless `--tags-only`) commits touching the
   public dir. `--tags-only` is what we use for big repos.
4. **Discriminator selection:** read every ref's tree; drop files invariant across all refs; rank
   the rest by distinct-OID count; keep top `--max-files` (default **2000**). We only probe ~100
   files at scan time, so the long tail is pure storage cost.
5. **Collapse + write:** accumulate `(path,oid) → [ref_ids]`, write one `record_signatures` row per
   (path,blob). Incremental `--update` uses `append_ref_files` (only new refs, existing paths).

Flags: `--tags-only`, `--update`, `--max-files N` (0=unlimited), `--public-path`, `--name`.

## 6. Backends — git and wordpress.org SVN

The indexer is **host-agnostic**: `repo_url` may be GitHub, **GitLab** (`git.spip.net`,
`gitlab.com`), self-hosted, etc. — only `git` is shelled out. Per-host commit links come from
`commit_url_tpl`, which uses the **`/tree/{sha}`** form (browse the whole repo at that commit, not a
diff): GitHub `/tree/{sha}`, GitLab `/-/tree/{sha}`. A **full-clone fallback** covers servers that
reject blobless partial clone.

`source: wporg` (`indexer/wporg.py::WpOrgRepo`) indexes **wordpress.org plugins/themes** that aren't
on git. It mirrors the `GitRepo` interface (`tags()`/`ls_tree()`) but over **plain HTTP** against
`plugins.svn.wordpress.org/<slug>/`:
- versions from the WP.org API (`api.wordpress.org/plugins/info/1.0/<slug>.json`), fallback to the
  SVN `tags/` HTML listing;
- `ls_tree(version, paths)` recursively scrapes the SVN HTML dir listing and **fetches each file to
  compute its git blob OID** (no free OIDs in SVN → content fetch; slower, fine for small plugin
  asset sets). `name` is the slug; `served_prefix`/`commit_url_tpl` point at the SVN tag.

## 7. Scanning (`detector/scan.py::scan_target`)

1. **Detect software:** `--software/-s` forces a project; else `banner.py` matches each registered
   project's banner (dedicated marker endpoint like Nextcloud `status.php` is strongest; loose
   header presence is avoided — it false-positives).
2. **Probe selection (`scan.py::_probe_paths`):** project `probe_files` (anchors) + top
   discriminators, restricted to indexed paths. Adaptive 2nd round fetches more if not yet pinned.
3. **Fetch + web-root normalization (`fetcher.py`):** async GET, `follow_redirects=False` (a
   redirecting asset isn't served here), reject `text/html` bodies (SPA/login fallbacks). For each
   indexed path it also tries **web-root-prefix-stripped URLs** (`public/`, `htdocs/`, `html/`,
   `public_html/`, `web/`, `www/`, `upload/`) so deployments serving a subdir as the root (Rails
   `public/`, Moodle 5.x) match without re-indexing. Match keys on the indexed path.
4. **Match (`matcher.py::match_project`):** per file, `refs_for_file` → set of refs. Then:
   - **exact intersection** of all matched files' ref-sets → usually one commit;
   - if empty (inconsistent/patched/themed deployment) → **anchor resolution**: intersect only the
     anchor (probe_files) ref-sets to pin the core version;
   - if still empty → **support** (most-voted refs).
   Emits `version`, `commit_sha`/`commit_url`, `commit_range`, `candidate_versions`, `key_files`
   (files matching only the candidates), `version_range` (evidence spread), `match_basis`, and
   `modified` (some files match no/other commit). `confidence`: exact (1 commit) / medium / low.
   It also fills `files` — per-file `FileEvidence` (path, observed OID, status
   match/unknown_hash/missing/unexpected, `pin` = #refs sharing that content, and a link to the file
   on the host at the matched commit via `ProjectMeta.file_url`) — the detail the HTML report uses.
4a. **Active probing (`active.py`, opt-in `--active`):** a detected project with a `version_probe`
   is *not* git-blob matched — instead each probe endpoint is queried and the version is pulled from
   a response header (e.g. Mattermost `X-Version-Id`) or body via regex → `Finding(detected_by=
   "active")`. **Off by default** (it hits non-static endpoints); when such a project is detected
   without `--active`, the finding carries `needs_active_probe=True` and the report says so
   explicitly rather than reporting nothing. Commit resolution: `commit_regex` captures an observed
   SHA (e.g. Discourse's generator embeds the full git commit); else `resolve_commit_from_tags` infers
   it from the version's release tag (`git ls-remote`) and sets `commit_inferred=True` (Flarum). All
   commit links use **`/tree/{sha}`** (browse the whole repo at that commit), not `/commit/` (diff).
5. **Dependents (`dependents.py`):** for each `dependents.projects` of the parent, fetch
   under `served_prefix` (WordPress plugin = `wp-content/plugins/<slug>`). Presence-gated cheaply
   (plugin asset or `readme.txt`); only installed+matched plugins are reported, as `detected_by:
   "dependent"` findings.

Flags: `--path` (app sub-path install), `-s`, `--targets` (batch), `--json`, `--details`
(discrepancies), `--no-dependents`, `--active` (opt-in version probing), `--cve/--no-cve` (on by
default), `--cve-source`, `--report PATH`, `--insecure/-k`, `-c` concurrency, `--verbose/-v`.

## 7a. Vulnerability enrichment (`vuln/`)

Online **post-scan** step, **on by default** (disable with `--no-cve`; sources via
`--cve-source nvd|osv|both`), kept out of the core scan so fingerprinting stays offline-capable and
hermetically testable (`--no-cve` makes a run fully offline). Two
complementary sources per finding, **merged and deduplicated by CVE id** in `merge.py::build_summary`
(union of sources per advisory; highest CVSS kept; `total` honours the NVD result count):

- **NVD** (`nvd.py`) — by **CPE + version**: `virtualMatchString` CPE 2.3 (version filled from the
  finding; tag normalized `v27.1.11`→`27.1.11`), CVSS severity v3.1→v3.0→v2. Needs a project `cpe:`.
  For a non-exact match it checks **every candidate version** (`fetch_nvd_many`, bounded by
  `MAX_NVD_VERSIONS`) and unions the CVEs — symmetric with the OSV multi-commit check.
  Rate-limited (~5 req/30s unauth); `NVD_API_KEY` raises it. **CPE accuracy matters** — a wrong
  product silently yields 0 CVEs (false "clean"); builtin CPEs are validated against the NVD CVE
  endpoint (the CPE *dictionary* gives false negatives, so validate against actual CVE matches).
- **OSV** (`osv.py`) — by the **identified git commit(s)**: `POST api.osv.dev/v1/query {"commit": sha}`.
  No per-project mapping (works without a CPE). For a non-exact match it queries **every candidate
  commit** (best + `commit_range`, bounded by `MAX_OSV_COMMITS`, concurrency-capped) and unions the
  advisories; `commits_checked` records how many. OSV returns CVSS as a *vector*, so `cvss.py`
  computes the base score locally (CVSS 3.1 formula) for cross-source comparability; GHSA ids are
  canonicalised to their CVE alias for dedup. (OSV's commit query is API-only; the web UI can't search
  by commit, so the report links each candidate commit on the source host for manual verification.)

Output: a `VulnSummary` (total, counts by severity, top-N advisories each with `sources`, links, and
a browsable NVD search URL).

## 7b. Reporting (`report.py`, `report_html.py`)

- **JSON** (`--json`): the full `ScanResult` (now incl. `files` + `vulnerabilities`).
- **Human** (rich): findings + (with `--cve`) a CVE summary line and top CVEs.
- **HTML** (`--report out.html`): a single self-contained file (inline CSS/JS, offline). Per target:
  each software unit, the linked commit, version, the **files checked** (each linked to the host at
  the matched commit, with status + pin), and the vulnerability section (severity badges, CVE links,
  per-advisory source chips NVD/OSV, NVD search link). Host filter, "only targets with CVEs" toggle,
  embedded raw JSON.
  Data-driven from the same `ScanResult` models — interactivity can grow without touching the scan.

## 8. Project definition (registry YAML)

Builtins live in **one file**, `registry/builtin/platforms.yaml`:

```yaml
defaults: {source: git, commit_url_tpl: "{repo_url}/tree/{sha}"}   # merged into every platform
platforms:
  <name>: { <overrides...> }     # only non-default fields; may use `extends: <other>`
```

Each platform entry (and a local per-file YAML added via `registry add`) has the fields:

```yaml
name: <slug>                     # also the wporg plugin slug (the map key in platforms.yaml)
repo_url: <git url | svn base>
source: git | wporg              # default git
commit_url_tpl: "{repo_url}/tree/{sha}"     # browse files at the commit; GitLab /-/tree/{sha}
repo_subdir: ""                  # repo subdir that is the deployed web root (stripped from paths)
served_prefix: ""                # where this project sits under a PARENT web root (dependents)
public_paths: [ ... ]            # web-root-relative dirs holding served static assets
banners: {paths: [...], headers: {Name: regex}, body_regex: [...]}
probe_files: [ ... ]             # anchor files (curated, reliable core assets)
dependents: {pattern: "...", projects: [<names>]}
version_probe:                   # optional; opt-in active version extraction (--active)
  paths: [/api/.../version]      # endpoint(s) to query
  header: X-Version-Id           # read from this header (omit to match the body)
  regex: '^(\d+\.\d+\.\d+)'      # capture group 1 = version
  commit_regex: '([0-9a-f]{40})' # optional: observed commit SHA (e.g. Discourse generator)
  resolve_commit_from_tags: true # optional: if no observed commit, infer it from the version's
                                 # release tag via `git ls-remote` (marks Finding.commit_inferred)
kind: core | plugin
cpe: "cpe:2.3:a:vendor:product"  # optional; enables NVD/CVE lookup for matched versions (--cve)
```
`commit_url_tpl` accepts the legacy key `github_commit_url_tpl` (alias). Builtins live in the single
`registry/builtin/platforms.yaml`; users add their own per-file via `CommiPiste registry add
<yaml>`, which still uses the flat single-project shape above.

## 9. Interfaces

- **CLI** (`cli.py`): `index`, `scan`, `fetch`/`interactive-update`, `registry list|add`.
- **Library**: `CommiPiste.index_project()`, `CommiPiste.scan_target()`, returns `ScanResult`.

## 10. Testing

- **Hermetic** (default `pytest`, ~32 tests): build throwaway git repos, serve over local HTTP,
  assert. Covers hashing parity with real `git`, indexing, the matcher (exact/range/modified/anchor),
  incremental, web-root normalization, dependent plugins, the active probe
  (off-by-default notice, version extraction, `resolve_tag_commit` against a local repo), the vuln
  layer (NVD parse, OSV parse + CVSS-from-vector, multi-source merge/dedup, candidate fan-out), and
  the HTML report (evidence, source chips, NVD-key hint, `--active` notice).
- **Live, public** (`CR_E2E_LIVE=1 pytest tests/test_e2e_instances.py`): scans real public instances
  (`CASES`, 37 platforms / 43 instances), cross-checks versions against each site's self-report where
  exposed (Nextcloud `status.php`, WordPress/Joomla `generator`, MediaWiki API), plus parametrized
  WordPress→plugin dependent tests (yoast→akismet, yithemes→woocommerce, wpastra→elementor). Version
  detection only; unreachable hosts skip, not fail.
- **Live, local Docker** (`CR_E2E_DOCKER=1 pytest tests/test_e2e_docker.py`, harness in `docker/`):
  brings up default installs at **pinned** versions and scans `localhost` — exact ground truth, and
  the only way to cover **internal-only tools** (Zabbix/GLPI/NetBox/…) that have no public instances.
  See `CATALOG.md` for the per-project table + caveats and `../docker/README.md` for the harness.

## 11. Limitations (see README "Not yet supported")

- **Build-artifact apps don't git-blob fingerprint:** SPA/webpack/Go-embedded/generated assets
  (Grafana, Kibana, GitLab, Keycloak; **Zabbix** — its UI CSS/JS is compiled/concatenated at build,
  so served assets don't match repo blobs and it mis-resolves; partially Magento `pub/static`,
  Elementor/Yoast bundles). The
  dividing line is "serves source verbatim" vs "ships built assets". Their **version** can still be
  read via **active probing** (`--active`) when exposed at an endpoint — implemented for Mattermost,
  Grafana, Gitea, Jenkins, Discourse (+ observed git commit) and Flarum (commit inferred from tag).
- **Patch-level ceiling:** when a project ships identical assets across adjacent patches (WordPress
  `wp-includes`), the *version* pins but the exact patch commit may not → `confidence: medium`.
- **Path mapping is the main failure mode**, not hashing (web-root subdirs, sub-path installs, CDN
  offload). Handled by scan-time normalization + `--path` + `repo_subdir`; CDN offload is
  unfixable.
- **Internal tools are least testable:** the highest-value targets (Zabbix, Cacti, Webmin, GLPI,
  firewalls, MISP) rarely have stable public instances.

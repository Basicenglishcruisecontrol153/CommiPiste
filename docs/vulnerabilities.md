# Vulnerability lookup (CVEs)

Vulnerability lookup runs **by default**: each match is checked against two complementary sources and
the report gains a short summary — counts by severity, the most severe advisories (CVSS score + a
link to each detail page), and per-advisory **source attribution**. Pass `--no-cve` to identify the
version without any NVD/OSV calls (fully offline).

- **NIST NVD** — by **CPE product + version**. Driven by a per-project `cpe:` mapping in the
  registry YAML (e.g. `cpe:2.3:a:nextcloud:nextcloud_server`); projects without a CPE are skipped
  for this source. For a non-exact match **every candidate version** is checked (a CVE fixed in a
  later candidate still affects the earlier ones). Public API is rate-limited (~5 req/30s) — set
  `NVD_API_KEY` to raise it.
- **CVEDB** (Shodan, `cvedb.shodan.io`) — the **same CPE + version** query as the NVD, but
  **keyless and not rate-limited**. It runs alongside the NVD and the results are unioned, so it
  backfills the NVD when that returns 503s and catches CVEs the NVD's CPE applicability misses.
  (Like the NVD, a CVE recorded without affected-version ranges won't surface from a version-scoped
  query — upstream data completeness, not a CVEDB limit.)
- **OSV** (osv.dev) — by the **identified git commit(s)**. CommiPiste asks OSV which advisories'
  affected git ranges include the commit — no per-project mapping needed, so OSV gives coverage even
  for projects without a CPE. When a match isn't pinned to one commit, **every candidate commit**
  (best + `commit_range`) is checked and the advisories are unioned. OSV reports CVSS as a vector;
  the base score is computed locally to make it comparable with the NVD's. (OSV's commit query is
  API-only — the osv.dev web UI can't search by commit — so the report links each candidate commit on
  the source host for manual verification, plus each advisory's detail page.)

Results are **merged and deduplicated** by CVE id (the union of sources is shown per advisory, with
the highest CVSS kept). Pick sources with `--cve-source nvd|cvedb|osv|both|all`. The **default is
CVEDB + OSV** (both keyless and fast); the **NVD is opt-in** (`--cve-source nvd` or `all`) because
its rate-limited API is slow and CVEDB already answers the same CPE+version query. Skip the whole
step with `--no-cve`. The lookup is a post-scan enrichment kept separate from fingerprinting, so the
core match still works offline (and `--no-cve` makes the run fully offline).

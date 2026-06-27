# Install & usage

## Install

**Prerequisites:** Python ≥ 3.11 and a system **`git`** binary — `git` is a *runtime* dependency,
not just for development: indexing shells out to `git clone`/`ls-tree`, and active-probe commit
inference uses `git ls-remote`. (Scanning a target with an already-built DB does not need `git`.)

```bash
pip install -e .               # core
pip install -e '.[dev]'        # core + tests
```

## Commands

```bash
# Scan a single target (auto-downloads the signature DB on first run; see docs/database.md).
CommiPiste scan https://cloud.example.org
CommiPiste scan https://cloud.example.org --json        # machine-readable
CommiPiste scan https://cloud.example.org -s nextcloud  # force software (skip auto-detect)
CommiPiste scan https://host --path blog -s wordpress   # app installed under a sub-path
CommiPiste scan https://host -v                         # verbose: show files fetched/hashed
CommiPiste scan https://host --details                  # include per-file discrepancies
CommiPiste scan https://host --no-dependents            # skip plugin/dependent checks
CommiPiste scan https://host --active                   # active probing: read versions from endpoints
CommiPiste scan https://host                            # vuln lookup (NVD+OSV) runs by default
CommiPiste scan https://host --no-cve                   # version only, no NVD/OSV calls (offline)
CommiPiste scan https://host --cve-source osv           # OSV only (by commit; no CPE needed)
CommiPiste scan https://host --report out.html          # write an interactive HTML report
CommiPiste scan --targets t.txt --report out.html       # batch: one combined report

# Autoindex software the DB doesn't know yet: clone its repo, index release tags, then fingerprint.
CommiPiste scan https://demo.bookstackapp.com --autoindex \
  --repo https://github.com/BookStackApp/BookStack   # --public dir,dir if auto-detect misses;
                                                      # --cpe to enable CVE lookup
# The project is saved to the local registry, so a later plain `scan <url>` detects it by fingerprint.

# Batch scan.
CommiPiste scan --targets targets.txt

# Check for / apply a newer signature DB (interactive: download or rebuild).
CommiPiste interactive-update           # menu-driven; confirms each step
CommiPiste interactive-update --check   # report only; exit 1 if a newer DB exists (CI-friendly)
CommiPiste interactive-update --download # non-interactive: download if newer
CommiPiste interactive-update --yes      # assume yes to confirmations

# Build the signature DB for a known project (ships with builtin definitions).
CommiPiste index nextcloud
CommiPiste index nextcloud --tags-only            # releases only (bounded; for huge repos)
CommiPiste index nextcloud --tags-only --max-files 2000   # cap stored discriminator files
CommiPiste index nextcloud --update               # incremental: index only new refs
CommiPiste index https://gitlab.com/org/app.git --public-path public --name app  # arbitrary repo

# Manage project definitions (builtins in registry/builtin/platforms.yaml; local in ~/.CommiPiste).
CommiPiste registry list
CommiPiste registry add my-private-app.yaml             # add a local/private project
```

A scan finds the software via banner (or `-s`), then reports per software unit: `version`,
`commit`/source link, `confidence` (exact / medium / low), `candidate versions` + `key files` when
not pinned to one commit, `evidence range` and `modified` for patched/themed deployments, any
installed WordPress plugins as `detected by dependent` findings, and (with `--cve`) a per-version
vulnerability summary. Use `--report out.html` for the interactive HTML version.

### Interactive HTML report
`--report out.html` writes a single, self-contained HTML file (inline CSS/JS, works offline). Per
target it shows each identified software unit, the deployed **commit** (linked to the source host),
the version, the exact **files checked** (each linked to that file on the host at the matched
commit, with a match/mismatch status and how tightly it pins the version), and — when `--cve` ran —
the vulnerability summary with severity badges and links to the NVD. The page has a host filter and
an "only targets with CVEs" toggle; it also embeds the raw JSON so it can double as a data carrier.

## Library API

```python
import asyncio
from CommiPiste import scan_target

result = asyncio.run(scan_target("https://cloud.example.org", software="nextcloud"))
print(result.to_json())
```

## Data location

Working data (signature DB, bare clones, local registry) lives under `~/.CommiPiste`, overridable
via `COMMIPISTE_HOME`.

## Scope

Intended for authorized security testing and defense. Requests are made only to publicly accessible
static files; the tool performs no exploitation.

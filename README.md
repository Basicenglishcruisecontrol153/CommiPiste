# CommiPiste

<div align="center">

<img width="318" height="322" alt="CommiPiste logo" src="https://github.com/user-attachments/assets/8c0ff846-17cd-483a-8e80-330c2af82b04" />

Find the **exact version and CVEs of open-source web software** just from the static files.
<br> _Idea by paranoid android_.

_**commit** (Git commit) + **piste** (French for "track")_

</div>

## Why

Knowing the precise commit beats a version string: CVE-affected code "leaks" a few releases up and
down a version range, so the commit tells you whether a given fix is actually present. CommiPiste
is for authorized security testing and perimeter asset inventory — it only requests public static
files and never exploits anything.

## How it works

<img width="800" alt="How CommiPiste fingerprints a target" src="https://github.com/user-attachments/assets/9d11c503-75a7-4d56-9f26-d6edaf51edce" />

Open-source apps serve static files (JS, CSS, icons) straight from their source tree.

CommiPiste:
- builds a signature database of every release's files (keyed by **git blob OID**, taken for free from
`git ls-tree`)
- then downloads those files from a target
- reproduces the same OIDs from the bytes
- matches them back to a single commit.

- [More on how it works](docs/how-it-works.md)

## Quickstart

```bash
pip install -e .                              # needs Python ≥ 3.11 and a `git` binary
CommiPiste scan https://mantisbt.org/bugs     # first run auto-downloads the signature DB
```

The first scan pulls a prebuilt signature database automatically, then identifies the software and
prints the version/commit plus known CVEs.

On MantisBT's own public bug tracker, for example, it
pins **MantisBT 2.28.3** and surfaces its vulnerabilities —
[see an example HTML report](https://htmlpreview.github.io/?https://github.com/soxoj/CommiPiste/blob/main/example.html).

A few more examples:

```bash
CommiPiste scan https://mantisbt.org/bugs --verbose # show matching process
CommiPiste scan https://mantisbt.org/bugs --json    # machine-readable
CommiPiste scan https://mantisbt.org/bugs --no-cve  # version only, fully offline
CommiPiste scan https://mantisbt.org/bugs --report out.html  # interactive HTML report
CommiPiste scan --targets hosts.txt                 # batch
```

## Autoindex new software

The bundled database covers 200+ platforms. To fingerprint software it doesn't know yet, point
`--autoindex` at the project's git repo — CommiPiste clones it, indexes its **release tags**, and
then identifies the running version, all in one command:

```bash
CommiPiste scan https://demo.bookstackapp.com --autoindex \
  --repo https://github.com/BookStackApp/BookStack
```

- **Public dirs** are auto-detected: it probes the repo's top-level directories against the names
  already common across the registry (`js`, `themes`, `css`, `public`, `assets`, …). Override with
  `--public dist,css` if the guess misses.
- **Optional flags:** `--name` (defaults to the repo name), `--cpe cpe:2.3:a:vendor:product` (enables
  CVE lookup for the matched version).
- **It's remembered.** The project is saved to your local registry (`~/.CommiPiste/registry/`), so
  later runs need neither flag — a plain `scan <url>` detects it by fingerprint:

  ```bash
  CommiPiste scan https://demo.bookstackapp.com   # detected, no --autoindex needed
  ```

Autoindexed projects survive a database update: after `interactive-update` downloads a fresh DB,
any local project missing from it is re-indexed automatically.

## Documentation

- [Install & full CLI / library usage](docs/usage.md)
- [The signature database (auto-download, building it)](docs/database.md)
- [How it works](docs/how-it-works.md) · [Architecture & internals](docs/ARCHITECTURE.md)
- [What can / can't be fingerprinted](docs/supported.md)
- [Vulnerability lookup (NVD + OSV)](docs/vulnerabilities.md)
- [Active probing (SPA / bundled apps)](docs/active-probing.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Supported software list](docs/CATALOG.md)
- [Testing](docs/testing.md)

## Related research

Prior and adjacent work on web-application fingerprinting:

- [Understanding and Improving Web Application Fingerprinting (WASABO)](https://www.usenix.org/publications/loginonline/understanding-and-improving-web-application-fingerprinting-wasabo) — USENIX
- [WAFP — Web Application Fingerprinting](https://web.archive.org/web/20100323114756/https://www.mytty.org/wafp/)
- [Sucuri — Fingerprinting Web Apps](https://web.archive.org/web/20100201135658/http://sucuri.net/?page=docs&title=fingerprinting-web-apps)
- [WhatWeb](https://web.archive.org/web/20110513043304/http://www.morningstarsecurity.com/research/whatweb) — Morning Star Security

## License

[MIT](LICENSE)

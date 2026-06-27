# The signature database

Scanning matches served files against a prebuilt **signature DB** (`hash → paths → commits`). The DB
is **not shipped in the repo** (it is generated data, ~65 MB). You don't normally fetch it by hand:

- **Auto-download on first run (default):** the first `scan` with no DB present downloads a prebuilt
  one (a GitHub Release asset, `signatures.db.gz`, decompressed on the fly) into
  `$COMMIPISTE_HOME/signatures.db` (default `~/.CommiPiste`), validates it, and continues. If
  the download isn't configured or fails, the scan still runs — git-blob projects just report
  `not indexed`, and active-probe apps work regardless. Point it elsewhere with
  `export COMMIPISTE_DB_URL=https://…/signatures.db[.gz]` (an HTTP(S) URL or a local path).
- **Drop a file in place:** put `signatures.db` at `$COMMIPISTE_HOME/signatures.db`
  (`export COMMIPISTE_HOME=/path/to/dir`).
- **Build it yourself:** run `CommiPiste index <project>` per project (needs `git`; clones each
  repo blobless). See `CommiPiste registry list` for names. Building all git-blob projects takes a
  while and downloads several GB of blobless clones (the resulting DB is still ~65 MB; the clones
  live under `$COMMIPISTE_HOME/repos/` and are only needed for later `index --update`).

Active-probe projects (Mattermost, Grafana, Gitea, Jenkins, Discourse, Flarum) need **no** DB — only
`--active`.

## Keeping it current

`CommiPiste interactive-update` checks the published release manifest (`signatures.json`, built
date + project count + sha256) against your local copy and offers to **download** the newer prebuilt
DB or **rebuild** it locally (refresh latest tags, or re-index chosen platforms with tags-only or
full history). Non-interactive flags: `--check` (report only, exit 1 if newer), `--download`, `--yes`.

Maintainers publish a new DB with `scripts/publish-db.sh <owner/repo>` (gzips the DB, generates the
manifest, and `gh release create`s a dated `db-YYYY-MM-DD` tag). Publishing is separate from the tool.

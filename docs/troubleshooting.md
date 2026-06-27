# Troubleshooting: software detected, but version not found

If a scan reports the software (by banner) but `confidence: none` / `matched 0/N` / `not indexed`,
the assets it probed weren't found at the URLs it tried. Common causes and fixes:

- **App installed under a URL sub-path** (e.g. WordPress at `https://host/blog/`, Nagios at
  `/nagios/`). Pass the sub-path explicitly:
  ```bash
  CommiPiste scan https://host --path blog -s wordpress
  ```
- **Web root is a repo subdirectory.** Many apps serve a subdir as the web root, so the subdir
  name is absent from served URLs — Rails/Redmine and Moodle 5.x serve `public/`, phpBB serves
  `phpBB/`, Zabbix serves `ui/`. The scanner **handles this automatically**: for an indexed path
  like `public/theme/x.css` it also tries the prefix-stripped URL `/theme/x.css` (known web-root
  prefixes: `public/`, `htdocs/`, `html/`, `public_html/`, `web/`, `www/`, `upload/`). No action
  needed, and no re-indexing — the match still keys on the indexed path.
- **Unusual web-root subdir** not in that list: set `repo_subdir:` in the project's registry YAML
  so indexing stores web-root-relative paths (this is an index-time setting; re-index that project
  once after changing it).
- **Project not indexed yet** (the `not indexed` hint is literal): set `COMMIPISTE_DB_URL` to a
  prebuilt DB, or run `CommiPiste index <name>`.
- **Genuinely absent content** — the version's assets were never indexed (e.g. a newer release
  moved files to a directory the registry definition doesn't cover, like GLPI 10's `public/`). No
  scan-time logic can match data that isn't in the DB; add the directory to `public_paths` and
  re-index that project.
- **Assets served from a CDN / offloaded** (e.g. `*.wp.com`) or behind auth: the origin doesn't
  serve them, so they can't be hashed. Nothing to do.

If a scan returns a candidate *range* with `modified`, that's expected for patched/themed
deployments — see the `version_range` and `key files` in the report.

# Active probing (versions of build-artifact apps, opt-in)

Some apps don't serve git-blob-matchable assets (bundled/minified/content-hashed frontends) but
**expose their version at an endpoint** — e.g. Mattermost's `X-Version-Id` header, or `/api/...`
version routes. `--active` enables **active probing**: querying those endpoints and extracting the
version via a per-project `version_probe` (header/body regex). It's **off by default** because it
hits dedicated (often API) endpoints rather than public static files.

When such a platform is detected **without** `--active`, CommiPiste says so explicitly — e.g.
*"mattermost: active probing required — re-run with `--active` to read the version"* — rather than
silently reporting nothing. With `--active`, you get the exact version (e.g. Mattermost `11.9.0`),
`detected by active`. Registry shape:

```yaml
version_probe:
  paths: [/api/v4/system/ping]   # endpoint(s) to query
  header: X-Version-Id           # read from this header (omit to match the body)
  regex: '^(\d+\.\d+\.\d+)'      # capture group 1 = version
```

Implemented for **Mattermost** (`X-Version-Id`), **Grafana** (`/api/health`), **Gitea**
(`/api/v1/version`), **Jenkins** (`X-Jenkins` header), **Discourse** (generator meta — exposes
version **and** the git commit SHA) and **Flarum** (version in page; commit inferred from the release
tag, marked approximate).

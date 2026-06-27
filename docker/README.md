# Local-instance e2e harness

Deterministic end-to-end coverage by running **default installs at pinned versions** locally and
scanning them — the approach the *Smudged Fingerprints / WASABO* paper used. Its main value:

- **Covers internal-only tools** (Zabbix, Cacti, GLPI, NetBox, …) that have **no public instances**,
  so they can't be reached by `tests/test_e2e_instances.py`.
- **Exact ground truth** — the version is whatever image tag you pinned, so the test cross-checks the
  detected version precisely, with no flakiness from third-party sites or CDN/customisation.
- **Version detection only** (no vulnerability checks).

## Run — laptop-friendly runner (recommended)

`docker/run_e2e.py` processes **one app at a time**: bring it up → wait → scan → assert the version →
tear it down → **remove its image**. Only one app image (plus cached DB/redis sidecars) sits on disk
at any moment, and cleanup is automatic — so the whole set runs on a laptop without filling the disk.

```bash
python docker/run_e2e.py                 # all cases, sequential, remove app images as it goes
python docker/run_e2e.py -k wordpress    # only cases matching "software:version"
python docker/run_e2e.py --keep-images   # keep images (faster re-runs, more disk)
python docker/run_e2e.py --jobs 2        # N apps concurrently (faster, but N images on disk)
```

Exit code is 1 if any case FAILs. It reuses `DOCKER_CASES` (single source) and links each case to its
compose service by the URL port, so it stays in sync with `docker-compose.yml`.

## Run — raw pytest (CI with lots of disk)

Brings nothing up itself — you bring up a profile, then run pytest (sequential; un-booted services
are **skipped**, not failed); cleanup is manual:

```bash
docker compose -f docker/docker-compose.yml --profile light up -d   # light/cms/internal/legacy/all
# wait ~1-2 min (CMS/internal run DB migrations on first start), then:
CR_E2E_DOCKER=1 CR_E2E_READY_TIMEOUT=120 pytest tests/test_e2e_docker.py -q
docker compose -f docker/docker-compose.yml --profile all down -v   # manual teardown (no image rm)
```

## Profiles

| Profile | Apps | Notes |
|---|---|---|
| `light` | phpmyadmin, grafana, jenkins | single container, no DB, fast — start here |
| `cms` | wordpress, mediawiki, drupal, nextcloud, joomla | serve their static tree even before setup |
| `internal` | netbox, glpi | the high-value tools with no public instances |
| `legacy` | wordpress 4.7/4.9/5.0, nextcloud 15/18/20, owncloud 10.11, mediawiki 1.27/1.31/1.35, drupal 8.9/9.2/9.4, joomla 3.10, prestashop 1.6, phpmyadmin 4.6/4.7/4.9, roundcube 1.3/1.4, grafana 5.4/6.7/7.5, redmine 4.0 | **specific OLD versions** (hard to find live; where the CVEs are) |

> Gitea is covered by **public** instances (`gitea.com`, `codeberg.org`) in
> `tests/test_e2e_instances.py`, not Docker — old Gitea can't be install-locked via env so its API
> stays behind `/install`.

## Adding an app

1. Add a service to `docker-compose.yml` with a **pinned** image tag and a host port, under the right
   profile (add a DB sidecar + `depends_on` if it needs one).
2. Add a matching `DCase(software, "http://localhost:<port>", "<pinned-version>")` to
   `tests/test_e2e_docker.py` (set `active=True` for active-probe apps like Grafana/Gitea/Jenkins).
3. Keep the pinned tag and the `DCase` version in sync — the tag is the ground truth.

This is the path to 75 %+ coverage: public instances top out around ~37 % (internal tools, plugins,
SPA/bundled apps, and customised official sites can't be reached), whereas Docker can host any app.

# Testing

- **Hermetic** (`pytest`): builds throwaway git repos + local HTTP servers — no network.
- **Live, public** (`CR_E2E_LIVE=1 pytest tests/test_e2e_instances.py`): real public instances,
  version-detection only, plus WordPress→plugin dependent checks.
- **Live, local Docker** (`CR_E2E_DOCKER=1 pytest tests/test_e2e_docker.py`): default installs at
  pinned versions via [`../docker/`](../docker/README.md) — exact ground truth, and the only way to
  cover internal-only tools (Zabbix/GLPI/NetBox/…) that have no public instances.

## Coverage caveats

See [CATALOG.md](CATALOG.md) for the per-project table. Key points:

- **Not yet verified on a live instance:** some indexed projects haven't been confirmed against a
  real deployment. On such a site a `0/0` / `not indexed`-style result may mean a custom theme or a
  version/path outside the index — not necessarily a bug.
- **Thin index:** a few projects (e.g. coppermine, pico, getsimple) have very few signatures (their
  assets barely change across releases), so they yield a coarse version *range*, not an exact commit.
- **CPE (for `--cve` NVD lookups) not fully validated** for some newer entries; a wrong/absent CPE
  can show "no known CVEs (via NVD)" — cross-check OSV (which works by commit, no CPE needed).

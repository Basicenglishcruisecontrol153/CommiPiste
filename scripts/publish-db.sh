#!/usr/bin/env bash
# Maintainer-only: publish the prebuilt signature DB as a dated GitHub Release asset + manifest,
# so `CommiPiste interactive-update` can detect and download it.
#
# This is NOT part of the tool runtime — run it by hand after (re)building the DB. It produces:
#   - signatures.db.gz   (the gzipped DB; interactive-update / fetch-db decompress on the fly)
#   - signatures.json    (manifest: build_date, projects, sha256 — drives the "is newer?" check)
# uploaded under a dated tag (db-YYYY-MM-DD); `releases/latest` then points at the newest.
#
# Usage: scripts/publish-db.sh <owner/repo> [db_path]
set -euo pipefail

REPO="${1:?usage: publish-db.sh <owner/repo> [db_path]}"
DB="${2:-$HOME/.CommiPiste/signatures.db}"
[ -f "$DB" ] || { echo "no DB at $DB" >&2; exit 1; }

# Fold any WAL sidecar into the main .db file first — otherwise we'd gzip a stale main file that's
# missing the most recently indexed projects (they'd live only in <db>-wal).
sqlite3 "$DB" 'PRAGMA wal_checkpoint(TRUNCATE);' >/dev/null

TAG="db-$(date -u +%Y-%m-%d)"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

gzip -c "$DB" > "$work/signatures.db.gz"
sha="$(shasum -a 256 "$DB" | awk '{print $1}')"
projects="$(sqlite3 "$DB" 'SELECT count(*) FROM projects;')"
gz_size="$(wc -c < "$work/signatures.db.gz" | tr -d ' ')"
gz_url="https://github.com/$REPO/releases/download/$TAG/signatures.db.gz"

cat > "$work/signatures.json" <<JSON
{
  "schema": 1,
  "build_date": "$BUILD_DATE",
  "release_tag": "$TAG",
  "projects": $projects,
  "db_sha256": "$sha",
  "gz_size": $gz_size,
  "gz_url": "$gz_url"
}
JSON

gh release create "$TAG" "$work/signatures.db.gz" "$work/signatures.json" \
  --repo "$REPO" --title "Signature DB $TAG" \
  --notes "Prebuilt CommiPiste signature DB — $projects projects, built $BUILD_DATE."

echo "published $TAG ($projects projects) -> $gz_url"

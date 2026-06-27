#!/usr/bin/env python3
"""Rank internet-exposed web software by site count (HTTP Archive), minus what we already index.

One keyless call to HTTP Archive's Tech Report API returns ~3600 web technologies, each with the
number of origins (websites) it was detected on plus a Wappalyzer category. We drop infra/library
categories, drop anything already in our registry, and print the rest as "index-this-next"
candidates ranked by prevalence.

    python scripts/discover.py [--top 40] [--client mobile|desktop]
    SHODAN_API_KEY=... python scripts/discover.py --source shodan   # admin panels HA can't see
    python scripts/discover.py --source selfhosted --tag monitoring,dns,password  # OSS w/ repo+demo
    python scripts/discover.py --self-test          # offline: check the filter logic

Three complementary sources:
- httparchive (default, keyless): counts public home pages — prevalence for server-rendered apps.
- shodan (--source shodan): facet counts of internet-exposed services HA can't see; the count
  endpoint works even on the free OSS plan (host search needs paid membership).
- selfhosted (--source selfhosted): the awesome-selfhosted-data catalog — OSS-only by construction,
  every entry has a git repo (source_code_url) and often a demo_url to verify against; ranked by
  GitHub stars. Best for admin panels. Filter categories with --tag.
ponytail: name + category denylist is a coarse filter; tighten the sets if the top-N is still noisy.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tarfile
import urllib.parse
import urllib.request

TECH_API = "https://cdn.httparchive.org/v1/technologies"
SHODAN_COUNT_API = "https://api.shodan.io/shodan/host/count"
ASH_TARBALL = "https://codeload.github.com/awesome-selfhosted/awesome-selfhosted-data/tar.gz/refs/heads/master"

# Categories that are never a self-hosted app we can fingerprint from a git repo (infra, libs,
# analytics, ads, fonts, CDNs, languages). Matched case-insensitively as substrings of the
# comma-separated category field.
BORING_CATEGORIES = {
    "analytics", "advertising", "tag manager", "retargeting", "a/b testing", "personalisation",
    "font script", "cdn", "javascript librar", "javascript framework", "ui framework",
    "web server", "reverse prox", "programming language", "paas", "iaas", "hosting",
    "ssl/tls", "cookie compliance", "performance", "security", "cookie", "appcelerator",
    "web frameworks", "miscellaneous", "payment processor", "maps", "video player",
    "marketing automation", "operating system", "live chat", "authentication", "email",
    "webmail", "social", "buy now pay later", "shipping", "translation",
}
# High-volume names that slip past the category filter (libs, SaaS, and HA's "ALL" aggregate).
BORING_NAMES = {"jquery", "bootstrap", "modernizr", "core-js", "lodash", "moment.js", "webpack",
                "all", "popper", "shopify", "wix", "squarespace", "google workspace",
                "microsoft 365", "pwa", "http/3"}
# Shodan facets carry no category, so infra/IoT products must be dropped by name. Lowercase
# substrings; merged into the name filter only for --source shodan.
SHODAN_INFRA = {
    # web/mail/db/ftp/ssh servers and protocols
    "nginx", "apache", "openssh", "iis", "lighttpd", "openresty", "tomcat", "jetty", "caddy",
    "exim", "postfix", "dovecot", "sendmail", "mysql", "mariadb", "postgresql", "redis",
    "mongodb", "memcached", "elasticsearch", "ftp", "proftpd", "vsftpd", "pure-ftpd", "dropbear",
    "telnet", "dns", "bind", "ntpd", "snmp", "rtsp", "upnp", "smtp", "imap", "pop3", "kestrel",
    "gunicorn", "werkzeug", "boa", "thttpd", "mini_httpd", "goahead", "httpapi", "openssl",
    # OSes / distros
    "ubuntu", "debian", "centos", "unix", "windows", "red hat", "redhat", "fedora", "alpine",
    "freebsd", "hsts",
    # IoT / appliances / networking gear
    "router", "mikrotik", "routeros", "hikvision", "dahua", "webcam", "modem", "kerio", "cisco",
    "huawei", "synology", "sonicwall", "fortinet", "fortigate", "citrix", "netflix",
    # cloud / CDN / hosted libs
    "amazon", "cloudfront", "cloudflare", "akamai", "fastly", "jsdelivr", "cdnjs",
    "google hosted", "google tag", "google analytics",
    # JS frameworks / languages (http.component noise)
    "angularjs", "angular", "vue.js", "react", "next.js", "express", "node.js", "prototype",
    "requirejs", "extjs", "less", "uvicorn", "python", "java", "asp.net", "twitter",
}


def fetch_technologies(client: str) -> list[tuple[str, int, str]]:
    """Return [(name, site_count, category), ...] from HTTP Archive, most common first."""
    with urllib.request.urlopen(TECH_API, timeout=60) as resp:
        rows = json.load(resp)
    out = [
        (r["technology"], (r.get("origins") or {}).get(client) or 0, r.get("category") or "")
        for r in rows
    ]
    out.sort(key=lambda t: t[1], reverse=True)
    return out


def fetch_shodan(key: str, query: str) -> list[tuple[str, int, str]]:
    """Return [(name, host_count, ""), ...] from Shodan facets (product + http.component), merged.

    The /shodan/host/count endpoint returns facet histograms without consuming result credits, so
    it works on the free OSS plan. category is "" (Shodan has none) → only the name denylist applies.
    """
    params = urllib.parse.urlencode(
        {"key": key, "query": query, "facets": "product:100,http.component:100"}
    )
    with urllib.request.urlopen(f"{SHODAN_COUNT_API}?{params}", timeout=30) as resp:
        facets = json.load(resp).get("facets", {})
    merged: dict[str, int] = {}
    for buckets in facets.values():
        for b in buckets:
            merged[b["value"]] = max(merged.get(b["value"], 0), b["count"])
    return sorted(((n, c, "") for n, c in merged.items()), key=lambda t: t[1], reverse=True)


def fetch_selfhosted(tags: list[str]) -> list[dict]:
    """Return self-hosted OSS apps from awesome-selfhosted-data (one tarball, keyless).

    Each entry already carries a git repo (source_code_url) and license (so it's OSS by
    construction); many carry a demo_url to verify against. Ranked by GitHub stars. If `tags` is
    non-empty, keep only entries whose category tags contain one of those substrings.
    """
    import yaml  # already a project dep (registry YAML)

    with urllib.request.urlopen(ASH_TARBALL, timeout=60) as resp:
        raw = resp.read()
    out = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        for m in tar:
            if not (m.isfile() and "/software/" in m.name and m.name.endswith(".yml")):
                continue
            d = yaml.safe_load(tar.extractfile(m).read()) or {}
            repo = d.get("source_code_url") or ""
            if not any(h in repo for h in ("github.com", "gitlab", "codeberg", ".git")):
                continue  # we can only index a git repo
            cats = d.get("tags") or []
            if tags and not any(t in c.lower() for c in cats for t in tags):
                continue
            out.append({
                "name": d.get("name", ""),
                "stars": d.get("stargazers_count") or 0,
                "demo": bool(d.get("demo_url")),
                "tag": (d.get("current_release") or {}).get("tag", ""),
                "category": cats[0] if cats else "",
                "repo": repo,
            })
    out.sort(key=lambda r: r["stars"], reverse=True)
    return out


def known_terms(registry) -> set[str]:
    """Lowercase product names we already index — registry name + CPE vendor/product."""
    terms = set()
    for p in registry.all():
        terms.add(p.name.lower())
        if p.cpe:  # cpe:2.3:a:vendor:product -> take vendor + product
            terms.update(part for part in p.cpe.split(":")[3:5] if part not in ("", "*"))
    return terms


def candidates(techs: list[tuple[str, int, str]], known: set[str],
               boring_names: set[str] = BORING_NAMES) -> list[tuple[str, int, str]]:
    """Drop boring categories/names and anything we already index; keep prevalence order."""
    out = []
    for name, count, category in techs:
        low, cat = name.lower(), category.lower()
        if any(b in cat for b in BORING_CATEGORIES) or low in boring_names:
            continue
        if any(b in low for b in boring_names if " " not in b and len(b) > 3):
            continue  # substring match for multi-product infra names (e.g. "Apache httpd")
        if any(k in low or low in k for k in known):
            continue
        out.append((name, count, category))
    return out


def _self_test() -> None:
    known = {"nextcloud", "gitlab"}
    techs = [
        ("Google Analytics", 9, "Analytics"),
        ("GitLab", 5, "Git"),
        ("Grafana", 3, "Dashboards"),
        ("jQuery", 8, "JavaScript libraries"),
        ("Nextcloud", 1, "CMS"),
    ]
    got = candidates(techs, known)
    assert got == [("Grafana", 3, "Dashboards")], got  # analytics+lib dropped, gitlab/nextcloud known
    print("self-test ok")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", choices=("httparchive", "shodan", "selfhosted"),
                    default="httparchive",
                    help="httparchive (public home pages), shodan (exposed services), or "
                         "selfhosted (awesome-selfhosted OSS catalog with repo+demo)")
    ap.add_argument("--top", type=int, default=40, help="how many candidates to print")
    ap.add_argument("--client", choices=("mobile", "desktop"), default="mobile",
                    help="HTTP Archive crawl to count (mobile is the larger one)")
    ap.add_argument("--query", default="http.status:200",
                    help="Shodan filter to scope the facet (--source shodan)")
    ap.add_argument("--tag", default="",
                    help="comma-separated category substrings to keep (--source selfhosted)")
    ap.add_argument("--self-test", action="store_true", help="run offline filter check and exit")
    args = ap.parse_args()

    if args.self_test:
        _self_test()
        return 0

    from CommiPiste.registry.loader import load_registry

    known = known_terms(load_registry())
    if args.source == "selfhosted":
        tags = [t.strip().lower() for t in args.tag.split(",") if t.strip()]
        apps = fetch_selfhosted(tags)
        fresh = [a for a in apps if not any(k in a["name"].lower() or a["name"].lower() in k
                                            for k in known)]
        shown = fresh[: args.top]
        width = max((len(a["name"]) for a in shown), default=0)
        for a in shown:
            demo = "demo" if a["demo"] else "  - "
            print(f"{a['stars']:>7}  {demo}  {a['name']:<{width}}  {a['tag']:<14} {a['category']}")
        print(f"\n{len(fresh)} OSS candidates with a git repo, not yet indexed "
              f"(of {len(apps)} cataloged{', tag-filtered' if tags else ''}); showing {len(shown)}.")
        return 0

    if args.source == "shodan":
        key = os.environ.get("SHODAN_API_KEY")
        if not key:
            print("set SHODAN_API_KEY", file=sys.stderr)
            return 2
        techs = fetch_shodan(key, args.query)
        cand = candidates(techs, known, boring_names=BORING_NAMES | SHODAN_INFRA)
        seen, unit = len(techs), "products"
    else:
        techs = fetch_technologies(args.client)
        cand = candidates(techs, known)
        seen, unit = len(techs), "technologies"
    cand = cand[: args.top]

    width = max((len(n) for n, _, _ in cand), default=0)
    for name, count, category in cand:
        print(f"{count:>10,}  {name:<{width}}  {category}".rstrip())
    print(f"\n{len(cand)} candidates not yet indexed (of {seen} {unit} seen).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Render scan results as a self-contained, interactive HTML report.

The output is a single HTML file with embedded CSS + vanilla JS (no external assets, works
offline). Per target it shows each identified software unit, the deployed commit (linked), the
version, the exact files we checked (each linked to the host at that commit, with a match/mismatch
status and how tightly it pins the version), and — when CVE enrichment ran — a vulnerability summary
with severity badges and links to the NVD.

Groundwork: ``render_html`` is intentionally data-driven (it consumes the same ``ScanResult``
models as the JSON/human reports), so richer interactivity can be layered on without touching the
scan/match pipeline.
"""

from __future__ import annotations

import html
import json

from .models import Finding, ScanResult
from .report import NVD_KEY_URL, _plural, candidate_commit_urls, nvd_key_hint


def _nvd_hint_html(error: str | None) -> str:
    """A clickable 'set NVD_API_KEY' hint div when an NVD failure is shown and no key is set."""
    if nvd_key_hint(error) is None:
        return ""
    return (
        '<div class="note act">fix: get a free NVD API key, then '
        "<code>export NVD_API_KEY=&lt;key&gt;</code> — "
        f'<a href="{NVD_KEY_URL}" target="_blank" rel="noopener">request a key</a></div>'
    )

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]


def _e(text: object) -> str:
    return html.escape(str(text), quote=True)


def _conf_class(label: str) -> str:
    return {"high": "ok", "medium": "warn", "low": "warn", "none": "bad"}.get(label, "warn")


def _link(url: str | None, text: str, *, mono: bool = False) -> str:
    cls = ' class="mono"' if mono else ""
    if not url:
        return f'<span{cls}>{_e(text)}</span>'
    return f'<a{cls} href="{_e(url)}" target="_blank" rel="noopener">{_e(text)}</a>'


def _vuln_via(v) -> str:
    """Source attribution stating exactly what each source checked.

    e.g. 'NVD: 4 versions, OSV: 4 candidate commits'.
    """
    parts = []
    if "NVD" in v.sources:
        parts.append(f"NVD: {_plural(v.versions_checked or 1, 'version')}")
    if "OSV" in v.sources:
        parts.append(f"OSV: {_plural(v.commits_checked or 1, 'candidate commit')}")
    return ", ".join(parts) if parts else ", ".join(_e(s) for s in v.sources)


def _vuln_block(f: Finding) -> str:
    v = f.vulnerabilities
    if v is None:
        return ""
    if not v.total:
        via = f" (via {_vuln_via(v)})" if v.sources else ""
        if v.error and not v.sources:
            return (
                f'<div class="vuln muted">Vulnerability lookup: {_e(v.error)}</div>'
                + _nvd_hint_html(v.error)
            )
        return (
            f'<div class="vuln muted">No known vulnerabilities for this version{via}.</div>'
            + _nvd_hint_html(v.error)
        )
    chips = "".join(
        f'<span class="sev sev-{sev.lower()}">{sev} {v.by_severity.get(sev, 0)}</span>'
        for sev in _SEVERITY_ORDER
        if v.by_severity.get(sev)
    )
    via = f'<span class="via">via {_vuln_via(v)}</span>' if v.sources else ""
    rows = []
    for cve in v.top:
        sev = (cve.severity or "NONE").upper()
        score = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "—"
        desc = (cve.description or "").strip()
        if len(desc) > 240:
            desc = desc[:240].rsplit(" ", 1)[0] + "…"
        srcs = "".join(f'<span class="src">{_e(s)}</span>' for s in cve.sources)
        rows.append(
            "<tr>"
            f'<td><span class="sev sev-{sev.lower()}">{sev}</span></td>'
            f'<td class="mono">{score}</td>'
            f'<td class="cve">{_link(cve.url, cve.cve_id, mono=True)}</td>'
            f'<td class="srcs">{srcs}</td>'
            f'<td class="desc">{_e(desc)}</td>'
            "</tr>"
        )
    more = ""
    if v.total > len(v.top):
        link = _link(v.nvd_url, "view all on NVD") if v.nvd_url else "view on NVD/OSV"
        more = f'<div class="vuln-more">{v.total - len(v.top)} more — {link}</div>'
    note = f'<div class="vuln-more muted">note: {_e(v.error)}</div>' if v.error else ""
    note += _nvd_hint_html(v.error)
    search = _link(v.nvd_url, "NVD search") if v.nvd_url else ""
    return (
        '<div class="vuln">'
        f'<div class="vuln-head"><strong>Vulnerabilities</strong> {chips} {via} {search}</div>'
        '<table class="vuln-table"><thead><tr>'
        "<th>Severity</th><th>CVSS</th><th>CVE</th><th>Source</th><th>Summary</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
        + more
        + note
        + "</div>"
    )


def _files_block(f: Finding) -> str:
    if not f.files:
        return ""
    rows = []
    for fe in f.files:
        oid = (fe.oid or "")[:12]
        pin = (
            f'<span class="pin" title="appears in {fe.pin} indexed refs (lower = more '
            f'discriminating)">{fe.pin}</span>'
            if fe.status == "match" and fe.pin
            else ""
        )
        rows.append(
            "<tr>"
            f'<td><span class="fstat fstat-{fe.status}">{fe.status.replace("_", " ")}</span></td>'
            f"<td>{_link(fe.url, fe.rel_path, mono=True)}</td>"
            f'<td class="mono dim">{_e(oid)}</td>'
            f"<td>{pin}</td>"
            "</tr>"
        )
    return (
        '<details class="files"><summary>Files checked '
        f"({len(f.files)})</summary>"
        '<table class="file-table"><thead><tr>'
        "<th>status</th><th>file</th><th>blob</th><th>pin</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></details>"
    )


def _finding_card(f: Finding) -> str:
    c = f.confidence
    if f.needs_active_probe:
        conf_badge = (
            '<span class="badge warn" title="version requires active probing (--active)">'
            "active probe needed</span>"
        )
    elif c.label == "none":
        # Software detected (banner/user) but no version pinned. Informational, not a danger signal.
        conf_badge = (
            '<span class="badge muted" title="software detected, but its version was not '
            'identified">version not found</span>'
        )
    else:
        conf_badge = (
            f'<span class="badge {_conf_class(c.label)}" title="how confidently the version was '
            f'identified">confidence: {_e(c.label)}</span>'
        )
    badges = [
        conf_badge,
        f'<span class="badge muted">{_e(f.detected_by)}</span>',
    ]
    if f.modified:
        badges.append('<span class="badge warn">modified</span>')
    nvuln = f.vulnerabilities.total if f.vulnerabilities else 0
    if nvuln:
        badges.append(f'<span class="badge bad">{nvuln} CVE</span>')

    meta = []
    if f.version:
        basis = "" if f.match_basis == "exact" else f" <span class='dim'>(by {_e(f.match_basis)})</span>"
        meta.append(f'<div><span class="k">version</span>{_e(f.version)}{basis}</div>')
    if f.version_range:
        meta.append(
            '<div title="range of releases the matched files appear in — the deployment is somewhere '
            f'in this span"><span class="k">evidence range</span>{_e(f.version_range)}</div>'
        )
    if f.commit_sha:
        inferred = (
            ' <span class="dim" title="derived from the version tag, not observed — may differ if '
            'the deployment is patched/forked">(inferred from version tag)</span>'
            if f.commit_inferred
            else ""
        )
        meta.append(
            f'<div><span class="k">commit</span>'
            f'{_link(f.commit_url, f.commit_sha[:12], mono=True)}{inferred}</div>'
        )
    meta.append(
        f'<div><span class="k">match</span>{c.files_matched}/{c.files_probed} '
        f"<span class='dim'>(score {c.score:.2f})</span></div>"
    )
    if f.candidate_versions:
        shown = ", ".join(_e(x) for x in f.candidate_versions[:8])
        more = "" if len(f.candidate_versions) <= 8 else f" (+{len(f.candidate_versions) - 8})"
        meta.append(
            f'<div class="wide-nowrap"><span class="k">candidates</span>'
            f'<span class="mono">{shown}{more}</span></div>'
        )
    cand_urls = candidate_commit_urls(f)
    if cand_urls:
        links = " ".join(
            _link(u, u.rstrip("/").rsplit("/", 1)[-1][:12], mono=True) for u in cand_urls[:8]
        )
        extra = "" if len(cand_urls) <= 8 else f' <span class="dim">(+{len(cand_urls) - 8})</span>'
        meta.append(
            f'<div class="cand-commits"><span class="k">candidate commits</span>{links}{extra}</div>'
        )

    note = ""
    if f.needs_active_probe:
        note = (
            '<div class="note act">Active probing required — re-run with <code>--active</code> to '
            "read the version for this platform (its served assets are bundled, not git-blob "
            "fingerprintable).</div>"
        )
    elif not f.commit_sha and c.files_probed == 0 and not f.version:
        if f.detected_by == "active":
            msg = "Active probe found no version at the configured endpoint."
        elif not f.indexed:
            msg = "not indexed — run <code>CommiPiste index</code> for this project"
        else:
            msg = (
                "no probe files served by the target — asset paths differ, or assets are "
                "generated/bundled (not fingerprintable)"
            )
        note = f'<div class="note muted">{msg}</div>'

    return (
        '<div class="finding">'
        f'<div class="fhead"><h3>{_e(f.software)}</h3><div class="badges">{"".join(badges)}</div></div>'
        f'<div class="meta">{"".join(meta)}</div>'
        + note
        + _vuln_block(f)
        + _files_block(f)
        + "</div>"
    )


def _target_card(r: ScanResult) -> str:
    title = (
        '<span class="urlk">URL:</span> '
        + _e(r.url)
        + (f' <span class="dim">(path: {_e(r.path)})</span>' if r.path else "")
    )
    if r.error:
        body = f'<div class="error">{_e(r.error)}</div>'
    elif not r.findings:
        body = '<div class="muted">no findings</div>'
    else:
        body = "".join(_finding_card(f) for f in r.findings)
    host = _e(r.url)
    return f'<section class="target" data-host="{host}"><h2>{title}</h2>{body}</section>'


def _stats(results: list[ScanResult]) -> str:
    targets = len(results)
    findings = sum(len(r.findings) for r in results)
    cves = sum(
        (f.vulnerabilities.total if f.vulnerabilities else 0)
        for r in results
        for f in r.findings
    )
    crit = sum(
        (f.vulnerabilities.by_severity.get("CRITICAL", 0) if f.vulnerabilities else 0)
        for r in results
        for f in r.findings
    )
    cells = [
        ("targets", targets, ""),
        ("software found", findings, ""),
        ("known CVEs", cves, "bad" if cves else ""),
        ("critical", crit, "bad" if crit else ""),
    ]
    return '<div class="stats">' + "".join(
        f'<div class="stat {cls}"><span class="num">{n}</span><span class="lbl">{_e(lbl)}</span></div>'
        for lbl, n, cls in cells
    ) + "</div>"


_CSS = """
:root{--bg:#0e1116;--panel:#161b22;--panel2:#1c232d;--line:#2a3340;--fg:#e6edf3;
--dim:#8b949e;--accent:#58a6ff;--ok:#3fb950;--warn:#d29922;--bad:#f85149;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.dim,.muted{color:var(--dim)}
header{position:sticky;top:0;background:linear-gradient(180deg,#0e1116,#0e1116ee);
border-bottom:1px solid var(--line);padding:18px 28px;backdrop-filter:blur(6px);z-index:5}
header h1{margin:0;font-size:18px;letter-spacing:.3px}
header .sub{color:var(--dim);font-size:12px;margin-top:2px}
.wrap{max-width:1080px;margin:0 auto;padding:24px 28px 64px}
.toolbar{display:flex;gap:10px;align-items:center;margin:18px 0;flex-wrap:wrap}
.toolbar input{background:var(--panel);border:1px solid var(--line);color:var(--fg);
border-radius:8px;padding:8px 12px;min-width:240px}
.toolbar label{color:var(--dim);font-size:13px;display:flex;gap:6px;align-items:center;cursor:pointer}
.stats{display:flex;gap:14px;flex-wrap:wrap;margin:8px 0 4px}
.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;
padding:14px 18px;min-width:120px}
.stat .num{display:block;font-size:26px;font-weight:700}.stat .lbl{color:var(--dim);font-size:12px}
.stat.bad .num{color:var(--bad)}
section.target{background:var(--panel);border:1px solid var(--line);border-radius:14px;
padding:18px 20px;margin:18px 0}
section.target>h2{margin:0 0 6px;font-size:16px;word-break:break-all}
.finding{border-top:1px solid var(--line);margin-top:14px;padding-top:14px}
.finding:first-of-type{border-top:none;margin-top:8px}
.fhead{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.fhead h3{margin:0;font-size:15px}
.badges{display:flex;gap:6px;flex-wrap:wrap}
.badge{font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid var(--line);
text-transform:uppercase;letter-spacing:.4px}
.badge.ok{color:var(--ok);border-color:#1f6f2e}.badge.warn{color:var(--warn);border-color:#6b5410}
.badge.bad{color:var(--bad);border-color:#7d2620}.badge.muted{color:var(--dim)}
.meta{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:6px 22px;
margin:12px 0}
.meta .k{display:inline-block;color:var(--dim);width:96px;font-size:12px}
.cand-commits{grid-column:1/-1}.cand-commits a{margin-right:10px}
.wide-nowrap{grid-column:1/-1;white-space:nowrap;overflow-x:auto}
.urlk{color:var(--dim);font-weight:600}
.note{margin:8px 0;font-size:13px}
.note.act{color:var(--warn)}
code{font-family:ui-monospace,monospace;background:#1c232d;padding:1px 5px;border-radius:4px}
.vuln{background:var(--panel2);border:1px solid var(--line);border-radius:10px;
padding:12px 14px;margin:10px 0}
.vuln-head{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:8px}
.sev{font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;color:#0e1116}
.sev-critical{background:#f85149}.sev-high{background:#fb8500}.sev-medium{background:#d29922}
.sev-low{background:#3fb950}.sev-none{background:#6e7681;color:#fff}
table{border-collapse:collapse;width:100%;font-size:13px}
th{text-align:left;color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase;
padding:6px 10px;border-bottom:1px solid var(--line)}
td{padding:6px 10px;border-bottom:1px solid #20272f;vertical-align:top}
td.desc{color:var(--dim)}
.vuln-table td.cve,.vuln-table th:nth-child(3){white-space:nowrap;width:1%}
.via{color:var(--dim);font-size:12px}
.srcs{white-space:nowrap}
.src{font-size:10px;padding:1px 6px;border-radius:5px;border:1px solid var(--line);
color:var(--dim);margin-right:3px}
.vuln-more{margin-top:8px;font-size:12px;color:var(--dim)}
details.files{margin-top:10px}
details.files>summary{cursor:pointer;color:var(--accent);font-size:13px;user-select:none}
.fstat{font-size:11px;padding:1px 7px;border-radius:6px;border:1px solid var(--line)}
.fstat-match{color:var(--ok);border-color:#1f6f2e}
.fstat-unknown_hash{color:var(--warn);border-color:#6b5410}
.fstat-missing{color:var(--dim)}.fstat-unexpected{color:var(--accent)}
.pin{font-family:ui-monospace,monospace;color:var(--dim)}
.error{color:var(--bad)}.hidden{display:none}
footer{color:var(--dim);font-size:12px;text-align:center;padding:24px}
"""

_JS = """
const q=document.getElementById('flt');
const onlyV=document.getElementById('onlyvuln');
function apply(){
  const term=(q.value||'').toLowerCase();
  document.querySelectorAll('section.target').forEach(s=>{
    const host=(s.dataset.host||'').toLowerCase();
    const hasV=s.querySelector('.badge.bad')!==null;
    const show=(!term||host.includes(term))&&(!onlyV.checked||hasV);
    s.classList.toggle('hidden',!show);
  });
}
q.addEventListener('input',apply);onlyV.addEventListener('change',apply);
"""


def render_html(results: list[ScanResult], *, title: str = "CommiPiste report") -> str:
    """Build a single self-contained interactive HTML report from scan results."""
    cards = "".join(_target_card(r) for r in results)
    # Embed the raw results too, so downstream tooling can re-use the report as a data carrier.
    data = json.dumps([json.loads(r.to_json(indent=0)) for r in results])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)}</title>
<style>{_CSS}</style></head>
<body>
<header><h1>CommiPiste</h1>
<div class="sub">For each scanned site: which open-source software it runs, the exact version and
git commit deployed, and the known vulnerabilities affecting that version.</div></header>
<div class="wrap">
{_stats(results)}
<div class="toolbar">
  <input id="flt" type="search" placeholder="filter by host…">
  <label><input id="onlyvuln" type="checkbox"> only targets with CVEs</label>
</div>
{cards}
<footer>Generated by CommiPiste. Vulnerability data from the NIST NVD and OSV.dev. Commit/file links go to the source host.</footer>
</div>
<script id="cr-data" type="application/json">{_e(data)}</script>
<script>{_JS}</script>
</body></html>"""

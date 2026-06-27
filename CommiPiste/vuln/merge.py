"""Merge vulnerabilities from multiple sources into one deduplicated summary."""

from __future__ import annotations

from typing import Optional

from ..models import Vulnerability, VulnSummary
from .cvss import SEVERITY_RANK


def build_summary(
    cpe: Optional[str],
    version: Optional[str],
    vulns: list[Vulnerability],
    *,
    nvd_url: Optional[str] = None,
    sources: Optional[list[str]] = None,
    max_cves: int = 10,
    versions_checked: int = 0,
    commits_checked: int = 0,
    error: Optional[str] = None,
) -> VulnSummary:
    """Dedup advisories (by id) across sources, rank by severity, and assemble a VulnSummary.

    When the same CVE comes from more than one source, the entries are merged: ``sources`` is the
    union, and the highest CVSS score (and matching severity) and the first non-empty description/URL
    win.
    """
    dedup: dict[str, Vulnerability] = {}
    for v in vulns:
        key = v.cve_id
        if key in dedup:
            ex = dedup[key]
            ex.sources = sorted(set(ex.sources) | set(v.sources))
            if (v.cvss_score or 0.0) > (ex.cvss_score or 0.0):
                ex.cvss_score, ex.severity = v.cvss_score, v.severity
            if not ex.description and v.description:
                ex.description = v.description
            if not ex.published and v.published:
                ex.published = v.published
        else:
            dedup[key] = v.model_copy()

    merged = list(dedup.values())
    merged.sort(
        key=lambda v: (SEVERITY_RANK.get((v.severity or "NONE").upper(), 9), -(v.cvss_score or 0.0))
    )
    by_severity: dict[str, int] = {}
    for v in merged:
        if v.severity:
            by_severity[v.severity] = by_severity.get(v.severity, 0) + 1
    by_severity = dict(sorted(by_severity.items(), key=lambda kv: SEVERITY_RANK.get(kv[0], 9)))

    return VulnSummary(
        cpe=cpe,
        version=version,
        total=len(merged),
        by_severity=by_severity,
        top=merged[:max_cves],
        nvd_url=nvd_url,
        sources=sources or [],
        versions_checked=versions_checked,
        commits_checked=commits_checked,
        error=error,
    )

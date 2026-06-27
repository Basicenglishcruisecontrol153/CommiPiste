"""CommiPiste — fingerprint versions of open-source web software via git blob OIDs.

Public library API (interface surface: CLI + Python library + REST API).
"""

from __future__ import annotations

from .models import (
    Discrepancy,
    FileEvidence,
    Finding,
    MatchConfidence,
    Project,
    ScanResult,
    VulnSummary,
    Vulnerability,
)

__all__ = [
    "Project",
    "ScanResult",
    "Finding",
    "Discrepancy",
    "FileEvidence",
    "MatchConfidence",
    "Vulnerability",
    "VulnSummary",
    "index_project",
    "scan_target",
    "enrich_result",
    "render_html",
    "__version__",
]

__version__ = "0.1.0"


async def index_project(*args, **kwargs):
    """Build the signature database for a project. See :mod:`CommiPiste.indexer.builder`."""
    from .indexer.builder import index_project as _impl

    return await _impl(*args, **kwargs)


async def scan_target(*args, **kwargs):
    """Scan a target and identify its commit. See :mod:`CommiPiste.detector.scan`."""
    from .detector.scan import scan_target as _impl

    return await _impl(*args, **kwargs)


async def enrich_result(*args, **kwargs):
    """Attach NVD/CVE summaries to a scan result. See :mod:`CommiPiste.vuln`."""
    from .vuln import enrich_result as _impl

    return await _impl(*args, **kwargs)


def render_html(*args, **kwargs) -> str:
    """Render scan results as an interactive HTML report. See :mod:`CommiPiste.report_html`."""
    from .report_html import render_html as _impl

    return _impl(*args, **kwargs)

"""CVSS v3.x base-score computation from a vector string, and severity ranking.

OSV returns CVSS as a vector (e.g. ``CVSS:3.1/AV:N/AC:L/...``) rather than a numeric base score, so
we compute the score with the official CVSS 3.1 formula to make OSV results comparable/sortable with
the numeric scores the NVD returns.
"""

from __future__ import annotations

import math
from typing import Optional

# Most→least severe; used for sorting and stable summary ordering across sources.
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # scope unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}  # scope changed


def severity_bucket(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score == 0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def _roundup(x: float) -> float:
    """CVSS-spec roundup: round up to the nearest 0.1."""
    i = round(x * 100000)
    if i % 10000 == 0:
        return i / 100000
    return (math.floor(i / 10000) + 1) / 10.0


def score_from_vector(vector: str) -> tuple[Optional[float], Optional[str]]:
    """Compute (base_score, severity) from a CVSS v3.x vector string. (None, None) if unparseable."""
    if not vector or not vector.startswith("CVSS:3"):
        return None, None
    metrics = {}
    for part in vector.split("/")[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            metrics[k] = v
    try:
        scope_changed = metrics.get("S") == "C"
        pr_tbl = _PR_C if scope_changed else _PR_U
        exploitability = (
            8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr_tbl[metrics["PR"]] * _UI[metrics["UI"]]
        )
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
    except KeyError:
        return None, None
    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = _roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = _roundup(min(impact + exploitability, 10))
    return score, severity_bucket(score)

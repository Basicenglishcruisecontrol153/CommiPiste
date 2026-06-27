"""CommiPiste domain models (pydantic v2).

Terminology:
  - ref       — an indexed point in history (a tag/release or a diff-commit that changes public-dir)
  - blob OID  — git content hash, sha1("blob "+len+"\\0"+content); the canonical hash
  - signature — a (rel_path, oid, ref) triple; the signature DB is the set of such triples
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class ProjectKind(str, Enum):
    CORE = "core"
    PLUGIN = "plugin"


# --------------------------------------------------------------------------- #
# Project definitions (registry YAML -> this type)                            #
# --------------------------------------------------------------------------- #


class BannerPathProbe(BaseModel):
    """Detect presence/version of software by requesting a specific path."""

    path: str
    match: Optional[str] = None  # substring/regex expected in the response


class BannerSpec(BaseModel):
    """Banner-based software auto-detection signals.

    `headers` maps a header name to a regex its value must match — mere presence of a header (e.g.
    a generic ``X-Powered-By``) is not a signal, which previously caused false positives on
    unrelated PHP sites. `paths` are the strongest signal (a dedicated marker endpoint).
    """

    headers: dict[str, str] = Field(default_factory=dict)
    paths: list[BannerPathProbe] = Field(default_factory=list)
    body_regex: list[str] = Field(default_factory=list)


class DependentsSpec(BaseModel):
    """Describes dependent projects living in the same public dir."""

    pattern: Optional[str] = None  # e.g. "apps/*"
    projects: list[str] = Field(default_factory=list)  # explicit related project names


class VersionProbe(BaseModel):
    """Active version extraction (opt-in via `--active`).

    For software whose served assets are bundled build artifacts (not git-blob fingerprintable) but
    which expose their version at an endpoint — e.g. Mattermost's ``X-Version-Id`` header. The probe
    requests each path and pulls the version out of a response header (if `header` set) or the body,
    via `regex` (capture group 1). Because it queries dedicated (often API) endpoints rather than
    static assets, it is gated behind `--active`.
    """

    paths: list[str] = Field(default_factory=lambda: [""])  # relative endpoints to query ("" = base)
    method: str = "GET"  # "GET" or "POST" (e.g. Zabbix's JSON-RPC apiinfo.version)
    body: Optional[str] = None  # request body for POST (e.g. a JSON-RPC payload)
    content_type: Optional[str] = None  # Content-Type for POST (defaults to application/json)
    header: Optional[str] = None  # response header to read; if None, match against the body
    regex: str  # capture group 1 = version (unless version_template is set)
    # Optional: assemble the version from multiple regex groups, e.g. an API returning
    # {"major":2,"minor":7,"patch":5} -> regex captures 3 groups, template "{0}.{1}.{2}" -> "2.7.5".
    version_template: Optional[str] = None
    commit_regex: Optional[str] = None  # optional capture group 1 = commit/build id (observed)
    # If no commit is observed, infer it from the release tag matching the version (via the repo's
    # tags). Inexact — the tag's commit, not the actual deployed one (mark Finding.commit_inferred).
    resolve_commit_from_tags: bool = False


class Project(BaseModel):
    """Project definition loaded from a registry YAML.

    Host-agnostic: `repo_url` may point at any git remote (GitHub, GitLab, self-hosted, SourceForge)
    since indexing only shells out to `git`. `commit_url_tpl` is just a format string, so set it to
    the host's commit-URL shape (e.g. GitLab uses ``/-/commit/{sha}``).
    """

    model_config = ConfigDict(populate_by_name=True)

    name: str
    repo_url: str
    # Index source backend: "git" (default, any git host) or "wporg" (wordpress.org SVN over HTTP,
    # for plugins/themes not mirrored to git). For "wporg", `name` is the plugin slug.
    source: str = "git"
    # Accepts `commit_url_tpl` (preferred) or the legacy `github_commit_url_tpl` key.
    # Uses /tree/{sha} (browse the whole repo at that commit), not /commit/{sha} (diff only).
    commit_url_tpl: str = Field(
        default="{repo_url}/tree/{sha}",
        validation_alias=AliasChoices("commit_url_tpl", "github_commit_url_tpl"),
    )
    # Repo subdirectory that maps to the deployed web root (e.g. phpBB ships its app under
    # "phpBB/" but serves it at "/"). public_paths are relative to that web root; this prefix is
    # prepended when reading the repo and stripped from stored paths so they match served URLs.
    repo_subdir: str = ""
    # Where this project is served under a PARENT's web root, for dependent scanning.
    # E.g. a WordPress plugin is served at "wp-content/plugins/<slug>". Prepended to the fetch base
    # when this project is scanned as a dependent.
    served_prefix: str = ""
    public_paths: list[str] = Field(default_factory=list)
    banners: BannerSpec = Field(default_factory=BannerSpec)
    probe_files: list[str] = Field(default_factory=list)
    dependents: DependentsSpec = Field(default_factory=DependentsSpec)
    # Active version extraction (opt-in via --active) for build-artifact apps that expose a version
    # at an endpoint instead of serving git-blob-matchable assets.
    version_probe: Optional[VersionProbe] = None
    kind: ProjectKind = ProjectKind.CORE
    parent: Optional[str] = None
    is_local: bool = False  # True for user-supplied/private projects
    # CPE 2.3 product prefix (without version), e.g. "cpe:2.3:a:nextcloud:nextcloud". When set, the
    # NVD/CVE enrichment step can look up known vulnerabilities for the matched version. Optional.
    cpe: Optional[str] = None

    def commit_url(self, sha: str) -> str:
        return self.commit_url_tpl.format(repo_url=self.repo_url.rstrip("/"), sha=sha)


# --------------------------------------------------------------------------- #
# Signatures (what lives in the DB)                                           #
# --------------------------------------------------------------------------- #


class Ref(BaseModel):
    """An indexed point in history."""

    sha: str
    tag: Optional[str] = None
    committed_date: Optional[str] = None
    is_release: bool = False


class FileSignature(BaseModel):
    """A file paired with its hash (used for fetching from a target / indexing)."""

    rel_path: str
    oid: str  # git blob OID


# --------------------------------------------------------------------------- #
# Scan result                                                      #
# --------------------------------------------------------------------------- #


class MatchConfidence(BaseModel):
    """Confidence metric for an identification."""

    files_probed: int = 0
    files_matched: int = 0
    candidate_count: int = 0  # how many refs remain candidates after narrowing
    score: float = 0.0  # 0..1, fraction of files matched
    exact: bool = False  # True if narrowed down to a single commit

    @property
    def label(self) -> str:
        if self.exact and self.score >= 0.99:
            return "high"
        if self.score >= 0.6:
            return "medium"
        if self.score > 0:
            return "low"
        return "none"


class Discrepancy(BaseModel):
    """A mismatch: a file that matches no commit, or is missing."""

    rel_path: str
    kind: str  # "unknown_hash" | "missing" | "unexpected"
    detail: Optional[str] = None


class FileEvidence(BaseModel):
    """Per-file evidence behind a finding — what we checked and where it points.

    Powers the detailed (esp. HTML) report: each probed file, the git blob OID we observed, whether
    it matched the deployed commit, how tightly it pins the version (``pin`` = number of refs that
    share this exact content; smaller = more discriminating), and a link to that file on the host at
    the matched commit.
    """

    rel_path: str
    oid: Optional[str] = None  # git blob OID observed over HTTP (None when the file was missing)
    status: str  # "match" | "unknown_hash" | "missing" | "unexpected"
    pin: int = 0  # refs sharing this exact content (only meaningful for status == "match")
    url: Optional[str] = None  # link to this file on the host at the matched commit


class Vulnerability(BaseModel):
    """A single advisory affecting the matched version/commit.

    Aggregated across vulnerability sources (NVD, OSV); ``sources`` lists which ones reported it.
    """

    cve_id: str  # CVE id when known, else the source advisory id (e.g. a GHSA-…)
    severity: Optional[str] = None  # CRITICAL | HIGH | MEDIUM | LOW | NONE
    cvss_score: Optional[float] = None  # CVSS base score (v3.1 preferred)
    description: Optional[str] = None  # English summary
    url: str  # advisory detail page (NVD for CVEs, else OSV)
    published: Optional[str] = None  # ISO date
    sources: list[str] = Field(default_factory=list)  # e.g. ["NVD", "OSV"]


class VulnSummary(BaseModel):
    """Vulnerability summary for one finding: counts + the most severe advisories + links."""

    cpe: Optional[str] = None
    version: Optional[str] = None
    total: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)  # e.g. {"CRITICAL": 2, "HIGH": 5}
    top: list[Vulnerability] = Field(default_factory=list)  # most severe, capped
    nvd_url: Optional[str] = None  # human-browsable NVD search page for this product+version
    sources: list[str] = Field(default_factory=list)  # which sources contributed (NVD/OSV)
    versions_checked: int = 0  # how many candidate versions were checked against the NVD
    commits_checked: int = 0  # how many candidate commits were checked against OSV
    error: Optional[str] = None  # set if the lookup failed (rate limit, network, no CPE)

    @property
    def headline(self) -> str:
        if self.error:
            return self.error
        if not self.total:
            return "no known CVEs for this version"
        parts = [f"{n} {sev.lower()}" for sev, n in self.by_severity.items() if n]
        return f"{self.total} known CVE(s)" + (f" — {', '.join(parts)}" if parts else "")


class Finding(BaseModel):
    """An identified unit of software on the target (core or dependent project)."""

    software: str
    detected_by: str  # "banner" | "user" | "dependent" | "active"
    indexed: bool = True  # False if the project has no signatures in the DB (vs. target served none)
    needs_active_probe: bool = False  # detected, but version needs `--active` (build-artifact app)
    commit_sha: Optional[str] = None
    commit_inferred: bool = False  # commit derived from the version's release tag, not observed
    commit_range: list[str] = Field(default_factory=list)  # candidate shas if not narrowed to one
    commit_url: Optional[str] = None
    version: Optional[str] = None  # headline matched tag/release
    candidate_versions: list[str] = Field(default_factory=list)  # candidate version labels (tags)
    key_files: list[str] = Field(default_factory=list)  # files matching ONLY the candidate versions
    version_range: Optional[str] = None  # span of releases the evidence covers (mixed deployments)
    match_basis: str = "exact"  # "exact" | "anchor" | "support" — how the version was resolved
    confidence: MatchConfidence = Field(default_factory=MatchConfidence)
    discrepancies: list[Discrepancy] = Field(default_factory=list)
    files: list[FileEvidence] = Field(default_factory=list)  # per-file evidence (report detail)
    vulnerabilities: Optional[VulnSummary] = None  # populated by the NVD enrichment step
    modified: bool = False  # some files matched no commit, or files disagree on the version

class ScanResult(BaseModel):
    """Result of scanning a single target."""

    url: str
    path: Optional[str] = None
    findings: list[Finding] = Field(default_factory=list)
    error: Optional[str] = None

    def to_json(self, indent: int = 2) -> str:
        return self.model_dump_json(indent=indent)

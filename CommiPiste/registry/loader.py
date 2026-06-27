"""Load project definitions from YAML.

Definitions come from two sources, both producing :class:`CommiPiste.models.Project`:
  - built-in: shipped with the package as a single ``registry/builtin/platforms.yaml`` — a
    ``defaults:`` block (common values, merged into every entry) + a ``platforms:`` map
    (``name -> overrides``). A platform may ``extends: <other>`` to inherit another's fields.
  - local: user/private projects under the data dir (``~/.CommiPiste/registry/*.yaml``).

Local definitions override built-ins with the same name.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import yaml

from ..config import Settings, get_settings
from ..models import Project

_BUILTIN_DIR = Path(__file__).parent / "builtin"
_BUILTIN_FILE = _BUILTIN_DIR / "platforms.yaml"


class Registry:
    def __init__(self, projects: dict[str, Project]) -> None:
        self._projects = projects

    def get(self, name: str) -> Project | None:
        return self._projects.get(name)

    def names(self) -> list[str]:
        return sorted(self._projects)

    def all(self) -> list[Project]:
        return [self._projects[n] for n in self.names()]


def _load_dir(directory: Path, *, is_local: bool) -> dict[str, Project]:
    out: dict[str, Project] = {}
    if not directory.exists():
        return out
    for file in sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml")):
        data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        data.setdefault("is_local", is_local)
        project = Project.model_validate(data)
        out[project.name] = project
    return out


def _load_combined(file: Path, *, is_local: bool) -> dict[str, Project]:
    """Load the combined ``defaults: + platforms:`` file. ``platforms.<name>`` is a dict of overrides
    merged over ``defaults`` (platform wins); an optional ``extends: <name>`` inherits another entry."""
    raw = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
    defaults = raw.get("defaults") or {}
    platforms = raw.get("platforms") or {}
    out: dict[str, Project] = {}
    for name, spec in platforms.items():
        spec = spec or {}
        base = platforms.get(spec["extends"]) or {} if "extends" in spec else {}
        merged = {**defaults, **base, **spec}
        merged.pop("extends", None)
        merged["name"] = name
        merged.setdefault("is_local", is_local)
        out[name] = Project.model_validate(merged)
    return out


def load_registry(settings: Settings | None = None) -> Registry:
    settings = settings or get_settings()
    projects = _load_combined(_BUILTIN_FILE, is_local=False)  # shipped with the package
    projects.update(_load_dir(settings.local_registry_dir, is_local=True))  # local overrides
    return Registry(projects)


def add_local_project(yaml_path: Path | str, settings: Settings | None = None) -> Project:
    """Copy a project-definition YAML into the local registry and validate it."""
    settings = settings or get_settings()
    settings.ensure_dirs()
    src = Path(yaml_path)
    data = yaml.safe_load(src.read_text(encoding="utf-8")) or {}
    data["is_local"] = True
    project = Project.model_validate(data)  # validate before copying
    dest = settings.local_registry_dir / f"{project.name}.yaml"
    shutil.copyfile(src, dest)
    return project

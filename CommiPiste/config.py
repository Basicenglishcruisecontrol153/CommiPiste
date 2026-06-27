"""CommiPiste settings and paths.

All working data lives under the data directory (default ~/.CommiPiste),
overridable via the COMMIPISTE_HOME environment variable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ENV_HOME = "COMMIPISTE_HOME"


def _default_home() -> Path:
    override = os.environ.get(ENV_HOME)
    if override:
        return Path(override).expanduser()
    return Path.home() / ".CommiPiste"


@dataclass(frozen=True)
class Settings:
    home: Path

    @property
    def db_path(self) -> Path:
        return self.home / "signatures.db"

    @property
    def repos_dir(self) -> Path:
        """Directory holding bare clones of indexed repositories."""
        return self.home / "repos"

    @property
    def local_registry_dir(self) -> Path:
        """Directory for user-supplied/private project definitions."""
        return self.home / "registry"

    def ensure_dirs(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        self.repos_dir.mkdir(parents=True, exist_ok=True)
        self.local_registry_dir.mkdir(parents=True, exist_ok=True)


def get_settings(home: Path | str | None = None) -> Settings:
    if home is not None:
        return Settings(home=Path(home).expanduser())
    return Settings(home=_default_home())

"""Project registry: built-in and user/local project definitions."""

from __future__ import annotations

from .loader import Registry, load_registry

__all__ = ["Registry", "load_registry"]

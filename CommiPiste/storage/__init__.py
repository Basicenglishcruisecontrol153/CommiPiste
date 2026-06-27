"""Signature storage layer — a SQLite-backed ``hash -> paths -> commits`` store."""

from __future__ import annotations

from .base import ProjectMeta
from .sqlite import SqliteStorage, open_storage

# `Storage` aliases the concrete class so existing `store: Storage` hints resolve without a separate
# Protocol — there's only ever one backend.
Storage = SqliteStorage

__all__ = ["Storage", "SqliteStorage", "ProjectMeta", "open_storage"]

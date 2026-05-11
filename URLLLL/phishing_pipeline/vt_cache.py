"""
vt_cache.py — VirusTotal Response Cache with 24-Hour TTL
=========================================================
Prevents exhausting the free-tier VT API limits (4 req/min, 500 req/day)
by caching URL and file hash lookups in a local SQLite database.

Usage:
    from vt_cache import VTCache
    cache = VTCache()

    # Check cache before calling VT API
    cached = cache.get("https://evil-site.com")
    if cached:
        return cached  # Skip VT API call

    # After VT API call, store result
    cache.set("https://evil-site.com", vt_result_dict)

Storage: SQLite file at ./data/vt_cache.db (auto-created)
TTL: 24 hours (configurable via VT_CACHE_TTL_HOURS env var)
"""

from __future__ import annotations

import json
import os
import sqlite3
import time
import hashlib
from pathlib import Path
from typing import Optional

# ─── Configuration ──────────────────────────────────────────────────────────
_TTL_HOURS: int = int(os.environ.get("VT_CACHE_TTL_HOURS", "24"))
_TTL_SECONDS: int = _TTL_HOURS * 3600
_DB_DIR: Path = Path(__file__).parent / "data"
_DB_PATH: Path = Path(os.environ.get("VT_CACHE_DB", str(_DB_DIR / "vt_cache.db")))


class VTCache:
    """
    Thread-safe SQLite cache for VirusTotal API responses.

    Stores URL → VT result and file_hash → VT result with automatic
    TTL expiration. Expired entries are purged on each read.
    """

    def __init__(self, db_path: str | Path = _DB_PATH, ttl_seconds: int = _TTL_SECONDS):
        self._db_path = Path(db_path)
        self._ttl = ttl_seconds
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Create the cache table if it doesn't exist."""
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS vt_cache (
                    cache_key   TEXT PRIMARY KEY,
                    result_json TEXT NOT NULL,
                    created_at  REAL NOT NULL,
                    expires_at  REAL NOT NULL,
                    input_type  TEXT DEFAULT 'url',
                    hit_count   INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_expires ON vt_cache(expires_at)
            """)

    def _connect(self) -> sqlite3.Connection:
        """Open a new connection (SQLite is file-locked, safe for single-server)."""
        conn = sqlite3.connect(str(self._db_path), timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _make_key(identifier: str) -> str:
        """
        Normalize the cache key.
        For URLs: SHA-256 of the lowercase URL.
        For file hashes: use the hash directly.
        """
        normalized = identifier.strip().lower()
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def get(self, identifier: str) -> Optional[dict]:
        """
        Retrieve a cached VT result if it exists and hasn't expired.

        Args:
            identifier: URL string or file SHA-256 hash.

        Returns:
            Cached VT result dict, or None if not found / expired.
        """
        key = self._make_key(identifier)
        now = time.time()

        with self._connect() as conn:
            # Purge expired entries (background cleanup)
            conn.execute("DELETE FROM vt_cache WHERE expires_at < ?", (now,))

            row = conn.execute(
                "SELECT result_json, created_at, expires_at FROM vt_cache WHERE cache_key = ?",
                (key,)
            ).fetchone()

            if row and row["expires_at"] > now:
                # Update hit count
                conn.execute(
                    "UPDATE vt_cache SET hit_count = hit_count + 1 WHERE cache_key = ?",
                    (key,)
                )
                return json.loads(row["result_json"])

        return None

    def set(self, identifier: str, result: dict, input_type: str = "url") -> None:
        """
        Store a VT API result in the cache.

        Args:
            identifier:  URL string or file SHA-256 hash.
            result:      VT result dict (vt_malicious, vt_suspicious, etc.)
            input_type:  "url" or "file" for tracking.
        """
        key = self._make_key(identifier)
        now = time.time()
        expires = now + self._ttl

        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO vt_cache
                   (cache_key, result_json, created_at, expires_at, input_type, hit_count)
                   VALUES (?, ?, ?, ?, ?, 0)""",
                (key, json.dumps(result), now, expires, input_type),
            )

    def stats(self) -> dict:
        """Return cache statistics for monitoring."""
        now = time.time()
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM vt_cache").fetchone()[0]
            valid = conn.execute(
                "SELECT COUNT(*) FROM vt_cache WHERE expires_at > ?", (now,)
            ).fetchone()[0]
            total_hits = conn.execute(
                "SELECT COALESCE(SUM(hit_count), 0) FROM vt_cache"
            ).fetchone()[0]
        return {
            "total_entries": total,
            "valid_entries": valid,
            "expired_entries": total - valid,
            "total_cache_hits": total_hits,
            "ttl_hours": self._ttl // 3600,
            "db_path": str(self._db_path),
        }

    def clear(self) -> int:
        """Purge all cache entries. Returns count of deleted rows."""
        with self._connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM vt_cache").fetchone()[0]
            conn.execute("DELETE FROM vt_cache")
        return count


# ─── Singleton instance for import convenience ─────────────────────────────
_cache_instance: Optional[VTCache] = None


def get_cache() -> VTCache:
    """Get or create the singleton VTCache instance."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = VTCache()
    return _cache_instance

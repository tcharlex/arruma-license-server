import os
import sqlite3
from pathlib import Path

def _db_path() -> str:
    # Prefer explicit path if provided
    explicit = os.getenv("AUTH_DB_PATH")
    if explicit:
        return explicit

    # Persistent dir (Render/Fly/etc.) if mounted
    data_dir = os.getenv("DATA_DIR") or os.getenv("FILEFLOW_DATA_DIR") or "/data"
    p = Path(data_dir)
    if not p.exists():
        p = Path(".")
    p.mkdir(parents=True, exist_ok=True)
    return str(p / "auth.db")

def db():
    """SQLite connection compatible with multi-threaded WSGI env."""
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn

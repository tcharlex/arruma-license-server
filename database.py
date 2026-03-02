import os
import sqlite3
from pathlib import Path


def _db_path() -> str:
    explicit = os.getenv("AUTH_DB_PATH")
    if explicit:
        return explicit

    data_dir = os.getenv("DATA_DIR") or os.getenv("FILEFLOW_DATA_DIR")
    if not data_dir:
        raise RuntimeError(
            "Banco não configurado. Defina AUTH_DB_PATH ou DATA_DIR/FILEFLOW_DATA_DIR "
            "para usar storage persistente."
        )

    p = Path(data_dir)
    p.mkdir(parents=True, exist_ok=True)
    return str(p / "auth.db")


def db():
    """SQLite connection compatible with multi-threaded WSGI env."""
    conn = sqlite3.connect(_db_path(), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=5000;")
    return conn

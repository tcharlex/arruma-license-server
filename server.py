from flask import Flask, request, jsonify
import bcrypt
import secrets
import time
import sqlite3
import os
import hmac
import hashlib
from pathlib import Path
import psycopg2
import psycopg2.extras

app = Flask(__name__)

TOKEN_DURATION = 60 * 60 * 24 * 90  # 90 dias
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "DEV_ADMIN_TOKEN")


# =========================
# Banco
# =========================
def get_data_dir():
    base = os.getenv("DATA_DIR") or os.getenv("FILEFLOW_DATA_DIR")
    path = Path(base) if base else Path.home() / ".fileflow_downloads"
    path.mkdir(parents=True, exist_ok=True)
    return path


DB = str(get_data_dir() / "auth.db")


def db():
    url = os.getenv("DATABASE_URL")

    # Se existir DATABASE_URL → usa Postgres (Render)
    if url:
        conn = psycopg2.connect(url)
        return conn

    # Senão → continua usando SQLite (local)
    conn = sqlite3.connect(DB)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def init_db():
    conn = db()
    c = conn.cursor()

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY,
            password BYTEA
        )
    """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            email TEXT,
            expires INTEGER
        )
    """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS entitlements (
            email TEXT,
            product TEXT,
            revoked INTEGER DEFAULT 0,
            PRIMARY KEY(email, product)
        )
    """
    )

    # dispositivo ativo
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS active_devices (
            email TEXT PRIMARY KEY,
            device_id TEXT,
            last_seen INTEGER
        )
    """
    )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS licenses (
            license_key TEXT PRIMARY KEY,
            app TEXT NOT NULL,
            device_id TEXT
        )
    """
    )

    conn.commit()
    conn.close()


init_db()


# =========================
# Helpers
# =========================
def has_product(email, product):
    conn = db()
    c = conn.cursor()

    c.execute(
        "SELECT 1 FROM entitlements WHERE email=? AND product=? AND revoked=0",
        (email, product),
    )

    ok = c.fetchone() is not None
    conn.close()
    return ok


def require_admin(req):
    return req.headers.get("Authorization") == f"Bearer {ADMIN_TOKEN}"


def validate_session_request(req):
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False, None

    token = auth.split(" ")[1]

    conn = db()
    c = conn.cursor()

    c.execute("SELECT email, expires FROM sessions WHERE token=?", (token,))
    row = c.fetchone()

    if not row:
        conn.close()
        return False, None

    email, expires = row

    if time.time() > expires:
        c.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
        return False, None

    conn.close()
    return True, email


def _error(code, message, status, details=None):
    return (
        jsonify(
            {
                "error": {
                    "code": code,
                    "message": message,
                    "details": details or {},
                }
            }
        ),
        status,
    )


def _verify_password(raw_password, stored_value):
    if stored_value is None:
        return False

    # Normalize incoming password to both str and bytes without raising on type mismatch.
    if isinstance(raw_password, bytes):
        raw_password_bytes = raw_password
        raw_password_str = raw_password.decode("utf-8", errors="replace")
    else:
        raw_password_str = str(raw_password)
        raw_password_bytes = raw_password_str.encode("utf-8")

    if isinstance(stored_value, memoryview):
        stored_value = stored_value.tobytes()

    stored_bytes = None
    stored_str = None

    if isinstance(stored_value, bytes):
        stored_bytes = stored_value
        stored_str = stored_value.decode("utf-8", errors="replace")
    elif isinstance(stored_value, str):
        stored_str = stored_value
        stored_bytes = stored_value.encode("utf-8")
    else:
        stored_str = str(stored_value)
        stored_bytes = stored_str.encode("utf-8")

    # Auto-detect bcrypt by prefix/signature in stored representation.
    is_bcrypt = (
        stored_str.startswith("$2a$")
        or stored_str.startswith("$2b$")
        or stored_str.startswith("$2y$")
    )
    if is_bcrypt:
        try:
            return bcrypt.checkpw(raw_password_bytes, stored_bytes)
        except (ValueError, TypeError):
            return False

    # Legacy plaintext comparison (constant-time).
    return hmac.compare_digest(raw_password_str, stored_str)


def _get_entitlements(email):
    conn = db()
    c = conn.cursor()
    c.execute(
        "SELECT product FROM entitlements WHERE email=? AND revoked=0 ORDER BY product",
        (email,),
    )
    rows = c.fetchall()
    conn.close()
    return [{"product": product, "active": True} for (product,) in rows]


def _extract_bearer_token(req):
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    return auth.split(" ", 1)[1].strip()


def _session_id_from_token(token):
    return f"ses_{token[:12]}"


def _user_id_for_email(email):
    digest = hashlib.sha256(email.encode("utf-8")).hexdigest()[:12]
    return f"usr_{digest}"


# =========================
# Login
# =========================
@app.post("/v1/sessions/login")
def v1_login():
    data = request.json or {}

    email = data.get("email", "").lower().strip()
    password = data.get("password", "")
    product = data.get("product", "").strip()
    device = data.get("device") or {}
    device_id = str(device.get("device_id", "")).strip()

    if not email or not password or not product or not device_id:
        return _error("invalid_request", "Campos obrigatórios ausentes", 400)

    conn = db()
    c = conn.cursor()

    c.execute("SELECT password FROM users WHERE email=?", (email,))
    row = c.fetchone()
    if not row or not _verify_password(password, row[0]):
        conn.close()
        return _error("invalid_credentials", "Email ou senha inválidos", 401)

    if not has_product(email, product):
        conn.close()
        return _error("product_required", "Acesso ao produto não encontrado", 403)

    c.execute("SELECT device_id FROM active_devices WHERE email=?", (email,))
    existing = c.fetchone()
    if existing and existing[0] != device_id:
        conn.close()
        return _error("already_in_use", "Conta ativa em outro dispositivo", 403)

    now = int(time.time())
    access_expires_in = 3600
    access_token = secrets.token_hex(32)
    refresh_token = secrets.token_hex(32)

    c.execute(
        "INSERT OR REPLACE INTO active_devices (email, device_id, last_seen) VALUES (?, ?, ?)",
        (email, device_id, now),
    )
    c.execute(
        "INSERT OR REPLACE INTO sessions (token, email, expires) VALUES (?, ?, ?)",
        (access_token, email, now + access_expires_in),
    )

    conn.commit()
    conn.close()

    return jsonify(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "expires_in": access_expires_in,
            "session_id": _session_id_from_token(access_token),
            "user": {
                "user_id": _user_id_for_email(email),
                "email": email,
            },
            "entitlements": _get_entitlements(email),
            "device": {
                "device_id": device_id,
                "is_primary": True,
            },
        }
    )


@app.post("/login")
def login():
    data = request.json or {}

    email = data.get("email", "").lower().strip()
    password = data.get("password", "")
    product = data.get("product", "").strip()
    device_id = data.get("device_id", "").strip()

    if not device_id:
        return jsonify({"error": "missing_device"}), 400
    if not product:
        return jsonify({"error": "missing_product"}), 400

    conn = db()
    c = conn.cursor()

    # validar senha
    c.execute("SELECT password FROM users WHERE email=?", (email,))
    row = c.fetchone()
    if not row or not bcrypt.checkpw(password.encode(), row[0]):
        conn.close()
        return jsonify({"error": "invalid_credentials"}), 401

    # validar produto
    if not has_product(email, product):
        conn.close()
        return jsonify({"error": "product_required"}), 403

    # =========================
    # BLOQUEIO DE SEGUNDO PC
    # =========================
    c.execute("SELECT device_id FROM active_devices WHERE email=?", (email,))
    existing = c.fetchone()

    if existing and existing[0] != device_id:
        conn.close()
        return jsonify({"error": "already_in_use"}), 403

    # registrar dispositivo
    c.execute(
        "INSERT OR REPLACE INTO active_devices (email, device_id, last_seen) VALUES (?, ?, ?)",
        (email, device_id, int(time.time())),
    )

    # criar sessão
    token = secrets.token_hex(32)
    expires = int(time.time() + TOKEN_DURATION)

    c.execute(
        "INSERT OR REPLACE INTO sessions (token, email, expires) VALUES (?, ?, ?)",
        (token, email, expires),
    )

    conn.commit()
    conn.close()

    return jsonify({"token": token})


# =========================
# Criar conta
# =========================
@app.post("/register")
def register():
    data = request.json or {}

    email = data.get("email", "").lower().strip()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "missing_fields"}), 400

    if len(password) < 4:
        return jsonify({"error": "weak_password"}), 400

    conn = db()
    c = conn.cursor()

    c.execute("SELECT email FROM users WHERE email=?", (email,))
    if c.fetchone():
        conn.close()
        return jsonify({"error": "email_exists"}), 409

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, pw_hash))

    conn.commit()
    conn.close()

    return jsonify({"status": "account_created"})


# =========================
# Sessão
# =========================
@app.get("/me")
def me():
    ok, email = validate_session_request(request)
    if not ok:
        return jsonify({"status": "invalid"}), 401

    device_id = request.headers.get("X-Device-ID")

    if device_id:
        conn = db()
        c = conn.cursor()
        c.execute(
            "UPDATE active_devices SET last_seen=? WHERE email=? AND device_id=?",
            (int(time.time()), email, device_id),
        )
        conn.commit()
        conn.close()

    return jsonify({"status": "ok", "email": email})


@app.get("/v1/sessions/me")
def v1_me():
    token = _extract_bearer_token(request)
    if not token:
        return _error("unauthorized", "Token ausente ou inválido", 401)

    device_id = (request.headers.get("X-Device-ID") or "").strip()
    if not device_id:
        return _error("invalid_request", "X-Device-ID é obrigatório", 400)

    conn = db()
    c = conn.cursor()

    c.execute("SELECT email, expires FROM sessions WHERE token=?", (token,))
    row = c.fetchone()
    if not row:
        conn.close()
        return _error("unauthorized", "Sessão inválida", 401)

    email, expires = row
    now = int(time.time())
    if now > int(expires):
        c.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
        return _error("unauthorized", "Sessão expirada", 401)

    c.execute("SELECT device_id FROM active_devices WHERE email=?", (email,))
    device_row = c.fetchone()
    if device_row and device_row[0] != device_id:
        conn.close()
        return _error("device_not_authorized", "Dispositivo não autorizado", 403)

    c.execute(
        "INSERT OR REPLACE INTO active_devices (email, device_id, last_seen) VALUES (?, ?, ?)",
        (email, device_id, now),
    )
    conn.commit()
    conn.close()

    return jsonify(
        {
            "valid": True,
            "session_id": _session_id_from_token(token),
            "user": {
                "user_id": _user_id_for_email(email),
                "email": email,
            },
            "entitlements": _get_entitlements(email),
            "device": {
                "device_id": device_id,
                "authorized": True,
                "last_seen_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            },
        }
    )


@app.post("/v1/licenses/validate")
def v1_validate_license():
    data = request.json or {}
    license_key = str(data.get("license_key", "")).strip().upper()
    device_id = str(data.get("device_id", "")).strip()
    app_name = str(data.get("app", "")).strip().lower()

    if not license_key or not device_id or not app_name:
        return _error("invalid_request", "Campos obrigatórios ausentes", 400)

    conn = db()
    c = conn.cursor()
    c.execute(
        "SELECT app, device_id FROM licenses WHERE license_key=?",
        (license_key,),
    )
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({"valid": False, "reason": "not_found"})

    stored_app, bound_device = row
    if str(stored_app).strip().lower() != app_name:
        conn.close()
        return jsonify({"valid": False, "reason": "not_found"})

    if bound_device and bound_device != device_id:
        conn.close()
        return jsonify({"valid": False, "reason": "device_mismatch"})

    first_activation = not bool(bound_device)
    if first_activation:
        c.execute(
            "UPDATE licenses SET device_id=? WHERE license_key=?",
            (device_id, license_key),
        )
        conn.commit()

    conn.close()
    return jsonify({"valid": True, "first_activation": first_activation})


# =========================
# ADMIN — conceder acesso
# =========================
@app.post("/admin/grant")
def grant_entitlement():

    if not require_admin(request):
        return jsonify({"error": "unauthorized"}), 401

    data = request.json or {}
    email = data.get("email", "").lower().strip()
    product = data.get("product", "").strip()

    if not email or not product:
        return jsonify({"error": "missing_fields"}), 400

    conn = db()
    c = conn.cursor()

    c.execute("SELECT email FROM users WHERE email=?", (email,))
    if not c.fetchone():
        conn.close()
        return jsonify({"error": "account_not_found"}), 404

    c.execute(
        "INSERT OR REPLACE INTO entitlements (email, product, revoked) VALUES (?, ?, 0)",
        (email, product),
    )

    conn.commit()
    conn.close()

    return jsonify({"status": "granted"})


# =========================
# ADMIN — revogar acesso
# =========================
@app.post("/admin/revoke")
def revoke_entitlement():

    if not require_admin(request):
        return jsonify({"error": "unauthorized"}), 401

    data = request.json or {}
    email = data.get("email", "").lower().strip()
    product = data.get("product", "").strip()

    conn = db()
    c = conn.cursor()

    c.execute(
        "UPDATE entitlements SET revoked=1 WHERE email=? AND product=?",
        (email, product),
    )

    conn.commit()
    conn.close()

    return jsonify({"status": "revoked"})


@app.post("/admin/create_license")
def admin_create_license():

    if not require_admin(request):
        return jsonify({"error": "unauthorized"}), 401

    data = request.json or {}
    app_name = data.get("app", "").strip()

    if not app_name:
        return jsonify({"error": "missing_fields"}), 400

    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    def _new_key():
        parts = []
        for _ in range(3):
            part = "".join(secrets.choice(alphabet) for _ in range(4))
            parts.append(part)
        return "-".join(parts)

    conn = db()
    c = conn.cursor()

    license_key = None
    for _ in range(10):
        candidate = _new_key()
        try:
            c.execute(
                "INSERT INTO licenses (license_key, app, device_id) VALUES (%s, %s, %s)",
                (candidate, app_name, None),
            )
            conn.commit()
            license_key = candidate
            break
        except Exception:
            continue

    conn.close()

    if not license_key:
        return jsonify({"error": "could_not_create_license"}), 500

    return jsonify({"license_key": license_key})


if __name__ == "__main__":
    from waitress import serve

    port = int(os.environ.get("PORT", 5001))
    serve(app, host="0.0.0.0", port=port)

from flask import Flask, request, jsonify
import bcrypt
import secrets
import time
import sqlite3
import os
import hmac
import hashlib
import base64
from pathlib import Path
import psycopg2
import psycopg2.extras
from nacl.signing import SigningKey
import json
from database import db

app = Flask(__name__)
# blueprints
from admin import admin_bp

app.register_blueprint(admin_bp)
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
            device_id TEXT,
            device_pubkey TEXT,
            reset_count INTEGER DEFAULT 0,
            license_version INTEGER DEFAULT 0
        )
    """
    )

    # Migração para bases já existentes sem device_pubkey.
    try:
        c.execute("ALTER TABLE licenses ADD COLUMN device_pubkey TEXT")
    except Exception:
        pass

    # Migração para bases já existentes sem reset_count.
    try:
        c.execute("ALTER TABLE licenses ADD COLUMN reset_count INTEGER DEFAULT 0")
    except Exception:
        pass

    try:
        c.execute("ALTER TABLE licenses ADD COLUMN license_version INTEGER DEFAULT 0")
    except Exception:
        pass

    conn.commit()
    conn.close()


init_db()


# =========================
# License Signing (Ed25519)
# =========================
def load_private_key():
    key_b64 = os.getenv("LICENSE_PRIVATE_KEY")
    if not key_b64:
        raise RuntimeError("LICENSE_PRIVATE_KEY não configurada no ambiente")

    key = base64.b64decode(key_b64)
    return SigningKey(key)


SIGNING_KEY = load_private_key()


# =========================
# Helpers
# =========================
def has_product(email, product):
    conn = db()
    c = conn.cursor()

    c.execute(
        "SELECT 1 FROM entitlements WHERE email=%s AND product=%s AND revoked=0",
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

    c.execute("SELECT email, expires FROM sessions WHERE token=%s", (token,))
    row = c.fetchone()

    if not row:
        conn.close()
        return False, None

    email, expires = row

    if time.time() > expires:
        c.execute("DELETE FROM sessions WHERE token=%s", (token,))
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
        "SELECT product FROM entitlements WHERE email=%s AND revoked=0 ORDER BY product",
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


def _generate_offline_token(license_key, device_id, license_version):
    issued_at = int(time.time())

    payload = f"{license_key}:{device_id}:{issued_at}:{license_version}".encode()
    signature = SIGNING_KEY.sign(payload).signature
    token = base64.urlsafe_b64encode(payload + b"." + signature).decode()

    # não existe mais expiração criptográfica
    return token, issued_at


def _signed_validate_response(payload: dict):
    response_payload = dict(payload)
    canonical = json.dumps(
        response_payload, separators=(",", ":"), sort_keys=True
    ).encode()
    signature = SIGNING_KEY.sign(canonical).signature
    response_payload["sig"] = base64.b64encode(signature).decode("utf-8")
    return jsonify(response_payload)


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

    c.execute("SELECT device_id FROM active_devices WHERE email=%s", (email,))
    existing = c.fetchone()
    if existing and existing[0] != device_id:
        conn.close()
        return _error("already_in_use", "Conta ativa em outro dispositivo", 403)

    now = int(time.time())
    access_expires_in = 3600
    access_token = secrets.token_hex(32)
    refresh_token = secrets.token_hex(32)

    c.execute(
        "INSERT OR REPLACE INTO active_devices (email, device_id, last_seen) VALUES (%s, %s, %s)",
        (email, device_id, now),
    )
    c.execute(
        "INSERT OR REPLACE INTO sessions (token, email, expires) VALUES (%s, %s, %s)",
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
    c.execute("SELECT password FROM users WHERE email=%s", (email,))
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
    c.execute("SELECT device_id FROM active_devices WHERE email=%s", (email,))
    existing = c.fetchone()

    if existing and existing[0] != device_id:
        conn.close()
        return jsonify({"error": "already_in_use"}), 403

    # registrar dispositivo
    c.execute(
        "INSERT OR REPLACE INTO active_devices (email, device_id, last_seen) VALUES (%s, %s, %s)",
        (email, device_id, int(time.time())),
    )

    # criar sessão
    token = secrets.token_hex(32)
    expires = int(time.time() + TOKEN_DURATION)

    c.execute(
        "INSERT OR REPLACE INTO sessions (token, email, expires) VALUES (%s, %s, %s)",
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

    c.execute("SELECT email FROM users WHERE email=%s", (email,))
    if c.fetchone():
        conn.close()
        return jsonify({"error": "email_exists"}), 409

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    c.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, pw_hash))

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
            "UPDATE active_devices SET last_seen=? WHERE email=? AND device_id=%s",
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
        "INSERT OR REPLACE INTO active_devices (email, device_id, last_seen) VALUES (%s, %s, %s)",
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
    device_pubkey = str(data.get("device_pubkey", "")).strip()
    app_name = str(data.get("app", "")).strip().lower()

    if not license_key or not device_id or not device_pubkey or not app_name:
        return _error("invalid_request", "Campos obrigatórios ausentes", 400)

    conn = db()
    c = conn.cursor()
    c.execute(
        "SELECT app, device_id, device_pubkey, license_version FROM licenses WHERE license_key=%s",
        (license_key,),
    )
    row = c.fetchone()

    if not row:
        conn.close()
        return _signed_validate_response({"valid": False, "reason": "not_found"})

    stored_app = row[0]
    bound_device = row[1]
    bound_pubkey = row[2]
    license_version = int(row[3] or 0)

    if str(stored_app).strip().lower() != app_name:
        conn.close()
        return _signed_validate_response({"valid": False, "reason": "not_found"})

    if bound_device and bound_device != device_id:
        conn.close()
        return _signed_validate_response({"valid": False, "reason": "device_mismatch"})

    if bound_pubkey and bound_pubkey != device_pubkey:
        conn.close()
        return _signed_validate_response({"valid": False, "reason": "invalid"})

    first_activation = not bool(bound_device)
    needs_pubkey_bind = not bool(bound_pubkey)
    if first_activation:
        c.execute(
            """
            UPDATE licenses
            SET device_id=%s,
                device_pubkey=%s
            WHERE license_key=%s
            AND device_id IS NULL
            """,
            (device_id, device_pubkey, license_key),
        )

        if c.rowcount == 0:
            conn.close()
            return _signed_validate_response(
                {"valid": False, "reason": "already_bound"}
            )

        conn.commit()
    elif needs_pubkey_bind:
        c.execute(
            "UPDATE licenses SET device_pubkey=%s WHERE license_key=%s",
            (device_pubkey, license_key),
        )
        conn.commit()
    # garantir versão atual da licença
    c.execute(
        "SELECT license_version FROM licenses WHERE license_key=%s",
        (license_key,),
    )
    license_version = int(c.fetchone()[0] or 0)
    conn.close()
    token, expiry = _generate_offline_token(license_key, device_id, license_version)
    response_payload = {
        "valid": True,
        "license_key": license_key,
        "device_id": device_id,
        "offline_token": token,
        "expires": expiry,
        "first_activation": first_activation,
    }
    return _signed_validate_response(response_payload)


@app.post("/v1/licenses/reset")
def v1_reset_license():
    if not require_admin(request):
        return jsonify({"error": "unauthorized"}), 401

    data = request.json or {}
    license_key = str(data.get("license_key", "")).strip().upper()
    if not license_key:
        return _error("invalid_request", "Campos obrigatórios ausentes", 400)

    conn = db()
    c = conn.cursor()
    c.execute(
        "SELECT reset_count FROM licenses WHERE license_key=%s",
        (license_key,),
    )
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "not_found"}), 404

    reset_count = int(row[0] or 0)
    if reset_count >= 3:
        conn.close()
        return jsonify({"error": "reset_limit_reached"}), 403

    c.execute(
        """
        UPDATE licenses
        SET device_id = NULL,
            device_pubkey = NULL,
            reset_count = reset_count + 1,
            license_version = license_version + 1
        WHERE license_key = %s
        """,
        (license_key,),
    )
    conn.commit()
    conn.close()

    return jsonify(
        {
            "status": "reset_ok",
            "resets_remaining": 3 - reset_count - 1,
        }
    )


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

    c.execute("SELECT email FROM users WHERE email=%s", (email,))
    if not c.fetchone():
        conn.close()
        return jsonify({"error": "account_not_found"}), 404

    c.execute(
        """
        INSERT INTO entitlements (email, product, revoked)
        VALUES (%s, %s, 0)
        ON CONFLICT (email, product) DO UPDATE SET revoked=0
        """,
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


def generate_license_key(app_name):
    prefix = app_name[:2].upper()
    part1 = secrets.token_hex(2).upper()
    part2 = secrets.token_hex(2).upper()
    part3 = secrets.token_hex(2).upper()
    return f"{prefix}-{part1}-{part2}-{part3}"


@app.post("/internal/create_license")
def internal_create_license():
    if request.headers.get("X-Internal-Key") != os.getenv("ADMIN_TOKEN"):
        return {"error": "unauthorized"}, 401

    data = request.json
    app_name = data.get("app")

    key = generate_license_key(app_name)

    conn = db()
    c = conn.cursor()
    c.execute(
        "INSERT INTO licenses (license_key, app, device_id) VALUES (%s, %s, NULL)",
        (key, app_name),
    )
    conn.commit()
    conn.close()

    return {"license_key": key}


if __name__ == "__main__":
    from waitress import serve

    port = int(os.environ.get("PORT", 5001))
    serve(app, host="0.0.0.0", port=port)

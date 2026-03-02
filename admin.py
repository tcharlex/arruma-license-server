from flask import Blueprint, request, jsonify
import os
from database import db

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")


def check():
    token_ok = request.headers.get("Authorization") == f"Bearer {ADMIN_TOKEN}"
    ip_ok = allowed_ip()
    return token_ok and ip_ok


@admin_bp.get("/users")
def users():
    if not check():
        return {"error": "unauthorized"}, 401

    conn = db()
    c = conn.cursor()
    c.execute("SELECT email FROM users")
    rows = c.fetchall()
    conn.close()

    return jsonify(rows)


@admin_bp.get("/licenses")
def licenses():
    if not check():
        return {"error": "unauthorized"}, 401

    conn = db()
    c = conn.cursor()
    c.execute("SELECT license_key, app, device_id FROM licenses")
    rows = [{"key": r[0], "app": r[1], "device": r[2]} for r in c.fetchall()]
    return jsonify(rows)


def allowed_ip():
    allowed = os.getenv("ADMIN_IP")
    if not allowed:
        return True

    ip = request.remote_addr or ""
    trust_xff = str(os.getenv("TRUST_X_FORWARDED_FOR", "")).lower() in (
        "1",
        "true",
        "yes",
    )
    if trust_xff:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            ip = xff.split(",")[0].strip()

    # permitir localhost em desenvolvimento
    if ip.startswith("127.0.0.1") or ip.startswith("192.168."):
        return True

    return ip.startswith(allowed)


@admin_bp.post("/revoke_license", endpoint="revoke_license")
def revoke_license():
    if not check():
        return {"error": "unauthorized"}, 401

    data = request.json
    key = data.get("key")

    if not key:
        return {"error": "missing key"}, 400

    conn = db()
    c = conn.cursor()
    c.execute("DELETE FROM licenses WHERE license_key = ?", (key,))
    conn.commit()
    conn.close()

    return {"status": "revoked"}


@admin_bp.post("/reset_device", endpoint="reset_device")
def reset_device():
    if not check():
        return {"error": "unauthorized"}, 401

    data = request.json
    key = data.get("key")

    if not key:
        return {"error": "missing key"}, 400

    conn = db()
    c = conn.cursor()

    c.execute(
        """
        UPDATE licenses
        SET device_id = NULL,
            device_pubkey = NULL,
            reset_count = reset_count + 1
        WHERE license_key = ?
    """,
        (key,),
    )

    conn.commit()
    conn.close()

    return {"status": "device reset"}


@admin_bp.post("/register_license", endpoint="register_license")
def register_license():
    token = request.headers.get("Authorization")
    internal = os.getenv("INTERNAL_API")
    if not internal or token != f"Bearer {internal}":
        return {"error": "unauthorized"}, 401

    data = request.json
    key = data.get("key")
    email = data.get("email")
    product = data.get("product")

    if not key:
        return {"error": "missing_key"}, 400

    conn = db()
    c = conn.cursor()

    # se já existir, ignora
    c.execute("SELECT license_key FROM licenses WHERE license_key=?", (key,))
    if c.fetchone():
        conn.close()
        return {"status": "exists"}

    c.execute(
        """
        INSERT INTO licenses (license_key, app, device_id, device_pubkey, reset_count)
        VALUES (?, ?, NULL, NULL, 0)
    """,
        (key, product),
    )

    conn.commit()
    conn.close()

    return {"status": "created"}

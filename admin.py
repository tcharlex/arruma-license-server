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

    ip = request.headers.get("X-Forwarded-For", request.remote_addr)

    # permitir localhost em desenvolvimento
    if ip.startswith("127.0.0.1") or ip.startswith("192.168."):
        return True

    return ip.startswith(allowed)


@admin_bp.post("/revoke")
def revoke():
    if not check():
        return {"error": "unauthorized"}, 401

    data = request.json
    key = data.get("key")

    if not key:
        return {"error": "missing key"}, 400

    conn = db()
    c = conn.cursor()
    c.execute("DELETE FROM licenses WHERE license_key = %s", (key,))
    conn.commit()
    conn.close()

    return {"status": "revoked"}


@admin_bp.post("/revoke")
def revoke():
    if not check():
        return {"error": "unauthorized"}, 401

    data = request.json
    key = data.get("key")

    if not key:
        return {"error": "missing key"}, 400

    conn = db()
    c = conn.cursor()
    c.execute("DELETE FROM licenses WHERE license_key = %s", (key,))
    conn.commit()
    conn.close()

    return {"status": "revoked"}

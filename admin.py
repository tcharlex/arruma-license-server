from flask import Blueprint, request, jsonify
import os
from server import db

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")


def check():
    return request.headers.get("Authorization") == f"Bearer {ADMIN_TOKEN}"


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
    c.execute("SELECT email, product FROM licenses")
    rows = c.fetchall()
    conn.close()

    return jsonify(rows)

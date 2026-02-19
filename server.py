from flask import Flask, request, jsonify
import sqlite3
import hashlib
import os
import json
import base64
import time
import secrets
import string

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from datetime import datetime


# ---------------- CONFIG ----------------
PORT = int(os.environ.get("PORT", 5000))
DB = "database.db"
LICENSE_DURATION = 7 * 24 * 3600  # 7 dias offline
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN")

app = Flask(__name__)


# ---------------- LOAD PRIVATE KEY (ENV) ----------------
private_key_pem = os.environ.get("PRIVATE_KEY_PEM")

if not private_key_pem:
    raise RuntimeError("PRIVATE_KEY_PEM not configured in environment variables")

PRIVATE_KEY = serialization.load_pem_private_key(
    private_key_pem.encode(),
    password=None,
)


# ---------------- MACHINE ID ----------------
def hash_machine(machine):
    return hashlib.sha256(machine.encode()).hexdigest()


# ---------------- SIGN LICENSE ----------------
def sign_license(payload_dict):
    payload = json.dumps(payload_dict, separators=(",", ":"), sort_keys=True).encode()

    signature = PRIVATE_KEY.sign(payload, padding.PKCS1v15(), hashes.SHA256())

    return {"license": payload_dict, "signature": base64.b64encode(signature).decode()}


# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            machine TEXT,
            revoked INTEGER DEFAULT 0,
            last_validation INTEGER
        )
    """
    )

    conn.commit()
    conn.close()


init_db()


# ---------------- VALIDATE ----------------
@app.route("/validate", methods=["POST"])
def validate():
    data = request.json
    if not data:
        return jsonify({"status": "bad_request"}), 400

    key = data.get("key")
    machine_raw = data.get("machine")

    if not key or not machine_raw:
        return jsonify({"status": "bad_request"}), 400

    machine = hash_machine(machine_raw)

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("SELECT machine, revoked FROM licenses WHERE key=?", (key,))
    row = c.fetchone()

    if not row:
        return jsonify({"status": "invalid"})

    saved_machine, revoked = row

    if revoked:
        return jsonify({"status": "blocked"})

    # primeira ativação
    if saved_machine is None:
        c.execute(
            "UPDATE licenses SET machine=?, last_validation=? WHERE key=?",
            (machine, int(time.time()), key),
        )
        conn.commit()
        saved_machine = machine

    # máquina diferente
    if saved_machine != machine:
        return jsonify({"status": "used"})

    now = int(time.time())

    payload = {
        "key": key,
        "machine": machine,
        "exp": now + LICENSE_DURATION,
        "nonce": secrets.token_hex(8),
    }

    c.execute("UPDATE licenses SET last_validation=? WHERE key=?", (now, key))
    conn.commit()
    conn.close()

    return jsonify(sign_license(payload))


# ---------------- KEY GENERATOR ----------------
import random
import string


def generate_key():
    parts = []
    for _ in range(4):
        part = "".join(random.choices(string.ascii_uppercase + string.digits, k=4))
        parts.append(part)
    return "-".join(parts)


# ---------------- ADMIN PROTECTION ----------------
def require_admin():
    if not ADMIN_TOKEN:
        return False

    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return False

    if auth_header != f"Bearer {ADMIN_TOKEN}":
        return False

    return True


# ---------------- GENERATE KEY ----------------
@app.route("/generate", methods=["POST"])
def generate():
    if not require_admin():
        return jsonify({"status": "unauthorized"}), 403

    key = generate_key()

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("INSERT INTO licenses(key, machine) VALUES(?, NULL)", (key,))
    conn.commit()
    conn.close()

    return {"status": "generated", "key": key}


# ---------------- ADD KEY ----------------
@app.route("/add", methods=["POST"])
def add():
    if not require_admin():
        return jsonify({"status": "unauthorized"}), 403

    key = request.json.get("key")

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    try:
        c.execute("INSERT INTO licenses(key, machine) VALUES(?, NULL)", (key,))
        conn.commit()
        conn.close()
        return {"status": "added"}
    except:
        conn.close()
        return {"status": "exists"}


# ---------------- REVOKE ----------------
@app.route("/revoke", methods=["POST"])
def revoke():
    if not require_admin():
        return jsonify({"status": "unauthorized"}), 403

    key = request.json.get("key")

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("UPDATE licenses SET revoked=1 WHERE key=?", (key,))
    conn.commit()
    conn.close()

    return {"status": "revoked"}


# ---------------- PURCHASE WEBHOOK ----------------
@app.route("/purchase", methods=["POST"])
def purchase_webhook():
    data = request.json
    print("WEBHOOK RECEBIDO:", data)

    try:
        event = data.get("event")

        # só processa compra aprovada
        if event not in ["purchase.approved", "compra.aprovada"]:
            return {"status": "ignored"}

        customer = data.get("customer", {})
        email = customer.get("email")

        if not email:
            return {"status": "no_email"}

        key = generate_key()

        conn = sqlite3.connect(DB)
        c = conn.cursor()

        c.execute(
            "INSERT INTO licenses(key, machine) VALUES(?, NULL)",
            (key,),
        )

        conn.commit()
        conn.close()

        print("LICENÇA GERADA:", key, "para", email)

        return {"status": "license_generated", "key": key}

    except Exception as e:
        print("ERRO WEBHOOK:", e)
        return {"status": "error"}


# ---------------- ADMIN PANEL ----------------
from flask import render_template, redirect


@app.route("/admin")
def admin_panel():
    token = request.args.get("token")
    if token != ADMIN_TOKEN:
        return "Unauthorized", 403

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("SELECT key, machine, revoked FROM licenses ORDER BY rowid DESC")
    rows = c.fetchall()
    conn.close()

    licenses = []
    for key, machine, revoked in rows:
        if revoked:
            status = "Bloqueada"
        elif machine:
            status = "Ativada"
        else:
            status = "Livre"

        licenses.append({"key": key, "machine": machine or "-", "status": status})

    return render_template("admin.html", licenses=licenses, token=ADMIN_TOKEN)


# ---------------- MAIN ----------------
if __name__ == "__main__":
    from waitress import serve

    serve(app, host="0.0.0.0", port=PORT)

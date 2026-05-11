import os
import random
import time
import uuid

from flask import Flask, request, jsonify, session, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

import psycopg2
import psycopg2.pool

# ---------------------------------------------------
# Load environment variables
# ---------------------------------------------------

load_dotenv()

# ---------------------------------------------------
# Flask app
# ---------------------------------------------------

app = Flask(__name__)

app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Set to True only if using HTTPS custom domain
app.config["SESSION_COOKIE_SECURE"] = False

# ---------------------------------------------------
# Rate limiting
# ---------------------------------------------------

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per minute"]
)

limiter.init_app(app)

# ---------------------------------------------------
# Domains
# ---------------------------------------------------

DOMAINS = [
    d.strip()
    for d in os.getenv("DOMAINS", "").split(",")
    if d.strip()
]

# fallback for local testing
if not DOMAINS:
    DOMAINS = ["example.com"]

# ---------------------------------------------------
# Database
# ---------------------------------------------------

DATABASE_URL = os.getenv("DATABASE_URL")

db_pool = None


def init_db():
    global db_pool

    if db_pool is not None:
        return

    if not DATABASE_URL:
        print("DATABASE_URL not set")
        return

    try:
        db_pool = psycopg2.pool.SimpleConnectionPool(
            1,
            20,
            DATABASE_URL,
            sslmode="require",
            connect_timeout=10
        )

        print("Database connected")

    except Exception as e:
        print("Database connection failed:", e)
        db_pool = None


def get_db_connection():
    init_db()

    if not db_pool:
        raise Exception("Database unavailable")

    return db_pool.getconn()


def put_db_connection(conn):
    if db_pool and conn:
        db_pool.putconn(conn)

# ---------------------------------------------------
# Message functions
# ---------------------------------------------------


def store_message(to_addr, from_addr, subject, body):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        INSERT INTO messages
        (id, to_addr, from_addr, subject, body, received_at)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            str(uuid.uuid4()),
            to_addr,
            from_addr,
            subject,
            body,
            int(time.time())
        )
    )

    conn.commit()

    cur.close()
    put_db_connection(conn)


def get_messages(to_addr, limit=200):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT id, from_addr, subject, received_at
        FROM messages
        WHERE to_addr = %s
        ORDER BY received_at DESC
        LIMIT %s
        """,
        (to_addr, limit)
    )

    rows = cur.fetchall()

    cur.close()
    put_db_connection(conn)

    return [
        {
            "id": str(r[0]),
            "from": r[1],
            "subject": r[2],
            "timestamp": r[3]
        }
        for r in rows
    ]


def get_single_message(msg_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT from_addr, subject, body, received_at
        FROM messages
        WHERE id = %s
        """,
        (msg_id,)
    )

    row = cur.fetchone()

    cur.close()
    put_db_connection(conn)

    if not row:
        return None

    return {
        "from": row[0],
        "subject": row[1],
        "body": row[2],
        "date": row[3]
    }


def delete_message_by_id(msg_id):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "DELETE FROM messages WHERE id = %s",
        (msg_id,)
    )

    conn.commit()

    cur.close()
    put_db_connection(conn)


def delete_all_messages(to_addr):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        "DELETE FROM messages WHERE to_addr = %s",
        (to_addr,)
    )

    conn.commit()

    cur.close()
    put_db_connection(conn)

# ---------------------------------------------------
# Webhook endpoint
# ---------------------------------------------------


@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json()

    if not data:
        return "Bad request: no JSON", 400

    to_addr = data.get("to", "").strip()
    from_addr = data.get("from", "").strip()
    subject = data.get("subject", "").strip()

    body = data.get("text", "") or data.get("html", "")

    if to_addr and from_addr:
        try:
            store_message(
                to_addr,
                from_addr,
                subject,
                body
            )
        except Exception as e:
            print("Store message failed:", e)

    return "OK", 200

# ---------------------------------------------------
# Frontend routes
# ---------------------------------------------------


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({
        "status": "ok"
    })


@app.route("/api/status")
def session_status():
    return jsonify({
        "email": session.get("email")
    })


@app.route("/api/new", methods=["POST"])
@limiter.limit("10 per minute")
def new_address():
    domain = random.choice(DOMAINS)

    local_part = uuid.uuid4().hex[:12]

    email = f"{local_part}@{domain}"

    session["email"] = email

    return jsonify({
        "success": True,
        "email": email
    })


@app.route("/api/inbox")
@limiter.limit("60 per minute")
def inbox():
    if "email" not in session:
        return jsonify({
            "error": "No active address"
        }), 400

    try:
        messages = get_messages(session["email"])

        return jsonify({
            "messages": messages
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@app.route("/api/message/<msg_id>")
def get_message(msg_id):
    if "email" not in session:
        return jsonify({
            "error": "No session"
        }), 400

    try:
        msg = get_single_message(msg_id)

        if not msg:
            return jsonify({
                "error": "Message not found"
            }), 404

        return jsonify(msg)

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@app.route("/api/delete/<msg_id>", methods=["POST"])
def delete_message(msg_id):
    if "email" not in session:
        return jsonify({
            "error": "No session"
        }), 400

    try:
        delete_message_by_id(msg_id)

        return jsonify({
            "success": True
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@app.route("/api/delete_all", methods=["POST"])
def delete_all():
    if "email" not in session:
        return jsonify({
            "error": "No session"
        }), 400

    try:
        delete_all_messages(session["email"])

        return jsonify({
            "success": True
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

# ---------------------------------------------------
# Main
# ---------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=8080,
        debug=False
    )
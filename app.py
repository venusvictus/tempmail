import os
import re
import time
import uuid
import json
import email
import secrets
import threading
import queue as queue_module
import warnings
from email import policy
from datetime import datetime, timedelta, timezone

from flask import Flask, request, jsonify, session, render_template, Response, stream_with_context
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from dotenv import load_dotenv
from flask_cors import CORS

import psycopg2
import psycopg2.pool
import redis

# ---------------------------------------------------
# Load environment variables
# ---------------------------------------------------
load_dotenv()

# ---------------------------------------------------
# Flask app
# ---------------------------------------------------
app = Flask(__name__)

# ────────── CORS: allow any localhost port for Flutter dev ──────────
# supports_credentials=True is needed because you use session cookies.
# The regex covers http://localhost:anyport and http://127.0.0.1:anyport
CORS(
    app,
    supports_credentials=True,
    origins=[
        r"http://localhost:\d+",
        r"http://127.0.0.1:\d+",
        # Add your production Flutter front‑end URL later, e.g.:
        # "https://your-flutter-app.pages.dev"
    ]
)

app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "supersecretkey"),
    SESSION_COOKIE_SAMESITE="None",
    SESSION_COOKIE_SECURE=True,   # Must be True if you ever serve over HTTPS
)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "False").lower() == "true"

# ---------------------------------------------------
# Security headers (Talisman)
# ---------------------------------------------------
csp = {
    'default-src': ["'self'"],
    'style-src': ["'self'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com'],
    'font-src': ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
    'img-src': ["'self'", 'data:', 'https://cdn.openai.com'],
    'script-src': ["'self'"],
}
Talisman(
    app,
    force_https=app.config["SESSION_COOKIE_SECURE"],
    session_cookie_secure=app.config["SESSION_COOKIE_SECURE"],
    session_cookie_http_only=True,
    frame_options='SAMEORIGIN',
    content_security_policy=csp,
    referrer_policy='strict-origin-when-cross-origin'
)

# ---------------------------------------------------
# Rate limiting (Redis or in‑memory fallback)
# ---------------------------------------------------
REDIS_URL = os.getenv("REDIS_URL")
if REDIS_URL:
    try:
        limiter = Limiter(
            key_func=get_remote_address,
            default_limits=["200 per minute"],
            storage_uri=f"redis://{REDIS_URL}",
            storage_options={"socket_connect_timeout": 5, "socket_timeout": 5}
        )
        print("Using Redis for rate limiting")
    except Exception as e:
        warnings.warn(f"Redis connection failed, falling back to in‑memory storage: {e}")
        limiter = Limiter(key_func=get_remote_address, default_limits=["200 per minute"])
else:
    warnings.warn("REDIS_URL not set – using in‑memory rate limiting")
    limiter = Limiter(key_func=get_remote_address, default_limits=["200 per minute"])
limiter.init_app(app)

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Too many requests. Please slow down."}), 429

# ---------------------------------------------------
# Domain pool
# ---------------------------------------------------
DOMAINS = [d.strip() for d in os.getenv("DOMAINS", "").split(",") if d.strip()]
if not DOMAINS:
    DOMAINS = ["example.com"]

# ---------------------------------------------------
# Database (Neon)
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
            1, 20, DATABASE_URL,
            sslmode="require", connect_timeout=10
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
# SSE pub/sub (in‑memory, one listener per inbox)
# ---------------------------------------------------
sse_queues = {}          # inbox_token -> queue.Queue
sse_lock = threading.Lock()

def get_sse_queue(inbox_token):
    with sse_lock:
        if inbox_token not in sse_queues:
            sse_queues[inbox_token] = queue_module.Queue()
        return sse_queues[inbox_token]

def notify_inbox(inbox_token, event_data):
    """Push new message event to the inbox's SSE queue if someone is listening."""
    q = sse_queues.get(inbox_token)
    if q:
        try:
            q.put_nowait(event_data)
        except queue_module.Full:
            pass  # discard if queue is full (shouldn't happen)

# ---------------------------------------------------
# Inbox management helpers
# ---------------------------------------------------
def create_inbox(ip_address=None):
    """Create a new inbox row and return (token, email_address)."""
    domain = random.choice(DOMAINS)
    local_part = secrets.token_urlsafe(8)
    address = f"{local_part}@{domain}"
    token = str(uuid.uuid4())

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO inboxes (token, address, domain, ip_address) VALUES (%s, %s, %s, %s)",
            (token, address, domain, ip_address)
        )
        conn.commit()
        cur.close()
    finally:
        put_db_connection(conn)

    return token, address

def get_inbox_email(token):
    """Retrieve the email address for a given inbox token."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT address FROM inboxes WHERE token = %s AND is_banned = FALSE", (token,))
        row = cur.fetchone()
        cur.close()
        return row[0] if row else None
    finally:
        put_db_connection(conn)

# ---------------------------------------------------
# Message functions (with dedup and OTP detection)
# ---------------------------------------------------
OTP_REGEX = re.compile(r"\b\d{6}\b")
OTP_KEYWORDS = ["verification", "code", "otp", "confirm", "login", "verify"]

def detect_otp(text):
    """Extract a 6‑digit OTP and a confidence flag from text."""
    matches = OTP_REGEX.findall(text)
    if not matches:
        return None, False
    text_lower = text.lower()
    for code in matches:
        if any(kw in text_lower for kw in OTP_KEYWORDS):
            return code, True
    return matches[0], False

def extract_message_id(raw_email):
    """Parse the Message-ID header from a raw email string."""
    try:
        msg = email.message_from_string(raw_email, policy=policy.default)
        return msg.get("Message-ID", "").strip()
    except Exception:
        return None

def store_message(to_addr, from_addr, subject, body, raw_email=None):
    """Insert message into DB, handling deduplication and async OTP detection."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        msg_id = extract_message_id(raw_email) if raw_email else None
        otp_code, otp_detected = detect_otp(body)

        cur.execute(
            """INSERT INTO messages
               (id, to_addr, from_addr, subject, body, received_at, message_id, otp_code, otp_detected)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (message_id) DO NOTHING""",
            (
                str(uuid.uuid4()),
                to_addr,
                from_addr,
                subject,
                body,
                int(time.time()),
                msg_id,
                otp_code,
                otp_detected
            )
        )
        conn.commit()
        cur.close()
        return True
    except Exception as e:
        print("Store message failed:", e)
        return False
    finally:
        put_db_connection(conn)

def get_messages(to_addr, limit=200):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """SELECT id, from_addr, subject, received_at, is_read, otp_code, otp_detected
               FROM messages WHERE to_addr = %s
               ORDER BY received_at DESC LIMIT %s""",
            (to_addr, limit)
        )
        rows = cur.fetchall()
        cur.close()
        return [{
            "id": str(r[0]),
            "from": r[1],
            "subject": r[2],
            "timestamp": r[3],
            "read": r[4],
            "otp_code": r[5],
            "otp_detected": r[6]
        } for r in rows]
    finally:
        put_db_connection(conn)

def get_single_message(msg_id):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT from_addr, subject, body, received_at, otp_code, otp_detected FROM messages WHERE id = %s",
            (msg_id,)
        )
        row = cur.fetchone()
        cur.close()
        if not row:
            return None
        return {
            "from": row[0],
            "subject": row[1],
            "body": row[2],
            "date": row[3],
            "otp_code": row[4],
            "otp_detected": row[5]
        }
    finally:
        put_db_connection(conn)

def delete_message_by_id(msg_id):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM messages WHERE id = %s", (msg_id,))
        conn.commit()
        cur.close()
    finally:
        put_db_connection(conn)

def delete_all_messages(to_addr):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM messages WHERE to_addr = %s", (to_addr,))
        conn.commit()
        cur.close()
    finally:
        put_db_connection(conn)

# ---------------------------------------------------
# Email body parser (plain text extraction)
# ---------------------------------------------------
def extract_plain_text(raw_email):
    try:
        msg = email.message_from_string(raw_email, policy=policy.default)
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    charset = part.get_content_charset() or "utf-8"
                    return part.get_payload(decode=True).decode(charset, errors="replace")
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    charset = part.get_content_charset() or "utf-8"
                    html = part.get_payload(decode=True).decode(charset, errors="replace")
                    return re.sub(r'<[^>]+>', '', html).strip()
        else:
            charset = msg.get_content_charset() or "utf-8"
            return msg.get_payload(decode=True).decode(charset, errors="replace")
    except Exception as e:
        print("Email parsing error:", e)
    return raw_email

# ---------------------------------------------------
# Webhook endpoint (secured, async processing)
# ---------------------------------------------------
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")

@app.route("/webhook", methods=["POST"])
@limiter.limit("30 per minute")
def webhook():
    if WEBHOOK_SECRET:
        received_secret = request.headers.get("X-Webhook-Secret")
        if received_secret != WEBHOOK_SECRET:
            return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data:
        return "Bad request: no JSON", 400

    to_addr = data.get("to", "").strip()
    from_addr = data.get("from", "").strip()
    subject = data.get("subject", "").strip()

    raw_body = (
        data.get("text") or data.get("html") or data.get("plain") or
        data.get("body") or data.get("content") or data.get("raw") or
        data.get("message") or ""
    ).strip()

    # Extract plain text
    if raw_body and ("Received:" in raw_body or "MIME-Version:" in raw_body):
        body = extract_plain_text(raw_body)
    else:
        body = raw_body

    if not body:
        body = json.dumps(data, indent=2)

    # Offload to a thread to avoid blocking the webhook response
    def process():
        if to_addr and from_addr:
            success = store_message(to_addr, from_addr, subject, body, raw_email=raw_body if raw_body else None)
            if success:
                conn2 = get_db_connection()
                try:
                    cur2 = conn2.cursor()
                    cur2.execute("SELECT token FROM inboxes WHERE address = %s", (to_addr,))
                    row = cur2.fetchone()
                    if row:
                        inbox_token = row[0]
                        notify_inbox(inbox_token, {
                            "type": "new_message",
                            "data": {
                                "from": from_addr,
                                "subject": subject,
                                "timestamp": int(time.time()),
                                "id": None
                            }
                        })
                finally:
                    put_db_connection(conn2)

    threading.Thread(target=process).start()

    return "OK", 200

# ---------------------------------------------------
# Frontend routes
# ---------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

# ---------------------------------------------------
# Inbox API
# ---------------------------------------------------
@app.route("/api/status")
def session_status():
    token = session.get("inbox_token")
    if token:
        email_addr = get_inbox_email(token)
        if email_addr:
            return jsonify({"email": email_addr, "token": token})
    return jsonify({"email": None, "token": None})

@app.route("/api/new", methods=["POST"])
@limiter.limit("10 per minute")
def new_address():
    ip = request.remote_addr
    token, address = create_inbox(ip)
    session["inbox_token"] = token
    return jsonify({"success": True, "email": address, "token": token})

# Get inbox messages (requires valid inbox token in session)
@app.route("/api/inbox")
@limiter.limit("60 per minute")
def inbox():
    token = session.get("inbox_token")
    if not token:
        return jsonify({"error": "No active inbox"}), 400
    email_addr = get_inbox_email(token)
    if not email_addr:
        return jsonify({"error": "Inbox not found or banned"}), 404
    try:
        messages = get_messages(email_addr)
        return jsonify({"messages": messages})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# SSE stream for live inbox updates
@app.route("/api/inbox/stream")
def inbox_stream():
    token = session.get("inbox_token")
    if not token:
        return jsonify({"error": "No active inbox"}), 400

    def event_stream():
        q = get_sse_queue(token)
        while True:
            try:
                event = q.get(timeout=30)
                yield f"event: {event['type']}\n"
                yield f"data: {json.dumps(event['data'])}\n\n"
            except queue_module.Empty:
                yield ": heartbeat\n\n"
    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

# Single message (secured by session)
@app.route("/api/message/<msg_id>")
def get_message(msg_id):
    if "inbox_token" not in session:
        return jsonify({"error": "No session"}), 400
    try:
        msg = get_single_message(msg_id)
        if not msg:
            return jsonify({"error": "Message not found"}), 404
        return jsonify(msg)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/delete/<msg_id>", methods=["POST"])
def delete_message(msg_id):
    if "inbox_token" not in session:
        return jsonify({"error": "No session"}), 400
    try:
        delete_message_by_id(msg_id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/delete_all", methods=["POST"])
def delete_all():
    if "inbox_token" not in session:
        return jsonify({"error": "No session"}), 400
    email_addr = get_inbox_email(session["inbox_token"])
    if not email_addr:
        return jsonify({"error": "Inbox not found"}), 404
    try:
        delete_all_messages(email_addr)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Basic metrics endpoint
@app.route("/metrics")
def metrics():
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM messages")
        total_messages = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM inboxes WHERE is_banned = FALSE")
        active_inboxes = cur.fetchone()[0]
        cur.close()
        return jsonify({
            "total_messages": total_messages,
            "active_inboxes": active_inboxes
        })
    finally:
        put_db_connection(conn)

# ---------------------------------------------------
# Main
# ---------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)

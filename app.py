import os
import re
import time
import uuid
import json
import email
import secrets
import random
import threading
import queue as queue_module
import warnings
from email import policy
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, render_template, Response, stream_with_context, g, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from dotenv import load_dotenv
from flask_cors import CORS

import psycopg2
import psycopg2.pool
import redis
import nh3  # <-- HTML sanitizer (install with: pip install nh3)

# ---------------------------------------------------
# Load environment variables
# ---------------------------------------------------
load_dotenv()

# ---------------------------------------------------
# Flask app
# ---------------------------------------------------
app = Flask(__name__)

# ────────── CORS: allow any localhost port for Flutter dev ──────────
CORS(
    app,
    supports_credentials=False,  # We no longer use cookies/sessions
    origins=[
        r"http://localhost:\d+",
        r"http://127.0.0.1:\d+",
        "https://yourdomain.com",  # replace with your frontend domain
    ]
)

app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "supersecretkey"),
)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key")

# ---------------------------------------------------
# Security headers (Talisman) – enforce HTTPS
# ---------------------------------------------------
csp = {
    'default-src': ["'self'"],
    'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com'],
    'font-src': ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
    'img-src': ["'self'", 'data:', 'https://cdn.openai.com'],
    'script-src': ["'self'", "'unsafe-inline'"],
}
Talisman(
    app,
    force_https=os.getenv("FORCE_HTTPS", "True").lower() == "true",
    session_cookie_secure=True,
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
# Token authentication decorator
# ---------------------------------------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid token"}), 401
        token = auth_header.split(" ")[1]

        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                "SELECT address, is_banned FROM inboxes WHERE token = %s AND created_at > NOW() - INTERVAL '1 day'",
                (token,)
            )
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "Invalid or expired token"}), 401
            if row[1]:  # is_banned
                return jsonify({"error": "Inbox banned"}), 403
            g.inbox_token = token
            g.inbox_address = row[0]
        finally:
            put_db_connection(conn)
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------
# Per‑token rate limiting (Redis)
# ---------------------------------------------------
redis_client = None
if REDIS_URL:
    try:
        redis_client = redis.from_url(f"redis://{REDIS_URL}", decode_responses=True)
    except:
        pass

def per_token_limit(limit_per_minute=60):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if redis_client and hasattr(g, 'inbox_token'):
                key = f"ratelimit:{g.inbox_token}"
                current = redis_client.incr(key)
                if current == 1:
                    redis_client.expire(key, 60)
                if current > limit_per_minute:
                    return jsonify({"error": "Inbox rate limit exceeded"}), 429
            return f(*args, **kwargs)
        return decorated
    return decorator

# ---------------------------------------------------
# SSE pub/sub (in‑memory, one listener per inbox)
# ---------------------------------------------------
sse_queues = {}
sse_lock = threading.Lock()

def get_sse_queue(inbox_token):
    with sse_lock:
        if inbox_token not in sse_queues:
            sse_queues[inbox_token] = queue_module.Queue()
        return sse_queues[inbox_token]

def notify_inbox(inbox_token, event_data):
    q = sse_queues.get(inbox_token)
    if q:
        try:
            q.put_nowait(event_data)
        except queue_module.Full:
            pass

# ---------------------------------------------------
# Inbox management helpers
# ---------------------------------------------------
def create_inbox(ip_address=None, captcha_token=None):
    # Optional: verify captcha if provided (implement later)
    # if captcha_token and not verify_turnstile(captcha_token):
    #     raise Exception("CAPTCHA failed")

    domain = random.choice(DOMAINS)
    local_part = secrets.token_urlsafe(8)
    address = f"{local_part}@{domain}"
    token = str(uuid.uuid4())

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO inboxes (token, address, domain, ip_address, created_at) VALUES (%s, %s, %s, %s, NOW())",
            (token, address, domain, ip_address)
        )
        conn.commit()
        cur.close()
    finally:
        put_db_connection(conn)

    return token, address

def get_inbox_email(token):
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
    matches = OTP_REGEX.findall(text)
    if not matches:
        return None, False
    text_lower = text.lower()
    for code in matches:
        if any(kw in text_lower for kw in OTP_KEYWORDS):
            return code, True
    return matches[0], False

def extract_message_id(raw_email):
    try:
        msg = email.message_from_string(raw_email, policy=policy.default)
        return msg.get("Message-ID", "").strip()
    except Exception:
        return None

def sanitize_html(html_content):
    """Remove all dangerous tags and attributes using nh3 (ammonia wrapper)."""
    return nh3.clean(html_content, tags=nh3.ALLOWED_TAGS, attributes=nh3.ALLOWED_ATTRIBUTES)

def store_message(to_addr, from_addr, subject, body, raw_email=None):
    # Sanitize body if it contains HTML
    if body and ("<" in body and ">" in body):
        body = sanitize_html(body)

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
                body[:10000],  # limit body length to 10k chars
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

def get_single_message(msg_id, inbox_address):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT from_addr, subject, body, received_at, otp_code, otp_detected FROM messages WHERE id = %s AND to_addr = %s",
            (msg_id, inbox_address)
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

def delete_message_by_id(msg_id, inbox_address):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM messages WHERE id = %s AND to_addr = %s", (msg_id, inbox_address))
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

    # Validate required fields
    to_addr = data.get("to", "").strip()
    from_addr = data.get("from", "").strip()
    subject = data.get("subject", "").strip()
    if not to_addr or not from_addr:
        return "Missing to/from", 400

    # Limit email size
    raw_body = data.get("raw", "")
    if len(raw_body) > 2_000_000:  # 2MB
        print(f"Email too large: {len(raw_body)} bytes")
        return "Email too large", 413

    if raw_body and ("Received:" in raw_body or "MIME-Version:" in raw_body):
        body = extract_plain_text(raw_body)
    else:
        body = raw_body

    if not body:
        body = json.dumps(data, indent=2)

    # Optional: block known spammer domains
    blocked_domains = os.getenv("BLOCKED_SENDER_DOMAINS", "").split(",")
    if any(blocked in from_addr for blocked in blocked_domains):
        return "Blocked sender", 403

    def process():
        success = store_message(to_addr, from_addr, subject, body, raw_email=raw_body)
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
# Frontend routes (with session-based auth)
# ---------------------------------------------------
@app.route("/")
def index():
    is_logged_in = 'user' in session
    return render_template("index.html", is_logged_in=is_logged_in)

@app.route("/auth", methods=["GET", "POST"])
def auth():
    if request.method == "POST":
        # Simple demo login – accept any email/password for now
        # In a real app, validate credentials against a database.
        email = request.form.get("email")
        password = request.form.get("password")
        # For demo, just check that they filled something.
        if email and password:
            session['user'] = {'email': email}
            return redirect(url_for('index'))
        else:
            # Render auth page with error
            return render_template("auth.html", error="Please fill in all fields")
    else:
        # If already logged in, redirect to account page
        if 'user' in session:
            return redirect(url_for('account'))
        return render_template("auth.html")

@app.route("/logout")
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route("/account")
def account():
    if 'user' not in session:
        return redirect(url_for('auth'))
    return render_template("account.html", user=session['user'])

@app.route("/health")
def health():
    return jsonify({"status": "ok"})

# ---------------------------------------------------
# Inbox API (token required)
# ---------------------------------------------------
@app.route("/api/status", methods=["GET"])
@token_required
def status():
    return jsonify({
        "email": g.inbox_address,
        "token": g.inbox_token
    })

@app.route("/api/new", methods=["POST"])
@limiter.limit("10 per minute")
def new_address():
    ip = request.remote_addr
    # Optionally read captcha token from request body
    data = request.get_json(silent=True) or {}
    captcha_token = data.get("captcha_token")
    try:
        token, address = create_inbox(ip, captcha_token)
        return jsonify({
            "success": True,
            "email": address,
            "token": token  # return token directly (client must store it)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/inbox", methods=["GET"])
@token_required
@per_token_limit(limit_per_minute=60)
def inbox():
    try:
        messages = get_messages(g.inbox_address)
        return jsonify({"messages": messages})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/inbox/stream", methods=["GET"])
@token_required
def inbox_stream():
    def event_stream():
        q = get_sse_queue(g.inbox_token)
        while True:
            try:
                event = q.get(timeout=30)
                yield f"event: {event['type']}\n"
                yield f"data: {json.dumps(event['data'])}\n\n"
            except queue_module.Empty:
                yield ": heartbeat\n\n"
    return Response(stream_with_context(event_stream()), mimetype="text/event-stream")

@app.route("/api/message/<msg_id>", methods=["GET"])
@token_required
def get_message(msg_id):
    try:
        msg = get_single_message(msg_id, g.inbox_address)
        if not msg:
            return jsonify({"error": "Message not found"}), 404
        return jsonify(msg)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/delete/<msg_id>", methods=["POST"])
@token_required
def delete_message(msg_id):
    try:
        delete_message_by_id(msg_id, g.inbox_address)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/delete_all", methods=["POST"])
@token_required
def delete_all():
    try:
        delete_all_messages(g.inbox_address)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/delete_inbox", methods=["POST"])
@token_required
def delete_inbox():
    """Permanently delete the inbox and all messages."""
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM inboxes WHERE token = %s", (g.inbox_token,))
        conn.commit()
        cur.close()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        put_db_connection(conn)

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
# Cleanup cron (run every hour via external scheduler)
# ---------------------------------------------------
@app.route("/api/cleanup", methods=["POST"])
def cleanup():
    # Secure with a secret key
    if request.headers.get("X-Cleanup-Secret") != os.getenv("CLEANUP_SECRET"):
        return "Unauthorized", 401
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        # Delete messages older than 3 days
        cur.execute("DELETE FROM messages WHERE received_at < EXTRACT(EPOCH FROM NOW() - INTERVAL '3 days')")
        # Delete inboxes older than 24 hours
        cur.execute("DELETE FROM inboxes WHERE created_at < NOW() - INTERVAL '1 day'")
        conn.commit()
        cur.close()
        return "Cleanup done", 200
    finally:
        put_db_connection(conn)

# ---------------------------------------------------
# Main
# ---------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)

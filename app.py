import os
import random
import time
import uuid
from flask import Flask, request, jsonify, session, render_template
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import psycopg2
import psycopg2.pool
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ['SECRET_KEY']
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Rate limiting
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per minute"])
limiter.init_app(app)

# Domain pool
DOMAINS = [d.strip() for d in os.environ.get('DOMAINS', '').split(',') if d.strip()]
if not DOMAINS:
    raise Exception("No domains configured. Set DOMAINS in .env")

# PostgreSQL connection pool
db_pool = psycopg2.pool.SimpleConnectionPool(
    1, 20, os.environ['DATABASE_URL'] + '?sslmode=require'
)

def get_db_connection():
    return db_pool.getconn()

def put_db_connection(conn):
    db_pool.putconn(conn)

def store_message(to_addr, from_addr, subject, body):
    """Store an incoming email into the database."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO messages (id, to_addr, from_addr, subject, body, received_at) VALUES (%s, %s, %s, %s, %s, %s)",
        (str(uuid.uuid4()), to_addr, from_addr, subject, body, int(time.time()))
    )
    conn.commit()
    cur.close()
    put_db_connection(conn)

def get_messages(to_addr, limit=200):
    """Retrieve messages for a given email address, newest first."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, from_addr, subject, received_at, is_read FROM messages WHERE to_addr = %s ORDER BY received_at DESC LIMIT %s",
        (to_addr, limit)
    )
    rows = cur.fetchall()
    cur.close()
    put_db_connection(conn)
    return [
        {
            'id': str(r[0]),
            'from': r[1],
            'subject': r[2],
            'timestamp': r[3],
            'read': r[4]
        }
        for r in rows
    ]

def get_single_message(msg_id):
    """Fetch full details of one message by its UUID."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT from_addr, subject, body, received_at FROM messages WHERE id = %s",
        (msg_id,)
    )
    row = cur.fetchone()
    cur.close()
    put_db_connection(conn)
    if not row:
        return None
    return {
        'from': row[0],
        'subject': row[1],
        'body': row[2],
        'date': row[3]
    }

def delete_message_by_id(msg_id):
    """Delete a single message."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM messages WHERE id = %s", (msg_id,))
    conn.commit()
    cur.close()
    put_db_connection(conn)

def delete_all_messages(to_addr):
    """Delete all messages belonging to a specific email address."""
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM messages WHERE to_addr = %s", (to_addr,))
    conn.commit()
    cur.close()
    put_db_connection(conn)

# ---------- Webhook endpoint (receives emails from Cloudflare) ----------
@app.route('/webhook', methods=['POST'])
def webhook():
    """
    Cloudflare Email Routing sends a JSON POST to this endpoint.
    Expected JSON structure:
    {
        "to": "user@yourdomain.com",
        "from": "sender@example.com",
        "subject": "Hello",
        "text": "plain text body",
        "html": "<p>html body</p>"
    }
    """
    data = request.get_json()
    if not data:
        return 'Bad request: no JSON', 400

    to_addr = data.get('to', '').strip()
    from_addr = data.get('from', '').strip()
    subject = data.get('subject', '').strip()
    body = data.get('text', '') or data.get('html', '')

    if to_addr and from_addr:
        store_message(to_addr, from_addr, subject, body)

    return 'OK', 200

# ---------- Frontend API routes ----------
@app.route('/')
def index():
    """Serve the main frontend page."""
    return render_template('index.html')

@app.route('/health')
def health():
    """Health check for load balancers / monitoring."""
    return jsonify({'status': 'ok'})

@app.route('/api/status')
def session_status():
    """Return the current email address if a session exists."""
    if 'email' in session:
        return jsonify({'email': session['email']})
    return jsonify({'email': None})

@app.route('/api/new', methods=['POST'])
@limiter.limit("10 per minute")
def new_address():
    """
    Generate a new random email address using one of the owned domains.
    The address is stored in the user's session.
    """
    domain = random.choice(DOMAINS)
    local_part = uuid.uuid4().hex[:12]
    email = f"{local_part}@{domain}"
    session['email'] = email
    return jsonify({'success': True, 'email': email})

@app.route('/api/inbox')
@limiter.limit("60 per minute")
def inbox():
    """Return the list of messages for the current session's email address."""
    if 'email' not in session:
        return jsonify({'error': 'No active address. Please create one first.'}), 400
    messages = get_messages(session['email'])
    return jsonify({'messages': messages})

@app.route('/api/message/<msg_id>')
def get_message(msg_id):
    """Return full content of a single message."""
    if 'email' not in session:
        return jsonify({'error': 'No session'}), 400
    msg = get_single_message(msg_id)
    if not msg:
        return jsonify({'error': 'Message not found'}), 404
    return jsonify(msg)

@app.route('/api/delete/<msg_id>', methods=['POST'])
def delete_message(msg_id):
    """Delete a specific message."""
    if 'email' not in session:
        return jsonify({'error': 'No session'}), 400
    delete_message_by_id(msg_id)
    return jsonify({'success': True})

@app.route('/api/delete_all', methods=['POST'])
def delete_all():
    """Delete all messages for the current email address."""
    if 'email' not in session:
        return jsonify({'error': 'No session'}), 400
    delete_all_messages(session['email'])
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
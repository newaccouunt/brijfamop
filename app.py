import os, re, time, imaplib, email, datetime, random, string, base64, sqlite3, secrets
import json, hashlib, hmac, threading, queue, concurrent.futures
from io import BytesIO
from email.header import decode_header
from email.utils import parsedate_to_datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, session, g, redirect
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode

# ==========================================
# CONFIG
# ==========================================
app = Flask(__name__)
CORS(app, supports_credentials=True, resources={r"/*": {"origins": "*"}})
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=7)

DB_PATH = os.environ.get("DB_PATH", "fampay.db")
IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
BASE_URL = os.environ.get("BASE_URL", "")
APP_VERSION = "5.0.0 ULTRA SESSION"
BUILD_DATE = "2025"
BOOT_TIME = time.time()

# ==========================================
# DB
# ==========================================
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA synchronous=NORMAL")
        g.db.execute("PRAGMA cache_size=2000")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db: db.close()

def init_db():
    with sqlite3.connect(DB_PATH) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT DEFAULT '', upi_id TEXT DEFAULT '',
            mobile TEXT DEFAULT '', email TEXT DEFAULT '',
            app_password TEXT DEFAULT '', total_earning REAL DEFAULT 0,
            default_qr_minutes INTEGER DEFAULT 15,
            email_status TEXT DEFAULT 'unknown',
            email_last_check TEXT DEFAULT '',
            tolerance REAL DEFAULT 0.0,
            webhook_url TEXT DEFAULT '',
            auto_verify INTEGER DEFAULT 1,
            theme TEXT DEFAULT 'dark',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key TEXT UNIQUE NOT NULL, username TEXT NOT NULL,
            expiry TEXT NOT NULL, label TEXT DEFAULT '',
            total_requests INTEGER DEFAULT 0, total_qr INTEGER DEFAULT 0,
            total_received REAL DEFAULT 0,
            rate_limit INTEGER DEFAULT 60,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS qr_sessions (
            session_id TEXT PRIMARY KEY,
            order_id TEXT UNIQUE NOT NULL,
            api_key TEXT NOT NULL,
            username TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT DEFAULT 'PENDING',
            txn_id TEXT DEFAULT '', utr TEXT DEFAULT '',
            paid_amount REAL DEFAULT 0,
            partial_amount REAL DEFAULT 0,
            short_by REAL DEFAULT 0,
            overpaid REAL DEFAULT 0,
            total_paid REAL DEFAULT 0,
            payment_count INTEGER DEFAULT 0,
            notes TEXT DEFAULT '',
            created_at REAL NOT NULL, expires_at REAL NOT NULL,
            paid_at REAL DEFAULT 0,
            session_json TEXT DEFAULT '',
            tg_link TEXT DEFAULT '',
            web_link TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
            session_id TEXT, order_id TEXT, amount REAL NOT NULL,
            txn_id TEXT UNIQUE, utr TEXT,
            sender_name TEXT DEFAULT '',
            sender_upi TEXT DEFAULT '',
            email_date TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            paid_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS partial_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT, order_id TEXT, username TEXT,
            expected REAL, received REAL, short_by REAL,
            txn_id TEXT, utr TEXT,
            notified INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, action TEXT, details TEXT,
            ip TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_qr_apikey ON qr_sessions(api_key);
        CREATE INDEX IF NOT EXISTS idx_qr_status ON qr_sessions(status);
        CREATE INDEX IF NOT EXISTS idx_qr_session ON qr_sessions(session_id);
        CREATE INDEX IF NOT EXISTS idx_txn_username ON transactions(username);
        CREATE INDEX IF NOT EXISTS idx_partial_txn ON partial_payments(txn_id);
        """)
        if not db.execute("SELECT id FROM users WHERE username='admin'").fetchone():
            db.execute("INSERT INTO users (username,password_hash,full_name,upi_id) VALUES (?,?,?,?)",
                       ("admin", generate_password_hash("admin123"), "Riju Mondal", "riju@fam"))
        db.commit()
init_db()

# ==========================================
# HELPERS
# ==========================================
def login_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        if 'user' not in session:
            return jsonify({"error":"Unauthorized", "code":"AUTH_REQUIRED"}), 401
        return f(*a, **k)
    return wrapper

def gen_key(): return ''.join(random.choices(string.ascii_uppercase+string.digits, k=20))
def gen_order_id(): return "ORD" + str(int(time.time())) + ''.join(random.choices(string.digits, k=6))
def gen_session_id():
    return "SES" + ''.join(random.choices(string.ascii_letters + string.digits, k=20))

def qr_b64(data):
    q = qrcode.QRCode(version=1, box_size=10, border=4, error_correction=qrcode.constants.ERROR_CORRECT_M)
    q.add_data(data); q.make(fit=True)
    img = q.make_image(fill_color="black", back_color="white")
    buf = BytesIO(); img.save(buf, format="PNG")
    return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode()}"

def clean_body(msg):
    if msg.is_multipart():
        for p in msg.walk():
            if p.get_content_type()=="text/plain":
                try: return p.get_payload(decode=True).decode(errors="ignore")
                except: return ""
    else:
        try: return msg.get_payload(decode=True).decode(errors="ignore")
        except: return ""
    return ""

def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()

def audit(username, action, details="", ip=None):
    try:
        db = get_db()
        db.execute("INSERT INTO audit_log (username,action,details,ip) VALUES (?,?,?,?)",
                   (username, action, details[:500], ip or get_client_ip()))
        db.commit()
    except: pass

def parse_request_data():
    data = {}
    if request.is_json: data.update(request.get_json(silent=True) or {})
    if request.form: data.update(request.form.to_dict())
    if request.args: data.update(request.args.to_dict())
    if not data and request.data:
        try: data.update(json.loads(request.data.decode()))
        except: pass
    return data

def build_url(path):
    base = BASE_URL.rstrip('/') or request.host_url.rstrip('/')
    return base + path

def notify_webhook(username, event, payload):
    try:
        db = get_db()
        u = db.execute("SELECT webhook_url FROM users WHERE username=?", (username,)).fetchone()
        if u and u['webhook_url']:
            import urllib.request
            body = json.dumps({"event": event, "data": payload, "ts": time.time()}).encode()
            req = urllib.request.Request(u['webhook_url'], data=body,
                                          headers={"Content-Type":"application/json","User-Agent":"FamPay-AutoQR/5.0"})
            urllib.request.urlopen(req, timeout=3)
    except: pass

# ==========================================
# FLASH SPEED EMAIL CHECK
# ==========================================
def strip_personal_lines(body):
    lines = body.split('\n')
    cleaned = []
    for line in lines:
        t = line.strip()
        if re.match(r'^hey\s+[a-z\s]+[,\.]?$', t, re.I):
            continue
        if re.match(r'^updated\s+balance\s*[:\-]?', t, re.I):
            continue
        cleaned.append(line)
    return '\n'.join(cleaned)

def extract_sender(body):
    sender_name = ''
    sender_upi = ''
    m = re.search(r'from\s+([a-z0-9._\-]+)@([a-z0-9.\-]+)', body, re.I)
    if m:
        sender_upi = f"{m.group(1)}@{m.group(2)}"
    m2 = re.search(r'received\s+.*?from\s+([^\n]+?)(?:\n|$)', body, re.I)
    if m2:
        line = m2.group(1).strip()
        name_part = re.split(r'[<@]', line)[0].strip()
        if name_part:
            sender_name = name_part
    if not sender_upi:
        m3 = re.search(r'([a-z0-9._\-]+@[a-z0-9.\-]+)', body, re.I)
        if m3: sender_upi = m3.group(1)
    return sender_name[:60], sender_upi[:80]

def extract_email_date(body):
    m = re.search(r'Date\s*[:\-]\s*([^\n]+)', body, re.I)
    if m: return m.group(1).strip()[:100]
    return ''

def read_fampay_email(username, expected_amount, tolerance=0.0, window_minutes=2):
    """
    Returns:
      (True,  {txn data}, "PAID")       -- EXACT match
      (False, {partial data}, "PARTIAL") -- short/over
      (False, None, "NO_EMAIL")
      (False, None, error)
    """
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not u or not u['email'] or not u['app_password']:
        return False, None, "Email/App Password missing"

    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com", timeout=6)
        mail.login(u['email'], u['app_password'].replace(" ", ""))
        mail.select("inbox", readonly=False)

        now_ist = datetime.datetime.now(IST)
        cutoff = now_ist - datetime.timedelta(minutes=window_minutes)
        imap_date = cutoff.strftime("%d-%b-%Y")

        status, messages = mail.search(None, f'(SINCE "{imap_date}" UNSEEN)')
        if status != "OK" or not messages[0]:
            mail.logout()
            return False, None, "NO_EMAIL"

        email_ids = messages[0].split()
        if not email_ids:
            mail.logout()
            return False, None, "NO_EMAIL"

        latest_ids = email_ids[-5:]

        for e_id in reversed(latest_ids):
            status, data = mail.fetch(e_id, '(RFC822)')
            for rp in data:
                if not isinstance(rp, tuple): continue
                msg = email.message_from_bytes(rp[1])

                subj = msg.get('subject', '')
                if "Fam" not in subj and "fam" not in subj: continue

                try:
                    dt = parsedate_to_datetime(msg.get('date')).astimezone(IST)
                    if dt < cutoff: continue
                except: continue

                raw_body = clean_body(msg)
                body = strip_personal_lines(raw_body)

                am = re.search(r'₹\s?([\d,]+\.?\d*)', body)
                if not am: continue
                recv = float(am.group(1).replace(",", ""))

                txn_m = re.search(r'Transaction ID\s*[:\-]?\s*([A-Z0-9]+)', body, re.I)
                txn_id = txn_m.group(1) if txn_m else f"AUTO{int(time.time())}{random.randint(100,999)}"

                utr_m = re.search(r'UTR\s*[:\-]?\s*(\d+)', body, re.I)
                utr = utr_m.group(1) if utr_m else ""

                sender_name, sender_upi = extract_sender(raw_body)
                email_date = extract_email_date(raw_body)
                if not email_date:
                    email_date = dt.strftime("%d %b %Y, %I:%M %p IST")

                dup = db.execute("SELECT id FROM transactions WHERE txn_id=?", (txn_id,)).fetchone()
                if dup:
                    mail.store(e_id, '+FLAGS', '\\Seen')
                    continue

                exact_min = expected_amount - tolerance
                exact_max = expected_amount + tolerance

                if exact_min <= recv <= exact_max:
                    mail.store(e_id, '+FLAGS', '\\Seen')
                    mail.logout()
                    return True, {
                        "txn_id": txn_id, "utr": utr, "amount": recv,
                        "expected": expected_amount, "kind": "EXACT",
                        "sender_name": sender_name,
                        "sender_upi": sender_upi,
                        "email_date": email_date
                    }, "PAID"

                elif recv < exact_min:
                    short_by = round(expected_amount - recv, 2)
                    mail.store(e_id, '+FLAGS', '\\Seen')
                    mail.logout()
                    return False, {
                        "txn_id": txn_id, "utr": utr, "amount": recv,
                        "expected": expected_amount, "short_by": short_by,
                        "kind": "SHORT",
                        "sender_name": sender_name,
                        "sender_upi": sender_upi,
                        "email_date": email_date
                    }, "PARTIAL"
                else:
                    over = round(recv - expected_amount, 2)
                    mail.store(e_id, '+FLAGS', '\\Seen')
                    mail.logout()
                    return False, {
                        "txn_id": txn_id, "utr": utr, "amount": recv,
                        "expected": expected_amount, "overpaid": over,
                        "kind": "OVER",
                        "sender_name": sender_name,
                        "sender_upi": sender_upi,
                        "email_date": email_date
                    }, "PARTIAL"

        mail.logout()
        return False, None, "NO_EMAIL"
    except Exception as e:
        return False, None, str(e)

# ==========================================
# ⚡ SESSION-AWARE VERIFICATION CORE
# Handles: multi-payment, partial, overpay, session linking
# ==========================================
def build_session_json(s):
    """Create the JSON result that /session/<session_id> will return."""
    db = get_db()
    txns = db.execute("SELECT * FROM transactions WHERE session_id=? ORDER BY id ASC",
                      (s['session_id'],)).fetchall()
    return {
        "status": s['status'],
        "session_id": s['session_id'],
        "order_id": s['order_id'],
        "expected": round(s['amount'], 2),
        "total_paid": round(s['total_paid'], 2),
        "payment_count": s['payment_count'],
        "txn_id": s['txn_id'],
        "utr": s['utr'],
        "paid_at": s['paid_at'],
        "created_at": s['created_at'],
        "expires_at": s['expires_at'],
        "payments": [{
            "txn_id": t['txn_id'], "utr": t['utr'],
            "amount": round(t['amount'], 2),
            "sender_name": t['sender_name'] or '',
            "sender_upi": t['sender_upi'] or '',
            "email_date": t['email_date'] or '',
            "paid_at": t['paid_at']
        } for t in txns],
        "verified": s['status'] == 'PAID'
    }

def _apply_payment_to_session(s, info, key_row):
    """Apply a payment (full or partial) to a session. Multi-payment aware."""
    db = get_db()
    sess_id = s['session_id']
    recv_amt = round(info['amount'], 2)

    # Recompute totals from transactions for accuracy
    total_paid = db.execute(
        "SELECT COALESCE(SUM(amount),0) AS s FROM transactions WHERE session_id=?",
        (sess_id,)).fetchone()['s']
    new_total = round((total_paid or 0) + recv_amt, 2)

    # Insert transaction row
    try:
        db.execute("""INSERT INTO transactions
                      (username, session_id, order_id, amount, txn_id, utr, sender_name, sender_upi, email_date)
                      VALUES (?,?,?,?,?,?,?,?,?)""",
                   (s['username'], sess_id, s['order_id'], recv_amt,
                    info['txn_id'], info['utr'],
                    info.get('sender_name',''), info.get('sender_upi',''),
                    info.get('email_date','')))
    except sqlite3.IntegrityError:
        # already recorded
        pass

    expected = round(s['amount'], 2)
    tol = float(info.get('tol', 0) or 0)

    if new_total >= (expected - tol):
        # FULL (or over) — mark PAID
        overpaid = max(0, round(new_total - expected, 2))
        db.execute("""UPDATE qr_sessions
                      SET status='PAID', txn_id=?, utr=?, paid_amount=?, total_paid=?,
                          payment_count=payment_count+1, short_by=0, overpaid=?,
                          partial_amount=?, paid_at=?
                      WHERE session_id=?""",
                   (info['txn_id'], info['utr'], new_total, new_total,
                    overpaid, new_total, time.time(), sess_id))
        db.execute("UPDATE users SET total_earning=total_earning+? WHERE username=?",
                   (recv_amt, s['username']))
        db.execute("UPDATE api_keys SET total_received=total_received+? WHERE api_key=?",
                   (recv_amt, key_row['api_key']))
        db.commit()

        # refresh
        s2 = db.execute("SELECT * FROM qr_sessions WHERE session_id=?", (sess_id,)).fetchone()
        sj = build_session_json(s2)
        db.execute("UPDATE qr_sessions SET session_json=? WHERE session_id=?",
                   (json.dumps(sj), sess_id))
        db.commit()

        notify_webhook(s['username'], "payment.success", sj)
        return True, sj

    else:
        # PARTIAL — update running totals, keep PENDING
        short_by = round(expected - new_total, 2)
        db.execute("""UPDATE qr_sessions
                      SET status='PENDING', txn_id=?, utr=?, partial_amount=?,
                          total_paid=?, payment_count=payment_count+1, short_by=?
                      WHERE session_id=?""",
                   (info['txn_id'], info['utr'], new_total,
                    new_total, short_by, sess_id))
        # log the partial payment event
        db.execute("""INSERT INTO partial_payments
                      (session_id, order_id, username, expected, received, short_by, txn_id, utr)
                      VALUES (?,?,?,?,?,?,?,?)""",
                   (sess_id, s['order_id'], s['username'], expected, recv_amt,
                    short_by, info['txn_id'], info['utr']))
        db.execute("UPDATE users SET total_earning=total_earning+? WHERE username=?",
                   (recv_amt, s['username']))
        db.execute("UPDATE api_keys SET total_received=total_received+? WHERE api_key=?",
                   (recv_amt, key_row['api_key']))
        db.commit()

        # build session json snapshot
        s2 = db.execute("SELECT * FROM qr_sessions WHERE session_id=?", (sess_id,)).fetchone()
        sj = build_session_json(s2)
        db.execute("UPDATE qr_sessions SET session_json=? WHERE session_id=?",
                   (json.dumps(sj), sess_id))
        db.commit()

        notify_webhook(s['username'], "payment.partial", {
            "session_id": sess_id, "order_id": s['order_id'],
            "expected": expected, "received_total": new_total,
            "short_by": short_by, "message": f"Please pay ₹{short_by:.2f} more to complete."
        })
        return False, sj

# ==========================================
# AUTH
# ==========================================
@app.route('/api/register', methods=['POST'])
def register():
    d = parse_request_data()
    u = (d.get('username') or '').strip().lower()
    p = d.get('password') or ''
    em = (d.get('email') or '').strip()
    if len(u) < 3 or len(p) < 4:
        return jsonify({"error":"Min 3 chars username, 4 chars password"}), 400
    if u and not re.match(r'^[a-z0-9_]+$', u):
        return jsonify({"error":"Username: a-z, 0-9, _ only"}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO users (username,password_hash,email) VALUES (?,?,?)",
                   (u, generate_password_hash(p), em))
        db.commit()
        audit(u, "REGISTER", f"New user from {get_client_ip()}")
        return jsonify({"status":"success", "message":"Account created. Please login."})
    except sqlite3.IntegrityError:
        return jsonify({"error":"Username already exists"}), 409

@app.route('/api/login', methods=['POST'])
def login():
    d = parse_request_data()
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username=?", (d.get('username','').strip().lower(),)).fetchone()
    if row and check_password_hash(row['password_hash'], d.get('password','')):
        session.permanent = True
        session['user'] = row['username']
        audit(row['username'], "LOGIN", "OK")
        return jsonify({"status":"success","user":row['username'],"version":APP_VERSION})
    audit(d.get('username','?'), "LOGIN_FAIL", get_client_ip())
    return jsonify({"error":"Invalid credentials"}), 401

@app.route('/api/logout', methods=['POST', 'GET'])
def logout():
    session.clear(); return jsonify({"status":"success"})

@app.route('/api/me', methods=['GET'])
@login_required
def me():
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE username=?", (session['user'],)).fetchone()
    return jsonify({
        "username": u['username'], "full_name": u['full_name'], "upi_id": u['upi_id'],
        "mobile": u['mobile'], "email": u['email'], "has_app_password": bool(u['app_password']),
        "total_earning": round(u['total_earning'],2), "default_qr_minutes": u['default_qr_minutes'],
        "email_status": u['email_status'], "email_last_check": u['email_last_check'],
        "tolerance": u['tolerance'] or 0, "webhook_url": u['webhook_url'] or '',
        "auto_verify": u['auto_verify'], "theme": u['theme'] or 'dark',
        "version": APP_VERSION, "boot_time": BOOT_TIME
    })

@app.route('/api/setup-account', methods=['POST'])
@login_required
def setup_account():
    d = parse_request_data()
    db = get_db()
    db.execute("""UPDATE users SET full_name=?, upi_id=?, mobile=?, email=?, app_password=?,
                  default_qr_minutes=?, tolerance=?, webhook_url=?, auto_verify=?, theme=?
                  WHERE username=?""",
               (d.get('full_name','').strip(), d.get('upi_id','').strip(), d.get('mobile','').strip(),
                d.get('email','').strip(), d.get('app_password','').strip(),
                int(d.get('default_qr_minutes', 15)),
                float(d.get('tolerance', 0) or 0),
                d.get('webhook_url','').strip(),
                int(d.get('auto_verify', 1)),
                d.get('theme', 'dark'),
                session['user']))
    db.commit()
    audit(session['user'], "SETUP_ACCOUNT", "Account details updated")
    return jsonify({"status":"success", "message": "Saved!"})

@app.route('/api/test-email', methods=['POST'])
@login_required
def test_email():
    d = parse_request_data()
    email_addr = (d.get('email') or '').strip()
    app_pass = (d.get('app_password') or '').strip()
    if not email_addr or not app_pass:
        return jsonify({"ok": False, "error": "Email and App Password required"}), 400
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com", timeout=10)
        mail.login(email_addr, app_pass.replace(" ", ""))
        mail.select("inbox", readonly=True)
        typ, msgs = mail.search(None, 'ALL')
        total = len(msgs[0].split()) if msgs and msgs[0] else 0
        typ, msgs = mail.search(None, '(UNSEEN)')
        unseen = len(msgs[0].split()) if msgs and msgs[0] else 0
        mail.logout()
        db = get_db()
        db.execute("UPDATE users SET email_status='online', email_last_check=? WHERE username=?",
                   (datetime.datetime.now(IST).isoformat(), session['user']))
        db.commit()
        return jsonify({"ok": True, "message": "✅ Gmail connected!", "total_emails": total, "unseen_emails": unseen})
    except Exception as e:
        db = get_db()
        db.execute("UPDATE users SET email_status='offline' WHERE username=?", (session['user'],))
        db.commit()
        return jsonify({"ok": False, "error": f"❌ Failed: {str(e)}"}), 400

# ==========================================
# ANALYTICS
# ==========================================
def _sum_between(db, username, start_dt, end_dt):
    s = db.execute("""SELECT COALESCE(SUM(amount),0) as s FROM transactions 
                      WHERE username=? AND paid_at>=? AND paid_at<?""",
                   (username, start_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    end_dt.strftime("%Y-%m-%d %H:%M:%S"))).fetchone()['s']
    return round(s or 0, 2)

def _count_between(db, username, start_dt, end_dt):
    c = db.execute("""SELECT COUNT(*) as c FROM transactions 
                      WHERE username=? AND paid_at>=? AND paid_at<?""",
                   (username, start_dt.strftime("%Y-%m-%d %H:%M:%S"),
                    end_dt.strftime("%Y-%m-%d %H:%M:%S"))).fetchone()['c']
    return c or 0

@app.route('/api/analytics', methods=['GET'])
@login_required
def analytics():
    db = get_db()
    u = session['user']
    now = datetime.datetime.now(IST)
    
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_sum = _sum_between(db, u, today_start, now + datetime.timedelta(seconds=1))
    today_count = _count_between(db, u, today_start, now + datetime.timedelta(seconds=1))
    
    week_start = today_start - datetime.timedelta(days=6)
    week_sum = _sum_between(db, u, week_start, now + datetime.timedelta(seconds=1))
    week_count = _count_between(db, u, week_start, now + datetime.timedelta(seconds=1))
    
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    month_sum = _sum_between(db, u, month_start, now + datetime.timedelta(seconds=1))
    month_count = _count_between(db, u, month_start, now + datetime.timedelta(seconds=1))
    
    year_start = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
    year_sum = _sum_between(db, u, year_start, now + datetime.timedelta(seconds=1))
    year_count = _count_between(db, u, year_start, now + datetime.timedelta(seconds=1))
    
    days_7 = []
    for i in range(6, -1, -1):
        day = (now - datetime.timedelta(days=i))
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + datetime.timedelta(days=1)
        amt = _sum_between(db, u, day_start, day_end)
        days_7.append({"day": day.strftime("%a"), "date": day.strftime("%d"),
                       "full": day.strftime("%Y-%m-%d"), "amount": amt})
    
    months_12 = []
    for i in range(11, -1, -1):
        y = now.year
        m = now.month - i
        while m <= 0: m += 12; y -= 1
        m_start = datetime.datetime(y, m, 1, tzinfo=IST)
        m_end = datetime.datetime(y+1, 1, 1, tzinfo=IST) if m == 12 else datetime.datetime(y, m+1, 1, tzinfo=IST)
        amt = _sum_between(db, u, m_start, min(m_end, now + datetime.timedelta(seconds=1)))
        months_12.append({"month": m_start.strftime("%b"), "year": y, "amount": amt})
    
    years_5 = []
    for i in range(4, -1, -1):
        y = now.year - i
        y_start = datetime.datetime(y, 1, 1, tzinfo=IST)
        y_end = datetime.datetime(y+1, 1, 1, tzinfo=IST)
        amt = _sum_between(db, u, y_start, min(y_end, now + datetime.timedelta(seconds=1)))
        years_5.append({"year": y, "amount": amt})
    
    weekday_dist = [0]*7
    rows = db.execute("SELECT amount, paid_at FROM transactions WHERE username=?", (u,)).fetchall()
    for r in rows:
        try:
            dt = datetime.datetime.strptime(r['paid_at'], "%Y-%m-%d %H:%M:%S")
            weekday_dist[dt.weekday()] += r['amount']
        except: pass
    weekday_names = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
    
    return jsonify({
        "today":   {"amount": today_sum, "count": today_count},
        "week":    {"amount": week_sum, "count": week_count},
        "month":   {"amount": month_sum, "count": month_count},
        "year":    {"amount": year_sum, "count": year_count},
        "days_7": days_7, "months_12": months_12, "years_5": years_5,
        "weekday_dist": [{"day": weekday_names[i], "amount": round(weekday_dist[i],2)} for i in range(7)]
    })

# ==========================================
# DASHBOARD
# ==========================================
@app.route('/api/dashboard', methods=['GET'])
@login_required
def dashboard():
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE username=?", (session['user'],)).fetchone()
    keys = db.execute("SELECT * FROM api_keys WHERE username=?", (session['user'],)).fetchall()
    txns = db.execute("SELECT * FROM transactions WHERE username=? ORDER BY id DESC LIMIT 50",
                      (session['user'],)).fetchall()
    partials = db.execute("SELECT * FROM partial_payments WHERE username=? ORDER BY id DESC LIMIT 20",
                          (session['user'],)).fetchall()
    return jsonify({
        "total_earning": round(u['total_earning'],2), "upi_id": u['upi_id'],
        "email_status": u['email_status'], "email_last_check": u['email_last_check'],
        "total_api_keys": len(keys),
        "total_requests": sum(k['total_requests'] for k in keys),
        "total_qr_generated": sum(k['total_qr'] for k in keys),
        "total_received_via_api": round(sum(k['total_received'] for k in keys),2),
        "transactions": [{
            "amount": t['amount'], "txn_id": t['txn_id'], "utr": t['utr'],
            "session_id": t['session_id'],
            "order_id": t['order_id'], "paid_at": t['paid_at'],
            "sender_name": t['sender_name'] or '',
            "sender_upi": t['sender_upi'] or '',
            "email_date": t['email_date'] or ''
        } for t in txns],
        "partial_payments": [{
            "session_id": p['session_id'],
            "order_id": p['order_id'], "expected": p['expected'],
            "received": p['received'], "short_by": p['short_by'],
            "txn_id": p['txn_id'], "created_at": p['created_at']
        } for p in partials]
    })

# ==========================================
# KEYS
# ==========================================
@app.route('/api/generate-key', methods=['POST'])
@login_required
def gen_key_api():
    d = parse_request_data()
    mode = d.get('mode', 'days')
    days = int(d.get('days', 30) or 30)
    label = (d.get('label', '') or '')[:40]
    rate_limit = int(d.get('rate_limit', 60) or 60)
    expiry = 'LIFETIME' if mode == 'lifetime' else (datetime.datetime.now()+datetime.timedelta(days=days)).isoformat()
    key = gen_key()
    db = get_db()
    db.execute("INSERT INTO api_keys (api_key,username,expiry,label,rate_limit) VALUES (?,?,?,?,?)",
               (key, session['user'], expiry, label, rate_limit))
    db.commit()
    audit(session['user'], "GEN_KEY", f"Key={key[:8]}... mode={mode}")
    return jsonify({"status":"success", "api_key": key, "expiry": expiry,
        "api_url": build_url(f"/v2/fam/{key}"),
        "example": build_url(f"/v2/fam/{key}?qr=100"),
        "check_url": build_url(f"/api/v2/check/{key}"),
        "session_url": build_url(f"/api/session/<session_id>")})

@app.route('/api/list-keys', methods=['GET'])
@login_required
def list_keys():
    db = get_db()
    rows = db.execute("SELECT * FROM api_keys WHERE username=? ORDER BY id DESC", (session['user'],)).fetchall()
    return jsonify([{
        "api_key": r['api_key'], "expiry": r['expiry'], "label": r['label'],
        "total_requests": r['total_requests'], "total_qr": r['total_qr'],
        "total_received": round(r['total_received'],2),
        "rate_limit": r['rate_limit'],
        "url": build_url(f"/v2/fam/{r['api_key']}"),
        "check_url": build_url(f"/api/v2/check/{r['api_key']}"),
        "session_url": build_url("/api/session/<session_id>")
    } for r in rows])

@app.route('/api/delete-key/<api_key>', methods=['DELETE'])
@login_required
def del_key(api_key):
    db = get_db()
    db.execute("DELETE FROM api_keys WHERE api_key=? AND username=?", (api_key, session['user']))
    db.commit()
    audit(session['user'], "DEL_KEY", api_key[:8])
    return jsonify({"status":"success"})

@app.route('/api/transactions', methods=['GET'])
@login_required
def list_txns():
    db = get_db()
    limit = min(int(request.args.get('limit', 100)), 500)
    txns = db.execute("SELECT * FROM transactions WHERE username=? ORDER BY id DESC LIMIT ?",
                      (session['user'], limit)).fetchall()
    return jsonify([{
        "amount": t['amount'], "txn_id": t['txn_id'], "utr": t['utr'],
        "session_id": t['session_id'],
        "order_id": t['order_id'], "paid_at": t['paid_at'],
        "sender_name": t['sender_name'] or '',
        "sender_upi": t['sender_upi'] or '',
        "email_date": t['email_date'] or ''
    } for t in txns])

@app.route('/api/partial-payments', methods=['GET'])
@login_required
def list_partials():
    db = get_db()
    rows = db.execute("SELECT * FROM partial_payments WHERE username=? ORDER BY id DESC LIMIT 100",
                      (session['user'],)).fetchall()
    return jsonify([{
        "session_id": p['session_id'],
        "order_id": p['order_id'], "expected": p['expected'],
        "received": p['received'], "short_by": p['short_by'],
        "txn_id": p['txn_id'], "utr": p['utr'],
        "created_at": p['created_at']
    } for p in rows])

@app.route('/api/audit-log')
@login_required
def audit_log():
    db = get_db()
    rows = db.execute("SELECT * FROM audit_log WHERE username=? ORDER BY id DESC LIMIT 100",
                      (session['user'],)).fetchall()
    return jsonify([{
        "action": r['action'], "details": r['details'],
        "ip": r['ip'], "created_at": r['created_at']
    } for r in rows])

# ==========================================
# PAYMENT VERIFICATION CORE
# ==========================================
def _key_status(key):
    db = get_db()
    clean_key = (key or '').split('&')[0].split('?')[0].strip()
    row = db.execute("SELECT * FROM api_keys WHERE api_key=?", (clean_key,)).fetchone()
    if not row: return None, "invalid"
    if row['expiry'] != 'LIFETIME':
        try:
            if datetime.datetime.now() > datetime.datetime.fromisoformat(row['expiry']):
                return row, "expired"
        except: pass
    return row, "active"

def _verify_session(s, key_row):
    """Poll email for this session. Session-isolated."""
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (s['username'],)).fetchone()
    tol = (user['tolerance'] if user else 0) or 0

    expected = round(s['amount'], 2)
    already_paid = round(s['total_paid'] or 0, 2)
    remaining = round(max(0, expected - already_paid), 2)

    if remaining <= 0:
        return s['status']

    # Read email — but expected_amount should be "remaining" so any payment
    # up to remaining is accepted; partial detection uses tolerance-based match
    ok, info, status = read_fampay_email(
        s['username'],
        expected_amount=remaining,
        tolerance=tol,
        window_minutes=2
    )

    if status == "PAID" and ok:
        info['tol'] = tol
        _apply_payment_to_session(s, info, key_row)
    elif status == "PARTIAL" and info:
        # Short payment — record it, session remains PENDING
        info['tol'] = tol
        _apply_payment_to_session(s, info, key_row)
    return "OK"

# ==========================================
# PUBLIC QR PAGE (V5)
# ==========================================
@app.route('/v2/fam/<path:api_key>')
def fam_qr(api_key):
    amount_str = request.args.get('qr')
    if not amount_str and '&qr=' in request.full_path:
        amount_str = request.full_path.split('&qr=')[1].split('&')[0].split('?')[0]

    if not amount_str:
        return render_template_string(ERROR_HTML, msg="Missing amount. Use ?qr=100"), 400
    try:
        amount = float(amount_str)
        if amount <= 0: raise ValueError()
    except:
        return render_template_string(ERROR_HTML, msg="Invalid amount"), 400

    key_row, status = _key_status(api_key)
    if status == "invalid":
        return render_template_string(ERROR_HTML, msg="❌ Invalid API Key"), 403
    if status == "expired":
        return render_template_string(ERROR_HTML, msg="❌ API Key Expired"), 403

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (key_row['username'],)).fetchone()
    if not user or not user['upi_id']:
        return render_template_string(ERROR_HTML, msg="❌ UPI not configured"), 400

    db.execute("UPDATE api_keys SET total_requests=total_requests+1, total_qr=total_qr+1 WHERE api_key=?",
               (key_row['api_key'],))
    db.commit()

    minutes = int(request.args.get('minutes', user['default_qr_minutes'] or 15))
    upi = f"upi://pay?pa={user['upi_id']}&pn={user['full_name'] or user['username']}&am={amount}&cu=INR"
    order_id = gen_order_id()
    session_id = gen_session_id()
    now = time.time()

    # Build session links
    tg_link = build_url(f"/tg/session/{session_id}")
    web_link = build_url(f"/api/session/{session_id}")

    db.execute("""INSERT INTO qr_sessions 
                  (session_id, order_id, api_key, username, amount, created_at, expires_at, tg_link, web_link)
                  VALUES (?,?,?,?,?,?,?,?,?)""",
               (session_id, order_id, key_row['api_key'], key_row['username'], amount, now, now + minutes*60, tg_link, web_link))
    db.commit()
    audit(key_row['username'], "QR_GENERATED", f"session={session_id} order={order_id} amt={amount}")

    qr_image = qr_b64(upi)
    return render_template_string(
        QR_HTML_TEMPLATE_V5,
        amount=amount, qr_b64=qr_image, order_id=order_id,
        session_id=session_id,
        upi_id=user['upi_id'], full_name=user['full_name'] or user['username'],
        minutes=minutes, tolerance=user['tolerance'] or 0,
        brand=APP_VERSION,
        tg_link=tg_link, web_link=web_link,
        domain=BASE_URL or request.host_url.rstrip('/')
    )

# ==========================================
# SESSION RESULT ENDPOINT (JSON)
# ==========================================
@app.route('/api/session/<session_id>')
def session_result(session_id):
    db = get_db()
    s = db.execute("SELECT * FROM qr_sessions WHERE session_id=?", (session_id,)).fetchone()
    if not s:
        return jsonify({"status": "NOTFOUND", "session_id": session_id}), 404
    return jsonify(build_session_json(s))

# ==========================================
# TG UNIVERSAL LINK (Bot-friendly)
# ==========================================
@app.route('/tg/session/<session_id>')
def tg_session(session_id):
    db = get_db()
    s = db.execute("SELECT * FROM qr_sessions WHERE session_id=?", (session_id,)).fetchone()
    if not s:
        return render_template_string(ERROR_HTML, msg="Session not found"), 404
    sj = build_session_json(s)

    if s['status'] == 'PAID':
        title = "✅ PAYMENT SUCCESSFUL"
        color = "#00e0a4"
        lines = [
            f"💰 Amount: ₹{sj['total_paid']:.2f}",
            f"🆔 Txn ID: {sj['txn_id'] or '-'}",
            f"🔢 UTR: {sj['utr'] or '-'}",
            f"📦 Order: {sj['order_id']}",
            f"🔗 Session: {sj['session_id']}",
            "",
            "📋 Payments:"
        ]
        for i, p in enumerate(sj['payments'], 1):
            lines.append(
                f"{i}. ₹{p['amount']:.2f} from {p['sender_name'] or p['sender_upi'] or 'Unknown'}"
                f" — Txn {p['txn_id']}"
            )
    elif s['status'] == 'PENDING' and sj['payment_count'] > 0:
        title = "⚠️ PARTIAL PAYMENT RECEIVED"
        color = "#ffa502"
        short = round(sj['expected'] - sj['total_paid'], 2)
        lines = [
            f"💵 Expected: ₹{sj['expected']:.2f}",
            f"📥 Received: ₹{sj['total_paid']:.2f}",
            f"🔴 Remaining: ₹{short:.2f}",
            "",
            f"👉 Please pay ₹{short:.2f} more to complete.",
            f"Same QR is still valid until expiry."
        ]
    elif s['status'] == 'EXPIRED':
        title = "⏰ QR EXPIRED"
        color = "#ff4757"
        lines = [f"Expected: ₹{sj['expected']:.2f}", f"Received: ₹{sj['total_paid']:.2f}"]
    else:
        title = "⏳ AWAITING PAYMENT"
        color = "#00d4ff"
        lines = [
            f"💵 Expected: ₹{sj['expected']:.2f}",
            f"⏰ Expires: {datetime.datetime.fromtimestamp(sj['expires_at'], tz=IST).strftime('%d %b %Y, %I:%M %p IST')}"
        ]

    html = f"""
    <!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{title}</title>
    <style>
    body{{background:#05050a;color:#e8e8f5;font-family:-apple-system,Segoe UI,Roboto,sans-serif;
      margin:0;padding:20px;display:flex;justify-content:center;min-height:100vh;box-sizing:border-box}}
    .card{{max-width:500px;width:100%;background:#0f0f1e;border:1px solid #1f1f3a;border-radius:18px;
      padding:24px;box-shadow:0 0 60px {color}40;align-self:flex-start}}
    h1{{color:{color};font-size:20px;margin:0 0 16px;text-align:center}}
    pre{{background:#02020a;padding:16px;border-radius:10px;font-family:'Space Mono',monospace;
      font-size:12px;color:#00ffb3;overflow-x:auto;white-space:pre-wrap;word-break:break-all;
      border:1px solid #1f1f3a;line-height:1.6;margin:0}}
    .json-note{{font-size:11px;color:#7a7a9a;text-align:center;margin-top:14px}}
    a{{color:#00d4ff}}
    </style></head><body>
    <div class="card">
      <h1>{title}</h1>
      <pre>{chr(10).join(lines)}</pre>
      <div class="json-note">
        API: <a href="/api/session/{session_id}">/api/session/{session_id}</a>
      </div>
    </div></body></html>
    """
    return html

# ==========================================
# JSON CHECK (multi-payment aware)
# ==========================================
@app.route('/api/v2/check/<path:api_key>')
def api_check_v2(api_key):
    key_row, status = _key_status(api_key)
    if status != "active":
        return jsonify({"status": "ERROR", "error": status, "code": 403}), 403

    db = get_db()
    session_id = request.args.get('session_id')
    order_id = request.args.get('order_id')

    if session_id:
        s = db.execute("SELECT * FROM qr_sessions WHERE session_id=? AND api_key=?",
                       (session_id, key_row['api_key'])).fetchone()
    elif order_id:
        s = db.execute("SELECT * FROM qr_sessions WHERE order_id=? AND api_key=?",
                       (order_id, key_row['api_key'])).fetchone()
    else:
        s = db.execute("SELECT * FROM qr_sessions WHERE api_key=? ORDER BY created_at DESC LIMIT 1",
                       (key_row['api_key'],)).fetchone()

    if not s:
        return jsonify({"status": "NOTFOUND"})

    # Paid?
    if s['status'] == 'PAID':
        return jsonify(build_session_json(s))

    # Expired?
    if s['status'] == 'EXPIRED' or time.time() > s['expires_at']:
        if s['status'] != 'EXPIRED':
            db.execute("UPDATE qr_sessions SET status='EXPIRED' WHERE session_id=?", (s['session_id'],))
            db.commit()
        return jsonify(build_session_json(db.execute("SELECT * FROM qr_sessions WHERE session_id=?",
                                                   (s['session_id'],)).fetchone()))

    # Try verify
    _verify_session(s, key_row)
    s = db.execute("SELECT * FROM qr_sessions WHERE session_id=?", (s['session_id'],)).fetchone()
    return jsonify(build_session_json(s))

@app.route('/api/check-payment/<order_id>')
def check_payment(order_id):
    db = get_db()
    s = db.execute("SELECT * FROM qr_sessions WHERE order_id=?", (order_id,)).fetchone()
    if not s:
        return jsonify({"status": "NOTFOUND"}), 404

    if s['status'] == 'PAID':
        return jsonify({"status": "PAID", "session": build_session_json(s)})

    if time.time() > s['expires_at'] and s['status'] != 'PAID':
        if s['status'] != 'EXPIRED':
            db.execute("UPDATE qr_sessions SET status='EXPIRED' WHERE order_id=?", (order_id,))
            db.commit()
        s = db.execute("SELECT * FROM qr_sessions WHERE order_id=?", (order_id,)).fetchone()

    # For QR page polling — verify
    if s['status'] == 'PENDING':
        key_row = db.execute("SELECT * FROM api_keys WHERE api_key=?", (s['api_key'],)).fetchone()
        if key_row:
            _verify_session(s, key_row)
            s = db.execute("SELECT * FROM qr_sessions WHERE order_id=?", (order_id,)).fetchone()

    sj = build_session_json(s)
    # Also include display hints
    sj['partial_msg'] = None
    if s['status'] == 'PENDING' and sj['total_paid'] > 0:
        rem = round(sj['expected'] - sj['total_paid'], 2)
        sj['partial_msg'] = f"⚠️ ₹{rem:.2f} remaining. Same QR is still valid — please pay the balance."
    elif s['status'] == 'PENDING' and sj['total_paid'] == 0:
        sj['partial_msg'] = f"⏳ Waiting for ₹{sj['expected']:.2f}..."
    return jsonify(sj)

# ==========================================
# SESSION STATUS — for landing page after payment
# ==========================================
@app.route('/session/<session_id>')
def session_landing(session_id):
    db = get_db()
    s = db.execute("SELECT * FROM qr_sessions WHERE session_id=?", (session_id,)).fetchone()
    if not s:
        return render_template_string(ERROR_HTML, msg="Session not found"), 404
    sj = build_session_json(s)
    # Pretty-print JSON
    pretty = json.dumps(sj, indent=2, ensure_ascii=False)
    return render_template_string(SESSION_VIEW_HTML, session_id=session_id,
                                  pretty=pretty, raw=json.dumps(sj))

# ==========================================
# UPTIME
# ==========================================
@app.route('/api/uptime')
def uptime():
    seconds = int(time.time() - BOOT_TIME)
    d = seconds // 86400
    h = (seconds % 86400) // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return jsonify({
        "uptime_seconds": seconds,
        "human": f"{d}d {h}h {m}m {s}s",
        "days": d, "hours": h, "minutes": m, "seconds": s,
        "version": APP_VERSION
    })

# ==========================================
# ERROR TEMPLATE
# ==========================================
ERROR_HTML = """
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Error</title>
<style>body{background:#05050a;color:#e8e8f5;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#0f0f1e;border:1px solid #1f1f3a;padding:40px;border-radius:20px;text-align:center;max-width:400px;box-shadow:0 0 60px rgba(255,71,87,.3)}
h2{color:#ff4757;margin-bottom:12px}p{color:#7a7a9a}</style></head>
<body><div class="card"><h2>⚠️ Error</h2><p>{{ msg }}</p></div></body></html>
"""

# ==========================================
# SESSION JSON VIEW
# ==========================================
SESSION_VIEW_HTML = """
<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Session JSON</title>
<style>
body{background:#05050a;color:#e8e8f5;font-family:'Space Mono',monospace;margin:0;padding:20px}
.card{max-width:700px;margin:0 auto;background:#0f0f1e;border:1px solid #1f1f3a;border-radius:16px;padding:24px;
box-shadow:0 0 60px rgba(0,224,164,.2)}
h1{color:#00e0a4;font-size:18px;margin:0 0 14px}
pre{background:#02020a;padding:18px;border-radius:10px;font-size:12px;color:#00ffb3;overflow-x:auto;
white-space:pre-wrap;word-break:break-all;border:1px solid #1f1f3a;line-height:1.6;max-height:600px;overflow-y:auto}
.tab{display:inline-block;padding:8px 16px;border-radius:8px;cursor:pointer;margin-right:6px;
background:#15152a;border:1px solid #1f1f3a;color:#7a7a9a;font-size:12px;font-weight:700;transition:.2s}
.tab.active{background:linear-gradient(90deg,#00ffb3,#00d4ff);color:#05050a;border-color:#00ffb3}
.copy{float:right;background:#15152a;border:1px solid #1f1f3a;color:#e8e8f5;padding:6px 12px;
border-radius:8px;font-size:11px;font-weight:700;cursor:pointer}
.copy:hover{background:#00ffb3;color:#05050a}
</style></head><body>
<div class="card">
<h1>🔑 Session: {{ session_id }}</h1>
<div style="margin-bottom:14px">
  <span class="tab active" onclick="showTab('pretty',this)">Pretty</span>
  <span class="tab" onclick="showTab('raw',this)">Raw</span>
  <button class="copy" onclick="copyJson()">📋 Copy JSON</button>
</div>
<pre id="prettyBox">{{ pretty }}</pre>
<pre id="rawBox" style="display:none">{{ raw }}</pre>
</div>
<script>
function showTab(t, el) {
  document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('prettyBox').style.display = t === 'pretty' ? 'block' : 'none';
  document.getElementById('rawBox').style.display = t === 'raw' ? 'block' : 'none';
}
function copyJson() {
  const t = document.getElementById('rawBox').textContent;
  navigator.clipboard.writeText(t).then(() => alert('JSON copied!'));
}
</script></body></html>
"""

# ==========================================
# QR PAGE V5 — with Telegram + Web universal links
# ==========================================
QR_HTML_TEMPLATE_V5 = """
<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pay ₹{{ amount }}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Inter',sans-serif}
body{background:radial-gradient(circle at 30% 20%,rgba(0,224,164,.18),transparent 45%),
radial-gradient(circle at 70% 80%,rgba(168,85,247,.18),transparent 45%),#05050a;
color:#e8e8f5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:-1;
background:radial-gradient(circle at 50% 50%,rgba(0,255,179,.05),transparent 70%);
animation:pulseBg 6s ease-in-out infinite}
@keyframes pulseBg{0%,100%{opacity:.5}50%{opacity:1}}
.card{width:100%;max-width:480px;background:rgba(15,15,30,.85);backdrop-filter:blur(20px);
border:1px solid rgba(0,255,179,.2);border-radius:24px;padding:28px 22px;
box-shadow:0 0 60px rgba(0,224,164,.2),0 0 120px rgba(168,85,247,.15);
text-align:center;position:relative;overflow:hidden;animation:cardIn .6s cubic-bezier(.175,.885,.32,1.275)}
@keyframes cardIn{0%{transform:scale(.9);opacity:0}100%{transform:scale(1);opacity:1}}
.card::before{content:'';position:absolute;top:-50%;left:-50%;width:200%;height:200%;
background:conic-gradient(from 0deg,transparent,rgba(0,255,179,.1),transparent 30%);
animation:rotateGlow 8s linear infinite;z-index:-1}
@keyframes rotateGlow{to{transform:rotate(360deg)}}
.tag{font-size:11px;color:#00e0a4;text-transform:uppercase;letter-spacing:3px;margin-bottom:6px;font-weight:700;
text-shadow:0 0 20px rgba(0,255,179,.5)}
h1{font-size:46px;font-weight:900;margin:6px 0;
background:linear-gradient(90deg,#00ffb3,#a855f7,#ff00aa,#00d4ff);background-size:300% 100%;
-webkit-background-clip:text;color:transparent;animation:rbow 4s linear infinite;
filter:drop-shadow(0 0 20px rgba(0,255,179,.4))}
@keyframes rbow{to{background-position:300% 0}}
.qr-wrap{background:#fff;border-radius:20px;padding:12px;display:inline-block;margin:14px 0;
box-shadow:0 0 60px rgba(0,224,164,.4),inset 0 0 20px rgba(0,0,0,.05);
position:relative;animation:qrPulse 3s ease-in-out infinite}
@keyframes qrPulse{0%,100%{box-shadow:0 0 60px rgba(0,224,164,.4)}50%{box-shadow:0 0 90px rgba(0,224,164,.7)}}
.qr-wrap img{display:block;width:220px;height:220px;border-radius:8px}
.logos{display:flex;justify-content:center;gap:6px;margin:12px 0;flex-wrap:wrap}
.logos span{background:rgba(255,255,255,.95);color:#000;padding:6px 10px;border-radius:8px;
font-weight:800;font-size:10px}
.timer{font-size:30px;font-weight:900;margin:8px 0;color:#00e0a4;
letter-spacing:2px;font-variant-numeric:tabular-nums;font-family:'Space Mono',monospace;
text-shadow:0 0 20px rgba(0,255,179,.5)}
.status{padding:14px;border-radius:12px;font-weight:700;font-size:13px;margin-top:8px;
backdrop-filter:blur(10px)}
.pending{background:rgba(255,165,2,.15);color:#ffa502;border:1px solid rgba(255,165,2,.3);
animation:pendingPulse 2s ease-in-out infinite}
@keyframes pendingPulse{0%,100%{box-shadow:0 0 0 0 rgba(255,165,2,.4)}50%{box-shadow:0 0 0 10px rgba(255,165,2,0)}}
.partial-status{background:rgba(255,165,2,.15);color:#ffa502;border:1px solid rgba(255,165,2,.3);text-align:left;font-size:12px;line-height:1.6}
.partial-status b{color:#fff}
.expired{background:rgba(255,71,87,.15);color:#ff4757;border:1px solid rgba(255,71,87,.3)}
.upi{font-size:11px;color:#7a7a9a;margin-top:6px}.upi b{color:#e8e8f5}

/* UNIVERSAL LINKS */
.links-block{margin-top:14px;padding:12px;background:rgba(21,21,42,.7);border:1px solid rgba(0,255,179,.15);border-radius:12px;text-align:left}
.links-block h3{font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:#00e0a4;margin-bottom:8px;font-weight:800}
.link-row{display:flex;align-items:center;gap:6px;margin-bottom:6px;padding:8px 10px;background:rgba(2,2,10,.6);border-radius:8px;border:1px solid #1f1f3a}
.link-row:last-child{margin-bottom:0}
.link-row .ico{font-size:14px;flex-shrink:0}
.link-row .lbl{font-size:10px;color:#7a7a9a;flex-shrink:0;font-weight:700;text-transform:uppercase;letter-spacing:.5px}
.link-row a{font-size:10px;color:#00d4ff;text-decoration:none;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:'Space Mono',monospace}
.link-row .cp{background:#15152a;border:1px solid #1f1f3a;color:#e8e8f5;padding:3px 8px;border-radius:6px;font-size:9px;cursor:pointer;font-weight:700;flex-shrink:0}
.link-row .cp:hover{background:#00ffb3;color:#05050a}

/* SUCCESS OVERLAY */
.success-overlay{position:absolute;inset:0;background:rgba(15,15,30,.98);backdrop-filter:blur(30px);
border-radius:24px;display:none;flex-direction:column;align-items:center;justify-content:flex-start;
padding:28px 22px;z-index:10;opacity:0;transition:.5s;overflow-y:auto;text-align:center}
.success-overlay.show{display:flex;opacity:1}
.check-icon{width:84px;height:84px;border-radius:50%;flex-shrink:0;
background:radial-gradient(circle,rgba(0,224,164,.3),rgba(0,224,164,.05));
border:3px solid #00e0a4;display:flex;align-items:center;justify-content:center;
font-size:42px;margin-bottom:14px;
box-shadow:0 0 40px rgba(0,224,164,.7),inset 0 0 20px rgba(0,224,164,.3);
animation:popIn .6s cubic-bezier(.175,.885,.32,1.275),checkPulse 2s ease-in-out 0.6s infinite}
@keyframes popIn{0%{transform:scale(0) rotate(-180deg)}100%{transform:scale(1) rotate(0)}}
@keyframes checkPulse{0%,100%{box-shadow:0 0 40px rgba(0,224,164,.7)}50%{box-shadow:0 0 80px rgba(0,224,164,1)}}
.success-title{font-size:24px;font-weight:900;color:#00e0a4;margin-bottom:4px;
text-shadow:0 0 30px rgba(0,224,164,.5)}
.success-amt{font-size:42px;font-weight:900;
background:linear-gradient(90deg,#00ffb3,#00d4ff);background-size:200% 100%;
-webkit-background-clip:text;color:transparent;margin-bottom:16px;
animation:rbow 3s linear infinite;filter:drop-shadow(0 0 20px rgba(0,255,179,.6))}
.success-details{background:rgba(21,21,42,.8);backdrop-filter:blur(10px);
border:1px solid rgba(0,255,179,.25);border-radius:12px;padding:14px;width:100%;
text-align:left;font-size:11px;font-family:'Space Mono',monospace;margin-bottom:14px}
.success-details div{display:flex;justify-content:space-between;margin-bottom:8px;color:#7a7a9a;gap:10px}
.success-details div:last-child{margin-bottom:0}
.success-details b{color:#e8e8f5;font-weight:700;text-align:right;word-break:break-all}
.success-details .ok{color:#00e0a4;font-weight:800}
.session-link{background:linear-gradient(90deg,rgba(0,224,164,.15),rgba(168,85,247,.15));
border:1px solid rgba(0,224,164,.4);border-radius:12px;padding:12px;width:100%;margin-top:8px}
.session-link .lbl{font-size:9px;text-transform:uppercase;letter-spacing:1.5px;color:#00e0a4;font-weight:800;margin-bottom:6px}
.session-link a{display:block;color:#00d4ff;font-size:11px;text-decoration:none;word-break:break-all;font-family:'Space Mono',monospace;margin-bottom:6px}
.session-link .btns{display:flex;gap:6px;flex-wrap:wrap}
.session-link button{flex:1;min-width:120px;padding:8px;border-radius:8px;font-size:10px;font-weight:800;cursor:pointer;border:none;background:#15152a;color:#e8e8f5;border:1px solid #1f1f3a}
.session-link button:hover{background:#00ffb3;color:#05050a}

.partial-overlay{position:absolute;inset:0;background:rgba(15,15,30,.98);backdrop-filter:blur(30px);
border-radius:24px;display:none;flex-direction:column;align-items:center;justify-content:center;
padding:28px 22px;z-index:10;opacity:0;transition:.5s}
.partial-overlay.show{display:flex;opacity:1}
.warn-icon{width:84px;height:84px;border-radius:50%;
background:radial-gradient(circle,rgba(255,165,2,.3),rgba(255,165,2,.05));
border:3px solid #ffa502;display:flex;align-items:center;justify-content:center;
font-size:42px;margin-bottom:18px;box-shadow:0 0 40px rgba(255,165,2,.7)}
.warn-title{font-size:22px;font-weight:900;color:#ffa502;margin-bottom:6px;text-shadow:0 0 30px rgba(255,165,2,.5)}
.warn-msg{color:#e8e8f5;font-size:13px;margin-bottom:14px;text-align:center;line-height:1.6}
.warn-details{background:rgba(21,21,42,.8);border:1px solid rgba(255,165,2,.25);border-radius:12px;padding:14px;width:100%;font-size:12px;margin-bottom:14px;font-family:'Space Mono',monospace}
.warn-details div{display:flex;justify-content:space-between;margin-bottom:8px}
.warn-details div:last-child{margin-bottom:0}
.warn-details b{color:#ffa502}
.warn-hint{font-size:11px;color:#7a7a9a;line-height:1.5;margin-top:6px}
.brand{position:fixed;bottom:10px;right:14px;font-size:9px;color:#3a3a5a;letter-spacing:2px;font-family:'Space Mono',monospace}
</style></head><body>
<div class="card" id="mainCard">
    <div class="tag">◆ Pay via UPI</div>
    <h1>₹{{ "%.2f"|format(amount) }}</h1>
    <div class="upi">to <b>{{ full_name }}</b> · {{ upi_id }}</div>
    <div class="qr-wrap"><img src="{{ qr_b64 }}" alt="QR"></div>
    <div class="logos"><span>GPay</span><span>PhonePe</span><span>Paytm</span><span>UPI</span><span>BHIM</span></div>
    <div class="timer" id="timer">{{ '%02d:00'|format(minutes) }}</div>
    <div class="status pending" id="status">⏳ Waiting for payment of ₹{{ "%.2f"|format(amount) }}...</div>

    <!-- UNIVERSAL LINKS -->
    <div class="links-block">
        <h3>🔗 Universal Links (Bot / Web)</h3>
        <div class="link-row">
            <span class="ico">🤖</span>
            <span class="lbl">TG</span>
            <a href="{{ tg_link }}" target="_blank">{{ tg_link }}</a>
            <button class="cp" onclick="copyLink('{{ tg_link }}')">Copy</button>
        </div>
        <div class="link-row">
            <span class="ico">🌐</span>
            <span class="lbl">API</span>
            <a href="{{ web_link }}" target="_blank">{{ web_link }}</a>
            <button class="cp" onclick="copyLink('{{ web_link }}')">Copy</button>
        </div>
    </div>

    <!-- SUCCESS OVERLAY -->
    <div class="success-overlay" id="successOverlay">
        <div class="check-icon">✅</div>
        <div class="success-title">Payment Successful</div>
        <div class="success-amt" id="successAmt">₹{{ amount }}</div>
        <div class="success-details">
            <div><span>Total Paid</span><b id="dtAmount">-</b></div>
            <div><span>Transaction ID</span><b id="dtTxn">-</b></div>
            <div><span>UTR</span><b id="dtUtr">-</b></div>
            <div><span>From</span><b id="dtFrom">-</b></div>
            <div><span>Date</span><b id="dtDate">-</b></div>
            <div><span>Status</span><b class="ok">Verified ✅</b></div>
        </div>
        <div class="session-link">
            <div class="lbl">Session ID: {{ session_id }}</div>
            <a href="{{ web_link }}" target="_blank">{{ web_link }}</a>
            <div class="btns">
                <button onclick="copyLink('{{ web_link }}')">📋 Copy JSON Link</button>
                <button onclick="window.open('{{ tg_link }}','_blank')">🤖 Telegram</button>
            </div>
        </div>
    </div>

    <!-- PARTIAL OVERLAY -->
    <div class="partial-overlay" id="partialOverlay">
        <div class="warn-icon">⚠️</div>
        <div class="warn-title">Partial Payment Received</div>
        <div class="warn-msg" id="partialMsg">You paid less than required.</div>
        <div class="warn-details">
            <div><span>Expected</span><b>₹{{ "%.2f"|format(amount) }}</b></div>
            <div><span>Received</span><b id="partialRecv">₹0.00</b></div>
            <div><span>Remaining</span><b id="partialShort">₹0.00</b></div>
            <div><span>Last Txn</span><b id="partialTxn" style="color:#e8e8f5">-</b></div>
        </div>
        <div class="warn-hint">👉 Please pay the remaining amount to the same QR. Verification will complete automatically.</div>
    </div>
</div>
<div class="brand">FamPay AutoQR V5 ULTRA</div>
<script>
const orderId="{{ order_id }}", sessionId="{{ session_id }}";
const totalSecs={{ minutes*60 }}, expectedAmt={{ amount }};
let secs=totalSecs, tInt, pInt, partialShown=false, paidShown=false;
const T=document.getElementById('timer'), S=document.getElementById('status');

function copyLink(t){navigator.clipboard.writeText(t).then(()=>{const o=T.textContent;T.textContent='✅ Copied';setTimeout(()=>{if(T.textContent==='✅ Copied')T.textContent=o},1000)}).catch(()=>{})}
function fmt(secs){
  const m=String(Math.floor(secs/60)).padStart(2,'0'), s=String(secs%60).padStart(2,'0');
  return m+':'+s;
}
function tick(){
  secs--;
  if(secs<=0){
    T.textContent='00:00'; T.style.color='#ff4757';
    S.textContent='❌ QR Expired'; S.className='status expired';
    clearInterval(tInt); clearInterval(pInt); return;
  }
  T.textContent=fmt(secs); if(secs<=60) T.style.color='#ff4757';
}

async function poll(){
  try{
    const r=await fetch('/api/check-payment/'+orderId), d=await r.json();
    if(d.status==='PAID' && !paidShown){
      paidShown=true;
      clearInterval(tInt); clearInterval(pInt);
      const ses = d.session || {};
      const total = ses.total_paid || expectedAmt;
      document.getElementById('successAmt').textContent='₹'+total.toFixed(2);
      document.getElementById('dtAmount').textContent='₹'+total.toFixed(2);
      document.getElementById('dtTxn').textContent=ses.txn_id || '-';
      document.getElementById('dtUtr').textContent=ses.utr || '-';
      const p0 = (ses.payments && ses.payments[0]) || {};
      document.getElementById('dtFrom').textContent=p0.sender_upi || p0.sender_name || '-';
      document.getElementById('dtDate').textContent=p0.email_date || new Date().toLocaleString('en-IN',{hour:'2-digit',minute:'2-digit',hour12:true})+' IST';
      document.getElementById('successOverlay').classList.add('show');
    }
    else if(d.status==='PENDING' && (d.total_paid||0) > 0 && !paidShown){
      // Partial — show overlay but keep polling
      partialShown=true;
      const recv = d.total_paid || 0;
      const short = Math.max(0, expectedAmt - recv);
      document.getElementById('partialRecv').textContent='₹'+recv.toFixed(2);
      document.getElementById('partialShort').textContent='₹'+short.toFixed(2);
      document.getElementById('partialMsg').textContent = d.partial_msg || ('⚠️ ₹'+short.toFixed(2)+' remaining. Same QR still valid.');
      document.getElementById('partialTxn').textContent = d.txn_id || '-';
      document.getElementById('partialOverlay').classList.add('show');
      // Update status bar too
      S.className='status partial-status';
      S.innerHTML='⚠️ <b>Partial payment received.</b><br>Received: ₹'+recv.toFixed(2)+' · Remaining: ₹'+short.toFixed(2);
      // When partialOverlay is dismissed, show QR again
      setTimeout(()=>{
        document.getElementById('partialOverlay').classList.remove('show');
      }, 5000);
    }
    else if(d.status==='EXPIRED' && !paidShown){
      S.textContent='❌ QR Expired'; S.className='status expired';
      clearInterval(tInt); clearInterval(pInt);
    }
  }catch(e){}
}
tInt=setInterval(tick,1000); pInt=setInterval(poll,1500); poll();
</script></body></html>
"""

# ==========================================
# MAIN DASHBOARD — V5
# ==========================================
MAIN_HTML = r"""
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FamPay AutoQR V5 ULTRA</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{--bg:#05050a;--surface:#0f0f1e;--surface2:#15152a;--border:#1f1f3a;--text:#e8e8f5;--dim:#7a7a9a;
--ng:#00ffb3;--nc:#00d4ff;--np:#a855f7;--npink:#ff00aa;--nwarn:#ffa502;--dang:#ff4757;--ok:#00e0a4;
--shadow:0 0 60px rgba(0,255,179,.2)}
[data-theme="light"]{--bg:#f5f7fa;--surface:#ffffff;--surface2:#f0f2f7;--border:#e0e4ec;--text:#0f0f1e;--dim:#6a6a8a;--shadow:0 0 40px rgba(168,85,247,.1)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden;transition:.3s}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:-1;background:
radial-gradient(700px at 10% 5%,rgba(0,255,179,.12),transparent 60%),
radial-gradient(700px at 90% 10%,rgba(168,85,247,.12),transparent 60%),
radial-gradient(700px at 50% 90%,rgba(255,0,170,.12),transparent 60%);
animation:auroraMove 20s ease-in-out infinite}
@keyframes auroraMove{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(20px,-20px) scale(1.05)}}
button,input,select,textarea{font-family:inherit;outline:none}
.hidden{display:none!important}
.auth-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.auth-card{width:100%;max-width:420px;background:rgba(15,15,30,.85);backdrop-filter:blur(20px);
border:1px solid rgba(0,255,179,.2);border-radius:24px;padding:34px 28px;box-shadow:var(--shadow);
position:relative;overflow:hidden;animation:cardIn .6s cubic-bezier(.175,.885,.32,1.275)}
@keyframes cardIn{0%{transform:scale(.9);opacity:0}100%{transform:scale(1);opacity:1}}
.logo{font-size:22px;font-weight:900;text-align:center;margin-bottom:4px;
background:linear-gradient(90deg,var(--ng),var(--np),var(--npink),var(--nc));background-size:300% 100%;
-webkit-background-clip:text;color:transparent;animation:rbow 4s linear infinite;
filter:drop-shadow(0 0 10px rgba(0,255,179,.4))}
@keyframes rbow{to{background-position:300% 0}}
.logo-sub{text-align:center;color:var(--dim);font-size:12px;margin-bottom:22px}
.field{margin-bottom:14px}
.field label{display:block;font-size:11px;font-weight:700;color:var(--dim);margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}
.field input{width:100%;padding:12px 14px;background:var(--surface2);border:1px solid var(--border);
border-radius:10px;color:var(--text);font-size:14px;transition:.2s}
.field input:focus{border-color:var(--ng);box-shadow:0 0 0 3px rgba(0,255,179,.15),0 0 20px rgba(0,255,179,.3)}
.btn{width:100%;padding:13px;border:none;border-radius:10px;font-weight:800;font-size:14px;
background:linear-gradient(90deg,var(--ng),var(--nc),var(--np));color:#05050a;
transition:.2s;cursor:pointer;background-size:200% 100%;display:flex;align-items:center;justify-content:center;gap:8px;
position:relative;overflow:hidden}
.btn::before{content:'';position:absolute;top:0;left:-100%;width:100%;height:100%;
background:linear-gradient(90deg,transparent,rgba(255,255,255,.4),transparent);transition:.5s}
.btn:hover::before{left:100%}
.btn:hover{transform:translateY(-2px);box-shadow:0 0 30px rgba(0,255,179,.6),0 0 60px rgba(168,85,247,.4);background-position:100% 0}
.btn.sec{background:var(--surface2);color:var(--text);border:1px solid var(--border)}
.btn.sec:hover{box-shadow:0 0 20px rgba(0,255,179,.3);border-color:var(--ng)}
.switch{text-align:center;margin-top:14px;font-size:13px;color:var(--dim)}
.switch a{color:var(--ng);font-weight:700;cursor:pointer}
.shell{display:flex;min-height:100vh}
.sidebar{width:260px;background:rgba(15,15,30,.85);backdrop-filter:blur(20px);
border-right:1px solid var(--border);padding:22px 14px;position:fixed;inset:0 auto 0 0;overflow-y:auto;z-index:50;transition:transform .3s}
.brand{font-size:17px;font-weight:900;padding:0 8px 20px;
background:linear-gradient(90deg,var(--ng),var(--np),var(--npink));background-size:200%;
-webkit-background-clip:text;color:transparent;animation:rbow 3s infinite linear;
filter:drop-shadow(0 0 8px rgba(0,255,179,.3))}
.nav{display:flex;flex-direction:column;gap:3px}
.item{padding:11px 14px;border-radius:10px;color:var(--dim);font-size:13px;font-weight:600;
display:flex;align-items:center;gap:10px;cursor:pointer;transition:.15s;position:relative}
.item:hover{background:var(--surface2);color:var(--text);transform:translateX(3px)}
.item.active{background:linear-gradient(90deg,rgba(0,255,179,.18),rgba(168,85,247,.08));
color:var(--ng);box-shadow:inset 0 0 20px rgba(0,255,179,.15),0 0 15px rgba(0,255,179,.2)}
.sec-lbl{font-size:10px;font-weight:800;color:#3a3a5a;text-transform:uppercase;letter-spacing:1.5px;padding:16px 14px 6px}
.main{flex:1;margin-left:260px;padding:24px;max-width:100%}
@media(max-width:860px){.sidebar{transform:translateX(-100%)}.sidebar.open{transform:none}.main{margin-left:0;padding:14px}}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px;
padding-bottom:16px;border-bottom:1px solid var(--border);gap:12px;flex-wrap:wrap}
.topbar h1{font-size:22px;font-weight:800;background:linear-gradient(90deg,var(--text),var(--ng));
-webkit-background-clip:text;color:transparent}
.chip{display:flex;align-items:center;gap:8px;padding:7px 14px;background:var(--surface);
border:1px solid var(--border);border-radius:30px;font-size:12px;font-weight:600}
.hamburger{display:none;background:var(--surface2);border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:8px;cursor:pointer;font-size:18px}
@media(max-width:860px){.hamburger{display:block}}
.dot{width:8px;height:8px;border-radius:50%;box-shadow:0 0 12px currentColor}
.dot.on{background:var(--ng);color:var(--ng);animation:dotPulse 2s infinite}
@keyframes dotPulse{0%,100%{box-shadow:0 0 12px currentColor}50%{box-shadow:0 0 24px currentColor}}
.dot.off{background:var(--dang);color:var(--dang)}
.dot.unk{background:var(--dim);color:var(--dim)}
.icon-btn{background:var(--surface2);border:1px solid var(--border);color:var(--text);
padding:8px 11px;border-radius:8px;cursor:pointer;transition:.2s;font-size:15px}
.icon-btn:hover{border-color:var(--ng);color:var(--ng);box-shadow:0 0 15px rgba(0,255,179,.4)}
.card{background:rgba(15,15,30,.85);backdrop-filter:blur(10px);border:1px solid var(--border);
border-radius:16px;padding:22px;margin-bottom:16px;transition:.3s}
.card:hover{border-color:rgba(0,255,179,.3);box-shadow:0 0 30px rgba(0,255,179,.1)}
.card h2{font-size:15px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
@media(max-width:860px){.grid-2,.grid-3,.grid-4{grid-template-columns:1fr 1fr}}
@media(max-width:500px){.grid-2,.grid-3,.grid-4{grid-template-columns:1fr}}
.hero{background:linear-gradient(135deg,rgba(0,255,179,.18),rgba(168,85,247,.18),rgba(255,0,170,.12));
border:1px solid rgba(0,255,179,.4);border-radius:20px;padding:28px;position:relative;overflow:hidden;
box-shadow:0 0 60px rgba(0,255,179,.2),0 0 120px rgba(168,85,247,.1)}
.hero::before{content:'';position:absolute;top:-50%;left:-50%;width:200%;height:200%;
background:conic-gradient(from 0deg,transparent,rgba(0,255,179,.15),transparent 30%);
animation:rotateGlow 10s linear infinite;z-index:0}
@keyframes rotateGlow{to{transform:rotate(360deg)}}
.hero > *{position:relative;z-index:1}
.hero-amt{font-size:52px;font-weight:900;margin:8px 0;
background:linear-gradient(90deg,var(--ng),var(--np),var(--npink));background-size:200% 100%;
-webkit-background-clip:text;color:transparent;filter:drop-shadow(0 0 20px rgba(255,0,170,.5));
animation:rbow 4s linear infinite}
.hero-lbl{font-size:11px;font-weight:800;color:var(--dim);text-transform:uppercase;letter-spacing:2px}
.hero-sub{font-size:13px;color:var(--dim)}.hero-sub b{color:var(--text)}
.stat{background:rgba(21,21,42,.7);backdrop-filter:blur(10px);border:1px solid var(--border);
border-radius:14px;padding:16px;position:relative;overflow:hidden;transition:.3s}
.stat:hover{transform:translateY(-3px);border-color:var(--ng);box-shadow:0 0 25px rgba(0,255,179,.3)}
.stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
background:linear-gradient(90deg,var(--ng),var(--nc));box-shadow:0 0 10px var(--ng)}
.stat-lbl{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;font-weight:700}
.stat-val{font-size:24px;font-weight:800;margin-top:4px;color:var(--ng);text-shadow:0 0 15px rgba(0,255,179,.4)}
.stat.alt .stat-val{color:var(--np);text-shadow:0 0 15px rgba(168,85,247,.4)}
.stat.alt2 .stat-val{color:var(--npink);text-shadow:0 0 15px rgba(255,0,170,.4)}
.stat.warn .stat-val{color:var(--nwarn);text-shadow:0 0 15px rgba(255,165,2,.4)}
.tabs{display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap}
.tab{padding:8px 14px;background:var(--surface2);border:1px solid var(--border);
border-radius:8px;font-size:12px;font-weight:600;color:var(--dim);cursor:pointer;transition:.2s}
.tab:hover{border-color:var(--ng)}
.tab.active{background:linear-gradient(90deg,var(--ng),var(--nc));color:#05050a;border-color:var(--ng);
box-shadow:0 0 20px rgba(0,255,179,.5)}
.chart-box{position:relative;height:260px;margin-top:8px}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
@media(max-width:600px){.form-grid{grid-template-columns:1fr}}
.fg{display:flex;flex-direction:column;gap:6px}
.fg label{font-size:11px;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
.fg input,.fg select,.fg textarea{padding:11px 14px;background:var(--surface2);
border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:14px;transition:.2s}
.fg input:focus,.fg select:focus,.fg textarea:focus{border-color:var(--ng);
box-shadow:0 0 0 3px rgba(0,255,179,.15),0 0 20px rgba(0,255,179,.3)}
.fg small{font-size:10px;color:var(--dim);margin-top:-2px}
.api-out{background:rgba(2,2,10,.8);border:1px dashed rgba(0,255,179,.5);padding:12px;
border-radius:10px;color:var(--ng);font-family:'Space Mono',monospace;font-size:11px;
word-break:break-all;margin-top:8px;display:flex;justify-content:space-between;align-items:center;gap:8px;
box-shadow:inset 0 0 20px rgba(0,255,179,.1)}
.copy{background:var(--surface2);border:1px solid var(--border);color:var(--text);
padding:5px 9px;border-radius:6px;font-size:10px;font-weight:700;flex-shrink:0;cursor:pointer;transition:.2s}
.copy:hover{background:var(--ng);color:#05050a;border-color:var(--ng);box-shadow:0 0 15px rgba(0,255,179,.5)}
.txn{display:flex;justify-content:space-between;align-items:flex-start;padding:14px;
background:rgba(21,21,42,.7);border-radius:10px;margin-bottom:8px;font-size:13px;
border-left:3px solid var(--ok);transition:.2s}
.txn:hover{background:rgba(21,21,42,.95);box-shadow:0 0 20px rgba(0,224,164,.15)}
.txn.partial{border-left-color:var(--nwarn)}
.txn .amt{color:var(--ok);font-weight:800;font-size:15px}
.txn.partial .amt{color:var(--nwarn)}
.txn .meta{font-size:11px;color:var(--dim);margin-top:3px;font-family:'Space Mono',monospace}
.flist{list-style:none}.flist li{padding:10px 0;border-bottom:1px solid var(--border);
display:flex;align-items:center;gap:10px;font-size:13px}
.flist li:last-child{border:none}.flist li::before{content:'✦';color:var(--ng);font-size:14px;
text-shadow:0 0 8px var(--ng)}
#toast{position:fixed;bottom:20px;right:20px;padding:14px 20px;border-radius:12px;
background:rgba(21,21,42,.95);backdrop-filter:blur(10px);color:var(--text);font-size:13px;font-weight:600;
border-left:3px solid var(--ng);box-shadow:0 0 30px rgba(0,255,179,.4);
transform:translateY(100px);opacity:0;transition:.3s;z-index:1000;max-width:340px}
#toast.show{transform:translateY(0);opacity:1}
#toast.err{border-left-color:var(--dang);box-shadow:0 0 30px rgba(255,71,87,.4)}
.empty{text-align:center;padding:36px 20px;color:var(--dim);font-size:13px}
.empty-ic{font-size:36px;opacity:.4;margin-bottom:8px}
.badge{display:inline-block;padding:3px 8px;border-radius:6px;font-size:10px;font-weight:800;text-transform:uppercase}
.badge.life{background:rgba(168,85,247,.2);color:var(--np);box-shadow:0 0 10px rgba(168,85,247,.3)}
.badge.warn{background:rgba(255,165,2,.2);color:var(--nwarn)}
.badge.ok{background:rgba(0,224,164,.2);color:var(--ok);box-shadow:0 0 10px rgba(0,224,164,.3)}
.uptime{font-family:'Space Mono',monospace;font-size:11px;color:var(--dim);padding:6px 12px;
background:rgba(21,21,42,.8);border-radius:20px;border:1px solid var(--border);
box-shadow:0 0 15px rgba(0,255,179,.1)}
.uptime b{color:var(--ng);text-shadow:0 0 8px var(--ng)}
.period-tab{display:flex;gap:6px;margin-bottom:14px}
.period-tab .tab{flex:1;text-align:center}
</style></head><body>

<div id="authScreen" class="auth-wrap">
  <div class="auth-card">
    <div class="logo">◆ FamPay AutoQR V5 ULTRA</div>
    <div class="logo-sub">Session Edition · Universal Links · Flash Speed</div>
    <div id="loginForm">
      <div class="field"><label>Username</label><input id="lgU" placeholder="admin" autocomplete="username"></div>
      <div class="field"><label>Password</label><input id="lgP" type="password" placeholder="••••••" autocomplete="current-password"></div>
      <button class="btn" onclick="doLogin()">⚡ Login →</button>
      <div class="switch">New? <a onclick="toggleAuth('reg')">Create account</a></div>
    </div>
    <div id="regForm" class="hidden">
      <div class="field"><label>Username</label><input id="rgU" placeholder="yourname"></div>
      <div class="field"><label>Password</label><input id="rgP" type="password" placeholder="min 4 chars"></div>
      <div class="field"><label>Email (optional)</label><input id="rgE" type="email" placeholder="you@gmail.com"></div>
      <button class="btn" onclick="doReg()">Create Account →</button>
      <div class="switch">Have account? <a onclick="toggleAuth('login')">Login</a></div>
    </div>
  </div>
</div>

<div id="shell" class="shell hidden">
  <aside id="sidebar" class="sidebar">
    <div class="brand">◆ FamPay V5</div>
    <nav class="nav">
      <div class="item active" data-p="dashboard" onclick="go('dashboard')">📊 Dashboard</div>
      <div class="item" data-p="analytics" onclick="go('analytics')">📈 Analytics</div>
      <div class="item" data-p="account" onclick="go('account')">👤 Account</div>
      <div class="item" data-p="keys" onclick="go('keys')">🔑 API Keys</div>
      <div class="sec-lbl">Data</div>
      <div class="item" data-p="history" onclick="go('history')">📜 Transactions</div>
      <div class="item" data-p="partials" onclick="go('partials')">⚠️ Partial Payments</div>
      <div class="item" data-p="audit" onclick="go('audit')">🔍 Audit Log</div>
      <div class="sec-lbl">Help</div>
      <div class="item" data-p="docs" onclick="go('docs')">📖 API Docs</div>
      <div class="item" data-p="settings" onclick="go('settings')">⚙️ Settings</div>
    </nav>
    <div style="margin-top:20px"><button class="btn sec" onclick="doLogout()">🚪 Logout</button></div>
  </aside>
  <main class="main">
    <div class="topbar">
      <div style="display:flex;align-items:center;gap:10px">
        <button class="hamburger" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>
        <h1 id="title">Dashboard</h1>
      </div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <div class="uptime" id="uptime">⏱ <b>--</b></div>
        <button class="icon-btn" onclick="toggleTheme()" title="Toggle theme">🌗</button>
        <div class="chip"><span id="emailDot" class="dot unk"></span><span id="chipUser">-</span></div>
      </div>
    </div>

    <section id="p-dashboard" class="page">
      <div class="hero">
        <div class="hero-lbl">💰 Total Earnings</div>
        <div class="hero-amt">₹ <span id="earn">0.00</span></div>
        <div class="hero-sub">UPI: <b id="upiTxt">-</b> · Email: <b id="emailTxt">-</b></div>
      </div>
      <div class="grid-4" style="margin-top:16px">
        <div class="stat"><div class="stat-lbl">API Keys</div><div class="stat-val" id="stKeys">0</div></div>
        <div class="stat alt"><div class="stat-lbl">Requests</div><div class="stat-val" id="stReq">0</div></div>
        <div class="stat alt2"><div class="stat-lbl">QRs</div><div class="stat-val" id="stQR">0</div></div>
        <div class="stat warn"><div class="stat-lbl">Today</div><div class="stat-val" id="stToday">₹0</div></div>
      </div>
      <div class="card" style="margin-top:16px">
        <h2>📊 Last 7 Days</h2>
        <div class="chart-box"><canvas id="chart7"></canvas></div>
      </div>
    </section>

    <section id="p-analytics" class="page hidden">
      <div class="period-tab">
        <div class="tab active" data-period="today" onclick="setPeriod('today',this)">Today</div>
        <div class="tab" data-period="week" onclick="setPeriod('week',this)">Week</div>
        <div class="tab" data-period="month" onclick="setPeriod('month',this)">Month</div>
        <div class="tab" data-period="year" onclick="setPeriod('year',this)">Year</div>
      </div>
      <div class="grid-2">
        <div class="stat"><div class="stat-lbl">Amount</div><div class="stat-val" id="anAmount">₹0</div></div>
        <div class="stat alt"><div class="stat-lbl">Transactions</div><div class="stat-val" id="anCount">0</div></div>
      </div>
      <div class="card" style="margin-top:16px"><h2>🥧 Pie Distribution</h2><div class="chart-box"><canvas id="pieChart"></canvas></div></div>
      <div class="card"><h2>📅 Monthly (12 months)</h2><div class="chart-box"><canvas id="monthChart"></canvas></div></div>
      <div class="card"><h2>📆 Weekday Distribution</h2><div class="chart-box"><canvas id="weekdayChart"></canvas></div></div>
      <div class="card"><h2>📈 Yearly (5 years)</h2><div class="chart-box"><canvas id="yearChart"></canvas></div></div>
    </section>

    <section id="p-account" class="page hidden">
      <div class="card">
        <h2>👤 Account Details</h2>
        <div class="form-grid">
          <div class="fg"><label>Full Name</label><input id="acName"></div>
          <div class="fg"><label>UPI ID</label><input id="acUpi" placeholder="name@bank"></div>
        </div>
        <div class="form-grid">
          <div class="fg"><label>Mobile</label><input id="acMob"></div>
          <div class="fg"><label>Gmail</label><input id="acEmail" type="email"></div>
        </div>
        <div class="form-grid">
          <div class="fg"><label>Gmail App Password</label><input id="acPass" type="password" placeholder="16 char app password"><small>Leave blank to keep current</small></div>
          <div class="fg"><label>QR Minutes</label><input id="acMin" type="number" value="15" min="1"></div>
        </div>
        <div class="form-grid">
          <div class="fg"><label>Tolerance (₹)</label><input id="acTol" type="number" step="0.01" value="0"><small>0 = strict. 0.5 = allow ₹0.50 less</small></div>
          <div class="fg"><label>Webhook URL</label><input id="acHook" placeholder="https://yoursite.com/hook"></div>
        </div>
        <div style="display:flex;gap:10px;margin-top:10px">
          <button class="btn" style="flex:1" onclick="saveAccount()">💾 Save</button>
          <button class="btn sec" style="flex:1" onclick="testEmail()">🔍 Test Email</button>
        </div>
        <div id="testRes" style="margin-top:12px"></div>
      </div>
    </section>

    <section id="p-keys" class="page hidden">
      <div class="card">
        <h2>🔑 Generate API Key</h2>
        <div class="form-grid">
          <div class="fg"><label>Label</label><input id="keyLabel" placeholder="e.g. Bot 1"></div>
          <div class="fg"><label>Expiry Mode</label>
            <select id="keyMode" onchange="toggleMode()">
              <option value="days">Days</option><option value="lifetime">Lifetime</option>
            </select></div>
        </div>
        <div class="form-grid">
          <div class="fg" id="daysWrap"><label>Days</label><input id="keyDays" type="number" value="30"></div>
          <div class="fg"><label>Rate Limit (per min)</label><input id="keyRate" type="number" value="60"></div>
        </div>
        <button class="btn" onclick="genKey()">🚀 Generate Key</button>
        <div id="keyRes" style="margin-top:12px"></div>
      </div>
      <div class="card"><h2>📋 Your Keys</h2><div id="keysList"></div></div>
    </section>

    <section id="p-history" class="page hidden">
      <div class="card"><h2>📜 Transactions</h2><div id="txnList"></div></div>
    </section>

    <section id="p-partials" class="page hidden">
      <div class="card">
        <h2>⚠️ Partial / Over Payments</h2>
        <p style="font-size:12px;color:var(--dim);margin-bottom:14px">Transactions that did NOT match expected amount. Each has its own session — bot can fetch exact JSON.</p>
        <div id="partialList"></div>
      </div>
    </section>

    <section id="p-audit" class="page hidden">
      <div class="card"><h2>🔍 Audit Log</h2><div id="auditList"></div></div>
    </section>

    <section id="p-docs" class="page hidden">
      <div class="card">
        <h2>📖 API Documentation V5</h2>
        <h3 style="font-size:13px;margin:14px 0 8px;color:var(--ng)">1. Generate QR (HTML)</h3>
        <div class="api-out"><span>GET /v2/fam/YOUR_API_KEY?qr=100</span><button class="copy" onclick="copyText('/v2/fam/YOUR_KEY?qr=100')">Copy</button></div>
        <p style="font-size:12px;color:var(--dim);margin-top:6px">Each QR gets unique <b>session_id</b>. Multiple same-amount QRs supported independently.</p>

        <h3 style="font-size:13px;margin:14px 0 8px;color:var(--ng)">2. Session JSON (Universal)</h3>
        <div class="api-out"><span>GET /api/session/&lt;session_id&gt;</span><button class="copy" onclick="copyText('/api/session/SESSION_ID')">Copy</button></div>
        <p style="font-size:12px;color:var(--dim);margin-top:6px">Works in <b>any</b> website/app — pure JSON. Bot-friendly format.</p>

        <h3 style="font-size:13px;margin:14px 0 8px;color:var(--ng)">3. Telegram Universal Link</h3>
        <div class="api-out"><span>GET /tg/session/&lt;session_id&gt;</span><button class="copy" onclick="copyText('/tg/session/SESSION_ID')">Copy</button></div>
        <p style="font-size:12px;color:var(--dim);margin-top:6px">Human-readable TG card — shows payment details + JSON link. Anyone can open in any bot.</p>

        <h3 style="font-size:13px;margin:14px 0 8px;color:var(--ng)">4. Check by session_id / order_id</h3>
        <div class="api-out"><span>GET /api/v2/check/YOUR_API_KEY?session_id=SES...</span><button class="copy" onclick="copyText('/api/v2/check/YOUR_KEY?session_id=SES...')">Copy</button></div>

        <h3 style="font-size:13px;margin:14px 0 8px;color:var(--ng)">5. Telegram Bot (Python)</h3>
<pre style="background:#02020a;color:#00ffb3;padding:14px;border-radius:10px;font-size:11px;overflow-x:auto">import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

API_KEY = "YOUR_API_KEY"
BASE = "https://yourdomain.com"

async def qr(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    amount = ctx.args[0] if ctx.args else "100"
    url = f"{BASE}/v2/fam/{API_KEY}?qr={amount}"
    await update.message.reply_text(
        f"💳 Pay ₹{amount}\n\n🔗 {url}\n\n"
        f"⏳ After payment, the QR page will show a session link. "
        f"Send it here for full JSON details."
    )

async def check(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    sid = ctx.args[0] if ctx.args else ""
    r = requests.get(f"{BASE}/api/session/{sid}").json()
    if r.get('status') == 'PAID':
        await update.message.reply_text(
            f"✅ PAID ₹{r['total_paid']:.2f}\n"
            f"Txn: {r['txn_id']}\nUTR: {r['utr']}"
        )
    elif r.get('status') == 'PENDING' and r.get('total_paid',0) > 0:
        rem = r['expected'] - r['total_paid']
        await update.message.reply_text(f"⚠️ Partial. ₹{rem:.2f} remaining.")
    else:
        await update.message.reply_text(f"Status: {r.get('status')}")

app = Application.builder().token("YOUR_BOT_TOKEN").build()
app.add_handler(CommandHandler("qr", qr))
app.add_handler(CommandHandler("check", check))
app.run_polling()</pre>

        <h3 style="font-size:13px;margin:14px 0 8px;color:var(--ng)">6. JSON Response Example (PAID)</h3>
<pre style="background:#02020a;color:#00ffb3;padding:14px;border-radius:10px;font-size:11px;overflow-x:auto">{
  "status": "PAID",
  "session_id": "SESaB3xYzK9pQ7mN2wL4",
  "order_id": "ORD17300000001234",
  "expected": 10.0,
  "total_paid": 10.0,
  "payment_count": 1,
  "txn_id": "FMPIB6930608000",
  "utr": "667524755400",
  "verified": true,
  "payments": [
    {
      "txn_id": "FMPIB6930608000",
      "utr": "667524755400",
      "amount": 10.0,
      "sender_name": "mal",
      "sender_upi": "mal.628@superyes",
      "email_date": "10:54 AM IST, 05 November 2026",
      "paid_at": "2026-11-05 10:54:00"
    }
  ]
}</pre>

        <h3 style="font-size:13px;margin:14px 0 8px;color:var(--ng)">7. Partial Payment Example</h3>
<pre style="background:#02020a;color:#ffa502;padding:14px;border-radius:10px;font-size:11px;overflow-x:auto">{
  "status": "PENDING",
  "expected": 10.0,
  "total_paid": 9.0,
  "short_by": 1.0,
  "payment_count": 1,
  "verified": false,
  "message": "Please pay ₹1.00 more to complete."
}</pre>

        <h3 style="font-size:13px;margin:14px 0 8px;color:var(--ng)">8. Multi-Payment Flow</h3>
        <p style="font-size:12px;color:var(--dim);line-height:1.6">
          <b>Example:</b> QR for ₹10 → payer sends ₹9 → <code>status: PENDING, total_paid: 9, short_by: 1</code> → QR is <b>still valid</b> → payer sends ₹1 → <code>status: PAID, total_paid: 10, verified: true</code> ✅
          <br><br>
          <b>Same-amount isolation:</b> Two QRs for ₹10 are generated. Payer 1 pays on QR-A, Payer 2 pays on QR-B → Each session is separate, no cross-matching. First completion locks its session; other stays pending independently.
        </p>
      </div>
    </section>

    <section id="p-settings" class="page hidden">
      <div class="card">
        <h2>⚙️ Settings</h2>
        <div class="fg" style="margin-bottom:12px">
          <label>Theme</label>
          <select id="themeSel" onchange="applyTheme(this.value)">
            <option value="dark">Dark</option><option value="light">Light</option>
          </select>
        </div>
        <button class="btn" onclick="saveSettings()">💾 Save Settings</button>
      </div>
      <div class="card">
        <h2>ℹ️ About V5.0</h2>
        <ul class="flist">
          <li>Version: V5.0.0 ULTRA SESSION</li>
          <li>Session-based isolation (no cross-matching)</li>
          <li>Multi-payment support (partial + full)</li>
          <li>Universal TG link: /tg/session/&lt;id&gt;</li>
          <li>Universal JSON API: /api/session/&lt;id&gt;</li>
          <li>Flash speed verification: ~1-2 sec</li>
          <li>Webhook: payment.success / payment.partial</li>
          <li>Session view landing page: /session/&lt;id&gt;</li>
          <li>Sender name/UPI extraction</li>
          <li>Duplicate txn block</li>
        </ul>
      </div>
    </section>

  </main>
</div>
<div id="toast"></div>

<script>
function toast(m,err){const t=document.getElementById('toast');t.textContent=m;t.className='show'+(err?' err':'');clearTimeout(window.__t);window.__t=setTimeout(()=>t.className='',3000);}
function copyText(t){navigator.clipboard.writeText(t).then(()=>toast('✅ Copied'))}
async function api(p,o={}){const r=await fetch(p,{headers:{'Content-Type':'application/json'},credentials:'same-origin',...o});let d={};try{d=await r.json()}catch{}if(!r.ok)throw new Error(d.error||d.message||'Failed');return d;}
function esc(s){return String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function applyTheme(t){document.documentElement.setAttribute('data-theme',t);localStorage.setItem('theme',t);const s=document.getElementById('themeSel');if(s)s.value=t;}
function toggleTheme(){const c=document.documentElement.getAttribute('data-theme')||'dark';applyTheme(c==='dark'?'light':'dark');}
applyTheme(localStorage.getItem('theme')||'dark');

function toggleAuth(m){document.getElementById('loginForm').classList.toggle('hidden',m!=='login');document.getElementById('regForm').classList.toggle('hidden',m!=='reg');}
async function doLogin(){try{const u=document.getElementById('lgU').value.trim(),p=document.getElementById('lgP').value;if(!u||!p)return toast('Fill fields',true);await api('/api/login',{method:'POST',body:JSON.stringify({username:u,password:p})});toast('✅ Logged in');bootApp();}catch(e){toast('❌ '+e.message,true)}}
async function doReg(){try{const u=document.getElementById('rgU').value.trim(),p=document.getElementById('rgP').value,em=document.getElementById('rgE').value.trim();if(!u||!p)return toast('Fill fields',true);await api('/api/register',{method:'POST',body:JSON.stringify({username:u,password:p,email:em})});toast('✅ Account created. Please login.');toggleAuth('login');document.getElementById('lgU').value=u;}catch(e){toast('❌ '+e.message,true)}}
async function doLogout(){if(!confirm('Logout?'))return;await api('/api/logout',{method:'POST'});location.reload();}

function go(p){
  document.querySelectorAll('.page').forEach(x=>x.classList.add('hidden'));
  document.getElementById('p-'+p).classList.remove('hidden');
  document.querySelectorAll('.item').forEach(i=>i.classList.toggle('active',i.dataset.p===p));
  const titles={dashboard:'Dashboard',analytics:'Analytics',account:'Account',keys:'API Keys',history:'Transactions',partials:'Partial Payments',audit:'Audit Log',docs:'API Docs',settings:'Settings'};
  document.getElementById('title').textContent=titles[p]||p;
  document.getElementById('sidebar').classList.remove('open');
  if(p==='keys')loadKeys();
  if(p==='history')loadHistory();
  if(p==='partials')loadPartials();
  if(p==='audit')loadAudit();
  if(p==='settings')loadSettings();
  if(p==='analytics')loadAnalytics();
}

let chart7Obj=null, pieObj=null, monthObj=null, yearObj=null, weekdayObj=null;
let currentPeriod='today';

async function bootApp(){
  try{
    const me=await api('/api/me');
    document.getElementById('authScreen').classList.add('hidden');
    document.getElementById('shell').classList.remove('hidden');
    document.getElementById('chipUser').textContent=me.username;
    const dot=document.getElementById('emailDot');
    dot.className='dot '+(me.email_status==='online'?'on':me.email_status==='offline'?'off':'unk');
    fillAccount(me); loadDashboard(); loadUptime();
    if(me.theme) applyTheme(me.theme);
  }catch(e){ location.reload(); }
}

async function loadUptime(){
  try{const d=await fetch('/api/uptime').then(r=>r.json());
    document.getElementById('uptime').innerHTML='⏱ <b>'+d.human+'</b>';
  }catch(e){}
}
setInterval(loadUptime, 1000);

function fillAccount(me){
  document.getElementById('acName').value=me.full_name||'';
  document.getElementById('acUpi').value=me.upi_id||'';
  document.getElementById('acMob').value=me.mobile||'';
  document.getElementById('acEmail').value=me.email||'';
  document.getElementById('acMin').value=me.default_qr_minutes||15;
  document.getElementById('acTol').value=me.tolerance||0;
  document.getElementById('acHook').value=me.webhook_url||'';
  document.getElementById('emailTxt').textContent=me.email||'-';
  document.getElementById('upiTxt').textContent=me.upi_id||'-';
}

async function loadDashboard(){
  try{
    const d=await api('/api/dashboard');
    document.getElementById('earn').textContent=d.total_earning.toFixed(2);
    document.getElementById('stKeys').textContent=d.total_api_keys;
    document.getElementById('stReq').textContent=d.total_requests;
    document.getElementById('stQR').textContent=d.total_qr_generated;
    
    const an = await api('/api/analytics');
    document.getElementById('stToday').textContent = '₹' + an.today.amount.toFixed(0);
    
    const ctx = document.getElementById('chart7').getContext('2d');
    if(chart7Obj) chart7Obj.destroy();
    chart7Obj = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: an.days_7.map(x=>x.day),
        datasets: [{
          label: '₹',
          data: an.days_7.map(x=>x.amount),
          backgroundColor: 'rgba(0,255,179,.6)',
          borderColor: '#00ffb3',
          borderWidth: 2,
          borderRadius: 8
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, ticks: { color: '#7a7a9a' }, grid: { color: 'rgba(31,31,58,.5)' } },
          x: { ticks: { color: '#7a7a9a' }, grid: { display: false } }
        }
      }
    });
  }catch(e){toast('❌ '+e.message,true)}
}

function setPeriod(p, el){
  currentPeriod = p;
  document.querySelectorAll('.period-tab .tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
  loadAnalytics();
}

async function loadAnalytics(){
  try{
    const an = await api('/api/analytics');
    const period = an[currentPeriod];
    document.getElementById('anAmount').textContent = '₹' + period.amount.toFixed(2);
    document.getElementById('anCount').textContent = period.count;
    
    const pieCtx = document.getElementById('pieChart').getContext('2d');
    if(pieObj) pieObj.destroy();
    pieObj = new Chart(pieCtx, {
      type: 'doughnut',
      data: {
        labels: ['Today','Week','Month','Year'],
        datasets: [{
          data: [an.today.amount, an.week.amount, an.month.amount, an.year.amount],
          backgroundColor: ['#00ffb3','#00d4ff','#a855f7','#ff00aa'],
          borderColor: '#0f0f1e', borderWidth: 3
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { color: '#7a7a9a', padding: 12 } } }
      }
    });
    
    const monthCtx = document.getElementById('monthChart').getContext('2d');
    if(monthObj) monthObj.destroy();
    monthObj = new Chart(monthCtx, {
      type: 'line',
      data: {
        labels: an.months_12.map(x=>x.month),
        datasets: [{
          label: 'Monthly Earnings',
          data: an.months_12.map(x=>x.amount),
          borderColor: '#a855f7', backgroundColor: 'rgba(168,85,247,.2)',
          borderWidth: 3, fill: true, tension: 0.4
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, ticks: { color: '#7a7a9a' }, grid: { color: 'rgba(31,31,58,.5)' } },
          x: { ticks: { color: '#7a7a9a' }, grid: { display: false } }
        }
      }
    });
    
    const wdCtx = document.getElementById('weekdayChart').getContext('2d');
    if(weekdayObj) weekdayObj.destroy();
    weekdayObj = new Chart(wdCtx, {
      type: 'bar',
      data: {
        labels: an.weekday_dist.map(x=>x.day),
        datasets: [{
          label: 'By Weekday',
          data: an.weekday_dist.map(x=>x.amount),
          backgroundColor: ['#00ffb3','#00d4ff','#a855f7','#ff00aa','#ffa502','#00e0a4','#ff4757'],
          borderRadius: 8, borderWidth: 2, borderColor: 'transparent'
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, ticks: { color: '#7a7a9a' }, grid: { color: 'rgba(31,31,58,.5)' } },
          x: { ticks: { color: '#7a7a9a' }, grid: { display: false } }
        }
      }
    });
    
    const yCtx = document.getElementById('yearChart').getContext('2d');
    if(yearObj) yearObj.destroy();
    yearObj = new Chart(yCtx, {
      type: 'bar',
      data: {
        labels: an.years_5.map(x=>x.year.toString()),
        datasets: [{
          label: 'Yearly',
          data: an.years_5.map(x=>x.amount),
          backgroundColor: 'rgba(255,0,170,.5)', borderColor: '#ff00aa',
          borderWidth: 2, borderRadius: 8
        }]
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, ticks: { color: '#7a7a9a' }, grid: { color: 'rgba(31,31,58,.5)' } },
          x: { ticks: { color: '#7a7a9a' }, grid: { display: false } }
        }
      }
    });
  }catch(e){toast('❌ '+e.message,true)}
}

async function saveAccount(){
  try{
    const payload={
      full_name:document.getElementById('acName').value.trim(),
      upi_id:document.getElementById('acUpi').value.trim(),
      mobile:document.getElementById('acMob').value.trim(),
      email:document.getElementById('acEmail').value.trim(),
      app_password:document.getElementById('acPass').value.trim() || '',
      default_qr_minutes:parseInt(document.getElementById('acMin').value)||15,
      tolerance:parseFloat(document.getElementById('acTol').value)||0,
      webhook_url:document.getElementById('acHook').value.trim()
    };
    if(!payload.upi_id)return toast('UPI required',true);
    await api('/api/setup-account',{method:'POST',body:JSON.stringify(payload)});
    toast('✅ Saved'); document.getElementById('acPass').value=''; bootApp();
  }catch(e){toast('❌ '+e.message,true)}
}

async function testEmail(){
  try{
    document.getElementById('testRes').innerHTML='<div style="color:var(--nwarn)">⏳ Testing…</div>';
    const d=await api('/api/test-email',{method:'POST',body:JSON.stringify({email:document.getElementById('acEmail').value,app_password:document.getElementById('acPass').value})});
    document.getElementById('testRes').innerHTML=`<div style="background:rgba(0,255,179,.1);border:1px solid rgba(0,255,179,.4);padding:12px;border-radius:10px;color:var(--ng);font-size:13px">${d.message}<br><b>Total:</b> ${d.total_emails||0} | <b>Unseen:</b> ${d.unseen_emails||0}</div>`;
    document.getElementById('emailDot').className='dot on';
  }catch(e){
    document.getElementById('testRes').innerHTML=`<div style="background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.4);padding:12px;border-radius:10px;color:var(--dang);font-size:13px">${e.message}</div>`;
    document.getElementById('emailDot').className='dot off';
  }
}

function toggleMode(){document.getElementById('daysWrap').style.display=document.getElementById('keyMode').value==='lifetime'?'none':'flex';}
async function genKey(){
  try{
    const mode=document.getElementById('keyMode').value;
    const days=parseInt(document.getElementById('keyDays').value)||30;
    const rate_limit=parseInt(document.getElementById('keyRate').value)||60;
    const d=await api('/api/generate-key',{method:'POST',body:JSON.stringify({mode,days,rate_limit,label:document.getElementById('keyLabel').value})});
    document.getElementById('keyRes').innerHTML=`<div style="background:rgba(0,255,179,.08);border:1px solid rgba(0,255,179,.4);padding:14px;border-radius:10px">
      <div style="color:var(--ng);font-weight:700;margin-bottom:6px">✅ Key Generated</div>
      <div class="api-out"><span>${esc(d.example)}</span><button class="copy" onclick="copyText('${esc(d.example)}')">Copy</button></div>
    </div>`;
    loadKeys();
  }catch(e){toast('❌ '+e.message,true)}
}
async function loadKeys(){
  try{
    const list=await api('/api/list-keys'), el=document.getElementById('keysList');
    if(!list.length){el.innerHTML='<div class="empty"><div class="empty-ic">🔑</div>No keys yet</div>';return}
    el.innerHTML=list.map(k=>`<div class="txn" style="flex-direction:column;align-items:stretch;gap:8px;padding:14px">
      <div style="display:flex;justify-content:space-between;align-items:center">
        <div><b style="font-family:monospace;font-size:12px">${esc(k.api_key)}</b> ${k.expiry==='LIFETIME'?'<span class="badge life">Lifetime</span>':''}</div>
        <button class="copy" style="background:rgba(255,71,87,.15);color:var(--dang)" onclick="delKey('${esc(k.api_key)}')">Delete</button>
      </div>
      <div class="meta">Requests: ${k.total_requests} · QRs: ${k.total_qr} · Received: ₹${k.total_received} · Rate: ${k.rate_limit}/min</div>
      <div class="api-out"><span>${esc(k.url)}</span><button class="copy" onclick="copyText('${esc(k.url)}')">Copy URL</button></div>
    </div>`).join('');
  }catch(e){toast('❌ '+e.message,true)}
}
async function delKey(k){
  if(!confirm('Delete this key?'))return;
  try{await api('/api/delete-key/'+k,{method:'DELETE'});toast('Deleted');loadKeys()}catch(e){toast('❌ '+e.message,true)}
}
async function loadHistory(){
  try{
    const txns=await api('/api/transactions');
    const el=document.getElementById('txnList');
    if(!txns.length){el.innerHTML='<div class="empty"><div class="empty-ic">📜</div>No transactions yet</div>';return}
    el.innerHTML=txns.map(t=>`<div class="txn">
      <div style="flex:1"><div class="amt">+ ₹${t.amount.toFixed(2)}</div>
      <div class="meta">Txn: ${esc(t.txn_id)||'-'}</div>
      <div class="meta">UTR: ${esc(t.utr)||'-'}</div>
      <div class="meta">From: ${esc(t.sender_upi)||'-'}</div>
      <div class="meta">${esc(t.email_date)||esc(t.paid_at)}</div></div>
      <div style="font-size:10px;color:var(--dim);text-align:right;font-family:'Space Mono',monospace">${esc(t.order_id)||''}<br>${esc(t.session_id)||''}</div>
    </div>`).join('');
  }catch(e){toast('❌ '+e.message,true)}
}
async function loadPartials(){
  try{
    const ps=await api('/api/partial-payments');
    const el=document.getElementById('partialList');
    if(!ps.length){el.innerHTML='<div class="empty"><div class="empty-ic">✨</div>No partial payments — all clean!</div>';return}
    el.innerHTML=ps.map(p=>`<div class="txn partial">
      <div><div class="amt">₹${p.received.toFixed(2)} / ₹${p.expected.toFixed(2)}</div>
      <div class="meta">Short by ₹${(p.short_by||0).toFixed(2)} · Txn ${esc(p.txn_id)||'-'}</div>
      <div class="meta">Session: ${esc(p.session_id)||''}</div></div>
      <div style="font-size:11px;color:var(--dim);text-align:right">${esc(p.created_at)}<br>${esc(p.order_id)}</div>
    </div>`).join('');
  }catch(e){toast('❌ '+e.message,true)}
}
async function loadAudit(){
  try{
    const list=await api('/api/audit-log');
    const el=document.getElementById('auditList');
    if(!list.length){el.innerHTML='<div class="empty"><div class="empty-ic">🔍</div>No logs</div>';return}
    el.innerHTML=list.map(l=>`<div class="txn"><div><div style="font-weight:700;font-size:12px">${esc(l.action)}</div>
      <div class="meta">${esc(l.details||'')}</div></div>
      <div style="font-size:11px;color:var(--dim);text-align:right">${esc(l.created_at)}<br>${esc(l.ip||'')}</div>
    </div>`).join('');
  }catch(e){toast('❌ '+e.message,true)}
}
async function loadSettings(){
  try{
    const me=await api('/api/me');
    document.getElementById('themeSel').value = me.theme || 'dark';
  }catch(e){}
}
async function saveSettings(){
  try{
    const theme=document.getElementById('themeSel').value;
    applyTheme(theme);
    const me=await api('/api/me');
    await api('/api/setup-account',{method:'POST',body:JSON.stringify({
      full_name:me.full_name,upi_id:me.upi_id,mobile:me.mobile,
      email:me.email,default_qr_minutes:me.default_qr_minutes,
      tolerance:me.tolerance,webhook_url:me.webhook_url,theme
    })});
    toast('✅ Settings saved');
  }catch(e){toast('❌ '+e.message,true)}
}

(async()=>{try{await api('/api/me');bootApp()}catch{}})();
</script></body></html>
"""

@app.route('/')
def home(): return render_template_string(MAIN_HTML)

@app.route('/health')
def health(): return jsonify({"status":"ok", "version":APP_VERSION, "time": time.time()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), threaded=True)

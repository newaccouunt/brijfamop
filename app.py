import os, re, time, imaplib, email, datetime, random, string, base64, sqlite3, secrets
import json, hashlib, hmac, threading, queue, concurrent.futures
from io import BytesIO
from email.header import decode_header
from email.utils import parsedate_to_datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, session, g, redirect, make_response
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
APP_VERSION = "5.0.0"
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
            telegram_bot_link TEXT DEFAULT '',
            website_link TEXT DEFAULT '',
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
            order_id TEXT PRIMARY KEY, 
            session_id TEXT UNIQUE,
            api_key TEXT NOT NULL,
            username TEXT NOT NULL, amount REAL NOT NULL,
            status TEXT DEFAULT 'PENDING',
            txn_id TEXT DEFAULT '', utr TEXT DEFAULT '',
            paid_amount REAL DEFAULT 0,
            partial_amount REAL DEFAULT 0,
            total_paid REAL DEFAULT 0,
            short_by REAL DEFAULT 0,
            overpaid REAL DEFAULT 0,
            notes TEXT DEFAULT '',
            created_at REAL NOT NULL, expires_at REAL NOT NULL,
            paid_at REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
            order_id TEXT, session_id TEXT,
            amount REAL NOT NULL,
            txn_id TEXT UNIQUE, utr TEXT,
            sender_name TEXT DEFAULT '',
            sender_upi TEXT DEFAULT '',
            email_date TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            paid_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, action TEXT, details TEXT,
            ip TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS partial_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id TEXT, session_id TEXT, username TEXT,
            expected REAL, received REAL, short_by REAL,
            txn_id TEXT, utr TEXT,
            notified INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_qr_apikey ON qr_sessions(api_key);
        CREATE INDEX IF NOT EXISTS idx_qr_status ON qr_sessions(status);
        CREATE INDEX IF NOT EXISTS idx_qr_session ON qr_sessions(session_id);
        CREATE INDEX IF NOT EXISTS idx_txn_username ON transactions(username);
        CREATE INDEX IF NOT EXISTS idx_txn_paidat ON transactions(paid_at);
        CREATE INDEX IF NOT EXISTS idx_partial_txn ON partial_payments(txn_id);
        """)
        
        # Migrate existing DB - add new columns if missing
        try:
            db.execute("ALTER TABLE users ADD COLUMN telegram_bot_link TEXT DEFAULT ''")
        except: pass
        try:
            db.execute("ALTER TABLE users ADD COLUMN website_link TEXT DEFAULT ''")
        except: pass
        try:
            db.execute("ALTER TABLE qr_sessions ADD COLUMN session_id TEXT")
        except: pass
        try:
            db.execute("ALTER TABLE qr_sessions ADD COLUMN total_paid REAL DEFAULT 0")
        except: pass
        try:
            db.execute("ALTER TABLE transactions ADD COLUMN session_id TEXT")
        except: pass
        try:
            db.execute("ALTER TABLE partial_payments ADD COLUMN session_id TEXT")
        except: pass
        
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
    """Generate random session ID like: Jwowbsiajjaj1919199"""
    chars = string.ascii_letters + string.digits
    prefix = ''.join(random.choices(string.ascii_letters, k=14))
    suffix = ''.join(random.choices(string.digits, k=7))
    return prefix + suffix

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
# EMAIL PARSING
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

def read_fampay_email(username, expected_amount, order_id=None, tolerance=0.0, window_minutes=2):
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
                        "sender_name": sender_name, "sender_upi": sender_upi,
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
                        "sender_name": sender_name, "sender_upi": sender_upi,
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
                        "sender_name": sender_name, "sender_upi": sender_upi,
                        "email_date": email_date
                    }, "PARTIAL"

        mail.logout()
        return False, None, "NO_EMAIL"
    except Exception as e:
        return False, None, str(e)

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
        "telegram_bot_link": u['telegram_bot_link'] or '',
        "website_link": u['website_link'] or '',
        "version": APP_VERSION, "boot_time": BOOT_TIME
    })

@app.route('/api/setup-account', methods=['POST'])
@login_required
def setup_account():
    d = parse_request_data()
    db = get_db()
    db.execute("""UPDATE users SET full_name=?, upi_id=?, mobile=?, email=?, app_password=?,
                  default_qr_minutes=?, tolerance=?, webhook_url=?, auto_verify=?, theme=?,
                  telegram_bot_link=?, website_link=?
                  WHERE username=?""",
               (d.get('full_name','').strip(), d.get('upi_id','').strip(), d.get('mobile','').strip(),
                d.get('email','').strip(), d.get('app_password','').strip(),
                int(d.get('default_qr_minutes', 15)),
                float(d.get('tolerance', 0) or 0),
                d.get('webhook_url','').strip(),
                int(d.get('auto_verify', 1)),
                d.get('theme', 'dark'),
                d.get('telegram_bot_link','').strip(),
                d.get('website_link','').strip(),
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
            "order_id": t['order_id'], "session_id": t['session_id'] or '',
            "paid_at": t['paid_at'],
            "sender_name": t['sender_name'] or '',
            "sender_upi": t['sender_upi'] or '',
            "email_date": t['email_date'] or ''
        } for t in txns],
        "partial_payments": [{
            "order_id": p['order_id'], "session_id": p['session_id'] or '',
            "expected": p['expected'],
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
        "check_url": build_url(f"/api/v2/check/{key}")})

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
        "check_url": build_url(f"/api/v2/check/{r['api_key']}")
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
        "order_id": t['order_id'], "session_id": t['session_id'] or '',
        "paid_at": t['paid_at'],
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
        "order_id": p['order_id'], "session_id": p['session_id'] or '',
        "expected": p['expected'],
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
# PAYMENT VERIFICATION - MULTI-PAYMENT SUPPORT
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

def _verify_payment_for_session(s, key_row, tolerance=0.0):
    """
    NEW V5 LOGIC:
    - Supports PARTIAL payments (accumulates)
    - Each QR session has unique session_id
    - Once PAID, other QR with same amount won't be affected
    """
    db = get_db()
    
    # If already PAID or EXPIRED, skip
    if s['status'] in ['PAID', 'EXPIRED']:
        return False, None, s['status']
    
    # Check if this specific order is still within expiry
    if time.time() > s['expires_at']:
        db.execute("UPDATE qr_sessions SET status='EXPIRED' WHERE order_id=?", (s['order_id'],))
        db.commit()
        return False, None, "EXPIRED"
    
    # Calculate remaining amount needed (expected - already_paid)
    already_paid = s['total_paid'] or 0
    remaining = round(s['amount'] - already_paid, 2)
    
    if remaining <= tolerance:
        # Fully paid from previous partial payments
        db.execute("""UPDATE qr_sessions SET status='PAID', paid_at=? WHERE order_id=?""",
                   (time.time(), s['order_id']))
        db.commit()
        return True, {
            "txn_id": s['txn_id'], "utr": s['utr'],
            "amount": already_paid, "expected": s['amount'],
            "session_id": s['session_id'],
            "sender_name": "", "sender_upi": "", "email_date": ""
        }, "PAID"
    
    # Read emails - expected amount is remaining
    ok, info, status = read_fampay_email(s['username'], remaining, s['order_id'], tolerance)
    
    if status == "PAID" and ok:
        # FULL payment received
        new_total = round(already_paid + info['amount'], 2)
        db.execute("""UPDATE qr_sessions SET status='PAID',txn_id=?,utr=?,paid_amount=?,total_paid=?,paid_at=?
                      WHERE order_id=?""",
                   (info['txn_id'], info['utr'], info['amount'], new_total, time.time(), s['order_id']))
        db.execute("UPDATE users SET total_earning=total_earning+? WHERE username=?",
                   (info['amount'], s['username']))
        db.execute("UPDATE api_keys SET total_received=total_received+? WHERE api_key=?",
                   (info['amount'], key_row['api_key']))
        try:
            db.execute("""INSERT INTO transactions 
                          (username,order_id,session_id,amount,txn_id,utr,sender_name,sender_upi,email_date) 
                          VALUES (?,?,?,?,?,?,?,?,?)""",
                       (s['username'], s['order_id'], s['session_id'], info['amount'], 
                        info['txn_id'], info['utr'],
                        info.get('sender_name',''), info.get('sender_upi',''), info.get('email_date','')))
        except sqlite3.IntegrityError:
            pass
        db.commit()
        notify_webhook(s['username'], "payment.success", {
            "order_id": s['order_id'], "session_id": s['session_id'],
            "amount": info['amount'], "total_paid": new_total,
            "txn_id": info['txn_id'], "utr": info['utr'],
            "sender_name": info.get('sender_name',''),
            "sender_upi": info.get('sender_upi',''),
            "email_date": info.get('email_date','')
        })
        return True, info, "PAID"

    elif status == "PARTIAL" and info:
        # Partial payment received - accumulate
        new_total = round(already_paid + info['amount'], 2)
        new_short = round(s['amount'] - new_total, 2)
        
        # Update session with accumulated total
        db.execute("""UPDATE qr_sessions SET 
                      partial_amount=?, total_paid=?, short_by=?, overpaid=?, txn_id=?, utr=?
                      WHERE order_id=?""",
                   (info['amount'], new_total, new_short, 
                    info.get('overpaid', 0), info['txn_id'], info['utr'], s['order_id']))
        
        # Record partial payment
        existing = db.execute("SELECT id FROM partial_payments WHERE txn_id=?",
                              (info['txn_id'],)).fetchone()
        if not existing:
            db.execute("""INSERT INTO partial_payments
                          (order_id,session_id,username,expected,received,short_by,txn_id,utr)
                          VALUES (?,?,?,?,?,?,?,?)""",
                       (s['order_id'], s['session_id'], s['username'], s['amount'],
                        info['amount'], new_short, info['txn_id'], info['utr']))
        
        # If new_total >= expected, mark as PAID
        if new_total + tolerance >= s['amount']:
            db.execute("""UPDATE qr_sessions SET status='PAID', paid_amount=?, paid_at=?
                          WHERE order_id=?""",
                       (new_total, time.time(), s['order_id']))
            db.execute("UPDATE users SET total_earning=total_earning+? WHERE username=?",
                       (info['amount'], s['username']))
            db.execute("UPDATE api_keys SET total_received=total_received+? WHERE api_key=?",
                       (info['amount'], key_row['api_key']))
            try:
                db.execute("""INSERT INTO transactions 
                              (username,order_id,session_id,amount,txn_id,utr,sender_name,sender_upi,email_date) 
                              VALUES (?,?,?,?,?,?,?,?,?)""",
                           (s['username'], s['order_id'], s['session_id'], info['amount'],
                            info['txn_id'], info['utr'],
                            info.get('sender_name',''), info.get('sender_upi',''), info.get('email_date','')))
            except: pass
            db.commit()
            notify_webhook(s['username'], "payment.success", {
                "order_id": s['order_id'], "session_id": s['session_id'],
                "amount": info['amount'], "total_paid": new_total,
                "txn_id": info['txn_id'], "utr": info['utr']
            })
            return True, {**info, "total_paid": new_total}, "PAID"
        else:
            db.commit()
            notify_webhook(s['username'], "payment.partial", {
                "order_id": s['order_id'], "session_id": s['session_id'],
                "expected": s['amount'], "received": info['amount'],
                "total_paid": new_total, "short_by": new_short,
                "txn_id": info['txn_id']
            })
            return False, {**info, "total_paid": new_total, "short_by": new_short}, "PARTIAL"

    return False, None, status or "PENDING"

# ==========================================
# PUBLIC QR - V5 WITH SESSION LINKS
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
    session_id = gen_session_id()  # NEW: Random session ID
    now = time.time()

    db.execute("""INSERT INTO qr_sessions (order_id,session_id,api_key,username,amount,created_at,expires_at)
                  VALUES (?,?,?,?,?,?,?)""",
               (order_id, session_id, key_row['api_key'], key_row['username'], amount, now, now + minutes*60))
    db.commit()
    audit(key_row['username'], "QR_GENERATED", f"order={order_id} session={session_id} amt={amount}")

    qr_image = qr_b64(upi)
    
    # Build session/result URLs
    session_url = build_url(f"/result/{session_id}")
    
    return render_template_string(
        QR_HTML_TEMPLATE_V5,
        amount=amount, qr_b64=qr_image, order_id=order_id, session_id=session_id,
        upi_id=user['upi_id'], full_name=user['full_name'] or user['username'],
        minutes=minutes, tolerance=user['tolerance'] or 0,
        brand=APP_VERSION, session_url=session_url
    )

# ==========================================
# SESSION RESULT - JSON endpoint (for TG bot/webapp)
# ==========================================
@app.route('/result/<session_id>')
def session_result(session_id):
    """Universal session result page - can be opened by TG bot / webapp"""
    db = get_db()
    s = db.execute("SELECT * FROM qr_sessions WHERE session_id=?", (session_id,)).fetchone()
    if not s:
        return render_template_string(ERROR_HTML, msg="❌ Invalid session ID"), 404
    
    # Get sender info from transaction if paid
    txn = None
    if s['status'] == 'PAID':
        txn = db.execute("SELECT * FROM transactions WHERE order_id=? ORDER BY id DESC LIMIT 1",
                         (s['order_id'],)).fetchone()
    
    # Return JSON for API clients (Accept: application/json or ?format=json)
    want_json = (request.args.get('format') == 'json' or 
                 'application/json' in request.headers.get('Accept', ''))
    
    if want_json:
        return jsonify(_build_result_json(s, txn))
    
    # Return HTML page with auto-refresh
    return render_template_string(SESSION_RESULT_HTML, 
        session_id=session_id,
        order_id=s['order_id'],
        amount=s['amount'],
        expected=s['amount'],
        status=s['status'],
        paid=s['paid_amount'] or 0,
        total_paid=s['total_paid'] or 0,
        short_by=s['short_by'] or 0,
        txn_id=s['txn_id'] or '',
        utr=s['utr'] or '',
        sender_name=txn['sender_name'] if txn else '',
        sender_upi=txn['sender_upi'] if txn else '',
        email_date=txn['email_date'] if txn else '',
        brand=APP_VERSION
    )

def _build_result_json(s, txn):
    """Build JSON response for session result"""
    result = {
        "session_id": s['session_id'],
        "order_id": s['order_id'],
        "status": s['status'],
        "expected": s['amount'],
        "paid": s['paid_amount'] or 0,
        "total_paid": s['total_paid'] or 0,
        "short_by": s['short_by'] or 0,
        "overpaid": s['overpaid'] or 0,
        "txn_id": s['txn_id'] or '',
        "utr": s['utr'] or '',
        "verified": s['status'] == 'PAID',
        "created_at": s['created_at'],
        "expires_at": s['expires_at'],
        "paid_at": s['paid_at'] or 0,
        "seconds_left": int(max(0, s['expires_at'] - time.time())) if s['status'] == 'PENDING' else 0,
    }
    if txn:
        result["sender_name"] = txn['sender_name'] or ''
        result["sender_upi"] = txn['sender_upi'] or ''
        result["email_date"] = txn['email_date'] or ''
    else:
        result["sender_name"] = ''
        result["sender_upi"] = ''
        result["email_date"] = ''
    
    if s['status'] == 'PARTIAL':
        result["message"] = f"⚠️ Payment incomplete. Paid ₹{s['total_paid']:.2f} of ₹{s['amount']:.2f}. Please pay ₹{s['short_by']:.2f} more."
    elif s['status'] == 'PAID':
        result["message"] = f"✅ Payment verified! ₹{s['paid_amount']:.2f} received."
    elif s['status'] == 'EXPIRED':
        result["message"] = "❌ Session expired"
    else:
        result["message"] = "⏳ Waiting for payment..."
    
    return result

# ==========================================
# JSON CHECK API (V2 compatibility)
# ==========================================
@app.route('/api/v2/check/<path:api_key>')
def api_check_v2(api_key):
    key_row, status = _key_status(api_key)
    if status != "active":
        return jsonify({"status": "ERROR", "error": status, "code": 403}), 403

    db = get_db()
    order_id = request.args.get('order_id')
    session_id = request.args.get('session_id')
    
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

    # Handle terminal states
    if s['status'] == 'PAID':
        txn = db.execute("SELECT * FROM transactions WHERE order_id=? ORDER BY id DESC LIMIT 1",
                         (s['order_id'],)).fetchone()
        return jsonify({
            "status": "PAID", "order_id": s['order_id'], "session_id": s['session_id'],
            "amount": s['paid_amount'] or s['amount'],
            "expected": s['amount'], "paid": s['paid_amount'] or s['amount'],
            "total_paid": s['total_paid'] or s['amount'],
            "txn_id": s['txn_id'], "utr": s['utr'],
            "sender_name": txn['sender_name'] if txn else '',
            "sender_upi": txn['sender_upi'] if txn else '',
            "email_date": txn['email_date'] if txn else '',
            "verified": True
        })

    if s['status'] == 'PARTIAL':
        return jsonify({
            "status": "PARTIAL", "order_id": s['order_id'], "session_id": s['session_id'],
            "expected": s['amount'], "received": s['partial_amount'],
            "total_paid": s['total_paid'] or s['partial_amount'],
            "short_by": s['short_by'], "overpaid": s['overpaid'],
            "txn_id": s['txn_id'], "utr": s['utr'], "verified": False,
            "message": f"Please pay remaining ₹{s['short_by']:.2f}" if s['short_by'] > 0 else f"Overpaid ₹{s['overpaid']:.2f}"
        })

    if s['status'] == 'EXPIRED' or time.time() > s['expires_at']:
        if s['status'] != 'EXPIRED':
            db.execute("UPDATE qr_sessions SET status='EXPIRED' WHERE order_id=?", (s['order_id'],))
            db.commit()
        return jsonify({"status": "EXPIRED", "order_id": s['order_id'], "session_id": s['session_id']})

    user = db.execute("SELECT tolerance FROM users WHERE username=?", (s['username'],)).fetchone()
    tol = (user['tolerance'] if user else 0) or 0
    ok, info, st = _verify_payment_for_session(s, key_row, tol)
    s = db.execute("SELECT * FROM qr_sessions WHERE order_id=?", (s['order_id'],)).fetchone()

    if s['status'] == 'PAID':
        txn = db.execute("SELECT * FROM transactions WHERE order_id=? ORDER BY id DESC LIMIT 1",
                         (s['order_id'],)).fetchone()
        return jsonify({
            "status": "PAID", "order_id": s['order_id'], "session_id": s['session_id'],
            "amount": s['paid_amount'], "expected": s['amount'],
            "total_paid": s['total_paid'],
            "txn_id": s['txn_id'], "utr": s['utr'],
            "sender_name": txn['sender_name'] if txn else '',
            "sender_upi": txn['sender_upi'] if txn else '',
            "email_date": txn['email_date'] if txn else '',
            "verified": True
        })
    if s['status'] == 'PARTIAL':
        return jsonify({
            "status": "PARTIAL", "order_id": s['order_id'], "session_id": s['session_id'],
            "expected": s['amount'], "received": s['partial_amount'],
            "total_paid": s['total_paid'],
            "short_by": s['short_by'], "verified": False
        })

    return jsonify({
        "status": "PENDING", "order_id": s['order_id'], "session_id": s['session_id'],
        "seconds_left": int(max(0, s['expires_at']-time.time()))
    })

@app.route('/api/check-payment/<order_id>')
def check_payment(order_id):
    db = get_db()
    s = db.execute("SELECT * FROM qr_sessions WHERE order_id=?", (order_id,)).fetchone()
    if not s:
        return jsonify({"status": "NOTFOUND"}), 404

    if s['status'] == 'PAID':
        t = db.execute("SELECT * FROM transactions WHERE txn_id=?", (s['txn_id'],)).fetchone()
        return jsonify({"status": "PAID", "session_id": s['session_id'], "txn": {
            "txn_id": s['txn_id'], "utr": s['utr'],
            "amount": s['paid_amount'] or s['amount'],
            "total_paid": s['total_paid'] or s['amount'],
            "sender_name": t['sender_name'] if t else '',
            "sender_upi": t['sender_upi'] if t else '',
            "email_date": t['email_date'] if t else '',
            "order_id": s['order_id'],
            "session_id": s['session_id']
        }})

    if s['status'] == 'PARTIAL':
        return jsonify({"status": "PARTIAL", "session_id": s['session_id'],
            "expected": s['amount'], "received": s['partial_amount'],
            "total_paid": s['total_paid'] or s['partial_amount'],
            "short_by": s['short_by'],
            "message": f"⚠️ Short by ₹{s['short_by']:.2f}. Please pay ₹{s['short_by']:.2f} more."
        })

    if time.time() > s['expires_at']:
        if s['status'] != 'EXPIRED':
            db.execute("UPDATE qr_sessions SET status='EXPIRED' WHERE order_id=?", (order_id,))
            db.commit()
        return jsonify({"status": "EXPIRED", "session_id": s['session_id']})

    key_row = db.execute("SELECT * FROM api_keys WHERE api_key=?", (s['api_key'],)).fetchone()
    if not key_row:
        return jsonify({"status": "PENDING"})

    user = db.execute("SELECT tolerance FROM users WHERE username=?", (s['username'],)).fetchone()
    tol = (user['tolerance'] if user else 0) or 0
    ok, info, st = _verify_payment_for_session(s, key_row, tol)

    s = db.execute("SELECT * FROM qr_sessions WHERE order_id=?", (order_id,)).fetchone()
    if s['status'] == 'PAID':
        t = db.execute("SELECT * FROM transactions WHERE txn_id=?", (s['txn_id'],)).fetchone()
        return jsonify({"status": "PAID", "session_id": s['session_id'], "txn": {
            "txn_id": s['txn_id'], "utr": s['utr'],
            "amount": s['paid_amount'],
            "total_paid": s['total_paid'],
            "sender_name": t['sender_name'] if t else '',
            "sender_upi": t['sender_upi'] if t else '',
            "email_date": t['email_date'] if t else '',
            "order_id": s['order_id'],
            "session_id": s['session_id']
        }})
    if s['status'] == 'PARTIAL':
        return jsonify({"status": "PARTIAL", "session_id": s['session_id'],
            "expected": s['amount'], "received": s['partial_amount'],
            "total_paid": s['total_paid'],
            "short_by": s['short_by']
        })
    return jsonify({"status": "PENDING", "session_id": s['session_id']})

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
# SESSION RESULT HTML (auto-refreshes, works in TG webapp)
# ==========================================
SESSION_RESULT_HTML = """
<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Payment Result · {{ session_id }}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Inter',sans-serif}
body{background:radial-gradient(circle at 30% 20%,rgba(0,224,164,.18),transparent 45%),
radial-gradient(circle at 70% 80%,rgba(168,85,247,.18),transparent 45%),#05050a;
color:#e8e8f5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{width:100%;max-width:460px;background:rgba(15,15,30,.9);backdrop-filter:blur(20px);
border:1px solid rgba(0,255,179,.25);border-radius:24px;padding:32px 26px;
box-shadow:0 0 60px rgba(0,224,164,.25);text-align:center}
.tag{font-size:11px;color:#00e0a4;text-transform:uppercase;letter-spacing:3px;margin-bottom:8px;font-weight:700}
.sid{font-family:'Space Mono',monospace;font-size:12px;color:#7a7a9a;margin-bottom:20px;word-break:break-all;
padding:8px 12px;background:rgba(21,21,42,.8);border-radius:8px;border:1px solid #1f1f3a}
.status-icon{font-size:64px;margin:10px 0}
.status-title{font-size:26px;font-weight:900;margin-bottom:8px}
.status-title.paid{color:#00e0a4;text-shadow:0 0 30px rgba(0,224,164,.6)}
.status-title.pending{color:#ffa502}
.status-title.partial{color:#ffa502}
.status-title.expired{color:#ff4757}
.amount{font-size:44px;font-weight:900;margin:8px 0;
background:linear-gradient(90deg,#00ffb3,#00d4ff);background-size:200% 100%;
-webkit-background-clip:text;color:transparent;animation:rbow 3s linear infinite}
@keyframes rbow{to{background-position:200% 0}}
.msg{color:#7a7a9a;font-size:14px;margin-bottom:20px;line-height:1.6;padding:0 10px}
.details{background:rgba(21,21,42,.8);border:1px solid rgba(0,255,179,.2);border-radius:14px;
padding:18px;text-align:left;font-size:12px;font-family:'Space Mono',monospace}
.details div{display:flex;justify-content:space-between;margin-bottom:10px;color:#7a7a9a;gap:12px}
.details div:last-child{margin-bottom:0}
.details b{color:#e8e8f5;font-weight:700;text-align:right;word-break:break-all}
.details b.ok{color:#00e0a4}
.details b.warn{color:#ffa502}
.details b.err{color:#ff4757}
.refresh{margin-top:16px;font-size:11px;color:#3a3a5a;font-family:'Space Mono',monospace}
.brand{position:fixed;bottom:12px;right:16px;font-size:10px;color:#3a3a5a;letter-spacing:2px;font-family:'Space Mono',monospace}
</style></head><body>
<div class="card">
    <div class="tag">◆ Payment Session</div>
    <div class="sid">🔖 {{ session_id }}</div>
    
    {% if status == 'PAID' %}
        <div class="status-icon">✅</div>
        <div class="status-title paid">Payment Verified</div>
        <div class="amount">₹{{ "%.2f"|format(total_paid or paid or amount) }}</div>
        <div class="msg">Payment successfully verified from your Gmail account.</div>
    {% elif status == 'PARTIAL' %}
        <div class="status-icon">⚠️</div>
        <div class="status-title partial">Payment Incomplete</div>
        <div class="amount">₹{{ "%.2f"|format(total_paid) }} / ₹{{ "%.2f"|format(expected) }}</div>
        <div class="msg">You have paid ₹{{ "%.2f"|format(total_paid) }}. Please pay <b style="color:#ffa502">₹{{ "%.2f"|format(short_by) }}</b> more to complete verification.</div>
    {% elif status == 'EXPIRED' %}
        <div class="status-icon">⏱</div>
        <div class="status-title expired">Session Expired</div>
        <div class="msg">This payment session has expired. Please generate a new QR.</div>
    {% else %}
        <div class="status-icon">⏳</div>
        <div class="status-title pending">Waiting for Payment</div>
        <div class="amount">₹{{ "%.2f"|format(amount) }}</div>
        <div class="msg">Waiting for your payment to be detected...</div>
    {% endif %}
    
    <div class="details">
        <div><span>Session ID</span><b>{{ session_id }}</b></div>
        <div><span>Order ID</span><b>{{ order_id }}</b></div>
        <div><span>Expected</span><b>₹{{ "%.2f"|format(expected) }}</b></div>
        {% if total_paid > 0 %}
        <div><span>Total Paid</span><b class="ok">₹{{ "%.2f"|format(total_paid) }}</b></div>
        {% endif %}
        {% if status == 'PARTIAL' and short_by > 0 %}
        <div><span>Short By</span><b class="warn">₹{{ "%.2f"|format(short_by) }}</b></div>
        {% endif %}
        {% if txn_id %}
        <div><span>Transaction ID</span><b>{{ txn_id }}</b></div>
        {% endif %}
        {% if utr %}
        <div><span>UTR</span><b>{{ utr }}</b></div>
        {% endif %}
        {% if sender_name %}
        <div><span>Sender Name</span><b>{{ sender_name }}</b></div>
        {% endif %}
        {% if sender_upi %}
        <div><span>Sender UPI</span><b>{{ sender_upi }}</b></div>
        {% endif %}
        {% if email_date %}
        <div><span>Email Date</span><b>{{ email_date }}</b></div>
        {% endif %}
        <div><span>Status</span><b class="{% if status == 'PAID' %}ok{% elif status == 'PARTIAL' %}warn{% elif status == 'EXPIRED' %}err{% endif %}">{{ status }}</b></div>
    </div>
    
    {% if status not in ['PAID', 'EXPIRED'] %}
    <div class="refresh">🔄 Auto-refreshing every 3 seconds...</div>
    <script>setTimeout(()=>location.reload(), 3000);</script>
    {% endif %}
</div>
<div class="brand">FamPay AutoQR V{{ brand }}</div>
</body></html>
"""

# ==========================================
# QR PAGE V5 — WITH SESSION LINKS
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
.card{width:100%;max-width:460px;background:rgba(15,15,30,.85);backdrop-filter:blur(20px);
border:1px solid rgba(0,255,179,.2);border-radius:24px;padding:32px 26px;
box-shadow:0 0 60px rgba(0,224,164,.2),0 0 120px rgba(168,85,247,.15);
text-align:center;position:relative;overflow:hidden;animation:cardIn .6s cubic-bezier(.175,.885,.32,1.275)}
@keyframes cardIn{0%{transform:scale(.9);opacity:0}100%{transform:scale(1);opacity:1}}
.tag{font-size:12px;color:#00e0a4;text-transform:uppercase;letter-spacing:3px;margin-bottom:8px;font-weight:700;
text-shadow:0 0 20px rgba(0,255,179,.5)}
h1{font-size:48px;font-weight:900;margin:8px 0;
background:linear-gradient(90deg,#00ffb3,#a855f7,#ff00aa,#00d4ff);background-size:300% 100%;
-webkit-background-clip:text;color:transparent;animation:rbow 4s linear infinite;
filter:drop-shadow(0 0 20px rgba(0,255,179,.4))}
@keyframes rbow{to{background-position:300% 0}}
.sid-badge{display:inline-block;font-family:'Space Mono',monospace;font-size:10px;
padding:6px 12px;background:rgba(168,85,247,.15);border:1px solid rgba(168,85,247,.4);
border-radius:20px;color:#a855f7;margin-top:6px;letter-spacing:1px;word-break:break-all;max-width:100%}
.qr-wrap{background:#fff;border-radius:20px;padding:14px;display:inline-block;margin:18px 0;
box-shadow:0 0 60px rgba(0,224,164,.4),inset 0 0 20px rgba(0,0,0,.05);
position:relative;animation:qrPulse 3s ease-in-out infinite}
@keyframes qrPulse{0%,100%{box-shadow:0 0 60px rgba(0,224,164,.4)}50%{box-shadow:0 0 90px rgba(0,224,164,.7)}}
.qr-wrap img{display:block;width:230px;height:230px;border-radius:8px}
.logos{display:flex;justify-content:center;gap:8px;margin:16px 0;flex-wrap:wrap}
.logos span{background:rgba(255,255,255,.95);color:#000;padding:7px 12px;border-radius:9px;
font-weight:800;font-size:11px}
.timer{font-size:34px;font-weight:900;margin:12px 0;color:#00e0a4;
letter-spacing:2px;font-variant-numeric:tabular-nums;font-family:'Space Mono',monospace;
text-shadow:0 0 20px rgba(0,255,179,.5)}
.status{padding:16px;border-radius:14px;font-weight:700;font-size:14px;margin-top:10px}
.pending{background:rgba(255,165,2,.15);color:#ffa502;border:1px solid rgba(255,165,2,.3);
animation:pendingPulse 2s ease-in-out infinite}
@keyframes pendingPulse{0%,100%{box-shadow:0 0 0 0 rgba(255,165,2,.4)}50%{box-shadow:0 0 0 10px rgba(255,165,2,0)}}
.expired{background:rgba(255,71,87,.15);color:#ff4757;border:1px solid rgba(255,71,87,.3)}
.success-overlay{position:absolute;inset:0;background:rgba(15,15,30,.98);backdrop-filter:blur(30px);
border-radius:24px;display:none;flex-direction:column;align-items:center;justify-content:flex-start;
padding:32px 26px;z-index:10;opacity:0;transition:.5s;overflow-y:auto}
.success-overlay.show{display:flex;opacity:1}
.check-icon{width:100px;height:100px;border-radius:50%;
background:radial-gradient(circle,rgba(0,224,164,.3),rgba(0,224,164,.05));
border:3px solid #00e0a4;display:flex;align-items:center;justify-content:center;
font-size:50px;margin-bottom:22px;flex-shrink:0;
box-shadow:0 0 40px rgba(0,224,164,.7),inset 0 0 20px rgba(0,224,164,.3);
animation:popIn .6s cubic-bezier(.175,.885,.32,1.275)}
@keyframes popIn{0%{transform:scale(0) rotate(-180deg)}100%{transform:scale(1) rotate(0)}}
.success-title{font-size:28px;font-weight:900;color:#00e0a4;margin-bottom:8px;
text-shadow:0 0 30px rgba(0,224,164,.5)}
.success-amt{font-size:46px;font-weight:900;
background:linear-gradient(90deg,#00ffb3,#00d4ff);background-size:200% 100%;
-webkit-background-clip:text;color:transparent;margin-bottom:22px;
animation:rbow 3s linear infinite}
.success-details{background:rgba(21,21,42,.8);backdrop-filter:blur(10px);
border:1px solid rgba(0,255,179,.25);border-radius:14px;padding:18px;width:100%;
text-align:left;font-size:12px;font-family:'Space Mono',monospace;margin-bottom:16px}
.success-details div{display:flex;justify-content:space-between;margin-bottom:10px;color:#7a7a9a;gap:12px}
.success-details div:last-child{margin-bottom:0}
.success-details b{color:#e8e8f5;font-weight:700;text-align:right;word-break:break-all}
.success-details .ok{color:#00e0a4}

/* SESSION LINKS BOX - V5 NEW */
.session-links{width:100%;margin-top:16px;animation:linksIn .6s .3s both}
@keyframes linksIn{0%{opacity:0;transform:translateY(20px)}100%{opacity:1;transform:translateY(0)}}
.links-title{font-size:11px;color:#7a7a9a;text-transform:uppercase;letter-spacing:2px;
margin-bottom:10px;text-align:left;font-weight:700}
.link-item{display:flex;align-items:center;gap:10px;background:rgba(21,21,42,.8);
border:1px solid rgba(0,255,179,.25);border-radius:12px;padding:12px 14px;margin-bottom:8px;
transition:.2s;cursor:pointer;text-align:left}
.link-item:hover{border-color:#00e0a4;box-shadow:0 0 20px rgba(0,224,164,.3);transform:translateX(3px)}
.link-item .ic{font-size:20px;flex-shrink:0}
.link-item .info{flex:1;min-width:0}
.link-item .lbl{font-size:12px;font-weight:700;color:#e8e8f5;margin-bottom:2px}
.link-item .url{font-size:10px;color:#00e0a4;font-family:'Space Mono',monospace;
overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.link-item .arrow{color:#7a7a9a;font-size:14px}

.partial-overlay{position:absolute;inset:0;background:rgba(15,15,30,.98);backdrop-filter:blur(30px);
border-radius:24px;display:none;flex-direction:column;align-items:center;justify-content:flex-start;
padding:32px 26px;z-index:10;opacity:0;transition:.5s;overflow-y:auto}
.partial-overlay.show{display:flex;opacity:1}
.warn-icon{width:100px;height:100px;border-radius:50%;flex-shrink:0;
background:radial-gradient(circle,rgba(255,165,2,.3),rgba(255,165,2,.05));
border:3px solid #ffa502;display:flex;align-items:center;justify-content:center;
font-size:50px;margin-bottom:22px;box-shadow:0 0 40px rgba(255,165,2,.7)}
.warn-title{font-size:26px;font-weight:900;color:#ffa502;margin-bottom:8px;
text-shadow:0 0 30px rgba(255,165,2,.5)}
.warn-msg{color:#e8e8f5;font-size:14px;margin-bottom:18px;text-align:center;line-height:1.6}
.warn-msg b{color:#ffa502;font-size:16px}
.warn-details{background:rgba(21,21,42,.8);backdrop-filter:blur(10px);
border:1px solid rgba(255,165,2,.25);border-radius:14px;padding:18px;width:100%;
font-size:13px;margin-bottom:18px;font-family:'Space Mono',monospace}
.warn-details div{display:flex;justify-content:space-between;margin-bottom:10px}
.warn-details div:last-child{margin-bottom:0}
.warn-details b{color:#ffa502}
.qr-still-valid{background:rgba(0,224,164,.1);border:1px solid rgba(0,224,164,.3);
padding:10px;border-radius:10px;font-size:12px;color:#00e0a4;margin-top:14px;text-align:center}
.brand{position:fixed;bottom:12px;right:16px;font-size:10px;color:#3a3a5a;letter-spacing:2px;
font-family:'Space Mono',monospace}
</style></head><body>
<div class="card" id="mainCard">
    <div class="tag">◆ Pay via UPI</div>
    <h1>₹{{ "%.2f"|format(amount) }}</h1>
    <div style="font-size:12px;color:#7a7a9a;margin-top:4px">to <b style="color:#e8e8f5">{{ full_name }}</b> · {{ upi_id }}</div>
    <div class="sid-badge">🔖 {{ session_id }}</div>
    <div class="qr-wrap" id="qrWrap"><img src="{{ qr_b64 }}" alt="QR"></div>
    <div class="logos"><span>GPay</span><span>PhonePe</span><span>Paytm</span><span>UPI</span><span>BHIM</span></div>
    <div class="timer" id="timer">{{ '%02d:00'|format(minutes) }}</div>
    <div class="status pending" id="status">⏳ Waiting for payment of ₹{{ "%.2f"|format(amount) }}...</div>

    <!-- SUCCESS OVERLAY -->
    <div class="success-overlay" id="successOverlay">
        <div class="check-icon">✅</div>
        <div class="success-title">Payment Verified</div>
        <div class="success-amt" id="successAmt">₹{{ amount }}</div>
        <div class="success-details">
            <div><span>Amount</span><b id="dtAmount">-</b></div>
            <div><span>Transaction ID</span><b id="dtTxn">-</b></div>
            <div><span>UTR</span><b id="dtUtr">-</b></div>
            <div><span>Sender</span><b id="dtSender">-</b></div>
            <div><span>Date</span><b id="dtDate">-</b></div>
            <div><span>Status</span><b class="ok">Verified ✅</b></div>
        </div>
        
        <div class="session-links">
            <div class="links-title">◆ Session Links</div>
            <a class="link-item" id="tgLink" href="#" target="_blank">
                <div class="ic">📱</div>
                <div class="info">
                    <div class="lbl">Telegram Bot Result</div>
                    <div class="url" id="tgUrl">Loading...</div>
                </div>
                <div class="arrow">↗</div>
            </a>
            <a class="link-item" id="webLink" href="{{ session_url }}" target="_blank">
                <div class="ic">🌐</div>
                <div class="info">
                    <div class="lbl">Website / App Result</div>
                    <div class="url" id="webUrl">{{ session_url }}</div>
                </div>
                <div class="arrow">↗</div>
            </a>
            <a class="link-item" id="jsonLink" href="{{ session_url }}?format=json" target="_blank">
                <div class="ic">📋</div>
                <div class="info">
                    <div class="lbl">JSON Result (API)</div>
                    <div class="url">{{ session_url }}?format=json</div>
                </div>
                <div class="arrow">↗</div>
            </a>
        </div>
    </div>

    <!-- PARTIAL OVERLAY -->
    <div class="partial-overlay" id="partialOverlay">
        <div class="warn-icon">⚠️</div>
        <div class="warn-title">Payment Incomplete</div>
        <div class="warn-msg" id="partialMsg">You paid less than required.</div>
        <div class="warn-details">
            <div><span>Expected</span><b>₹{{ "%.2f"|format(amount) }}</b></div>
            <div><span>Total Paid</span><b id="partialTotal">₹0.00</b></div>
            <div><span>Remaining</span><b id="partialShort">₹0.00</b></div>
            <div><span>Txn ID</span><b id="partialTxn" style="color:#e8e8f5">-</b></div>
        </div>
        <div class="qr-still-valid">✅ QR is still valid. Pay remaining amount to complete verification.</div>
    </div>
</div>
<div class="brand">FamPay AutoQR V{{ brand }}</div>
<script>
const orderId="{{ order_id }}", sessionId="{{ session_id }}", totalSecs={{ minutes*60 }}, expectedAmt={{ amount }};
let secs=totalSecs, tInt, pInt;
const T=document.getElementById('timer'), S=document.getElementById('status');
function tick(){
    secs--;
    if(secs<=0){
        T.textContent='00:00'; T.style.color='#ff4757';
        S.textContent='❌ QR Expired'; S.className='status expired';
        clearInterval(tInt); clearInterval(pInt); return;
    }
    const m=String(Math.floor(secs/60)).padStart(2,'0'), s=String(secs%60).padStart(2,'0');
    T.textContent=m+':'+s; if(secs<=60) T.style.color='#ff4757';
}
let partialShown = false;
async function poll(){
    try{
        const r=await fetch('/api/check-payment/'+orderId), d=await r.json();
        if(d.status==='PAID'){
            document.getElementById('successAmt').textContent = '₹' + (d.txn.amount||expectedAmt).toFixed(2);
            document.getElementById('dtAmount').textContent = '₹' + (d.txn.amount||expectedAmt).toFixed(2);
            document.getElementById('dtTxn').textContent = d.txn.txn_id || '-';
            document.getElementById('dtUtr').textContent = d.txn.utr || '-';
            document.getElementById('dtSender').textContent = (d.txn.sender_name || '') + ' ' + (d.txn.sender_upi || '');
            document.getElementById('dtDate').textContent = d.txn.email_date || new Date().toLocaleString('en-IN') + ' IST';
            
            // Setup Telegram link - opens session result JSON
            const sessUrl = window.location.origin + '/result/' + sessionId;
            document.getElementById('tgUrl').textContent = 'Open in Telegram → ' + sessionId;
            document.getElementById('tgLink').href = sessUrl + '?format=json';
            document.getElementById('webUrl').textContent = sessUrl;
            document.getElementById('webLink').href = sessUrl;
            
            document.getElementById('successOverlay').classList.add('show');
            clearInterval(tInt); clearInterval(pInt);
        }
        else if(d.status==='PARTIAL' && !partialShown){
            partialShown = true;
            document.getElementById('partialTotal').textContent = '₹' + (d.total_paid||d.received||0).toFixed(2);
            document.getElementById('partialShort').textContent = '₹' + (d.short_by||0).toFixed(2);
            document.getElementById('partialMsg').innerHTML = d.message || 'Payment incomplete.';
            document.getElementById('partialTxn').textContent = d.txn_id || '-';
            document.getElementById('partialOverlay').classList.add('show');
            // Re-show QR after 6 sec
            setTimeout(()=>{document.getElementById('partialOverlay').classList.remove('show'); partialShown = false;}, 6000);
        }
        else if(d.status==='EXPIRED'){
            S.textContent='❌ QR Expired'; S.className='status expired';
            clearInterval(tInt); clearInterval(pInt);
        }
    }catch(e){}
}
tInt=setInterval(tick,1000); pInt=setInterval(poll,1500); poll();
</script></body></html>
"""

@app.route('/')
def home(): return render_template_string(MAIN_HTML)

@app.route('/health')
def health(): return jsonify({"status":"ok", "version":APP_VERSION, "time": time.time()})

# ==========================================
# MAIN DASHBOARD (abbreviated - keep existing from V4 but add Telegram/Website links)
# ==========================================
MAIN_HTML = r"""
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FamPay AutoQR V5.0 ULTRA</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{--bg:#05050a;--surface:#0f0f1e;--surface2:#15152a;--border:#1f1f3a;--text:#e8e8f5;--dim:#7a7a9a;
--ng:#00ffb3;--nc:#00d4ff;--np:#a855f7;--npink:#ff00aa;--nwarn:#ffa502;--dang:#ff4757;--ok:#00e0a4;}
[data-theme="light"]{--bg:#f5f7fa;--surface:#ffffff;--surface2:#f0f2f7;--border:#e0e4ec;--text:#0f0f1e;--dim:#6a6a8a}
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
border:1px solid rgba(0,255,179,.2);border-radius:24px;padding:34px 28px;
box-shadow:0 0 60px rgba(0,255,179,.2);position:relative;overflow:hidden;animation:cardIn .6s}
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
.field input:focus{border-color:var(--ng);box-shadow:0 0 0 3px rgba(0,255,179,.15)}
.btn{width:100%;padding:13px;border:none;border-radius:10px;font-weight:800;font-size:14px;
background:linear-gradient(90deg,var(--ng),var(--nc),var(--np));color:#05050a;
transition:.2s;cursor:pointer;background-size:200% 100%;position:relative;overflow:hidden}
.btn:hover{transform:translateY(-2px);box-shadow:0 0 30px rgba(0,255,179,.6);background-position:100% 0}
.btn.sec{background:var(--surface2);color:var(--text);border:1px solid var(--border)}
.btn.dang{background:linear-gradient(90deg,var(--dang),var(--npink))}
.switch{text-align:center;margin-top:14px;font-size:13px;color:var(--dim)}
.switch a{color:var(--ng);font-weight:700;cursor:pointer}
.shell{display:flex;min-height:100vh}
.sidebar{width:260px;background:rgba(15,15,30,.85);backdrop-filter:blur(20px);
border-right:1px solid var(--border);padding:22px 14px;position:fixed;inset:0 auto 0 0;overflow-y:auto;z-index:50;transition:transform .3s}
.brand{font-size:17px;font-weight:900;padding:0 8px 20px;
background:linear-gradient(90deg,var(--ng),var(--np),var(--npink));background-size:200%;
-webkit-background-clip:text;color:transparent;animation:rbow 3s infinite linear}
.nav{display:flex;flex-direction:column;gap:3px}
.item{padding:11px 14px;border-radius:10px;color:var(--dim);font-size:13px;font-weight:600;
display:flex;align-items:center;gap:10px;cursor:pointer;transition:.15s}
.item:hover{background:var(--surface2);color:var(--text);transform:translateX(3px)}
.item.active{background:linear-gradient(90deg,rgba(0,255,179,.18),rgba(168,85,247,.08));
color:var(--ng);box-shadow:inset 0 0 20px rgba(0,255,179,.15)}
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
box-shadow:0 0 60px rgba(0,255,179,.2)}
.hero-amt{font-size:52px;font-weight:900;margin:8px 0;
background:linear-gradient(90deg,var(--ng),var(--np),var(--npink));background-size:200% 100%;
-webkit-background-clip:text;color:transparent;filter:drop-shadow(0 0 20px rgba(255,0,170,.5));
animation:rbow 4s linear infinite}
.hero-lbl{font-size:11px;font-weight:800;color:var(--dim);text-transform:uppercase;letter-spacing:2px}
.hero-sub{font-size:13px;color:var(--dim)}.hero-sub b{color:var(--text)}
.stat{background:rgba(21,21,42,.7);border:1px solid var(--border);border-radius:14px;padding:16px;transition:.3s}
.stat:hover{transform:translateY(-3px);border-color:var(--ng);box-shadow:0 0 25px rgba(0,255,179,.3)}
.stat-lbl{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;font-weight:700}
.stat-val{font-size:24px;font-weight:800;margin-top:4px;color:var(--ng);text-shadow:0 0 15px rgba(0,255,179,.4)}
.stat.alt .stat-val{color:var(--np)}.stat.alt2 .stat-val{color:var(--npink)}
.stat.warn .stat-val{color:var(--nwarn)}
.chart-box{position:relative;height:260px;margin-top:8px}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
@media(max-width:600px){.form-grid{grid-template-columns:1fr}}
.fg{display:flex;flex-direction:column;gap:6px}
.fg label{font-size:11px;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
.fg input,.fg select,.fg textarea{padding:11px 14px;background:var(--surface2);
border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:14px;transition:.2s}
.fg input:focus,.fg select:focus,.fg textarea:focus{border-color:var(--ng);box-shadow:0 0 0 3px rgba(0,255,179,.15)}
.fg small{font-size:10px;color:var(--dim);margin-top:-2px}
.api-out{background:rgba(2,2,10,.8);border:1px dashed rgba(0,255,179,.5);padding:12px;
border-radius:10px;color:var(--ng);font-family:'Space Mono',monospace;font-size:11px;
word-break:break-all;margin-top:8px;display:flex;justify-content:space-between;align-items:center;gap:8px}
.copy{background:var(--surface2);border:1px solid var(--border);color:var(--text);
padding:5px 9px;border-radius:6px;font-size:10px;font-weight:700;flex-shrink:0;cursor:pointer;transition:.2s}
.copy:hover{background:var(--ng);color:#05050a;border-color:var(--ng)}
.txn{display:flex;justify-content:space-between;align-items:flex-start;padding:14px;
background:rgba(21,21,42,.7);border-radius:10px;margin-bottom:8px;font-size:13px;
border-left:3px solid var(--ok)}
.txn.partial{border-left-color:var(--nwarn)}
.txn .amt{color:var(--ok);font-weight:800;font-size:15px}
.txn.partial .amt{color:var(--nwarn)}
.txn .meta{font-size:11px;color:var(--dim);margin-top:3px;font-family:'Space Mono',monospace}
.txn .sess{font-size:10px;color:var(--np);font-family:'Space Mono',monospace;margin-top:2px;word-break:break-all}
#toast{position:fixed;bottom:20px;right:20px;padding:14px 20px;border-radius:12px;
background:rgba(21,21,42,.95);color:var(--text);font-size:13px;font-weight:600;
border-left:3px solid var(--ng);box-shadow:0 0 30px rgba(0,255,179,.4);
transform:translateY(100px);opacity:0;transition:.3s;z-index:1000;max-width:340px}
#toast.show{transform:translateY(0);opacity:1}
#toast.err{border-left-color:var(--dang)}
.empty{text-align:center;padding:36px 20px;color:var(--dim);font-size:13px}
.empty-ic{font-size:36px;opacity:.4;margin-bottom:8px}
.badge{display:inline-block;padding:3px 8px;border-radius:6px;font-size:10px;font-weight:800;text-transform:uppercase}
.badge.life{background:rgba(168,85,247,.2);color:var(--np)}
.badge.ok{background:rgba(0,224,164,.2);color:var(--ok)}
.uptime{font-family:'Space Mono',monospace;font-size:11px;color:var(--dim);padding:6px 12px;
background:rgba(21,21,42,.8);border-radius:20px;border:1px solid var(--border)}
.uptime b{color:var(--ng)}
.period-tab{display:flex;gap:6px;margin-bottom:14px}
.tab{flex:1;text-align:center;padding:8px 14px;background:var(--surface2);border:1px solid var(--border);
border-radius:8px;font-size:12px;font-weight:600;color:var(--dim);cursor:pointer;transition:.2s}
.tab.active{background:linear-gradient(90deg,var(--ng),var(--nc));color:#05050a;border-color:var(--ng);box-shadow:0 0 20px rgba(0,255,179,.5)}
pre{background:#02020a;color:#00ffb3;padding:14px;border-radius:10px;font-size:11px;overflow-x:auto;margin-top:8px}
h3{font-size:13px;margin:14px 0 8px;color:var(--ng)}
</style></head><body>

<div id="authScreen" class="auth-wrap">
  <div class="auth-card">
    <div class="logo">◆ FamPay AutoQR V5.0</div>
    <div class="logo-sub">Ultra Session Edition · Multi-Payment · Universal Links</div>
    <div id="loginForm">
      <div class="field"><label>Username</label><input id="lgU" placeholder="admin"></div>
      <div class="field"><label>Password</label><input id="lgP" type="password"></div>
      <button class="btn" onclick="doLogin()">⚡ Login →</button>
      <div class="switch">New? <a onclick="toggleAuth('reg')">Create account</a></div>
    </div>
    <div id="regForm" class="hidden">
      <div class="field"><label>Username</label><input id="rgU"></div>
      <div class="field"><label>Password</label><input id="rgP" type="password"></div>
      <div class="field"><label>Email</label><input id="rgE" type="email"></div>
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
        <div class="tab active" onclick="setPeriod('today',this)">Today</div>
        <div class="tab" onclick="setPeriod('week',this)">Week</div>
        <div class="tab" onclick="setPeriod('month',this)">Month</div>
        <div class="tab" onclick="setPeriod('year',this)">Year</div>
      </div>
      <div class="grid-2">
        <div class="stat"><div class="stat-lbl">Amount</div><div class="stat-val" id="anAmount">₹0</div></div>
        <div class="stat alt"><div class="stat-lbl">Count</div><div class="stat-val" id="anCount">0</div></div>
      </div>
      <div class="card" style="margin-top:16px"><h2>📅 Monthly</h2><div class="chart-box"><canvas id="monthChart"></canvas></div></div>
    </section>

    <section id="p-account" class="page hidden">
      <div class="card">
        <h2>👤 Account Details</h2>
        <div class="form-grid">
          <div class="fg"><label>Full Name</label><input id="acName"></div>
          <div class="fg"><label>UPI ID</label><input id="acUpi"></div>
        </div>
        <div class="form-grid">
          <div class="fg"><label>Mobile</label><input id="acMob"></div>
          <div class="fg"><label>Gmail</label><input id="acEmail"></div>
        </div>
        <div class="form-grid">
          <div class="fg"><label>Gmail App Password</label><input id="acPass" type="password" placeholder="Leave blank to keep"></div>
          <div class="fg"><label>QR Minutes</label><input id="acMin" type="number" value="15"></div>
        </div>
        <div class="form-grid">
          <div class="fg"><label>Tolerance (₹)</label><input id="acTol" type="number" step="0.01" value="0"></div>
          <div class="fg"><label>Webhook</label><input id="acHook" placeholder="https://..."></div>
        </div>
        <div class="form-grid">
          <div class="fg"><label>📱 Telegram Bot Link</label><input id="acTgLink" placeholder="https://t.me/YourBot"><small>Optional - shown on success page</small></div>
          <div class="fg"><label>🌐 Website Link</label><input id="acWebLink" placeholder="https://yoursite.com"><small>Optional - shown on success page</small></div>
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
          <div class="fg"><label>Label</label><input id="keyLabel"></div>
          <div class="fg"><label>Mode</label>
            <select id="keyMode" onchange="toggleMode()">
              <option value="days">Days</option><option value="lifetime">Lifetime</option>
            </select></div>
        </div>
        <div class="form-grid">
          <div class="fg" id="daysWrap"><label>Days</label><input id="keyDays" type="number" value="30"></div>
          <div class="fg"><label>Rate Limit</label><input id="keyRate" type="number" value="60"></div>
        </div>
        <button class="btn" onclick="genKey()">🚀 Generate</button>
        <div id="keyRes" style="margin-top:12px"></div>
      </div>
      <div class="card"><h2>📋 Keys</h2><div id="keysList"></div></div>
    </section>

    <section id="p-history" class="page hidden">
      <div class="card"><h2>📜 Transactions</h2><div id="txnList"></div></div>
    </section>

    <section id="p-partials" class="page hidden">
      <div class="card"><h2>⚠️ Partial Payments</h2><div id="partialList"></div></div>
    </section>

    <section id="p-audit" class="page hidden">
      <div class="card"><h2>🔍 Audit Log</h2><div id="auditList"></div></div>
    </section>

    <section id="p-docs" class="page hidden">
      <div class="card">
        <h2>📖 API Documentation V5</h2>
        <h3>1. Generate QR</h3>
        <div class="api-out"><span>GET /v2/fam/YOUR_KEY?qr=100</span></div>
        <p style="font-size:12px;color:var(--dim);margin-top:6px">Returns HTML with QR + Session ID + Result links</p>

        <h3>2. Check Session (NEW)</h3>
        <div class="api-out"><span>GET /api/v2/check/YOUR_KEY?session_id=SESSION_ID</span></div>

        <h3>3. Result JSON (NEW)</h3>
        <div class="api-out"><span>GET /result/SESSION_ID?format=json</span></div>

        <h3>4. Response Format</h3>
        <pre>{
  "session_id": "Jwowbsiajjaj1919199",
  "order_id": "ORD17300000001234",
  "status": "PAID",
  "expected": 10.0,
  "paid": 10.0,
  "total_paid": 10.0,
  "short_by": 0,
  "txn_id": "FMPIB6930608000",
  "utr": "667524755400",
  "sender_name": "mal",
  "sender_upi": "mal.628@superyes",
  "email_date": "10:54 AM IST, 05 November 2026",
  "verified": true,
  "message": "✅ Payment verified!"
}</pre>

        <h3>5. Telegram Bot (Python)</h3>
        <pre>import requests
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

API_KEY = "YOUR_API_KEY"
BASE = "https://yourdomain.com"

async def qr(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    amount = ctx.args[0] if ctx.args else "100"
    url = f"{BASE}/v2/fam/{API_KEY}?qr={amount}"
    await update.message.reply_text(f"💳 Pay ₹{amount}: {url}")

async def check(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    sid = ctx.args[0] if ctx.args else ""
    r = requests.get(f"{BASE}/result/{sid}?format=json").json()
    if r.get('status') == 'PAID':
        await update.message.reply_text(
            f"✅ Payment Verified!\n"
            f"Amount: ₹{r['paid']}\n"
            f"Session: {r['session_id']}\n"
            f"Txn: {r['txn_id']}\n"
            f"UTR: {r['utr']}\n"
            f"Sender: {r.get('sender_upi','')}"
        )
    elif r.get('status') == 'PARTIAL':
        await update.message.reply_text(
            f"⚠️ Partial Payment\n"
            f"Paid: ₹{r['total_paid']}\n"
            f"Short by: ₹{r['short_by']}\n"
            f"Please pay ₹{r['short_by']} more"
        )
    else:
        await update.message.reply_text(f"Status: {r.get('status')}")

app = Application.builder().token("BOT_TOKEN").build()
app.add_handler(CommandHandler("qr", qr))
app.add_handler(CommandHandler("check", check))
app.run_polling()</pre>

        <h3>6. Telegram Bot (Node.js)</h3>
        <pre>const TelegramBot = require('node-telegram-bot-api');
const axios = require('axios');
const BOT_TOKEN = 'YOUR_BOT_TOKEN';
const API_KEY = 'YOUR_API_KEY';
const BASE = 'https://yourdomain.com';

const bot = new TelegramBot(BOT_TOKEN, { polling: true });

bot.onText(/\/qr (.+)/, async (msg, match) => {
  const url = `${BASE}/v2/fam/${API_KEY}?qr=${match[1]}`;
  bot.sendMessage(msg.chat.id, `💳 Pay ₹${match[1]}:\n${url}`);
});

bot.onText(/\/check (.+)/, async (msg, match) => {
  const { data } = await axios.get(`${BASE}/result/${match[1]}?format=json`);
  if (data.status === 'PAID') {
    bot.sendMessage(msg.chat.id, `✅ Verified! ₹${data.paid}\nSession: ${data.session_id}`);
  } else {
    bot.sendMessage(msg.chat.id, `Status: ${data.status}`);
  }
});</pre>

        <h3>7. Website (HTML+JS)</h3>
        <pre>&lt;iframe src="https://yourdomain.com/v2/fam/YOUR_KEY?qr=100"
        width="460" height="900"&gt;&lt;/iframe&gt;

&lt;script&gt;
setInterval(async () => {
  const r = await fetch('/api/v2/check/YOUR_KEY').then(r=>r.json());
  if (r.status === 'PAID') alert('Paid ₹' + r.paid);
}, 1500);
&lt;/script&gt;</pre>
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

function toggleAuth(m){document.getElementById('loginForm').classList.toggle('hidden',m!=='login');document.getElementById('regForm').classList.toggle('hidden',m!=='reg');}
async function doLogin(){try{const u=document.getElementById('lgU').value.trim(),p=document.getElementById('lgP').value;if(!u||!p)return toast('Fill fields',true);await api('/api/login',{method:'POST',body:JSON.stringify({username:u,password:p})});toast('✅ Logged in');bootApp();}catch(e){toast('❌ '+e.message,true)}}
async function doReg(){try{const u=document.getElementById('rgU').value.trim(),p=document.getElementById('rgP').value,em=document.getElementById('rgE').value.trim();if(!u||!p)return toast('Fill fields',true);await api('/api/register',{method:'POST',body:JSON.stringify({username:u,password:p,email:em})});toast('✅ Created');toggleAuth('login');}catch(e){toast('❌ '+e.message,true)}}
async function doLogout(){if(!confirm('Logout?'))return;await api('/api/logout',{method:'POST'});location.reload();}

function go(p){
  document.querySelectorAll('.page').forEach(x=>x.classList.add('hidden'));
  document.getElementById('p-'+p).classList.remove('hidden');
  document.querySelectorAll('.item').forEach(i=>i.classList.toggle('active',i.dataset.p===p));
  const titles={dashboard:'Dashboard',analytics:'Analytics',account:'Account',keys:'API Keys',history:'Transactions',partials:'Partial',audit:'Audit',docs:'API Docs'};
  document.getElementById('title').textContent=titles[p]||p;
  document.getElementById('sidebar').classList.remove('open');
  if(p==='keys')loadKeys();
  if(p==='history')loadHistory();
  if(p==='partials')loadPartials();
  if(p==='audit')loadAudit();
  if(p==='analytics')loadAnalytics();
}

let chart7Obj=null, monthObj=null, currentPeriod='today';

async function bootApp(){
  try{
    const me=await api('/api/me');
    document.getElementById('authScreen').classList.add('hidden');
    document.getElementById('shell').classList.remove('hidden');
    document.getElementById('chipUser').textContent=me.username;
    document.getElementById('emailDot').className='dot '+(me.email_status==='online'?'on':me.email_status==='offline'?'off':'unk');
    fillAccount(me); loadDashboard(); loadUptime();
  }catch(e){location.reload();}
}

async function loadUptime(){
  try{const d=await fetch('/api/uptime').then(r=>r.json());
    document.getElementById('uptime').innerHTML='⏱ <b>'+d.human+'</b>';
  }catch(e){}
}
setInterval(loadUptime,1000);

function fillAccount(me){
  document.getElementById('acName').value=me.full_name||'';
  document.getElementById('acUpi').value=me.upi_id||'';
  document.getElementById('acMob').value=me.mobile||'';
  document.getElementById('acEmail').value=me.email||'';
  document.getElementById('acMin').value=me.default_qr_minutes||15;
  document.getElementById('acTol').value=me.tolerance||0;
  document.getElementById('acHook').value=me.webhook_url||'';
  document.getElementById('acTgLink').value=me.telegram_bot_link||'';
  document.getElementById('acWebLink').value=me.website_link||'';
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
    const an=await api('/api/analytics');
    document.getElementById('stToday').textContent='₹'+an.today.amount.toFixed(0);
    const ctx=document.getElementById('chart7').getContext('2d');
    if(chart7Obj)chart7Obj.destroy();
    chart7Obj=new Chart(ctx,{type:'bar',data:{labels:an.days_7.map(x=>x.day),
      datasets:[{data:an.days_7.map(x=>x.amount),backgroundColor:'rgba(0,255,179,.6)',
        borderColor:'#00ffb3',borderWidth:2,borderRadius:8}]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
        scales:{y:{beginAtZero:true,ticks:{color:'#7a7a9a'},grid:{color:'rgba(31,31,58,.5)'}},
          x:{ticks:{color:'#7a7a9a'},grid:{display:false}}}}});
  }catch(e){toast('❌ '+e.message,true)}
}

async function loadAnalytics(){
  try{
    const an=await api('/api/analytics');
    const period=an[currentPeriod];
    document.getElementById('anAmount').textContent='₹'+period.amount.toFixed(2);
    document.getElementById('anCount').textContent=period.count;
    const ctx=document.getElementById('monthChart').getContext('2d');
    if(monthObj)monthObj.destroy();
    monthObj=new Chart(ctx,{type:'line',data:{labels:an.months_12.map(x=>x.month),
      datasets:[{data:an.months_12.map(x=>x.amount),borderColor:'#a855f7',
        backgroundColor:'rgba(168,85,247,.2)',borderWidth:3,fill:true,tension:.4}]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
        scales:{y:{beginAtZero:true,ticks:{color:'#7a7a9a'},grid:{color:'rgba(31,31,58,.5)'}},
          x:{ticks:{color:'#7a7a9a'},grid:{display:false}}}}});
  }catch(e){toast('❌ '+e.message,true)}
}
function setPeriod(p,el){currentPeriod=p;document.querySelectorAll('.period-tab .tab').forEach(t=>t.classList.remove('active'));el.classList.add('active');loadAnalytics();}

async function saveAccount(){
  try{
    const payload={
      full_name:document.getElementById('acName').value.trim(),
      upi_id:document.getElementById('acUpi').value.trim(),
      mobile:document.getElementById('acMob').value.trim(),
      email:document.getElementById('acEmail').value.trim(),
      app_password:document.getElementById('acPass').value.trim()||'',
      default_qr_minutes:parseInt(document.getElementById('acMin').value)||15,
      tolerance:parseFloat(document.getElementById('acTol').value)||0,
      webhook_url:document.getElementById('acHook').value.trim(),
      telegram_bot_link:document.getElementById('acTgLink').value.trim(),
      website_link:document.getElementById('acWebLink').value.trim()
    };
    if(!payload.upi_id)return toast('UPI required',true);
    await api('/api/setup-account',{method:'POST',body:JSON.stringify(payload)});
    toast('✅ Saved');document.getElementById('acPass').value='';bootApp();
  }catch(e){toast('❌ '+e.message,true)}
}
async function testEmail(){
  try{
    document.getElementById('testRes').innerHTML='<div style="color:var(--nwarn)">⏳ Testing…</div>';
    const d=await api('/api/test-email',{method:'POST',body:JSON.stringify({
      email:document.getElementById('acEmail').value,
      app_password:document.getElementById('acPass').value})});
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
    const d=await api('/api/generate-key',{method:'POST',body:JSON.stringify({
      mode:document.getElementById('keyMode').value,
      days:parseInt(document.getElementById('keyDays').value)||30,
      rate_limit:parseInt(document.getElementById('keyRate').value)||60,
      label:document.getElementById('keyLabel').value})});
    document.getElementById('keyRes').innerHTML=`<div style="background:rgba(0,255,179,.08);border:1px solid rgba(0,255,179,.4);padding:14px;border-radius:10px">
      <div style="color:var(--ng);font-weight:700;margin-bottom:6px">✅ Generated</div>
      <div class="api-out"><span>${esc(d.example)}</span><button class="copy" onclick="copyText('${esc(d.example)}')">Copy</button></div>
    </div>`;
    loadKeys();
  }catch(e){toast('❌ '+e.message,true)}
}
async function loadKeys(){
  try{
    const list=await api('/api/list-keys'),el=document.getElementById('keysList');
    if(!list.length){el.innerHTML='<div class="empty"><div class="empty-ic">🔑</div>No keys</div>';return}
    el.innerHTML=list.map(k=>`<div class="txn" style="flex-direction:column;align-items:stretch;gap:8px">
      <div style="display:flex;justify-content:space-between"><b style="font-family:monospace;font-size:12px">${esc(k.api_key)}</b>
      <button class="copy" style="background:rgba(255,71,87,.15);color:var(--dang)" onclick="delKey('${esc(k.api_key)}')">Delete</button></div>
      <div class="meta">Requests: ${k.total_requests} · QRs: ${k.total_qr} · Received: ₹${k.total_received}</div>
      <div class="api-out"><span>${esc(k.url)}</span><button class="copy" onclick="copyText('${esc(k.url)}')">Copy</button></div>
    </div>`).join('');
  }catch(e){toast('❌ '+e.message,true)}
}
async function delKey(k){if(!confirm('Delete?'))return;try{await api('/api/delete-key/'+k,{method:'DELETE'});toast('Deleted');loadKeys()}catch(e){toast('❌ '+e.message,true)}}

async function loadHistory(){
  try{
    const txns=await api('/api/transactions'),el=document.getElementById('txnList');
    if(!txns.length){el.innerHTML='<div class="empty"><div class="empty-ic">📜</div>No transactions</div>';return}
    el.innerHTML=txns.map(t=>`<div class="txn">
      <div style="flex:1"><div class="amt">+ ₹${t.amount.toFixed(2)}</div>
      <div class="meta">Txn: ${esc(t.txn_id)||'-'}</div>
      <div class="meta">UTR: ${esc(t.utr)||'-'}</div>
      <div class="meta">From: ${esc(t.sender_upi)||'-'}</div>
      <div class="meta">${esc(t.email_date)||esc(t.paid_at)}</div>
      ${t.session_id?`<div class="sess">🔖 ${esc(t.session_id)}</div>`:''}
      </div>
      <div style="font-size:10px;color:var(--dim);text-align:right;font-family:monospace">${esc(t.order_id)||''}</div>
    </div>`).join('');
  }catch(e){toast('❌ '+e.message,true)}
}
async function loadPartials(){
  try{
    const ps=await api('/api/partial-payments'),el=document.getElementById('partialList');
    if(!ps.length){el.innerHTML='<div class="empty"><div class="empty-ic">✨</div>No partials</div>';return}
    el.innerHTML=ps.map(p=>`<div class="txn partial">
      <div><div class="amt">₹${p.received.toFixed(2)} / ₹${p.expected.toFixed(2)}</div>
      <div class="meta">Short by ₹${(p.short_by||0).toFixed(2)} · Txn ${esc(p.txn_id)||'-'}</div>
      ${p.session_id?`<div class="sess">🔖 ${esc(p.session_id)}</div>`:''}
      </div>
      <div style="font-size:11px;color:var(--dim);text-align:right">${esc(p.created_at)}</div>
    </div>`).join('');
  }catch(e){toast('❌ '+e.message,true)}
}
async function loadAudit(){
  try{
    const list=await api('/api/audit-log'),el=document.getElementById('auditList');
    if(!list.length){el.innerHTML='<div class="empty"><div class="empty-ic">🔍</div>No logs</div>';return}
    el.innerHTML=list.map(l=>`<div class="txn"><div><div style="font-weight:700;font-size:12px">${esc(l.action)}</div>
      <div class="meta">${esc(l.details||'')}</div></div>
      <div style="font-size:11px;color:var(--dim);text-align:right">${esc(l.created_at)}<br>${esc(l.ip||'')}</div>
    </div>`).join('');
  }catch(e){toast('❌ '+e.message,true)}
}

(async()=>{try{await api('/api/me');bootApp()}catch{}})();
</script></body></html>
"""

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), threaded=True)

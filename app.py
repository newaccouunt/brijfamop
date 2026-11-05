import os, re, time, imaplib, email, datetime, random, string, base64, sqlite3, secrets, json, hashlib, hmac
from io import BytesIO
from email.header import decode_header
from email.utils import parsedate_to_datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, session, g, redirect
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode

# ==========================================
# CONFIGURATION & DATABASE SETUP
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
APP_VERSION = "2.0.0"
BUILD_DATE = "2025"

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA synchronous=NORMAL")
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
            order_id TEXT PRIMARY KEY, api_key TEXT NOT NULL,
            username TEXT NOT NULL, amount REAL NOT NULL,
            status TEXT DEFAULT 'PENDING',
            txn_id TEXT DEFAULT '', utr TEXT DEFAULT '',
            paid_amount REAL DEFAULT 0,
            partial_amount REAL DEFAULT 0,
            short_by REAL DEFAULT 0,
            overpaid REAL DEFAULT 0,
            notes TEXT DEFAULT '',
            created_at REAL NOT NULL, expires_at REAL NOT NULL,
            paid_at REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
            order_id TEXT, amount REAL NOT NULL,
            txn_id TEXT UNIQUE, utr TEXT,
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
            order_id TEXT, username TEXT,
            expected REAL, received REAL, short_by REAL,
            txn_id TEXT, utr TEXT,
            notified INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_qr_apikey ON qr_sessions(api_key);
        CREATE INDEX IF NOT EXISTS idx_qr_status ON qr_sessions(status);
        CREATE INDEX IF NOT EXISTS idx_txn_username ON transactions(username);
        """)
        if not db.execute("SELECT id FROM users WHERE username='admin'").fetchone():
            db.execute("INSERT INTO users (username,password_hash,full_name,upi_id) VALUES (?,?,?,?)",
                       ("admin", generate_password_hash("admin123"), "Riju Mondal", "riju@fam"))
        db.commit()
init_db()

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def login_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        if 'user' not in session:
            return jsonify({"error":"Unauthorized", "code":"AUTH_REQUIRED"}), 401
        return f(*a, **k)
    return wrapper

def gen_key(): return ''.join(random.choices(string.ascii_uppercase+string.digits, k=20))
def gen_order_id(): return "ORD" + str(int(time.time())) + ''.join(random.choices(string.digits, k=4))

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
    """Supports JSON, form-data, urlencoded, query params — auto-detect"""
    data = {}
    if request.is_json:
        data.update(request.get_json(silent=True) or {})
    if request.form:
        data.update(request.form.to_dict())
    if request.args:
        data.update(request.args.to_dict())
    if not data and request.data:
        try: data.update(json.loads(request.data.decode()))
        except: pass
    return data

# ==========================================
# ULTRA-FAST SMART EMAIL CHECK (V2.0)
# Exact amount + partial detection + duplicate block
# ==========================================
def read_fampay_email(username, expected_amount, order_id=None, tolerance=0.0):
    """
    Returns:
      (True,  {txn data}, "PAID")           -> Exact match
      (False, {partial data}, "PARTIAL")    -> Short/Over payment
      (False, None, "NO_EMAIL")             -> No matching email yet
      (False, None, error_string)           -> Email error
    """
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not u or not u['email'] or not u['app_password']:
        return False, None, "Email/App Password missing"

    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com", timeout=8)
        mail.login(u['email'], u['app_password'].replace(" ", ""))
        mail.select("inbox", readonly=False)

        today_date = datetime.datetime.now(IST).strftime("%d-%b-%Y")
        status, messages = mail.search(None, f'(SINCE "{today_date}" UNSEEN)')

        if status != "OK" or not messages[0]:
            mail.logout()
            return False, None, "NO_EMAIL"

        email_ids = messages[0].split()
        now_ist = datetime.datetime.now(IST)

        for e_id in reversed(email_ids[-5:]):
            status, data = mail.fetch(e_id, '(RFC822)')
            for rp in data:
                if not isinstance(rp, tuple): continue
                msg = email.message_from_bytes(rp[1])

                subj = msg.get('subject', '')
                if "Fam" not in subj and "fam" not in subj: continue

                try:
                    dt = parsedate_to_datetime(msg.get('date')).astimezone(IST)
                    diff_min = (now_ist - dt).total_seconds() / 60
                    if diff_min > 5 or diff_min < -2:
                        continue
                except:
                    continue

                body = clean_body(msg)
                am = re.search(r'₹\s?([\d,]+\.?\d*)', body)
                if not am: continue

                recv = float(am.group(1).replace(",", ""))

                txn_m = re.search(r'Transaction ID\s*[:\-]?\s*([A-Z0-9]+)', body, re.I)
                txn_id = txn_m.group(1) if txn_m else f"AUTO{int(time.time())}{random.randint(100,999)}"
                utr_m = re.search(r'UTR\s*[:\-]?\s*(\d+)', body, re.I)
                utr = utr_m.group(1) if utr_m else ""

                # DUPLICATE TXN BLOCK (V2 anti-glitch)
                dup = db.execute("SELECT id FROM transactions WHERE txn_id=?", (txn_id,)).fetchone()
                if dup:
                    mail.store(e_id, '+FLAGS', '\\Seen')
                    continue

                # PAYMENT CLASSIFICATION
                exact_min = expected_amount - tolerance
                exact_max = expected_amount + tolerance

                if recv >= exact_min and recv <= exact_max:
                    # ✅ EXACT PAYMENT
                    mail.store(e_id, '+FLAGS', '\\Seen')
                    mail.logout()
                    return True, {
                        "txn_id": txn_id, "utr": utr, "amount": recv,
                        "expected": expected_amount, "kind": "EXACT"
                    }, "PAID"

                elif recv < exact_min:
                    # ⚠️ SHORT PAYMENT — DO NOT MARK PAID
                    short_by = round(expected_amount - recv, 2)
                    mail.store(e_id, '+FLAGS', '\\Seen')
                    mail.logout()
                    return False, {
                        "txn_id": txn_id, "utr": utr, "amount": recv,
                        "expected": expected_amount, "short_by": short_by,
                        "kind": "SHORT"
                    }, "PARTIAL"

                else:
                    # ⚠️ OVERPAYMENT — flag for review, don't auto-pay
                    over = round(recv - expected_amount, 2)
                    mail.store(e_id, '+FLAGS', '\\Seen')
                    mail.logout()
                    return False, {
                        "txn_id": txn_id, "utr": utr, "amount": recv,
                        "expected": expected_amount, "overpaid": over,
                        "kind": "OVER"
                    }, "PARTIAL"

        mail.logout()
        return False, None, "NO_EMAIL"
    except Exception as e:
        return False, None, str(e)

def build_url(path):
    base = BASE_URL.rstrip('/') or request.host_url.rstrip('/')
    return base + path

def notify_webhook(username, event, payload):
    """Fire webhook if user configured one — works with any HTTP client"""
    try:
        db = get_db()
        u = db.execute("SELECT webhook_url FROM users WHERE username=?", (username,)).fetchone()
        if u and u['webhook_url']:
            import urllib.request
            body = json.dumps({"event": event, "data": payload, "ts": time.time()}).encode()
            req = urllib.request.Request(u['webhook_url'], data=body,
                                          headers={"Content-Type":"application/json","User-Agent":"FamPay-AutoQR/2.0"})
            urllib.request.urlopen(req, timeout=3)
    except: pass

# ==========================================
# AUTH ROUTES
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
        "version": APP_VERSION
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
# DASHBOARD / DATA ROUTES
# ==========================================
@app.route('/api/dashboard', methods=['GET'])
@login_required
def dashboard():
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE username=?", (session['user'],)).fetchone()
    keys = db.execute("SELECT * FROM api_keys WHERE username=?", (session['user'],)).fetchall()

    chart = []
    for i in range(6, -1, -1):
        day = (datetime.datetime.now(IST) - datetime.timedelta(days=i)).strftime("%Y-%m-%d")
        s = db.execute("SELECT SUM(amount) as s FROM transactions WHERE username=? AND DATE(paid_at)=?",
                       (session['user'], day)).fetchone()['s'] or 0
        chart.append({"day": day, "amount": round(s,2)})

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
        "chart": chart,
        "transactions": [{
            "amount": t['amount'], "txn_id": t['txn_id'], "utr": t['utr'],
            "order_id": t['order_id'], "paid_at": t['paid_at']
        } for t in txns],
        "partial_payments": [{
            "order_id": p['order_id'], "expected": p['expected'],
            "received": p['received'], "short_by": p['short_by'],
            "txn_id": p['txn_id'], "created_at": p['created_at']
        } for p in partials]
    })

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
        "example": build_url(f"/v2/fam/{key}?qr=100")})

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
        "url": build_url(f"/v2/fam/{r['api_key']}")
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
        "order_id": t['order_id'], "paid_at": t['paid_at']
    } for t in txns])

@app.route('/api/partial-payments', methods=['GET'])
@login_required
def list_partials():
    db = get_db()
    rows = db.execute("SELECT * FROM partial_payments WHERE username=? ORDER BY id DESC LIMIT 100",
                      (session['user'],)).fetchall()
    return jsonify([{
        "order_id": p['order_id'], "expected": p['expected'],
        "received": p['received'], "short_by": p['short_by'],
        "txn_id": p['txn_id'], "utr": p['utr'],
        "created_at": p['created_at']
    } for p in rows])

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    db = get_db()
    u = session['user']
    total_txn = db.execute("SELECT COUNT(*) c FROM transactions WHERE username=?", (u,)).fetchone()['c']
    total_partial = db.execute("SELECT COUNT(*) c FROM partial_payments WHERE username=?", (u,)).fetchone()['c']
    today = datetime.datetime.now(IST).strftime("%Y-%m-%d")
    today_sum = db.execute("SELECT COALESCE(SUM(amount),0) s FROM transactions WHERE username=? AND DATE(paid_at)=?", (u, today)).fetchone()['s']
    return jsonify({"total_txn": total_txn, "total_partial": total_partial, "today": round(today_sum,2)})

# ==========================================
# PUBLIC API ROUTES (Cross-platform compatible)
# ==========================================
def _get_key_from_request():
    # Header first
    hkey = request.headers.get('X-API-Key') or request.headers.get('X-Api-Key')
    if hkey: return hkey
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '): return auth[7:]
    return None

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
    """Core V2 payment verification — handles exact/partial/over"""
    db = get_db()

    # Duplicate txn block
    ok, info, status = read_fampay_email(s['username'], s['amount'], s['order_id'], tolerance)

    if status == "PAID" and ok:
        # Exact match
        db.execute("""UPDATE qr_sessions SET status='PAID',txn_id=?,utr=?,paid_amount=?,paid_at=?
                      WHERE order_id=?""",
                   (info['txn_id'], info['utr'], info['amount'], time.time(), s['order_id']))
        db.execute("UPDATE users SET total_earning=total_earning+? WHERE username=?",
                   (info['amount'], s['username']))
        db.execute("UPDATE api_keys SET total_received=total_received+? WHERE api_key=?",
                   (info['amount'], key_row['api_key']))
        try:
            db.execute("""INSERT INTO transactions (username,order_id,amount,txn_id,utr) VALUES (?,?,?,?,?)""",
                       (s['username'], s['order_id'], info['amount'], info['txn_id'], info['utr']))
        except sqlite3.IntegrityError:
            pass  # duplicate
        db.commit()
        notify_webhook(s['username'], "payment.success", {
            "order_id": s['order_id'], "amount": info['amount'],
            "txn_id": info['txn_id'], "utr": info['utr']
        })
        return True, info, "PAID"

    elif status == "PARTIAL" and info:
        # Short or Over payment — DO NOT mark paid
        existing = db.execute("SELECT id FROM partial_payments WHERE txn_id=?",
                              (info['txn_id'],)).fetchone()
        if not existing:
            db.execute("""INSERT INTO partial_payments
                          (order_id,username,expected,received,short_by,txn_id,utr)
                          VALUES (?,?,?,?,?,?,?)""",
                       (s['order_id'], s['username'], s['amount'],
                        info['amount'], info.get('short_by', 0),
                        info['txn_id'], info['utr']))
            db.execute("""UPDATE qr_sessions SET partial_amount=?, short_by=?, overpaid=?, txn_id=?, utr=?
                          WHERE order_id=?""",
                       (info['amount'], info.get('short_by', 0),
                        info.get('overpaid', 0), info['txn_id'], info['utr'], s['order_id']))
            db.commit()
            notify_webhook(s['username'], "payment.partial", {
                "order_id": s['order_id'], "expected": s['amount'],
                "received": info['amount'], "short_by": info.get('short_by', 0)
            })
        return False, info, "PARTIAL"

    return False, None, status or "PENDING"

@app.route('/v2/fam/<path:api_key>')
def fam_qr(api_key):
    """QR generation endpoint — HTML page, works everywhere"""
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
    now = time.time()

    db.execute("""INSERT INTO qr_sessions (order_id,api_key,username,amount,created_at,expires_at)
                  VALUES (?,?,?,?,?,?)""",
               (order_id, key_row['api_key'], key_row['username'], amount, now, now + minutes*60))
    db.commit()
    audit(key_row['username'], "QR_GENERATED", f"order={order_id} amt={amount}")

    qr_image = qr_b64(upi)
    return render_template_string(
        QR_HTML_TEMPLATE_V2,
        amount=amount, qr_b64=qr_image, order_id=order_id,
        upi_id=user['upi_id'], full_name=user['full_name'] or user['username'],
        minutes=minutes, tolerance=user['tolerance'] or 0
    )

@app.route('/api/v2/check/<path:api_key>')
def api_check_v2(api_key):
    """JSON check — for Telegram bot, JS, PHP, React — everything"""
    key_row, status = _key_status(api_key)
    if status != "active":
        return jsonify({"status": "ERROR", "error": status, "code": 403}), 403

    db = get_db()
    order_id = request.args.get('order_id')
    if order_id:
        s = db.execute("SELECT * FROM qr_sessions WHERE order_id=? AND api_key=?",
                       (order_id, key_row['api_key'])).fetchone()
    else:
        s = db.execute("SELECT * FROM qr_sessions WHERE api_key=? ORDER BY created_at DESC LIMIT 1",
                       (key_row['api_key'],)).fetchone()

    if not s:
        return jsonify({"status": "NOTFOUND"})

    if s['status'] == 'PAID':
        return jsonify({
            "status": "PAID", "order_id": s['order_id'],
            "amount": s['paid_amount'] or s['amount'],
            "expected": s['amount'], "paid": s['paid_amount'] or s['amount'],
            "txn_id": s['txn_id'], "utr": s['utr'],
            "verified": True
        })

    if s['status'] == 'PARTIAL':
        return jsonify({
            "status": "PARTIAL", "order_id": s['order_id'],
            "expected": s['amount'], "received": s['partial_amount'],
            "short_by": s['short_by'], "overpaid": s['overpaid'],
            "txn_id": s['txn_id'], "utr": s['utr'],
            "verified": False,
            "message": f"Please pay remaining ₹{s['short_by']:.2f}" if s['short_by'] > 0 else f"Overpaid ₹{s['overpaid']:.2f} — contact support"
        })

    if s['status'] == 'EXPIRED' or time.time() > s['expires_at']:
        if s['status'] != 'EXPIRED':
            db.execute("UPDATE qr_sessions SET status='EXPIRED' WHERE order_id=?", (s['order_id'],))
            db.commit()
        return jsonify({"status": "EXPIRED", "order_id": s['order_id']})

    # Attempt verify (needs email creds)
    user = db.execute("SELECT tolerance FROM users WHERE username=?", (s['username'],)).fetchone()
    tol = (user['tolerance'] if user else 0) or 0
    ok, info, st = _verify_payment_for_session(s, key_row, tol)

    # Re-fetch latest session state
    s = db.execute("SELECT * FROM qr_sessions WHERE order_id=?", (s['order_id'],)).fetchone()

    if s['status'] == 'PAID':
        return jsonify({
            "status": "PAID", "order_id": s['order_id'],
            "amount": s['paid_amount'], "expected": s['amount'],
            "txn_id": s['txn_id'], "utr": s['utr'], "verified": True
        })
    if s['status'] == 'PARTIAL':
        return jsonify({
            "status": "PARTIAL", "order_id": s['order_id'],
            "expected": s['amount'], "received": s['partial_amount'],
            "short_by": s['short_by'], "verified": False
        })

    return jsonify({
        "status": "PENDING", "order_id": s['order_id'],
        "seconds_left": int(max(0, s['expires_at']-time.time()))
    })

@app.route('/api/check-payment/<order_id>')
def check_payment(order_id):
    """Legacy check — kept for compatibility with QR page"""
    db = get_db()
    s = db.execute("SELECT * FROM qr_sessions WHERE order_id=?", (order_id,)).fetchone()
    if not s:
        return jsonify({"status": "NOTFOUND"}), 404

    if s['status'] == 'PAID':
        return jsonify({"status": "PAID", "txn": {
            "txn_id": s['txn_id'], "utr": s['utr'], "amount": s['paid_amount'] or s['amount']
        }})

    if s['status'] == 'PARTIAL':
        return jsonify({"status": "PARTIAL",
            "expected": s['amount'], "received": s['partial_amount'],
            "short_by": s['short_by'],
            "message": f"⚠️ Short by ₹{s['short_by']:.2f}"
        })

    if time.time() > s['expires_at']:
        if s['status'] != 'EXPIRED':
            db.execute("UPDATE qr_sessions SET status='EXPIRED' WHERE order_id=?", (order_id,))
            db.commit()
        return jsonify({"status": "EXPIRED"})

    key_row = db.execute("SELECT * FROM api_keys WHERE api_key=?", (s['api_key'],)).fetchone()
    if not key_row:
        return jsonify({"status": "PENDING"})

    user = db.execute("SELECT tolerance FROM users WHERE username=?", (s['username'],)).fetchone()
    tol = (user['tolerance'] if user else 0) or 0
    ok, info, st = _verify_payment_for_session(s, key_row, tol)

    s = db.execute("SELECT * FROM qr_sessions WHERE order_id=?", (order_id,)).fetchone()
    if s['status'] == 'PAID':
        return jsonify({"status": "PAID", "txn": {
            "txn_id": s['txn_id'], "utr": s['utr'], "amount": s['paid_amount']
        }})
    if s['status'] == 'PARTIAL':
        return jsonify({"status": "PARTIAL",
            "expected": s['amount'], "received": s['partial_amount'],
            "short_by": s['short_by']
        })
    return jsonify({"status": "PENDING"})

# ==========================================
# ERROR PAGE TEMPLATE
# ==========================================
ERROR_HTML = """
<!DOCTYPE html><html><head><meta charset="utf-8"><title>Error</title>
<style>body{background:#05050a;color:#e8e8f5;font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#0f0f1e;border:1px solid #1f1f3a;padding:40px;border-radius:20px;text-align:center;max-width:400px}
h2{color:#ff4757;margin-bottom:12px}p{color:#7a7a9a}</style></head>
<body><div class="card"><h2>⚠️ Error</h2><p>{{ msg }}</p></div></body></html>
"""

# ==========================================
# PREMIUM QR PAGE (V2 with partial payment UI)
# ==========================================
QR_HTML_TEMPLATE_V2 = """
<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pay ₹{{ amount }}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:'Inter',sans-serif}
body{background:#05050a;color:#e8e8f5;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;
background:radial-gradient(circle at 30% 20%,rgba(0,224,164,.15),transparent 45%),radial-gradient(circle at 70% 80%,rgba(168,85,247,.15),transparent 45%),#05050a}
.card{width:100%;max-width:430px;background:#0f0f1e;border:1px solid #1f1f3a;border-radius:24px;padding:30px 24px;
box-shadow:0 0 60px rgba(0,224,164,.12);text-align:center;position:relative;transition:all .4s}
.tag{font-size:12px;color:#7a7a9a;text-transform:uppercase;letter-spacing:2px;margin-bottom:6px}
h1{font-size:44px;font-weight:900;margin:6px 0;background:linear-gradient(90deg,#00ffb3,#a855f7,#ff00aa);
-webkit-background-clip:text;color:transparent}
.qr-wrap{background:#fff;border-radius:18px;padding:12px;display:inline-block;margin:16px 0;
box-shadow:0 0 50px rgba(0,224,164,.3);transition:.4s}
.qr-wrap img{display:block;width:240px;height:240px;transition:.3s}
.logos{display:flex;justify-content:center;gap:8px;margin:14px 0;flex-wrap:wrap}
.logos span{background:#fff;color:#000;padding:6px 11px;border-radius:8px;font-weight:700;font-size:11px}
.timer{font-size:30px;font-weight:800;margin:10px 0;color:#00e0a4;letter-spacing:1px;font-variant-numeric:tabular-nums}
.status{padding:14px;border-radius:12px;font-weight:600;font-size:14px;margin-top:8px;transition:.3s}
.pending{background:rgba(255,165,2,.12);color:#ffa502}
.partial{background:rgba(255,165,2,.2);color:#ffa502;border:1px solid #ffa502}
.expired{background:rgba(255,71,87,.15);color:#ff4757}
.upi{font-size:12px;color:#7a7a9a;margin-top:8px}.upi b{color:#e8e8f5}
.success-overlay{position:absolute;inset:0;background:#0f0f1e;border-radius:24px;display:none;
flex-direction:column;align-items:center;justify-content:center;padding:30px;z-index:10;opacity:0;transition:.4s}
.success-overlay.show{display:flex;opacity:1}
.check-icon{width:90px;height:90px;border-radius:50%;background:rgba(0,224,164,.15);border:2px solid #00e0a4;
display:flex;align-items:center;justify-content:center;font-size:45px;margin-bottom:20px;
box-shadow:0 0 30px rgba(0,224,164,.5);animation:popIn .5s cubic-bezier(.175,.885,.32,1.275)}
@keyframes popIn{0%{transform:scale(0)}100%{transform:scale(1)}}
.success-title{font-size:26px;font-weight:900;color:#00e0a4;margin-bottom:6px}
.success-amt{font-size:40px;font-weight:900;background:linear-gradient(90deg,#00ffb3,#00d4ff);
-webkit-background-clip:text;color:transparent;margin-bottom:20px}
.success-details{background:#15152a;border:1px solid #1f1f3a;border-radius:12px;padding:16px;width:100%;
text-align:left;font-size:12px}
.success-details div{display:flex;justify-content:space-between;margin-bottom:8px;color:#7a7a9a}
.success-details b{color:#e8e8f5;font-weight:700}
.partial-overlay{position:absolute;inset:0;background:#0f0f1e;border-radius:24px;display:none;
flex-direction:column;align-items:center;justify-content:center;padding:30px;z-index:10;opacity:0;transition:.4s}
.partial-overlay.show{display:flex;opacity:1}
.warn-icon{width:90px;height:90px;border-radius:50%;background:rgba(255,165,2,.15);border:2px solid #ffa502;
display:flex;align-items:center;justify-content:center;font-size:45px;margin-bottom:20px}
.warn-title{font-size:24px;font-weight:900;color:#ffa502;margin-bottom:6px}
.warn-msg{color:#e8e8f5;font-size:14px;margin-bottom:16px;text-align:center;line-height:1.5}
.warn-details{background:#15152a;border:1px solid #1f1f3a;border-radius:12px;padding:16px;width:100%;
font-size:13px;margin-bottom:16px}
.warn-details div{display:flex;justify-content:space-between;margin-bottom:8px}
.warn-details b{color:#ffa502}
</style></head><body>
<div class="card" id="mainCard">
    <div class="tag">Pay via UPI</div>
    <h1>₹{{ "%.2f"|format(amount) }}</h1>
    <div class="upi">to <b>{{ full_name }}</b> · {{ upi_id }}</div>
    <div class="qr-wrap" id="qrWrap"><img src="{{ qr_b64 }}" alt="QR"></div>
    <div class="logos"><span>GPay</span><span>PhonePe</span><span>Paytm</span><span>UPI</span></div>
    <div class="timer" id="timer">{{ '%02d:00'|format(minutes) }}</div>
    <div class="status pending" id="status">⏳ Waiting for payment of ₹{{ "%.2f"|format(amount) }}...</div>

    <!-- EXACT SUCCESS -->
    <div class="success-overlay" id="successOverlay">
        <div class="check-icon">✅</div>
        <div class="success-title">Payment Successful</div>
        <div class="success-amt" id="successAmt">₹{{ amount }}</div>
        <div class="success-details">
            <div><span>Txn ID</span><b id="successTxn">-</b></div>
            <div><span>UTR</span><b id="successUtr">-</b></div>
            <div><span>Status</span><b style="color:#00e0a4">Verified ✅</b></div>
        </div>
    </div>

    <!-- PARTIAL PAYMENT WARNING -->
    <div class="partial-overlay" id="partialOverlay">
        <div class="warn-icon">⚠️</div>
        <div class="warn-title">Payment Incomplete</div>
        <div class="warn-msg" id="partialMsg">You paid less than required.</div>
        <div class="warn-details">
            <div><span>Expected</span><b>₹{{ "%.2f"|format(amount) }}</b></div>
            <div><span>Received</span><b id="partialRecv">₹0.00</b></div>
            <div><span>Remaining</span><b id="partialShort">₹0.00</b></div>
            <div><span>Txn ID</span><b id="partialTxn" style="color:#e8e8f5">-</b></div>
        </div>
        <div style="font-size:12px;color:#7a7a9a;text-align:center">Please pay the remaining amount to complete verification.</div>
    </div>
</div>
<script>
const orderId="{{ order_id }}", totalSecs={{ minutes*60 }}, expectedAmt={{ amount }};
let secs=totalSecs, tInt, pInt;
const T=document.getElementById('timer'), S=document.getElementById('status');
const soundDone=(() => {try{return new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdJivrJBhNjVgodDbq2EcBj+a2/LDciUFLIHO8tiJNwgZaLvt559NEAxQp+PwtmMcBjiR1/LMeSwFJHfH8N2QQAoUXrTp66hVFApGn+DyvmwhBSuBzvLZiTYIG2m98OScTgwOUarm7blmGgU7k9n1unEiBC13yO/eizEIHWq+8+OWT');}catch(e){return null}})();

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
            if(soundDone) try{soundDone.play()}catch(e){}
            document.getElementById('successAmt').textContent = '₹' + (d.txn.amount||expectedAmt);
            document.getElementById('successTxn').textContent = d.txn.txn_id || '-';
            document.getElementById('successUtr').textContent = d.txn.utr || '-';
            document.getElementById('successOverlay').classList.add('show');
            clearInterval(tInt); clearInterval(pInt);
        }
        else if(d.status==='PARTIAL' && !partialShown){
            partialShown = true;
            document.getElementById('partialRecv').textContent = '₹' + (d.received||0).toFixed(2);
            document.getElementById('partialShort').textContent = '₹' + (d.short_by||0).toFixed(2);
            document.getElementById('partialMsg').textContent = d.message || 'Payment incomplete.';
            document.getElementById('partialOverlay').classList.add('show');
        }
        else if(d.status==='EXPIRED'){
            S.textContent='❌ QR Expired'; S.className='status expired';
            clearInterval(tInt); clearInterval(pInt);
        }
    }catch(e){}
}
tInt=setInterval(tick,1000); pInt=setInterval(poll,3000); poll();
</script></body></html>
"""

# ==========================================
# MAIN DASHBOARD UI (V2 — ULTRA RAINBOW)
# ==========================================
MAIN_HTML = r"""
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FamPay AutoQR — V2.0 Ultra</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
:root{--bg:#05050a;--surface:#0f0f1e;--surface2:#15152a;--border:#1f1f3a;--text:#e8e8f5;--dim:#7a7a9a;
--ng:#00ffb3;--nc:#00d4ff;--np:#a855f7;--npink:#ff00aa;--nwarn:#ffa502;--dang:#ff4757;--ok:#00e0a4;
--shadow:0 0 40px rgba(0,255,179,.15)}
[data-theme="light"]{--bg:#f5f7fa;--surface:#ffffff;--surface2:#f0f2f7;--border:#e0e4ec;--text:#0f0f1e;--dim:#6a6a8a;--shadow:0 0 40px rgba(168,85,247,.1)}
*{margin:0;padding:0;box-sizing:border-box}
html,body{transition:background .3s,color .3s}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:-1;background:
radial-gradient(700px at 10% 5%,rgba(0,255,179,.09),transparent 60%),
radial-gradient(700px at 90% 10%,rgba(168,85,247,.09),transparent 60%),
radial-gradient(700px at 50% 90%,rgba(255,0,170,.09),transparent 60%)}
[data-theme="light"] body::before{background:
radial-gradient(700px at 10% 5%,rgba(0,255,179,.15),transparent 60%),
radial-gradient(700px at 90% 10%,rgba(168,85,247,.12),transparent 60%),
radial-gradient(700px at 50% 90%,rgba(255,0,170,.1),transparent 60%)}
button,input,select,textarea{font-family:inherit;outline:none}
.hidden{display:none!important}

/* AUTH */
.auth-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.auth-card{width:100%;max-width:420px;background:var(--surface);border:1px solid var(--border);
border-radius:22px;padding:34px 28px;box-shadow:var(--shadow)}
.logo{font-size:22px;font-weight:900;text-align:center;margin-bottom:4px;
background:linear-gradient(90deg,var(--ng),var(--np),var(--npink),var(--nc));
-webkit-background-clip:text;color:transparent;background-size:300% 100%;animation:rbow 4s linear infinite}
@keyframes rbow{to{background-position:300% 0}}
.logo-sub{text-align:center;color:var(--dim);font-size:12px;margin-bottom:22px}
.field{margin-bottom:14px}.field label{display:block;font-size:11px;font-weight:700;color:var(--dim);
margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}
.field input{width:100%;padding:12px 14px;background:var(--surface2);border:1px solid var(--border);
border-radius:10px;color:var(--text);font-size:14px;transition:.2s}
.field input:focus{border-color:var(--ng);box-shadow:0 0 0 3px rgba(0,255,179,.15)}
.btn{width:100%;padding:13px;border:none;border-radius:10px;font-weight:800;font-size:14px;
background:linear-gradient(90deg,var(--ng),var(--nc),var(--np));color:#05050a;transition:.2s;
cursor:pointer;background-size:200% 100%;display:flex;align-items:center;justify-content:center;gap:8px}
.btn:hover{transform:translateY(-1px);box-shadow:0 0 30px rgba(0,255,179,.5);background-position:100% 0}
.btn.sec{background:var(--surface2);color:var(--text);border:1px solid var(--border)}
.btn.sec:hover{box-shadow:none;border-color:var(--ng)}
.btn.dang{background:linear-gradient(90deg,var(--dang),var(--npink))}
.switch{text-align:center;margin-top:14px;font-size:13px;color:var(--dim)}
.switch a{color:var(--ng);font-weight:700;cursor:pointer}

/* LAYOUT */
.shell{display:flex;min-height:100vh}
.sidebar{width:260px;background:var(--surface);border-right:1px solid var(--border);padding:22px 14px;
position:fixed;inset:0 auto 0 0;overflow-y:auto;z-index:50;transition:transform .3s}
.brand{font-size:17px;font-weight:900;padding:0 8px 20px;
background:linear-gradient(90deg,var(--ng),var(--np),var(--npink));
-webkit-background-clip:text;color:transparent;background-size:200%;animation:rbow 3s infinite linear}
.nav{display:flex;flex-direction:column;gap:3px}
.item{padding:11px 14px;border-radius:10px;color:var(--dim);font-size:13px;font-weight:600;
display:flex;align-items:center;gap:10px;cursor:pointer;transition:.15s;position:relative}
.item:hover{background:var(--surface2);color:var(--text)}
.item.active{background:linear-gradient(90deg,rgba(0,255,179,.15),rgba(168,85,247,.08));
color:var(--ng);box-shadow:inset 0 0 20px rgba(0,255,179,.1)}
.sec-lbl{font-size:10px;font-weight:800;color:#3a3a5a;text-transform:uppercase;
letter-spacing:1.5px;padding:16px 14px 6px}
.main{flex:1;margin-left:260px;padding:24px;max-width:100%}
@media(max-width:860px){.sidebar{transform:translateX(-100%)}
.sidebar.open{transform:none}.main{margin-left:0;padding:14px}}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px;
padding-bottom:16px;border-bottom:1px solid var(--border);gap:12px;flex-wrap:wrap}
.topbar h1{font-size:22px;font-weight:800}
.chip{display:flex;align-items:center;gap:8px;padding:7px 14px;background:var(--surface);
border:1px solid var(--border);border-radius:30px;font-size:12px;font-weight:600}
.hamburger{display:none;background:var(--surface2);border:1px solid var(--border);
color:var(--text);padding:8px 10px;border-radius:8px;cursor:pointer;font-size:18px}
@media(max-width:860px){.hamburger{display:block}}
.dot{width:8px;height:8px;border-radius:50%;box-shadow:0 0 8px currentColor}
.dot.on{background:var(--ng);color:var(--ng)}
.dot.off{background:var(--dang);color:var(--dang)}
.dot.unk{background:var(--dim);color:var(--dim)}
.icon-btn{background:var(--surface2);border:1px solid var(--border);color:var(--text);
padding:8px 11px;border-radius:8px;cursor:pointer;transition:.2s;font-size:15px}
.icon-btn:hover{border-color:var(--ng);color:var(--ng)}

/* CARDS */
.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;
padding:22px;margin-bottom:16px}
.card h2{font-size:15px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.grid-4{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}
@media(max-width:860px){.grid-2,.grid-3,.grid-4{grid-template-columns:1fr 1fr}}
@media(max-width:500px){.grid-2,.grid-3,.grid-4{grid-template-columns:1fr}}

.hero{background:linear-gradient(135deg,rgba(0,255,179,.15),rgba(168,85,247,.15),rgba(255,0,170,.1));
border:1px solid rgba(0,255,179,.3);border-radius:20px;padding:26px;position:relative;overflow:hidden}
.hero-amt{font-size:48px;font-weight:900;margin:8px 0;
background:linear-gradient(90deg,var(--ng),var(--np),var(--npink));
-webkit-background-clip:text;color:transparent;filter:drop-shadow(0 0 15px rgba(255,0,170,.4))}
.hero-lbl{font-size:11px;font-weight:800;color:var(--dim);text-transform:uppercase;letter-spacing:2px}
.hero-sub{font-size:13px;color:var(--dim)}.hero-sub b{color:var(--text)}

.stat{background:var(--surface2);border:1px solid var(--border);border-radius:14px;padding:16px;
position:relative;overflow:hidden;transition:.3s}
.stat:hover{transform:translateY(-2px);border-color:var(--ng)}
.stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;
background:linear-gradient(90deg,var(--ng),var(--nc))}
.stat-lbl{font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:1px;font-weight:700}
.stat-val{font-size:24px;font-weight:800;margin-top:4px;color:var(--ng)}
.stat.alt .stat-val{color:var(--np)}.stat.alt2 .stat-val{color:var(--npink)}
.stat.warn .stat-val{color:var(--nwarn)}

/* CHART */
.chart{display:flex;align-items:flex-end;gap:8px;height:140px;padding-top:10px}
.bar-wrap{flex:1;display:flex;flex-direction:column;align-items:center;gap:6px}
.bar{width:100%;background:linear-gradient(180deg,var(--ng),rgba(0,255,179,.2));
border-radius:6px 6px 0 0;min-height:4px;transition:.3s}
.bar-wrap:hover .bar{box-shadow:0 0 20px rgba(0,255,179,.6)}
.bar-label{font-size:10px;color:var(--dim)}.bar-val{font-size:10px;font-weight:700;color:var(--ng)}

/* FORM */
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
@media(max-width:600px){.form-grid{grid-template-columns:1fr}}
.fg{display:flex;flex-direction:column;gap:6px}
.fg label{font-size:11px;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:.5px}
.fg input,.fg select,.fg textarea{padding:11px 14px;background:var(--surface2);
border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:14px;transition:.2s}
.fg input:focus,.fg select:focus,.fg textarea:focus{border-color:var(--ng);
box-shadow:0 0 0 3px rgba(0,255,179,.15)}
.fg small{font-size:10px;color:var(--dim);margin-top:-2px}

/* API OUTPUT */
.api-out{background:#02020a;border:1px dashed rgba(0,255,179,.4);padding:12px;border-radius:10px;
color:var(--ng);font-family:monospace;font-size:11px;word-break:break-all;margin-top:8px;
display:flex;justify-content:space-between;align-items:center;gap:8px}
[data-theme="light"] .api-out{background:#f0f0f8;color:#0a8a5a}
.copy{background:var(--surface2);border:1px solid var(--border);color:var(--text);
padding:5px 9px;border-radius:6px;font-size:10px;font-weight:700;flex-shrink:0;cursor:pointer}
.copy:hover{background:var(--ng);color:#05050a;border-color:var(--ng)}

/* TXN LIST */
.txn{display:flex;justify-content:space-between;align-items:center;padding:12px;
background:var(--surface2);border-radius:10px;margin-bottom:6px;font-size:13px;border-left:3px solid var(--ok)}
.txn.partial{border-left-color:var(--nwarn)}
.txn .amt{color:var(--ok);font-weight:800}
.txn.partial .amt{color:var(--nwarn)}
.txn .meta{font-size:11px;color:var(--dim);margin-top:2px}

/* MISC */
.flist{list-style:none}.flist li{padding:10px 0;border-bottom:1px solid var(--border);
display:flex;align-items:center;gap:10px;font-size:13px}
.flist li:last-child{border:none}.flist li::before{content:'✦';color:var(--ng);font-size:14px}
#toast{position:fixed;bottom:20px;right:20px;padding:14px 20px;border-radius:12px;
background:var(--surface2);color:var(--text);font-size:13px;font-weight:600;
border-left:3px solid var(--ng);box-shadow:0 0 30px rgba(0,255,179,.3);
transform:translateY(100px);opacity:0;transition:.3s;z-index:1000;max-width:340px}
#toast.show{transform:translateY(0);opacity:1}
#toast.err{border-left-color:var(--dang);box-shadow:0 0 30px rgba(255,71,87,.3)}
.empty{text-align:center;padding:36px 20px;color:var(--dim);font-size:13px}
.empty-ic{font-size:36px;opacity:.4;margin-bottom:8px}
.badge{display:inline-block;padding:3px 8px;border-radius:6px;font-size:10px;font-weight:800;text-transform:uppercase}
.badge.life{background:rgba(168,85,247,.15);color:var(--np)}
.badge.warn{background:rgba(255,165,2,.15);color:var(--nwarn)}
.badge.ok{background:rgba(0,224,164,.15);color:var(--ok)}

/* TABS */
.tabs{display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap}
.tab{padding:8px 14px;background:var(--surface2);border:1px solid var(--border);
border-radius:8px;font-size:12px;font-weight:600;color:var(--dim);cursor:pointer;transition:.2s}
.tab.active{background:var(--ng);color:#05050a;border-color:var(--ng)}
</style></head><body>

<!-- AUTH -->
<div id="authScreen" class="auth-wrap">
  <div class="auth-card">
    <div class="logo">◆ FamPay AutoQR V2.0</div>
    <div class="logo-sub">Ultra Verification Edition</div>
    <div id="loginForm">
      <div class="field"><label>Username</label><input id="lgU" placeholder="admin" autocomplete="username"></div>
      <div class="field"><label>Password</label><input id="lgP" type="password" placeholder="••••••" autocomplete="current-password"></div>
      <button class="btn" onclick="doLogin()">Login →</button>
      <div class="switch">New? <a onclick="toggleAuth('reg')">Create account</a></div>
    </div>
    <div id="regForm" class="hidden">
      <div class="field"><label>Username</label><input id="rgU" placeholder="yourname" autocomplete="username"></div>
      <div class="field"><label>Password</label><input id="rgP" type="password" placeholder="min 4 chars" autocomplete="new-password"></div>
      <div class="field"><label>Email (optional)</label><input id="rgE" type="email" placeholder="you@gmail.com" autocomplete="email"></div>
      <button class="btn" onclick="doReg()">Create Account →</button>
      <div class="switch">Have account? <a onclick="toggleAuth('login')">Login</a></div>
    </div>
  </div>
</div>

<!-- MAIN -->
<div id="shell" class="shell hidden">
  <aside id="sidebar" class="sidebar">
    <div class="brand">◆ FamPay AutoQR V2</div>
    <nav class="nav">
      <div class="item active" data-p="dashboard" onclick="go('dashboard')">📊 Dashboard</div>
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
      <div style="display:flex;gap:8px;align-items:center">
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
        <h2>📊 Last 7 Days</h2><div class="chart" id="chart"></div>
      </div>
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
          <div class="fg"><label>Tolerance (₹)</label><input id="acTol" type="number" step="0.01" value="0" placeholder="0 = exact match"><small>0 = strict. 0.5 = allow ₹0.50 less</small></div>
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
        <p style="font-size:12px;color:var(--dim);margin-bottom:14px">
          These transactions did NOT match the expected amount. Either short-paid or overpaid. Manual review required.
        </p>
        <div id="partialList"></div>
      </div>
    </section>

    <section id="p-audit" class="page hidden">
      <div class="card"><h2>🔍 Audit Log</h2><div id="auditList"></div></div>
    </section>

    <section id="p-docs" class="page hidden">
      <div class="card">
        <h2>📖 API Documentation</h2>
        <h3 style="font-size:13px;margin:14px 0 8px;color:var(--ng)">1. Generate QR (HTML Page)</h3>
        <div class="api-out"><span>GET /v2/fam/YOUR_API_KEY?qr=100</span><button class="copy" onclick="copyText('/v2/fam/YOUR_KEY?qr=100')">Copy</button></div>
        <p style="font-size:12px;color:var(--dim);margin-top:6px">Optional: &minutes=20 for custom timeout</p>

        <h3 style="font-size:13px;margin:14px 0 8px;color:var(--ng)">2. Check Payment Status (JSON)</h3>
        <div class="api-out"><span>GET /api/v2/check/YOUR_API_KEY?order_id=ORD...</span><button class="copy" onclick="copyText('/api/v2/check/YOUR_KEY')">Copy</button></div>
        <p style="font-size:12px;color:var(--dim);margin-top:6px">No order_id → checks latest session</p>

        <h3 style="font-size:13px;margin:14px 0 8px;color:var(--ng)">3. Response Format</h3>
        <pre style="background:#02020a;color:#00ffb3;padding:14px;border-radius:10px;font-size:11px;overflow-x:auto">{
  "status": "PAID" | "PENDING" | "PARTIAL" | "EXPIRED" | "NOTFOUND",
  "order_id": "ORD17300000001234",
  "amount": 100,
  "expected": 100,
  "received": 100,
  "short_by": 0,
  "txn_id": "TXN123456",
  "utr": "123456789012",
  "verified": true
}</pre>

        <h3 style="font-size:13px;margin:14px 0 8px;color:var(--ng)">4. Header Authentication</h3>
        <p style="font-size:12px;color:var(--dim)">Send <code>X-API-Key: YOUR_KEY</code> header instead of URL</p>

        <h3 style="font-size:13px;margin:14px 0 8px;color:var(--ng)">5. PHP / cURL Example</h3>
        <pre style="background:#02020a;color:#00ffb3;padding:14px;border-radius:10px;font-size:11px;overflow-x:auto">$ch = curl_init("https://yourdomain.com/api/v2/check/KEY");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$res = json_decode(curl_exec($ch), true);
if ($res['status'] === 'PAID') { echo "Paid ₹".$res['amount']; }</pre>

        <h3 style="font-size:13px;margin:14px 0 8px;color:var(--ng)">6. JS / Node.js Example</h3>
        <pre style="background:#02020a;color:#00ffb3;padding:14px;border-radius:10px;font-size:11px;overflow-x:auto">const r = await fetch('/api/v2/check/KEY');
const d = await r.json();
if (d.status === 'PAID') console.log('Amount:', d.amount);</pre>
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
        <div class="fg" style="margin-bottom:12px">
          <label>Auto Verification</label>
          <select id="autoSel">
            <option value="1">Enabled (auto-verify payments)</option>
            <option value="0">Disabled (manual only)</option>
          </select>
        </div>
        <button class="btn" onclick="saveSettings()">💾 Save Settings</button>
      </div>
      <div class="card">
        <h2>ℹ️ About</h2>
        <ul class="flist">
          <li>Version: V2.0.0 Ultra</li>
          <li>Engine: Python Flask + SQLite</li>
          <li>Partial payment protection: ENABLED</li>
          <li>Duplicate txn block: ENABLED</li>
          <li>Webhook support: ENABLED</li>
          <li>CORS: All origins allowed</li>
          <li>Supported clients: Telegram Bot, PHP, JS, React, HTML, Android, iOS</li>
        </ul>
      </div>
    </section>

  </main>
</div>
<div id="toast"></div>

<script>
// ============ UTILS ============
function toast(m, err){const t=document.getElementById('toast');t.textContent=m;t.className='show'+(err?' err':'');clearTimeout(window.__t);window.__t=setTimeout(()=>t.className='',3000);}
function copyText(t){navigator.clipboard.writeText(t).then(()=>toast('✅ Copied'))}
async function api(p, o={}){
  const r=await fetch(p,{headers:{'Content-Type':'application/json'},credentials:'same-origin',...o});
  let d={};try{d=await r.json()}catch{}
  if(!r.ok)throw new Error(d.error||d.message||'Failed');
  return d;
}
function esc(s){return String(s||'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}

// ============ THEME ============
function applyTheme(t){
  document.documentElement.setAttribute('data-theme', t);
  localStorage.setItem('theme', t);
  const sel = document.getElementById('themeSel'); if(sel) sel.value = t;
}
function toggleTheme(){
  const cur = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(cur === 'dark' ? 'light' : 'dark');
}
applyTheme(localStorage.getItem('theme') || 'dark');

// ============ AUTH ============
function toggleAuth(m){
  document.getElementById('loginForm').classList.toggle('hidden', m!=='login');
  document.getElementById('regForm').classList.toggle('hidden', m!=='reg');
}
async function doLogin(){
  try{
    const u=document.getElementById('lgU').value.trim(), p=document.getElementById('lgP').value;
    if(!u||!p)return toast('Fill fields',true);
    await api('/api/login',{method:'POST',body:JSON.stringify({username:u,password:p})});
    toast('✅ Logged in'); bootApp();
  }catch(e){toast('❌ '+e.message,true)}
}
async function doReg(){
  try{
    const u=document.getElementById('rgU').value.trim(),
          p=document.getElementById('rgP').value,
          em=document.getElementById('rgE').value.trim();
    if(!u||!p)return toast('Fill fields',true);
    await api('/api/register',{method:'POST',body:JSON.stringify({username:u,password:p,email:em})});
    toast('✅ Account created. Please login.');
    toggleAuth('login');
    document.getElementById('lgU').value=u;
  }catch(e){toast('❌ '+e.message,true)}
}
async function doLogout(){
  if(!confirm('Logout?')) return;
  await api('/api/logout',{method:'POST'}); location.reload();
}

// ============ NAV ============
function go(p){
  document.querySelectorAll('.page').forEach(x=>x.classList.add('hidden'));
  document.getElementById('p-'+p).classList.remove('hidden');
  document.querySelectorAll('.item').forEach(i=>i.classList.toggle('active',i.dataset.p===p));
  const titles={dashboard:'Dashboard',account:'Account',keys:'API Keys',history:'Transactions',
    partials:'Partial Payments',audit:'Audit Log',docs:'API Docs',settings:'Settings'};
  document.getElementById('title').textContent=titles[p]||p;
  document.getElementById('sidebar').classList.remove('open');
  if(p==='keys')loadKeys();
  if(p==='history')loadHistory();
  if(p==='partials')loadPartials();
  if(p==='audit')loadAudit();
  if(p==='settings')loadSettings();
}

// ============ BOOT ============
async function bootApp(){
  try{
    const me=await api('/api/me');
    document.getElementById('authScreen').classList.add('hidden');
    document.getElementById('shell').classList.remove('hidden');
    document.getElementById('chipUser').textContent=me.username;
    const dot=document.getElementById('emailDot');
    dot.className='dot '+(me.email_status==='online'?'on':me.email_status==='offline'?'off':'unk');
    fillAccount(me); loadDashboard(); loadStats();
    if(me.theme) applyTheme(me.theme);
  }catch(e){ location.reload(); }
}

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
    const ch=document.getElementById('chart'), cd=d.chart||[], max=Math.max(...cd.map(x=>x.amount),1);
    ch.innerHTML=cd.map(x=>{
      const h=Math.max(4,(x.amount/max)*100);
      const day=new Date(x.day).toLocaleDateString('en',{weekday:'short'});
      return `<div class="bar-wrap"><div class="bar-val">₹${x.amount.toFixed(0)}</div><div class="bar" style="height:${h}%"></div><div class="bar-label">${day}</div></div>`;
    }).join('');
  }catch(e){toast('❌ '+e.message,true)}
}

async function loadStats(){
  try{
    const s = await api('/api/stats');
    document.getElementById('stToday').textContent = '₹' + (s.today||0).toFixed(0);
  }catch(e){}
}

// ============ ACCOUNT ============
async function saveAccount(){
  try{
    const payload={
      full_name:document.getElementById('acName').value.trim(),
      upi_id:document.getElementById('acUpi').value.trim(),
      mobile:document.getElementById('acMob').value.trim(),
      email:document.getElementById('acEmail').value.trim(),
      app_password:document.getElementById('acPass').value.trim(),
      default_qr_minutes:parseInt(document.getElementById('acMin').value)||15,
      tolerance:parseFloat(document.getElementById('acTol').value)||0,
      webhook_url:document.getElementById('acHook').value.trim()
    };
    if(!payload.upi_id)return toast('UPI required',true);
    if(!payload.app_password){
      // keep existing
      delete payload.app_password;
      const res = await fetch('/api/setup-account',{method:'POST',credentials:'same-origin',
        headers:{'Content-Type':'application/json'},
        body:JSON.stringify({...payload, app_password:''})});
      if(!res.ok){const d=await res.json();throw new Error(d.error||'Failed')}
    } else {
      await api('/api/setup-account',{method:'POST',body:JSON.stringify(payload)});
    }
    toast('✅ Saved'); document.getElementById('acPass').value=''; bootApp();
  }catch(e){toast('❌ '+e.message,true)}
}

async function testEmail(){
  try{
    document.getElementById('testRes').innerHTML='<div style="color:var(--nwarn)">⏳ Testing…</div>';
    const d=await api('/api/test-email',{method:'POST',body:JSON.stringify({
      email:document.getElementById('acEmail').value,
      app_password:document.getElementById('acPass').value
    })});
    document.getElementById('testRes').innerHTML=`<div style="background:rgba(0,255,179,.1);border:1px solid rgba(0,255,179,.4);padding:12px;border-radius:10px;color:var(--ng);font-size:13px">${d.message}<br><b>Total:</b> ${d.total_emails||0} | <b>Unseen:</b> ${d.unseen_emails||0}</div>`;
    document.getElementById('emailDot').className='dot on';
  }catch(e){
    document.getElementById('testRes').innerHTML=`<div style="background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.4);padding:12px;border-radius:10px;color:var(--dang);font-size:13px">${e.message}</div>`;
    document.getElementById('emailDot').className='dot off';
  }
}

// ============ KEYS ============
function toggleMode(){
  document.getElementById('daysWrap').style.display = document.getElementById('keyMode').value==='lifetime'?'none':'flex';
}
async function genKey(){
  try{
    const mode=document.getElementById('keyMode').value;
    const days=parseInt(document.getElementById('keyDays').value)||30;
    const rate_limit=parseInt(document.getElementById('keyRate').value)||60;
    const d=await api('/api/generate-key',{method:'POST',body:JSON.stringify({
      mode,days,rate_limit,label:document.getElementById('keyLabel').value
    })});
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

// ============ HISTORY ============
async function loadHistory(){
  try{
    const txns=await api('/api/transactions');
    const el=document.getElementById('txnList');
    if(!txns.length){el.innerHTML='<div class="empty"><div class="empty-ic">📜</div>No transactions yet</div>';return}
    el.innerHTML=txns.map(t=>`<div class="txn">
      <div><div class="amt">+ ₹${t.amount.toFixed(2)}</div>
      <div class="meta">${esc(t.txn_id)||'-'} · UTR ${esc(t.utr)||'-'}</div></div>
      <div style="font-size:11px;color:var(--dim);text-align:right">${esc(t.paid_at)||''}<br>${esc(t.order_id)||''}</div>
    </div>`).join('');
  }catch(e){toast('❌ '+e.message,true)}
}

// ============ PARTIALS ============
async function loadPartials(){
  try{
    const ps=await api('/api/partial-payments');
    const el=document.getElementById('partialList');
    if(!ps.length){el.innerHTML='<div class="empty"><div class="empty-ic">✨</div>No partial payments — all clean!</div>';return}
    el.innerHTML=ps.map(p=>`<div class="txn partial">
      <div><div class="amt">₹${p.received.toFixed(2)} / ₹${p.expected.toFixed(2)}</div>
      <div class="meta">Short by ₹${(p.short_by||0).toFixed(2)} · Txn ${esc(p.txn_id)||'-'}</div></div>
      <div style="font-size:11px;color:var(--dim);text-align:right">${esc(p.created_at)}<br>${esc(p.order_id)}</div>
    </div>`).join('');
  }catch(e){toast('❌ '+e.message,true)}
}

// ============ AUDIT ============
async function loadAudit(){
  try{
    const r = await fetch('/api/audit-log', {credentials:'same-origin'});
    const list = await r.json();
    const el = document.getElementById('auditList');
    if(!list.length){el.innerHTML='<div class="empty"><div class="empty-ic">🔍</div>No logs</div>';return}
    el.innerHTML = list.map(l=>`<div class="txn"><div><div style="font-weight:700;font-size:12px">${esc(l.action)}</div>
      <div class="meta">${esc(l.details||'')}</div></div>
      <div style="font-size:11px;color:var(--dim);text-align:right">${esc(l.created_at)}<br>${esc(l.ip||'')}</div>
    </div>`).join('');
  }catch(e){toast('❌ '+e.message,true)}
}

// ============ SETTINGS ============
async function loadSettings(){
  try{
    const me = await api('/api/me');
    document.getElementById('autoSel').value = me.auto_verify ? '1' : '0';
  }catch(e){}
}
async function saveSettings(){
  try{
    const theme = document.getElementById('themeSel').value;
    const auto_verify = parseInt(document.getElementById('autoSel').value);
    applyTheme(theme);
    const me = await api('/api/me');
    await api('/api/setup-account', {method:'POST', body:JSON.stringify({
      full_name: me.full_name, upi_id: me.upi_id, mobile: me.mobile,
      email: me.email, default_qr_minutes: me.default_qr_minutes,
      tolerance: me.tolerance, webhook_url: me.webhook_url,
      auto_verify, theme
    })});
    toast('✅ Settings saved');
  }catch(e){toast('❌ '+e.message,true)}
}

// ============ INIT ============
(async()=>{try{await api('/api/me');bootApp()}catch{}})();
</script></body></html>
"""

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

@app.route('/')
def home(): return render_template_string(MAIN_HTML)

@app.route('/health')
def health(): return jsonify({"status":"ok", "version":APP_VERSION, "time": time.time()})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), threaded=True)

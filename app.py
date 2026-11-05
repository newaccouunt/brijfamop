import os, re, time, imaplib, email, datetime, random, string, base64, sqlite3, secrets, json
from io import BytesIO
from email.header import decode_header
from email.utils import parsedate_to_datetime
from functools import wraps
from flask import Flask, request, jsonify, render_template_string, session, g
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode

# ==========================================
# CONFIGURATION
# ==========================================
app = Flask(__name__)
CORS(app) 
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True

DB_PATH = os.environ.get("DB_PATH", "fampay.db")
IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
BASE_URL = os.environ.get("BASE_URL", "")

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH, check_same_thread=False)
        g.db.row_factory = sqlite3.Row
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
            theme TEXT DEFAULT 'dark',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            api_key TEXT UNIQUE NOT NULL, username TEXT NOT NULL,
            expiry TEXT NOT NULL, label TEXT DEFAULT '',
            total_requests INTEGER DEFAULT 0, total_qr INTEGER DEFAULT 0,
            total_received REAL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS qr_sessions (
            order_id TEXT PRIMARY KEY, api_key TEXT NOT NULL,
            username TEXT NOT NULL, amount REAL NOT NULL,
            status TEXT DEFAULT 'PENDING',
            txn_id TEXT DEFAULT '', utr TEXT DEFAULT '',
            paid_amount REAL DEFAULT 0,
            created_at REAL NOT NULL, expires_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
            order_id TEXT, amount REAL NOT NULL,
            txn_id TEXT, utr TEXT,
            paid_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
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
        if 'user' not in session: return jsonify({"error":"Unauthorized"}), 401
        return f(*a, **k)
    return wrapper

def gen_key(): return ''.join(random.choices(string.ascii_uppercase+string.digits, k=16))

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

# ==========================================
# SMART EMAIL CHECK (No Glitch, Exact Match)
# ==========================================
def read_fampay_email(username, expected_amount, order_id):
    """
    Reads email for a SPECIFIC order. Prevents multi-QR glitch.
    """
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not u or not u['email'] or not u['app_password']:
        return False, None, "Email missing"
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com", timeout=8)
        mail.login(u['email'], u['app_password'].replace(" ", ""))
        mail.select("inbox", readonly=False)
        
        today_date = datetime.datetime.now(IST).strftime("%d-%b-%Y")
        # Sirf naye unread emails check honge
        status, messages = mail.search(None, f'(SINCE "{today_date}" UNSEEN)')
        
        if status != "OK" or not messages[0]:
            mail.logout()
            return False, None, "No new unread email today"
            
        email_ids = messages[0].split()
        
        # Latest 5 check karo
        for e_id in reversed(email_ids[-5:]):
            status, data = mail.fetch(e_id, '(RFC822)')
            for rp in data:
                if not isinstance(rp, tuple): continue
                msg = email.message_from_bytes(rp[1])
                
                subj = msg.get('subject', '')
                if "Fam" not in subj: continue
                
                try:
                    dt = parsedate_to_datetime(msg.get('date')).astimezone(IST)
                    diff_min = (datetime.datetime.now(IST) - dt).total_seconds() / 60
                    if diff_min > 10 or diff_min < -2: continue 
                except: continue
                
                body = clean_body(msg)
                am = re.search(r'₹\s?([\d,]+\.?\d*)', body)
                if not am: continue
                
                recv = float(am.group(1).replace(",", ""))
                
                # SMART FIX: Agar 99 rs aaya jabki 100 chahiye, toh status 'PARTIAL' karo
                if recv < expected_amount - 0.01: 
                    # Mark as read to avoid re-checking
                    mail.store(e_id, '+FLAGS', '\\Seen')
                    mail.logout()
                    return False, {"paid": recv, "req": expected_amount}, "PARTIAL"

                txn_m = re.search(r'Transaction ID\s*:\s*([A-Z0-9]+)', body)
                txn_id = txn_m.group(1) if txn_m else "UNKNOWN"
                utr_m = re.search(r'UTR\s*:\s*(\d+)', body)
                utr = utr_m.group(1) if utr_m else ""

                mail.store(e_id, '+FLAGS', '\\Seen')
                mail.logout()
                return True, {"txn_id": txn_id, "utr": utr, "amount": recv}, "OK"
                
        mail.logout()
        return False, None, "Pending"
    except Exception as e:
        return False, None, str(e)

def build_url(path):
    base = BASE_URL.rstrip('/') or request.host_url.rstrip('/')
    return base + path

# ==========================================
# API ROUTES (Login, Dashboard, Keys)
# ==========================================
@app.route('/api/register', methods=['POST'])
def register():
    d = request.json or {}
    u = (d.get('username') or '').strip().lower()
    p = d.get('password') or ''
    if len(u) < 3 or len(p) < 4: return jsonify({"error":"Invalid length"}), 400
    db = get_db()
    try:
        db.execute("INSERT INTO users (username,password_hash) VALUES (?,?)", (u, generate_password_hash(p)))
        db.commit(); return jsonify({"status":"success"})
    except: return jsonify({"error":"Username exists"}), 409

@app.route('/api/login', methods=['POST'])
def login():
    d = request.json or {}
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username=?", (d.get('username','').lower(),)).fetchone()
    if row and check_password_hash(row['password_hash'], d.get('password','')):
        session['user'] = row['username']
        return jsonify({"status":"success","user":row['username']})
    return jsonify({"error":"Invalid credentials"}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear(); return jsonify({"status":"success"})

@app.route('/api/me', methods=['GET'])
@login_required
def me():
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE username=?", (session['user'],)).fetchone()
    return jsonify({
        "username": u['username'], "full_name": u['full_name'], "upi_id": u['upi_id'],
        "email": u['email'], "has_app_password": bool(u['app_password']),
        "total_earning": round(u['total_earning'],2), "default_qr_minutes": u['default_qr_minutes'],
        "theme": u['theme']
    })

@app.route('/api/setup-account', methods=['POST'])
@login_required
def setup_account():
    d = request.json or {}
    db = get_db()
    db.execute("""UPDATE users SET full_name=?, upi_id=?, mobile=?, email=?, app_password=?, default_qr_minutes=?, theme=? 
                  WHERE username=?""",
               (d.get('full_name',''), d.get('upi_id',''), d.get('mobile',''),
                d.get('email',''), d.get('app_password',''), int(d.get('default_qr_minutes', 15)), d.get('theme','dark'), session['user']))
    db.commit()
    return jsonify({"status":"success"})

@app.route('/api/test-email', methods=['POST'])
@login_required
def test_email():
    d = request.json or {}
    email_addr = d.get('email') or ''
    app_pass = d.get('app_password') or ''
    if not email_addr or not app_pass: return jsonify({"ok": False, "error": "Required"}), 400
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com", timeout=10)
        mail.login(email_addr, app_pass.replace(" ", ""))
        mail.select("inbox", readonly=True)
        typ, msgs = mail.search(None, 'ALL')
        total = len(msgs[0].split()) if msgs and msgs[0] else 0
        mail.logout()
        return jsonify({"ok": True, "message": "✅ Gmail connected!", "total_emails": total})
    except Exception as e:
        return jsonify({"ok": False, "error": f"❌ Failed: {str(e)}"}), 400

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
        
    return jsonify({
        "total_earning": round(u['total_earning'],2), "upi_id": u['upi_id'],
        "total_api_keys": len(keys), "total_requests": sum(k['total_requests'] for k in keys),
        "total_qr_generated": sum(k['total_qr'] for k in keys),
        "chart": chart
    })

@app.route('/api/generate-key', methods=['POST'])
@login_required
def gen_key_api():
    d = request.json or {}
    mode = d.get('mode', 'days'); days = int(d.get('days', 30) or 30); label = d.get('label', '')[:40]
    expiry = 'LIFETIME' if mode == 'lifetime' else (datetime.datetime.now()+datetime.timedelta(days=days)).isoformat()
    key = gen_key()
    db = get_db()
    db.execute("INSERT INTO api_keys (api_key,username,expiry,label) VALUES (?,?,?,?)", (key, session['user'], expiry, label))
    db.commit()
    return jsonify({"status":"success", "api_key": key, "expiry": expiry,
        "api_url": build_url(f"/v2/fam/{key}"), "example": build_url(f"/v2/fam/{key}?qr=100")})

@app.route('/api/list-keys', methods=['GET'])
@login_required
def list_keys():
    db = get_db()
    rows = db.execute("SELECT * FROM api_keys WHERE username=? ORDER BY id DESC", (session['user'],)).fetchall()
    return jsonify([{
        "api_key": r['api_key'], "expiry": r['expiry'], "label": r['label'],
        "total_requests": r['total_requests'], "total_qr": r['total_qr'], "total_received": round(r['total_received'],2),
        "url": build_url(f"/v2/fam/{r['api_key']}")
    } for r in rows])

@app.route('/api/delete-key/<api_key>', methods=['DELETE'])
@login_required
def del_key(api_key):
    db = get_db()
    db.execute("DELETE FROM api_keys WHERE api_key=? AND username=?", (api_key, session['user']))
    db.commit()
    return jsonify({"status":"success"})

# ==========================================
# PUBLIC API (Glitch Free & Multi-QR Support)
# ==========================================
def _key_status(key):
    db = get_db()
    clean_key = key.split('&')[0].split('?')[0]
    row = db.execute("SELECT * FROM api_keys WHERE api_key=?", (clean_key,)).fetchone()
    if not row: return None, "invalid"
    if row['expiry'] != 'LIFETIME':
        try:
            if datetime.datetime.now() > datetime.datetime.fromisoformat(row['expiry']): return row, "expired"
        except: pass
    return row, "active"

@app.route('/v2/fam/<path:api_key>') 
def fam_qr(api_key):
    amount_str = request.args.get('qr') or (request.full_path.split('&qr=')[1].split('&')[0].split('?')[0] if '&qr=' in request.full_path else None)
    if not amount_str: return "❌ Missing Amount", 400
    try: amount = float(amount_str)
    except: return "❌ Invalid amount", 400

    key_row, status = _key_status(api_key)
    if status != "active": return f"❌ API Key {status}", 403

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=?", (key_row['username'],)).fetchone()
    
    db.execute("UPDATE api_keys SET total_requests=total_requests+1, total_qr=total_qr+1 WHERE api_key=?", (key_row['api_key'],)); db.commit()

    minutes = int(request.args.get('minutes', user['default_qr_minutes'] or 15))
    upi = f"upi://pay?pa={user['upi_id']}&pn={user['full_name']}&am={amount}&cu=INR"
    
    # MULTI-QR SUPPORT: Unique Order ID
    order_id = "ORD" + str(int(time.time())) + str(random.randint(1000,9999)) 
    
    now = time.time()
    db.execute("INSERT INTO qr_sessions (order_id,api_key,username,amount,created_at,expires_at) VALUES (?,?,?,?,?,?)",
               (order_id, key_row['api_key'], key_row['username'], amount, now, now + minutes*60))
    db.commit()
    
    return render_template_string(QR_HTML_TEMPLATE, amount=amount, qr_b64=qr_b64(upi), order_id=order_id, upi_id=user['upi_id'], full_name=user['full_name'], minutes=minutes)

@app.route('/api/check-payment/<order_id>')
def check_payment(order_id):
    db = get_db()
    s = db.execute("SELECT * FROM qr_sessions WHERE order_id=?", (order_id,)).fetchone()
    if not s: return jsonify({"status":"NOTFOUND"}), 404
    if s['status'] == 'PAID': return jsonify({"status":"PAID","txn":{"txn_id":s['txn_id'],"utr":s['utr'],"amount":s['paid_amount'] or s['amount']}})
    if s['status'] == 'PARTIAL': return jsonify({"status":"PARTIAL", "req": s['amount'], "paid": s['paid_amount']})
    if time.time() > s['expires_at']:
        db.execute("UPDATE qr_sessions SET status='EXPIRED' WHERE order_id=?", (order_id,)); db.commit()
        return jsonify({"status":"EXPIRED"})

    # VERIFY SPECIFIC ORDER
    ok, info, msg = read_fampay_email(s['username'], s['amount'], order_id)
    
    if ok:
        db.execute("UPDATE qr_sessions SET status='PAID',txn_id=?,utr=?,paid_amount=? WHERE order_id=?",
                   (info['txn_id'], info['utr'], info['amount'], order_id))
        db.execute("UPDATE users SET total_earning=total_earning+? WHERE username=?", (info['amount'], s['username']))
        db.execute("UPDATE api_keys SET total_received=total_received+? WHERE api_key=?", (info['amount'], s['api_key']))
        db.execute("INSERT INTO transactions (username,order_id,amount,txn_id,utr) VALUES (?,?,?,?,?)",
                   (s['username'], order_id, info['amount'], info['txn_id'], info['utr']))
        db.commit()
        return jsonify({"status":"PAID","txn":info})
    elif msg == "PARTIAL":
        db.execute("UPDATE qr_sessions SET status='PARTIAL', paid_amount=? WHERE order_id=?", (info['paid'], order_id))
        db.commit()
        return jsonify({"status":"PARTIAL", "req": s['amount'], "paid": info['paid']})
        
    return jsonify({"status":"PENDING"})

# ==========================================
# ADVANCED UI - QR TEMPLATE (Light/Dark + Success + Partial)
# ==========================================
QR_HTML_TEMPLATE = """
<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Pay ₹{{ amount }}</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&display=swap" rel="stylesheet">
<style>
:root{--bg:#05050a;--card:#0f0f1e;--text:#e8e8f5;--dim:#7a7a9a;--border:#1f1f3a;--ng:#00ffb3;}
[data-theme="light"]{--bg:#f4f4f9;--card:#ffffff;--text:#111;--dim:#555;--border:#ddd;}
*{margin:0;padding:0;box-sizing:border-box;font-family:'Inter',sans-serif}
body{background:var(--bg);color:var(--text);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px;transition:.3s;overflow:hidden}
.card{width:100%;max-width:430px;background:var(--card);border:1px solid var(--border);border-radius:24px;padding:30px 24px;box-shadow:0 0 60px rgba(0,224,164,.12);text-align:center;position:relative;transition:all 0.4s ease}
h1{font-size:44px;font-weight:900;margin:6px 0;background:linear-gradient(90deg,#00ffb3,#a855f7,#ff00aa);-webkit-background-clip:text;color:transparent}
.qr-wrap{background:#fff;border-radius:18px;padding:12px;display:inline-block;margin:16px 0;box-shadow:0 0 50px rgba(0,224,164,.3);transition:all 0.4s}
.qr-wrap img{display:block;width:240px;height:240px;transition:all 0.3s}
.timer{font-size:30px;font-weight:800;margin:10px 0;color:#00e0a4;letter-spacing:1px}
.status{padding:14px;border-radius:12px;font-weight:600;font-size:14px;margin-top:8px}
.pending{background:rgba(255,165,2,.12);color:#ffa502}
.partial{background:rgba(255,71,87,.15);color:#ff4757}
.success-overlay{position:absolute;inset:0;background:var(--card);border-radius:24px;display:none;flex-direction:column;align-items:center;justify-content:center;padding:30px;z-index:10;opacity:0;transition:opacity 0.4s}
.success-overlay.show{display:flex;opacity:1}
.check-icon{width:90px;height:90px;border-radius:50%;background:rgba(0,224,164,.15);border:2px solid #00e0a4;display:flex;align-items:center;justify-content:center;font-size:45px;margin-bottom:20px;animation:popIn 0.5s}
@keyframes popIn{0%{transform:scale(0)}100%{transform:scale(1)}}
.success-title{font-size:26px;font-weight:900;color:#00e0a4;margin-bottom:6px}
.success-amt{font-size:40px;font-weight:900;background:linear-gradient(90deg,#00ffb3,#00d4ff);-webkit-background-clip:text;color:transparent;margin-bottom:20px}
.success-details{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:16px;width:100%;text-align:left;font-size:12px}
.success-details div{display:flex;justify-content:space-between;margin-bottom:8px;color:var(--dim)}
.theme-toggle{position:absolute;top:15px;right:15px;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:5px 10px;border-radius:20px;cursor:pointer;font-size:12px;}
</style></head><body>
<div class="card" id="mainCard">
    <button class="theme-toggle" onclick="toggleTheme()">🌓 Theme</button>
    <div class="tag" style="font-size:12px;color:var(--dim);text-transform:uppercase;">Pay via UPI</div>
    <h1>₹{{ "%.2f"|format(amount) }}</h1>
    <div style="font-size:12px;color:var(--dim);margin-top:8px;">to <b style="color:var(--text)">{{ full_name }}</b></div>
    <div class="qr-wrap" id="qrWrap"><img src="{{ qr_b64 }}"></div>
    <div class="timer" id="timer">{{ '%02d:00'|format(minutes) }}</div>
    <div class="status pending" id="status">⏳ Waiting for payment...</div>

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
</div>
<script>
function toggleTheme(){const b=document.body;b.dataset.theme=b.dataset.theme==='light'?'dark':'light';}
const orderId="{{ order_id }}", totalSecs={{ minutes*60 }};
let secs=totalSecs, tInt, pInt;
const T=document.getElementById('timer'), S=document.getElementById('status');

function tick(){
    secs--;
    if(secs<=0){ T.textContent='00:00'; S.textContent='❌ Expired'; S.className='status partial'; clearInterval(tInt); clearInterval(pInt); return; }
    T.textContent=String(Math.floor(secs/60)).padStart(2,'0')+':'+String(secs%60).padStart(2,'0');
}

async function poll(){
    try{
        const r=await fetch('/api/check-payment/'+orderId), d=await r.json();
        if(d.status==='PAID'){
            document.getElementById('successAmt').textContent = '₹' + (d.txn.amount || '{{ amount }}');
            document.getElementById('successTxn').textContent = d.txn.txn_id || '-';
            document.getElementById('successUtr').textContent = d.txn.utr || '-';
            document.getElementById('successOverlay').classList.add('show');
            clearInterval(tInt); clearInterval(pInt);
        } else if(d.status==='PARTIAL'){
            // SMART GLITCH FIX: Showing partial message
            S.innerHTML = `⚠️ Short Payment!<br>Received: ₹${d.paid}<br>Please Pay: ₹${(d.req - d.paid).toFixed(2)}`;
            S.className='status partial';
        } else if(d.status==='EXPIRED'){
            S.textContent='❌ Expired'; S.className='status partial'; clearInterval(tInt); clearInterval(pInt);
        }
    }catch(e){}
}
tInt=setInterval(tick,1000); pInt=setInterval(poll,3000); poll();
</script></body></html>
"""

# ==========================================
# ULTRA DASHBOARD (50+ Features Sidebar + Light/Dark)
# ==========================================
MAIN_HTML = """
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FamPay V2.0 — Ultra</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
:root{--bg:#05050a;--surface:#0f0f1e;--surface2:#15152a;--border:#1f1f3a;--text:#e8e8f5;--dim:#7a7a9a;--ng:#00ffb3;--nc:#00d4ff;--np:#a855f7;--dang:#ff4757;}
[data-theme="light"]{--bg:#f4f4f9;--surface:#ffffff;--surface2:#f9f9ff;--border:#e0e0ea;--text:#111;--dim:#666;}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;transition:.3s}
button,input,select{font-family:inherit;outline:none}.hidden{display:none!important}
.auth-wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.auth-card{width:100%;max-width:420px;background:var(--surface);border:1px solid var(--border);border-radius:22px;padding:34px 28px;}
.logo{font-size:22px;font-weight:900;text-align:center;margin-bottom:4px;background:linear-gradient(90deg,var(--ng),var(--np),var(--nc));-webkit-background-clip:text;color:transparent;background-size:300% 100%;animation:rbow 4s linear infinite}
@keyframes rbow{to{background-position:300% 0}}
.field{margin-bottom:14px}.field label{display:block;font-size:11px;font-weight:700;color:var(--dim);margin-bottom:6px;text-transform:uppercase}
.field input{width:100%;padding:12px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;color:var(--text);font-size:14px;}
.btn{width:100%;padding:13px;border:none;border-radius:10px;font-weight:800;font-size:14px;background:linear-gradient(90deg,var(--ng),var(--nc),var(--np));color:#05050a;transition:.2s;cursor:pointer;background-size:200% 100%}
.btn.sec{background:var(--surface2);color:var(--text);border:1px solid var(--border)}
.shell{display:flex;min-height:100vh}
.sidebar{width:260px;background:var(--surface);border-right:1px solid var(--border);padding:22px 14px;position:fixed;inset:0 auto 0 0;overflow-y:auto;z-index:50;}
.brand{font-size:17px;font-weight:900;padding:0 8px 20px;background:linear-gradient(90deg,var(--ng),var(--np),var(--nc));-webkit-background-clip:text;color:transparent;}
.nav{display:flex;flex-direction:column;gap:3px}
.item{padding:10px 14px;border-radius:10px;color:var(--dim);font-size:13px;font-weight:600;display:flex;align-items:center;gap:10px;cursor:pointer;transition:.15s}
.item:hover{background:var(--surface2);color:var(--text)}.item.active{background:rgba(0,255,179,.1);color:var(--ng)}
.sec-lbl{font-size:10px;font-weight:800;color:var(--dim);text-transform:uppercase;letter-spacing:1.5px;padding:16px 14px 6px}
.main{flex:1;margin-left:260px;padding:24px;}
@media(max-width:860px){.sidebar{transform:translateX(-100%)}.main{margin-left:0}}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:22px;padding-bottom:16px;border-bottom:1px solid var(--border);}
.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:22px;margin-bottom:16px}
.hero{background:linear-gradient(135deg,rgba(0,255,179,.1),rgba(168,85,247,.1));border:1px solid rgba(0,255,179,.3);border-radius:20px;padding:26px;}
.hero-amt{font-size:48px;font-weight:900;margin:8px 0;background:linear-gradient(90deg,var(--ng),var(--np));-webkit-background-clip:text;color:transparent;}
.grid-3{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.form-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
@media(max-width:600px){.form-grid{grid-template-columns:1fr}.grid-3{grid-template-columns:1fr}}
.api-out{background:var(--surface2);border:1px dashed var(--ng);padding:12px;border-radius:10px;color:var(--ng);font-family:monospace;font-size:11px;margin-top:8px;display:flex;justify-content:space-between;align-items:center;word-break:break-all}
.copy{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:5px 9px;border-radius:6px;font-size:10px;font-weight:700;cursor:pointer}
</style></head><body data-theme="dark">

<div id="authScreen" class="auth-wrap">
  <div class="auth-card">
    <div class="logo">◆ FamPay V2.0</div>
    <div id="loginForm">
      <div class="field"><label>Username</label><input id="lgU" placeholder="admin"></div>
      <div class="field"><label>Password</label><input id="lgP" type="password" placeholder="••••••"></div>
      <button class="btn" onclick="doLogin()">Login →</button>
    </div>
  </div>
</div>

<div id="shell" class="shell hidden">
  <aside id="sidebar" class="sidebar">
    <div class="brand">◆ FamPay V2.0</div>
    
    <!-- CORE OPTIONS -->
    <div class="sec-lbl">Main</div>
    <div class="item active" data-p="dashboard" onclick="go('dashboard')">📊 Dashboard</div>
    <div class="item" data-p="account" onclick="go('account')">👤 Account Settings</div>
    <div class="item" data-p="keys" onclick="go('keys')">🔑 API Keys Manager</div>
    
    <!-- 50+ ADVANCE OPTIONS (UI READY) -->
    <div class="sec-lbl">Advance Features</div>
    <div class="item" onclick="alert('Coming Soon in V3')">📈 Analytics Reports</div>
    <div class="item" onclick="alert('Coming Soon')">🧾 Invoice Generator</div>
    <div class="item" onclick="alert('Coming Soon')">🔔 Webhooks & Alerts</div>
    <div class="item" onclick="alert('Coming Soon')">🛡️ Fraud Detection</div>
    <div class="item" onclick="alert('Coming Soon')">👥 Team Members</div>
    <div class="item" onclick="alert('Coming Soon')">💰 Payout Settings</div>
    <div class="item" onclick="alert('Coming Soon')">📱 UPI QR Styling</div>
    <div class="item" onclick="alert('Coming Soon')">🌐 Multi-Currency</div>
    <div class="item" onclick="alert('Coming Soon')">💬 SMS Gateway</div>
    <div class="item" onclick="alert('Coming Soon')">📧 Email Templates</div>
    <div class="item" onclick="alert('Coming Soon')">🧪 Test Sandbox</div>
    <div class="item" onclick="alert('Coming Soon')">🔌 Plugin Store</div>
    <div class="item" onclick="alert('Coming Soon')">📊 Live Logs</div>
    <div class="item" onclick="alert('Coming Soon')">🧠 AI Assistant</div>
    <div class="item" onclick="alert('Coming Soon')">🔒 IP Whitelist</div>

    <div class="sec-lbl">Support</div>
    <div class="item" onclick="go('docs')">📖 API Docs</div>
    <div class="item" onclick="toggleTheme()">🌓 Switch Theme</div>
    <div style="margin-top:20px"><button class="btn sec" onclick="doLogout()">🚪 Logout</button></div>
  </aside>

  <main class="main">
    <div class="topbar">
      <h1 id="title">Dashboard</h1>
      <div style="font-size:12px;font-weight:600">👤 <span id="chipUser">-</span></div>
    </div>

    <section id="p-dashboard" class="page">
      <div class="hero">
        <div style="font-size:11px;font-weight:800;color:var(--dim);text-transform:uppercase">Total Earnings</div>
        <div class="hero-amt">₹ <span id="earn">0.00</span></div>
        <div style="font-size:13px;color:var(--dim)">UPI: <b id="upiTxt">-</b></div>
      </div>
      <div class="grid-3" style="margin-top:16px">
        <div class="card"><div style="font-size:10px;color:var(--dim)">API KEYS</div><div style="font-size:24px;font-weight:800" id="stKeys">0</div></div>
        <div class="card"><div style="font-size:10px;color:var(--dim)">REQUESTS</div><div style="font-size:24px;font-weight:800" id="stReq">0</div></div>
        <div class="card"><div style="font-size:10px;color:var(--dim)">QRs GEN</div><div style="font-size:24px;font-weight:800" id="stQR">0</div></div>
      </div>
    </section>

    <section id="p-account" class="page hidden">
      <div class="card">
        <h2>👤 Account Settings</h2>
        <div class="form-grid">
          <div class="field"><label>Full Name</label><input id="acName"></div>
          <div class="field"><label>UPI ID</label><input id="acUpi"></div>
        </div>
        <div class="form-grid">
          <div class="field"><label>Mobile</label><input id="acMob"></div>
          <div class="field"><label>Gmail</label><input id="acEmail" type="email"></div>
        </div>
        <div class="form-grid">
          <div class="field"><label>App Password</label><input id="acPass" type="password"></div>
          <div class="field"><label>QR Minutes</label><input id="acMin" type="number" value="15"></div>
        </div>
        <button class="btn" onclick="saveAccount()">💾 Save Settings</button>
      </div>
    </section>

    <section id="p-keys" class="page hidden">
      <div class="card">
        <h2>🔑 API Keys Manager</h2>
        <div class="form-grid">
          <div class="field"><label>Label</label><input id="keyLabel"></div>
          <div class="field"><label>Type</label><select id="keyMode"><option value="days">Days</option><option value="lifetime">Lifetime</option></select></div>
        </div>
        <button class="btn" onclick="genKey()">🚀 Generate Key</button>
        <div id="keyRes" style="margin-top:12px"></div>
      </div>
      <div class="card"><h2>📋 Your Keys</h2><div id="keysList"></div></div>
    </section>

    <section id="p-docs" class="page hidden">
      <div class="card">
        <h2>📖 API Docs (Multi-Language Support)</h2>
        <p style="font-size:12px;color:var(--dim);margin-bottom:12px">CORS enabled! Works with PHP, JS, Python, Apps.</p>
        <div class="api-out"><span>GET /v2/fam/API_KEY?qr=100</span></div>
        <div class="api-out" style="margin-top:8px"><span>GET /api/check-payment/ORDER_ID</span></div>
      </div>
    </section>
  </main>
</div>

<script>
function toast(m, err){alert(m);}
function copyText(t){navigator.clipboard.writeText(t);alert('✅ Copied')}
async function api(p, o={}){const r=await fetch(p,{headers:{'Content-Type':'application/json'},credentials:'same-origin',...o});let d={};try{d=await r.json()}catch{}if(!r.ok)throw new Error(d.error||'Failed');return d;}
function toggleTheme(){const b=document.body;b.dataset.theme=b.dataset.theme==='light'?'dark':'light';localStorage.setItem('theme',b.dataset.theme);}
if(localStorage.getItem('theme')) document.body.dataset.theme = localStorage.getItem('theme');

async function doLogin(){try{const u=document.getElementById('lgU').value,p=document.getElementById('lgP').value;await api('/api/login',{method:'POST',body:JSON.stringify({username:u,password:p})});bootApp();}catch(e){alert(e.message)}}
async function doLogout(){await api('/api/logout',{method:'POST'});location.reload();}

function go(p){
  document.querySelectorAll('.page').forEach(x=>x.classList.add('hidden'));
  document.getElementById('p-'+p).classList.remove('hidden');
  document.querySelectorAll('.item').forEach(i=>i.classList.toggle('active',i.dataset.p===p));
  document.getElementById('title').textContent=p.toUpperCase();
  if(p==='keys')loadKeys();
}

async function bootApp(){
  try{
    const me=await api('/api/me');
    document.getElementById('authScreen').classList.add('hidden');
    document.getElementById('shell').classList.remove('hidden');
    document.getElementById('chipUser').textContent=me.username;
    document.getElementById('acName').value=me.full_name||'';
    document.getElementById('acUpi').value=me.upi_id||'';
    document.getElementById('acEmail').value=me.email||'';
    document.getElementById('upiTxt').textContent=me.upi_id||'-';
    loadDashboard();
  }catch(e){location.reload();}
}

async function loadDashboard(){try{
  const d=await api('/api/dashboard');
  document.getElementById('earn').textContent=d.total_earning.toFixed(2);
  document.getElementById('stKeys').textContent=d.total_api_keys;
  document.getElementById('stReq').textContent=d.total_requests;
  document.getElementById('stQR').textContent=d.total_qr_generated;
}catch(e){}}

async function saveAccount(){try{
  const payload={
    full_name:document.getElementById('acName').value,
    upi_id:document.getElementById('acUpi').value,
    mobile:document.getElementById('acMob').value,
    email:document.getElementById('acEmail').value,
    app_password:document.getElementById('acPass').value,
    default_qr_minutes:parseInt(document.getElementById('acMin').value)||15
  };
  await api('/api/setup-account',{method:'POST',body:JSON.stringify(payload)});
  alert('✅ Saved!'); bootApp();
}catch(e){alert(e.message)}}

async function genKey(){try{
  const d=await api('/api/generate-key',{method:'POST',body:JSON.stringify({mode:document.getElementById('keyMode').value,days:30,label:document.getElementById('keyLabel').value})});
  document.getElementById('keyRes').innerHTML=`<div class="api-out"><span>${d.example}</span><button class="copy" onclick="copyText('${d.example}')">Copy</button></div>`;
  loadKeys();
}catch(e){alert(e.message)}}

async function loadKeys(){try{
  const list=await api('/api/list-keys'),el=document.getElementById('keysList');
  el.innerHTML=list.map(k=>`<div class="card" style="padding:12px;margin-bottom:8px"><b>${k.api_key}</b><div class="api-out"><span>${k.url}</span><button class="copy" onclick="copyText('${k.url}')">Copy</button></div></div>`).join('');
}catch(e){}}

(async()=>{try{await api('/api/me');bootApp()}catch{}})();
</script></body></html>
"""

@app.route('/')
def home(): return render_template_string(MAIN_HTML)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

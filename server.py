"""
Animioo – Produktions-Server v2
Auth + KI-Analyse + Stripe Payments + Admin
+ bcrypt, rate limiting, email, Sentry, PostgreSQL
"""
from flask import Flask, request, jsonify, send_from_directory, redirect
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import anthropic, hashlib, secrets, os, json, smtplib, logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from functools import wraps

# ═══════════════════════════════════════════════════
# APP SETUP
# ═══════════════════════════════════════════════════
app = Flask(__name__, static_folder='static', static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app, supports_credentials=True)

# Sentry Error-Monitoring
SENTRY_DSN = os.environ.get('SENTRY_DSN', '')
if SENTRY_DSN:
    try:
        import sentry_sdk
        from sentry_sdk.integrations.flask import FlaskIntegration
        sentry_sdk.init(dsn=SENTRY_DSN, integrations=[FlaskIntegration()],
                        traces_sample_rate=0.2, environment=os.environ.get('RAIL_ENVIRONMENT','production'))
        app.logger.info('Sentry initialisiert')
    except ImportError:
        app.logger.warning('sentry-sdk nicht installiert')

# Rate Limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per minute"],
                  storage_uri="memory://")

# ═══════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════
ANTHROPIC_API_KEY    = os.environ.get('ANTHROPIC_API_KEY', '')
OPENAI_API_KEY       = os.environ.get('OPENAI_API_KEY', '')
GEMINI_API_KEY       = os.environ.get('GEMINI_API_KEY', '')
STRIPE_SECRET_KEY    = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_PUB_KEY       = os.environ.get('STRIPE_PUBLISHABLE_KEY', '')
STRIPE_WEBHOOK_SEC   = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
STRIPE_PRICE_STARTER = os.environ.get('STRIPE_PRICE_STARTER', '')
STRIPE_PRICE_PRO     = os.environ.get('STRIPE_PRICE_PRO', '')
APP_URL              = os.environ.get('APP_URL', 'http://localhost:5000')
DATABASE_URL         = os.environ.get('DATABASE_URL', '')
DB_PATH              = 'animioo.db'

# E-Mail Config
SMTP_HOST = os.environ.get('SMTP_HOST', '')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
SMTP_FROM = os.environ.get('SMTP_FROM', 'noreply@animioo.de')

# ═══════════════════════════════════════════════════
# DATENBANK (PostgreSQL mit SQLite-Fallback)
# ═══════════════════════════════════════════════════
USE_POSTGRES = bool(DATABASE_URL)

def get_db():
    if USE_POSTGRES:
        import psycopg2, psycopg2.extras
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        return conn
    else:
        import sqlite3
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

def db_execute(conn, query, params=None):
    """Execute query with PostgreSQL/SQLite compatibility."""
    if USE_POSTGRES:
        # Convert ? placeholders to %s for PostgreSQL
        query = query.replace('?', '%s')
    cur = conn.cursor()
    cur.execute(query, params or ())
    return cur

def db_fetchone(conn, query, params=None):
    if USE_POSTGRES:
        import psycopg2.extras
        query = query.replace('?', '%s')
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(query, params or ())
        return cur.fetchone()
    else:
        return conn.execute(query, params or ()).fetchone()

def db_fetchall(conn, query, params=None):
    if USE_POSTGRES:
        import psycopg2.extras
        query = query.replace('?', '%s')
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(query, params or ())
        return cur.fetchall()
    else:
        return [dict(r) for r in conn.execute(query, params or ()).fetchall()]

def db_dict(row):
    """Convert a row to dict."""
    if row is None:
        return None
    if isinstance(row, dict):
        return row
    return dict(row)

def init_db():
    conn = get_db()
    if USE_POSTGRES:
        cur = conn.cursor()
        tables = [
            '''CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT DEFAULT '',
                praxis TEXT DEFAULT '',
                plan TEXT DEFAULT 'trial',
                active INTEGER DEFAULT 1,
                role TEXT DEFAULT 'customer',
                analyses_used INTEGER DEFAULT 0,
                analyses_limit INTEGER DEFAULT 3,
                stripe_customer_id TEXT DEFAULT '',
                stripe_subscription_id TEXT DEFAULT '',
                email_verified INTEGER DEFAULT 0,
                verify_token TEXT DEFAULT '',
                reset_token TEXT DEFAULT '',
                reset_expires TEXT DEFAULT '',
                trial_ends_at TEXT DEFAULT '',
                created_at TEXT,
                last_login TEXT
            )''',
            '''CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT
            )''',
            '''CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                pet_name TEXT DEFAULT '',
                species TEXT,
                region TEXT,
                mode TEXT,
                severity TEXT,
                report_text TEXT,
                image_data TEXT DEFAULT '',
                created_at TEXT
            )''',
            '''CREATE TABLE IF NOT EXISTS leads (
                id TEXT PRIMARY KEY,
                name TEXT, contact TEXT, email TEXT,
                phone TEXT, message TEXT,
                status TEXT DEFAULT 'new',
                source TEXT DEFAULT 'Website',
                created_at TEXT
            )''',
            '''CREATE TABLE IF NOT EXISTS payments (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                stripe_session_id TEXT,
                plan TEXT,
                amount INTEGER,
                status TEXT DEFAULT 'pending',
                created_at TEXT
            )''',
            '''CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                action TEXT, user_id TEXT,
                detail TEXT, created_at TEXT
            )'''
        ]
        for t in tables:
            try:
                cur.execute(t)
            except Exception as e:
                app.logger.warning(f'Table creation: {e}')
        conn.commit()
    else:
        import sqlite3
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT DEFAULT "",
                praxis TEXT DEFAULT "",
                plan TEXT DEFAULT "trial",
                active INTEGER DEFAULT 1,
                role TEXT DEFAULT "customer",
                analyses_used INTEGER DEFAULT 0,
                analyses_limit INTEGER DEFAULT 3,
                stripe_customer_id TEXT DEFAULT "",
                stripe_subscription_id TEXT DEFAULT "",
                email_verified INTEGER DEFAULT 0,
                verify_token TEXT DEFAULT "",
                reset_token TEXT DEFAULT "",
                reset_expires TEXT DEFAULT "",
                trial_ends_at TEXT DEFAULT "",
                created_at TEXT,
                last_login TEXT
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                pet_name TEXT DEFAULT "",
                species TEXT,
                region TEXT,
                mode TEXT,
                severity TEXT,
                report_text TEXT,
                image_data TEXT DEFAULT "",
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS leads (
                id TEXT PRIMARY KEY,
                name TEXT, contact TEXT, email TEXT,
                phone TEXT, message TEXT,
                status TEXT DEFAULT "new",
                source TEXT DEFAULT "Website",
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS payments (
                id TEXT PRIMARY KEY,
                user_id TEXT,
                stripe_session_id TEXT,
                plan TEXT,
                amount INTEGER,
                status TEXT DEFAULT "pending",
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT, user_id TEXT,
                detail TEXT, created_at TEXT
            );
        ''')

    # Migrate: add new columns if missing (for existing DBs)
    try:
        db_execute(conn, "ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0")
    except: pass
    try:
        db_execute(conn, "ALTER TABLE users ADD COLUMN verify_token TEXT DEFAULT ''")
    except: pass
    try:
        db_execute(conn, "ALTER TABLE users ADD COLUMN reset_token TEXT DEFAULT ''")
    except: pass
    try:
        db_execute(conn, "ALTER TABLE users ADD COLUMN reset_expires TEXT DEFAULT ''")
    except: pass
    try:
        db_execute(conn, "ALTER TABLE users ADD COLUMN pet_name TEXT DEFAULT ''")
    except: pass
    try:
        db_execute(conn, "ALTER TABLE reports ADD COLUMN image_data TEXT DEFAULT ''")
    except: pass

    # Admin-User anlegen oder Passwort aktualisieren
    try:
        existing = db_fetchone(conn, 'SELECT id FROM users WHERE email=?', ('admin@animioo.de',))
        if existing:
            db_execute(conn, 'UPDATE users SET password=? WHERE email=?', (hash_pw('admin123'), 'admin@animioo.de'))
            app.logger.info('Admin-Passwort aktualisiert')
        else:
            trial_end = (datetime.now() + timedelta(days=14)).isoformat()
            db_execute(conn, '''INSERT INTO users
                (id,email,password,name,praxis,plan,active,role,analyses_used,analyses_limit,email_verified,trial_ends_at,created_at)
                VALUES (?,?,?,?,?,?,1,?,?,?,1,?,?)''',
                ('admin1','admin@animioo.de',hash_pw('admin123'),'Administrator','Animioo GmbH','admin','admin',0,999999,trial_end,datetime.now().isoformat()))
            app.logger.info('Admin-User erstellt')
    except Exception as e:
        app.logger.error(f'Admin-User Fehler: {e}')
    conn.commit()
    if USE_POSTGRES:
        conn.close()
    else:
        conn.close()

# ═══════════════════════════════════════════════════
# PASSWORT HASHING (bcrypt mit SHA256-Fallback)
# ═══════════════════════════════════════════════════
try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

def hash_pw(pw):
    if HAS_BCRYPT:
        return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    return hashlib.sha256(pw.encode()).hexdigest()

def check_pw(pw, hashed):
    if HAS_BCRYPT and hashed.startswith('$2'):
        return bcrypt.checkpw(pw.encode(), hashed.encode())
    # Fallback: SHA256 (alte Passwörter)
    return hashlib.sha256(pw.encode()).hexdigest() == hashed

def nid():   return secrets.token_hex(8)
def now():   return datetime.now().isoformat()

# ═══════════════════════════════════════════════════
# E-MAIL
# ═══════════════════════════════════════════════════
def send_email(to, subject, html_body):
    """Send email via SMTP. Returns True on success."""
    if not SMTP_HOST or not SMTP_USER:
        app.logger.warning(f'E-Mail nicht gesendet (SMTP nicht konfiguriert): {subject} -> {to}')
        return False
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = SMTP_FROM
        msg['To'] = to
        msg['Subject'] = subject
        msg.attach(MIMEText(html_body, 'html'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        app.logger.error(f'E-Mail Fehler: {e}')
        return False

def send_verify_email(email, token):
    link = f"{APP_URL}/app?verify={token}"
    send_email(email, 'Animioo – E-Mail bestätigen', f'''
        <div style="font-family:Inter,sans-serif;max-width:500px;margin:0 auto;padding:30px;">
            <h2 style="color:#0f172a;">E-Mail-Adresse bestätigen</h2>
            <p style="color:#475569;">Klicken Sie auf den Button, um Ihre E-Mail-Adresse zu bestätigen:</p>
            <a href="{link}" style="display:inline-block;padding:12px 24px;background:#1a56db;color:#fff;border-radius:6px;text-decoration:none;font-weight:700;">E-Mail bestätigen</a>
            <p style="color:#94a3b8;font-size:12px;margin-top:20px;">Falls Sie sich nicht registriert haben, ignorieren Sie diese E-Mail.</p>
        </div>''')

def send_reset_email(email, token):
    link = f"{APP_URL}/app?reset={token}"
    send_email(email, 'Animioo – Passwort zurücksetzen', f'''
        <div style="font-family:Inter,sans-serif;max-width:500px;margin:0 auto;padding:30px;">
            <h2 style="color:#0f172a;">Passwort zurücksetzen</h2>
            <p style="color:#475569;">Klicken Sie auf den Button, um ein neues Passwort zu setzen. Der Link ist 1 Stunde gültig.</p>
            <a href="{link}" style="display:inline-block;padding:12px 24px;background:#1a56db;color:#fff;border-radius:6px;text-decoration:none;font-weight:700;">Neues Passwort setzen</a>
            <p style="color:#94a3b8;font-size:12px;margin-top:20px;">Falls Sie kein neues Passwort angefordert haben, ignorieren Sie diese E-Mail.</p>
        </div>''')

def send_admin_notification(subject, body):
    """Send notification to admin."""
    send_email('admin@animioo.de', f'Animioo Admin: {subject}', f'''
        <div style="font-family:Inter,sans-serif;max-width:500px;margin:0 auto;padding:30px;">
            <h3 style="color:#0f172a;">{subject}</h3>
            <p style="color:#475569;">{body}</p>
            <p style="color:#94a3b8;font-size:11px;margin-top:20px;">Animioo Admin-Benachrichtigung</p>
        </div>''')

# ═══════════════════════════════════════════════════
# AUDIT
# ═══════════════════════════════════════════════════
def audit(action, uid, detail=''):
    try:
        conn = get_db()
        db_execute(conn, 'INSERT INTO audit_log (action,user_id,detail,created_at) VALUES (?,?,?,?)',(action,uid,detail,now()))
        conn.commit(); conn.close()
    except: pass

# ═══════════════════════════════════════════════════
# AUTH MIDDLEWARE
# ═══════════════════════════════════════════════════
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization','').replace('Bearer ','').strip()
        if not token: return jsonify({'error':'Nicht angemeldet'}), 401
        conn = get_db()
        sess = db_dict(db_fetchone(conn, 'SELECT * FROM sessions WHERE token=? AND expires_at>?',(token,now())))
        if not sess: conn.close(); return jsonify({'error':'Sitzung abgelaufen – bitte neu anmelden'}), 401
        user = db_dict(db_fetchone(conn, 'SELECT * FROM users WHERE id=? AND active=1',(sess['user_id'],)))
        conn.close()
        if not user: return jsonify({'error':'Account nicht gefunden oder deaktiviert'}), 403
        request.user = user
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def dec(*args, **kwargs):
        if request.user.get('role') != 'admin':
            return jsonify({'error':'Kein Admin-Zugang'}), 403
        return f(*args, **kwargs)
    return require_auth(dec)

# ═══════════════════════════════════════════════════
# STATIC ROUTES
# ═══════════════════════════════════════════════════
@app.route('/')
def index(): return send_from_directory('static','index.html')

@app.route('/app')
def platform(): return send_from_directory('static','app.html')

@app.route('/admin')
def admin_page(): return send_from_directory('static','admin.html')

@app.route('/impressum')
def impressum(): return send_from_directory('static','impressum.html')

@app.route('/datenschutz')
def datenschutz(): return send_from_directory('static','datenschutz.html')

@app.route('/agb')
def agb(): return send_from_directory('static','agb.html')

# ═══════════════════════════════════════════════════
# AUTH API
# ═══════════════════════════════════════════════════
@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    d = request.json or {}
    email    = d.get('email','').strip().lower()
    password = d.get('password','')
    name     = d.get('name','').strip()
    praxis   = d.get('praxis','').strip()

    if not email or '@' not in email:
        return jsonify({'error':'Bitte gültige E-Mail-Adresse eingeben'}), 400
    if len(password) < 6:
        return jsonify({'error':'Passwort muss mindestens 6 Zeichen haben'}), 400

    conn = get_db()
    if db_fetchone(conn, 'SELECT id FROM users WHERE email=?',(email,)):
        conn.close()
        return jsonify({'error':'Diese E-Mail ist bereits registriert. Bitte anmelden.'}), 409

    uid = 'u_'+nid()
    verify_token = secrets.token_urlsafe(32)
    trial_end = (datetime.now()+timedelta(days=14)).isoformat()
    db_execute(conn, '''INSERT INTO users
        (id,email,password,name,praxis,plan,active,role,analyses_used,analyses_limit,email_verified,verify_token,trial_ends_at,created_at)
        VALUES (?,?,?,?,?,?,1,?,0,3,0,?,?,?)''',
        (uid,email,hash_pw(password),name or email.split('@')[0],praxis or 'Meine Praxis','trial','customer',verify_token,trial_end,now()))

    token = secrets.token_hex(32)
    db_execute(conn, 'INSERT INTO sessions (token,user_id,expires_at,created_at) VALUES (?,?,?,?)',
                 (token,uid,(datetime.now()+timedelta(days=30)).isoformat(),now()))
    conn.commit(); conn.close()

    # E-Mail-Verifizierung senden
    send_verify_email(email, verify_token)

    # Admin benachrichtigen
    send_admin_notification('Neue Registrierung',
        f'{name or email} ({email}) hat sich registriert. Praxis: {praxis or "k.A."}')

    audit('Registrierung',uid,email)
    return jsonify({
        'token': token,
        'user': {'id':uid,'email':email,'name':name or email,'praxis':praxis,'plan':'trial','role':'customer',
                 'analyses_used':0,'analyses_limit':3,'email_verified':0}
    }), 201

@app.route('/api/auth/verify-email', methods=['POST'])
def verify_email():
    d = request.json or {}
    token = d.get('token','').strip()
    if not token: return jsonify({'error':'Token fehlt'}), 400

    conn = get_db()
    user = db_dict(db_fetchone(conn, 'SELECT id,email FROM users WHERE verify_token=?',(token,)))
    if not user:
        conn.close()
        return jsonify({'error':'Ungültiger oder abgelaufener Token'}), 400

    db_execute(conn, "UPDATE users SET email_verified=1, verify_token='' WHERE id=?",(user['id'],))
    conn.commit(); conn.close()
    audit('E-Mail verifiziert',user['id'],user['email'])
    return jsonify({'ok':True,'message':'E-Mail erfolgreich bestätigt!'})

@app.route('/api/auth/forgot-password', methods=['POST'])
@limiter.limit("3 per minute")
def forgot_password():
    d = request.json or {}
    email = d.get('email','').strip().lower()
    if not email: return jsonify({'error':'E-Mail erforderlich'}), 400

    conn = get_db()
    user = db_dict(db_fetchone(conn, 'SELECT id FROM users WHERE email=? AND active=1',(email,)))
    if not user:
        conn.close()
        # Immer "OK" zurückgeben, um E-Mail-Enumeration zu verhindern
        return jsonify({'ok':True,'message':'Falls ein Account existiert, wurde eine E-Mail gesendet.'})

    reset_token = secrets.token_urlsafe(32)
    reset_expires = (datetime.now() + timedelta(hours=1)).isoformat()
    db_execute(conn, 'UPDATE users SET reset_token=?, reset_expires=? WHERE id=?',
               (reset_token, reset_expires, user['id']))
    conn.commit(); conn.close()

    send_reset_email(email, reset_token)
    audit('Passwort-Reset angefordert', user['id'], email)
    return jsonify({'ok':True,'message':'Falls ein Account existiert, wurde eine E-Mail gesendet.'})

@app.route('/api/auth/reset-password', methods=['POST'])
@limiter.limit("5 per minute")
def reset_password():
    d = request.json or {}
    token = d.get('token','').strip()
    new_pw = d.get('password','')

    if not token: return jsonify({'error':'Token fehlt'}), 400
    if len(new_pw) < 6: return jsonify({'error':'Passwort muss mindestens 6 Zeichen haben'}), 400

    conn = get_db()
    user = db_dict(db_fetchone(conn, 'SELECT id,reset_expires FROM users WHERE reset_token=?',(token,)))
    if not user:
        conn.close()
        return jsonify({'error':'Ungültiger oder abgelaufener Token'}), 400

    if user.get('reset_expires','') < now():
        conn.close()
        return jsonify({'error':'Token abgelaufen. Bitte erneut anfordern.'}), 400

    db_execute(conn, "UPDATE users SET password=?, reset_token='', reset_expires='' WHERE id=?",
               (hash_pw(new_pw), user['id']))
    # Alle Sessions löschen
    db_execute(conn, 'DELETE FROM sessions WHERE user_id=?', (user['id'],))
    conn.commit(); conn.close()

    audit('Passwort zurückgesetzt', user['id'])
    return jsonify({'ok':True,'message':'Passwort erfolgreich geändert. Bitte neu anmelden.'})

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    d  = request.json or {}
    em = d.get('email','').strip().lower()
    pw = d.get('password','')

    if not em or not pw:
        return jsonify({'error':'E-Mail und Passwort erforderlich'}), 400

    conn = get_db()
    user = db_dict(db_fetchone(conn, 'SELECT * FROM users WHERE email=?',(em,)))
    if not user or not check_pw(pw, user['password']):
        conn.close()
        return jsonify({'error':'E-Mail oder Passwort falsch'}), 401
    if not user['active']:
        conn.close()
        return jsonify({'error':'Account deaktiviert. Bitte Support kontaktieren.'}), 403

    # Upgrade old SHA256 hash to bcrypt on login
    if HAS_BCRYPT and not user['password'].startswith('$2'):
        db_execute(conn, 'UPDATE users SET password=? WHERE id=?', (hash_pw(pw), user['id']))

    token = secrets.token_hex(32)
    db_execute(conn, 'INSERT INTO sessions (token,user_id,expires_at,created_at) VALUES (?,?,?,?)',
                 (token,user['id'],(datetime.now()+timedelta(days=30)).isoformat(),now()))
    db_execute(conn, 'UPDATE users SET last_login=? WHERE id=?',(now(),user['id']))
    conn.commit(); conn.close()

    audit('Login',user['id'],em)
    return jsonify({
        'token': token,
        'user': {k: user[k] for k in ['id','email','name','praxis','plan','role','analyses_used','analyses_limit']}
    })

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    token = request.headers.get('Authorization','').replace('Bearer ','')
    conn = get_db()
    db_execute(conn, 'DELETE FROM sessions WHERE token=?',(token,))
    conn.commit(); conn.close()
    audit('Logout',request.user['id'])
    return jsonify({'ok':True})

@app.route('/api/auth/me')
@require_auth
def me():
    conn = get_db()
    user = db_dict(db_fetchone(conn, 'SELECT * FROM users WHERE id=?',(request.user['id'],)))
    conn.close()
    if not user: return jsonify({'error':'User not found'}), 404
    return jsonify({'user': {k: user.get(k,'') for k in ['id','email','name','praxis','plan','role','analyses_used','analyses_limit','trial_ends_at','email_verified']}})

# ═══════════════════════════════════════════════════
# KI-ANALYSE
# ═══════════════════════════════════════════════════
@app.route('/api/analyse', methods=['POST'])
@require_auth
@limiter.limit("10 per minute")
def analyse():
    if not ANTHROPIC_API_KEY:
        return jsonify({'error':'KI nicht konfiguriert. Admin muss ANTHROPIC_API_KEY setzen.'}), 503

    user = request.user
    if user['role'] != 'admin':
        if user['plan'] in ('trial',) and user['analyses_used'] >= user['analyses_limit']:
            return jsonify({
                'error': f'Ihr Trial-Kontingent ({user["analyses_limit"]} Analysen) ist aufgebraucht.',
                'upgrade_required': True, 'plan': user['plan']
            }), 402
        if user['plan'] == 'starter' and user['analyses_used'] >= 50:
            return jsonify({'error':'Monatliches Starter-Kontingent (50 Analysen) erreicht.','upgrade_required':True}), 402

    d          = request.json or {}
    pet_name   = d.get('pet_name','').strip()
    species    = d.get('species','Hund')
    region     = d.get('region','Thorax')
    mode       = d.get('mode','single')
    ctx        = d.get('context','')
    focus_mode = d.get('focus_mode','general')
    focus_text = d.get('focus_text','').strip()
    img_a      = d.get('img_a','')
    img_b      = d.get('img_b','')

    if not img_a: return jsonify({'error':'Kein Bild hochgeladen'}), 400

    prompts = {
        'single':  f'Erstelle einen vollständigen veterinärradiologischen Befundbericht für einen {species} im Bereich {region}. Analysiere das Bild EXTREM GRÜNDLICH. Untersuche JEDEN sichtbaren Knochen, jedes Gelenk, jedes Organ systematisch. Achte BESONDERS auf: Frakturlinien, Fissuren, Luxationen, Stufenbildungen, Periostreaktionen, Osteolysen, abnorme Verschattungen, Fremdkörper, Weichteilschwellungen. Beschreibe auch subtile Veränderungen. ÜBERSEHE NICHTS.',
        'compare': f'Vergleiche Aufnahme A (früher) mit Aufnahme B (aktuell) eines {species} im Bereich {region}. Beschreibe ALLE Veränderungen zwischen den Aufnahmen präzise. Achte besonders auf: Frakturheilung/Konsolidierung, Kallusbildung, Veränderungen der Gelenkspalten, neue oder verschwundene Pathologien, Implantatposition.',
        'diff':    f'Analysiere die Unterschiede zwischen Aufnahme A und B bei einem {species} im Bereich {region}. Erstelle eine systematische Gegenüberstellung aller Veränderungen.',
        'second':  f'Erstelle eine kritische Zweitmeinung zu den Röntgenaufnahmen eines {species} im Bereich {region}. Hinterfrage offensichtliche Diagnosen und suche gezielt nach übersehenen Pathologien. Untersuche jede Struktur einzeln.',
    }

    # DSGVO: Bilddaten werden NUR zur KI-Analyse an Anthropic gesendet,
    # NICHT in der Datenbank gespeichert. Nach der Analyse werden sie verworfen.

    system = """Du bist ECVDI-Diplomate mit 20 Jahren Erfahrung in der Veterinärradiologie.
Erstelle professionelle Befundberichte auf Deutsch.

WICHTIG DATENSCHUTZ: Falls im Bild DICOM-Metadaten oder Patientendaten sichtbar sind,
ignoriere diese vollständig. Nenne KEINE Patientennamen, Geburtsdaten oder andere
personenbezogene Daten aus dem Bild im Befund.

KRITISCHE ANALYSE-REGELN:
1. Analysiere JEDE sichtbare anatomische Struktur systematisch — überspringe NICHTS.
2. Beschreibe bei Knochen: Kortikalis-Kontinuität, Periostreaktion, Mineralisierung, Alignment.
3. Bei Gelenken: Gelenkspalt, Kongruenz, periartikuläre Veränderungen.
4. Bei Weichteilen: Schwellungen, Gaseinschlüsse, Fremdkörper, abnorme Verschattungen.
5. Bei Thorax: Lungenparenchym, Herzsilhouette, Pleuraraum, Mediastinum, Trachea.
6. Bei Abdomen: Organgrößen, -positionen, -konturen, freie Flüssigkeit, Gas.
7. Wenn du eine Fraktur, Luxation oder andere akute Pathologie siehst — stelle diese SOFORT als Hauptdiagnose dar.
8. Beschreibe die GENAUE LOKALISATION jeder Pathologie (welcher Knochen, proximal/distal/diaphysär, welche Seite).
9. Sei NICHT vorsichtig oder vage — nenne klare Befunde wenn du Pathologien siehst.

PFLICHT: Die DIAGNOSE und der MEDIZINISCHE ZUSTAND kommen IMMER ZUERST.

FORMAT - genau diese Reihenfolge einhalten:

## Diagnose & Klinische Beurteilung
**Hauptdiagnose:** [Was ist das wichtigste/dringendste Ergebnis? Klar und konkret, keine Vermutungen]
**Dringlichkeit:** **[NIEDRIG / MITTEL / HOCH / NOTFALL]** — [1 Satz Begründung]

## Differenzialdiagnosen
| Diagnose | Wahrscheinlichkeit | Begründung |
|---|---|---|

## Detaillierter Radiologischer Befund
[Systematische Analyse JEDER sichtbaren Struktur. Unterabschnitte je Körperregion mit ### Überschriften. Beschreibe sowohl normale als auch pathologische Befunde.]

## Therapie- & Kontrollempfehlungen
[Konkrete, priorisierte Handlungsempfehlungen für den Tierarzt]

## Technische Bildqualität
[Kurz — max 2 Sätze zur Aufnahmequalität]

---
*Animioo KI-Befundassistent · Kein Ersatz für tierärztliche Diagnose*"""

    msgs = [
        {'type':'image','source':{'type':'base64','media_type':'image/jpeg','data':img_a}},
        {'type':'text','text':'Aufnahme A:'}
    ]
    if img_b and mode != 'single':
        msgs += [
            {'type':'image','source':{'type':'base64','media_type':'image/jpeg','data':img_b}},
            {'type':'text','text':'Aufnahme B:'}
        ]
    prompt = prompts.get(mode, prompts['single'])
    if ctx: prompt += f'\n\nKlinischer Kontext vom Tierarzt: {ctx}'
    if focus_mode == 'specific' and focus_text:
        prompt += f'\n\nSPEZIFISCHER ANALYSE-FOKUS: Der Tierarzt bittet um gezielte Untersuchung folgender Aspekte: {focus_text}. Bitte gehe besonders detailliert auf diese Fragestellung ein.'
    msgs.append({'type':'text','text':prompt})

    import time as _time

    # ── Helper: Anthropic ──
    def try_anthropic():
        if not ANTHROPIC_API_KEY: return None
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        for attempt in range(3):
            try:
                resp = client.messages.create(
                    model='claude-sonnet-4-20250514',
                    max_tokens=2400,
                    system=system,
                    messages=[{'role':'user','content':msgs}]
                )
                return resp.content[0].text
            except anthropic.APIStatusError as e:
                if e.status_code == 529 and attempt < 2:
                    _time.sleep(2 * (attempt + 1))
                    continue
                app.logger.warning(f'Anthropic Fehler (Versuch {attempt+1}): {e}')
                return None
            except Exception as e:
                app.logger.warning(f'Anthropic Fehler: {e}')
                return None
        return None

    # ── Helper: OpenAI ──
    def try_openai():
        if not OPENAI_API_KEY: return None
        try:
            from openai import OpenAI
            oc = OpenAI(api_key=OPENAI_API_KEY)
            oai_msgs = [{'type':'text','text':system}]
            oai_content = []
            for m in msgs:
                if m['type'] == 'image':
                    oai_content.append({'type':'image_url','image_url':{'url':f"data:{m['source']['media_type']};base64,{m['source']['data']}"}})
                else:
                    oai_content.append({'type':'text','text':m['text']})
            resp = oc.chat.completions.create(
                model='gpt-4o',
                max_tokens=2400,
                messages=[
                    {'role':'system','content':system},
                    {'role':'user','content':oai_content}
                ]
            )
            return resp.choices[0].message.content
        except Exception as e:
            app.logger.warning(f'OpenAI Fehler: {e}')
            return None

    # ── Helper: Google Gemini ──
    def try_gemini():
        if not GEMINI_API_KEY: return None
        try:
            import google.generativeai as genai
            import base64
            genai.configure(api_key=GEMINI_API_KEY)
            model = genai.GenerativeModel('gemini-2.0-flash')
            parts = [system + '\n\n']
            for m in msgs:
                if m['type'] == 'image':
                    parts.append({'mime_type':m['source']['media_type'],'data':base64.b64decode(m['source']['data'])})
                else:
                    parts.append(m['text'])
            resp = model.generate_content(parts)
            return resp.text
        except Exception as e:
            app.logger.warning(f'Gemini Fehler: {e}')
            return None

    # ── Multi-Provider Fallback ──
    providers = [
        ('Anthropic', try_anthropic),
        ('OpenAI', try_openai),
        ('Gemini', try_gemini),
    ]
    text = None
    used_provider = None
    for pname, pfunc in providers:
        app.logger.info(f'Versuche KI-Provider: {pname}')
        text = pfunc()
        if text:
            used_provider = pname
            app.logger.info(f'Analyse erfolgreich mit: {pname}')
            break
        app.logger.warning(f'{pname} fehlgeschlagen, versuche nächsten Provider...')

    if not text:
        return jsonify({'error':'Alle KI-Server sind derzeit nicht erreichbar. Bitte in einigen Minuten erneut versuchen.'}), 503

    tl   = text.lower()
    sev  = 'high' if ('**hoch**' in tl or '**high**' in tl or '**notfall**' in tl) else ('low' if ('**niedrig**' in tl or '**low**' in tl) else 'mid')

    rid = 'r_'+nid()
    conn = get_db()
    db_execute(conn, 'INSERT INTO reports (id,user_id,pet_name,species,region,mode,severity,report_text,image_data,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
                 (rid,user['id'],pet_name,species,region,mode,sev,text,img_a,now()))
    db_execute(conn, 'UPDATE users SET analyses_used=analyses_used+1 WHERE id=?',(user['id'],))
    conn.commit(); conn.close()

    audit('Analyse',user['id'],f'{species}/{region}/{mode} via {used_provider}')
    return jsonify({'id':rid,'report_text':text,'severity':sev,'pet_name':pet_name,'species':species,'region':region,'mode':mode,'created_at':now()})

# ═══════════════════════════════════════════════════
# CHAT (Rückfragen zum Befund)
# ═══════════════════════════════════════════════════
@app.route('/api/chat', methods=['POST'])
@require_auth
@limiter.limit("20/minute")
def chat_about_report():
    d = request.json or {}
    question = d.get('question','').strip()
    report_text = d.get('report_text','')
    context = d.get('context',{})
    history = d.get('history',[])

    if not question: return jsonify({'error':'Keine Frage gestellt'}), 400
    if not report_text: return jsonify({'error':'Kein Befund vorhanden'}), 400

    system = f"""Du bist ein erfahrener ECVDI-Diplomate für Veterinärradiologie.
Ein Tierarzt hat einen KI-generierten Befundbericht erhalten und stellt nun Rückfragen.

Befund-Kontext: {context.get('species','Hund')}, {context.get('region','Thorax')}, Modus: {context.get('mode','single')}
{('Patient: '+context['pet_name']) if context.get('pet_name') else ''}

Der ursprüngliche Befundbericht:
---
{report_text}
---

Beantworte die Fragen des Tierarztes auf Deutsch, präzise und fachlich korrekt.
- Beziehe dich immer auf den konkreten Befund oben.
- Erkläre Fachbegriffe wenn nötig.
- Gib konkrete, praxisrelevante Antworten.
- Halte die Antworten kurz und fokussiert (max 200 Wörter).
- Wenn du dir bei etwas unsicher bist, sage es ehrlich."""

    messages = []
    for h in history[-10:]:
        messages.append({'role':h['role'] if h['role'] in ('user','assistant') else 'user', 'content':h['text']})

    answer = None

    # Try Anthropic
    if ANTHROPIC_API_KEY and not answer:
        try:
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            resp = client.messages.create(model='claude-sonnet-4-20250514', max_tokens=800, system=system, messages=messages)
            answer = resp.content[0].text
        except Exception as e:
            app.logger.warning(f'Chat Anthropic Fehler: {e}')

    # Try OpenAI
    if OPENAI_API_KEY and not answer:
        try:
            from openai import OpenAI
            oc = OpenAI(api_key=OPENAI_API_KEY)
            oai_msgs = [{'role':'system','content':system}] + [{'role':m['role'],'content':m['content']} for m in messages]
            resp = oc.chat.completions.create(model='gpt-4o', max_tokens=800, messages=oai_msgs)
            answer = resp.choices[0].message.content
        except Exception as e:
            app.logger.warning(f'Chat OpenAI Fehler: {e}')

    # Try Gemini
    if GEMINI_API_KEY and not answer:
        try:
            import google.generativeai as genai
            genai.configure(api_key=GEMINI_API_KEY)
            model = genai.GenerativeModel('gemini-2.0-flash')
            chat_text = system + '\n\n' + '\n'.join([f"{m['role']}: {m['content']}" for m in messages])
            resp = model.generate_content(chat_text)
            answer = resp.text
        except Exception as e:
            app.logger.warning(f'Chat Gemini Fehler: {e}')

    if answer:
        return jsonify({'answer':answer})
    return jsonify({'error':'Alle KI-Server nicht erreichbar. Bitte später versuchen.'}), 503

# ═══════════════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════════════
@app.route('/api/reports')
@require_auth
def get_reports():
    conn = get_db()
    if request.user['role'] == 'admin':
        rows = db_fetchall(conn, 'SELECT r.*,u.name as user_name,u.praxis FROM reports r LEFT JOIN users u ON r.user_id=u.id ORDER BY r.created_at DESC')
    else:
        rows = db_fetchall(conn, 'SELECT * FROM reports WHERE user_id=? ORDER BY created_at DESC',(request.user['id'],))
    conn.close()
    # Don't send image_data in list (too large), add has_image flag instead
    for r in rows:
        r['has_image'] = bool(r.get('image_data'))
        r.pop('image_data', None)
    return jsonify({'reports':rows})

@app.route('/api/reports/<rid>/image')
@require_auth
def get_report_image(rid):
    conn = get_db()
    rows = db_fetchall(conn, 'SELECT image_data,user_id FROM reports WHERE id=?',(rid,))
    conn.close()
    if not rows: return jsonify({'error':'Befund nicht gefunden'}), 404
    r = rows[0]
    if r['user_id'] != request.user['id'] and request.user['role'] != 'admin':
        return jsonify({'error':'Kein Zugriff'}), 403
    if not r.get('image_data'):
        return jsonify({'error':'Kein Bild vorhanden'}), 404
    return jsonify({'image_data':r['image_data']})

@app.route('/api/reports/<rid>', methods=['DELETE'])
@require_auth
def delete_report(rid):
    conn = get_db()
    if request.user['role'] == 'admin':
        db_execute(conn, 'DELETE FROM reports WHERE id=?',(rid,))
    else:
        db_execute(conn, 'DELETE FROM reports WHERE id=? AND user_id=?',(rid,request.user['id']))
    conn.commit(); conn.close()
    audit('Befund gelöscht',request.user['id'],rid)
    return jsonify({'ok':True})

# ═══════════════════════════════════════════════════
# STRIPE PAYMENTS
# ═══════════════════════════════════════════════════
@app.route('/api/payments/checkout', methods=['POST'])
@require_auth
def create_checkout():
    if not STRIPE_SECRET_KEY:
        return jsonify({'error':'Stripe nicht konfiguriert. STRIPE_SECRET_KEY fehlt.'}), 503

    import stripe
    stripe.api_key = STRIPE_SECRET_KEY

    d    = request.json or {}
    plan = d.get('plan','starter')

    price_id = STRIPE_PRICE_PRO if plan == 'professional' else STRIPE_PRICE_STARTER
    if not price_id:
        return jsonify({'error':f'Stripe Preis-ID für {plan} fehlt.'}), 503

    try:
        session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{'price': price_id, 'quantity': 1}],
            mode='subscription',
            customer_email=request.user['email'],
            metadata={'user_id': request.user['id'], 'plan': plan},
            success_url=f"{APP_URL}/app?payment=success&plan={plan}",
            cancel_url=f"{APP_URL}/app?payment=cancelled",
        )
        conn = get_db()
        db_execute(conn, 'INSERT INTO payments (id,user_id,stripe_session_id,plan,amount,status,created_at) VALUES (?,?,?,?,?,?,?)',
                     ('pay_'+nid(), request.user['id'], session.id, plan,
                      4900 if plan=='starter' else 17900, 'pending', now()))
        conn.commit(); conn.close()

        return jsonify({'checkout_url': session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/payments/webhook', methods=['POST'])
@limiter.exempt
def stripe_webhook():
    if not STRIPE_SECRET_KEY: return jsonify({'ok':True})
    import stripe
    stripe.api_key = STRIPE_SECRET_KEY

    payload = request.get_data()
    sig     = request.headers.get('Stripe-Signature','')

    try:
        event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SEC)
    except Exception as e:
        return jsonify({'error':str(e)}), 400

    if event['type'] == 'checkout.session.completed':
        sess     = event['data']['object']
        uid      = sess.get('metadata',{}).get('user_id')
        plan     = sess.get('metadata',{}).get('plan','starter')
        sub_id   = sess.get('subscription','')
        cust_id  = sess.get('customer','')

        if uid:
            limit = 50 if plan == 'starter' else 999999
            conn = get_db()
            db_execute(conn, 'UPDATE users SET plan=?,analyses_limit=?,stripe_customer_id=?,stripe_subscription_id=? WHERE id=?',
                         (plan,limit,cust_id,sub_id,uid))
            db_execute(conn, 'UPDATE payments SET status=? WHERE stripe_session_id=?',('paid',sess['id']))
            conn.commit(); conn.close()
            audit('Plan aktiviert',uid,plan)
            send_admin_notification('Neuer zahlender Kunde', f'User {uid} hat Plan "{plan}" aktiviert.')

    elif event['type'] == 'customer.subscription.deleted':
        sub = event['data']['object']
        conn = get_db()
        db_execute(conn, "UPDATE users SET plan=?,analyses_limit=3 WHERE stripe_subscription_id=?",
                     ('trial',sub['id']))
        conn.commit(); conn.close()

    return jsonify({'ok':True})

@app.route('/api/payments/portal', methods=['POST'])
@require_auth
def billing_portal():
    if not STRIPE_SECRET_KEY:
        return jsonify({'error':'Stripe nicht konfiguriert'}), 503
    import stripe
    stripe.api_key = STRIPE_SECRET_KEY
    cust_id = request.user.get('stripe_customer_id','')
    if not cust_id:
        return jsonify({'error':'Kein Stripe-Konto verknüpft'}), 400
    try:
        session = stripe.billing_portal.Session.create(
            customer=cust_id, return_url=f"{APP_URL}/app"
        )
        return jsonify({'url': session.url})
    except Exception as e:
        return jsonify({'error':str(e)}), 500

# ═══════════════════════════════════════════════════
# ADMIN API
# ═══════════════════════════════════════════════════
@app.route('/api/admin/stats')
@require_admin
def admin_stats():
    conn = get_db()
    stats = {
        'customers':  db_dict(db_fetchone(conn, "SELECT COUNT(*) as n FROM users WHERE role='customer' AND active=1"))['n'],
        'leads':      db_dict(db_fetchone(conn, "SELECT COUNT(*) as n FROM leads"))['n'],
        'new_leads':  db_dict(db_fetchone(conn, "SELECT COUNT(*) as n FROM leads WHERE status='new'"))['n'],
        'analyses':   db_dict(db_fetchone(conn, "SELECT COALESCE(SUM(analyses_used),0) as n FROM users"))['n'],
        'mrr':        db_dict(db_fetchone(conn, "SELECT COALESCE(SUM(CASE plan WHEN 'professional' THEN 179 WHEN 'starter' THEN 49 ELSE 0 END),0) as n FROM users WHERE active=1 AND role='customer'"))['n'],
        'audit':      db_fetchall(conn, 'SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 30'),
        'plan_dist':  db_fetchall(conn, "SELECT plan, COUNT(*) as n FROM users WHERE role='customer' GROUP BY plan"),
        'weekly':     db_fetchall(conn, "SELECT date(created_at) as day, COUNT(*) as n FROM reports GROUP BY date(created_at) ORDER BY date(created_at) DESC LIMIT 7"),
    }
    conn.close()
    return jsonify(stats)

@app.route('/api/admin/customers')
@require_admin
def admin_customers():
    conn = get_db()
    rows = db_fetchall(conn, "SELECT id,email,name,praxis,plan,active,analyses_used,analyses_limit,email_verified,created_at,last_login FROM users WHERE role!='admin' ORDER BY created_at DESC")
    conn.close()
    return jsonify({'customers':rows})

@app.route('/api/admin/customers', methods=['POST'])
@require_admin
def admin_create_customer():
    d = request.json or {}
    uid = 'u_'+nid()
    limit = 999999 if d.get('plan')=='professional' else (50 if d.get('plan')=='starter' else 3)
    conn = get_db()
    try:
        db_execute(conn, 'INSERT INTO users (id,email,password,name,praxis,plan,active,role,analyses_used,analyses_limit,email_verified,created_at) VALUES (?,?,?,?,?,?,1,?,0,?,1,?)',
                     (uid,d['email'].lower(),hash_pw(d.get('password','Animioo2025!')),d.get('name',''),d.get('praxis',''),d.get('plan','trial'),'customer',limit,now()))
        conn.commit()
    except: conn.close(); return jsonify({'error':'E-Mail existiert bereits'}), 409
    conn.close()
    audit('Kunde angelegt',request.user['id'],d.get('email',''))
    return jsonify({'ok':True,'id':uid}), 201

@app.route('/api/admin/customers/<uid>', methods=['PUT'])
@require_admin
def admin_update_customer(uid):
    d = request.json or {}
    limit = 999999 if d.get('plan')=='professional' else (50 if d.get('plan')=='starter' else 3)
    conn = get_db()
    db_execute(conn, 'UPDATE users SET name=?,praxis=?,plan=?,active=?,analyses_limit=? WHERE id=?',
                 (d.get('name'),d.get('praxis'),d.get('plan'),int(d.get('active',1)),limit,uid))
    conn.commit(); conn.close()
    audit('Kunde bearbeitet',request.user['id'],uid)
    return jsonify({'ok':True})

@app.route('/api/admin/customers/<uid>', methods=['DELETE'])
@require_admin
def admin_delete_customer(uid):
    conn = get_db()
    db_execute(conn, 'UPDATE users SET active=0 WHERE id=?',(uid,))
    conn.commit(); conn.close()
    audit('Kunde deaktiviert',request.user['id'],uid)
    return jsonify({'ok':True})

@app.route('/api/admin/leads')
@require_admin
def admin_leads():
    conn = get_db()
    rows = db_fetchall(conn, 'SELECT * FROM leads ORDER BY created_at DESC')
    conn.close()
    return jsonify({'leads':rows})

@app.route('/api/admin/leads', methods=['POST'])
@require_admin
def admin_create_lead():
    d = request.json or {}
    lid = 'l_'+nid()
    conn = get_db()
    db_execute(conn, 'INSERT INTO leads (id,name,contact,email,phone,message,status,source,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
                 (lid,d.get('name',''),d.get('contact',''),d.get('email',''),d.get('phone',''),d.get('message',''),'new',d.get('source','Website'),now()))
    conn.commit(); conn.close()
    return jsonify({'ok':True,'id':lid}), 201

@app.route('/api/admin/leads/<lid>', methods=['PUT'])
@require_admin
def admin_update_lead(lid):
    d = request.json or {}
    conn = get_db()
    db_execute(conn, 'UPDATE leads SET name=?,contact=?,email=?,phone=?,status=?,source=?,message=? WHERE id=?',
                 (d.get('name'),d.get('contact'),d.get('email'),d.get('phone'),d.get('status'),d.get('source'),d.get('message'),lid))
    conn.commit(); conn.close()
    return jsonify({'ok':True})

@app.route('/api/admin/leads/<lid>', methods=['DELETE'])
@require_admin
def admin_delete_lead(lid):
    conn = get_db()
    db_execute(conn, 'DELETE FROM leads WHERE id=?',(lid,))
    conn.commit(); conn.close()
    return jsonify({'ok':True})

@app.route('/api/admin/reports')
@require_admin
def admin_reports():
    conn = get_db()
    rows = db_fetchall(conn, 'SELECT r.*,u.name as user_name,u.praxis FROM reports r LEFT JOIN users u ON r.user_id=u.id ORDER BY r.created_at DESC')
    conn.close()
    return jsonify({'reports':rows})

# ═══════════════════════════════════════════════════
# CONTACT / LEAD CAPTURE (öffentlich)
# ═══════════════════════════════════════════════════
@app.route('/api/contact', methods=['POST'])
@limiter.limit("5 per minute")
def contact():
    d = request.json or {}
    lid = 'l_'+nid()
    conn = get_db()
    db_execute(conn, 'INSERT INTO leads (id,name,contact,email,phone,message,status,source,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
                 (lid,d.get('company',''),d.get('name',''),d.get('email',''),d.get('phone',''),d.get('message',''),'new',d.get('source','Kontaktformular'),now()))
    conn.commit(); conn.close()

    # Admin benachrichtigen
    send_admin_notification('Neuer Lead',
        f'Name: {d.get("name","k.A.")}<br>E-Mail: {d.get("email","k.A.")}<br>Nachricht: {d.get("message","k.A.")}')

    return jsonify({'ok':True}), 201

# ═══════════════════════════════════════════════════
# ERROR HANDLER
# ═══════════════════════════════════════════════════
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Zu viele Anfragen. Bitte warten Sie einen Moment.'}), 429

@app.errorhandler(500)
def internal_error(e):
    app.logger.error(f'Server Error: {e}')
    return jsonify({'error': 'Interner Serverfehler'}), 500

# ═══════════════════════════════════════════════════
# DEBUG: DB Health Check (temporär)
# ═══════════════════════════════════════════════════
@app.route('/api/health')
def health_check():
    try:
        conn = get_db()
        # Force-create admin if missing
        admin = db_fetchone(conn, 'SELECT id, email, role FROM users WHERE email=?', ('admin@animioo.de',))
        if not admin:
            trial_end = (datetime.now() + timedelta(days=14)).isoformat()
            db_execute(conn, '''INSERT INTO users
                (id,email,password,name,praxis,plan,active,role,analyses_used,analyses_limit,email_verified,trial_ends_at,created_at)
                VALUES (%s,%s,%s,%s,%s,%s,1,%s,%s,%s,1,%s,%s)''',
                ('admin1','admin@animioo.de',hash_pw('admin123'),'Administrator','Animioo GmbH','admin','admin',0,999999,trial_end,datetime.now().isoformat()))
            conn.commit()
            admin = {'id':'admin1','email':'admin@animioo.de','role':'admin','status':'CREATED'}
        users = db_fetchall(conn, 'SELECT id, email, role, plan FROM users LIMIT 10')
        conn.close()
        return jsonify({'db': 'postgresql' if USE_POSTGRES else 'sqlite', 'users': users, 'admin': admin, 'bcrypt': HAS_BCRYPT})
    except Exception as e:
        return jsonify({'error': str(e), 'type': type(e).__name__}), 500

# ═══════════════════════════════════════════════════
# START
# ═══════════════════════════════════════════════════
init_db()

if __name__ == '__main__':
    port  = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG','false').lower() == 'true'

    missing = []
    if not ANTHROPIC_API_KEY:  missing.append('ANTHROPIC_API_KEY')
    if not STRIPE_SECRET_KEY:  missing.append('STRIPE_SECRET_KEY')

    db_type = 'PostgreSQL' if USE_POSTGRES else 'SQLite'
    print(f"""
╔══════════════════════════════════════════════╗
║   Animioo – Server v2 gestartet             ║
║   URL: http://localhost:{port}                  ║
║   DB:     {db_type}
║   KI:     {'Bereit' if ANTHROPIC_API_KEY else 'ANTHROPIC_API_KEY fehlt'}
║   Stripe: {'Bereit' if STRIPE_SECRET_KEY else 'STRIPE_SECRET_KEY fehlt'}
║   E-Mail: {'Bereit' if SMTP_HOST else 'SMTP nicht konfiguriert'}
║   Sentry: {'Bereit' if SENTRY_DSN else 'Nicht konfiguriert'}
║   bcrypt: {'Ja' if HAS_BCRYPT else 'Nein (SHA256-Fallback)'}
{"║   Fehlend: " + ", ".join(missing) if missing else "║   Alle Variablen gesetzt"}
╚══════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=port, debug=debug)

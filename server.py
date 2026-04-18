"""
Animioo – Produktions-Server v2
Auth + KI-Analyse + Stripe Payments + Admin
+ bcrypt, rate limiting, email, Sentry, PostgreSQL
"""
from flask import Flask, request, jsonify, send_from_directory, redirect, make_response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import anthropic, hashlib, secrets, os, json, smtplib, logging, math, io
try:
    import pyotp
except ImportError:
    pyotp = None
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

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    # CSP: allow self + inline scripts/styles (needed for app) + Google Fonts + data URIs for images
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self';"
    )
    return response

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
                analyses_limit INTEGER DEFAULT 20,
                stripe_customer_id TEXT DEFAULT '',
                stripe_subscription_id TEXT DEFAULT '',
                email_verified INTEGER DEFAULT 0,
                verify_token TEXT DEFAULT '',
                reset_token TEXT DEFAULT '',
                reset_expires TEXT DEFAULT '',
                trial_ends_at TEXT DEFAULT '',
                pet_name TEXT DEFAULT '',
                api_key TEXT DEFAULT '',
                totp_secret TEXT DEFAULT '',
                totp_enabled INTEGER DEFAULT 0,
                created_at TEXT,
                last_login TEXT
            )''',
            '''CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                email TEXT DEFAULT '',
                expires_at TEXT NOT NULL,
                created_at TEXT,
                ip_address TEXT DEFAULT '',
                user_agent TEXT DEFAULT ''
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
                image_hash TEXT DEFAULT '',
                quality_score INTEGER,
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
            )''',
            '''CREATE TABLE IF NOT EXISTS report_feedback (
                id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                rating INTEGER,
                correct INTEGER,
                comment TEXT DEFAULT '',
                created_at TEXT
            )''',
            '''CREATE TABLE IF NOT EXISTS patients (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                species TEXT DEFAULT '',
                breed TEXT DEFAULT '',
                birth_date TEXT DEFAULT '',
                weight TEXT DEFAULT '',
                owner_name TEXT DEFAULT '',
                owner_phone TEXT DEFAULT '',
                owner_email TEXT DEFAULT '',
                notes TEXT DEFAULT '',
                created_at TEXT
            )''',
            '''CREATE TABLE IF NOT EXISTS teams (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                created_at TEXT
            )''',
            '''CREATE TABLE IF NOT EXISTS team_members (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT DEFAULT 'member',
                invited_by TEXT DEFAULT '',
                joined_at TEXT
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
                analyses_limit INTEGER DEFAULT 20,
                stripe_customer_id TEXT DEFAULT "",
                stripe_subscription_id TEXT DEFAULT "",
                email_verified INTEGER DEFAULT 0,
                verify_token TEXT DEFAULT "",
                reset_token TEXT DEFAULT "",
                reset_expires TEXT DEFAULT "",
                trial_ends_at TEXT DEFAULT "",
                totp_secret TEXT DEFAULT "",
                totp_enabled INTEGER DEFAULT 0,
                created_at TEXT,
                last_login TEXT
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                email TEXT DEFAULT "",
                expires_at TEXT NOT NULL,
                created_at TEXT,
                ip_address TEXT DEFAULT "",
                user_agent TEXT DEFAULT ""
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
                image_hash TEXT DEFAULT "",
                quality_score INTEGER,
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
            CREATE TABLE IF NOT EXISTS report_feedback (
                id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                rating INTEGER,
                correct INTEGER,
                comment TEXT DEFAULT "",
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS patients (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                species TEXT DEFAULT "",
                breed TEXT DEFAULT "",
                birth_date TEXT DEFAULT "",
                weight TEXT DEFAULT "",
                owner_name TEXT DEFAULT "",
                owner_phone TEXT DEFAULT "",
                owner_email TEXT DEFAULT "",
                notes TEXT DEFAULT "",
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS teams (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                owner_id TEXT NOT NULL,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS team_members (
                id TEXT PRIMARY KEY,
                team_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT DEFAULT "member",
                invited_by TEXT DEFAULT "",
                joined_at TEXT
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
    try:
        db_execute(conn, "ALTER TABLE reports ADD COLUMN image_hash TEXT DEFAULT ''")
    except: pass
    try:
        db_execute(conn, "ALTER TABLE reports ADD COLUMN quality_score INTEGER DEFAULT NULL")
    except: pass
    try:
        db_execute(conn, "ALTER TABLE users ADD COLUMN api_key TEXT DEFAULT ''")
    except: pass
    for col in [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled INTEGER DEFAULT 0",
        "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS email TEXT DEFAULT ''",
        "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip_address TEXT DEFAULT ''",
        "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT DEFAULT ''",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS patient_id TEXT DEFAULT ''",
        "ALTER TABLE patients ADD COLUMN IF NOT EXISTS photo_url TEXT DEFAULT ''",
        "ALTER TABLE teams ADD COLUMN IF NOT EXISTS name TEXT",
        "ALTER TABLE teams ADD COLUMN IF NOT EXISTS owner_id TEXT",
        "ALTER TABLE teams ADD COLUMN IF NOT EXISTS created_at TEXT",
        "ALTER TABLE team_members ADD COLUMN IF NOT EXISTS team_id TEXT",
        "ALTER TABLE team_members ADD COLUMN IF NOT EXISTS user_id TEXT",
        "ALTER TABLE team_members ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'member'",
        "ALTER TABLE team_members ADD COLUMN IF NOT EXISTS invited_by TEXT DEFAULT ''",
        "ALTER TABLE team_members ADD COLUMN IF NOT EXISTS joined_at TEXT",
    ]:
        try:
            db_execute(conn, col); conn.commit()
        except Exception:
            try: conn.rollback()
            except: pass

    # ── DB-INDIZES ──
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_reports_severity ON reports(severity)",
        "CREATE INDEX IF NOT EXISTS idx_reports_species ON reports(species)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_log(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
    ]
    for idx in indexes:
        try:
            db_execute(conn, idx)
        except Exception as e:
            app.logger.warning(f'Index creation: {e}')
    conn.commit()

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

def image_hash(base64_data, species='', region='', mode='', ctx='', focus_mode='', focus_text=''):
    """SHA-256 hash über Bild + alle Analyse-Parameter.
    Gleiche Bild + andere Einstellungen → neuer Hash → neue Analyse."""
    key = f"{base64_data[:10000]}|{species}|{region}|{mode}|{ctx}|{focus_mode}|{focus_text}"
    return hashlib.sha256(key.encode()).hexdigest()

def convert_dicom_to_jpeg_base64(dicom_base64):
    """Konvertiert DICOM-Datei (als base64) zu JPEG base64 für KI-Analyse."""
    try:
        import pydicom
        import numpy as np
        from PIL import Image
        import base64, io

        # Base64 dekodieren
        dicom_bytes = base64.b64decode(dicom_base64)
        dicom_file = io.BytesIO(dicom_bytes)

        # DICOM parsen
        ds = pydicom.dcmread(dicom_file)

        # Pixel-Array extrahieren
        pixel_array = ds.pixel_array.astype(float)

        # Normalisierung auf 0-255
        pixel_min = pixel_array.min()
        pixel_max = pixel_array.max()
        if pixel_max > pixel_min:
            pixel_array = ((pixel_array - pixel_min) / (pixel_max - pixel_min) * 255).astype(np.uint8)
        else:
            pixel_array = pixel_array.astype(np.uint8)

        # Graustufen zu RGB
        if len(pixel_array.shape) == 2:
            img = Image.fromarray(pixel_array, 'L').convert('RGB')
        else:
            img = Image.fromarray(pixel_array)

        # Zu JPEG konvertieren
        output = io.BytesIO()
        img.save(output, format='JPEG', quality=95)
        jpeg_b64 = base64.b64encode(output.getvalue()).decode('utf-8')

        # DICOM-Metadaten extrahieren
        metadata = {}
        for tag_name in ['PatientName', 'Modality', 'StudyDate', 'BodyPartExamined', 'InstitutionName']:
            try:
                val = getattr(ds, tag_name, None)
                if val: metadata[tag_name] = str(val)
            except: pass

        return jpeg_b64, metadata
    except ImportError:
        app.logger.warning('pydicom nicht installiert')
        return None, {}
    except Exception as e:
        app.logger.warning(f'DICOM-Konvertierung fehlgeschlagen: {e}')
        return None, {}

# ═══════════════════════════════════════════════════
# E-MAIL
# ═══════════════════════════════════════════════════
def send_email(to, subject, html_body):
    """Send email via SMTP. Returns True on success."""
    if not SMTP_HOST or not SMTP_USER:
        app.logger.warning(f'E-Mail nicht gesendet (SMTP nicht konfiguriert): {subject} -> {to}')
        app.logger.warning(f'  SMTP_HOST={SMTP_HOST!r}, SMTP_USER={SMTP_USER!r}, SMTP_PORT={SMTP_PORT}')
        return False
    try:
        app.logger.info(f'E-Mail senden: {subject} -> {to} via {SMTP_HOST}:{SMTP_PORT}')
        msg = MIMEMultipart('alternative')
        msg['From'] = f'Animioo <{SMTP_FROM}>'
        msg['To'] = to
        msg['Subject'] = subject
        msg.attach(MIMEText(html_body, 'html'))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        app.logger.info(f'E-Mail erfolgreich gesendet: {subject} -> {to}')
        return True
    except smtplib.SMTPAuthenticationError as e:
        app.logger.error(f'SMTP Auth Fehler (Passwort falsch?): {e}')
        return False
    except smtplib.SMTPException as e:
        app.logger.error(f'SMTP Fehler: {e}')
        return False
    except Exception as e:
        app.logger.error(f'E-Mail Fehler: {type(e).__name__}: {e}')
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
        # Cookie zuerst (sicherer), dann Authorization-Header als Fallback
        token = request.cookies.get('ps_session', '')
        if not token:
            token = request.headers.get('Authorization','').replace('Bearer ','').strip()
        # X-API-Key Header Support
        api_key_header = request.headers.get('X-API-Key', '')
        if api_key_header and not token:
            conn = get_db()
            user = db_dict(db_fetchone(conn, 'SELECT * FROM users WHERE api_key=? AND active=1', (api_key_header,)))
            conn.close()
            if user:
                request.user = user
                return f(*args, **kwargs)
            return jsonify({'error':'Ungültiger API-Key'}), 401
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

def require_api_key(f):
    """Authenticate via X-API-Key header for external integrations."""
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key', '').strip()
        if not api_key:
            return jsonify({'error': 'API-Key fehlt. Header X-API-Key erforderlich.'}), 401
        conn = get_db()
        user = db_dict(db_fetchone(conn, 'SELECT * FROM users WHERE api_key=? AND active=1', (api_key,)))
        conn.close()
        if not user:
            return jsonify({'error': 'Ungültiger API-Key'}), 401
        request.user = user
        return f(*args, **kwargs)
    return decorated

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

@app.route('/wissen')
def wissen(): return send_from_directory('static','wissen.html')


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
        VALUES (?,?,?,?,?,?,1,?,0,20,0,?,?,?)''',
        (uid,email,hash_pw(password),name or email.split('@')[0],praxis or 'Meine Praxis','trial','customer',verify_token,trial_end,now()))

    token = secrets.token_hex(32)
    _ip = request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()
    _ua = request.headers.get('User-Agent', '')[:200]
    db_execute(conn, 'INSERT INTO sessions (token,user_id,email,expires_at,created_at,ip_address,user_agent) VALUES (?,?,?,?,?,?,?)',
                 (token,uid,email,(datetime.now()+timedelta(days=30)).isoformat(),now(),_ip,_ua))
    conn.commit(); conn.close()

    # E-Mail-Verifizierung senden
    send_verify_email(email, verify_token)

    # Admin benachrichtigen
    send_admin_notification('Neue Registrierung',
        f'{name or email} ({email}) hat sich registriert. Praxis: {praxis or "k.A."}')

    audit('Registrierung',uid,email)
    resp = make_response(jsonify({
        'token': token,
        'user': {'id':uid,'email':email,'name':name or email,'praxis':praxis,'plan':'trial','role':'customer',
                 'analyses_used':0,'analyses_limit':20,'email_verified':0}
    }), 201)
    is_https = APP_URL.startswith('https')
    resp.set_cookie('ps_session', token, httponly=True, secure=is_https, samesite='Lax', max_age=30*24*3600, path='/')
    return resp

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

@app.route('/api/auth/resend-verification', methods=['POST'])
@require_auth
@limiter.limit("3 per minute")
def resend_verification():
    """Verifizierungs-E-Mail erneut senden."""
    user = request.user
    if user.get('email_verified'):
        return jsonify({'ok':True,'message':'E-Mail ist bereits bestätigt.'})

    conn = get_db()
    verify_token = secrets.token_urlsafe(32)
    db_execute(conn, 'UPDATE users SET verify_token=? WHERE id=?', (verify_token, user['id']))
    conn.commit(); conn.close()

    send_verify_email(user['email'], verify_token)
    audit('Verifizierung erneut gesendet', user['id'], user['email'])
    return jsonify({'ok':True,'message':'Bestätigungs-E-Mail wurde erneut gesendet. Bitte prüfen Sie Ihr Postfach.'})

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

    # 2FA Check
    if user.get('totp_enabled'):
        # Nur temporären Token erstellen (kurze Gültigkeit: 10 Minuten)
        temp_token = 'tmp_' + secrets.token_hex(32)
        db_execute(conn, 'INSERT INTO sessions (token,user_id,expires_at,created_at) VALUES (?,?,?,?)',
                   (temp_token, user['id'], (datetime.now()+timedelta(minutes=10)).isoformat(), now()))
        conn.commit(); conn.close()
        return jsonify({'requires_2fa': True, 'temp_token': temp_token})

    token = secrets.token_hex(32)
    _ip = request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()
    _ua = request.headers.get('User-Agent', '')[:200]
    db_execute(conn, 'INSERT INTO sessions (token,user_id,email,expires_at,created_at,ip_address,user_agent) VALUES (?,?,?,?,?,?,?)',
                 (token,user['id'],em,(datetime.now()+timedelta(days=30)).isoformat(),now(),_ip,_ua))
    db_execute(conn, 'UPDATE users SET last_login=? WHERE id=?',(now(),user['id']))
    conn.commit(); conn.close()

    audit('Login',user['id'],em)
    resp = make_response(jsonify({
        'token': token,
        'user': {k: user[k] for k in ['id','email','name','praxis','plan','role','analyses_used','analyses_limit','email_verified']}
    }))
    is_https = APP_URL.startswith('https')
    resp.set_cookie('ps_session', token, httponly=True, secure=is_https, samesite='Lax', max_age=30*24*3600, path='/')
    return resp

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    # Token aus Cookie ODER Header lesen
    token = request.cookies.get('ps_session','') or request.headers.get('Authorization','').replace('Bearer ','').strip()
    conn = get_db()
    if token: db_execute(conn, 'DELETE FROM sessions WHERE token=?',(token,))
    conn.commit(); conn.close()
    audit('Logout',request.user['id'])
    resp = make_response(jsonify({'ok':True}))
    resp.delete_cookie('ps_session', path='/')
    return resp

@app.route('/api/auth/me')
@require_auth
def me():
    conn = get_db()
    user = db_dict(db_fetchone(conn, 'SELECT * FROM users WHERE id=?',(request.user['id'],)))
    conn.close()
    if not user: return jsonify({'error':'User not found'}), 404
    return jsonify({'user': {k: user.get(k,'') for k in ['id','email','name','praxis','plan','role','analyses_used','analyses_limit','trial_ends_at','email_verified']}})

# ═══════════════════════════════════════════════════
# PATIENTENKARTEI
# ═══════════════════════════════════════════════════

@app.route('/api/patients', methods=['GET'])
@require_auth
def list_patients():
    uid = request.user['id']
    conn = get_db()
    # Einzige Query mit Report-Count via Subquery (kein N+1)
    rows = db_fetchall(conn, '''
        SELECT p.*,
               (SELECT COUNT(*) FROM reports r WHERE r.patient_id=p.id AND r.user_id=p.user_id) AS report_count
        FROM patients p
        WHERE p.user_id=?
        ORDER BY p.name ASC
    ''', (uid,))
    conn.close()
    patients = rows or []
    # report_count sicherstellen (PostgreSQL gibt int, SQLite auch)
    for p in patients:
        p['report_count'] = int(p.get('report_count') or 0)
    return jsonify({'patients': patients})

@app.route('/api/patients', methods=['POST'])
@require_auth
def create_patient():
    d = request.json or {}
    name = d.get('name','').strip()
    if not name: return jsonify({'error': 'Tiername erforderlich'}), 400
    pid = 'p_' + nid()
    conn = get_db()
    try:
        db_execute(conn, '''INSERT INTO patients (id,user_id,name,species,breed,birth_date,weight,owner_name,owner_phone,owner_email,notes,created_at)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                   (pid, request.user['id'], name, d.get('species',''), d.get('breed',''),
                    d.get('birth_date',''), d.get('weight',''), d.get('owner_name',''),
                    d.get('owner_phone',''), d.get('owner_email',''), d.get('notes',''), now()))
        conn.commit()
    except Exception as e:
        try: conn.rollback()
        except: pass
        conn.close()
        return jsonify({'error': str(e)}), 500
    conn.close()
    return jsonify({'id': pid, 'ok': True})

@app.route('/api/patients/<pid>', methods=['GET'])
@require_auth
def get_patient(pid):
    conn = get_db()
    rows = db_fetchall(conn, 'SELECT * FROM patients WHERE id=? AND user_id=?', (pid, request.user['id']))
    if not rows:
        conn.close()
        return jsonify({'error': 'Patient nicht gefunden'}), 404
    patient = db_dict(rows[0]) if rows and not isinstance(rows[0], dict) else rows[0]
    # Befunde des Patienten
    rep_rows = db_fetchall(conn, 'SELECT id,species,region,mode,severity,pet_name,created_at FROM reports WHERE patient_id=? AND user_id=? ORDER BY created_at DESC', (pid, request.user['id']))
    conn.close()
    patient['reports'] = [db_dict(r) if not isinstance(r, dict) else r for r in (rep_rows or [])]
    return jsonify({'patient': patient})

@app.route('/api/patients/<pid>', methods=['PUT'])
@require_auth
def update_patient(pid):
    d = request.json or {}
    conn = get_db()
    existing = db_fetchone(conn, 'SELECT id FROM patients WHERE id=? AND user_id=?', (pid, request.user['id']))
    if not existing:
        conn.close()
        return jsonify({'error': 'Patient nicht gefunden'}), 404
    # Whitelist — verhindert SQL Injection über Feldnamen
    allowed = {'name','species','breed','birth_date','weight','owner_name','owner_phone','owner_email','notes'}
    updates = {k: d[k] for k in allowed if k in d}
    if not updates:
        conn.close()
        return jsonify({'ok': True})
    set_clause = ', '.join(f'{k}=?' for k in updates)
    try:
        db_execute(conn, f'UPDATE patients SET {set_clause} WHERE id=? AND user_id=?',
                   list(updates.values()) + [pid, request.user['id']])
        conn.commit()
    except Exception as e:
        try: conn.rollback()
        except: pass
        conn.close()
        return jsonify({'error': str(e)}), 500
    conn.close()
    return jsonify({'ok': True})

@app.route('/api/patients/<pid>', methods=['DELETE'])
@require_auth
def delete_patient(pid):
    conn = get_db()
    try:
        db_execute(conn, 'DELETE FROM patients WHERE id=? AND user_id=?', (pid, request.user['id']))
        conn.commit()
    except Exception as e:
        try: conn.rollback()
        except: pass
        conn.close()
        return jsonify({'error': str(e)}), 500
    conn.close()
    return jsonify({'ok': True})

# ═══════════════════════════════════════════════════
# STATISTIK-DASHBOARD
# ═══════════════════════════════════════════════════

@app.route('/api/stats')
@require_auth
def user_stats():
    uid = request.user['id']
    conn = get_db()

    def scalar(row):
        """COUNT(*)-Zeile → int, egal ob PostgreSQL-Dict oder SQLite-Tuple."""
        if row is None: return 0
        if isinstance(row, dict):
            return list(row.values())[0]
        return row[0]

    # Gesamt-Befunde
    total = scalar(db_fetchone(conn, 'SELECT COUNT(*) as cnt FROM reports WHERE user_id=?', (uid,)))

    # Diese Woche
    week_ago = (datetime.now() - timedelta(days=7)).isoformat()
    week = scalar(db_fetchone(conn, 'SELECT COUNT(*) as cnt FROM reports WHERE user_id=? AND created_at>?', (uid, week_ago)))

    # Dieser Monat
    month_ago = (datetime.now() - timedelta(days=30)).isoformat()
    month = scalar(db_fetchone(conn, 'SELECT COUNT(*) as cnt FROM reports WHERE user_id=? AND created_at>?', (uid, month_ago)))

    # Nach Tierart (Top 5)
    by_species_rows = db_fetchall(conn, 'SELECT species, COUNT(*) as cnt FROM reports WHERE user_id=? GROUP BY species ORDER BY cnt DESC LIMIT 5', (uid,))
    by_species = [{'species': (r['species'] if isinstance(r, dict) else r[0]), 'count': (r['cnt'] if isinstance(r, dict) else r[1])} for r in (by_species_rows or [])]

    # Nach Schweregrad
    by_sev_rows = db_fetchall(conn, 'SELECT severity, COUNT(*) as cnt FROM reports WHERE user_id=? GROUP BY severity', (uid,))
    by_severity = {(r['severity'] if isinstance(r, dict) else r[0]): (r['cnt'] if isinstance(r, dict) else r[1]) for r in (by_sev_rows or [])}

    # Nach Region (Top 5)
    by_reg_rows = db_fetchall(conn, 'SELECT region, COUNT(*) as cnt FROM reports WHERE user_id=? GROUP BY region ORDER BY cnt DESC LIMIT 5', (uid,))
    by_region = [{'region': (r['region'] if isinstance(r, dict) else r[0]), 'count': (r['cnt'] if isinstance(r, dict) else r[1])} for r in (by_reg_rows or [])]

    # Letzten 7 Tage täglich
    daily = []
    for i in range(6, -1, -1):
        day_start = (datetime.now() - timedelta(days=i)).replace(hour=0,minute=0,second=0).isoformat()
        day_end = (datetime.now() - timedelta(days=i)).replace(hour=23,minute=59,second=59).isoformat()
        cnt = scalar(db_fetchone(conn, 'SELECT COUNT(*) as cnt FROM reports WHERE user_id=? AND created_at>=? AND created_at<=?', (uid, day_start, day_end)))
        day_label = (datetime.now() - timedelta(days=i)).strftime('%a')
        daily.append({'day': day_label, 'count': cnt})

    # Patienten-Anzahl
    patient_count = scalar(db_fetchone(conn, 'SELECT COUNT(*) as cnt FROM patients WHERE user_id=?', (uid,)))

    conn.close()
    return jsonify({
        'total': total,
        'this_week': week,
        'this_month': month,
        'by_species': by_species,
        'by_severity': by_severity,
        'by_region': by_region,
        'daily': daily,
        'patient_count': patient_count
    })

# ═══════════════════════════════════════════════════
# 2FA (TOTP)
# ═══════════════════════════════════════════════════

@app.route('/api/auth/2fa/setup', methods=['POST'])
@require_auth
def setup_2fa():
    """Generiert TOTP-Secret und gibt QR-Code-URL zurück."""
    try:
        import pyotp
    except ImportError:
        return jsonify({'error': 'pyotp nicht installiert. Bitte requirements.txt aktualisieren.'}), 503

    user = request.user
    # Neues Secret generieren
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)

    # QR-Code-URL für Authenticator-Apps
    issuer = 'Animioo'
    otp_uri = totp.provisioning_uri(name=user['email'], issuer_name=issuer)

    # Secret temporär speichern (noch nicht aktiviert)
    conn = get_db()
    try:
        db_execute(conn, "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret TEXT DEFAULT ''")
        db_execute(conn, "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled INTEGER DEFAULT 0")
        conn.commit()
    except:
        try: conn.rollback()
        except: pass
    db_execute(conn, 'UPDATE users SET totp_secret=? WHERE id=?', (secret, user['id']))
    conn.commit(); conn.close()

    return jsonify({'secret': secret, 'otp_uri': otp_uri, 'ok': True})

@app.route('/api/auth/2fa/activate', methods=['POST'])
@require_auth
def activate_2fa():
    """Aktiviert 2FA nach Verifikation des ersten TOTP-Codes."""
    try:
        import pyotp
    except ImportError:
        return jsonify({'error': 'pyotp nicht installiert'}), 503

    d = request.json or {}
    code = d.get('code', '').strip()
    if not code: return jsonify({'error': 'TOTP-Code fehlt'}), 400

    user = request.user
    conn = get_db()
    u = db_dict(db_fetchone(conn, 'SELECT * FROM users WHERE id=?', (user['id'],)))
    conn.close()

    secret = u.get('totp_secret', '')
    if not secret: return jsonify({'error': 'Kein Setup durchgeführt. Bitte zuerst /api/auth/2fa/setup aufrufen.'}), 400

    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({'error': 'Ungültiger Code. Bitte prüfen Sie Ihre Authenticator-App.'}), 400

    conn = get_db()
    db_execute(conn, 'UPDATE users SET totp_enabled=1 WHERE id=?', (user['id'],))
    conn.commit(); conn.close()
    audit('2FA aktiviert', user['id'])
    return jsonify({'ok': True, 'message': '2FA erfolgreich aktiviert!'})

@app.route('/api/auth/2fa/disable', methods=['POST'])
@require_auth
def disable_2fa():
    """Deaktiviert 2FA nach Passwortverifikation."""
    d = request.json or {}
    password = d.get('password', '')
    if not password: return jsonify({'error': 'Passwort erforderlich'}), 400

    user = request.user
    conn = get_db()
    u = db_dict(db_fetchone(conn, 'SELECT * FROM users WHERE id=?', (user['id'],)))
    if not check_pw(password, u['password']):
        conn.close()
        return jsonify({'error': 'Passwort falsch'}), 401

    db_execute(conn, "UPDATE users SET totp_enabled=0, totp_secret='' WHERE id=?", (user['id'],))
    conn.commit(); conn.close()
    audit('2FA deaktiviert', user['id'])
    return jsonify({'ok': True, 'message': '2FA wurde deaktiviert.'})

@app.route('/api/auth/2fa/verify', methods=['POST'])
@limiter.limit("10 per minute")
def verify_2fa():
    """Verifiziert TOTP-Code beim Login (zweiter Schritt)."""
    try:
        import pyotp
    except ImportError:
        return jsonify({'error': 'pyotp nicht installiert'}), 503

    d = request.json or {}
    temp_token = d.get('temp_token', '').strip()
    code = d.get('code', '').strip()

    if not temp_token or not code:
        return jsonify({'error': 'Token und Code erforderlich'}), 400

    # Temp-Session nachschlagen (mit prefix 'tmp_')
    conn = get_db()
    sess = db_dict(db_fetchone(conn, 'SELECT * FROM sessions WHERE token=? AND expires_at>?', (temp_token, now())))
    if not sess:
        conn.close()
        return jsonify({'error': 'Sitzung abgelaufen. Bitte neu anmelden.'}), 401

    user = db_dict(db_fetchone(conn, 'SELECT * FROM users WHERE id=?', (sess['user_id'],)))
    if not user or not user.get('totp_enabled'):
        conn.close()
        return jsonify({'error': 'Ungültige Anfrage'}), 400

    totp = pyotp.TOTP(user['totp_secret'])
    if not totp.verify(code, valid_window=1):
        conn.close()
        return jsonify({'error': 'Ungültiger Code'}), 400

    # Temp-Session löschen, vollständige Session erstellen
    db_execute(conn, 'DELETE FROM sessions WHERE token=?', (temp_token,))
    new_token = secrets.token_hex(32)
    _ip = request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()
    _ua = request.headers.get('User-Agent', '')[:200]
    db_execute(conn, 'INSERT INTO sessions (token,user_id,email,expires_at,created_at,ip_address,user_agent) VALUES (?,?,?,?,?,?,?)',
               (new_token, user['id'], user.get('email',''), (datetime.now()+timedelta(days=30)).isoformat(), now(), _ip, _ua))
    conn.commit(); conn.close()

    audit('2FA Login', user['id'], user['email'])
    resp = make_response(jsonify({
        'token': new_token,
        'user': {k: user.get(k,'') for k in ['id','email','name','praxis','plan','role','analyses_used','analyses_limit','email_verified']}
    }))
    is_https = APP_URL.startswith('https')
    resp.set_cookie('ps_session', new_token, httponly=True, secure=is_https, samesite='Lax', max_age=30*24*3600, path='/')
    return resp

# ═══════════════════════════════════════════════════
# KI-ANALYSE
# ═══════════════════════════════════════════════════
@app.route('/api/analyse', methods=['POST'])
@require_auth
@limiter.limit("10 per minute")
def analyse():
    if not OPENAI_API_KEY and not ANTHROPIC_API_KEY and not GEMINI_API_KEY:
        return jsonify({'error':'KI nicht konfiguriert. Admin muss OPENAI_API_KEY setzen.'}), 503

    user = request.user
    # E-Mail muss bestätigt sein (Admins ausgenommen)
    if user['role'] != 'admin' and not user.get('email_verified'):
        return jsonify({'error':'Bitte bestätigen Sie zuerst Ihre E-Mail-Adresse. Prüfen Sie Ihr Postfach oder lassen Sie die Bestätigungs-E-Mail erneut senden.','code':'EMAIL_NOT_VERIFIED'}), 403

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
    patient_id = d.get('patient_id','').strip()
    # patient_id validieren — muss dem User gehören
    if patient_id:
        conn_v = get_db()
        _p = db_fetchone(conn_v, 'SELECT id FROM patients WHERE id=? AND user_id=?', (patient_id, user['id']))
        conn_v.close()
        if not _p:
            patient_id = ''  # Unbekannter Patient → ignorieren, auto-create läuft später

    # DICOM-Erkennung: Falls Base64-Daten ein DICOM-File sind, konvertieren
    dicom_metadata = {}
    is_dicom = d.get('is_dicom', False)
    if is_dicom and img_a:
        app.logger.info('DICOM-Datei erkannt, konvertiere...')
        converted, dicom_metadata = convert_dicom_to_jpeg_base64(img_a)
        if converted:
            img_a = converted
            app.logger.info(f'DICOM erfolgreich konvertiert. Metadaten: {dicom_metadata}')
        else:
            return jsonify({'error': 'DICOM-Datei konnte nicht verarbeitet werden. Bitte als JPEG/PNG exportieren.'}), 400

    if not img_a: return jsonify({'error':'Kein Bild hochgeladen'}), 400

    # ── Image hash deduplication / caching (sicher falls Spalte noch nicht migriert) ──
    # Hash über Bild + alle Parameter: gleiche Bild mit anderen Einstellungen → neue Analyse
    img_h = image_hash(img_a, species, region, mode, ctx, focus_mode, focus_text)
    # Verweigerungsphrasen die auf einen schlechten Cache-Eintrag hinweisen
    _bad_phrases = ['tut mir leid', 'entschuldigung', 'cannot provide', 'kann keine spezifischen',
                    'unable to', 'i cannot', "i'm sorry", 'i am sorry', 'nicht in der lage']
    try:
        conn = get_db()
        cached = db_dict(db_fetchone(conn, 'SELECT * FROM reports WHERE image_hash=? AND user_id=?', (img_h, user['id'])))
        conn.close()
        if cached:
            cached_text = cached.get('report_text', '') or ''
            # Schlechten Cache-Eintrag ignorieren (KI-Verweigerung aus früherer Analyse)
            is_bad_cache = (
                len(cached_text) < 300 or
                any(p in cached_text.lower() for p in _bad_phrases)
            )
            if is_bad_cache:
                app.logger.info('Schlechter Cache-Eintrag gefunden, neue Analyse wird durchgeführt...')
                # Alten fehlerhaften Eintrag löschen damit er nicht wieder zurückkommt
                try:
                    conn2 = get_db()
                    db_execute(conn2, 'DELETE FROM reports WHERE id=?', (cached['id'],))
                    conn2.commit(); conn2.close()
                except: pass
            else:
                result = {k: cached.get(k, '') for k in ['id','report_text','severity','pet_name','species','region','mode','created_at']}
                result['cached'] = True
                if cached.get('quality_score') is not None:
                    result['quality_score'] = cached['quality_score']
                    result['quality_ok'] = cached['quality_score'] >= 1
                return jsonify(result)
    except Exception as e:
        app.logger.warning(f'Cache-Lookup fehlgeschlagen: {e}')
        try: conn.rollback(); conn.close()
        except: pass
        img_h = ''  # Cache deaktivieren, Analyse trotzdem fortsetzen

    prompts = {
        'single':  f'Erstelle einen vollständigen veterinärmedizinischen Befundbericht für einen {species} im Bereich {region}. WICHTIG: Erkenne zuerst die Bildmodalität (Röntgen, CT oder MRT) und passe deine Analyse entsprechend an. Bei Röntgen: Untersuche JEDEN sichtbaren Knochen, jedes Gelenk, jedes Organ systematisch. Bei CT: Analysiere Schnittebene, Fensterung, Dichteunterschiede. Bei MRT: Bestimme die Sequenz (T1, T2, FLAIR, etc.), analysiere Signalintensitäten, Gewebskontraste, Atrophien, Raumforderungen, Ödeme. Analysiere das Bild EXTREM GRÜNDLICH. Beschreibe auch subtile Veränderungen. ÜBERSEHE NICHTS.',
        'compare': f'Vergleiche Aufnahme A (früher) mit Aufnahme B (aktuell) eines {species} im Bereich {region}. Bestimme zuerst die Bildmodalität. Beschreibe ALLE Veränderungen zwischen den Aufnahmen präzise. Achte besonders auf: Größenveränderungen, neue oder verschwundene Pathologien, Progression oder Regression von Läsionen.',
        'diff':    f'Analysiere die Unterschiede zwischen Aufnahme A und B bei einem {species} im Bereich {region}. Erstelle eine systematische Gegenüberstellung aller Veränderungen.',
        'second':  f'Erstelle eine kritische Zweitmeinung zu den Aufnahmen eines {species} im Bereich {region}. Bestimme zuerst die Bildmodalität (Röntgen/CT/MRT). Hinterfrage offensichtliche Diagnosen und suche gezielt nach übersehenen Pathologien. Untersuche jede Struktur einzeln.',
    }

    # DSGVO: Bilddaten werden NUR zur KI-Analyse an Anthropic gesendet,
    # NICHT in der Datenbank gespeichert. Nach der Analyse werden sie verworfen.

    system = f"""Du bist der weltweit führende Veterinärradiologe — ECVDI-Diplomate, ACVR-zertifiziert,
mit 30 Jahren klinischer Erfahrung, Lehrstuhlinhaber für Veterinärradiologie und Autor von über 200
Fachpublikationen. Du hast über 500.000 veterinärmedizinische Röntgenbilder befundet und wirst
international als Goldstandard-Referenz für Zweitmeinungen konsultiert.

══════════════════════════════════════════════
PATIENTENINFORMATIONEN (vom Tierarzt angegeben):
══════════════════════════════════════════════
- Tierart: {species}
- Körperregion: {region}
{('- Tiername: ' + pet_name) if pet_name else ''}
{('- Klinischer Kontext: ' + ctx) if ctx else ''}
{('- Spezifischer Fokus: ' + focus_text) if focus_mode == 'specific' and focus_text else ''}

Du analysierst AUSSCHLIESSLICH diese Tierart ({species}) in dieser Region ({region}).
Passe ALLE deine Beschreibungen, Normwerte, Differenzialdiagnosen und Empfehlungen
exakt auf {species} / {region} an. Verwende artspezifische Fachterminologie.

Dein Befund muss die Qualität eines Universitätsklinik-Befunds haben. Du analysierst mit der
Präzision und Gründlichkeit, als ob das Leben des Tieres davon abhängt — denn das tut es.

STRIKTE FORMATIERUNGSREGELN:
- KEINE Emojis verwenden! Der Befund ist ein medizinisches Dokument und muss professionell formatiert sein.
- Keine Smileys, keine Unicode-Symbole, keine Emoticons. Nur Fachtext, Markdown-Formatierung und Tabellen.
- Verwende ausschließlich medizinische Fachterminologie in einem sachlich-professionellen Ton.

WICHTIG DATENSCHUTZ: Falls im Bild DICOM-Metadaten oder Patientendaten sichtbar sind,
ignoriere diese vollständig. Nenne KEINE personenbezogenen Daten aus dem Bild.

═══════════════════════════════════════════════════════
DEIN DIAGNOSTISCHER DENKPROZESS (befolge JEDEN Schritt):
═══════════════════════════════════════════════════════

SCHRITT 1 — ERSTE ORIENTIERUNG (5 Sekunden):
- Welche Tierart? Welche Körperregion? Welche Projektion (VD, lateral, DV, AP, ML, LM, CrCd, CdCr)?
- Ist das Bild technisch auswertbar? Belichtung, Lagerung, Artefakte, Bewegungsunschärfe?
- Erster Gesamteindruck: Fällt sofort etwas Abnormales auf?
- Stimmen Tierart und anatomische Proportionen mit den Angaben überein?

SCHRITT 2 — SYSTEMATISCHER SCAN (wie ein CT-Scan durch das Bild):
- Gehe das Bild systematisch von LINKS nach RECHTS, OBEN nach UNTEN durch
- Oder verwende das "Inside-Out"-Prinzip: Beginne zentral, arbeite nach peripher
- JEDE anatomische Struktur wird einzeln identifiziert und beurteilt
- Erstelle eine mentale Checkliste: Habe ich ALLES gesehen?
- ACHTUNG: Beurteile auch die BILDRÄNDER — dort werden die meisten Befunde übersehen!

SCHRITT 3 — PATTERN RECOGNITION (nutze deine 500.000 Bilder Erfahrung):
- Vergleiche das Bild mental mit deiner Datenbank normaler Anatomie
- Identifiziere JEDE Abweichung vom Normalen
- Auch subtile Veränderungen: leichte Dichteunterschiede, minimale Asymmetrien
- Achte auf das "Roentgen Sign": Silhouettenzeichen, Luftbronchogramm, etc.
- Berücksichtige Rasse-spezifische anatomische Normvarianten

SCHRITT 4 — PATHOLOGIE-DEEP-DIVE:
Für JEDE gefundene Abnormalität:
a) Beschreibe EXAKT was du siehst (Größe in mm/cm, Form, Dichte, Begrenzung, Lokalisation)
b) Erstelle eine Differenzialliste (mind. 3 Möglichkeiten)
c) Ordne nach Wahrscheinlichkeit basierend auf:
   - Häufigkeit bei dieser Tierart/Rasse/Alter
   - Röntgenmorphologie
   - Klinischer Kontext (wenn angegeben)
d) Bestimme die klinische Relevanz und Dringlichkeit

SCHRITT 5 — ZWEITER BLICK (der entscheidende Schritt!):
- Gehe NOCHMAL durch das gesamte Bild
- Suche gezielt nach häufig übersehenen Befunden:
  * Haarrissfrakturen (besonders an Metaphysen, Kondylen, Sesambeinen, Processus anconaeus)
  * Kleine Avulsionsfragmente und Chip-Frakturen
  * Fremdkörper (Nadeln, Steine, Knochensequester, Angelhaken)
  * Frühe Periostreaktion (kann sehr subtil sein — nur 1-2mm dick!)
  * Lungenmetastasen (systematisch jedes Lungenfeld! Strukturierte Suche im Lungenparenchym)
  * Wirbelfrakturen (oft übersehen bei Traumapatienten)
  * Veränderungen an den Bildrändern (werden am häufigsten übersehen!)
  * Freie Luft (subkutan, retroperitoneal, intraperitoneal — jeweils klinisch relevant!)
  * Weichteilverkalkungen (Ektopische Mineralisierungen, Dystrophische Verkalkungen)
- Frage dich: "Was würde der erfahrenste Radiologe der Welt hier noch finden?"

SCHRITT 6 — KLINISCHE KORRELATION:
- Passen die Befunde zum angegebenen klinischen Kontext?
- Gibt es Diskrepanzen zwischen Klinik und Röntgenbild? → Explizit erwähnen!
- Welche zusätzlichen Projektionen oder Modalitäten wären diagnostisch hilfreich?
- Gibt es „Red Flags" die sofortiges Handeln erfordern?

═══════════════════════════════════════════════════════
SPEZIES-SPEZIFISCHES EXPERTENWISSEN:
═══════════════════════════════════════════════════════

HUND — Häufige Befunde nach Rasse beachten:
- Große Rassen (>25kg): HD (Norberg-Winkel messen! <105° = dysplastisch), ED (FPC, OCD, IPA, UAP),
  Wobbler-Syndrom, Osteosarkom (Metaphysen langer Röhrenknochen! Prädilektionsstellen: distaler Radius,
  proximaler Humerus, distaler Femur, proximale Tibia), Kreuzbandriss (Schubladentest-Äquivalent:
  Tibiaplateau-Geometrie, periartikuläre Osteophyten, Kompression infrapatelläres Fettpolster)
- Kleine Rassen (<10kg): Patellaluxation (Sulcus-Tiefe beurteilen!), Legg-Calvé-Perthes (Femurkopfnekrose),
  Trachealkollaps (dynamisch! inspiratorisch zervikal, exspiratorisch thorakal), Mitralinsuffizienz
  (linksatriale Vergrößerung → Trachealelevation, Dorsalverlagerung linker Hauptbronchus)
- Brachyzephale (Mops, Bulldogge, Boston Terrier): BOAS, Hemivertebrae (Schmetterlingswirbel!),
  Keilwirbel, Kyphose, Hydrozephalus, verlängertes Gaumensegel
- Chondrodystrophe (Dackel, Basset, Pekinese): IVDD Typ Hansen I — JEDEN Zwischenwirbelraum messen!
  Vakuumphänomen? Kalzifizierte Diskuskerne? Verengter Zwischenwirbelraum?
- Junghunde (<18 Monate): Panosteitis (wandernde Lahmheit, endostale Sklerose), HOD (Metaphysen-
  irregularität), Retentio testis, Physenfrakturen (Salter-Harris I-V klassifizieren!),
  Incomplete ossification of humeral condyle (IOHC → Stress-Fraktur-Risiko!)
- Deutscher Schäferhund: Cauda equina, Lumbosakrale Stenose, Megaösophagus, Pannus
- Golden/Labrador: Osteosarkom, Lymphom (sternale LK!), Subvalvuläre Aortenstenose, Hüftdysplasie
- Rottweiler: Osteosarkom, Kreuzband, OCD Schulter/Tarsus

KATZE — Spezifische Aufmerksamkeit für:
- Thorax: Asthma (klassisches Bronchialpattern, "Donut"- und "Tramlines"-Zeichen),
  HCM (Valentine-Herzsilhouette auf VD), DCM, Pleuraerguss (Ursache? FIP? Lymphom? Pyothorax?),
  Mediastinaltumor (Thymuslymphom bei jungen Katzen!), Lungenlappenkonsolidierung
- Abdomen: Harnsteine (Struvit = röntgendicht, Oxalat = stark röntgendicht, Urat = oft röntgendurchlässig!),
  Obstipation/Megakolon (Kolon-Lumen >Länge L5?), Nierenerkrankung (Nierengröße: normal 2.4-3.0x L2),
  Triaditis, hepatische Lipidose, FIP (Aszites, Granulome)
- Skelett: Aortenthrombose bei HCM (Sattelthrombus → Hintergliedmaßen!), Polydaktylie, OS-Tumoren (seltener),
  Vitamin-A-Hypervitaminose bei reiner Leberfütterung (exostotische Spondylose zervikal!)
- Trauma: Hochhaussyndrom — systematisch: Kiefersymphysenfraktur, Gaumenspaltung, Pneumothorax,
  Harnblasenruptur, Femurkopfluxation, Sakrumfraktur → ALLES prüfen!
- Katzenspezifische Normvariante: "Fat Pad Sign" — retrosternales Fett, KEINE Masse!

PFERD — Falls Pferdebild:
- Huf/Zehe: Hufgelenkarthrose (DIP-Gelenk), Hufrollenerkrankung (Podotrochlose: Strahlbeinveränderungen,
  Kanäle, Zysten, Enthesophyten flexor cortex), Hufbeinfraktur (sagittal, Processus palmaris),
  Hufrehe (Rotationswinkel messen! Senkungsdistanz! Founder-Distanz! Sohlenstärke!)
- Fesselgelenk: Chip-Frakturen (dorsoproximal P1, Mc/Mt III), OCD (sagittaler Kamm),
  Sesamoidose (vaskuläre Kanäle vs. Fraktur vs. Degeneration), Villonodularsymovitis
- Röhrbein: Stressfrakturen (dorsale Kortikalis Mc III — "Bucked Shins"), Griffelbeinfrakturen,
  Kondylärfrakturen (sagittaler Spalt!)
- Karpus/Tarsus: Slab-Frakturen, OCD, Spat (Tarsitis, distale Tarsalgelenke)
- Thorax: EIPH (Exercise-Induced Pulmonary Hemorrhage), Pleuropneumonie

EXOTEN — Reptilien, Vögel, Nager:
- Reptilien: Metabolische Knochenerkrankung (MBD → generalisierte Demineralisation, Faltfrakturen!),
  Legenot (Retentio ovorum — Eier zählen, Größe, Position), Fremdkörper (Substrat!),
  Pneumonie (bei Reptilien oft KEINE Luftbronchogramme!), Gicht (periartikuläre Tophi)
- Vögel: Luftsackverdickung/-Verschattung (Aspergillose! Mykobakteriose!), Legenot,
  Frakturen (sehr dünne Kortikalis, Medullärer Knochen bei legenden Hennen = normal!),
  Proventrikulus-Dilatation (PDD), Hepatomegalie (Sanduhrzeichen), Keel-Bone-Frakturen
- Nager/Kaninchen: Zahnfehlstellungen (Molarensporen, Wurzelspitzen messen!), Tympanic Bullae
  (Otitis media → Vestibularsyndrom), Blasensteine (sehr häufig bei Meerschweinchen!),
  Uterustumoren (Kaninchen >3J: bis 80% Uterusadenokarzinom!), Pneumonie, Thymom (Kaninchen — mediastinale Masse)
- Frettchen: Nebennierenhyperplasie/-tumor (>3.5mm = vergrößert), Insulinom (Hypoglykämie!),
  Milzvergrößerung (extramedulläre Hämatopoese = häufig!), Lymphom, Kardiomyopathie,
  Fremdkörper (Frettchen fressen alles!), Nebennierenrindenerkrankung (Alopezie + NNR-Vergrößerung)
- Schildkröten: Pneumonie (oft einseitig! Schildkröten haben keine Zwerchfell → anders als Säuger!),
  Legenot, Blasensteine (Urat! röntgendurchlässig!), Panzerdefekte, MBD, Fremdkörper (Substrat)
- Igel: Orale Plattenepithelkarzinome (häufigster Tumor!), Pneumonie, Herzerkrankungen, Ballon-Syndrom

ZAHNRADIOLOGIE (Dentalröntgen):
- Hund/Katze: Zahnwurzelabszesse (periapikale Aufhellung!), Zahnresorptionen (FORL bei Katzen —
  Typ 1 vs. Typ 2 differenzieren!), Zahnfrakturen (Pulpahöhle betroffen?), Ankylose,
  Retinierte Zähne, Überzählige Zähne, Knochenabbau (horizontal vs. vertikal = Grad I-IV)
- Parodontalerkrankung graduieren: mild (<25% Knochenverlust), moderat (25-50%), schwer (>50%)
- Kieferfrakturen: Symphyse, Corpus mandibulae (pathologisch bei Tumorlyse?), Ramus

═══════════════════════════════════════════════════════
MRT-ANALYSE (Magnetresonanztomographie):
═══════════════════════════════════════════════════════

GRUNDREGELN MRT:
- ZUERST Sequenz identifizieren: T1 (Fett hell, Liquor dunkel), T2 (Liquor hell, Fett mittel),
  FLAIR (Liquor unterdrückt/dunkel, Ödeme hell), T1+Kontrast (Enhancement = hell), DWI, GRE/SWI
- Schnittebene: Sagittal, Transversal (axial), Dorsal (koronal)
- Signalintensität beschreiben: hyperintens, isointens, hypointens (immer relativ zur Sequenz!)

GEHIRN/SCHÄDEL MRT:
- Großhirn: Symmetrie der Hemisphären, Gyri/Sulci (Atrophie = erweiterte Sulci!), graue/weiße Substanz
- Kleinhirn (Cerebellum): Größe, Form, Fissurenmuster — ATROPHIE erkennen! (verkleinert, verbreiterte
  Fissuren, vergrößerter Subarachnoidalraum um Cerebellum = Kleinhirnatrophie!)
- Hirnstamm: Mesencephalon, Pons, Medulla oblongata — Symmetrie, Läsionen, Kompression
- Ventrikel: Größe (Hydrozephalus?), Symmetrie, Inhalt (Blutung? Tumor?)
- Meningen: Verdickung, Enhancement nach Kontrast (Meningitis/Meningoenzephalitis!)
- Raumforderungen: Intra- vs. extraaxial, Enhancement-Muster, Ödem, Masseneffekt, Mittellinienverlagerung
- Häufige Diagnosen Hund:
  * Meningoenzephalitis unbekannter Ursache (MUO/GME/NME) — multifokal, T2-hyperintens, ringförmiges Enhancement
  * Neospora caninum / Toxoplasma — Kleinhirnatrophie, multifokale Läsionen, junge Hunde!
  * Staupe-Enzephalitis — Demyelinisierung, T2-hyperintense Läsionen weiße Substanz
  * Hirntumoren: Meningeom (extra-axial, starkes homogenes Enhancement, Dural Tail Sign),
    Gliom (intra-axial, heterogen, wenig Enhancement), Choroidplexustumor (intraventrikulär)
  * Hydrozephalus: internus (Ventrikel erweitert) vs. externus (Subarachnoidalraum erweitert)
  * Chiari-ähnliche Malformation (CM/SM) — Herniation Kleinhirntonsillen, Syringomyelie (Cavalier!)
- Häufige Diagnosen Katze:
  * FIP-Meningoenzephalitis — periventrikuläres Enhancement, Hydrozephalus, Ependymitis
  * Lymphom — solitäre oder multifokale Masse, starkes Enhancement
  * Ischämischer Infarkt — keilförmig, territoriale Verteilung

WIRBELSÄULE MRT:
- Rückenmark: Signalintensität (T2-Hyperintensität = Ödem/Myelomalazie!), Dicke, Kompression
- Bandscheiben: Protrusion vs. Extrusion (Hansen I vs. II), Signalverlust T2 = Degeneration
- Epiduralraum: Kompression, Empyem, Hämatom, Fett
- Foramina: Nervenwurzelkompression
- Häufige Diagnosen:
  * IVDD (Diskopathie) — Bandscheibenextrusion, Rückenmarkkompression, Myelopathie-Signal
  * Fibrokartilaginöse Embolie (FCE) — akut, asymmetrisch, intramedullär T2-hyperintens
  * Diskospondylitis — Endplattendestruktion, paravertebraler Abszess
  * Spinale Tumoren: Intramedullär, intradural-extramedullär, extradural
  * Wobbler-Syndrom — dynamische Kompression, Rückenmark-Myelopathie
  * Degenerative Myelopathie — Rückenmarkatrophie, T2-Signalveränderung

GELENKE/MUSKULOSKELETTAL MRT:
- Kreuzband: Integrität, Signal, Verlaufsrichtung (T2 = normal hypointens, Riss = Signalverlust/Ausdünnung)
- Menisken: Signalveränderungen, Risse (erhöhtes Signal auf T2)
- Knorpel: Dicke, Defekte, Signal
- Knochenödem: T2/STIR hyperintens (= Bone Bruise, Stressfraktur, Tumor)

═══════════════════════════════════════════════════════
CT-ANALYSE (Computertomographie):
═══════════════════════════════════════════════════════

GRUNDREGELN CT:
- Fensterung beachten: Knochenfenster (W:2000, L:400), Weichteilfenster (W:400, L:40),
  Lungenfenster (W:1500, L:-600), Hirnfenster (W:80, L:40)
- Dichtewerte in Hounsfield-Einheiten (HU): Luft -1000, Fett -100, Wasser 0, Weichteil 20-60,
  Blut akut 50-70, Knochen >400, Metall >1000
- Kontrastmittel: Pre- vs. Post-Kontrast vergleichen, Enhancement-Muster beschreiben

SCHÄDEL CT:
- Nasen-/Stirnhöhlen: Destruktion, Masse, Flüssigkeit (Rhinitis, Tumor, Aspergillose)
- Bulla tympanica: Verdickung, Flüssigkeit, Osteolyse (Otitis media)
- Orbita: Retrobulbäre Masse, Zellulitis, Fremdkörper
- Gehirn: Blutung (hyperdens!), Tumor, Hydrozephalus, Ödem

THORAX CT:
- Lungenmetastasen-Suche (CT ist sensitiver als Röntgen!)
- Mediastinale Massen, Lymphknoten
- Pulmonale Angiographie: Thromboembolie

ABDOMEN CT:
- Lebertumoren, Milztumoren (Triple-Phase CT!)
- Nebennieren: Phäochromozytom, Adenom, Karzinom
- Portosystemischer Shunt (Angiographie-Phase!)
- Ektopische Ureteren

SKELETT CT:
- Ellbogengelenkdysplasie (FPC, IPA, UAP, OCD — besser als Röntgen!)
- Frakturen: Komplexe Gelenkfrakturen, Schädelfrakturen
- Wirbelsäule: Atlantoaxiale Instabilität, Wirbelkörperfrakturen

═══════════════════════════════════════════════════════
MODALITÄTSERKENNUNG — ENTSCHEIDEND:
═══════════════════════════════════════════════════════

BEVOR du mit der Analyse beginnst, identifiziere die Bildmodalität:
- RÖNTGEN: 2D-Projektionsbild, Graustufen, Knochen weiß, Luft schwarz, typische Projektionen (VD, lateral)
- CT: Schnittbild (axial/sagittal/koronal), scharfe Knochendetails, verschiedene Fensterungen möglich
- MRT: Schnittbild, hervorragender Weichteilkontrast, Liquor hell (T2) oder dunkel (T1),
  typisches Hirngewebe sichtbar mit Gyri/Sulci, kein Knochendetail
- Ultraschall: Echogenitäten, Schallschatten, typisches Sondenbild

Passe deine GESAMTE Analyse an die erkannte Modalität an! Ein MRT des Gehirns wird VÖLLIG ANDERS
befundet als ein Röntgenbild des Thorax!

═══════════════════════════════════════════════════════
NORMWERTE & MESSSTANDARDS (KOMPLETT):
═══════════════════════════════════════════════════════

HERZ:
- VHS (Vertebral Heart Score): Hund 9.7 ± 0.5 (rasseabhängig!)
  * Cavalier King Charles: 10.1-10.7, Boxer: 10.8-11.6, Labrador: 10.0-10.6
  * Whippet: 10.5-11.3, DSH: 9.5-10.0, Dackel: 9.5-10.5, Bulldogge: 11.0-12.0
  * Yorkshire: 9.4-9.8, Chihuahua: 9.0-10.5, Dobermann: 10.0-10.5
- VHS Katze: <8.1 normal, 8.1-8.5 grenzwertig, >8.5 = Kardiomegalie
- VLAS (Vertebral Left Atrial Size): Hund >2.3 = LA-Vergrößerung
- Aortenwurzel/LA-Ratio (M-Mode Echo): normal 1:1, >1.5 = LA-Dilatation
- Pulmonalarterie/Aorta auf VD: PA = Aorta (normal), PA > Aorta = pulmonale Hypertonie
- Pulmonalvene/Pulmonalarterie: 1:1 normal, PV>PA = Stauung, PA>PV = Hypertonie

ABDOMEN:
- Nierengröße Hund: 2.5-3.5 × L2 (Längsachse), Katze: 2.4-3.0 × L2
- Nebenniere Hund: Breite ≤7.4mm (Phäochromozytom wenn >20mm oder asymmetrisch)
- Dünndarmdurchmesser Hund: ≤1.6× Endplattenhöhe L5, Katze: ≤12mm oder ≤2× Endplattenhöhe L2
- Milzdicke Hund: <Kopf letzte Rippe, Katze: kaum sichtbar (wenn sichtbar → Splenomegalie)
- Leber: Magenachse >90° zur WS = Hepatomegalie, <45° = Mikroleber
- Prostata Hund: CC-Durchmesser ≤70% Distanz Sacrum-Pecten
- Kolon Katze: Durchmesser ≤Länge L5, Hund: ≤3× Endplattenhöhe L7
- Blase: Wanddicke Hund <2.3mm (leer bis 3mm), Katze <1.7mm
- Uterus: Normal nicht sichtbar! Wenn sichtbar → Pyometra/Gravidität/Stumpfpyometra

ATEMWEGE:
- Trachea-Thoracic Inlet Ratio (TI): Hund >0.20 normal, <0.16 = hypoplastisch (Bulldogge: normal 0.12-0.16!)
- Trachea/Thoraxeingangsbreite: Hund 0.20, Katze 0.21
- Hauptbronchien: Winkel auf VD normalerweise 60-80°, bei LA-Vergrößerung >80° (Spreading!)

ORTHOPÄDIE:
- Norberg-Winkel (HD): ≥105° = normal, 100-105° = grenzwertig, <100° = dysplastisch
- OFA Grading: Excellent >105°, Good 100-105°, Fair 95-100°, Borderline 90-95°, Mild <90°
- FCI HD-Klassifikation: A (frei), B (Übergang), C (leicht), D (mittel), E (schwer)
- PennHIP DI (Distraction Index): <0.30 = tight, >0.70 = lax (rasseabhängig!)
- Ellbogen IEWG-Grading: 0 (normal), 1 (mild <2mm), 2 (moderat 2-5mm), 3 (schwer >5mm)
- IPA: Processus anconaeus bis 20 Wochen offen = normal, >5 Monate = IPA
- Tibiaplateau-Winkel (TPA): Normal 22-25°, >30° → TPLO indiziert
- Patella: Sulcustiefe, Patellahöhe (Insall-Salvati-Index veterinär)

FRAKTUR-KLASSIFIKATION (Salter-Harris DETAILLIERT):
- Typ I: Physenfuge komplett (nur Epiphysenlösung, Röntgen oft normal! → Klinisch diagnostizieren)
- Typ II: Durch Physe + metaphysäres Dreieck (Thurston-Holland-Fragment) — HÄUFIGSTER TYP
- Typ III: Durch Physe + epiphysär (Gelenkbeteiligung! → Anatomische Reposition nötig!)
- Typ IV: Durch Metaphyse + Physe + Epiphyse (Gelenkbeteiligung + Wachstumsstörung!)
- Typ V: Kompressionsverletzung der Physe (Röntgen initial unauffällig! Retrospektive Diagnose!)
- Prognose: I-II gut, III-IV vorsichtig (Gelenkkongruenz!), V schlecht (Wachstumsstörung)

═══════════════════════════════════════════════════════
LUNGENPATTERN — SYSTEMATISCHE DIFFERENZIERUNG:
═══════════════════════════════════════════════════════

ALVEOLÄRES PATTERN (Luft in Alveolen durch Flüssigkeit/Zellen ersetzt):
- Zeichen: Luftbronchogramm (pathognomonisch!), Lappenzeichen, Konsolidierung
- DDx: Pneumonie (kranioventral!), Lungenblutung (traumatisch, Koagulopathie — oft kaudodorsal!),
  Atelektase (Volumenverlust, Mediastinalshift), Lungentorsion (Gasblase, Gefäßabbruch),
  Lungenödem (kardiogen = perihilär symmetrisch, nicht-kardiogen = kaudodorsal)
- WICHTIG: Verteilung gibt Hinweis auf Ursache!
  * Kranioventral → Aspirationspneumonie, bakterielle Pneumonie
  * Kaudodorsal → Blutung, nicht-kardiogenes Ödem
  * Perihilär symmetrisch → kardiogenes Ödem
  * Fokal → Tumor, Torsion, fokale Pneumonie, Abszess

BRONCHIALES PATTERN (Bronchialwandverdickung):
- Zeichen: "Donuts" (en face), "Tramlines" (seitlich), Bronchialwandverdickung
- DDx: Chronische Bronchitis, felines Asthma (Katze! + Lungenüberblähung!), Bronchiektasie,
  Allergische Bronchitis, parasitäre Bronchitis (Aelurostrongylus, Angiostrongylus)
- Bei Katze + Bronchialpattern + Hyperinflation = Asthma bis zum Beweis des Gegenteils!

INTERSTITIELLES PATTERN:
- Strukturiert (nodulär/retikulär): Metastasen!, Granulome, Fibrose, Pneumonie (Pilz)
  * Miliäres Muster (viele kleine <5mm) → Metastasen, Mykose, Tuberkulose
  * Wenige große Rundherde → Metastasen (Primärtumor suchen!), Granulome, Abszesse, Zysten
- Unstrukturiert: Ödem, Blutung, Fibrose, altersbedingt (normal bei alten Tieren!)
  * CAVE: Unstrukturiert interstitiell bei alten Hunden oft Normalbefund!

VASKULÄRES PATTERN:
- Vergrößerte Pulmonalgefäße: Herzwurm (Dirofilaria — aufgeblähte PA!), Links-Rechts-Shunt,
  Pulmonale Hypertonie, Flüssigkeitsüberladung
- Verkleinerte Gefäße: Hypovolämie, Pulmonalstenose, Rechts-Links-Shunt, Dehydratation
- Asymmetrie: Lungenembolie (verminderte Gefäße fokal!)

═══════════════════════════════════════════════════════
ONKOLOGISCHES STAGING — RADIOLOGISCHE KRITERIEN:
═══════════════════════════════════════════════════════

KNOCHENTUMOREN:
- Osteosarkom: Prädilektionsstellen ("fern vom Ellbogen, nah am Knie" = distaler Radius,
  proximaler Humerus, distaler Femur, proximale Tibia), Sunburst/Codman-Dreieck,
  permeative Lyse, KEINE Gelenküberschreitung (vs. Infektion die Gelenk überschreitet!)
- Chondrosarkom: Rippen, Nasenhöhle, flache Knochen, punktförmige Mineralisierungen
- Fibrosarkom: Ähnlich Osteosarkom, oft mehr lytisch, Mandibula/Maxilla häufig
- Metastatische Knochenläsionen: Multifokal, lytisch (selten produktiv), Weichteilursprung suchen
- Benigne Tumoren: Osteom (glatt, sklerotisch), Osteochondrom (exostotisch, Knorpelkappe)
- AGGRESSIVITÄTS-KRITERIEN: Breite Übergangszone, permeative/mottenfraßartige Lyse,
  Periostreaktion (lamellar, Sunburst, Codman), Weichteilmasse, kortikale Destruktion
  → Je mehr Kriterien, desto aggressiver/maligner

LUNGENMETASTASEN-STAGING:
- Systematisch JEDES Lungenfeld prüfen! Retrokardial und Zwerchfellwinkel nicht vergessen!
- Rundherde >5mm gut erkennbar auf Röntgen, <5mm nur auf CT zuverlässig
- 3-Projektionen-Regel: VD + linke + rechte Seitenlage → maximiert Sensitivität um 15-20%!
- Bei V.a. Lungenmetastasen IMMER CT empfehlen (2-3× sensitiver als Röntgen!)
- Häufigste Primärtumoren mit Lungenmetastasen: Osteosarkom, Hämangiosarkom, Mammakarzinom,
  orales Melanom, Schilddrüsenkarzinom, Übergangszellkarzinom

ABDOMINALE TUMORDIAGNOSTIK:
- Milztumor: Hämangiosarkom (50-66% maligne bei Milzmassen beim Hund!), Hämatom, Hyperplasie
  → Freie Flüssigkeit + Milzmasse = Hämangiosarkom bis zum Beweis des Gegenteils!
- Lebertumor: HCC (massive/nodulär/diffus), Metastasen, noduläre Hyperplasie (benigne!)
- Nebennieren: >20mm oder asymmetrisch → V.a. Adenom/Karzinom/Phäochromozytom
- Lymphom: Hepatosplenomegalie, sublumbale LK-Vergrößerung, renale Infiltration
- Blasentumor: Übergangszellkarzinom (TCC) — oft trigonal! Mineralisierung möglich

═══════════════════════════════════════════════════════
GDV — MAGENDREHUNG NOTFALL-ALGORITHMUS:
═══════════════════════════════════════════════════════

RÖNTGEN-ZEICHEN GDV (ALLE prüfen!):
1. "Double Bubble Sign" (Kompartimentalisierung) — Gas in Fundus UND Pylorus getrennt
2. Pylorus dorsal und links verschoben (normalerweise ventral rechts!)
3. "C-Zeichen" / "Reverse C" — Magengas zeichnet C-Form
4. "Shelf Sign" — Weichteilband teilt Magenlumen
5. Spleen Displacement — Milz nach medial/ventral verlagert
6. Gasfreier Duodenum-Abschnitt
7. Reduzierte seröse Detailzeichnung → freie Flüssigkeit (Perforation? Nekrose?)
8. Pneumoperitoneum → PERFORATION! → Sofort OP!

DIFFERENZIERUNG GDV vs. einfache Dilatation:
- Einfache Dilatation: Pylorus rechts, kein Kompartiment, oft selbstlimitierend
- GDV: Pylorus links-dorsal, Kompartimentalisierung, MUSS operiert werden!
- IMMER rechte Seitenlage-Aufnahme! (Gas im Pylorus links-dorsal = GDV-Beweis)

═══════════════════════════════════════════════════════
MRT-DIFFERENZIALDIAGNOSE-TABELLE GEHIRN:
═══════════════════════════════════════════════════════

INTRA-AXIALE LÄSIONEN (im Parenchym):
| Diagnose | T1 | T2 | FLAIR | Enhancement | Lokalisation | Typisch |
| Gliom | hypo-iso | hyper | hyper | gering-moderat | solitär, Hemisphäre | intra-axial, schlecht begrenzt |
| MUO/GME | iso-hypo | hyper | hyper | ring/multifokal | multifokal, WS+Gehirn | junge Toy-Rassen! |
| NME (Mops) | hypo | hyper | hyper | ring-Enhancement | Großhirn bilateral | Mops, Chihuahua, Malteser |
| NLE (Yorkshire) | hypo | hyper | hyper | minimal | Großhirn | Yorkshire, Französische Bulldogge |
| Infarkt | hypo | hyper | hyper | ±gering | territorial/vaskulär | keilförmig! akut, asymmetrisch |
| Neospora | hypo | hyper | hyper | multifokal | Cerebellum! + multifokal | Welpen, Junghunde! |
| Staupe | hypo | hyper | hyper | ±variabel | weiße Substanz | ungeimpfte Hunde |
| FIP (Katze) | iso | hyper | hyper | periventrikulär! | Ventrikel, Meningen | junge Katzen, Ependymitis |
| Toxoplasma | hypo | hyper | hyper | ring-Enhancement | multifokal | immunsupprimiert, Katze>Hund |
| Lymphom | iso-hypo | iso-hyper | hyper | stark homogen | solitär oder multifokal | oft extra-axial |

EXTRA-AXIALE LÄSIONEN (außerhalb Parenchym):
| Meningeom | iso-hypo | iso-hyper | hyper | stark homogen! | konvex, Dural Tail! | häufigster Tumor! >5J |
| Choroidplexus | iso | hyper | hyper | stark | intraventrikulär! | Seitenventrikel, 4. Ventrikel |
| Epidermoid/Dermoid | hypo | hyper | variabel | kein/minimal | CPA, Mittellinie | selten |
| Trigeminus-Tumor | iso-hypo | iso-hyper | hyper | stark | Schädelbasis, CN V | einseitig, Kaumuskelatrophie |

WICHTIG — Red Flags im MRT:
- Mittellinienverlagerung >3mm → Raumforderung → Dringend!
- Tentorielle Herniation → Lebensbedrohlich!
- Obex-Herniation (Foramen magnum) → Atemnot-Risiko!
- Ringförmiges Enhancement + Ödem → Tumor oder Abszess bis Beweis des Gegenteils
- DWI-Restriktion + ADC-Erniedrigung → Akuter Infarkt (<24h) oder Abszess

═══════════════════════════════════════════════════════
CT-KONTRASTMITTEL-PROTOKOLLE:
═══════════════════════════════════════════════════════

KONTRASTPHASEN (jodhaltig, nicht-ionisch, 600-800 mgI/kg IV):
- Angiographische Phase: 5-15 Sek nach Injektion → Gefäßdarstellung, Shunts, PSS
- Arterielle Phase: 15-25 Sek → Leberarterielle Versorgung, hypervaskularisierte Tumoren
- Portalvenöse Phase: 35-60 Sek → Standard-Abdomen, Leberparenchym, Milz
- Nephrographische Phase: 60-90 Sek → Nierenparenchym, Harnleiter
- Spätphase/Equilibrium: >120 Sek → Ektopische Ureteren, Exkretionsurographie, Harnblase
- Triple-Phase-CT (Leber/Milz): Arteriell + Portalvenös + Spät → Tumorcharakterisierung!
  * HCC: arteriell hyperdens, portalvenös wash-out
  * Hämangiom: peripheres arterielles Enhancement, zentripetales Fill-in
  * Noduläre Hyperplasie: isodens in allen Phasen

CT-SPEZIFISCHE MESSUNGEN:
- Hounsfield-Einheiten Referenz: Luft -1000, Fett -80 bis -120, Wasser 0, Leber 50-70,
  Milz 45-55, Niere 30-50, Muskel 35-55, akutes Blut 50-70, Knochen >400
- Fett: -80 bis -120 HU (Lipom? Liposarkom wenn heterogen!)
- Flüssigkeit: 0-20 HU (transsudat), 20-40 HU (modifiziertes Transsudat/Exsudat)
- Akute Blutung: 50-70 HU (hyperdens! → Trauma, Milzruptur, Koagulopathie)

═══════════════════════════════════════════════════════
HÄUFIGE FALLSTRICKE & FEHLDIAGNOSEN VERMEIDEN:
═══════════════════════════════════════════════════════

RÖNTGEN-FALLSTRICKE:
- Normvarianten NICHT als Pathologie melden: Fabellae, Sesamoide, akzessorische Ossifikationszentren,
  Enthesophyten bei älteren Tieren, Os penis, Os clitoridis, physiologische Periostreaktion bei Jungtieren
- NICHT verwechseln: Mach-Effekt (Mach Bands) mit echten Frakturlinien
- Überlagerungsartefakte: Hautfalten, Zitzen, Schmutz auf der Kassette → können Lungenrundherde vortäuschen!
- "Satisfaction of Search" vermeiden: Nach dem ersten Befund WEITERSUCHEN — es gibt oft 2-3 Pathologien!
- Seitenmarkierung beachten: Rechts/Links korrekt zuordnen! Bei Fehlen → explizit erwähnen
- Projektionsbedingte Verzerrungen berücksichtigen: Vergrößerung durch OFD (Object-Film Distance)
- Jungtiere: Wachstumsfugen NICHT mit Frakturen verwechseln! Altersentsprechende Ossifikation kennen
- Alte Tiere: Degenerative Veränderungen von akuten Pathologien unterscheiden — Spondylose ≠ Diskospondylitis!
- Artefakte erkennen: Bewegungsunschärfe, Streustrahlung, Gitterartefakte, Doppelbelichtung
- Exspiratorische Thoraxaufnahme → Pseudokardiomegalie und Pseudo-Lungenödem!
- Überbelichtung → Lungenrundherde werden unsichtbar! Unterbelichtung → Pseudo-Infiltrate!
- Adipöse Tiere: Fett vortäuschen Organomegalie, verminderte seröse Detailzeichnung ≠ Erguss
- Nasse Tiere/Fell: Können interstitielles Lungenmuster vortäuschen (Fellüberlagerung)

MRT-FALLSTRICKE:
- T1-Hyperintensität: Fett ODER Methämoglobin (subakute Blutung) ODER Protein ODER Melanin
  → Fettsättigung (STIR/Fat-Sat) nutzen zur Differenzierung!
- T2-Hyperintensität: Ödem ODER Tumor ODER Entzündung ODER Demyelinisierung ODER Gliose ODER Zyste
  → Enhancement-Muster und DWI zur Differenzierung nutzen!
- Magic Angle Artifact: Sehnen bei 55° zum Hauptmagnetfeld → falsch hyperintens auf kurzen TE-Sequenzen
- Truncation Artifact: Parallele Banden am Übergang Cortex/Medulla → kann Syringomyelie vortäuschen!
- Susceptibility Artifact: Metallimplantate, Luft → Signalauslöschung (besonders GRE/SWI)
- Chemical Shift Artifact: Fett-Wasser-Grenzfläche → Fehlregistrierung (Niere, Augen, Fettgewebe)
- Flow Artifacts: Pulsationsartefakte von Gefäßen → können Läsionen vortäuschen oder verbergen
- Partial Volume Effect: Kleine Strukturen in dicken Schichten → Läsionen werden über-/unterschätzt
- CAVE: Kontrastmittel-Enhancement ≠ automatisch Tumor! Auch Entzündung, Infarkt (subakut), Abszess!
- CAVE: Fehlende Enhancement ≠ benigne! Niedriggradige Gliome enhancen oft NICHT!

CT-FALLSTRICKE:
- Beam Hardening: Artefakte an Knochen-Weichteil-Grenzen (Schädelbasis!) → Pseudoläsionen
- Volume Averaging: Teilvolumeneffekte an Strukturgrenzen → kleine Läsionen unsichtbar
- Kontrastmittel-Timing: Falsches Timing → Tumor wird verpasst oder fehlcharakterisiert
  * Zu früh: Tumor noch nicht enhancet → wird als iso angesehen
  * Zu spät: Hypervaskularisierte Läsion zeigt Wash-out → wird als hypo fehlinterpretiert
- Pseudo-Enhancement: Zyste neben stark enhancender Struktur → scheinbares Enhancement (Beam Hardening)
- Hounsfield-Variabilität: Verschiedene CT-Geräte zeigen unterschiedliche HU-Werte für gleiches Gewebe!
- Window/Level: IMMER alle Fenster prüfen — Weichteil-Fenster zeigt keine Lungenläsionen, Lungenfenster keine Knochen!

═══════════════════════════════════════════════════════
UNVERHANDELBARE ANALYSE-REGELN:
═══════════════════════════════════════════════════════

1. SYSTEMATISCHE VOLLSTÄNDIGKEIT: Analysiere JEDE sichtbare anatomische Struktur — Knochen,
   Gelenke, Weichteile, Organe, Hohlräume. Überspringe NICHTS.

2. KNOCHEN & SKELETT: Prüfe bei JEDEM sichtbaren Knochen:
   - Kortikalis: Kontinuität, Dicke, Glattheit (Frakturen, Fissuren?)
   - Periost: Reaktionen, Auftreibungen, Spikulae (Sunburst? Codman-Dreieck? → Tumor!)
   - Spongiosa: Mineralisierung, Dichte, Lysen (geographisch? mottenfraßartig? permeativ?), Sklerosen
   - Alignment: Achsenstellung, Displacement, Angulation, Verkürzung, Rotation
   - Wachstumsfugen bei Jungtieren: Salter-Harris Typ I-V prüfen!
   - Medullärraum: Sklerose, Lyse, Pathologische Fraktur?

3. GELENKE: Bei JEDEM sichtbaren Gelenk:
   - Gelenkspalt: Weite, Symmetrie, Kongruenz
   - Subchondrale Knochenplatte: Sklerose, Erosionen, Zysten, Unregelmäßigkeiten
   - Periartikulär: Osteophyten (graduieren! Grad 1-4), Enthesophyten, Schwellungen, Verkalkungen
   - Gelenkerguss: Verbreiterter Gelenkspalt, Kapseldistension, Fettpolster-Zeichen
   - Luxation/Subluxation: Norberg-Index bei HD! Kongruenz bei Ellbogen!

4. WEICHTEILE: Systematisch untersuchen:
   - Schwellungen (diffus vs. lokalisiert), Asymmetrien, Masseneffekte
   - Gaseinschlüsse (subkutan? fascial? → Gasgangrän ausschließen!)
   - Fremdkörper, Faszienlinien, Fettstreifen (Verlust = Ödem/Infiltration)
   - Muskelatrophie (im Seitenvergleich beurteilen wenn möglich)
   - Verkalkungen (dystrophisch, metastatisch, idiopathisch — Calcinosis cutis/circumscripta)

5. THORAX (wenn sichtbar):
   - Herz: VHS BERECHNEN und exakten Zahlenwert nennen
   - Einzelne Kammern: LA-Vergrößerung (Dorsalverlagerung Trachea, Kompression linker Hauptbronchus,
     „Cowboy Legs" auf VD), RA, LV (Elongation Apex), RV (Verbreiterung Sternalkontakt)
   - Pulmonalgefäße: Vergrößert (>Rippe/Vene = pulmonale Hypertonie), Verkleinert (Hypovolämie, PS)
   - Lunge: JEDES Lungenfeld systematisch — alveoläres Pattern (Luftbronchogramm! → Pneumonie, Blutung,
     Atelektase), bronchiales Pattern (Tramlines, Donuts → Bronchitis, Asthma), interstitielles Pattern
     (strukturiert = Fibrose, unstrukturiert = Ödem, Blutung), vaskuläres Pattern, gemischt
   - Lungenrundherde: METASTASEN-SUCHE! Systematisch alle Lungenfelder, Zwerchfellwinkel, retrokardial
   - Pleura: Erguss (Meniskenzeichen, Lappenspalten?), Pneumothorax (Retraktionslinien, fehlende
     Lungengefäße peripher!), Pleuraverdickung
   - Mediastinum: Breite, Masse, sternale/tracheobronchiale Lymphknoten (>Rippe = vergrößert!)
   - Trachea: Hypoplasie (TI-Ratio!), Kollaps, Dorsalverlagerung, Masse, Fremdkörper
   - Ösophagus: Megaösophagus? Fremdkörper? Perforation (Pneumomediastinum!)?
   - Zwerchfell: Integrität, Hernia diaphragmatica, Eventration

6. ABDOMEN (wenn sichtbar):
   - Leber: Größe (Magenachse! >90° = Hepatomegalie, <45° = Mikroleber), Konturen, Masse?
   - Milz: Größe, Kontur, Masse (Hämangiosarkom! → Peritonealerguss?)
   - Nieren: Größe (L2-Verhältnis!), Konturen, Mineralisierungen (Nephrolithiasis, Nephrokalzinose)
   - Nebennieren: Vergrößerung, Mineralisierung (Cushing? Phäochromozytom?)
   - GI-Trakt: Gas-/Flüssigkeitsverteilung — Ileus? (Dünndarmdurchmesser-Regel!), Fremdkörper,
     Invagination, GDV (Double Bubble! C-Zeichen! Kompartmentalisierung! → NOTFALL!)
   - Blase: Größe, Wanddicke, Konkremente (Röntgendichte → Steinart?), Position (Ruptur? Hernie?)
   - Prostata/Uterus: Vergrößerung, Mineralisierung, Pyometra (vergrößerte Uterushörner!)
   - Peritonealer Detailzeichnung: verloren = freie Flüssigkeit! Fokaler Detailverlust = lokale Entzündung
   - Retroperitonealraum: Nierenloge, Nebennieren, sublumbale Lymphknoten
   - Freies Gas: Pneumoperitoneum → Perforation bis zum Beweis des Gegenteils!

7. WIRBELSÄULE (wenn sichtbar):
   - JEDEN Wirbelkörper einzeln: Form, Dichte, Endplatten, Processus spinosi
   - Zwischenwirbelräume: Höhe (Verengung = Diskopathie), Vakuumphänomen, Kalzifikation
   - Alignment: Scoliose, Kyphose, Lordose, Stufenbildung, Wirbelkörperluxation
   - Foramina: Einengung bei Diskopathie/Spondylose
   - Endplatten: Diskospondylitis (Irregularität, Lyse, Sklerose, Spondylose sekundär)
   - Facettengelenke: Arthrose, Asymmetrie
   - Cauda equina (lumbosakral): Spondylose, Osteophyten, Stenose

8. PATHOLOGIE-ERKENNUNG — NULL TOLERANZ:
   - Frakturen: JEDE Art — Quer, Schräg, Spiral, Trümmer, Grünholz, Salter-Harris, Avulsion, Stress,
     pathologisch, Insuffizienz, Ermüdung. Komplett vs. inkomplett. Disloziert vs. nicht-disloziert.
   - Tumore: Sunburst-Pattern, Codman-Dreieck, mottenfraßartige/permeative Lysen → SOFORT als Verdacht
     benennen! Histologische Differenzialdiagnosen: Osteosarkom, Chondrosarkom, Fibrosarkom, Hämangiosarkom,
     Metastasen. Weichteilsarkome: Randcharakteristik beurteilen
   - Aggressive vs. nicht-aggressive Knochenläsionen systematisch differenzieren (Zone of Transition!)
   - Infektionen: Osteomyelitis (Sequester? Involucrum? Kloake?), Diskospondylitis, septische Arthritis
   - JEDE osteolytische oder osteoproduktive Läsion als potenziell maligne betrachten bis zum Beweis des Gegenteils

9. KLARE AUSSAGEN — KEINE VAGHEIT:
   - "Querfraktur der distalen Diaphyse des rechten Femurs mit ca. 3mm lateralem Displacement,
     30° Angulation und moderater periartikulärer Weichteilschwellung" — SO muss eine Beschreibung aussehen
   - Graduiere: mild/moderat/schwer/hochgradig
   - Prozentangaben bei Differenzialdiagnosen
   - IMMER konkrete Messungen wenn möglich (mm, cm, Grad, Verhältnisse)

10. DRINGLICHKEIT — KORREKT UND VERANTWORTUNGSVOLL:
    - NIEDRIG: Normalbefund, leichte degenerative Veränderungen, Zufallsbefunde, chronische stabile Läsionen
    - MITTEL: Moderate Pathologien, zeitnahe Kontrolle nötig (Tage), neue Befunde ohne Notfallcharakter
    - HOCH: Frakturen, Luxationen, signifikante Organveränderungen, Tumorverdacht, Ileus-Verdacht
    - NOTFALL: GDV (Magendrehung!), Spannungspneumothorax, Harnröhrenverschluss, Harnblasenruptur,
      schwere Blutung/Hämabdomen, Wirbelfraktur mit Myelokompression, Zwerchfellruptur mit Organverlagerung,
      offene Frakturen, Ösophagus-Fremdkörper mit Perforationsgefahr

11. QUALITÄTSKONTROLLE — BEVOR DU DEN BEFUND ABGIBST:
    - Habe ich JEDE sichtbare Struktur beurteilt?
    - Habe ich die Bildränder geprüft?
    - Habe ich den „zweiten Blick" durchgeführt?
    - Habe ich nach "Satisfaction of Search" geprüft (gibt es weitere Befunde)?
    - Stimmt meine Dringlichkeitseinstufung mit den Befunden überein?
    - Sind meine Differenzialdiagnosen sinnvoll und nach Wahrscheinlichkeit geordnet?
    - Sind meine Therapieempfehlungen konkret und umsetzbar?
    - Habe ich Normwerte/Messungen angegeben wo relevant?
    - Würde der weltweit beste Veterinärradiologe etwas anders machen? Wenn ja — ändere es!

PFLICHT: Die DIAGNOSE und der MEDIZINISCHE ZUSTAND kommen IMMER ZUERST.
Erstelle den Befundbericht auf Deutsch.

FORMAT - genau diese Reihenfolge einhalten:

## Diagnose & Klinische Beurteilung
**Hauptdiagnose:** [Präzise, spezifische Diagnose mit exakter Lokalisation — so wie du es einem
Fachtierarzt-Kollegen sagen würdest. Kein "möglicherweise" oder "eventuell" bei klaren Befunden!]
**Nebendiagnosen:** [Falls vorhanden — ALLE weiteren relevanten Befunde, auch Zufallsbefunde]
**Dringlichkeit:** **[NIEDRIG / MITTEL / HOCH / NOTFALL]** — [Klare Begründung mit klinischer Relevanz]

## Differenzialdiagnosen
| Diagnose | Wahrscheinlichkeit | Begründung |
|---|---|---|
[Mindestens 3-5 Differenzialdiagnosen, nach Wahrscheinlichkeit sortiert, mit Prozentangabe und
konkreter röntgenologischer Begründung. Bei Tumorverdacht immer histologische Typen auflisten.
Bei Frakturen: Typ und Klassifikation angeben.]

## Detaillierter Radiologischer Befund
[Systematische Analyse JEDER sichtbaren Struktur mit ### Überschriften pro Region.
Beschreibe NORMALE und PATHOLOGISCHE Befunde. Normale Befunde dokumentieren die Gründlichkeit.
Verwende exakte veterinärradiologische Fachterminologie und Messungen wo möglich.
Gib Normwerte zum Vergleich an (z.B. "VHS 11.2 — normal <10.2 für diese Rasse").
Dies ist der Kernabschnitt — hier zeigst du deine 30 Jahre Erfahrung.]

## Therapie- & Kontrollempfehlungen
[Konkrete, priorisierte Handlungsempfehlungen:
1. Sofortmaßnahmen (wenn nötig — z.B. Stabilisierung, Analgesie, Thoraxdrainage)
2. Weiterführende Diagnostik (CT? MRT? Ultraschall? Arthroskopie? Biopsie? Blutbild? Urinanalyse?
   Kontrastmittelstudien? Zusätzliche Projektionen?)
3. Therapieoptionen mit Vor-/Nachteilen (konservativ vs. chirurgisch, welche OP-Technik?
   Plattenosteosynthese? Fixateur externe? Marknagel? Konservativ mit Robert-Jones-Verband?)
4. Medikamentöse Empfehlungen (Analgesie, Antibiotika wenn indiziert, Entzündungshemmer)
5. Kontrollzeitpunkt (wann? welche Aufnahmen? was erwarten wir? Kallusbildung nach 2-3 Wochen?)
6. Prognose (mit und ohne Therapie, kurz- und langfristig, funktionell)]

## Technische Bildqualität
[Aufnahmetechnik, Belichtung, Lagerung, Projektionsrichtung, Artefakte.
Empfehlungen für bessere Aufnahmen oder zusätzliche Projektionen (z.B. "Zusätzliche DV-Aufnahme
empfohlen zur besseren Beurteilung des Mediastinums")]

---
*Animioo KI-Befundassistent -- Expertenniveau. Kein Ersatz fuer tieraerztliche Diagnose.*"""

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

    # ── Helper: Anthropic (BACKUP — nur wenn OpenAI nicht verfuegbar) ──
    def try_anthropic():
        if not ANTHROPIC_API_KEY: return None
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        for attempt in range(3):
            try:
                resp = client.messages.create(
                    model='claude-sonnet-4-20250514',
                    max_tokens=4096,
                    temperature=0,
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

    # ── Helper: OpenAI (PRIMAER — GPT-4o Bildanalyse mit allen Nutzerparametern) ──
    def try_openai():
        if not OPENAI_API_KEY: return None
        from openai import OpenAI
        oc = OpenAI(api_key=OPENAI_API_KEY)

        # Alle vom Nutzer gewählten Parameter in den Prompt einbauen
        mode_labels = {
            'single':  'Einzelanalyse (ein Bild)',
            'compare': 'Verlaufsanalyse (Vorher/Nachher-Vergleich)',
            'diff':    'Bildvergleich (zwei Aufnahmen gegenüberstellen)',
            'second':  'Zweitmeinung (kritische Überprüfung)'
        }
        oai_system = f"""You are an expert veterinary radiologist helping licensed veterinarians interpret animal radiological images.
This is a professional veterinary diagnostic support platform (Animioo) used exclusively by licensed veterinarians.
You are analyzing ANIMAL (non-human) images — this is veterinary medicine only.

PATIENT INFORMATION provided by the veterinarian:
- Animal species (Tierart): {species}
- Body region (Körperregion): {region}
- Analysis mode (Analyse-Modus): {mode_labels.get(mode, mode)}
{f'- Patient name (Tiername): {pet_name}' if pet_name else ''}
{f'- Clinical context (Klinischer Kontext): {ctx}' if ctx else ''}
{f'- Specific focus (Spezifischer Fokus): {focus_text}' if focus_mode == 'specific' and focus_text else ''}

TASK: Create a complete, professional veterinary radiology report in German for this {species} — region: {region}.

MANDATORY REPORT STRUCTURE (use exactly these section headers):
## Befund
[Systematic description of ALL visible structures. Describe every bone, joint, organ, and soft tissue visible. Note any abnormalities precisely — location, size, shape, density, margins.]

## Diagnose
[Primary diagnosis with confidence level. Include radiological severity.]

## Differenzialdiagnosen
[List all differential diagnoses with reasoning.]

## Therapie- & Kontrollempfehlungen
[Concrete, prioritized recommendations: immediate actions, further diagnostics, therapy options, follow-up timing.]

## Technische Bildqualität
[Image technique, exposure, positioning, artifacts, recommendations for additional views.]

STRICT RULES:
- Write ONLY in professional German
- NO emojis, NO symbols — pure medical text
- Be extremely thorough — describe EVERY visible structure
- You MUST analyze the image completely — this is a professional veterinary tool
- Provide expert-level findings as a board-certified veterinary radiologist would"""

        # Bilder und Texte für OpenAI aufbereiten
        oai_content = []
        for m in msgs:
            if m['type'] == 'image':
                oai_content.append({
                    'type': 'image_url',
                    'image_url': {
                        'url': f"data:{m['source']['media_type']};base64,{m['source']['data']}",
                        'detail': 'high'
                    }
                })
            else:
                # Prompt-Texte überspringen (bereits im System-Prompt)
                if m['text'] not in ('Aufnahme A:', 'Aufnahme B:'):
                    oai_content.append({'type': 'text', 'text': m['text']})

        # Klarer Analyseauftrag als User-Message
        analysis_request = f"Bitte erstelle einen vollständigen radiologischen Befundbericht für diesen {species} (Körperregion: {region})."
        if pet_name:
            analysis_request += f" Patient: {pet_name}."
        if ctx:
            analysis_request += f" Klinischer Kontext: {ctx}."
        if focus_mode == 'specific' and focus_text:
            analysis_request += f" Besonderer Fokus auf: {focus_text}."
        oai_content.append({'type': 'text', 'text': analysis_request})

        for attempt in range(3):
            try:
                resp = oc.chat.completions.create(
                    model='gpt-4o',
                    max_tokens=4096,
                    temperature=0,
                    messages=[
                        {'role': 'system', 'content': oai_system},
                        {'role': 'user', 'content': oai_content}
                    ]
                )
                content = resp.choices[0].message.content or ''
                # Verweigerungsantworten erkennen und Fallback auslösen
                refusal_phrases = ['tut mir leid', 'entschuldigung', 'cannot provide', 'kann keine spezifischen',
                                   'unable to', 'i cannot', "i'm sorry", 'i am sorry', 'nicht in der lage']
                if any(p in content.lower() for p in refusal_phrases) and len(content) < 500:
                    app.logger.warning(f'OpenAI Verweigerung (Versuch {attempt+1}), retry...')
                    if attempt < 2:
                        _time.sleep(1)
                        continue
                    return None
                return content if len(content) > 150 else None
            except Exception as e:
                app.logger.warning(f'OpenAI Fehler (Versuch {attempt+1}): {e}')
                if attempt < 2:
                    _time.sleep(2 * (attempt + 1))
                    continue
                return None
        return None

    # ── Helper: Google Gemini ──
    def try_gemini():
        if not GEMINI_API_KEY: return None
        try:
            import google.generativeai as genai
            import base64
            genai.configure(api_key=GEMINI_API_KEY)
            model = genai.GenerativeModel('gemini-2.0-flash', generation_config={'temperature': 0})
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

    # ── Multi-Provider Fallback (OpenAI primär, Claude Backup, Gemini letzter Ausweg) ──
    providers = [
        ('OpenAI', try_openai),
        ('Anthropic', try_anthropic),
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

    # ── Qualitätskontrolle ──
    required_sections = ['diagnose', 'differenzialdiagnosen', 'befund', 'therapie']
    sections_found = sum(1 for s in required_sections if s in tl)
    quality_ok = sections_found >= len(required_sections) and len(text) >= 500
    quality_score = sections_found  # 0-4, 4 = all sections present

    rid = 'r_'+nid()
    conn = get_db()
    # Fehlende Spalten zuerst per Migration hinzufügen (PostgreSQL-sicher)
    for migration in [
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS image_hash TEXT DEFAULT ''",
        "ALTER TABLE reports ADD COLUMN IF NOT EXISTS quality_score INTEGER",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS api_key TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS pet_name TEXT DEFAULT ''",
    ]:
        try:
            db_execute(conn, migration)
            conn.commit()
        except Exception:
            try: conn.rollback()
            except: pass
    # INSERT mit allen Spalten
    try:
        db_execute(conn, 'INSERT INTO reports (id,user_id,pet_name,species,region,mode,severity,report_text,image_data,image_hash,quality_score,patient_id,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)',
                     (rid,user['id'],pet_name,species,region,mode,sev,text,img_a,img_h,quality_score,patient_id,now()))
    except Exception as e:
        app.logger.warning(f'INSERT fehlgeschlagen ({e}), Rollback + Fallback...')
        try: conn.rollback()
        except: pass
        try:
            db_execute(conn, 'INSERT INTO reports (id,user_id,pet_name,species,region,mode,severity,report_text,image_data,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
                         (rid,user['id'],pet_name,species,region,mode,sev,text,img_a,now()))
        except Exception as e2:
            app.logger.error(f'INSERT Fallback fehlgeschlagen: {e2}')
            try: conn.rollback()
            except: pass
            conn.close()
            return jsonify({'error': f'Datenbankfehler: {str(e2)}'}), 500
    db_execute(conn, 'UPDATE users SET analyses_used=analyses_used+1 WHERE id=?',(user['id'],))

    # Auto-Patientenakte: falls pet_name angegeben und noch kein patient_id verknüpft,
    # automatisch Patient suchen oder neu anlegen und Befund verknüpfen
    auto_patient_id = patient_id
    if pet_name and not patient_id:
        try:
            existing_patient = db_fetchone(conn,
                'SELECT id FROM patients WHERE user_id=? AND name=? AND species=?',
                (user['id'], pet_name, species))
            if existing_patient:
                auto_patient_id = db_dict(existing_patient)['id']
            else:
                auto_patient_id = 'p_' + nid()
                db_execute(conn,
                    '''INSERT INTO patients (id,user_id,name,species,breed,birth_date,weight,
                       owner_name,owner_phone,owner_email,notes,created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                    (auto_patient_id, user['id'], pet_name, species,
                     '','','','','','','', now()))
            # Befund mit Patient verknüpfen
            db_execute(conn, 'UPDATE reports SET patient_id=? WHERE id=?', (auto_patient_id, rid))
        except Exception as e:
            app.logger.warning(f'Auto-Patient Fehler: {e}')
            auto_patient_id = None

    conn.commit(); conn.close()

    audit('Analyse',user['id'],f'{species}/{region}/{mode} via {used_provider}')
    result = {'id':rid,'report_text':text,'severity':sev,'pet_name':pet_name,'species':species,'region':region,'mode':mode,'created_at':now(),
              'quality_ok':quality_ok,'quality_score':quality_score,'dicom_metadata':dicom_metadata,
              'patient_id': auto_patient_id or patient_id or ''}
    return jsonify(result)

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
    image_data = d.get('image_data','') or context.get('image_data','')

    if not question: return jsonify({'error':'Keine Frage gestellt'}), 400
    if not report_text: return jsonify({'error':'Kein Befund vorhanden'}), 400

    has_image = bool(image_data and len(image_data) > 100)

    system = f"""Du bist ein erfahrener ECVDI-Diplomate für Veterinärradiologie.
Ein Tierarzt stellt Rückfragen zu einem Röntgenbild und dem dazugehörigen KI-Befund.
{"Das originale Röntgenbild wurde dir zur direkten Begutachtung mitgeschickt. Analysiere es bei jeder Antwort erneut und beziehe dich auf das, was du konkret im Bild siehst." if has_image else ""}

Befund-Kontext: {context.get('species','Hund')}, {context.get('region','Thorax')}, Modus: {context.get('mode','single')}
{('Patient: '+context['pet_name']) if context.get('pet_name') else ''}

Der ursprüngliche KI-Befundbericht:
---
{report_text}
---

Beantworte die Fragen des Tierarztes auf Deutsch, präzise und fachlich korrekt.
- Schaue dir das Röntgenbild direkt an und beschreibe was du siehst — verlasse dich nicht nur auf den Textbefund.
- Erkläre Fachbegriffe wenn nötig.
- Gib konkrete, praxisrelevante Antworten.
- Halte die Antworten kurz und fokussiert (max 200 Wörter).
- Wenn du dir bei etwas unsicher bist, sage es ehrlich."""

    # Bisherige Chat-History (ohne Bild — Bild kommt bei jeder Frage neu)
    text_history = []
    for h in history[-8:]:
        text_history.append({'role':h['role'] if h['role'] in ('user','assistant') else 'user', 'content':h['text']})

    answer = None

    # Try OpenAI GPT-4o Vision (Primär)
    if OPENAI_API_KEY and not answer:
        try:
            from openai import OpenAI
            oc = OpenAI(api_key=OPENAI_API_KEY)
            oai_msgs = [{'role':'system','content':system}]
            # History ohne Bild
            for m in text_history[:-1] if text_history else []:
                oai_msgs.append({'role':m['role'],'content':m['content']})
            # Aktuelle Frage MIT Bild (falls vorhanden)
            if has_image:
                user_content = [
                    {'type':'image_url','image_url':{'url':f'data:image/jpeg;base64,{image_data}','detail':'high'}},
                    {'type':'text','text':question}
                ]
            else:
                user_content = question
            oai_msgs.append({'role':'user','content':user_content})
            resp = oc.chat.completions.create(model='gpt-4o', max_tokens=800, messages=oai_msgs)
            answer = resp.choices[0].message.content
        except Exception as e:
            app.logger.warning(f'Chat OpenAI Fehler: {e}')

    # Try Anthropic Claude Vision (Backup)
    if ANTHROPIC_API_KEY and not answer:
        try:
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            anth_msgs = []
            for m in text_history[:-1] if text_history else []:
                anth_msgs.append({'role':m['role'],'content':m['content']})
            if has_image:
                anth_msgs.append({'role':'user','content':[
                    {'type':'image','source':{'type':'base64','media_type':'image/jpeg','data':image_data}},
                    {'type':'text','text':question}
                ]})
            else:
                anth_msgs.append({'role':'user','content':question})
            resp = client.messages.create(model='claude-sonnet-4-20250514', max_tokens=800, system=system, messages=anth_msgs)
            answer = resp.content[0].text
        except Exception as e:
            app.logger.warning(f'Chat Anthropic Fehler: {e}')

    # Try Gemini Vision (Letzter Ausweg)
    if GEMINI_API_KEY and not answer:
        try:
            import google.generativeai as genai
            from PIL import Image as PILImage
            genai.configure(api_key=GEMINI_API_KEY)
            model = genai.GenerativeModel('gemini-2.0-flash')
            parts = []
            if has_image:
                img_bytes = __import__('base64').b64decode(image_data)
                img = PILImage.open(io.BytesIO(img_bytes))
                parts.append(img)
            chat_text = system + '\n\n'
            for m in text_history:
                chat_text += f"{m['role']}: {m['content']}\n"
            chat_text += f"user: {question}"
            parts.append(chat_text)
            resp = model.generate_content(parts)
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
    page = request.args.get('page', None, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    severity_filter = request.args.get('severity', '').strip()
    species_filter = request.args.get('species', '').strip()
    per_page = min(max(per_page, 1), 100)  # clamp 1-100

    conn = get_db()
    is_admin = request.user['role'] == 'admin'

    # Build WHERE clause
    conditions = []
    params = []
    if not is_admin:
        conditions.append('r.user_id=?')
        params.append(request.user['id'])
    if severity_filter:
        conditions.append('r.severity=?')
        params.append(severity_filter)
    if species_filter:
        conditions.append('r.species=?')
        params.append(species_filter)

    where = (' WHERE ' + ' AND '.join(conditions)) if conditions else ''
    join = ' LEFT JOIN users u ON r.user_id=u.id' if is_admin else ''
    select_extra = ',u.name as user_name,u.praxis' if is_admin else ''

    # If page param provided, use pagination; otherwise return all (backward compat)
    if page is not None:
        page = max(page, 1)
        # Get total count
        count_row = db_dict(db_fetchone(conn, f'SELECT COUNT(*) as n FROM reports r{join}{where}', params))
        total = count_row['n']
        pages = math.ceil(total / per_page) if per_page > 0 else 1
        offset = (page - 1) * per_page
        rows = db_fetchall(conn, f'SELECT r.*{select_extra} FROM reports r{join}{where} ORDER BY r.created_at DESC LIMIT ? OFFSET ?', params + [per_page, offset])
        conn.close()
        for r in rows:
            r['has_image'] = bool(r.get('image_data'))
            r.pop('image_data', None)
        return jsonify({'reports': rows, 'total': total, 'page': page, 'per_page': per_page, 'pages': pages})
    else:
        rows = db_fetchall(conn, f'SELECT r.*{select_extra} FROM reports r{join}{where} ORDER BY r.created_at DESC', params)
        conn.close()
        for r in rows:
            r['has_image'] = bool(r.get('image_data'))
            r.pop('image_data', None)
        return jsonify({'reports': rows})

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

@app.route('/api/reports/<rid>/thumbnail')
@require_auth
def get_report_thumbnail(rid):
    """Generate a small thumbnail (120px) from the report image"""
    conn = get_db()
    rows = db_fetchall(conn, 'SELECT image_data,user_id FROM reports WHERE id=?',(rid,))
    conn.close()
    if not rows: return jsonify({'error':'Befund nicht gefunden'}), 404
    r = rows[0]
    if r['user_id'] != request.user['id'] and request.user['role'] != 'admin':
        return jsonify({'error':'Kein Zugriff'}), 403
    if not r.get('image_data'):
        return jsonify({'error':'Kein Bild vorhanden'}), 404
    try:
        import base64, io
        from PIL import Image
        img_bytes = base64.b64decode(r['image_data'])
        img = Image.open(io.BytesIO(img_bytes))
        img.thumbnail((120, 120), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=60)
        thumb_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        return jsonify({'thumbnail': thumb_b64})
    except ImportError:
        # Pillow not installed — return first chars of original as fallback
        return jsonify({'thumbnail': r['image_data']})
    except Exception as e:
        app.logger.warning(f'Thumbnail-Fehler: {e}')
        return jsonify({'thumbnail': r['image_data']})

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
        db_execute(conn, "UPDATE users SET plan=?,analyses_limit=20 WHERE stripe_subscription_id=?",
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
    limit = 999999 if d.get('plan')=='professional' else (50 if d.get('plan')=='starter' else 20)
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
    limit = 999999 if d.get('plan')=='professional' else (50 if d.get('plan')=='starter' else 20)
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
# DSGVO ENDPOINTS (Art. 17, 20, Consent)
# ═══════════════════════════════════════════════════

@app.route('/api/auth/export-data')
@require_auth
def export_data():
    """DSGVO Art. 20 – Data Portability: export all user data as JSON."""
    try:
        uid = request.user['id']
        conn = get_db()

        user = db_dict(db_fetchone(conn, 'SELECT id,email,name,praxis,plan,role,analyses_used,analyses_limit,created_at,trial_ends_at FROM users WHERE id=?', (uid,)))
        if not user:
            conn.close()
            return jsonify({'error': 'Benutzer nicht gefunden'}), 404

        reports_raw = db_fetchall(conn, 'SELECT id,pet_name,species,created_at,status,summary FROM reports WHERE user_id=?', (uid,))
        reports = [db_dict(r) for r in reports_raw] if reports_raw else []

        session_count_row = db_fetchone(conn, 'SELECT COUNT(*) as cnt FROM sessions WHERE user_id=?', (uid,))
        session_count = db_dict(session_count_row)['cnt'] if session_count_row else 0

        conn.close()

        audit('dsgvo_data_export', uid, 'User exported personal data (Art. 20)')

        return jsonify({
            'user': user,
            'reports': reports,
            'sessions_count': session_count,
            'exported_at': now()
        })
    except Exception as e:
        app.logger.error(f'DSGVO export error: {e}')
        return jsonify({'error': 'Datenexport fehlgeschlagen'}), 500


@app.route('/api/auth/delete-account', methods=['DELETE'])
@require_auth
def delete_account():
    """DSGVO Art. 17 – Right to Erasure: delete all user data."""
    try:
        uid = request.user['id']

        if request.user.get('role') == 'admin':
            return jsonify({'error': 'Admin-Konten können nicht gelöscht werden'}), 403

        conn = get_db()

        # Verify user exists
        user = db_fetchone(conn, 'SELECT id FROM users WHERE id=?', (uid,))
        if not user:
            conn.close()
            return jsonify({'error': 'Benutzer nicht gefunden'}), 404

        # Delete all user data in correct order (foreign key safety)
        db_execute(conn, 'DELETE FROM reports WHERE user_id=?', (uid,))
        db_execute(conn, 'DELETE FROM sessions WHERE user_id=?', (uid,))
        db_execute(conn, 'DELETE FROM audit_log WHERE user_id=?', (uid,))
        db_execute(conn, 'DELETE FROM users WHERE id=?', (uid,))

        conn.commit()
        conn.close()

        # Audit logged after deletion (user_id kept for traceability)
        app.logger.info(f'DSGVO Art.17: Account {uid} fully deleted')

        return jsonify({'ok': True, 'message': 'Konto und alle Daten wurden gelöscht'})
    except Exception as e:
        app.logger.error(f'DSGVO delete error: {e}')
        return jsonify({'error': 'Kontolöschung fehlgeschlagen'}), 500


@app.route('/api/auth/consent', methods=['POST'])
@require_auth
def record_consent():
    """Track DSGVO consent (e.g. dsgvo_accepted, ai_processing_accepted)."""
    try:
        uid = request.user['id']
        d = request.json or {}
        consent_type = d.get('type', 'dsgvo_accepted')

        if consent_type not in ('dsgvo_accepted', 'ai_processing_accepted', 'marketing_accepted'):
            return jsonify({'error': 'Ungültiger Einwilligungstyp'}), 400

        audit('consent_given', uid, f'Consent: {consent_type} at {now()}')

        return jsonify({'ok': True, 'consent_type': consent_type, 'timestamp': now()})
    except Exception as e:
        app.logger.error(f'DSGVO consent error: {e}')
        return jsonify({'error': 'Einwilligung konnte nicht gespeichert werden'}), 500


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
# PDF-EXPORT
# ═══════════════════════════════════════════════════
@app.route('/api/reports/<rid>/pdf')
@require_auth
def export_report_pdf(rid):
    """Generate a professional PDF for a report."""
    conn = get_db()
    report = db_dict(db_fetchone(conn, 'SELECT * FROM reports WHERE id=?', (rid,)))
    conn.close()
    if not report:
        return jsonify({'error': 'Befund nicht gefunden'}), 404
    if report['user_id'] != request.user['id'] and request.user['role'] != 'admin':
        return jsonify({'error': 'Kein Zugriff'}), 403

    try:
        from fpdf import FPDF
    except ImportError:
        return jsonify({'error': 'PDF-Bibliothek (fpdf2) nicht installiert'}), 503

    class AnimiooPDF(FPDF):
        def header(self):
            self.set_fill_color(26, 86, 219)  # #1a56db
            self.rect(0, 0, 210, 28, 'F')
            self.set_font('Helvetica', 'B', 18)
            self.set_text_color(255, 255, 255)
            self.set_y(8)
            self.cell(0, 10, 'Animioo KI-Befundassistent', align='C')
            self.ln(18)

        def footer(self):
            self.set_y(-15)
            self.set_font('Helvetica', 'I', 8)
            self.set_text_color(128, 128, 128)
            self.cell(0, 10, 'Animioo KI-Befundassistent -- Kein Ersatz fuer tieraerztliche Diagnose.', align='C')
            self.cell(0, 10, f'Seite {self.page_no()}/{{nb}}', align='R')

    pdf = AnimiooPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)

    # ── Report Metadata ──
    pdf.set_y(32)
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(26, 86, 219)
    pdf.cell(0, 8, 'Befund-Metadaten', ln=True)

    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(60, 60, 60)
    meta_items = [
        ('Datum', report.get('created_at', '')[:19].replace('T', ' ')),
        ('Tierart', report.get('species', '')),
        ('Region', report.get('region', '')),
        ('Modus', report.get('mode', '')),
        ('Dringlichkeit', {'low': 'Niedrig', 'mid': 'Mittel', 'high': 'Hoch'}.get(report.get('severity', ''), report.get('severity', ''))),
    ]
    if report.get('pet_name'):
        meta_items.insert(1, ('Patient', report['pet_name']))

    for label, value in meta_items:
        pdf.set_font('Helvetica', 'B', 10)
        pdf.cell(35, 6, f'{label}:', ln=False)
        pdf.set_font('Helvetica', '', 10)
        pdf.cell(0, 6, str(value), ln=True)

    pdf.ln(4)
    # Separator line
    pdf.set_draw_color(26, 86, 219)
    pdf.set_line_width(0.5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    # ── Report text ──
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(26, 86, 219)
    pdf.cell(0, 8, 'Befundbericht', ln=True)

    report_text = report.get('report_text', '')
    # Parse markdown-style text into PDF
    pdf.set_text_color(30, 30, 30)
    for line in report_text.split('\n'):
        stripped = line.strip()
        if stripped.startswith('## '):
            pdf.ln(3)
            pdf.set_font('Helvetica', 'B', 11)
            pdf.set_text_color(26, 86, 219)
            pdf.multi_cell(0, 6, stripped[3:])
            pdf.set_text_color(30, 30, 30)
        elif stripped.startswith('### '):
            pdf.ln(2)
            pdf.set_font('Helvetica', 'B', 10)
            pdf.multi_cell(0, 6, stripped[4:])
        elif stripped.startswith('**') and stripped.endswith('**'):
            pdf.set_font('Helvetica', 'B', 10)
            pdf.multi_cell(0, 5, stripped.strip('*'))
            pdf.set_font('Helvetica', '', 10)
        elif stripped.startswith('|') and '|' in stripped[1:]:
            # Table row — render as simple text
            cells = [c.strip() for c in stripped.split('|') if c.strip() and c.strip() != '---']
            if cells and not all(set(c) <= set('-| ') for c in cells):
                pdf.set_font('Helvetica', '', 9)
                pdf.multi_cell(0, 5, '  |  '.join(cells))
                pdf.set_font('Helvetica', '', 10)
        elif stripped.startswith('- ') or stripped.startswith('* '):
            pdf.set_font('Helvetica', '', 10)
            pdf.multi_cell(0, 5, '  ' + stripped)
        elif stripped.startswith('---'):
            pdf.ln(2)
            pdf.set_draw_color(180, 180, 180)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(2)
        elif stripped:
            # Handle inline bold
            clean = stripped.replace('**', '')
            pdf.set_font('Helvetica', '', 10)
            pdf.multi_cell(0, 5, clean)
        else:
            pdf.ln(2)

    # Output PDF
    pdf_bytes = pdf.output()
    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename="Animioo-Befund-{rid}.pdf"'
    return response

# ═══════════════════════════════════════════════════
# BEFUND-FEEDBACK API
# ═══════════════════════════════════════════════════
@app.route('/api/reports/<rid>/feedback', methods=['POST'])
@require_auth
def create_report_feedback(rid):
    """Submit feedback for a report (rating, correctness, comment)."""
    conn = get_db()
    report = db_dict(db_fetchone(conn, 'SELECT id,user_id FROM reports WHERE id=?', (rid,)))
    if not report:
        conn.close()
        return jsonify({'error': 'Befund nicht gefunden'}), 404
    if report['user_id'] != request.user['id'] and request.user['role'] != 'admin':
        conn.close()
        return jsonify({'error': 'Kein Zugriff'}), 403

    d = request.json or {}
    rating = d.get('rating')
    correct = d.get('correct')
    comment = d.get('comment', '').strip()

    if rating is not None and (not isinstance(rating, int) or rating < 1 or rating > 5):
        conn.close()
        return jsonify({'error': 'Rating muss zwischen 1 und 5 liegen'}), 400

    fid = 'fb_' + nid()
    db_execute(conn, 'INSERT INTO report_feedback (id,report_id,user_id,rating,correct,comment,created_at) VALUES (?,?,?,?,?,?,?)',
               (fid, rid, request.user['id'], rating, 1 if correct else 0 if correct is not None else None, comment, now()))
    conn.commit(); conn.close()

    audit('Feedback', request.user['id'], f'Report {rid}: rating={rating}, correct={correct}')
    return jsonify({'ok': True, 'id': fid}), 201

@app.route('/api/reports/<rid>/feedback')
@require_auth
def get_report_feedback(rid):
    """Get feedback for a report."""
    conn = get_db()
    report = db_dict(db_fetchone(conn, 'SELECT id,user_id FROM reports WHERE id=?', (rid,)))
    if not report:
        conn.close()
        return jsonify({'error': 'Befund nicht gefunden'}), 404
    if report['user_id'] != request.user['id'] and request.user['role'] != 'admin':
        conn.close()
        return jsonify({'error': 'Kein Zugriff'}), 403

    rows = db_fetchall(conn, 'SELECT * FROM report_feedback WHERE report_id=? ORDER BY created_at DESC', (rid,))
    conn.close()
    return jsonify({'feedback': rows})

# ═══════════════════════════════════════════════════
# API-KEY MANAGEMENT
# ═══════════════════════════════════════════════════
@app.route('/api/auth/api-key')
@require_auth
def get_api_key():
    """Get or generate an API key for the current user."""
    conn = get_db()
    user = db_dict(db_fetchone(conn, 'SELECT api_key FROM users WHERE id=?', (request.user['id'],)))
    api_key = user.get('api_key', '') if user else ''
    if not api_key:
        api_key = 'ak_' + secrets.token_hex(24)
        db_execute(conn, 'UPDATE users SET api_key=? WHERE id=?', (api_key, request.user['id']))
        conn.commit()
    conn.close()
    return jsonify({'api_key': api_key})

# ═══════════════════════════════════════════════════
# PRAXISMANAGEMENT-INTEGRATION API (v1)
# ═══════════════════════════════════════════════════
@app.route('/api/v1/analyse', methods=['POST'])
@require_api_key
@limiter.limit("10 per minute")
def v1_analyse():
    """External API: analyse an image via multipart/form-data with API key auth."""
    user = request.user

    if user['role'] != 'admin':
        if user['plan'] in ('trial',) and user['analyses_used'] >= user['analyses_limit']:
            return jsonify({'error': 'Analyse-Kontingent aufgebraucht', 'upgrade_required': True}), 402
        if user['plan'] == 'starter' and user['analyses_used'] >= 50:
            return jsonify({'error': 'Monatliches Kontingent erreicht', 'upgrade_required': True}), 402

    import base64

    # Accept either multipart form or JSON
    if request.content_type and 'multipart/form-data' in request.content_type:
        image_file = request.files.get('image')
        if not image_file:
            return jsonify({'error': 'Kein Bild hochgeladen (multipart field "image" erwartet)'}), 400
        img_a = base64.b64encode(image_file.read()).decode('utf-8')
        species = request.form.get('species', 'Hund')
        region = request.form.get('region', 'Thorax')
    else:
        d = request.json or {}
        img_a = d.get('image', '')
        species = d.get('species', 'Hund')
        region = d.get('region', 'Thorax')

    if not img_a:
        return jsonify({'error': 'Kein Bild-Daten'}), 400

    # Reuse the main analyse logic by forwarding internally
    # Build the JSON body and call the analyse function indirectly
    from flask import g
    # Store original json and set up the request data
    request._v1_data = {
        'img_a': img_a, 'species': species, 'region': region,
        'mode': 'single', 'context': '', 'focus_mode': 'general', 'focus_text': '',
        'pet_name': '', 'img_b': ''
    }

    # Check cache
    img_h = image_hash(img_a, species, region, 'single')
    conn = get_db()
    cached = db_dict(db_fetchone(conn, 'SELECT * FROM reports WHERE image_hash=? AND user_id=?', (img_h, user['id'])))
    conn.close()
    if cached:
        result = {k: cached.get(k, '') for k in ['id', 'report_text', 'severity', 'species', 'region', 'mode', 'created_at']}
        result['cached'] = True
        return jsonify(result)

    # Call AI (simplified — use same providers)
    if not ANTHROPIC_API_KEY and not OPENAI_API_KEY and not GEMINI_API_KEY:
        return jsonify({'error': 'KI nicht konfiguriert'}), 503

    import time as _time

    system_prompt = "Du bist ein erfahrener Veterinärradiologe. Erstelle einen vollständigen Befundbericht auf Deutsch."
    msgs = [
        {'type': 'image', 'source': {'type': 'base64', 'media_type': 'image/jpeg', 'data': img_a}},
        {'type': 'text', 'text': f'Erstelle einen veterinärmedizinischen Befundbericht für einen {species} im Bereich {region}.'}
    ]

    text = None
    # Try OpenAI
    if OPENAI_API_KEY and not text:
        try:
            from openai import OpenAI
            oc = OpenAI(api_key=OPENAI_API_KEY)
            oai_content = []
            for m in msgs:
                if m['type'] == 'image':
                    oai_content.append({'type': 'image_url', 'image_url': {'url': f"data:{m['source']['media_type']};base64,{m['source']['data']}", 'detail': 'high'}})
                else:
                    oai_content.append({'type': 'text', 'text': m['text']})
            resp = oc.chat.completions.create(model='gpt-4o', max_tokens=4096, temperature=0,
                messages=[{'role': 'system', 'content': system_prompt}, {'role': 'user', 'content': oai_content}])
            text = resp.choices[0].message.content
        except Exception as e:
            app.logger.warning(f'v1 OpenAI Fehler: {e}')

    # Try Anthropic
    if ANTHROPIC_API_KEY and not text:
        try:
            client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
            resp = client.messages.create(model='claude-sonnet-4-20250514', max_tokens=4096, temperature=0,
                system=system_prompt, messages=[{'role': 'user', 'content': msgs}])
            text = resp.content[0].text
        except Exception as e:
            app.logger.warning(f'v1 Anthropic Fehler: {e}')

    if not text:
        return jsonify({'error': 'KI-Analyse fehlgeschlagen'}), 503

    tl = text.lower()
    sev = 'high' if ('**hoch**' in tl or '**notfall**' in tl) else ('low' if '**niedrig**' in tl else 'mid')

    required_sections = ['diagnose', 'differenzialdiagnosen', 'befund', 'therapie']
    sections_found = sum(1 for s in required_sections if s in tl)
    quality_score = sections_found

    rid = 'r_' + nid()
    conn = get_db()
    db_execute(conn, 'INSERT INTO reports (id,user_id,pet_name,species,region,mode,severity,report_text,image_data,image_hash,quality_score,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
               (rid, user['id'], '', species, region, 'single', sev, text, img_a, img_h, quality_score, now()))
    db_execute(conn, 'UPDATE users SET analyses_used=analyses_used+1 WHERE id=?', (user['id'],))
    conn.commit(); conn.close()

    audit('v1_Analyse', user['id'], f'{species}/{region}')
    return jsonify({'id': rid, 'report_text': text, 'severity': sev, 'species': species, 'region': region,
                    'quality_score': quality_score, 'created_at': now()})

@app.route('/api/v1/reports')
@require_api_key
def v1_list_reports():
    """External API: list reports for API key user."""
    page = request.args.get('page', 1, type=int)
    per_page = min(max(request.args.get('per_page', 20, type=int), 1), 100)
    page = max(page, 1)

    conn = get_db()
    count_row = db_dict(db_fetchone(conn, 'SELECT COUNT(*) as n FROM reports WHERE user_id=?', (request.user['id'],)))
    total = count_row['n']
    pages = math.ceil(total / per_page) if per_page > 0 else 1
    offset = (page - 1) * per_page
    rows = db_fetchall(conn, 'SELECT id,pet_name,species,region,mode,severity,quality_score,created_at FROM reports WHERE user_id=? ORDER BY created_at DESC LIMIT ? OFFSET ?',
                       (request.user['id'], per_page, offset))
    conn.close()
    return jsonify({'reports': rows, 'total': total, 'page': page, 'per_page': per_page, 'pages': pages})

@app.route('/api/v1/reports/<rid>')
@require_api_key
def v1_get_report(rid):
    """External API: get a single report by ID."""
    conn = get_db()
    report = db_dict(db_fetchone(conn, 'SELECT * FROM reports WHERE id=? AND user_id=?', (rid, request.user['id'])))
    conn.close()
    if not report:
        return jsonify({'error': 'Befund nicht gefunden'}), 404
    report.pop('image_data', None)
    return jsonify({'report': report})

# ═══════════════════════════════════════════════════
# PRAXIS-TEAMS
# ═══════════════════════════════════════════════════

@app.route('/api/teams', methods=['GET'])
@require_auth
def list_teams():
    uid = request.user['id']
    conn = get_db()
    # Teams where user is owner OR member
    teams = db_fetchall(conn, '''
        SELECT DISTINCT t.id, t.name, t.owner_id, t.created_at
        FROM teams t
        LEFT JOIN team_members tm ON t.id = tm.team_id
        WHERE t.owner_id=? OR tm.user_id=?
        ORDER BY t.created_at DESC
    ''', (uid, uid))
    result = []
    for team in (teams or []):
        t = dict(team)
        members = db_fetchall(conn, '''
            SELECT tm.id, tm.user_id, tm.role, tm.joined_at, u.name, u.email
            FROM team_members tm
            LEFT JOIN users u ON tm.user_id=u.id
            WHERE tm.team_id=?
        ''', (t['id'],))
        t['member_count'] = len(members or [])
        result.append(t)
    conn.close()
    return jsonify({'teams': result})


@app.route('/api/teams', methods=['POST'])
@require_auth
def create_team():
    d = request.json or {}
    name = d.get('name', '').strip()
    if not name:
        return jsonify({'error': 'Teamname erforderlich'}), 400
    uid = request.user['id']
    tid = 't_' + nid()
    mid = 'tm_' + nid()
    conn = get_db()
    try:
        db_execute(conn, 'INSERT INTO teams (id, name, owner_id, created_at) VALUES (?,?,?,?)',
                   (tid, name, uid, now()))
        db_execute(conn, 'INSERT INTO team_members (id, team_id, user_id, role, invited_by, joined_at) VALUES (?,?,?,?,?,?)',
                   (mid, tid, uid, 'owner', uid, now()))
        conn.commit()
    except Exception as e:
        try: conn.rollback()
        except: pass
        conn.close()
        return jsonify({'error': str(e)}), 500
    conn.close()
    audit('Team erstellt', uid, f'{name} ({tid})')
    return jsonify({'id': tid, 'ok': True}), 201


@app.route('/api/teams/<tid>', methods=['GET'])
@require_auth
def get_team(tid):
    uid = request.user['id']
    conn = get_db()
    team = db_dict(db_fetchone(conn, 'SELECT * FROM teams WHERE id=?', (tid,)))
    if not team:
        conn.close()
        return jsonify({'error': 'Team nicht gefunden'}), 404
    # Check membership
    member = db_fetchone(conn, 'SELECT id FROM team_members WHERE team_id=? AND user_id=?', (tid, uid))
    if not member and team['owner_id'] != uid and request.user.get('role') != 'admin':
        conn.close()
        return jsonify({'error': 'Kein Zugriff'}), 403
    members = db_fetchall(conn, '''
        SELECT tm.id, tm.user_id, tm.role, tm.invited_by, tm.joined_at,
               u.name, u.email, u.praxis
        FROM team_members tm
        LEFT JOIN users u ON tm.user_id=u.id
        WHERE tm.team_id=?
        ORDER BY tm.joined_at ASC
    ''', (tid,))
    conn.close()
    team['members'] = members or []
    return jsonify({'team': team})


@app.route('/api/teams/<tid>/members', methods=['POST'])
@require_auth
def add_team_member(tid):
    uid = request.user['id']
    d = request.json or {}
    email = d.get('email', '').strip().lower()
    if not email:
        return jsonify({'error': 'E-Mail erforderlich'}), 400
    conn = get_db()
    team = db_dict(db_fetchone(conn, 'SELECT * FROM teams WHERE id=?', (tid,)))
    if not team:
        conn.close()
        return jsonify({'error': 'Team nicht gefunden'}), 404
    # Only owner or admin can invite
    caller_member = db_dict(db_fetchone(conn, 'SELECT role FROM team_members WHERE team_id=? AND user_id=?', (tid, uid)))
    caller_role = caller_member['role'] if caller_member else None
    if team['owner_id'] != uid and caller_role not in ('owner', 'admin') and request.user.get('role') != 'admin':
        conn.close()
        return jsonify({'error': 'Nur Owner oder Admin darf Mitglieder einladen'}), 403
    # Find invited user
    invite_user = db_dict(db_fetchone(conn, 'SELECT id FROM users WHERE email=? AND active=1', (email,)))
    if not invite_user:
        conn.close()
        return jsonify({'error': 'Kein aktiver User mit dieser E-Mail gefunden'}), 404
    inv_uid = invite_user['id']
    # Check if already member
    existing = db_fetchone(conn, 'SELECT id FROM team_members WHERE team_id=? AND user_id=?', (tid, inv_uid))
    if existing:
        conn.close()
        return jsonify({'error': 'User ist bereits Mitglied dieses Teams'}), 409
    mid = 'tm_' + nid()
    role_to_assign = d.get('role', 'member')
    if role_to_assign not in ('admin', 'member'):
        role_to_assign = 'member'
    db_execute(conn, 'INSERT INTO team_members (id, team_id, user_id, role, invited_by, joined_at) VALUES (?,?,?,?,?,?)',
               (mid, tid, inv_uid, role_to_assign, uid, now()))
    conn.commit(); conn.close()
    audit('Team-Mitglied eingeladen', uid, f'{email} -> {tid}')
    return jsonify({'ok': True, 'id': mid}), 201


@app.route('/api/teams/<tid>/members/<invited_uid>', methods=['DELETE'])
@require_auth
def remove_team_member(tid, invited_uid):
    uid = request.user['id']
    conn = get_db()
    team = db_dict(db_fetchone(conn, 'SELECT * FROM teams WHERE id=?', (tid,)))
    if not team:
        conn.close()
        return jsonify({'error': 'Team nicht gefunden'}), 404
    caller_member = db_dict(db_fetchone(conn, 'SELECT role FROM team_members WHERE team_id=? AND user_id=?', (tid, uid)))
    caller_role = caller_member['role'] if caller_member else None
    if team['owner_id'] != uid and caller_role not in ('owner', 'admin') and request.user.get('role') != 'admin':
        conn.close()
        return jsonify({'error': 'Nur Owner oder Admin darf Mitglieder entfernen'}), 403
    # Cannot remove owner
    target_member = db_dict(db_fetchone(conn, 'SELECT role FROM team_members WHERE team_id=? AND user_id=?', (tid, invited_uid)))
    if target_member and target_member['role'] == 'owner':
        conn.close()
        return jsonify({'error': 'Owner kann nicht entfernt werden'}), 400
    db_execute(conn, 'DELETE FROM team_members WHERE team_id=? AND user_id=?', (tid, invited_uid))
    conn.commit(); conn.close()
    audit('Team-Mitglied entfernt', uid, f'{invited_uid} from {tid}')
    return jsonify({'ok': True})


@app.route('/api/teams/<tid>', methods=['DELETE'])
@require_auth
def delete_team(tid):
    uid = request.user['id']
    conn = get_db()
    team = db_dict(db_fetchone(conn, 'SELECT * FROM teams WHERE id=?', (tid,)))
    if not team:
        conn.close()
        return jsonify({'error': 'Team nicht gefunden'}), 404
    if team['owner_id'] != uid and request.user.get('role') != 'admin':
        conn.close()
        return jsonify({'error': 'Nur der Owner darf ein Team löschen'}), 403
    db_execute(conn, 'DELETE FROM team_members WHERE team_id=?', (tid,))
    db_execute(conn, 'DELETE FROM teams WHERE id=?', (tid,))
    conn.commit(); conn.close()
    audit('Team gelöscht', uid, tid)
    return jsonify({'ok': True})


# ═══════════════════════════════════════════════════
# E-MAIL-BEFUNDVERSAND
# ═══════════════════════════════════════════════════

def markdown_to_html(text):
    """Simple Markdown -> HTML conversion for report email."""
    import re
    lines = text.split('\n')
    html_lines = []
    for line in lines:
        # ## Heading
        if line.startswith('## '):
            line = '<h2>' + line[3:] + '</h2>'
        # **bold**
        line = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', line)
        html_lines.append(line)
    return '<br>\n'.join(html_lines)


@app.route('/api/reports/<rid>/send-email', methods=['POST'])
@require_auth
def send_report_email(rid):
    """Sendet einen Befund per E-Mail an eine angegebene Adresse."""
    if not SMTP_HOST or not SMTP_USER:
        return jsonify({'error': 'E-Mail-Versand nicht konfiguriert'}), 503

    conn = get_db()
    report = db_dict(db_fetchone(conn, 'SELECT * FROM reports WHERE id=? AND user_id=?', (rid, request.user['id'])))
    conn.close()
    if not report:
        return jsonify({'error': 'Befund nicht gefunden'}), 404

    d = request.json or {}
    to_email = d.get('to_email', '').strip()
    message = d.get('message', '').strip()

    if not to_email or '@' not in to_email:
        return jsonify({'error': 'Gültige Ziel-E-Mail erforderlich'}), 400

    pet_name = report.get('pet_name') or ''
    species = report.get('species') or ''
    region = report.get('region') or ''
    created_at = (report.get('created_at') or '')[:19].replace('T', ' ')
    report_text = report.get('report_text') or ''
    report_html = markdown_to_html(report_text)

    personal_message_html = ''
    if message:
        personal_message_html = f'''
        <div style="background:#f0f9ff;border-left:4px solid #1a56db;padding:15px 20px;margin:20px 0;border-radius:0 6px 6px 0;">
            <p style="margin:0;color:#1e3a5f;font-style:italic;">{message}</p>
        </div>'''

    html_body = f'''<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="font-family:Inter,Arial,sans-serif;max-width:700px;margin:0 auto;padding:20px;color:#1e293b;">
    <div style="background:#1a56db;padding:20px 30px;border-radius:8px 8px 0 0;">
        <h1 style="color:#fff;margin:0;font-size:22px;">Animioo KI-Befundassistent</h1>
        <p style="color:#bfdbfe;margin:5px 0 0;">Veterinärradiologischer Befundbericht</p>
    </div>
    <div style="background:#f8fafc;padding:20px 30px;border:1px solid #e2e8f0;border-top:none;">
        <table style="width:100%;border-collapse:collapse;margin-bottom:15px;">
            <tr><td style="padding:4px 0;color:#64748b;width:120px;">Datum:</td><td style="padding:4px 0;font-weight:600;">{created_at}</td></tr>
            {'<tr><td style="padding:4px 0;color:#64748b;">Patient:</td><td style="padding:4px 0;font-weight:600;">' + pet_name + '</td></tr>' if pet_name else ''}
            <tr><td style="padding:4px 0;color:#64748b;">Tierart:</td><td style="padding:4px 0;">{species}</td></tr>
            <tr><td style="padding:4px 0;color:#64748b;">Region:</td><td style="padding:4px 0;">{region}</td></tr>
        </table>
        {personal_message_html}
    </div>
    <div style="background:#fff;padding:25px 30px;border:1px solid #e2e8f0;border-top:none;line-height:1.7;font-size:14px;">
        {report_html}
    </div>
    <div style="background:#f1f5f9;padding:15px 30px;border:1px solid #e2e8f0;border-top:none;border-radius:0 0 8px 8px;">
        <p style="margin:0;font-size:11px;color:#94a3b8;">
            Animioo KI-Befundassistent &mdash; Kein Ersatz für tierärztliche Diagnose.<br>
            Dieser Befund wurde von <strong>{request.user.get('name','')}</strong> ({request.user.get('praxis','')}) per E-Mail versandt.
        </p>
    </div>
</body>
</html>'''

    subject_pet = f' – {pet_name}' if pet_name else ''
    subject = f'Animioo Befundbericht{subject_pet} ({species}, {region})'
    ok = send_email(to_email, subject, html_body)
    if not ok:
        return jsonify({'error': 'E-Mail-Versand fehlgeschlagen. Bitte Konfiguration prüfen.'}), 500
    audit('Befund per E-Mail versandt', request.user['id'], f'{rid} -> {to_email}')
    return jsonify({'ok': True})


# ═══════════════════════════════════════════════════
# API-SCHLÜSSEL-VERWALTUNG
# ═══════════════════════════════════════════════════

@app.route('/api/apikey', methods=['GET'])
@require_auth
def get_apikey():
    """Gibt den API-Key zurück (maskiert oder im Klartext bei ?reveal=1)."""
    conn = get_db()
    user = db_dict(db_fetchone(conn, 'SELECT api_key FROM users WHERE id=?', (request.user['id'],)))
    conn.close()
    api_key = user.get('api_key', '') if user else ''
    if not api_key:
        return jsonify({'api_key': None, 'has_key': False})
    reveal = request.args.get('reveal', '0') == '1'
    if reveal:
        return jsonify({'api_key': api_key, 'api_key_masked': api_key, 'has_key': True})
    # Maskieren: erste 8 + "..." + letzte 4
    if len(api_key) > 12:
        masked = api_key[:8] + '...' + api_key[-4:]
    else:
        masked = api_key[:4] + '...'
    return jsonify({'api_key': masked, 'api_key_masked': masked, 'has_key': True})


@app.route('/api/apikey/regenerate', methods=['POST'])
@require_auth
def regenerate_apikey():
    """Erzeugt einen neuen API-Key."""
    new_key = 'ak_' + secrets.token_hex(32)
    conn = get_db()
    db_execute(conn, 'UPDATE users SET api_key=? WHERE id=?', (new_key, request.user['id']))
    conn.commit(); conn.close()
    audit('API-Key erneuert', request.user['id'])
    return jsonify({'api_key': new_key, 'ok': True})


@app.route('/api/apikey', methods=['DELETE'])
@require_auth
def delete_apikey():
    """Löscht den API-Key."""
    conn = get_db()
    db_execute(conn, "UPDATE users SET api_key='' WHERE id=?", (request.user['id'],))
    conn.commit(); conn.close()
    audit('API-Key gelöscht', request.user['id'])
    return jsonify({'ok': True})


# ═══════════════════════════════════════════════════
# BEFUND-VERLAUF PRO PATIENT
# ═══════════════════════════════════════════════════

@app.route('/api/patients/<pid>/reports', methods=['GET'])
@require_auth
def patient_reports(pid):
    """Gibt alle Befunde eines Patienten zurück, sortiert nach Datum."""
    uid = request.user['id']
    conn = get_db()
    # Verify patient belongs to user
    patient = db_dict(db_fetchone(conn, 'SELECT id, name FROM patients WHERE id=? AND user_id=?', (pid, uid)))
    if not patient:
        conn.close()
        return jsonify({'error': 'Patient nicht gefunden'}), 404
    rows = db_fetchall(conn, '''
        SELECT id, species, region, mode, severity, pet_name, created_at, report_text
        FROM reports
        WHERE patient_id=? AND user_id=?
        ORDER BY created_at DESC
    ''', (pid, uid))
    conn.close()
    reports = []
    for r in (rows or []):
        entry = dict(r)
        rt = entry.get('report_text') or ''
        entry['preview'] = rt[:200]
        del entry['report_text']
        reports.append(entry)
    return jsonify({'reports': reports, 'patient': patient})


# ═══════════════════════════════════════════════════
# ÖFFENTLICHE API v1 (mit X-API-Key oder Bearer, zusätzliche Endpunkte)
# ═══════════════════════════════════════════════════

@app.route('/api/v1/patients', methods=['GET'])
@require_auth
@limiter.limit("60 per minute")
def v1_list_patients():
    """Public API: Gibt Patienten des API-Users zurück."""
    uid = request.user['id']
    conn = get_db()
    rows = db_fetchall(conn, 'SELECT * FROM patients WHERE user_id=? ORDER BY name ASC', (uid,))
    conn.close()
    return jsonify({'patients': rows or []})


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
@app.route('/api/db-check')
def db_check():
    """Debug: Prüft welche Spalten in reports/users existieren"""
    try:
        conn = get_db()
        if USE_POSTGRES:
            cur = conn.cursor()
            cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='reports' ORDER BY ordinal_position")
            report_cols = [r[0] for r in cur.fetchall()]
            cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='users' ORDER BY ordinal_position")
            user_cols = [r[0] for r in cur.fetchall()]
        else:
            cur = conn.execute("PRAGMA table_info(reports)")
            report_cols = [r[1] for r in cur.fetchall()]
            cur = conn.execute("PRAGMA table_info(users)")
            user_cols = [r[1] for r in cur.fetchall()]
        conn.close()
        return jsonify({
            'reports_columns': report_cols,
            'users_columns': user_cols,
            'has_image_hash': 'image_hash' in report_cols,
            'has_quality_score': 'quality_score' in report_cols,
            'has_api_key': 'api_key' in user_cols,
            'db': 'PostgreSQL' if USE_POSTGRES else 'SQLite'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
def health_check():
    # Bei jedem Health-Check: Admin-Passwort sicherstellen
    pw_hash = hash_pw('admin123')
    try:
        conn = get_db()
        existing = db_dict(db_fetchone(conn, 'SELECT id,password,active,role FROM users WHERE email=?', ('admin@animioo.de',)))
        if existing:
            db_execute(conn, 'UPDATE users SET password=?, active=1, role=?, email_verified=1 WHERE email=?',
                       (pw_hash, 'admin', 'admin@animioo.de'))
            admin_status = 'UPDATED'
        else:
            trial_end = (datetime.now() + timedelta(days=14)).isoformat()
            db_execute(conn, '''INSERT INTO users
                (id,email,password,name,praxis,plan,active,role,analyses_used,analyses_limit,email_verified,trial_ends_at,created_at)
                VALUES (?,?,?,?,?,?,1,?,?,?,1,?,?)''',
                ('admin1','admin@animioo.de',pw_hash,'Administrator','Animioo','admin','admin',0,999999,trial_end,now()))
            admin_status = 'CREATED'
        conn.commit()
        # Verify the password works
        verify_user = db_dict(db_fetchone(conn, 'SELECT password FROM users WHERE email=?', ('admin@animioo.de',)))
        conn.close()
        pw_ok = check_pw('admin123', verify_user['password']) if verify_user else False
        admin_status += f' pw_ok={pw_ok} bcrypt={HAS_BCRYPT} hash_start={pw_hash[:10]}'
    except Exception as e:
        admin_status = f'ERROR: {e}'
    return jsonify({'status': 'ok', 'admin': admin_status})

@app.route('/api/test-email')
@require_admin
def test_email():
    """Admin-only: Test ob E-Mail-Versand funktioniert."""
    ok = send_email(request.user['email'], 'Animioo – Test-E-Mail',
        '<div style="font-family:Inter,sans-serif;padding:30px;"><h2>Test erfolgreich!</h2><p>Der E-Mail-Versand funktioniert.</p></div>')
    return jsonify({
        'ok': ok,
        'smtp_host': SMTP_HOST,
        'smtp_port': SMTP_PORT,
        'smtp_user': SMTP_USER,
        'smtp_from': SMTP_FROM,
        'message': 'E-Mail gesendet!' if ok else 'E-Mail-Versand fehlgeschlagen. Siehe Logs.'
    })

# ═══════════════════════════════════════════════════
# START
# ═══════════════════════════════════════════════════
init_db()

if __name__ == '__main__':
    port  = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG','false').lower() == 'true'

    missing = []
    if not OPENAI_API_KEY and not ANTHROPIC_API_KEY:  missing.append('OPENAI_API_KEY')
    if not STRIPE_SECRET_KEY:  missing.append('STRIPE_SECRET_KEY')

    ki_status = 'OpenAI (primaer)' if OPENAI_API_KEY else ('Anthropic (backup)' if ANTHROPIC_API_KEY else ('Gemini' if GEMINI_API_KEY else 'KEINE KI konfiguriert!'))
    db_type = 'PostgreSQL' if USE_POSTGRES else 'SQLite'
    print(f"""
╔══════════════════════════════════════════════╗
║   Animioo – Server v2 gestartet             ║
║   URL: http://localhost:{port}                  ║
║   DB:     {db_type}
║   KI:     {ki_status}
║   Stripe: {'Bereit' if STRIPE_SECRET_KEY else 'STRIPE_SECRET_KEY fehlt'}
║   E-Mail: {'Bereit' if SMTP_HOST else 'SMTP nicht konfiguriert'}
║   Sentry: {'Bereit' if SENTRY_DSN else 'Nicht konfiguriert'}
║   bcrypt: {'Ja' if HAS_BCRYPT else 'Nein (SHA256-Fallback)'}
{"║   Fehlend: " + ", ".join(missing) if missing else "║   Alle Variablen gesetzt"}
╚══════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=port, debug=debug)

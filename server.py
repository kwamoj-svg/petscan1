"""
Petscan – KI-Radiologie SaaS Backend
=====================================
Startet mit: python server.py
Deployment:  Railway, Render, Heroku (kostenlos)
"""

from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
import anthropic
import sqlite3
import hashlib
import secrets
import os
import json
import base64
from datetime import datetime, timedelta
from functools import wraps

# ── SETUP ────────────────────────────────────────────────
app = Flask(__name__, static_folder='static', static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app, supports_credentials=True)

ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
DB_PATH = os.environ.get('DB_PATH', 'petscan.db')

# ── DATENBANK ────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id          TEXT PRIMARY KEY,
            email       TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            name        TEXT,
            praxis      TEXT,
            plan        TEXT DEFAULT "Starter",
            active      INTEGER DEFAULT 1,
            role        TEXT DEFAULT "customer",
            analyses    INTEGER DEFAULT 0,
            created_at  TEXT,
            last_login  TEXT
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token       TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL,
            expires_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS reports (
            id          TEXT PRIMARY KEY,
            user_id     TEXT NOT NULL,
            species     TEXT,
            region      TEXT,
            mode        TEXT,
            severity    TEXT,
            report_text TEXT,
            img_a       TEXT,
            img_b       TEXT,
            created_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS leads (
            id          TEXT PRIMARY KEY,
            name        TEXT,
            contact     TEXT,
            email       TEXT,
            phone       TEXT,
            message     TEXT,
            status      TEXT DEFAULT "new",
            source      TEXT,
            created_at  TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            action      TEXT,
            user_id     TEXT,
            detail      TEXT,
            created_at  TEXT
        );
    ''')

    # Demo-Accounts anlegen falls noch nicht vorhanden
    def hash_pw(pw):
        return hashlib.sha256(pw.encode()).hexdigest()

    seed_users = [
        ('u1', 'dr.mueller@tierklinik.de', hash_pw('demo123'), 'Dr. Anna Müller',
         'Tierklinik München-Mitte', 'Professional', 1, 'customer'),
        ('u2', 'info@kleintierpraxis.de', hash_pw('demo123'), 'Dr. Stefan Schmidt',
         'Kleintierpraxis Schmidt', 'Starter', 1, 'customer'),
        ('admin1', 'admin@petscan.de', hash_pw('admin123'), 'Administrator',
         'Petscan GmbH', 'Admin', 1, 'admin'),
    ]
    for uid, email, pw, name, praxis, plan, active, role in seed_users:
        try:
            conn.execute(
                'INSERT INTO users (id,email,password,name,praxis,plan,active,role,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
                (uid, email, pw, name, praxis, plan, active, role, datetime.now().isoformat())
            )
        except sqlite3.IntegrityError:
            pass

    conn.commit()
    conn.close()

# ── HELPER ───────────────────────────────────────────────
def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def new_id():
    return secrets.token_hex(8)

def now():
    return datetime.now().isoformat()

def audit(action, user_id, detail=''):
    conn = get_db()
    conn.execute(
        'INSERT INTO audit_log (action, user_id, detail, created_at) VALUES (?,?,?,?)',
        (action, user_id, detail, now())
    )
    conn.commit()
    conn.close()

# ── AUTH MIDDLEWARE ───────────────────────────────────────
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token:
            return jsonify({'error': 'Nicht authentifiziert'}), 401
        conn = get_db()
        sess = conn.execute(
            'SELECT * FROM sessions WHERE token=? AND expires_at>?',
            (token, now())
        ).fetchone()
        if not sess:
            conn.close()
            return jsonify({'error': 'Sitzung abgelaufen'}), 401
        user = conn.execute('SELECT * FROM users WHERE id=?', (sess['user_id'],)).fetchone()
        conn.close()
        if not user or not user['active']:
            return jsonify({'error': 'Kein Zugang'}), 403
        request.user = dict(user)
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.user.get('role') != 'admin':
            return jsonify({'error': 'Kein Admin-Zugang'}), 403
        return f(*args, **kwargs)
    return require_auth(decorated)

# ══════════════════════════════════════════════════════════
# ROUTES – STATIC FILES
# ══════════════════════════════════════════════════════════

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/app')
@app.route('/plattform')
def platform():
    return send_from_directory('static', 'app.html')

@app.route('/admin')
def admin_panel():
    return send_from_directory('static', 'admin.html')

# ══════════════════════════════════════════════════════════
# API – AUTHENTIFIZIERUNG
# ══════════════════════════════════════════════════════════

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'E-Mail und Passwort erforderlich'}), 400

    conn = get_db()
    user = conn.execute(
        'SELECT * FROM users WHERE email=? AND password=?',
        (email, hash_pw(password))
    ).fetchone()

    if not user:
        conn.close()
        return jsonify({'error': 'Falsche E-Mail oder Passwort'}), 401

    if not user['active']:
        conn.close()
        return jsonify({'error': 'Account deaktiviert. Bitte kontaktieren Sie den Support.'}), 403

    # Session erstellen (7 Tage gültig)
    token = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(days=7)).isoformat()
    conn.execute(
        'INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)',
        (token, user['id'], expires)
    )
    conn.execute(
        'UPDATE users SET last_login=? WHERE id=?',
        (now(), user['id'])
    )
    conn.commit()
    conn.close()

    audit('Login', user['id'], email)

    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'email': user['email'],
            'name': user['name'],
            'praxis': user['praxis'],
            'plan': user['plan'],
            'role': user['role'],
        }
    })

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    name = data.get('name', '').strip()
    praxis = data.get('praxis', '').strip()

    if not email or not password:
        return jsonify({'error': 'E-Mail und Passwort erforderlich'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Passwort mindestens 6 Zeichen'}), 400

    conn = get_db()
    existing = conn.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()
    if existing:
        conn.close()
        return jsonify({'error': 'E-Mail bereits registriert'}), 409

    uid = 'u_' + new_id()
    conn.execute(
        'INSERT INTO users (id,email,password,name,praxis,plan,active,role,analyses,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
        (uid, email, hash_pw(password), name or email.split('@')[0], praxis or 'Meine Praxis',
         'Starter', 1, 'customer', 0, now())
    )

    token = secrets.token_hex(32)
    expires = (datetime.now() + timedelta(days=7)).isoformat()
    conn.execute('INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)', (token, uid, expires))
    conn.commit()
    conn.close()

    audit('Registrierung', uid, email)

    return jsonify({
        'token': token,
        'user': {'id': uid, 'email': email, 'name': name or email, 'plan': 'Starter', 'role': 'customer'}
    }), 201

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    conn = get_db()
    conn.execute('DELETE FROM sessions WHERE token=?', (token,))
    conn.commit()
    conn.close()
    audit('Logout', request.user['id'])
    return jsonify({'ok': True})

@app.route('/api/auth/me', methods=['GET'])
@require_auth
def me():
    return jsonify({'user': request.user})

# ══════════════════════════════════════════════════════════
# API – KI-ANALYSE (Kernfunktion)
# ══════════════════════════════════════════════════════════

@app.route('/api/analyse', methods=['POST'])
@require_auth
def analyse():
    if not ANTHROPIC_API_KEY:
        return jsonify({'error': 'API-Key nicht konfiguriert. Bitte ANTHROPIC_API_KEY setzen.'}), 500

    data = request.json or {}
    species  = data.get('species', 'Hund')
    region   = data.get('region', 'Thorax')
    mode     = data.get('mode', 'single')
    context  = data.get('context', '')
    img_a    = data.get('img_a', '')  # base64
    img_b    = data.get('img_b', '')  # base64 (optional)

    if not img_a:
        return jsonify({'error': 'Kein Bild übertragen'}), 400

    # Analyse-Prompt je nach Modus
    mode_prompts = {
        'single':  f'Erstelle einen vollständigen veterinärradiologischen Befundbericht für einen {species} im Bereich {region}.',
        'compare': f'Vergleiche Aufnahme A (früher) mit Aufnahme B (aktuell) eines {species} im Bereich {region} und beschreibe Veränderungen.',
        'diff':    f'Identifiziere alle relevanten Unterschiede zwischen Aufnahme A und B beim {species}, Region {region}.',
        'second':  f'Erstelle eine fundierte Zweitmeinung zu den Aufnahmen eines {species} im Bereich {region}.',
    }

    system_prompt = """Du bist ein erfahrener Veterinärradiologe (ECVDI-Diplomate) mit 20 Jahren Erfahrung.
Erstelle professionelle, strukturierte Befundberichte auf Deutsch.

Struktur (Markdown):
## Technische Beurteilung der Aufnahme
## Radiologischer Befund
### [Bereich 1]
### [Bereich 2]
## Interpretation
## Differenzialdiagnosen
| Diagnose | Wahrscheinlichkeit | Begründung |
|---|---|---|
## Therapieempfehlungen
## Dringlichkeit
**NIEDRIG / MITTEL / HOCH** — kurze Begründung

Wichtig: Schreibe präzise, klinisch korrekt und evidenzbasiert nach WSAVA/BSAVA-Leitlinien."""

    # Nachrichten für die API aufbauen
    content = []
    content.append({
        'type': 'image',
        'source': {'type': 'base64', 'media_type': 'image/jpeg', 'data': img_a}
    })
    content.append({'type': 'text', 'text': 'Aufnahme A:'})

    if img_b and mode != 'single':
        content.append({
            'type': 'image',
            'source': {'type': 'base64', 'media_type': 'image/jpeg', 'data': img_b}
        })
        content.append({'type': 'text', 'text': 'Aufnahme B:'})

    prompt = mode_prompts.get(mode, mode_prompts['single'])
    if context:
        prompt += f'\n\nKlinischer Kontext vom behandelnden Tierarzt: {context}'
    content.append({'type': 'text', 'text': prompt})

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        response = client.messages.create(
            model='claude-sonnet-4-20250514',
            max_tokens=2200,
            system=system_prompt,
            messages=[{'role': 'user', 'content': content}]
        )
        report_text = response.content[0].text

        # Dringlichkeit erkennen
        text_lower = report_text.lower()
        if 'hoch' in text_lower and 'sofort' in text_lower:
            severity = 'high'
        elif 'niedrig' in text_lower:
            severity = 'low'
        else:
            severity = 'mid'

        # Befund speichern
        report_id = 'r_' + new_id()
        conn = get_db()
        conn.execute(
            'INSERT INTO reports (id,user_id,species,region,mode,severity,report_text,img_a,img_b,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
            (report_id, request.user['id'], species, region, mode, severity,
             report_text, img_a[:100]+'...', img_b[:100]+'...' if img_b else '',
             now())
        )
        conn.execute('UPDATE users SET analyses=analyses+1 WHERE id=?', (request.user['id'],))
        conn.commit()
        conn.close()

        audit('Analyse erstellt', request.user['id'], f'{species}/{region}')

        return jsonify({
            'id': report_id,
            'report_text': report_text,
            'severity': severity,
            'species': species,
            'region': region,
            'mode': mode,
            'created_at': now(),
        })

    except anthropic.APIError as e:
        return jsonify({'error': f'Anthropic API Fehler: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'Serverfehler: {str(e)}'}), 500

# ══════════════════════════════════════════════════════════
# API – BEFUNDE
# ══════════════════════════════════════════════════════════

@app.route('/api/reports', methods=['GET'])
@require_auth
def get_reports():
    conn = get_db()
    if request.user['role'] == 'admin':
        rows = conn.execute(
            'SELECT r.*, u.name as user_name FROM reports r LEFT JOIN users u ON r.user_id=u.id ORDER BY r.created_at DESC'
        ).fetchall()
    else:
        rows = conn.execute(
            'SELECT * FROM reports WHERE user_id=? ORDER BY created_at DESC',
            (request.user['id'],)
        ).fetchall()
    conn.close()
    return jsonify({'reports': [dict(r) for r in rows]})

@app.route('/api/reports/<report_id>', methods=['DELETE'])
@require_auth
def delete_report(report_id):
    conn = get_db()
    if request.user['role'] == 'admin':
        conn.execute('DELETE FROM reports WHERE id=?', (report_id,))
    else:
        conn.execute('DELETE FROM reports WHERE id=? AND user_id=?', (report_id, request.user['id']))
    conn.commit()
    conn.close()
    audit('Befund gelöscht', request.user['id'], report_id)
    return jsonify({'ok': True})

# ══════════════════════════════════════════════════════════
# API – ADMIN: KUNDEN
# ══════════════════════════════════════════════════════════

@app.route('/api/admin/customers', methods=['GET'])
@require_admin
def admin_customers():
    conn = get_db()
    rows = conn.execute(
        "SELECT id,email,name,praxis,plan,active,analyses,created_at,last_login FROM users WHERE role!='admin' ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return jsonify({'customers': [dict(r) for r in rows]})

@app.route('/api/admin/customers/<uid>', methods=['PUT'])
@require_admin
def admin_update_customer(uid):
    data = request.json or {}
    conn = get_db()
    conn.execute(
        'UPDATE users SET name=?, praxis=?, plan=?, active=? WHERE id=?',
        (data.get('name'), data.get('praxis'), data.get('plan'), int(data.get('active', 1)), uid)
    )
    conn.commit()
    conn.close()
    audit('Kunde bearbeitet', request.user['id'], uid)
    return jsonify({'ok': True})

@app.route('/api/admin/customers/<uid>', methods=['DELETE'])
@require_admin
def admin_delete_customer(uid):
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id=?', (uid,))
    conn.execute('DELETE FROM sessions WHERE user_id=?', (uid,))
    conn.commit()
    conn.close()
    audit('Kunde gelöscht', request.user['id'], uid)
    return jsonify({'ok': True})

@app.route('/api/admin/customers', methods=['POST'])
@require_admin
def admin_create_customer():
    data = request.json or {}
    uid = 'u_' + new_id()
    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO users (id,email,password,name,praxis,plan,active,role,analyses,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)',
            (uid, data['email'].lower(), hash_pw(data.get('password','demo123')),
             data.get('name',''), data.get('praxis',''), data.get('plan','Starter'),
             1, 'customer', 0, now())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'E-Mail bereits vorhanden'}), 409
    conn.close()
    audit('Kunde angelegt', request.user['id'], data.get('email',''))
    return jsonify({'ok': True, 'id': uid}), 201

# ══════════════════════════════════════════════════════════
# API – ADMIN: LEADS
# ══════════════════════════════════════════════════════════

@app.route('/api/admin/leads', methods=['GET'])
@require_admin
def admin_leads():
    conn = get_db()
    rows = conn.execute('SELECT * FROM leads ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify({'leads': [dict(r) for r in rows]})

@app.route('/api/admin/leads', methods=['POST'])
@require_admin
def admin_create_lead():
    data = request.json or {}
    lid = 'l_' + new_id()
    conn = get_db()
    conn.execute(
        'INSERT INTO leads (id,name,contact,email,phone,message,status,source,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
        (lid, data.get('name',''), data.get('contact',''), data.get('email',''),
         data.get('phone',''), data.get('message',''), 'new', data.get('source','Website'), now())
    )
    conn.commit()
    conn.close()
    audit('Lead angelegt', request.user['id'], data.get('name',''))
    return jsonify({'ok': True, 'id': lid}), 201

@app.route('/api/admin/leads/<lid>', methods=['PUT'])
@require_admin
def admin_update_lead(lid):
    data = request.json or {}
    conn = get_db()
    conn.execute(
        'UPDATE leads SET name=?,contact=?,email=?,status=?,source=?,message=? WHERE id=?',
        (data.get('name'), data.get('contact'), data.get('email'),
         data.get('status'), data.get('source'), data.get('message'), lid)
    )
    conn.commit()
    conn.close()
    audit('Lead aktualisiert', request.user['id'], lid)
    return jsonify({'ok': True})

@app.route('/api/admin/leads/<lid>', methods=['DELETE'])
@require_admin
def admin_delete_lead(lid):
    conn = get_db()
    conn.execute('DELETE FROM leads WHERE id=?', (lid,))
    conn.commit()
    conn.close()
    audit('Lead gelöscht', request.user['id'], lid)
    return jsonify({'ok': True})

# ══════════════════════════════════════════════════════════
# API – ADMIN: STATISTIKEN
# ══════════════════════════════════════════════════════════

@app.route('/api/admin/stats', methods=['GET'])
@require_admin
def admin_stats():
    conn = get_db()
    customers = conn.execute("SELECT COUNT(*) as n FROM users WHERE role='customer' AND active=1").fetchone()['n']
    leads      = conn.execute("SELECT COUNT(*) as n FROM leads").fetchone()['n']
    new_leads  = conn.execute("SELECT COUNT(*) as n FROM leads WHERE status='new'").fetchone()['n']
    analyses   = conn.execute("SELECT SUM(analyses) as n FROM users WHERE role='customer'").fetchone()['n'] or 0
    mrr_q      = conn.execute("SELECT SUM(CASE plan WHEN 'Professional' THEN 149 WHEN 'Starter' THEN 49 ELSE 0 END) as n FROM users WHERE active=1 AND role='customer'").fetchone()['n'] or 0
    audit_rows = conn.execute('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 20').fetchall()
    conn.close()
    return jsonify({
        'customers': customers,
        'leads': leads,
        'new_leads': new_leads,
        'analyses': analyses,
        'mrr': mrr_q,
        'audit': [dict(r) for r in audit_rows],
    })

# ══════════════════════════════════════════════════════════
# START
# ══════════════════════════════════════════════════════════

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    print(f"""
╔══════════════════════════════════════╗
║   Petscan SaaS – Server läuft       ║
║   http://localhost:{port}              ║
║   API-Key: {'✅ gesetzt' if ANTHROPIC_API_KEY else '❌ fehlt → setze ANTHROPIC_API_KEY'}    
╚══════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=port, debug=debug)

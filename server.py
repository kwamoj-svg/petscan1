"""
Petscan – Vollständiger Produktions-Server
Auth + KI-Analyse + Stripe Payments + Admin
"""
from flask import Flask, request, jsonify, send_from_directory, redirect
from flask_cors import CORS
import anthropic, sqlite3, hashlib, secrets, os, json
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__, static_folder='static', static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app, supports_credentials=True)

ANTHROPIC_API_KEY  = os.environ.get('ANTHROPIC_API_KEY', '')
STRIPE_SECRET_KEY  = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_PUB_KEY     = os.environ.get('STRIPE_PUBLISHABLE_KEY', '')
STRIPE_WEBHOOK_SEC = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
STRIPE_PRICE_STARTER = os.environ.get('STRIPE_PRICE_STARTER', '')
STRIPE_PRICE_PRO     = os.environ.get('STRIPE_PRICE_PRO', '')
APP_URL = os.environ.get('APP_URL', 'http://localhost:5000')
DB_PATH = 'petscan.db'

# ═══════════════════════════════════════════════════
# DATENBANK
# ═══════════════════════════════════════════════════
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
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
            analyses_limit INTEGER DEFAULT 5,
            stripe_customer_id TEXT DEFAULT "",
            stripe_subscription_id TEXT DEFAULT "",
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
    def hp(pw): return hashlib.sha256(pw.encode()).hexdigest()
    trial_end = (datetime.now() + timedelta(days=14)).isoformat()
    demo_users = [
        ('u1','dr.mueller@tierklinik.de',hp('demo123'),'Dr. Anna Müller','Tierklinik München','professional','customer',999,999),
        ('u2','info@kleintierpraxis.de', hp('demo123'),'Dr. Stefan Schmidt','Kleintierpraxis Schmidt','starter','customer',22,50),
        ('admin1','admin@petscan.de',    hp('admin123'),'Administrator','Petscan GmbH','admin','admin',0,999999),
    ]
    for uid,em,pw,name,praxis,plan,role,used,limit in demo_users:
        try:
            conn.execute('''INSERT INTO users
                (id,email,password,name,praxis,plan,active,role,analyses_used,analyses_limit,trial_ends_at,created_at)
                VALUES (?,?,?,?,?,?,1,?,?,?,?,?)''',
                (uid,em,pw,name,praxis,plan,role,used,limit,trial_end,datetime.now().isoformat()))
        except: pass
    conn.commit(); conn.close()

def hp(pw): return hashlib.sha256(pw.encode()).hexdigest()
def nid():   return secrets.token_hex(8)
def now():   return datetime.now().isoformat()

def audit(action, uid, detail=''):
    try:
        conn = get_db()
        conn.execute('INSERT INTO audit_log (action,user_id,detail,created_at) VALUES (?,?,?,?)',(action,uid,detail,now()))
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
        sess = conn.execute('SELECT * FROM sessions WHERE token=? AND expires_at>?',(token,now())).fetchone()
        if not sess: conn.close(); return jsonify({'error':'Sitzung abgelaufen – bitte neu anmelden'}), 401
        user = conn.execute('SELECT * FROM users WHERE id=? AND active=1',(sess['user_id'],)).fetchone()
        conn.close()
        if not user: return jsonify({'error':'Account nicht gefunden oder deaktiviert'}), 403
        request.user = dict(user)
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
    if conn.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone():
        conn.close()
        return jsonify({'error':'Diese E-Mail ist bereits registriert. Bitte anmelden.'}), 409

    uid = 'u_'+nid()
    trial_end = (datetime.now()+timedelta(days=14)).isoformat()
    conn.execute('''INSERT INTO users
        (id,email,password,name,praxis,plan,active,role,analyses_used,analyses_limit,trial_ends_at,created_at)
        VALUES (?,?,?,?,?,"trial",1,"customer",0,5,?,?)''',
        (uid,email,hp(password),name or email.split('@')[0],praxis or 'Meine Praxis',trial_end,now()))

    token = secrets.token_hex(32)
    conn.execute('INSERT INTO sessions (token,user_id,expires_at,created_at) VALUES (?,?,?,?)',
                 (token,uid,(datetime.now()+timedelta(days=30)).isoformat(),now()))
    conn.commit(); conn.close()

    audit('Registrierung',uid,email)
    return jsonify({
        'token': token,
        'user': {'id':uid,'email':email,'name':name or email,'praxis':praxis,'plan':'trial','role':'customer','analyses_used':0,'analyses_limit':5}
    }), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    d  = request.json or {}
    em = d.get('email','').strip().lower()
    pw = d.get('password','')

    if not em or not pw:
        return jsonify({'error':'E-Mail und Passwort erforderlich'}), 400

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE email=? AND password=?',(em,hp(pw))).fetchone()
    if not user:
        conn.close()
        return jsonify({'error':'E-Mail oder Passwort falsch'}), 401
    if not user['active']:
        conn.close()
        return jsonify({'error':'Account deaktiviert. Bitte Support kontaktieren.'}), 403

    token = secrets.token_hex(32)
    conn.execute('INSERT INTO sessions (token,user_id,expires_at,created_at) VALUES (?,?,?,?)',
                 (token,user['id'],(datetime.now()+timedelta(days=30)).isoformat(),now()))
    conn.execute('UPDATE users SET last_login=? WHERE id=?',(now(),user['id']))
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
    conn.execute('DELETE FROM sessions WHERE token=?',(token,))
    conn.commit(); conn.close()
    audit('Logout',request.user['id'])
    return jsonify({'ok':True})

@app.route('/api/auth/me')
@require_auth
def me():
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=?',(request.user['id'],)).fetchone()
    conn.close()
    if not user: return jsonify({'error':'User not found'}), 404
    return jsonify({'user': {k: user[k] for k in ['id','email','name','praxis','plan','role','analyses_used','analyses_limit','trial_ends_at']}})

# ═══════════════════════════════════════════════════
# KI-ANALYSE
# ═══════════════════════════════════════════════════
@app.route('/api/analyse', methods=['POST'])
@require_auth
def analyse():
    if not ANTHROPIC_API_KEY:
        return jsonify({'error':'KI nicht konfiguriert. Admin muss ANTHROPIC_API_KEY setzen.'}), 503

    user = request.user
    # Analyse-Limit prüfen (außer Admin und unbegrenzte Pläne)
    if user['role'] != 'admin':
        if user['plan'] in ('trial',) and user['analyses_used'] >= user['analyses_limit']:
            return jsonify({
                'error': f'Ihr Trial-Kontingent ({user["analyses_limit"]} Analysen) ist aufgebraucht.',
                'upgrade_required': True,
                'plan': user['plan']
            }), 402
        if user['plan'] == 'starter' and user['analyses_used'] >= 50:
            return jsonify({'error':'Monatliches Starter-Kontingent (50 Analysen) erreicht.','upgrade_required':True}), 402

    d        = request.json or {}
    pet_name = d.get('pet_name','').strip()
    species  = d.get('species','Hund')
    region   = d.get('region','Thorax')
    mode     = d.get('mode','single')
    ctx      = d.get('context','')
    img_a    = d.get('img_a','')
    img_b    = d.get('img_b','')

    if not img_a: return jsonify({'error':'Kein Bild hochgeladen'}), 400

    prompts = {
        'single':  f'Erstelle einen vollständigen veterinärradiologischen Befundbericht für einen {species} im Bereich {region}.',
        'compare': f'Vergleiche Aufnahme A (früher) mit Aufnahme B (aktuell) eines {species} im Bereich {region} und beschreibe alle Veränderungen präzise.',
        'diff':    f'Analysiere die Unterschiede zwischen Aufnahme A und B bei einem {species} im Bereich {region}.',
        'second':  f'Erstelle eine kritische Zweitmeinung zu den Röntgenaufnahmen eines {species} im Bereich {region}.',
    }

    system = """Du bist ECVDI-Diplomate mit 20 Jahren Erfahrung in der Veterinärradiologie.
Erstelle professionelle Befundberichte auf Deutsch.

PFLICHT: Die DIAGNOSE und der MEDIZINISCHE ZUSTAND kommen IMMER ZUERST.

FORMAT - genau diese Reihenfolge einhalten:

## Diagnose & Klinische Beurteilung
**Hauptdiagnose:** [Was ist das wichtigste Ergebnis? 1-2 Sätze]
**Dringlichkeit:** **[NIEDRIG / MITTEL / HOCH]** — [1 Satz Begründung]

## Differenzialdiagnosen
| Diagnose | Wahrscheinlichkeit | Begründung |
|---|---|---|

## Detaillierter Radiologischer Befund
[Unterabschnitte je Körperregion mit ### Überschriften]

## Therapie- & Kontrollempfehlungen
[Konkrete Handlungsempfehlungen für den Tierarzt]

## Technische Bildqualität
[Kurz — max 2 Sätze zur Aufnahmequalität]

---
*Petscan KI-Befundassistent · Kein Ersatz für tierärztliche Diagnose*"""

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
    msgs.append({'type':'text','text':prompt})

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        resp = client.messages.create(
            model='claude-sonnet-4-20250514',
            max_tokens=2400,
            system=system,
            messages=[{'role':'user','content':msgs}]
        )
        text = resp.content[0].text
        tl   = text.lower()
        sev  = 'high' if ('**hoch**' in tl or '**high**' in tl) else ('low' if ('**niedrig**' in tl or '**low**' in tl) else 'mid')

        rid = 'r_'+nid()
        conn = get_db()
        conn.execute('INSERT INTO reports (id,user_id,pet_name,species,region,mode,severity,report_text,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
                     (rid,user['id'],pet_name,species,region,mode,sev,text,now()))
        conn.execute('UPDATE users SET analyses_used=analyses_used+1 WHERE id=?',(user['id'],))
        conn.commit(); conn.close()

        audit('Analyse',user['id'],f'{species}/{region}/{mode}')
        return jsonify({'id':rid,'report_text':text,'severity':sev,'pet_name':pet_name,'species':species,'region':region,'mode':mode,'created_at':now()})

    except anthropic.APIStatusError as e:
        return jsonify({'error':f'KI-API Fehler: {e.message}'}), 500
    except Exception as e:
        return jsonify({'error':f'Serverfehler: {str(e)}'}), 500

# ═══════════════════════════════════════════════════
# REPORTS
# ═══════════════════════════════════════════════════
@app.route('/api/reports')
@require_auth
def get_reports():
    conn = get_db()
    if request.user['role'] == 'admin':
        rows = conn.execute('SELECT r.*,u.name as user_name,u.praxis FROM reports r LEFT JOIN users u ON r.user_id=u.id ORDER BY r.created_at DESC').fetchall()
    else:
        rows = conn.execute('SELECT * FROM reports WHERE user_id=? ORDER BY created_at DESC',(request.user['id'],)).fetchall()
    conn.close()
    return jsonify({'reports':[dict(r) for r in rows]})

@app.route('/api/reports/<rid>', methods=['DELETE'])
@require_auth
def delete_report(rid):
    conn = get_db()
    if request.user['role'] == 'admin':
        conn.execute('DELETE FROM reports WHERE id=?',(rid,))
    else:
        conn.execute('DELETE FROM reports WHERE id=? AND user_id=?',(rid,request.user['id']))
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
        return jsonify({'error':f'Stripe Preis-ID für {plan} fehlt. Bitte STRIPE_PRICE_{plan.upper()} in Railway setzen.'}), 503

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
        # Payment-Datensatz anlegen
        conn = get_db()
        conn.execute('INSERT INTO payments (id,user_id,stripe_session_id,plan,amount,status,created_at) VALUES (?,?,?,?,?,?,?)',
                     ('pay_'+nid(), request.user['id'], session.id, plan,
                      4900 if plan=='starter' else 14900, 'pending', now()))
        conn.commit(); conn.close()

        return jsonify({'checkout_url': session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/payments/webhook', methods=['POST'])
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
            conn.execute('UPDATE users SET plan=?,analyses_limit=?,stripe_customer_id=?,stripe_subscription_id=? WHERE id=?',
                         (plan,limit,cust_id,sub_id,uid))
            conn.execute('UPDATE payments SET status="paid" WHERE stripe_session_id=?',(sess['id'],))
            conn.commit(); conn.close()
            audit('Plan aktiviert',uid,plan)

    elif event['type'] == 'customer.subscription.deleted':
        sub = event['data']['object']
        conn = get_db()
        conn.execute("UPDATE users SET plan='trial',analyses_limit=5 WHERE stripe_subscription_id=?",
                     (sub['id'],))
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
            customer=cust_id,
            return_url=f"{APP_URL}/app"
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
        'customers':  conn.execute("SELECT COUNT(*) as n FROM users WHERE role='customer' AND active=1").fetchone()['n'],
        'leads':      conn.execute("SELECT COUNT(*) as n FROM leads").fetchone()['n'],
        'new_leads':  conn.execute("SELECT COUNT(*) as n FROM leads WHERE status='new'").fetchone()['n'],
        'analyses':   conn.execute("SELECT SUM(analyses_used) as n FROM users").fetchone()['n'] or 0,
        'mrr':        conn.execute("SELECT SUM(CASE plan WHEN 'professional' THEN 149 WHEN 'starter' THEN 49 ELSE 0 END) as n FROM users WHERE active=1 AND role='customer'").fetchone()['n'] or 0,
        'audit':     [dict(r) for r in conn.execute('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 30').fetchall()],
        'plan_dist':  [dict(r) for r in conn.execute("SELECT plan, COUNT(*) as n FROM users WHERE role='customer' GROUP BY plan").fetchall()],
        'weekly':     [dict(r) for r in conn.execute("SELECT date(created_at) as day, COUNT(*) as n FROM reports GROUP BY day ORDER BY day DESC LIMIT 7").fetchall()],
    }
    conn.close()
    return jsonify(stats)

@app.route('/api/admin/customers')
@require_admin
def admin_customers():
    conn = get_db()
    rows = conn.execute("SELECT id,email,name,praxis,plan,active,analyses_used,analyses_limit,created_at,last_login FROM users WHERE role!='admin' ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify({'customers':[dict(r) for r in rows]})

@app.route('/api/admin/customers', methods=['POST'])
@require_admin
def admin_create_customer():
    d = request.json or {}
    uid = 'u_'+nid()
    limit = 999999 if d.get('plan')=='professional' else (50 if d.get('plan')=='starter' else 5)
    conn = get_db()
    try:
        conn.execute('INSERT INTO users (id,email,password,name,praxis,plan,active,role,analyses_used,analyses_limit,created_at) VALUES (?,?,?,?,?,?,1,"customer",0,?,?)',
                     (uid,d['email'].lower(),hp(d.get('password','Petscan2025!')),d.get('name',''),d.get('praxis',''),d.get('plan','trial'),limit,now()))
        conn.commit()
    except: conn.close(); return jsonify({'error':'E-Mail existiert bereits'}), 409
    conn.close()
    audit('Kunde angelegt',request.user['id'],d.get('email',''))
    return jsonify({'ok':True,'id':uid}), 201

@app.route('/api/admin/customers/<uid>', methods=['PUT'])
@require_admin
def admin_update_customer(uid):
    d = request.json or {}
    limit = 999999 if d.get('plan')=='professional' else (50 if d.get('plan')=='starter' else 5)
    conn = get_db()
    conn.execute('UPDATE users SET name=?,praxis=?,plan=?,active=?,analyses_limit=? WHERE id=?',
                 (d.get('name'),d.get('praxis'),d.get('plan'),int(d.get('active',1)),limit,uid))
    conn.commit(); conn.close()
    audit('Kunde bearbeitet',request.user['id'],uid)
    return jsonify({'ok':True})

@app.route('/api/admin/customers/<uid>', methods=['DELETE'])
@require_admin
def admin_delete_customer(uid):
    conn = get_db()
    conn.execute('UPDATE users SET active=0 WHERE id=?',(uid,))
    conn.commit(); conn.close()
    audit('Kunde deaktiviert',request.user['id'],uid)
    return jsonify({'ok':True})

@app.route('/api/admin/leads')
@require_admin
def admin_leads():
    conn = get_db()
    rows = conn.execute('SELECT * FROM leads ORDER BY created_at DESC').fetchall()
    conn.close()
    return jsonify({'leads':[dict(r) for r in rows]})

@app.route('/api/admin/leads', methods=['POST'])
@require_admin
def admin_create_lead():
    d = request.json or {}
    lid = 'l_'+nid()
    conn = get_db()
    conn.execute('INSERT INTO leads (id,name,contact,email,phone,message,status,source,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
                 (lid,d.get('name',''),d.get('contact',''),d.get('email',''),d.get('phone',''),d.get('message',''),'new',d.get('source','Website'),now()))
    conn.commit(); conn.close()
    return jsonify({'ok':True,'id':lid}), 201

@app.route('/api/admin/leads/<lid>', methods=['PUT'])
@require_admin
def admin_update_lead(lid):
    d = request.json or {}
    conn = get_db()
    conn.execute('UPDATE leads SET name=?,contact=?,email=?,phone=?,status=?,source=?,message=? WHERE id=?',
                 (d.get('name'),d.get('contact'),d.get('email'),d.get('phone'),d.get('status'),d.get('source'),d.get('message'),lid))
    conn.commit(); conn.close()
    return jsonify({'ok':True})

@app.route('/api/admin/leads/<lid>', methods=['DELETE'])
@require_admin
def admin_delete_lead(lid):
    conn = get_db()
    conn.execute('DELETE FROM leads WHERE id=?',(lid,))
    conn.commit(); conn.close()
    return jsonify({'ok':True})

@app.route('/api/admin/reports')
@require_admin
def admin_reports():
    conn = get_db()
    rows = conn.execute('SELECT r.*,u.name as user_name,u.praxis FROM reports r LEFT JOIN users u ON r.user_id=u.id ORDER BY r.created_at DESC').fetchall()
    conn.close()
    return jsonify({'reports':[dict(r) for r in rows]})

# ═══════════════════════════════════════════════════
# CONTACT / LEAD CAPTURE (öffentlich)
# ═══════════════════════════════════════════════════
@app.route('/api/contact', methods=['POST'])
def contact():
    d = request.json or {}
    lid = 'l_'+nid()
    conn = get_db()
    conn.execute('INSERT INTO leads (id,name,contact,email,phone,message,status,source,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
                 (lid,d.get('company',''),d.get('name',''),d.get('email',''),d.get('phone',''),d.get('message',''),'new',d.get('source','Kontaktformular'),now()))
    conn.commit(); conn.close()
    return jsonify({'ok':True}), 201

# ═══════════════════════════════════════════════════
# START — Datenbank beim Import initialisieren (wichtig für Gunicorn)
# ═══════════════════════════════════════════════════
init_db()

if __name__ == '__main__':
    init_db()
    port  = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG','false').lower() == 'true'

    missing = []
    if not ANTHROPIC_API_KEY:  missing.append('ANTHROPIC_API_KEY')
    if not STRIPE_SECRET_KEY:  missing.append('STRIPE_SECRET_KEY')
    if not STRIPE_PRICE_STARTER: missing.append('STRIPE_PRICE_STARTER')
    if not STRIPE_PRICE_PRO:     missing.append('STRIPE_PRICE_PRO')

    print(f"""
╔══════════════════════════════════════════════╗
║   🐾 Petscan – Server gestartet             ║
║   URL: http://localhost:{port}                  ║
║   Status:                                    ║
║   KI:     {'✅ Bereit' if ANTHROPIC_API_KEY else '❌ ANTHROPIC_API_KEY fehlt'}
║   Stripe: {'✅ Bereit' if STRIPE_SECRET_KEY else '❌ STRIPE_SECRET_KEY fehlt'}
{"║   ⚠️  Fehlende Variablen: " + ", ".join(missing) if missing else "║   ✅ Alle Variablen gesetzt"}
╚══════════════════════════════════════════════╝
    """)
    app.run(host='0.0.0.0', port=port, debug=debug)

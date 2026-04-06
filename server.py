from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import anthropic, sqlite3, hashlib, secrets, os, json
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__, static_folder='static', static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app, supports_credentials=True)

ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
DB_PATH = 'petscan.db'

# ── DATENBANK ──
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL, name TEXT, praxis TEXT,
            plan TEXT DEFAULT "Starter", active INTEGER DEFAULT 1,
            role TEXT DEFAULT "customer", analyses INTEGER DEFAULT 0,
            created_at TEXT, last_login TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
            species TEXT, region TEXT, mode TEXT, severity TEXT,
            report_text TEXT, created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS leads (
            id TEXT PRIMARY KEY, name TEXT, contact TEXT, email TEXT,
            phone TEXT, message TEXT, status TEXT DEFAULT "new",
            source TEXT, created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT, user_id TEXT, detail TEXT, created_at TEXT
        );
    ''')
    def hp(pw): return hashlib.sha256(pw.encode()).hexdigest()
    for uid, email, pw, name, praxis, plan, role in [
        ('u1','dr.mueller@tierklinik.de', hp('demo123'),'Dr. Anna Müller','Tierklinik München','Professional','customer'),
        ('u2','info@kleintierpraxis.de',  hp('demo123'),'Dr. Stefan Schmidt','Kleintierpraxis Schmidt','Starter','customer'),
        ('admin1','admin@petscan.de',      hp('admin123'),'Administrator','Petscan GmbH','Admin','admin'),
    ]:
        try:
            conn.execute('INSERT INTO users (id,email,password,name,praxis,plan,active,role,analyses,created_at) VALUES (?,?,?,?,?,?,1,?,0,?)',
                         (uid,email,pw,name,praxis,plan,role,datetime.now().isoformat()))
        except: pass
    conn.commit(); conn.close()

def hp(pw): return hashlib.sha256(pw.encode()).hexdigest()
def nid(): return secrets.token_hex(8)
def now(): return datetime.now().isoformat()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization','').replace('Bearer ','')
        if not token: return jsonify({'error':'Nicht authentifiziert'}), 401
        conn = get_db()
        sess = conn.execute('SELECT * FROM sessions WHERE token=? AND expires_at>?',(token,now())).fetchone()
        if not sess: conn.close(); return jsonify({'error':'Sitzung abgelaufen'}), 401
        user = conn.execute('SELECT * FROM users WHERE id=?',(sess['user_id'],)).fetchone()
        conn.close()
        if not user or not user['active']: return jsonify({'error':'Kein Zugang'}), 403
        request.user = dict(user)
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.user.get('role') != 'admin': return jsonify({'error':'Kein Admin-Zugang'}), 403
        return f(*args, **kwargs)
    return require_auth(decorated)

# ── STATIC ROUTES ──
@app.route('/')
def index(): return send_from_directory('static','index.html')

@app.route('/app')
def platform(): return send_from_directory('static','app.html')

@app.route('/admin')
def admin_panel(): return send_from_directory('static','admin.html')

# ── AUTH ──
@app.route('/api/auth/login', methods=['POST'])
def login():
    d = request.json or {}
    em = d.get('email','').strip().lower()
    pw = d.get('password','')
    if not em or not pw: return jsonify({'error':'E-Mail und Passwort erforderlich'}), 400
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE email=? AND password=?',(em,hp(pw))).fetchone()
    if not user: conn.close(); return jsonify({'error':'Falsche E-Mail oder Passwort'}), 401
    if not user['active']: conn.close(); return jsonify({'error':'Account deaktiviert'}), 403
    token = secrets.token_hex(32)
    expires = (datetime.now()+timedelta(days=7)).isoformat()
    conn.execute('INSERT INTO sessions (token,user_id,expires_at) VALUES (?,?,?)',(token,user['id'],expires))
    conn.execute('UPDATE users SET last_login=? WHERE id=?',(now(),user['id']))
    conn.commit(); conn.close()
    return jsonify({'token':token,'user':{'id':user['id'],'email':user['email'],'name':user['name'],'praxis':user['praxis'],'plan':user['plan'],'role':user['role']}})

@app.route('/api/auth/register', methods=['POST'])
def register():
    d = request.json or {}
    em = d.get('email','').strip().lower()
    pw = d.get('password','')
    if not em or not pw: return jsonify({'error':'E-Mail und Passwort erforderlich'}), 400
    if len(pw) < 6: return jsonify({'error':'Passwort mindestens 6 Zeichen'}), 400
    conn = get_db()
    if conn.execute('SELECT id FROM users WHERE email=?',(em,)).fetchone():
        conn.close(); return jsonify({'error':'E-Mail bereits registriert'}), 409
    uid = 'u_'+nid()
    conn.execute('INSERT INTO users (id,email,password,name,praxis,plan,active,role,analyses,created_at) VALUES (?,?,?,?,?,?,1,"customer",0,?)',
                 (uid,em,hp(pw),d.get('name',em),d.get('praxis','Meine Praxis'),'Starter',now()))
    token = secrets.token_hex(32)
    conn.execute('INSERT INTO sessions (token,user_id,expires_at) VALUES (?,?,?)',(token,uid,(datetime.now()+timedelta(days=7)).isoformat()))
    conn.commit(); conn.close()
    return jsonify({'token':token,'user':{'id':uid,'email':em,'name':d.get('name',em),'plan':'Starter','role':'customer'}}), 201

@app.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    token = request.headers.get('Authorization','').replace('Bearer ','')
    conn = get_db(); conn.execute('DELETE FROM sessions WHERE token=?',(token,)); conn.commit(); conn.close()
    return jsonify({'ok':True})

@app.route('/api/auth/me')
@require_auth
def me(): return jsonify({'user':request.user})

# ── ANALYSE ──
@app.route('/api/analyse', methods=['POST'])
@require_auth
def analyse():
    if not ANTHROPIC_API_KEY:
        return jsonify({'error':'ANTHROPIC_API_KEY nicht gesetzt. Bitte in Railway Variables eintragen.'}), 500
    d = request.json or {}
    species = d.get('species','Hund')
    region  = d.get('region','Thorax')
    mode    = d.get('mode','single')
    ctx     = d.get('context','')
    img_a   = d.get('img_a','')
    img_b   = d.get('img_b','')
    if not img_a: return jsonify({'error':'Kein Bild übertragen'}), 400

    mode_prompts = {
        'single':  f'Erstelle einen vollständigen veterinärradiologischen Befundbericht für einen {species} im Bereich {region}.',
        'compare': f'Vergleiche Aufnahme A (früher) mit Aufnahme B (aktuell) eines {species} im Bereich {region}.',
        'diff':    f'Identifiziere alle relevanten Unterschiede zwischen Aufnahme A und B beim {species}, Region {region}.',
        'second':  f'Erstelle eine fundierte Zweitmeinung zu den Aufnahmen eines {species} im Bereich {region}.',
    }
    system = """Du bist ein erfahrener Veterinärradiologe (ECVDI-Diplomate).
Erstelle professionelle strukturierte Befundberichte auf Deutsch.
Struktur (Markdown):
## Technische Beurteilung
## Radiologischer Befund
## Interpretation
## Differenzialdiagnosen
| Diagnose | Wahrscheinlichkeit | Begründung |
|---|---|---|
## Therapieempfehlungen
## Dringlichkeit
**NIEDRIG / MITTEL / HOCH** — Begründung"""

    content = [{'type':'image','source':{'type':'base64','media_type':'image/jpeg','data':img_a}},{'type':'text','text':'Aufnahme A:'}]
    if img_b and mode != 'single':
        content += [{'type':'image','source':{'type':'base64','media_type':'image/jpeg','data':img_b}},{'type':'text','text':'Aufnahme B:'}]
    prompt = mode_prompts.get(mode, mode_prompts['single'])
    if ctx: prompt += f'\n\nKlinischer Kontext: {ctx}'
    content.append({'type':'text','text':prompt})

    try:
        client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        resp = client.messages.create(model='claude-sonnet-4-20250514',max_tokens=2200,system=system,messages=[{'role':'user','content':content}])
        text = resp.content[0].text
        tl = text.lower()
        sev = 'high' if ('hoch' in tl and 'sofort' in tl) else ('low' if 'niedrig' in tl else 'mid')
        rid = 'r_'+nid()
        conn = get_db()
        conn.execute('INSERT INTO reports (id,user_id,species,region,mode,severity,report_text,created_at) VALUES (?,?,?,?,?,?,?,?)',
                     (rid,request.user['id'],species,region,mode,sev,text,now()))
        conn.execute('UPDATE users SET analyses=analyses+1 WHERE id=?',(request.user['id'],))
        conn.commit(); conn.close()
        return jsonify({'id':rid,'report_text':text,'severity':sev,'species':species,'region':region,'mode':mode,'created_at':now()})
    except Exception as e:
        return jsonify({'error':str(e)}), 500

# ── REPORTS ──
@app.route('/api/reports')
@require_auth
def get_reports():
    conn = get_db()
    if request.user['role'] == 'admin':
        rows = conn.execute('SELECT r.*,u.name as user_name FROM reports r LEFT JOIN users u ON r.user_id=u.id ORDER BY r.created_at DESC').fetchall()
    else:
        rows = conn.execute('SELECT * FROM reports WHERE user_id=? ORDER BY created_at DESC',(request.user['id'],)).fetchall()
    conn.close()
    return jsonify({'reports':[dict(r) for r in rows]})

@app.route('/api/reports/<rid>', methods=['DELETE'])
@require_auth
def delete_report(rid):
    conn = get_db()
    if request.user['role'] == 'admin': conn.execute('DELETE FROM reports WHERE id=?',(rid,))
    else: conn.execute('DELETE FROM reports WHERE id=? AND user_id=?',(rid,request.user['id']))
    conn.commit(); conn.close()
    return jsonify({'ok':True})

# ── ADMIN ──
@app.route('/api/admin/stats')
@require_admin
def admin_stats():
    conn = get_db()
    r = {
        'customers': conn.execute("SELECT COUNT(*) as n FROM users WHERE role='customer' AND active=1").fetchone()['n'],
        'leads':     conn.execute("SELECT COUNT(*) as n FROM leads").fetchone()['n'],
        'new_leads': conn.execute("SELECT COUNT(*) as n FROM leads WHERE status='new'").fetchone()['n'],
        'analyses':  conn.execute("SELECT SUM(analyses) as n FROM users WHERE role='customer'").fetchone()['n'] or 0,
        'mrr':       conn.execute("SELECT SUM(CASE plan WHEN 'Professional' THEN 149 WHEN 'Starter' THEN 49 ELSE 0 END) as n FROM users WHERE active=1 AND role='customer'").fetchone()['n'] or 0,
        'audit':     [dict(x) for x in conn.execute('SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 20').fetchall()],
    }
    conn.close()
    return jsonify(r)

@app.route('/api/admin/customers')
@require_admin
def admin_customers():
    conn = get_db()
    rows = conn.execute("SELECT id,email,name,praxis,plan,active,analyses,created_at,last_login FROM users WHERE role!='admin' ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify({'customers':[dict(r) for r in rows]})

@app.route('/api/admin/customers', methods=['POST'])
@require_admin
def admin_create_customer():
    d = request.json or {}
    uid = 'u_'+nid()
    conn = get_db()
    try:
        conn.execute('INSERT INTO users (id,email,password,name,praxis,plan,active,role,analyses,created_at) VALUES (?,?,?,?,?,?,1,"customer",0,?)',
                     (uid,d['email'].lower(),hp(d.get('password','demo123')),d.get('name',''),d.get('praxis',''),d.get('plan','Starter'),now()))
        conn.commit()
    except: conn.close(); return jsonify({'error':'E-Mail bereits vorhanden'}), 409
    conn.close()
    return jsonify({'ok':True,'id':uid}), 201

@app.route('/api/admin/customers/<uid>', methods=['PUT'])
@require_admin
def admin_update_customer(uid):
    d = request.json or {}
    conn = get_db()
    conn.execute('UPDATE users SET name=?,praxis=?,plan=?,active=? WHERE id=?',(d.get('name'),d.get('praxis'),d.get('plan'),int(d.get('active',1)),uid))
    conn.commit(); conn.close()
    return jsonify({'ok':True})

@app.route('/api/admin/customers/<uid>', methods=['DELETE'])
@require_admin
def admin_delete_customer(uid):
    conn = get_db()
    conn.execute('DELETE FROM users WHERE id=?',(uid,))
    conn.execute('DELETE FROM sessions WHERE user_id=?',(uid,))
    conn.commit(); conn.close()
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
    conn.execute('UPDATE leads SET name=?,contact=?,email=?,status=?,source=?,message=? WHERE id=?',
                 (d.get('name'),d.get('contact'),d.get('email'),d.get('status'),d.get('source'),d.get('message'),lid))
    conn.commit(); conn.close()
    return jsonify({'ok':True})

@app.route('/api/admin/leads/<lid>', methods=['DELETE'])
@require_admin
def admin_delete_lead(lid):
    conn = get_db()
    conn.execute('DELETE FROM leads WHERE id=?',(lid,))
    conn.commit(); conn.close()
    return jsonify({'ok':True})

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    print(f"\n🐾 Petscan läuft auf http://localhost:{port}")
    print(f"   API-Key: {'✅ gesetzt' if ANTHROPIC_API_KEY else '❌ fehlt → ANTHROPIC_API_KEY in Railway Variables setzen'}\n")
    app.run(host='0.0.0.0', port=port, debug=False)

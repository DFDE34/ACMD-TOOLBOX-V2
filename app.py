from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3, os, socket, re, hashlib, base64, urllib.parse, html, json, ipaddress, struct
import threading, time
from datetime import datetime
from reporting import generate_pdf_report

app = Flask(__name__)
app.secret_key = os.urandom(24)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Veuillez vous connecter.'

DB = os.environ.get('DB_PATH', 'toolbox.db')  # Docker: /app/data/toolbox.db

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def get_setting(key, default=''):
    db = get_db()
    row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    db.close()
    return row['value'] if row else default

def init_db():
    db = get_db()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, tool TEXT NOT NULL, input TEXT, output TEXT, created_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, content TEXT, created_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS scan_tools (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT NOT NULL, description TEXT, command TEXT NOT NULL, default_options TEXT DEFAULT '', category TEXT DEFAULT 'custom', is_builtin INTEGER DEFAULT 0, created_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, tool_id INTEGER, tool_name TEXT NOT NULL, target TEXT NOT NULL, options TEXT DEFAULT '', status TEXT DEFAULT 'pending', output TEXT DEFAULT '', error TEXT DEFAULT '', started_at TEXT, finished_at TEXT, created_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS workflows (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT NOT NULL, description TEXT DEFAULT '', steps TEXT DEFAULT '[]', status TEXT DEFAULT 'idle', created_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE IF NOT EXISTS workflow_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, workflow_id INTEGER, user_id INTEGER, target TEXT NOT NULL, status TEXT DEFAULT 'running', current_step INTEGER DEFAULT 0, total_steps INTEGER DEFAULT 0, results TEXT DEFAULT '[]', started_at TEXT DEFAULT (datetime('now')), finished_at TEXT);
    ''')
    db.commit()
    # ── Migration RBAC : ajout des colonnes role / active ─────────────────
    cols = [r['name'] for r in db.execute("PRAGMA table_info(users)").fetchall()]
    if 'role' not in cols:
        db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
    if 'active' not in cols:
        db.execute("ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
    db.commit()
    # Bootstrap : si aucun admin n'existe, promouvoir le premier utilisateur
    if db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0] == 0:
        first = db.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1").fetchone()
        if first:
            db.execute("UPDATE users SET role='admin' WHERE id=?", (first['id'],))
            db.commit()
    # ── Table settings (clé/valeur pour la configuration de la plateforme) ─
    db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('registration_open', '1')")
    db.commit()
    existing = db.execute("SELECT COUNT(*) FROM scan_tools WHERE is_builtin=1").fetchone()[0]
    if existing == 0:
        builtins = [
            (None,'Port Scanner','Scan TCP des ports réseau','portscan','-p 22,80,443','réseau',1),
            (None,'DNS Lookup','Résolution DNS et reverse DNS','dns','','réseau',1),
            (None,'IP Analyser','Analyse détaillée d\'une adresse IP','ipinfo','','réseau',1),
            (None,'Subnet Calc','Calcul de sous-réseau CIDR','subnet','','réseau',1),
        ]
        db.executemany('INSERT INTO scan_tools (user_id,name,description,command,default_options,category,is_builtin) VALUES (?,?,?,?,?,?,?)', builtins)
        db.commit()
    db.close()

init_db()

class User(UserMixin):
    def __init__(self, id, username, role='user', active=1):
        self.id       = id
        self.username = username
        self.role     = role
        self.active   = bool(active)

    @property
    def is_admin(self):
        return self.role == 'admin'

    @property
    def is_tech(self):
        return self.role in ('admin', 'tech')


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    u  = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    db.close()
    if not u or not u['active']:
        return None
    return User(u['id'], u['username'], u['role'], u['active'])

def role_required(*roles):
    """Bloque avec 403 si le rôle de l'utilisateur connecté n'est pas dans la liste."""
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                abort(403)
            return view_func(*args, **kwargs)
        return wrapped
    return decorator

admin_required = role_required('admin')
tech_required  = role_required('admin', 'tech')


def save_history(tool, inp, out):
    if current_user.is_authenticated:
        db = get_db()
        db.execute('INSERT INTO history (user_id, tool, input, output) VALUES (?,?,?,?)',
                   (current_user.id, tool, str(inp)[:500], str(out)[:2000]))
        db.commit(); db.close()

NAV_LINKS = [
    ('dashboard',      'Dashboard'),
    ('tools',          'Fast Tools'),
    ('scans_page',     'Scans'),
    ('workflows_page', 'Workflows'),
    ('scan_tools_page','Outils'),
    ('history_page',   'Historique'),
    ('report_page',    'Rapport PDF'),
    ('owasp',          'OWASP TOP 10'),
]

@app.context_processor
def inject_nav():
    from flask import url_for as _url_for
    nav = []
    for endpoint, label in NAV_LINKS:
        try:
            nav.append({'url': _url_for(endpoint), 'label': label, 'endpoint': endpoint})
        except Exception:
            pass
    if current_user.is_authenticated and current_user.role == 'admin':
        try:
            nav.append({'url': _url_for('admin_page'), 'label': 'Administration', 'endpoint': 'admin_page'})
        except Exception:
            pass
    return {'nav_links': nav, 'current_role': getattr(current_user, 'role', None)}

@app.before_request
def check_setup_required():
    """Si aucun utilisateur n'existe encore, rediriger vers le wizard de setup."""
    if request.endpoint in ('setup', 'static', None):
        return
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    db.close()
    if count == 0:
        return redirect(url_for('setup'))


@app.route('/')
def index():
    return redirect(url_for('dashboard') if current_user.is_authenticated else url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        db = get_db()
        u = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
        db.close()
        if u and check_password_hash(u['password'], password):
            if not u['active']:
                flash("Ce compte a été désactivé. Contactez un administrateur.")
                return render_template('login.html')
            login_user(User(u['id'], u['username'], u['role'], u['active']))
            return redirect(url_for('dashboard'))
        flash('Identifiants incorrects.')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if get_setting('registration_open', '1') == '0':
        flash("L'inscription est actuellement désactivée. Contactez un administrateur.")
        return render_template('register.html', registration_closed=True)
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        error = None
        if len(username) < 3:
            error = 'Le nom d\'utilisateur doit contenir au moins 3 caractères.'
        elif len(password) < 10:
            error = 'Le mot de passe doit contenir au moins 10 caractères.'
        elif not re.search(r'[A-Z]', password):
            error = 'Le mot de passe doit contenir au moins une lettre majuscule.'
        elif not re.search(r'[a-z]', password):
            error = 'Le mot de passe doit contenir au moins une lettre minuscule.'
        elif not re.search(r'[0-9]', password):
            error = 'Le mot de passe doit contenir au moins un chiffre.'
        elif not re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?/]', password):
            error = 'Le mot de passe doit contenir au moins un caractère spécial (!@#$%...).'
        if error:
            flash(error)
        else:
            try:
                db = get_db()
                existing_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                role = 'admin' if existing_count == 0 else 'user'
                db.execute('INSERT INTO users (username, password, role) VALUES (?,?,?)',
                           (username, generate_password_hash(password), role))
                db.commit(); db.close()
                flash('Compte créé. Connectez-vous.')
                return redirect(url_for('login'))
            except: flash("Ce nom d'utilisateur existe déjà.")
    return render_template('register.html')

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """Wizard de premier déploiement — inaccessible une fois le premier compte créé."""
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    db.close()
    if count > 0:
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        error = None
        if len(username) < 3:
            error = "Le nom d'utilisateur doit contenir au moins 3 caractères."
        elif len(password) < 10:
            error = "Le mot de passe doit contenir au moins 10 caractères."
        elif not re.search(r'[A-Z]', password):
            error = "Le mot de passe doit contenir au moins une majuscule."
        elif not re.search(r'[a-z]', password):
            error = "Le mot de passe doit contenir au moins une minuscule."
        elif not re.search(r'[0-9]', password):
            error = "Le mot de passe doit contenir au moins un chiffre."
        elif not re.search(r'[!@#$%^&*()\-_=+\[\]{}|;:,.<>?/]', password):
            error = "Le mot de passe doit contenir au moins un caractère spécial (!@#$%...)."
        if error:
            flash(error)
        else:
            db = get_db()
            db.execute('INSERT INTO users (username, password, role) VALUES (?,?,?)',
                       (username, generate_password_hash(password), 'admin'))
            db.commit(); db.close()
            flash(f'Compte administrateur "{username}" créé. Connectez-vous.')
            return redirect(url_for('login'))
    return render_template('setup.html')


@app.route('/logout')
@login_required
def logout():
    logout_user(); return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    history = db.execute('SELECT * FROM history WHERE user_id=? ORDER BY id DESC LIMIT 10', (current_user.id,)).fetchall()
    notes = db.execute('SELECT * FROM notes WHERE user_id=? ORDER BY id DESC LIMIT 5', (current_user.id,)).fetchall()
    scan_count = db.execute('SELECT COUNT(*) FROM scans WHERE user_id=?', (current_user.id,)).fetchone()[0]
    wf_count = db.execute('SELECT COUNT(*) FROM workflows WHERE user_id=?', (current_user.id,)).fetchone()[0]
    tool_count = db.execute('SELECT COUNT(*) FROM scan_tools WHERE user_id=? OR is_builtin=1', (current_user.id,)).fetchone()[0]
    op_count = db.execute('SELECT COUNT(*) FROM history WHERE user_id=?', (current_user.id,)).fetchone()[0]
    recent_scans = db.execute('SELECT * FROM scans WHERE user_id=? ORDER BY id DESC LIMIT 5', (current_user.id,)).fetchall()
    db.close()
    return render_template('dashboard.html', history=history, notes=notes, scan_count=scan_count, wf_count=wf_count, tool_count=tool_count, op_count=op_count, recent_scans=recent_scans)

@app.route('/tools')
@login_required
def tools():
    return render_template('tools.html')

@app.route('/owasp')
@login_required
def owasp():
    return render_template('owasp.html')

@app.route('/scan-tools')
@login_required
def scan_tools_page():
    db = get_db()
    tools = db.execute('SELECT * FROM scan_tools WHERE is_builtin=1 OR user_id=? ORDER BY is_builtin DESC, name', (current_user.id,)).fetchall()
    db.close()
    return render_template('scan_tools.html', tools=tools)

# ── Package name mapping ─────────────────────────────────────────────────────
# ── Package mapping apt ──────────────────────────────────────────────────────
APT_PACKAGES = {
    'nmap':'nmap','nikto':'nikto','gobuster':'gobuster','dirb':'dirb',
    'sqlmap':'sqlmap','hydra':'hydra','masscan':'masscan','whois':'whois',
    'dig':'dnsutils','host':'dnsutils','traceroute':'traceroute',
    'tcpdump':'tcpdump','wget':'wget','curl':'curl','john':'john',
    'hashcat':'hashcat','aircrack-ng':'aircrack-ng','wfuzz':'wfuzz',
    'ffuf':'ffuf','amass':'amass','netcat':'netcat-openbsd','nc':'netcat-openbsd',
}

def _extract_executable(command):
    return command.strip().split()[0]

def _run_install(package, sudo_password=None):
    """
    Installe un paquet apt.
    Comportement selon le contexte :
      - Docker / root   : apt-get direct, sans mot de passe (cas nominal)
      - Linux + sudo    : sudo -S apt-get avec le mot de passe fourni
      - Pas de droits   : message d'aide explicite
    """
    import subprocess, shutil, os

    is_root  = (os.geteuid() == 0)
    has_sudo = bool(shutil.which('sudo'))

    # ── Mise à jour de l'index apt (silencieuse) ──────────────────
    if is_root:
        subprocess.run(['apt-get', 'update', '-qq'], capture_output=True, timeout=60)
    elif has_sudo and sudo_password:
        subprocess.run(['sudo', '-S', 'apt-get', 'update', '-qq'],
                       input=sudo_password + '\n', capture_output=True, text=True, timeout=60)

    # ── Construction de la commande ───────────────────────────────
    if is_root:
        # Docker ou root natif : pas de sudo, pas de mot de passe
        cmd = ['apt-get', 'install', '-y', package]
        inp = None
    elif has_sudo and sudo_password:
        cmd = ['sudo', '-S', 'apt-get', 'install', '-y', package]
        inp = sudo_password + '\n'
    elif has_sudo and not sudo_password:
        # Tentative sans mot de passe (nopasswd configuré ?)
        cmd = ['sudo', 'apt-get', 'install', '-y', package]
        inp = None
    else:
        return False, (
            'Droits insuffisants pour installer des paquets.\n\n'
            'Solutions :\n'
            '  • Docker (recommandé) : root automatique, aucun mot de passe\n'
            '  • Fournissez votre mot de passe sudo dans le formulaire\n'
            '  • Installation manuelle : sudo apt-get install -y ' + package
        )

    # ── Exécution ─────────────────────────────────────────────────
    try:
        r = subprocess.run(cmd, input=inp, capture_output=True, text=True, timeout=180)

        if 'incorrect password' in r.stderr.lower() or 'Sorry, try again' in r.stderr:
            return False, 'Mot de passe sudo incorrect. Réessayez.'

        if r.returncode == 0:
            return True, f'Paquet "{package}" installé avec succès.'

        stderr = r.stderr.strip()
        if 'Unable to locate package' in stderr:
            return False, (
                f'Paquet "{package}" introuvable dans les dépôts apt.\n'
                f'Vérifiez le nom exact sur https://packages.debian.org'
            )
        return False, f'Erreur installation (code {r.returncode}) : {stderr[:300]}'

    except subprocess.TimeoutExpired:
        return False, 'Timeout (>3 min). Essayez manuellement : apt-get install -y ' + package
    except Exception as e:
        return False, f'Erreur inattendue : {str(e)}'

@app.route('/api/check-tool', methods=['POST'])
@login_required
def api_check_tool():
    """
    Verifie si un executable est disponible.
    Retourne: available, executable, package (connu ou None), known (dans APT_PACKAGES).
    """
    import shutil
    exe = _extract_executable(request.json.get('command',''))
    if not exe: return jsonify({'error': 'Commande vide'}), 400
    available = bool(shutil.which(exe))
    known_pkg = APT_PACKAGES.get(exe)          # None si inconnu
    return jsonify({
        'available': available,
        'executable': exe,
        'package': known_pkg or exe,           # suggestion
        'known': known_pkg is not None,        # True = dans notre liste
    })

@app.route('/api/install-tool', methods=['POST'])
@login_required
@tech_required
def api_install_tool():
    """
    Installe un paquet avec confirmation explicite de l'utilisateur.
    Payload: { package: str, sudo_password: str|null }
    """
    import shutil
    data = request.json
    package = data.get('package','').strip()
    sudo_pw = data.get('sudo_password', None)

    if not package or not re.match(r'^[a-zA-Z0-9\-_.+]{1,80}$', package):
        return jsonify({'error': 'Nom de paquet invalide'}), 400

    if shutil.which(package.split('-')[0]) or shutil.which(package):
        return jsonify({'ok': True, 'already': True, 'message': f'Deja disponible.' })

    success, msg = _run_install(package, sudo_pw)
    return jsonify({'ok': success, 'already': False, 'message': msg})

@app.route('/api/scan-tools', methods=['GET','POST'])
@login_required
def api_scan_tools():
    """
    GET  : liste tous les outils.
    POST : cree un outil (sans installation — celle-ci passe par /api/install-tool).
    """
    import shutil
    db = get_db()
    if request.method == 'GET':
        tools = db.execute(
            'SELECT * FROM scan_tools WHERE is_builtin=1 OR user_id=? ORDER BY is_builtin DESC, name',
            (current_user.id,)).fetchall()
        db.close()
        return jsonify([dict(t) for t in tools])

    if not current_user.is_tech:
        db.close(); return jsonify({'error': 'Accès refusé : rôle tech ou admin requis'}), 403
    data    = request.json
    name    = data.get('name','').strip()
    command = data.get('command','').strip()
    if not name or not command:
        db.close(); return jsonify({'error': 'Nom et commande requis'}), 400
    if not re.match(r'^[a-zA-Z0-9\-_ ]{2,50}$', name):
        db.close(); return jsonify({'error': 'Nom invalide (2-50 chars, lettres/chiffres/tirets)'}), 400
    if db.execute('SELECT id FROM scan_tools WHERE name=? AND (user_id=? OR is_builtin=1)',
                  (name, current_user.id)).fetchone():
        db.close(); return jsonify({'error': f'Un outil nomme "{name}" existe deja'}), 409

    cur = db.execute(
        'INSERT INTO scan_tools (user_id, name, description, command, default_options, category) VALUES (?,?,?,?,?,?)',
        (current_user.id, name, data.get('description',''), command,
         data.get('default_options',''), data.get('category','custom')))
    db.commit(); new_id = cur.lastrowid; db.close()

    exe       = _extract_executable(command)
    available = bool(shutil.which(exe))
    known_pkg = APT_PACKAGES.get(exe)

    return jsonify({
        'ok':        True,
        'id':        new_id,
        'message':   f'Outil "{name}" cree.',
        'exe':       exe,
        'available': available,        # deja installe ?
        'known':     known_pkg is not None,
        'package':   known_pkg or exe, # paquet suggere
    })

@app.route('/api/scan-tools/<int:tool_id>', methods=['GET','PUT','DELETE'])
@login_required
def api_scan_tool(tool_id):
    db = get_db()
    tool = db.execute('SELECT * FROM scan_tools WHERE id=?', (tool_id,)).fetchone()
    if not tool:
        db.close(); return jsonify({'error': 'Outil introuvable'}), 404
    if request.method == 'GET':
        db.close(); return jsonify(dict(tool))
    if not current_user.is_tech:
        db.close(); return jsonify({'error': 'Accès refusé : rôle tech ou admin requis'}), 403
    if tool['is_builtin']:
        db.close(); return jsonify({'error': 'Les outils integres ne peuvent pas etre modifies'}), 403
    if tool['user_id'] != current_user.id:
        db.close(); return jsonify({'error': 'Acces refuse'}), 403
    if request.method == 'PUT':
        data = request.json
        name = data.get('name', tool['name']).strip()
        if not re.match(r'^[a-zA-Z0-9\-_ ]{2,50}$', name):
            db.close(); return jsonify({'error': 'Nom invalide'}), 400
        db.execute('UPDATE scan_tools SET name=?, description=?, command=?, default_options=?, category=? WHERE id=?',
            (name, data.get('description', tool['description']), data.get('command', tool['command']),
             data.get('default_options', tool['default_options']), data.get('category', tool['category']), tool_id))
        db.commit(); db.close()
        return jsonify({'ok': True, 'message': f'Outil "{name}" mis a jour'})
    if request.method == 'DELETE':
        wf_count = 0
        workflows = db.execute('SELECT steps FROM workflows WHERE user_id=?', (current_user.id,)).fetchall()
        for wf in workflows:
            for step in json.loads(wf['steps'] or '[]'):
                if step.get('tool_id') == tool_id: wf_count += 1; break
        db.execute('DELETE FROM scan_tools WHERE id=? AND user_id=?', (tool_id, current_user.id))
        db.commit(); db.close()
        msg = 'Outil supprime.'
        if wf_count: msg += f' {wf_count} workflow(s) utilisait cet outil.'
        return jsonify({'ok': True, 'message': msg})

@app.route('/scans')
@login_required
def scans_page():
    return render_template('scans.html')

@app.route('/api/scans', methods=['GET'])
@login_required
def api_scans():
    page = int(request.args.get('page', 1)); per_page = 20
    tool_f = request.args.get('tool',''); status_f = request.args.get('status','')
    date_f = request.args.get('date',''); search_f = request.args.get('search','')
    query = 'SELECT * FROM scans WHERE user_id=?'; params = [current_user.id]
    if tool_f:   query += ' AND tool_name=?';           params.append(tool_f)
    if status_f: query += ' AND status=?';              params.append(status_f)
    if date_f:   query += ' AND created_at LIKE ?';     params.append(f'{date_f}%')
    if search_f: query += ' AND (target LIKE ? OR tool_name LIKE ?)'; params += [f'%{search_f}%',f'%{search_f}%']
    db = get_db()
    total = db.execute(query.replace('SELECT *','SELECT COUNT(*)'), params).fetchone()[0]
    rows  = db.execute(query + ' ORDER BY id DESC LIMIT ? OFFSET ?', params + [per_page,(page-1)*per_page]).fetchall()
    tools = db.execute('SELECT DISTINCT tool_name FROM scans WHERE user_id=?', (current_user.id,)).fetchall()
    db.close()
    return jsonify({'scans':[dict(r) for r in rows],'total':total,'page':page,'pages':(total+per_page-1)//per_page,'tools':[t['tool_name'] for t in tools]})

@app.route('/api/scans/<int:scan_id>', methods=['GET','DELETE'])
@login_required
def api_scan(scan_id):
    db = get_db()
    scan = db.execute('SELECT * FROM scans WHERE id=? AND user_id=?', (scan_id, current_user.id)).fetchone()
    if not scan:
        db.close(); return jsonify({'error': 'Scan introuvable'}), 404
    if request.method == 'DELETE':
        db.execute('DELETE FROM scans WHERE id=? AND user_id=?', (scan_id, current_user.id))
        db.commit(); db.close(); return jsonify({'ok': True})
    db.close(); return jsonify(dict(scan))

@app.route('/api/scans/launch', methods=['POST'])
@login_required
@tech_required
def api_scan_launch():
    data = request.json
    tool_id = data.get('tool_id'); target = data.get('target','').strip(); options = data.get('options','').strip()
    if not target: return jsonify({'error': 'Cible requise'}), 400
    db = get_db()
    tool = db.execute('SELECT * FROM scan_tools WHERE id=?', (tool_id,)).fetchone()
    if not tool:
        db.close(); return jsonify({'error': 'Outil introuvable'}), 404
    cur = db.execute('INSERT INTO scans (user_id, tool_id, tool_name, target, options, status, started_at) VALUES (?,?,?,?,?,?,?)',
        (current_user.id, tool_id, tool['name'], target, options, 'running', datetime.now().isoformat()))
    db.commit(); scan_id = cur.lastrowid
    uid = current_user.id; tool_dict = dict(tool); db.close()
    def run_scan(scan_id, tool, target, options, user_id):
        result, error = execute_tool(tool, target, options)
        db2 = get_db()
        db2.execute('UPDATE scans SET status=?, output=?, error=?, finished_at=? WHERE id=?',
            ('completed' if not error else 'failed', result, error, datetime.now().isoformat(), scan_id))
        db2.execute('INSERT INTO history (user_id, tool, input, output) VALUES (?,?,?,?)',
            (user_id, tool['name'], target, (result or error)[:500]))
        db2.commit(); db2.close()
    t = threading.Thread(target=run_scan, args=(scan_id, tool_dict, target, options, uid))
    t.daemon = True; t.start()
    return jsonify({'ok': True, 'scan_id': scan_id, 'message': f'Scan lance sur {target}'})

def execute_tool(tool, target, options):
    """
    Exécute un outil de scan.
    - Outils intégrés (portscan, dns, ipinfo, subnet) : implémentation Python pure, pas de dépendance externe.
    - Outils custom : la commande est exécutée en shell réel.
      La chaîne '{target}' dans la commande est remplacée par la cible.
      Exemple : commande = "nmap -sV {target}" avec options "-p 80,443"
                → exécuté comme : nmap -sV 192.168.1.1 -p 80,443
    """
    import concurrent.futures, subprocess, shutil
    cmd = tool['command']
    effective_options = options.strip() if options.strip() else tool.get('default_options', '').strip()

    # ── Outils intégrés Python pur ────────────────────────────────────────────
    try:
        if cmd == 'portscan':
            # Extraire host:port si présent dans la cible
            if ':' in target:
                scan_host, extra_port = target.rsplit(':', 1)
            else:
                scan_host, extra_port = target, None
            # Ports depuis les options (format: "80,443,22" ou "-p 80,443,22")
            ports_str = re.sub(r'-p\s*', '', effective_options).strip()
            if not ports_str and extra_port and extra_port.isdigit():
                ports_str = extra_port
            ports_str = ports_str or '21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,27017'
            if not re.match(r'^[a-zA-Z0-9.\-]+$', scan_host):
                return '', 'Cible invalide (caractères non autorisés)'
            target = scan_host
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                return '', f'Impossible de résoudre "{target}" — vérifiez la cible et votre connexion réseau'

            ports = []
            for part in ports_str.split(','):
                part = part.strip()
                if '-' in part:
                    try:
                        a, b = part.split('-', 1)
                        ports += list(range(int(a), int(b)+1))
                    except: pass
                elif part.isdigit():
                    ports.append(int(part))
            ports = sorted(set(ports))[:100]  # max 100 ports

            lines = [
                f'╔══ PORT SCANNER ══════════════════════════',
                f'║  Cible  : {target}',
                f'║  IP     : {ip}',
                f'║  Ports  : {len(ports)} testés',
                f'╚══════════════════════════════════════════',
                ''
            ]
            open_ports = []
            closed_ports = []

            def check(port):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.8)
                r = s.connect_ex((ip, port)) == 0
                s.close()
                return port, r

            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
                for port, is_open in sorted(ex.map(check, ports)):
                    if is_open:
                        open_ports.append(port)
                        # Tentative de banner grabbing sur les ports ouverts
                        service = _known_service(port)
                        lines.append(f'  {str(port).ljust(6)} OUVERT   {service}')
                    else:
                        closed_ports.append(port)

            if not open_ports:
                lines.append('  (aucun port ouvert détecté)')
            lines += [
                '',
                f'RÉSUMÉ : {len(open_ports)} ouvert(s) / {len(ports)} testés',
            ]
            if open_ports:
                lines.append(f'OUVERTS : {", ".join(map(str, open_ports))}')
            return '\n'.join(lines), ''

        elif cmd == 'dns':
            dns_host = target.split(':')[0]
            if not re.match(r'^[a-zA-Z0-9.\-]+$', dns_host):
                return '', 'Hôte invalide'
            try:
                ip = socket.gethostbyname(dns_host)
            except socket.gaierror:
                return '', f'Résolution DNS échouée pour "{dns_host}"'
            try:
                rev = socket.gethostbyaddr(ip)[0]
            except:
                rev = 'N/A'
            try:
                all_ips = list({r[4][0] for r in socket.getaddrinfo(dns_host, None)})
            except:
                all_ips = [ip]
            lines = [
                f'╔══ DNS LOOKUP ═════════════════════════════',
                f'║  Hôte     : {dns_host}',
                f'║  IP       : {ip}',
                f'║  Reverse  : {rev}',
                f'║  Toutes IPs: {", ".join(all_ips)}',
                f'╚═══════════════════════════════════════════',
            ]
            return '\n'.join(lines), ''

        elif cmd == 'ipinfo':
            ip_str = target.split(':')[0]
            try:
                addr = ipaddress.ip_address(ip_str)
            except ValueError:
                return '', f'"{ip_str}" n\'est pas une adresse IP valide (utilisez DNS Lookup pour un nom de domaine)'
            lines = [
                f'╔══ IP ANALYSER ════════════════════════════',
                f'║  IP        : {ip_str}',
                f'║  Version   : IPv{addr.version}',
                f'║  Privée    : {"Oui" if addr.is_private else "Non"}',
                f'║  Loopback  : {"Oui" if addr.is_loopback else "Non"}',
                f'║  Multicast : {"Oui" if addr.is_multicast else "Non"}',
                f'║  Globale   : {"Oui" if addr.is_global else "Non"}',
            ]
            if addr.version == 4:
                packed = addr.packed
                dec = struct.unpack('!I', packed)[0]
                lines += [
                    f'║  Décimal   : {dec}',
                    f'║  Binaire   : {".".join(format(b,"08b") for b in packed)}',
                    f'║  Hexadéc.  : 0x{packed.hex().upper()}',
                    f'║  Classe    : {_ip_class(packed[0])}',
                ]
            lines.append(f'╚═══════════════════════════════════════════')
            return '\n'.join(lines), ''

        elif cmd == 'subnet':
            try:
                net = ipaddress.ip_network(target, strict=False)
            except ValueError:
                return '', f'CIDR invalide : "{target}". Format attendu : 192.168.1.0/24'
            hosts = list(net.hosts())
            lines = [
                f'╔══ SUBNET CALCULATOR ══════════════════════',
                f'║  CIDR      : {target}',
                f'║  Réseau    : {net.network_address}',
                f'║  Broadcast : {net.broadcast_address}',
                f'║  Masque    : {net.netmask}',
                f'║  Wildcard  : {net.hostmask}',
                f'║  Préfixe   : /{net.prefixlen}',
                f'║  Nb hôtes  : {len(hosts):,}',
                f'║  1er hôte  : {hosts[0] if hosts else "N/A"}',
                f'║  Dernier   : {hosts[-1] if hosts else "N/A"}',
                f'╚═══════════════════════════════════════════',
            ]
            if hosts and len(hosts) <= 30:
                lines += ['', 'Toutes les IPs :'] + [f'  {h}' for h in hosts]
            elif hosts:
                lines += ['', f'Premières IPs :'] + [f'  {h}' for h in hosts[:10]] + [f'  ... ({len(hosts)-10} de plus)']
            return '\n'.join(lines), ''

        # ── Outils custom : exécution shell réelle ────────────────────────────
        else:
            return _run_shell_tool(tool, target, effective_options)

    except Exception as e:
        return '', f'Erreur inattendue : {str(e)}'


def _known_service(port):
    """Retourne le nom du service connu pour un port."""
    services = {
        21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS',
        80:'HTTP', 110:'POP3', 143:'IMAP', 443:'HTTPS', 445:'SMB',
        3306:'MySQL', 3389:'RDP', 5432:'PostgreSQL', 6379:'Redis',
        8080:'HTTP-Alt', 8443:'HTTPS-Alt', 27017:'MongoDB',
        6443:'Kubernetes', 9200:'Elasticsearch', 5601:'Kibana',
    }
    return services.get(port, '')


def _ip_class(first_octet):
    if first_octet < 128:   return 'A (1.0.0.0 – 127.255.255.255)'
    elif first_octet < 192: return 'B (128.0.0.0 – 191.255.255.255)'
    elif first_octet < 224: return 'C (192.0.0.0 – 223.255.255.255)'
    elif first_octet < 240: return 'D – Multicast'
    else:                   return 'E – Réservée'


def _run_shell_tool(tool, target, options):
    """
    Exécute la commande shell de l'outil custom.

    Logique de construction de la commande :
      1. Si la commande contient '{target}', on remplace directement.
         Ex : "nmap -sV {target}" → "nmap -sV 192.168.1.1"
         Puis on ajoute les options à la fin si elles sont définies.

      2. Sinon, on traite la commande comme un exécutable seul :
         Ex : commande="nmap", options="-sV -p 80,443"
         → "nmap 192.168.1.1 -sV -p 80,443"

    Timeout : 60 secondes.
    """
    import subprocess, shutil

    raw_cmd = tool['command'].strip()

    if '{target}' in raw_cmd:
        # Substitution explicite dans la commande
        full_cmd = raw_cmd.replace('{target}', target)
        if options:
            full_cmd = full_cmd + ' ' + options
    else:
        # L'outil est juste un nom d'exécutable
        full_cmd = f'{raw_cmd} {target}'
        if options:
            full_cmd += f' {options}'

    # Vérifier que l'exécutable est disponible avant de lancer
    executable = full_cmd.split()[0]
    if not shutil.which(executable):
        return '', (
            f'Outil "{executable}" introuvable sur ce système.\n\n'
            f'Pour l\'installer (selon votre OS) :\n'
            f'  Debian/Ubuntu : sudo apt install {executable}\n'
            f'  Arch          : sudo pacman -S {executable}\n'
            f'  macOS         : brew install {executable}\n\n'
            f'Après installation, relancez le scan.'
        )

    try:
        result = subprocess.run(
            full_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300
        )
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        header = (
            f'╔══ {tool["name"].upper()} ═══════════════════════════\n'
            f'║  Commande : {full_cmd}\n'
            f'║  Code de retour : {result.returncode}\n'
            f'╚════════════════════════════════════════════\n'
        )

        if result.returncode != 0 and not stdout:
            # Commande échouée sans sortie standard
            error_msg = stderr or f'La commande a retourné le code {result.returncode} sans sortie.'
            return '', f'{header}\n[STDERR]\n{error_msg}'

        output = header
        if stdout:
            output += f'\n{stdout}'
        if stderr:
            output += f'\n\n[STDERR]\n{stderr}'
        return output, ''

    except subprocess.TimeoutExpired:
        return '', f'Timeout : la commande a dépassé 5 minutes (300 secondes).\nEssayez de réduire la plage de cibles ou d\'ajouter --timeout à vos options.'
    except Exception as e:
        return '', f'Erreur d\'exécution : {str(e)}'

@app.route('/workflows')
@login_required
def workflows_page():
    return render_template('workflows.html')

@app.route('/api/workflows', methods=['GET','POST'])
@login_required
def api_workflows():
    db = get_db()
    if request.method == 'GET':
        rows = db.execute('SELECT * FROM workflows WHERE user_id=? ORDER BY id DESC', (current_user.id,)).fetchall()
        db.close(); return jsonify([dict(r) for r in rows])
    data = request.json; name = data.get('name','').strip()
    if not name or len(name) < 2 or len(name) > 80:
        db.close(); return jsonify({'error': 'Nom requis (2-80 caracteres)'}), 400
    if db.execute('SELECT id FROM workflows WHERE name=? AND user_id=?', (name, current_user.id)).fetchone():
        db.close(); return jsonify({'error': f'Un workflow nomme "{name}" existe deja'}), 409
    steps = data.get('steps', [])
    for i, step in enumerate(steps):
        if not step.get('tool_id') or not step.get('label'):
            db.close(); return jsonify({'error': f'Etape {i+1} incomplete (outil et label requis)'}), 400
    cur = db.execute('INSERT INTO workflows (user_id, name, description, steps) VALUES (?,?,?,?)',
        (current_user.id, name, data.get('description',''), json.dumps(steps)))
    db.commit(); wf_id = cur.lastrowid; db.close()
    return jsonify({'ok': True, 'id': wf_id, 'message': f'Workflow "{name}" cree'})

@app.route('/api/workflows/<int:wf_id>', methods=['GET','PUT','DELETE'])
@login_required
def api_workflow(wf_id):
    db = get_db()
    wf = db.execute('SELECT * FROM workflows WHERE id=? AND user_id=?', (wf_id, current_user.id)).fetchone()
    if not wf:
        db.close(); return jsonify({'error': 'Workflow introuvable'}), 404
    if request.method == 'GET':
        db.close(); return jsonify(dict(wf))
    if request.method == 'DELETE':
        if wf['status'] == 'running':
            db.close(); return jsonify({'error': "Impossible de supprimer un workflow en cours d'execution"}), 409
        db.execute('DELETE FROM workflows WHERE id=?', (wf_id,))
        db.execute('DELETE FROM workflow_runs WHERE workflow_id=?', (wf_id,))
        db.commit(); db.close(); return jsonify({'ok': True, 'message': 'Workflow supprime'})
    if request.method == 'PUT':
        if wf['status'] == 'running':
            db.close(); return jsonify({'error': "Impossible de modifier un workflow en cours d'execution"}), 409
        data = request.json; name = data.get('name', wf['name']).strip()
        steps = data.get('steps', json.loads(wf['steps']))
        for i, step in enumerate(steps):
            if not step.get('tool_id') or not step.get('label'):
                db.close(); return jsonify({'error': f'Etape {i+1} incomplete'}), 400
        db.execute('UPDATE workflows SET name=?, description=?, steps=? WHERE id=?',
            (name, data.get('description', wf['description']), json.dumps(steps), wf_id))
        db.commit(); db.close(); return jsonify({'ok': True, 'message': f'Workflow "{name}" mis a jour'})

@app.route('/api/workflows/<int:wf_id>/run', methods=['POST'])
@login_required
@tech_required
def api_workflow_run(wf_id):
    db = get_db()
    wf = db.execute('SELECT * FROM workflows WHERE id=? AND user_id=?', (wf_id, current_user.id)).fetchone()
    if not wf:
        db.close(); return jsonify({'error': 'Workflow introuvable'}), 404
    if wf['status'] == 'running':
        db.close(); return jsonify({'error': "Ce workflow est deja en cours d'execution"}), 409
    target = request.json.get('target','').strip()
    if not target:
        db.close(); return jsonify({'error': 'Cible requise'}), 400
    steps = json.loads(wf['steps'])
    if not steps:
        db.close(); return jsonify({'error': "Ce workflow ne contient aucune etape"}), 400
    cur = db.execute('INSERT INTO workflow_runs (workflow_id, user_id, target, status, current_step, total_steps, results) VALUES (?,?,?,?,?,?,?)',
        (wf_id, current_user.id, target, 'running', 0, len(steps), json.dumps([])))
    db.execute('UPDATE workflows SET status=? WHERE id=?', ('running', wf_id))
    db.commit(); run_id = cur.lastrowid
    uid = current_user.id; wf_name = wf['name']; db.close()
    def run_wf(wf_id, run_id, steps, target, user_id, wf_name):
        results = []
        for i, step in enumerate(steps):
            db2 = get_db()
            db2.execute('UPDATE workflow_runs SET current_step=? WHERE id=?', (i+1, run_id)); db2.commit()
            tool = db2.execute('SELECT * FROM scan_tools WHERE id=?', (step['tool_id'],)).fetchone(); db2.close()
            if not tool:
                results.append({'step':i+1,'label':step.get('label'),'status':'failed','output':'','error':'Outil introuvable'}); break
            out, err = execute_tool(dict(tool), target, step.get('options',''))
            results.append({'step':i+1,'label':step.get('label'),'tool':tool['name'],'status':'failed' if err else 'completed','output':out,'error':err})
            db3 = get_db(); db3.execute('UPDATE workflow_runs SET results=? WHERE id=?', (json.dumps(results), run_id)); db3.commit(); db3.close()
            if err: break
        overall = 'completed' if all(r['status']=='completed' for r in results) else 'failed'
        db4 = get_db()
        db4.execute('UPDATE workflow_runs SET status=?, results=?, finished_at=?, current_step=? WHERE id=?',
            (overall, json.dumps(results), datetime.now().isoformat(), len(steps), run_id))
        db4.execute('UPDATE workflows SET status=? WHERE id=?', ('idle', wf_id))
        result_lines = []
        for r in results:
            icon = '✓' if r['status'] == 'completed' else '✗'
            excerpt = (r.get('output') or r.get('error') or '').strip()[:600]
            result_lines.append(f"{icon} Étape {r['step']} [{r.get('tool', r.get('label', ''))}]\n{excerpt}")
        history_output = f"Statut global : {overall} | {len(results)} étape(s)\n\n" + "\n\n".join(result_lines)
        db4.execute('INSERT INTO history (user_id, tool, input, output) VALUES (?,?,?,?)',
            (user_id, f'Workflow: {wf_name}', target, history_output[:8000]))
        db4.commit(); db4.close()
    t = threading.Thread(target=run_wf, args=(wf_id, run_id, steps, target, uid, wf_name))
    t.daemon = True; t.start()
    return jsonify({'ok': True, 'run_id': run_id, 'message': f'Workflow lance sur {target}'})

@app.route('/api/workflows/runs/<int:run_id>')
@login_required
def api_run_status(run_id):
    db = get_db()
    run = db.execute('SELECT * FROM workflow_runs WHERE id=? AND user_id=?', (run_id, current_user.id)).fetchone()
    db.close()
    if not run: return jsonify({'error': 'Run introuvable'}), 404
    d = dict(run); d['results'] = json.loads(d['results'] or '[]'); return jsonify(d)

@app.route('/api/workflows/<int:wf_id>/runs')
@login_required
def api_workflow_runs(wf_id):
    db = get_db()
    runs = db.execute('SELECT * FROM workflow_runs WHERE workflow_id=? AND user_id=? ORDER BY id DESC LIMIT 10', (wf_id, current_user.id)).fetchall()
    db.close()
    result = []
    for r in runs:
        d = dict(r); d['results'] = json.loads(d['results'] or '[]'); result.append(d)
    return jsonify(result)

@app.route('/history')
@login_required
def history_page():
    return render_template('history.html')

@app.route('/api/history')
@login_required
def api_history():
    page=int(request.args.get('page',1)); per_page=20
    tool_f=request.args.get('tool',''); date_f=request.args.get('date',''); search_f=request.args.get('search','')
    query='SELECT * FROM history WHERE user_id=?'; params=[current_user.id]
    if tool_f:   query+=' AND tool=?';                  params.append(tool_f)
    if date_f:   query+=' AND created_at LIKE ?';       params.append(f'{date_f}%')
    if search_f: query+=' AND (tool LIKE ? OR input LIKE ?)'; params+=[f'%{search_f}%',f'%{search_f}%']
    db=get_db()
    total=db.execute(query.replace('SELECT *','SELECT COUNT(*)'),params).fetchone()[0]
    rows=db.execute(query+' ORDER BY id DESC LIMIT ? OFFSET ?',params+[per_page,(page-1)*per_page]).fetchall()
    tools=db.execute('SELECT DISTINCT tool FROM history WHERE user_id=?',(current_user.id,)).fetchall()
    db.close()
    return jsonify({'items':[dict(r) for r in rows],'total':total,'page':page,'pages':(total+per_page-1)//per_page,'tools':[t['tool'] for t in tools]})

@app.route('/api/history/<int:hid>', methods=['DELETE'])
@login_required
def api_history_delete(hid):
    db=get_db(); db.execute('DELETE FROM history WHERE id=? AND user_id=?',(hid,current_user.id)); db.commit(); db.close()
    return jsonify({'ok':True})

@app.route('/api/encode', methods=['POST'])
@login_required
def api_encode():
    data=request.json; text=data.get('text',''); mode=data.get('mode','base64_encode')
    try:
        if mode=='base64_encode':   result=base64.b64encode(text.encode()).decode()
        elif mode=='base64_decode': result=base64.b64decode(text.encode()).decode()
        elif mode=='url_encode':    result=urllib.parse.quote(text)
        elif mode=='url_decode':    result=urllib.parse.unquote(text)
        elif mode=='hex_encode':    result=text.encode().hex()
        elif mode=='hex_decode':    result=bytes.fromhex(text).decode()
        elif mode=='html_encode':   result=html.escape(text)
        elif mode=='html_decode':   result=html.unescape(text)
        elif mode=='rot13':         result=text.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz','NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'))
        elif mode=='binary_encode': result=' '.join(format(ord(c),'08b') for c in text)
        elif mode=='binary_decode': result=''.join(chr(int(b,2)) for b in text.split())
        else: result='Mode inconnu'
        save_history('Encoder',f'{mode}: {text[:50]}',result[:200]); return jsonify({'result':result})
    except Exception as e: return jsonify({'error':str(e)}),400

@app.route('/api/hash', methods=['POST'])
@login_required
def api_hash():
    data=request.json; text=data.get('text',''); results={}
    for algo in ['md5','sha1','sha224','sha256','sha384','sha512']:
        h=hashlib.new(algo); h.update(text.encode()); results[algo]=h.hexdigest()
    save_history('Hasher',text[:50],json.dumps(results)[:300]); return jsonify({'results':results})

@app.route('/api/dns', methods=['POST'])
@login_required
def api_dns():
    data=request.json; host=data.get('host','').strip()
    if not re.match(r'^[a-zA-Z0-9.\-]+$',host): return jsonify({'error':'Hote invalide'}),400
    try:
        ip=socket.gethostbyname(host)
        try: hostname=socket.gethostbyaddr(ip)[0]
        except: hostname='N/A'
        save_history('DNS Lookup',host,f'{ip} / {hostname}'); return jsonify({'host':host,'ip':ip,'reverse':hostname})
    except Exception as e: return jsonify({'error':str(e)}),400

@app.route('/api/portscan', methods=['POST'])
@login_required
def api_portscan():
    data=request.json; host=data.get('host','').strip(); ports_input=data.get('ports','22,80,443,8080,3306,5432,6379,27017')
    if not re.match(r'^[a-zA-Z0-9.\-]+$',host): return jsonify({'error':'Hote invalide'}),400
    try:
        ip=socket.gethostbyname(host); ports=[int(p.strip()) for p in ports_input.split(',') if p.strip().isdigit()][:30]; results=[]
        for port in ports:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(0.5); open_=s.connect_ex((ip,port))==0; s.close()
            results.append({'port':port,'open':open_})
        save_history('Port Scanner',f'{host}:{ports_input}',str([r for r in results if r['open']])); return jsonify({'host':host,'ip':ip,'results':results})
    except Exception as e: return jsonify({'error':str(e)}),400

@app.route('/api/ipinfo', methods=['POST'])
@login_required
def api_ipinfo():
    data=request.json; ip=data.get('ip','').strip()
    try:
        addr=ipaddress.ip_address(ip)
        info={'ip':ip,'version':f'IPv{addr.version}','is_private':addr.is_private,'is_loopback':addr.is_loopback,'is_multicast':addr.is_multicast,'compressed':addr.compressed}
        if addr.version==4:
            packed=addr.packed; info.update({'octets':list(packed),'decimal':struct.unpack('!I',packed)[0],'binary':'.'.join(format(b,'08b') for b in packed),'hex':'0x'+packed.hex()})
        save_history('IP Info',ip,json.dumps(info)); return jsonify(info)
    except Exception as e: return jsonify({'error':str(e)}),400

@app.route('/api/regex', methods=['POST'])
@login_required
def api_regex():
    data=request.json; pattern,text,flags_str=data.get('pattern',''),data.get('text',''),data.get('flags','')
    flags=0
    if 'i' in flags_str: flags|=re.IGNORECASE
    if 'm' in flags_str: flags|=re.MULTILINE
    if 's' in flags_str: flags|=re.DOTALL
    try:
        matches=[{'match':m.group(),'groups':list(m.groups()),'start':m.start(),'end':m.end()} for m in re.compile(pattern,flags).finditer(text)]
        save_history('Regex',f'/{pattern}/{flags_str}',f'{len(matches)} matches'); return jsonify({'matches':matches,'count':len(matches)})
    except re.error as e: return jsonify({'error':str(e)}),400

@app.route('/api/caesar', methods=['POST'])
@login_required
def api_caesar():
    data=request.json; text,shift=data.get('text',''),int(data.get('shift',3))%26
    def st(t,s):
        r=''
        for c in t:
            if c.isalpha(): base=ord('A') if c.isupper() else ord('a'); r+=chr((ord(c)-base+s)%26+base)
            else: r+=c
        return r
    result=st(text,shift); brute=[{'shift':s,'text':st(text,s)} for s in range(1,26)]
    save_history('Cesar',f'shift={shift}: {text[:40]}',result[:100]); return jsonify({'result':result,'brute':brute})

@app.route('/api/xor', methods=['POST'])
@login_required
def api_xor():
    data=request.json; text,key=data.get('text',''),data.get('key','')
    input_format=data.get('input_format','text')
    if not key: return jsonify({'error':'Clé requise'}),400
    if input_format=='hex':
        try: input_bytes=bytes.fromhex(text.replace(' ',''))
        except ValueError: return jsonify({'error':'Format hexadécimal invalide (ex: 0a1b2c...)'}),400
    else:
        input_bytes=text.encode('utf-8')
    rb=bytes([b^ord(key[i%len(key)]) for i,b in enumerate(input_bytes)])
    try: decoded=rb.decode('utf-8')
    except: decoded=None
    result={'hex':rb.hex(),'base64':base64.b64encode(rb).decode()}
    if decoded is not None: result['text']=decoded
    save_history('XOR',f'key={key}: {text[:40]}',rb.hex()[:100]); return jsonify(result)

@app.route('/api/passgen', methods=['POST'])
@login_required
def api_passgen():
    import secrets,string
    data=request.json; length=min(int(data.get('length',16)),128); charset=''
    if data.get('upper',True): charset+=string.ascii_uppercase
    if data.get('lower',True): charset+=string.ascii_lowercase
    if data.get('digits',True): charset+=string.digits
    if data.get('special',True): charset+='!@#$%^&*()_+-=[]{}|;:,.<>?'
    if not charset: charset=string.ascii_letters
    return jsonify({'passwords':[''.join(secrets.choice(charset) for _ in range(length)) for _ in range(5)],'entropy_bits':round(length*len(charset).bit_length(),1),'charset_size':len(charset)})

@app.route('/api/subnet', methods=['POST'])
@login_required
def api_subnet():
    data=request.json
    try:
        net=ipaddress.ip_network(data.get('cidr','').strip(),strict=False); hosts=list(net.hosts())
        info={'network':str(net.network_address),'broadcast':str(net.broadcast_address),'netmask':str(net.netmask),'prefix':net.prefixlen,'num_hosts':len(hosts),'first_host':str(hosts[0]) if hosts else 'N/A','last_host':str(hosts[-1]) if hosts else 'N/A','hosts_list':[str(h) for h in hosts[:20]]}
        save_history('Subnet',data.get('cidr',''),f'Hosts: {info["num_hosts"]}'); return jsonify(info)
    except Exception as e: return jsonify({'error':str(e)}),400

@app.route('/api/notes', methods=['GET','POST','DELETE'])
@login_required
def api_notes():
    db=get_db()
    if request.method=='GET':
        notes=db.execute('SELECT * FROM notes WHERE user_id=? ORDER BY id DESC',(current_user.id,)).fetchall(); db.close(); return jsonify([dict(n) for n in notes])
    elif request.method=='POST':
        data=request.json; db.execute('INSERT INTO notes (user_id,title,content) VALUES (?,?,?)',(current_user.id,data.get('title',''),data.get('content',''))); db.commit(); db.close(); return jsonify({'ok':True})
    elif request.method=='DELETE':
        db.execute('DELETE FROM notes WHERE id=? AND user_id=?',(request.json.get('id'),current_user.id)); db.commit(); db.close(); return jsonify({'ok':True})

@app.route('/report')
@login_required
def report_page():
    db = get_db()
    targets = db.execute(
        'SELECT DISTINCT target FROM scans WHERE user_id=? ORDER BY target',
        (current_user.id,)
    ).fetchall()
    db.close()
    return render_template('report.html', targets=[t['target'] for t in targets])


@app.route('/api/report/pdf', methods=['POST'])
@login_required
def api_report_pdf():
    data = request.get_json(silent=True) or {}
    scope         = data.get('scope', 'all')
    target_filter = (data.get('target') or '').strip() or None
    date_from     = (data.get('date_from') or '').strip() or None  # format YYYY-MM-DD
    date_to       = (data.get('date_to')   or '').strip() or None  # format YYYY-MM-DD

    db = get_db()

    # Construction des filtres date pour les requêtes SQL
    def _date_clause(col):
        clauses, params = [], []
        if date_from:
            clauses.append(f"{col} >= ?"); params.append(date_from)
        if date_to:
            clauses.append(f"{col} <= ?"); params.append(date_to + 'T23:59:59')
        return (' AND ' + ' AND '.join(clauses)) if clauses else '', params

    sc_clause, sc_params = _date_clause('created_at')
    scans = [dict(r) for r in db.execute(
        f'SELECT * FROM scans WHERE user_id=?{sc_clause} ORDER BY id DESC',
        [current_user.id] + sc_params
    ).fetchall()]

    wr_clause, wr_params = _date_clause('workflow_runs.started_at')
    runs_raw = db.execute(
        f'''SELECT workflow_runs.*, workflows.name AS wf_name
            FROM workflow_runs
            JOIN workflows ON workflows.id = workflow_runs.workflow_id
            WHERE workflow_runs.user_id=?{wr_clause}
            ORDER BY workflow_runs.id DESC''',
        [current_user.id] + wr_params
    ).fetchall()
    workflow_runs = [dict(r) for r in runs_raw]

    hi_clause, hi_params = _date_clause('created_at')
    history = [dict(r) for r in db.execute(
        f'SELECT * FROM history WHERE user_id=?{hi_clause} ORDER BY id DESC LIMIT 500',
        [current_user.id] + hi_params
    ).fetchall()]

    notes = [dict(r) for r in db.execute(
        'SELECT * FROM notes WHERE user_id=? ORDER BY id DESC', (current_user.id,)
    ).fetchall()]
    db.close()

    if not scans and not workflow_runs and not history:
        return jsonify({'error': 'Aucune donnée disponible pour les filtres sélectionnés.'}), 400

    pdf_buffer = generate_pdf_report(
        username=current_user.username,
        scans=scans,
        workflow_runs=workflow_runs,
        history=history,
        notes=notes,
        scope=scope,
        target_filter=target_filter,
        date_from=date_from,
        date_to=date_to,
    )
    filename = f'rapport_acmd_{current_user.username}_{datetime.now().strftime("%Y%m%d_%H%M")}.pdf'
    return send_file(pdf_buffer, mimetype='application/pdf', as_attachment=True, download_name=filename)


@app.route('/admin')
@login_required
@admin_required
def admin_page():
    db = get_db()
    users = db.execute('SELECT id, username, role, active, created_at FROM users ORDER BY id').fetchall()
    db.close()
    return render_template('admin.html', users=users)


@app.route('/api/admin/users/<int:user_id>/role', methods=['PUT'])
@login_required
@admin_required
def api_admin_set_role(user_id):
    role = (request.json or {}).get('role', '').strip()
    if role not in ('admin', 'tech', 'user'):
        return jsonify({'error': 'Rôle invalide (admin, tech, user)'}), 400
    if user_id == current_user.id and role != 'admin':
        return jsonify({'error': 'Vous ne pouvez pas retirer votre propre rôle admin'}), 400
    db = get_db()
    target = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not target:
        db.close(); return jsonify({'error': 'Utilisateur introuvable'}), 404
    db.execute('UPDATE users SET role=? WHERE id=?', (role, user_id))
    db.commit(); db.close()
    return jsonify({'ok': True, 'message': f'Rôle de {target["username"]} mis à jour : {role}'})


@app.route('/api/admin/users/<int:user_id>/active', methods=['PUT'])
@login_required
@admin_required
def api_admin_set_active(user_id):
    active = 1 if (request.json or {}).get('active', True) else 0
    if user_id == current_user.id and not active:
        return jsonify({'error': 'Vous ne pouvez pas désactiver votre propre compte'}), 400
    db = get_db()
    target = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not target:
        db.close(); return jsonify({'error': 'Utilisateur introuvable'}), 404
    db.execute('UPDATE users SET active=? WHERE id=?', (active, user_id))
    db.commit(); db.close()
    state = 'activé' if active else 'désactivé'
    return jsonify({'ok': True, 'message': f'Compte {target["username"]} {state}'})


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
@admin_required
def api_admin_delete_user(user_id):
    if user_id == current_user.id:
        return jsonify({'error': 'Vous ne pouvez pas supprimer votre propre compte'}), 400
    db = get_db()
    target = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
    if not target:
        db.close(); return jsonify({'error': 'Utilisateur introuvable'}), 404
    db.execute('DELETE FROM users WHERE id=?', (user_id,))
    for table in ('history', 'notes', 'scans', 'workflows', 'workflow_runs', 'scan_tools'):
        db.execute(f'DELETE FROM {table} WHERE user_id=?', (user_id,))
    db.commit(); db.close()
    return jsonify({'ok': True, 'message': f'Compte {target["username"]} supprimé'})


@app.route('/api/admin/settings', methods=['GET', 'PUT'])
@login_required
@admin_required
def api_admin_settings():
    db = get_db()
    if request.method == 'GET':
        rows = db.execute("SELECT key, value FROM settings").fetchall()
        db.close()
        return jsonify({r['key']: r['value'] for r in rows})
    data = request.json or {}
    allowed_keys = {'registration_open'}
    for key, value in data.items():
        if key in allowed_keys:
            db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?,?)", (key, str(value)))
    db.commit(); db.close()
    return jsonify({'ok': True, 'message': 'Paramètres mis à jour'})


@app.route('/api/admin/stats', methods=['GET'])
@login_required
@admin_required
def api_admin_stats():
    db = get_db()
    stats = {
        'total':  db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        'admin':  db.execute("SELECT COUNT(*) FROM users WHERE role='admin'").fetchone()[0],
        'tech':   db.execute("SELECT COUNT(*) FROM users WHERE role='tech'").fetchone()[0],
        'user':   db.execute("SELECT COUNT(*) FROM users WHERE role='user'").fetchone()[0],
        'active': db.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0],
    }
    db.close()
    return jsonify(stats)


@app.errorhandler(403)
def forbidden(_):
    flash("Accès refusé : votre rôle ne permet pas cette action.")
    return redirect(url_for('dashboard')), 403


if __name__ == '__main__':
    app.run(debug=True, threaded=True)

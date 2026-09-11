import os, sqlite3, secrets, base64, ipaddress, subprocess, shutil, threading, time
from io import BytesIO
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, render_template, request, redirect, session, url_for, send_file, Response, flash, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
import qrcode

APP_PORT = int(os.environ.get('PORT') or os.environ.get('APP_PORT') or 5000)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')
SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
DATA_DIR = os.environ.get('DATA_DIR', '/data')
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.environ.get('DB_PATH', os.path.join(DATA_DIR, 'wgpanel.db'))
WG_INTERFACE = os.environ.get('WG_INTERFACE', 'wg0')
WG_CONF = os.environ.get('WG_CONF', f'/etc/wireguard/{WG_INTERFACE}.conf')
DEFAULT_SUBNET = os.environ.get('WG_SUBNET', '10.66.66.0/24')
DEFAULT_DNS = os.environ.get('WG_DNS', '1.1.1.1')
DEFAULT_PORT = int(os.environ.get('WG_PORT', '51820'))

app = Flask(__name__, template_folder=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates'))
app.secret_key = SECRET_KEY


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    return conn


def init_db():
    conn = db()
    conn.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        public_key TEXT NOT NULL UNIQUE,
        private_key TEXT NOT NULL,
        address TEXT NOT NULL UNIQUE,
        dns TEXT NOT NULL,
        allowed_ips TEXT NOT NULL DEFAULT '0.0.0.0/0, ::/0',
        created_at TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        quota_gb INTEGER NOT NULL DEFAULT 0,
        expires_at TEXT
    )''')
    defaults = {
        'server_name': os.environ.get('WG_SERVER_NAME', 'WireGuard Server'),
        'endpoint': os.environ.get('WG_ENDPOINT', ''),
        'subnet': DEFAULT_SUBNET,
        'dns': DEFAULT_DNS,
        'listen_port': str(DEFAULT_PORT),
        'server_private_key': '',
        'server_public_key': '',
        'next_host': '2',
    }
    for k, v in defaults.items():
        conn.execute('INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)', (k, v))
    # Backward-compatible migration for existing databases
    cols = {r['name'] for r in conn.execute('PRAGMA table_info(clients)').fetchall()}
    if 'expires_at' not in cols:
        conn.execute('ALTER TABLE clients ADD COLUMN expires_at TEXT')
    conn.commit(); conn.close()


def setting(k):
    row = db().execute('SELECT value FROM settings WHERE key=?', (k,)).fetchone()
    return row['value'] if row else ''


def set_setting(k, v):
    conn = db(); conn.execute('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (k, str(v))); conn.commit(); conn.close()


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get('logged_in'): return redirect(url_for('login'))
        return fn(*a, **kw)
    return wrapper


def cmd(*args, input_text=None, check=True):
    return subprocess.run(args, input=input_text, text=True, capture_output=True, check=check, timeout=20)


def wg_available():
    return shutil.which('wg') is not None and shutil.which('wg-quick') is not None


def generate_wg_keypair():
    if wg_available():
        priv = cmd('wg', 'genkey').stdout.strip()
        pub = cmd('wg', 'pubkey', input_text=priv + '\n').stdout.strip()
        return priv, pub
    # Fallback only for config generation; actual tunnel management requires wg-tools.
    raw = secrets.token_bytes(32)
    raw = bytearray(raw); raw[0] &= 248; raw[31] &= 127; raw[31] |= 64
    priv = base64.b64encode(bytes(raw)).decode()
    # No safe public derivation without Curve25519 implementation; PyNaCl is not required here.
    raise RuntimeError('wireguard-tools is not installed')


def ensure_server_keys():
    if setting('server_private_key') and setting('server_public_key'): return
    priv, pub = generate_wg_keypair()
    set_setting('server_private_key', priv); set_setting('server_public_key', pub)


def next_address():
    conn = db(); net = ipaddress.ip_network(setting('subnet'), strict=False)
    n = int(setting('next_host') or 2)
    used = {r['address'].split('/')[0] for r in conn.execute('SELECT address FROM clients')}
    for host in net.hosts():
        if int(host) < n: continue
        if str(host) not in used:
            conn.execute('UPDATE settings SET value=? WHERE key=?', (str(int(host)+1), 'next_host')); conn.commit(); conn.close(); return str(host)
    conn.close(); raise RuntimeError('No free addresses in WireGuard subnet')


def is_expired(expires_at):
    if not expires_at:
        return False
    try:
        dt = datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt <= datetime.now(timezone.utc)
    except Exception:
        return True


def enforce_expiry():
    conn = db()
    rows = conn.execute("SELECT id, expires_at, enabled FROM clients WHERE expires_at IS NOT NULL AND enabled=1").fetchall()
    changed = False
    for r in rows:
        if is_expired(r['expires_at']):
            conn.execute('UPDATE clients SET enabled=0 WHERE id=?', (r['id'],))
            changed = True
    conn.commit(); conn.close()
    if changed:
        apply_wireguard()
    return changed


def expiry_worker():
    while True:
        try:
            enforce_expiry()
        except Exception:
            pass
        time.sleep(30)


def render_server_conf():
    subnet = ipaddress.ip_network(setting('subnet'), strict=False)
    lines = [
        '[Interface]',
        f"Address = {subnet.network_address + 1}/{subnet.prefixlen}",
        f"ListenPort = {setting('listen_port')}",
        f"PrivateKey = {setting('server_private_key')}",
        '',
    ]
    conn = db(); clients = conn.execute('SELECT * FROM clients WHERE enabled=1 ORDER BY id').fetchall(); conn.close()
    for c in clients:
        lines += ['[Peer]', f"PublicKey = {c['public_key']}", f"AllowedIPs = {c['address']}/32", '']
    return '\n'.join(lines) + '\n'


def apply_wireguard():
    if not wg_available(): return False, 'wireguard-tools در این کانتینر نصب نیست.'
    os.makedirs('/etc/wireguard', exist_ok=True)
    conf = render_server_conf()
    tmp = WG_CONF + '.tmp'
    with open(tmp, 'w') as f: f.write(conf)
    os.chmod(tmp, 0o600); os.replace(tmp, WG_CONF)
    try:
        cmd('wg-quick', 'down', WG_INTERFACE, check=False)
        r = cmd('wg-quick', 'up', WG_INTERFACE, check=False)
        if r.returncode != 0: return False, (r.stderr or r.stdout).strip()
        return True, 'WireGuard فعال شد.'
    except Exception as e:
        return False, str(e)


def wg_status():
    if not wg_available(): return {'available': False, 'error': 'wg command unavailable'}
    r = cmd('wg', 'show', check=False)
    return {'available': True, 'running': r.returncode == 0, 'text': r.stdout if r.returncode == 0 else r.stderr}


# Initialize DB and background expiry enforcement on both Flask-dev and Gunicorn startup.
try:
    init_db()
    try:
        ensure_server_keys()
    except Exception:
        pass
    if not any(t.name == 'wireguard-expiry-worker' for t in threading.enumerate()):
        threading.Thread(target=expiry_worker, daemon=True, name='wireguard-expiry-worker').start()
except Exception:
    pass


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        u, p = request.form.get('username',''), request.form.get('password','')
        valid = False
        if u == ADMIN_USERNAME:
            if ADMIN_PASSWORD.startswith(('pbkdf2:', 'scrypt:')):
                try:
                    valid = check_password_hash(ADMIN_PASSWORD, p)
                except Exception:
                    valid = False
            else:
                valid = secrets.compare_digest(p, ADMIN_PASSWORD)
        if valid:
            session['logged_in'] = True
            return redirect(url_for('dashboard'))
        flash('نام کاربری یا رمز اشتباه است')
    return render_template('login.html')

@app.route('/logout')
def logout(): session.clear(); return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    conn = db(); clients = conn.execute('SELECT * FROM clients ORDER BY id DESC').fetchall(); conn.close()
    st = wg_status(); return render_template('dashboard.html', now_iso=datetime.now(timezone.utc).isoformat(), clients=clients, settings={k:setting(k) for k in ['server_name','endpoint','subnet','dns','listen_port','server_public_key']}, status=st)

@app.route('/settings', methods=['POST'])
@login_required
def settings_save():
    for k in ['server_name','endpoint','subnet','dns','listen_port']:
        v = request.form.get(k,'').strip()
        if v: set_setting(k,v)
    try: ipaddress.ip_network(setting('subnet'), strict=False)
    except ValueError: flash('Subnet نامعتبر است'); return redirect(url_for('dashboard'))
    ok,msg = apply_wireguard(); flash(msg)
    return redirect(url_for('dashboard'))

@app.route('/server/install', methods=['POST'])
@login_required
def server_install():
    try:
        ensure_server_keys(); ok,msg = apply_wireguard(); flash(msg)
    except Exception as e: flash('نصب/راه‌اندازی ناموفق: ' + str(e))
    return redirect(url_for('dashboard'))

@app.route('/clients/add', methods=['POST'])
@login_required
def add_client():
    try:
        ensure_server_keys(); priv,pub = generate_wg_keypair(); addr = next_address()
        name = request.form.get('name','').strip() or f'client-{secrets.token_hex(3)}'
        expiry = (request.form.get('expires_at') or '').strip()
        expires_at = None
        if expiry:
            dt = datetime.fromisoformat(expiry)
            if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
            if dt <= datetime.now(timezone.utc): raise ValueError('تاریخ انقضا باید در آینده باشد')
            expires_at = dt.astimezone(timezone.utc).isoformat()
        conn=db(); conn.execute('INSERT INTO clients(name,public_key,private_key,address,dns,created_at,quota_gb,expires_at) VALUES(?,?,?,?,?,?,?,?)', (name,pub,priv,addr,request.form.get('dns') or setting('dns'),datetime.now(timezone.utc).isoformat(),int(request.form.get('quota_gb') or 0),expires_at)); conn.commit(); conn.close()
        ok,msg=apply_wireguard(); flash('کاربر ساخته شد و به WireGuard اضافه شد.' if ok else 'کاربر ساخته شد ولی اعمال WireGuard شکست خورد: '+msg)
    except Exception as e: flash('خطا: '+str(e))
    return redirect(url_for('dashboard'))

@app.route('/clients/<int:client_id>/toggle', methods=['POST'])
@login_required
def toggle_client(client_id):
    c=get_client(client_id)
    if not c: return 'not found',404
    if not c['enabled'] and is_expired(c['expires_at']):
        flash('این کاربر منقضی شده است؛ ابتدا تاریخ انقضا را تمدید کنید.')
        return redirect(url_for('dashboard'))
    conn=db(); conn.execute('UPDATE clients SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END WHERE id=?',(client_id,)); conn.commit(); conn.close(); ok,msg=apply_wireguard(); flash(msg); return redirect(url_for('dashboard'))

@app.route('/clients/<int:client_id>/renew', methods=['POST'])
@login_required
def renew_client(client_id):
    c=get_client(client_id)
    if not c: return 'not found',404
    try:
        expiry=request.form.get('expires_at','').strip()
        dt=datetime.fromisoformat(expiry)
        if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
        if dt <= datetime.now(timezone.utc): raise ValueError
        conn=db(); conn.execute('UPDATE clients SET expires_at=?, enabled=1 WHERE id=?',(dt.astimezone(timezone.utc).isoformat(),client_id)); conn.commit(); conn.close()
        ok,msg=apply_wireguard(); flash('تاریخ انقضا تمدید و کاربر فعال شد.' if ok else 'تاریخ تمدید شد ولی اعمال WireGuard شکست خورد: '+msg)
    except Exception:
        flash('تاریخ انقضا نامعتبر است.')
    return redirect(url_for('dashboard'))


@app.route('/clients/<int:client_id>/delete', methods=['POST'])
@login_required
def delete_client(client_id):
    conn=db(); conn.execute('DELETE FROM clients WHERE id=?',(client_id,)); conn.commit(); conn.close(); apply_wireguard(); flash('کاربر حذف شد'); return redirect(url_for('dashboard'))


def get_client(cid):
    conn=db(); c=conn.execute('SELECT * FROM clients WHERE id=?',(cid,)).fetchone(); conn.close(); return c


def client_conf(c):
    subnet=ipaddress.ip_network(setting('subnet'), strict=False)
    return f'''[Interface]\nPrivateKey = {c['private_key']}\nAddress = {c['address']}/{subnet.prefixlen}\nDNS = {c['dns']}\n\n[Peer]\nPublicKey = {setting('server_public_key')}\nEndpoint = {setting('endpoint')}:{setting('listen_port')}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n'''

@app.route('/clients/<int:client_id>/conf')
@login_required
def conf(client_id):
    c=get_client(client_id)
    if not c: return 'not found',404
    return Response(client_conf(c),mimetype='text/plain',headers={'Content-Disposition':f"attachment; filename={c['name']}.conf"})

@app.route('/clients/<int:client_id>/qr.png')
@login_required
def qr(client_id):
    c=get_client(client_id)
    if not c:return 'not found',404
    img=qrcode.make(client_conf(c)); b=BytesIO(); img.save(b,'PNG'); b.seek(0); return send_file(b,mimetype='image/png')

@app.route('/sub/<token>')
def sub(token): return 'Subscriptions are disabled in this build',404

@app.route('/api/status')
@login_required
def api_status():
    enforce_expiry()
    return jsonify(wg_status())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=APP_PORT)

import sqlite3
import secrets
import string
import hashlib
import base64
from flask import Flask, render_template, request, redirect, url_for, session, flash
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
DB = 'passwords.db'

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS master (
                id INTEGER PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                url TEXT,
                notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        ''')

def derive_key(master_password, salt_hex):
    salt = bytes.fromhex(salt_hex)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def hash_master(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 480000).hex()

def encrypt(plain, key):
    return Fernet(key).encrypt(plain.encode()).decode()

def decrypt(encrypted, key):
    return Fernet(key).decrypt(encrypted.encode()).decode()

def get_key():
    mp = session.get('master_password')
    salt = session.get('salt')
    if mp and salt:
        return derive_key(mp, salt)
    return None

@app.route('/')
def index():
    with get_db() as conn:
        master = conn.execute('SELECT * FROM master').fetchone()
    if not master:
        return redirect(url_for('setup'))
    if not session.get('unlocked'):
        return redirect(url_for('unlock'))
    return redirect(url_for('vault'))

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if request.method == 'POST':
        pw = request.form['password']
        confirm = request.form['confirm']
        if len(pw) < 8:
            return render_template('setup.html', error='Password must be at least 8 characters.')
        if pw != confirm:
            return render_template('setup.html', error='Passwords do not match.')
        salt = secrets.token_hex(16)
        with get_db() as conn:
            conn.execute('INSERT INTO master (password_hash, salt) VALUES (?,?)', (hash_master(pw, salt), salt))
        return redirect(url_for('unlock'))
    return render_template('setup.html')

@app.route('/unlock', methods=['GET', 'POST'])
def unlock():
    with get_db() as conn:
        master = conn.execute('SELECT * FROM master').fetchone()
    if not master:
        return redirect(url_for('setup'))
    if request.method == 'POST':
        pw = request.form['password']
        if hash_master(pw, master['salt']) == master['password_hash']:
            session['unlocked'] = True
            session['master_password'] = pw
            session['salt'] = master['salt']
            return redirect(url_for('vault'))
        return render_template('unlock.html', error='Wrong password.')
    return render_template('unlock.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('unlock'))

@app.route('/vault')
def vault():
    if not session.get('unlocked'):
        return redirect(url_for('unlock'))
    q = request.args.get('q', '')
    with get_db() as conn:
        if q:
            entries = conn.execute(
                'SELECT * FROM passwords WHERE site LIKE ? OR username LIKE ? ORDER BY site',
                (f'%{q}%', f'%{q}%')).fetchall()
        else:
            entries = conn.execute('SELECT * FROM passwords ORDER BY site').fetchall()
    return render_template('vault.html', entries=entries, q=q)

@app.route('/add', methods=['GET', 'POST'])
def add():
    if not session.get('unlocked'):
        return redirect(url_for('unlock'))
    if request.method == 'POST':
        key = get_key()
        with get_db() as conn:
            conn.execute(
                'INSERT INTO passwords (site, username, password, url, notes) VALUES (?,?,?,?,?)',
                (request.form['site'], request.form['username'],
                 encrypt(request.form['password'], key),
                 request.form.get('url', ''), request.form.get('notes', '')))
        flash('Password saved.')
        return redirect(url_for('vault'))
    return render_template('form.html', entry=None, pwd='')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    if not session.get('unlocked'):
        return redirect(url_for('unlock'))
    with get_db() as conn:
        entry = conn.execute('SELECT * FROM passwords WHERE id=?', (id,)).fetchone()
    if not entry:
        return redirect(url_for('vault'))
    if request.method == 'POST':
        key = get_key()
        with get_db() as conn:
            conn.execute(
                'UPDATE passwords SET site=?,username=?,password=?,url=?,notes=? WHERE id=?',
                (request.form['site'], request.form['username'],
                 encrypt(request.form['password'], key),
                 request.form.get('url', ''), request.form.get('notes', ''), id))
        flash('Updated.')
        return redirect(url_for('vault'))
    key = get_key()
    pwd = decrypt(entry['password'], key)
    return render_template('form.html', entry=entry, pwd=pwd)

@app.route('/delete/<int:id>', methods=['POST'])
def delete(id):
    if not session.get('unlocked'):
        return redirect(url_for('unlock'))
    with get_db() as conn:
        conn.execute('DELETE FROM passwords WHERE id=?', (id,))
    flash('Deleted.')
    return redirect(url_for('vault'))

@app.route('/reveal/<int:id>')
def reveal(id):
    if not session.get('unlocked'):
        return 'Unauthorized', 401
    with get_db() as conn:
        entry = conn.execute('SELECT password FROM passwords WHERE id=?', (id,)).fetchone()
    if not entry:
        return 'Not found', 404
    pwd = decrypt(entry['password'], get_key())
    return pwd

@app.route('/generate')
def generate():
    length = int(request.args.get('length', 20))
    chars = string.ascii_letters + string.digits + '!@#$%^&*()'
    return ''.join(secrets.choice(chars) for _ in range(length))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)

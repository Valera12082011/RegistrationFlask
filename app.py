from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from io import BytesIO
import os
import sqlite3
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
DATABASE = 'users4.db'

# Load translations
def load_translations():
    translations = {}
    for lang in ['en', 'uk']:
        with open(f'translations/{lang}.json', 'r', encoding='utf-8') as file:
            translations[lang] = json.load(file)
    return translations

translations = load_translations()

def get_locale():
    return session.get('lang', request.accept_languages.best_match(['en', 'uk']))

def translate(text):
    locale = get_locale()
    return translations.get(locale, {}).get(text, text)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    cur.close()

@app.context_processor
def inject_translate():
    return dict(translate=translate, get_locale=get_locale)

@app.route('/set_language/<lang>')
def set_language(lang):
    if lang in ['en', 'uk']:
        session['lang'] = lang
    return redirect(request.referrer)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        avatar = request.files['avatar']

        hashed_password = generate_password_hash(password, method='sha256')

        if avatar:
            avatar_data = avatar.read()
            avatar_filename = secure_filename(avatar.filename)
        else:
            avatar_data = None
            avatar_filename = None

        execute_db('INSERT INTO users (username, password, avatar, avatar_filename) VALUES (?, ?, ?, ?)',
                   [username, hashed_password, avatar_data, avatar_filename])
        
        flash(translate('Registration successful! Please login.'), 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = query_db('SELECT * FROM users WHERE username = ?', [username], one=True)

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            flash(translate('Login successful!'), 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(translate('Login failed. Check your username and/or password.'), 'danger')

    return render_template('login.html')

@app.route('/avatar/<int:user_id>')
def avatar(user_id):
    user = query_db('SELECT * FROM users WHERE id = ?', [user_id], one=True)
    if user and user['avatar']:
        return send_file(BytesIO(user['avatar']), mimetype='image/jpeg', as_attachment=False, download_name=user['avatar_filename'])
    else:
        flash(translate('Avatar not found!'), 'danger')
        return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash(translate('Please login to access this page.'), 'danger')
        return redirect(url_for('login'))

    user = query_db('SELECT * FROM users WHERE id = ?', [session['user_id']], one=True)
    avatar_url = url_for('avatar', user_id=user['id']) if user['avatar'] else None
    return render_template('dashboard.html', username=user['username'], avatar_url=avatar_url)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash(translate('You have been logged out.'), 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db = get_db()
        db.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL UNIQUE,
                        password TEXT NOT NULL,
                        avatar BLOB,
                        avatar_filename TEXT)''')
        db.commit()
    app.run(debug=True)

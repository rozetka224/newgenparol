from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import hashlib
import secrets
import string
import re

app = Flask(__name__)
app.secret_key = 'dev_key_for_testing_only'

def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id INTEGER PRIMARY KEY, 
                     username TEXT UNIQUE, 
                     password TEXT,
                     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

def generate_strong_password(length=12):
    """Генерация надежного пароля"""
    if length < 8:
        length = 8

    characters = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        password = ''.join(secrets.choice(characters) for _ in range(length))
        if (any(c.islower() for c in password) and
                any(c.isupper() for c in password) and
                any(c.isdigit() for c in password) and
                any(c in "!@#$%^&*" for c in password)):
            return password

def validate_password(password):
    """Валидация пароля"""
    if len(password) < 8:
        return "Пароль должен содержать минимум 8 символов"
    if not re.search(r"[A-Z]", password):
        return "Пароль должен содержать хотя бы одну заглавную букву"
    if not re.search(r"[a-z]", password):
        return "Пароль должен содержать хотя бы одну строчную букву"
    if not re.search(r"\d", password):
        return "Пароль должен содержать хотя бы одну цифру"
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_password', methods=['GET', 'POST'])
def generate_password():
    if 'username' not in session:
        flash('Пожалуйста, войдите в систему, чтобы получить доступ к этой странице.')
        return redirect(url_for('login'))

    generated_password = None
    if request.method == 'POST':
        try:
            length = int(request.form.get('length', 12))
            if length < 8:
                length = 8
            elif length > 32:
                length = 32
            generated_password = generate_strong_password(length)
        except ValueError:
            generated_password = generate_strong_password()

    return render_template('generate_password.html',
                           generated_password=generated_password,
                           username=session.get('username'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        if len(username) < 3:
            flash('Имя пользователя должно содержать минимум 3 символа.')
            return render_template('register.html')

        password_error = validate_password(password)
        if password_error:
            flash(password_error)
            return render_template('register.html')

        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                         (username, hashed_password))
            conn.commit()
            flash('Регистрация прошла успешно! Вы можете войти.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Это имя пользователя уже занято. Пожалуйста, выберите другое.')
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?',
                           (username, hashed_password)).fetchone()
        conn.close()

        if user:
            session['username'] = user['username']
            flash(f'Добро пожаловать, {username}!')
            return redirect(url_for('generate_password'))
        else:
            flash('Неверное имя пользователя или пароль.')
            return render_template('login.html')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Вы успешно вышли из системы.')
    return redirect(url_for('index'))

@app.route('/profile')
def profile():
    if 'username' not in session:
        flash('Пожалуйста, войдите в систему.')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute('SELECT username, created_at FROM users WHERE username = ?',
                        (session['username'],)).fetchone()
    conn.close()

    return render_template('profile.html', user=user)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
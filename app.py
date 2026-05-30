from flask import Flask, render_template, request, redirect, session
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
app.secret_key = "secretkey"

bcrypt = Bcrypt(app)

# Database Connection
conn = sqlite3.connect('users.db', check_same_thread=False)
cursor = conn.cursor()

# Create Table
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
""")
conn.commit()


@app.route('/')
def home():
    return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        # Validation
        if not username or not password:
            return "Username and Password cannot be empty"

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )
            conn.commit()

            return redirect('/login')

        except sqlite3.IntegrityError:
            return "Username already exists"

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )

        user = cursor.fetchone()

        if user and bcrypt.check_password_hash(user[2], password):
            session['user'] = username
            return redirect('/dashboard')

        return "Invalid Username or Password"

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():

    if 'user' not in session:
        return redirect('/login')

    return render_template(
        'dashboard.html',
        user=session['user']
    )


@app.route('/logout')
def logout():

    session.pop('user', None)
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
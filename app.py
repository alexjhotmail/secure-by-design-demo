"""
secure-by-design-demo · app.py
A minimal Flask app demonstrating Secure by Design principles.
For educational use — Lovebeing Business CN5009 Week 7
"""

import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, g, flash
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dotenv import load_dotenv
from functools import wraps

# ─── Environment ──────────────────────────────────────────────────────────────
# Load from .env file — never hardcode secrets in source code
load_dotenv()

app = Flask(__name__)

# SECRET_KEY loaded from environment — crash at startup if not set
# This prevents accidentally running with an insecure key
app.secret_key = os.environ.get("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY environment variable is not set. "
        "Copy .env.example to .env and generate a key with: "
        "python -c \"import secrets; print(secrets.token_hex(32))\""
    )

DATABASE = os.environ.get("DATABASE_URL", "notes.db").replace("sqlite:///", "")

# ─── Password Hashing ─────────────────────────────────────────────────────────
# Using argon2id: memory-hard, resistant to GPU-based brute force
# See README Security Considerations for why argon2 over bcrypt
ph = PasswordHasher(
    time_cost=2,        # Number of iterations
    memory_cost=65536,  # 64 MB — makes GPU attacks expensive
    parallelism=2,      # Threads
    hash_len=32,
    salt_len=16
)

# ─── Simple Rate Limiting ─────────────────────────────────────────────────────
# NOTE: In-memory only — does not persist across restarts or scale horizontally
# A Redis-backed solution would be needed in production (see README Known Limitations)
login_attempts = {}
MAX_ATTEMPTS = int(os.environ.get("LOGIN_RATE_LIMIT", 5))

def check_rate_limit(ip):
    """Return True if this IP has exceeded the login attempt limit."""
    attempts = login_attempts.get(ip, 0)
    return attempts >= MAX_ATTEMPTS

def record_attempt(ip):
    login_attempts[ip] = login_attempts.get(ip, 0) + 1

def reset_attempts(ip):
    login_attempts.pop(ip, None)

# ─── Database ─────────────────────────────────────────────────────────────────
def get_db():
    """Get database connection, creating it if needed."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    """Initialise the database schema."""
    db = get_db()
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    # Parameterised queries used throughout — prevents SQL injection
    db.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    db.commit()

# ─── Auth Helper ──────────────────────────────────────────────────────────────
def login_required(f):
    """Decorator: redirect to login if user is not authenticated."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("notes"))
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "error")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return render_template("register.html")

        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()

        if existing:
            flash("Username already taken.", "error")
            return render_template("register.html")

        # Hash the password using argon2id before storing
        password_hash = ph.hash(password)
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        db.commit()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = request.remote_addr

        # Rate limiting check
        if check_rate_limit(ip):
            flash("Too many login attempts. Please wait and try again.", "error")
            return render_template("login.html")

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user is None:
            record_attempt(ip)
            # Same message for wrong username and wrong password
            # Prevents username enumeration attacks
            flash("Invalid username or password.", "error")
            return render_template("login.html")

        try:
            ph.verify(user["password_hash"], password)
            # Success
            reset_attempts(ip)
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = username
            # Regenerate session after login to prevent session fixation
            return redirect(url_for("notes"))
        except VerifyMismatchError:
            record_attempt(ip)
            flash("Invalid username or password.", "error")
            return render_template("login.html")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/notes", methods=["GET", "POST"])
@login_required
def notes():
    db = get_db()
    user_id = session["user_id"]

    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if content:
            # Input sanitisation happens at render time via Jinja2 auto-escaping
            # We store raw text; HTML is escaped in the template
            db.execute(
                "INSERT INTO notes (user_id, content) VALUES (?, ?)",
                (user_id, content)
            )
            db.commit()

    # Only fetch notes belonging to the authenticated user (access control)
    user_notes = db.execute(
        "SELECT content, created_at FROM notes WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()

    return render_template("notes.html", notes=user_notes, username=session["username"])

# ─── Security Headers ─────────────────────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    """Add HTTP security headers to every response."""
    # Prevents MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Stops the browser rendering the page in a frame (clickjacking protection)
    response.headers["X-Frame-Options"] = "DENY"
    # Forces HTTPS in browsers that have visited before (not useful on localhost)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Basic referrer policy
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# ─── Startup ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    with app.app_context():
        init_db()
    # debug=False in production — never expose debug mode
    app.run(debug=os.environ.get("FLASK_DEBUG", "False").lower() == "true")

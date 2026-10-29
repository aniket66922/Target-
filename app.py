from flask import Flask, render_template, request, redirect, session, url_for, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = "change-this-secret-key"
DB = "panel.db"


def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        status TEXT DEFAULT 'active'
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )""")
    # Default admin: username admin, password admin123 (change it!)
    if not conn.execute("SELECT 1 FROM admins").fetchone():
        conn.execute("INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                     ("admin", generate_password_hash("admin123")))
    conn.commit()
    conn.close()


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        conn = get_db()
        admin = conn.execute("SELECT * FROM admins WHERE username = ?",
                             (request.form["username"],)).fetchone()
        conn.close()
        if admin and check_password_hash(admin["password_hash"], request.form["password"]):
            session["admin"] = admin["username"]
            return redirect(url_for("users"))
        flash("Wrong username or password")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def users():
    conn = get_db()
    rows = conn.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    conn.close()
    return render_template("users.html", users=rows)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add_user():
    if request.method == "POST":
        try:
            conn = get_db()
            conn.execute("INSERT INTO users (name, email, status) VALUES (?, ?, ?)",
                         (request.form["name"], request.form["email"], request.form["status"]))
            conn.commit()
            conn.close()
            return redirect(url_for("users"))
        except sqlite3.IntegrityError:
            flash("Email already exists")
    return render_template("form.html", user=None)


@app.route("/edit/<int:user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    conn = get_db()
    if request.method == "POST":
        conn.execute("UPDATE users SET name = ?, email = ?, status = ? WHERE id = ?",
                     (request.form["name"], request.form["email"], request.form["status"], user_id))
        conn.commit()
        conn.close()
        return redirect(url_for("users"))
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return render_template("form.html", user=user)


@app.route("/delete/<int:user_id>", methods=["POST"])
@login_required
def delete_user(user_id):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("users"))


@app.route("/toggle/<int:user_id>", methods=["POST"])
@login_required
def toggle_user(user_id):
    conn = get_db()
    conn.execute("""UPDATE users SET status =
                    CASE WHEN status = 'active' THEN 'blocked' ELSE 'active' END
                    WHERE id = ?""", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("users"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)

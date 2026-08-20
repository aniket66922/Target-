from fastapi import FastAPI, HTTPException, Request, Form, Depends, Cookie, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
import sqlite3, secrets, string, time
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext

app = FastAPI()
DB_NAME = "database.db"
SECRET_KEY = "SECRET_KEY_12345"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash TEXT, role TEXT, credits REAL, status TEXT, created_by TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS licenses (key TEXT PRIMARY KEY, duration_hours REAL, credit_cost REAL, created_by TEXT, status TEXT, hwid TEXT, expiry_at TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS blacklist (identifier TEXT PRIMARY KEY, type TEXT)")
    c.execute("SELECT * FROM users WHERE username = 'owner'")
    if not c.fetchone():
        h = pwd_context.hash("owner1234")
        c.execute("INSERT INTO users (username, password_hash, role, credits, status, created_by) VALUES ('owner', ?, 'super_owner', 999999, 'active', 'system')", (h,))
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def get_current_user(token: str = Cookie(None)):
    if not token:
        return None
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        conn = get_db()
        u = conn.cursor().execute("SELECT * FROM users WHERE username = ?", (data.get("sub"),)).fetchone()
        conn.close()
        if u and u["status"] == "active":
            return dict(u)
    except:
        return None
    return None

class VerifyRequest(BaseModel):
    key: str
    hwid: str

@app.post("/api/verify")
def verify(d: VerifyRequest, req: Request):
    ip = req.client.host
    conn = get_db()
    c = conn.cursor()
    if c.execute("SELECT identifier FROM blacklist WHERE identifier IN (?, ?)", (ip, d.hwid)).fetchone():
        conn.close()
        raise HTTPException(status_code=403, detail="Banned")
    lic = c.execute("SELECT * FROM licenses WHERE key = ?", (d.key,)).fetchone()
    if not lic or lic["status"] == "banned":
        conn.close()
        raise HTTPException(status_code=403, detail="Invalid/Banned Key")
    now = datetime.utcnow()
    if lic["status"] == "unused":
        exp = (now + timedelta(hours=lic["duration_hours"])).strftime("%Y-%m-%d %H:%M:%S")
        c.execute("UPDATE licenses SET status='active', hwid=?, expiry_at=? WHERE key=?", (d.hwid, exp, d.key))
        conn.commit()
        conn.close()
        return {"status": "success", "expiry": exp}
    if lic["hwid"] != d.hwid:
        conn.close()
        raise HTTPException(status_code=403, detail="HWID Mismatch")
    if now > datetime.strptime(lic["expiry_at"], "%Y-%m-%d %H:%M:%S"):
        c.execute("UPDATE licenses SET status='expired' WHERE key=?", (d.key,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=403, detail="Expired")
    conn.close()
    return {"status": "success", "expiry": lic["expiry_at"]}

@app.get("/login", response_class=HTMLResponse)
def login_ui():
    return """
    <body style="background:#0f172a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;">
    <form action="/auth/login" method="post" style="background:#1e293b;padding:25px;border-radius:10px;display:flex;flex-direction:column;gap:12px;width:300px;">
    <h2 style="color:#10b981;text-align:center;">Admin Login</h2>
    <input name="username" placeholder="Username" style="padding:10px;background:#0f172a;border:1px solid #334155;color:#fff;border-radius:5px;" required>
    <input name="password" type="password" placeholder="Password" style="padding:10px;background:#0f172a;border:1px solid #334155;color:#fff;border-radius:5px;" required>
    <button type="submit" style="padding:10px;background:#10b981;font-weight:bold;border:none;border-radius:5px;cursor:pointer;">Login</button>
    </form>
    </body>
    """

@app.post("/auth/login")
def login(username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    u = conn.cursor().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    if not u or not pwd_context.verify(password, u["password_hash"]):
        return HTMLResponse("<script>alert('Wrong Login');location.href='/login';</script>")
    token = jwt.encode({"sub": u["username"], "role": u["role"], "exp": datetime.utcnow() + timedelta(days=2)}, SECRET_KEY, algorithm="HS256")
    res = RedirectResponse("/dashboard", status_code=302)
    res.set_cookie("token", token, httponly=True)
    return res

@app.get("/logout")
def logout():
    res = RedirectResponse("/login")
    res.delete_cookie("token")
    return res

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_ui(user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse("/login")
    conn = get_db()
    c = conn.cursor()
    if user["role"] in ["super_owner", "owner"]:
        keys = c.execute("SELECT * FROM licenses ORDER BY rowid DESC").fetchall()
        users = c.execute("SELECT * FROM users").fetchall()
    else:
        keys = c.execute("SELECT * FROM licenses WHERE created_by = ? ORDER BY rowid DESC", (user["username"],)).fetchall()
        users = []
    conn.close()
    
    k_rows = "".join(f"<tr><td>{k['key']}</td><td>{k['duration_hours']}h</td><td>{k['status']}</td><td>{k['hwid'] or 'None'}</td><td>{k['expiry_at'] or '-'}</td><td><a href='/hwid/reset/{k['key']}' style='color:#38bdf8;'>Reset HWID</a> | <a href='/key/del/{k['key']}' style='color:#ef4444;'>Del</a></td></tr>" for k in keys)
    u_rows = "".join(f"<tr><td>{u['username']}</td><td>{u['role']}</td><td>{u['credits']}</td><td>{u['status']}</td><td><a href='/user/del/{u['id']}' style='color:#ef4444;'>Del</a></td></tr>" for u in users) if users else ""
    
    return f"""
    <body style="background:#0b0f19;color:#fff;font-family:sans-serif;padding:20px;">
    <h2>⚡ PANEL ({user['username'].upper()} - {user['role']}) | Credits: {user['credits']} | <a href='/logout' style='color:#ef4444;'>Logout</a></h2>
    <hr style="margin:15px 0;border-color:#1e293b;">
    <div style="display:flex;gap:20px;flex-wrap:wrap;">
        <form action="/key/create" method="post" style="background:#131d2e;padding:15px;border-radius:8px;">
            <h3>Create Key</h3>
            <select name="duration" style="padding:6px;margin:6px 0;background:#0b0f19;color:#fff;">
                <option value="1">1 Hour</option><option value="2">2 Hours</option><option value="5">5 Hours</option>
                <option value="6">6 Hours</option><option value="12">12 Hours</option><option value="24">1 Day</option>
                <option value="168">7 Days</option><option value="360">15 Days</option><option value="720">30 Days</option>
            </select>
            <br><button type="submit" style="padding:6px 12px;background:#10b981;border:none;border-radius:4px;cursor:pointer;">Generate</button>
        </form>
        {'<form action="/user/create" method="post" style="background:#131d2e;padding:15px;border-radius:8px;"><h3>Create Reseller</h3><input name="username" placeholder="User" style="padding:6px;margin:4px 0;background:#0b0f19;color:#fff;" required><br><input name="password" placeholder="Pass" type="password" style="padding:6px;margin:4px 0;background:#0b0f19;color:#fff;" required><br><input name="credits" type="number" placeholder="Credits" value="50" style="padding:6px;margin:4px 0;background:#0b0f19;color:#fff;"><br><button type="submit" style="padding:6px 12px;background:#38bdf8;border:none;border-radius:4px;cursor:pointer;">Add User</button></form>' if user['role'] in ['super_owner','owner'] else ''}
        {'<form action="/block/add" method="post" style="background:#131d2e;padding:15px;border-radius:8px;"><h3>Block Device/IP</h3><input name="ident" placeholder="HWID or IP" style="padding:6px;margin:6px 0;background:#0b0f19;color:#fff;" required><br><button type="submit" style="background:#ef4444;color:#fff;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;">Ban Target</button></form>' if user['role'] in ['super_owner','owner'] else ''}
    </div>
    {'<h3 style="margin-top:20px;">Users</h3><table border="1" cellpadding="8" style="border-collapse:collapse;width:100%;margin-top:5px;border-color:#334155;"><tr><th>User</th><th>Role</th><th>Credits</th><th>Status</th><th>Action</th></tr>' + u_rows + '</table>' if users else ''}
    <h3 style="margin-top:20px;">Keys</h3>
    <table border="1" cellpadding="8" style="border-collapse:collapse;width:100%;margin-top:5px;border-color:#334155;">
        <tr><th>Key</th><th>Duration</th><th>Status</th><th>HWID</th><th>Expiry</th><th>Action</th></tr>
        {k_rows}
    </table>
    </body>
    """

@app.post("/key/create")
def create_key(duration: float = Form(...), user: dict = Depends(get_current_user)):
    if not user: return RedirectResponse("/login")
    cost_map = {1: 0.1, 2: 0.2, 5: 0.5, 6: 0.6, 12: 1.0, 24: 2.0, 168: 10.0, 360: 18.0, 720: 30.0}
    cost = cost_map.get(int(duration), 1.0)
    if user["role"] != "super_owner" and user["credits"] < cost:
        return HTMLResponse("<script>alert('Low Credits');location.href='/dashboard';</script>")
    k_str = "KEY-" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO licenses VALUES (?, ?, ?, ?, 'unused', NULL, NULL)", (k_str, duration, cost, user["username"]))
    if user["role"] != "super_owner":
        c.execute("UPDATE users SET credits = credits - ? WHERE id = ?", (cost, user["id"]))
    conn.commit()
    conn.close()
    return RedirectResponse("/dashboard", status_code=302)

@app.get("/hwid/reset/{k}")
def r_hwid(k: str, user: dict = Depends(get_current_user)):
    if not user: return RedirectResponse("/login")
    conn = get_db()
    conn.cursor().execute("UPDATE licenses SET hwid = NULL WHERE key = ?", (k,))
    conn.commit()
    conn.close()
    return RedirectResponse("/dashboard")

@app.get("/key/del/{k}")
def d_key(k: str, user: dict = Depends(get_current_user)):
    if not user: return RedirectResponse("/login")
    conn = get_db()
    conn.cursor().execute("DELETE FROM licenses WHERE key = ?", (k,))
    conn.commit()
    conn.close()
    return RedirectResponse("/dashboard")

@app.post("/user/create")
def u_create(username: str = Form(...), password: str = Form(...), credits: float = Form(...), user: dict = Depends(get_current_user)):
    if not user or user["role"] not in ["super_owner", "owner"]: return RedirectResponse("/login")
    conn = get_db()
    h = pwd_context.hash(password)
    try:
        conn.cursor().execute("INSERT INTO users (username, password_hash, role, credits, status, created_by) VALUES (?, ?, 'reseller', ?, 'active', ?)", (username, h, credits, user["username"]))
        conn.commit()
    except: pass
    conn.close()
    return RedirectResponse("/dashboard", status_code=302)

@app.get("/user/del/{uid}")
def u_del(uid: int, user: dict = Depends(get_current_user)):
    if not user or user["role"] != "super_owner": return RedirectResponse("/login")
    conn = get_db()
    conn.cursor().execute("DELETE FROM users WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    return RedirectResponse("/dashboard")

@app.post("/block/add")
def b_add(ident: str = Form(...), user: dict = Depends(get_current_user)):
    if not user or user["role"] not in ["super_owner", "owner"]: return RedirectResponse("/login")
    conn = get_db()
    try:
        conn.cursor().execute("INSERT INTO blacklist VALUES (?, 'banned')", (ident,))
        conn.commit()
    except: pass
    conn.close()
    return RedirectResponse("/dashboard", status_code=302)


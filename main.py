import sqlite3, secrets, string, hashlib, hmac
from datetime import datetime, timedelta
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException, Request, Form, Depends, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse

app = FastAPI()
DB = "database.db"
SECRET_SALT = "SECURITY_SALT_SUPER_SECURE_99"

def hash_pw(pw: str) -> str:
    return hashlib.sha256((pw + SECRET_SALT).encode()).hexdigest()

def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c

def init():
    with db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, role TEXT, credits REAL, status TEXT, created_by TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS licenses (key TEXT PRIMARY KEY, duration_hours REAL, credit_cost REAL, created_by TEXT, status TEXT, hwid TEXT, expiry_at TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS blacklist (identifier TEXT PRIMARY KEY)")
        if not c.execute("SELECT * FROM users WHERE username='owner'").fetchone():
            c.execute("INSERT INTO users (username, password_hash, role, credits, status, created_by) VALUES ('owner', ?, 'super_owner', 999999, 'active', 'system')", (hash_pw("owner1234"),))
init()

def get_user(token: str = Cookie(None)):
    if not token or ":" not in token: return None
    try:
        user, role = token.split(":", 1)
        with db() as c:
            u = c.execute("SELECT * FROM users WHERE username=? AND role=?", (user, role)).fetchone()
            return dict(u) if u and u["status"] == "active" else None
    except: return None

class VData(BaseModel):
    key: str
    hwid: str

@app.post("/api/verify")
def verify_api(d: VData, req: Request):
    ip = req.client.host
    with db() as c:
        if c.execute("SELECT identifier FROM blacklist WHERE identifier IN (?,?)", (ip, d.hwid)).fetchone():
            raise HTTPException(403, "Device/IP Banned")
        lic = c.execute("SELECT * FROM licenses WHERE key=?", (d.key,)).fetchone()
        if not lic or lic["status"] == "banned": raise HTTPException(403, "Invalid/Banned Key")
        now = datetime.utcnow()
        if lic["status"] == "unused":
            exp = (now + timedelta(hours=lic["duration_hours"])).strftime("%Y-%m-%d %H:%M:%S")
            c.execute("UPDATE licenses SET status='active', hwid=?, expiry_at=? WHERE key=?", (d.hwid, exp, d.key))
            return {"status": "success", "expiry": exp}
        if lic["hwid"] != d.hwid: raise HTTPException(403, "HWID Mismatch")
        if now > datetime.strptime(lic["expiry_at"], "%Y-%m-%d %H:%M:%S"):
            c.execute("UPDATE licenses SET status='expired' WHERE key=?", (d.key,))
            raise HTTPException(403, "Key Expired")
        return {"status": "success", "expiry": lic["expiry_at"]}

@app.get("/", response_class=RedirectResponse)
def root(): return RedirectResponse("/login")

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return '<body style="background:#0f172a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;"><form action="/auth/login" method="post" style="background:#1e293b;padding:25px;border-radius:10px;display:flex;flex-direction:column;gap:10px;width:280px;"><h2 style="color:#10b981;text-align:center;">⚡ Login</h2><input name="username" placeholder="Username" style="padding:10px;background:#0f172a;border:1px solid #334155;color:#fff;border-radius:5px;" required><input name="password" type="password" placeholder="Password" style="padding:10px;background:#0f172a;border:1px solid #334155;color:#fff;border-radius:5px;" required><button type="submit" style="padding:10px;background:#10b981;font-weight:bold;border:none;border-radius:5px;cursor:pointer;">Login</button></form></body>'

@app.post("/auth/login")
def auth_login(username: str = Form(...), password: str = Form(...)):
    with db() as c:
        u = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not u or u["password_hash"] != hash_pw(password) or u["status"] == "banned":
        return HTMLResponse("<script>alert('Invalid Login');location.href='/login';</script>")
    res = RedirectResponse("/dashboard", status_code=302)
    res.set_cookie("token", f"{u['username']}:{u['role']}", httponly=True)
    return res

@app.get("/logout")
def logout():
    res = RedirectResponse("/login")
    res.delete_cookie("token")
    return res

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(u: dict = Depends(get_user)):
    if not u: return RedirectResponse("/login")
    with db() as c:
        if u["role"] in ["super_owner", "owner"]:
            keys = c.execute("SELECT * FROM licenses ORDER BY rowid DESC").fetchall()
            users = c.execute("SELECT * FROM users").fetchall()
        else:
            keys = c.execute("SELECT * FROM licenses WHERE created_by=? ORDER BY rowid DESC", (u["username"],)).fetchall()
            users = []
    k_tr = "".join(f"<tr><td>{k['key']}</td><td>{k['duration_hours']}h</td><td>{k['status']}</td><td>{k['hwid'] or '-'}</td><td>{k['expiry_at'] or '-'}</td><td><a href='/hwid/{k['key']}' style='color:#38bdf8;'>Reset</a> | <a href='/kdel/{k['key']}' style='color:#ef4444;'>Del</a></td></tr>" for k in keys)
    u_tr = "".join(f"<tr><td>{x['username']}</td><td>{x['role']}</td><td>{x['credits']}</td><td>{x['status']}</td><td><a href='/udel/{x['id']}' style='color:#ef4444;'>Del</a></td></tr>" for x in users) if users else ""
    return f"""<body style="background:#0b0f19;color:#fff;font-family:sans-serif;padding:20px;">
    <h3>⚡ PANEL: {u['username']} ({u['role']}) | Credits: {u['credits']} | <a href='/logout' style='color:#ef4444;'>Logout</a></h3><hr style='border-color:#1e293b;margin:10px 0;'>
    <div style='display:flex;gap:15px;flex-wrap:wrap;'>
      <form action='/key/create' method='post' style='background:#131d2e;padding:15px;border-radius:8px;'>
        <b>Create Key</b><br>
        <select name='duration' style='padding:6px;margin:8px 0;background:#0b0f19;color:#fff;'>
          <option value='1'>1 Hour</option><option value='2'>2 Hours</option><option value='5'>5 Hours</option>
          <option value='6'>6 Hours</option><option value='12'>12 Hours</option><option value='24'>1 Day</option>
          <option value='168'>7 Days</option><option value='360'>15 Days</option><option value='720'>30 Days</option>
        </select><br><button type='submit' style='padding:6px 12px;background:#10b981;border:none;border-radius:4px;cursor:pointer;'>Generate</button>
      </form>
      {'<form action="/user/create" method="post" style="background:#131d2e;padding:15px;border-radius:8px;"><b>Create User</b><br><input name="username" placeholder="Username" style="padding:4px;margin:4px 0;background:#0b0f19;color:#fff;" required><br><input name="password" type="password" placeholder="Password" style="padding:4px;margin:4px 0;background:#0b0f19;color:#fff;" required><br><select name="role" style="padding:4px;margin:4px 0;background:#0b0f19;color:#fff;"><option value="reseller">Reseller</option><option value="admin">Admin</option><option value="owner">Sub-Owner</option></select><br><input name="credits" type="number" value="50" style="padding:4px;margin:4px 0;background:#0b0f19;color:#fff;"><br><button type="submit" style="padding:6px 12px;background:#38bdf8;border:none;border-radius:4px;cursor:pointer;">Save</button></form>' if u['role'] in ['super_owner','owner'] else ''}
      {'<form action="/block/add" method="post" style="background:#131d2e;padding:15px;border-radius:8px;"><b>Block HWID/IP</b><br><input name="ident" placeholder="HWID or IP" style="padding:4px;margin:8px 0;background:#0b0f19;color:#fff;" required><br><button type="submit" style="background:#ef4444;color:#fff;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;">Ban Target</button></form>' if u['role'] in ['super_owner','owner'] else ''}
    </div>
    {'<h4>Users</h4><table border="1" cellpadding="6" style="border-collapse:collapse;width:100%;margin-top:5px;border-color:#334155;"><tr><th>User</th><th>Role</th><th>Credits</th><th>Status</th><th>Action</th></tr>' + u_tr + '</table>' if users else ''}
    <h4>License Keys</h4><table border="1" cellpadding="6" style="border-collapse:collapse;width:100%;margin-top:5px;border-color:#334155;"><tr><th>Key</th><th>Duration</th><th>Status</th><th>HWID</th><th>Expiry</th><th>Action</th></tr>{k_tr}</table></body>"""

@app.post("/key/create")
def add_key(duration: float = Form(...), u: dict = Depends(get_user)):
    if not u: return RedirectResponse("/login")
    costs = {1:0.1, 2:0.2, 5:0.5, 6:0.6, 12:1.0, 24:2.0, 168:10.0, 360:18.0, 720:30.0}
    c_cost = costs.get(int(duration), 1.0)
    if u["role"] != "super_owner" and u["credits"] < c_cost:
        return HTMLResponse("<script>alert('Low Credits');location.href='/dashboard';</script>")
    k_code = "KEY-" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
    with db() as c:
        c.execute("INSERT INTO licenses VALUES (?, ?, ?, ?, 'unused', NULL, NULL)", (k_code, duration, c_cost, u["username"]))
        if u["role"] != "super_owner": c.execute("UPDATE users SET credits=credits-? WHERE id=?", (c_cost, u["id"]))
    return RedirectResponse("/dashboard", status_code=302)

@app.get("/hwid/{k}")
def r_hwid(k: str, u: dict = Depends(get_user)):
    if not u: return RedirectResponse("/login")
    with db() as c: c.execute("UPDATE licenses SET hwid=NULL WHERE key=?", (k,))
    return RedirectResponse("/dashboard")

@app.get("/kdel/{k}")
def k_del(k: str, u: dict = Depends(get_user)):
    if not u: return RedirectResponse("/login")
    with db() as c: c.execute("DELETE FROM licenses WHERE key=?", (k,))
    return RedirectResponse("/dashboard")

@app.post("/user/create")
def u_create(username: str = Form(...), password: str = Form(...), role: str = Form("reseller"), credits: float = Form(0), u: dict = Depends(get_user)):
    if not u or u["role"] not in ["super_owner", "owner"]: return RedirectResponse("/login")
    with db() as c:
        try: c.execute("INSERT INTO users (username, password_hash, role, credits, status, created_by) VALUES (?, ?, ?, ?, 'active', ?)", (username, hash_pw(password), role, credits, u["username"]))
        except: pass
    return RedirectResponse("/dashboard", status_code=302)

@app.get("/udel/{uid}")
def u_del(uid: int, u: dict = Depends(get_user)):
    if not u or u["role"] != "super_owner": return RedirectResponse("/login")
    with db() as c: c.execute("DELETE FROM users WHERE id=?", (uid,))
    return RedirectResponse("/dashboard")

@app.post("/block/add")
def b_add(ident: str = Form(...), u: dict = Depends(get_user)):
    if not u or u["role"] not in ["super_owner", "owner"]: return RedirectResponse("/login")
    with db() as c:
        try: c.execute("INSERT INTO blacklist VALUES (?)", (ident,))
        except: pass
    return RedirectResponse("/dashboard", status_code=302)
    

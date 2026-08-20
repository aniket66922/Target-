import sqlite3, secrets, string, hashlib
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
def root(): return RedirectResponse("/dashboard")

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return '''<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login - Target Panel</title>
<style>
body{background:#07090e;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:sans-serif;}
.box{background:#0e131f;padding:26px;border-radius:14px;border:1px solid #1a233a;width:90%;max-width:320px;text-align:center;}
input{width:100%;box-sizing:border-box;padding:12px;margin:8px 0;background:#070a12;border:1px solid #1f293d;color:#fff;border-radius:8px;}
button{width:100%;padding:12px;background:#00ff88;color:#07090e;border:none;border-radius:8px;font-weight:bold;cursor:pointer;margin-top:8px;}
a{color:#00ff88;text-decoration:none;font-size:13px;}
</style>
</head>
<body>
<div class="box">
<h2 style="color:#00ff88;margin-bottom:15px;">TARGET PANEL</h2>
<form action="/auth/login" method="post">
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">LOGIN</button>
</form>
<div style="margin-top:14px;"><a href="/register">Register New Account</a></div>
</div>
</body>
</html>'''

@app.get("/register", response_class=HTMLResponse)
def register_page():
    return '''<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Register - Target Panel</title>
<style>
body{background:#07090e;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;font-family:sans-serif;}
.box{background:#0e131f;padding:26px;border-radius:14px;border:1px solid #1a233a;width:90%;max-width:320px;text-align:center;}
input{width:100%;box-sizing:border-box;padding:12px;margin:8px 0;background:#070a12;border:1px solid #1f293d;color:#fff;border-radius:8px;}
button{width:100%;padding:12px;background:#38bdf8;color:#07090e;border:none;border-radius:8px;font-weight:bold;cursor:pointer;margin-top:8px;}
a{color:#38bdf8;text-decoration:none;font-size:13px;}
</style>
</head>
<body>
<div class="box">
<h2 style="color:#38bdf8;margin-bottom:6px;">REGISTER</h2>
<p style="font-size:11px;color:#94a3b8;margin-bottom:12px;">Approval required from admin</p>
<form action="/auth/register" method="post">
<input name="username" placeholder="Desired Username" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">SUBMIT REQUEST</button>
</form>
<div style="margin-top:14px;"><a href="/login">Already registered? Login</a></div>
</div>
</body>
</html>'''

@app.post("/auth/register")
def auth_register(username: str = Form(...), password: str = Form(...)):
    with db() as c:
        exist = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if exist:
            return HTMLResponse("<script>alert('Username already taken');location.href='/register';</script>")
        c.execute("INSERT INTO users (username, password_hash, role, credits, status, created_by) VALUES (?, ?, 'reseller', 0, 'pending', 'self_registered')", (username, hash_pw(password)))
    return HTMLResponse("<script>alert('Submitted! Awaiting Admin Approval.');location.href='/login';</script>")

@app.post("/auth/login")
def auth_login(username: str = Form(...), password: str = Form(...)):
    with db() as c:
        u = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not u or u["password_hash"] != hash_pw(password):
        return HTMLResponse("<script>alert('Invalid Credentials');location.href='/login';</script>")
    if u["status"] == "pending":
        return HTMLResponse("<script>alert('Account Pending Approval by Admin.');location.href='/login';</script>")
    if u["status"] == "banned":
        return HTMLResponse("<script>alert('Account Suspended');location.href='/login';</script>")
        
    token = f"{u['username']}:{u['role']}"
    res = RedirectResponse("/dashboard", status_code=302)
    res.set_cookie("token", token, httponly=True)
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
            active_users = c.execute("SELECT * FROM users WHERE status='active' AND username!='owner'").fetchall()
            pending_users = c.execute("SELECT * FROM users WHERE status='pending'").fetchall()
        else:
            keys = c.execute("SELECT * FROM licenses WHERE created_by=? ORDER BY rowid DESC", (u["username"],)).fetchall()
            active_users = []
            pending_users = []
            
    tot_keys = len(keys)
    used_keys = sum(1 for k in keys if k["status"] == "active")
    unused_keys = sum(1 for k in keys if k["status"] == "unused")
    tot_resellers = len(active_users)

    k_tr = "".join([f"<tr><td style='color:#00ff88;'>{k['key']}</td><td>{k['duration_hours']}h</td><td>{k['status']}</td><td>{k['hwid'] or '-'}</td><td>{k['expiry_at'] or '-'}</td><td><a href='/hwid/{k['key']}' style='color:#38bdf8;'>Reset</a> | <a href='/kdel/{k['key']}' style='color:#ef4444;'>Del</a></td></tr>" for k in keys])
    p_tr = "".join([f"<tr><td>{p['username']}</td><td style='color:#f59e0b;'>PENDING</td><td><a href='/user/approve/{p['id']}' style='color:#00ff88;'>Approve (+10CR)</a> | <a href='/udel/{p['id']}' style='color:#ef4444;'>Reject</a></td></tr>" for p in pending_users]) if pending_users else ""
    u_tr = "".join([f"<tr><td>{x['username']}</td><td>{x['role']}</td><td style='color:#00ff88;'>{x['credits']}</td><td>{x['status']}</td><td><a href='/udel/{x['id']}' style='color:#ef4444;'>Del</a></td></tr>" for x in active_users]) if active_users else ""

    p_section = f"<div class='card'><h3>⏳ PENDING REGISTRATIONS</h3><div class='tbl'><table><tr><th>User</th><th>Status</th><th>Action</th></tr>{p_tr}</table></div></div>" if pending_users else ""
    u_section = f"<div class='card'><h3>👥 RESELLERS</h3><div class='tbl'><table><tr><th>User</th><th>Role</th><th>Credits</th><th>Status</th><th>Action</th></tr>{u_tr}</table></div></div>" if active_users else ""
    
    admin_boxes = f"""<div class='card'><h3>👤 CREATE RESELLER</h3><form action='/user/create' method='post'><input name='username' placeholder='Username' required><input name='password' type='password' placeholder='Password' required><select name='role'><option value='reseller'>Reseller</option><option value='admin'>Admin</option></select><input name='credits' type='number' value='50'><button type='submit' style='background:#38bdf8;'>Save User</button></form></div>
<div class='card'><h3>🚫 BAN HWID/IP</h3><form action='/block/add' method='post'><input name='ident' placeholder='HWID or IP' required><button type='submit' style='background:#ef4444;color:#fff;'>Block Target</button></form></div>""" if u["role"] in ["super_owner", "owner"] else ""

    return f'''<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard</title>
<style>
body{{background:#07090e;color:#fff;margin:0;padding:12px;font-family:sans-serif;}}
.header{{display:flex;justify-content:space-between;align-items:center;background:#0e131f;padding:12px;border-radius:10px;border:1px solid #1a233a;margin-bottom:12px;}}
.grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:12px;}}
.stat{{background:#0e131f;padding:14px;border-radius:10px;border:1px solid #1a233a;text-align:center;}}
.stat b{{font-size:22px;color:#00ff88;display:block;}}
.stat span{{font-size:11px;color:#94a3b8;}}
.card{{background:#0e131f;padding:14px;border-radius:10px;border:1px solid #1a233a;margin-bottom:12px;}}
.card h3{{margin:0 0 10px 0;font-size:14px;color:#38bdf8;}}
input,select{{width:100%;box-sizing:border-box;padding:10px;margin:5px 0;background:#070a12;border:1px solid #1f293d;color:#fff;border-radius:6px;font-size:12px;}}
button{{width:100%;padding:10px;border:none;border-radius:6px;font-weight:bold;cursor:pointer;margin-top:5px;font-size:12px;}}
.tbl{{overflow-x:auto;}}
table{{width:100%;border-collapse:collapse;min-width:400px;font-size:12px;}}
th{{background:#070a12;color:#94a3b8;padding:8px;text-align:left;}}
td{{padding:8px;border-bottom:1px solid #1f293d;}}
a{{text-decoration:none;}}
</style>
</head>
<body>
<div class="header">
<div><b>{u['username'].upper()}</b> ({u['role']})</div>
<div><span style="color:#00ff88;font-weight:bold;">⚡ {u['credits']} CR</span> | <a href="/logout" style="color:#ef4444;font-weight:bold;">Logout</a></div>
</div>

<div class="grid">
<div class="stat"><b>{tot_keys}</b><span>Total Keys</span></div>
<div class="stat"><b style="color:#38bdf8;">{used_keys}</b><span>Used Keys</span></div>
<div class="stat"><b style="color:#f59e0b;">{unused_keys}</b><span>Unused Keys</span></div>
<div class="stat"><b style="color:#a855f7;">{tot_resellers}</b><span>Resellers</span></div>
</div>

<div class="card">
<h3>⚡ GENERATE LICENSE</h3>
<form action="/key/create" method="post">
<select name="duration">
<option value="1">1 Hour (0.1 Credit)</option>
<option value="2">2 Hours (0.2 Credit)</option>
<option value="5">5 Hours (0.5 Credit)</option>
<option value="6">6 Hours (0.6 Credit)</option>
<option value="12">12 Hours (1 Credit)</option>
<option value="24">1 Day (2 Credits)</option>
<option value="168">7 Days (10 Credits)</option>
<option value="360">15 Days (18 Credits)</option>
<option value="720">30 Days (30 Credits)</option>
</select>
<button type="submit" style="background:#00ff88;color:#07090e;">Create Key</button>
</form>
</div>

{admin_boxes}
{p_section}
{u_section}

<div class="card">
<h3>🔑 KEYS DIRECTORY</h3>
<div class="tbl">
<table>
<tr><th>Key</th><th>Duration</th><th>Status</th><th>HWID</th><th>Expiry</th><th>Action</th></tr>
{k_tr}
</table>
</div>
</div>
</body>
</html>'''

@app.get("/user/approve/{uid}")
def approve_user(uid: int, u: dict = Depends(get_user)):
    if not u or u["role"] not in ["super_owner", "owner"]: return RedirectResponse("/login")
    with db() as c:
        c.execute("UPDATE users SET status='active', credits=10 WHERE id=?", (uid,))
    return RedirectResponse("/dashboard")

@app.post("/key/create")
def add_key(duration: float = Form(...), u: dict = Depends(get_user)):
    if not u: return RedirectResponse("/login")
    costs = {1:0.1, 2:0.2, 5:0.5, 6:0.6, 12:1.0, 24:2.0, 168:10.0, 360:18.0, 720:30.0}
    c_cost = costs.get(int(duration), 1.0)
    if u["role"] != "super_owner" and u["credits"] < c_cost:
        return HTMLResponse("<script>alert('Low Credits');location.href='/dashboard';</script>")
    k_code = "TARGET-" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
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
    

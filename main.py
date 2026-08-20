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
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Login - Target Panel</title>
    <link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
        body { background: #07090e; color: #fff; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .card { background: #0e131f; border: 1px solid #1a233a; border-radius: 18px; width: 100%; max-width: 360px; padding: 30px 24px; box-shadow: 0 15px 35px rgba(0,0,0,0.6); position: relative; }
        .card::before { content:''; position: absolute; top:0; left:15%; right:15%; height:2px; background: linear-gradient(90deg, transparent, #00ff88, transparent); }
        .logo { font-family: 'Rajdhani', sans-serif; font-size: 26px; font-weight: 700; color: #00ff88; text-align: center; margin-bottom: 20px; letter-spacing: 2px; }
        .input-group { margin-bottom: 15px; }
        .input-group label { display: block; font-size: 11px; color: #718096; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 1px; }
        input { width: 100%; padding: 12px 14px; background: #070a12; border: 1px solid #1f293d; border-radius: 10px; color: #fff; font-size: 14px; outline: none; }
        input:focus { border-color: #00ff88; }
        button { width: 100%; padding: 13px; background: #00ff88; border: none; border-radius: 10px; color: #07090e; font-weight: 700; font-size: 15px; cursor: pointer; text-transform: uppercase; letter-spacing: 1px; margin-top: 10px; }
        .links { text-align: center; margin-top: 18px; font-size: 13px; color: #718096; }
        .links a { color: #00ff88; text-decoration: none; font-weight: 600; }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">🛡️ TARGET PANEL</div>
        <form action="/auth/login" method="post">
            <div class="input-group"><label>Username</label><input name="username" placeholder="Enter username" required></div>
            <div class="input-group"><label>Password</label><input name="password" type="password" placeholder="••••••••" required></div>
            <button type="submit">Sign In</button>
        </form>
        <div class="links">New user? <a href="/register">Create Account</a></div>
    </div>
</body>
</html>"""

@app.get("/register", response_class=HTMLResponse)
def register_page():
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Register - Target Panel</title>
    <link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@600;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
        body { background: #07090e; color: #fff; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
        .card { background: #0e131f; border: 1px solid #1a233a; border-radius: 18px; width: 100%; max-width: 360px; padding: 30px 24px; box-shadow: 0 15px 35px rgba(0,0,0,0.6); position: relative; }
        .card::before { content:''; position: absolute; top:0; left:15%; right:15%; height:2px; background: linear-gradient(90deg, transparent, #38bdf8, transparent); }
        .logo { font-family: 'Rajdhani', sans-serif; font-size: 26px; font-weight: 700; color: #38bdf8; text-align: center; margin-bottom: 8px; letter-spacing: 2px; }
        .sub { font-size: 12px; color: #718096; text-align: center; margin-bottom: 20px; }
        .input-group { margin-bottom: 15px; }
        .input-group label { display: block; font-size: 11px; color: #718096; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 1px; }
        input { width: 100%; padding: 12px 14px; background: #070a12; border: 1px solid #1f293d; border-radius: 10px; color: #fff; font-size: 14px; outline: none; }
        input:focus { border-color: #38bdf8; }
        button { width: 100%; padding: 13px; background: #38bdf8; border: none; border-radius: 10px; color: #07090e; font-weight: 700; font-size: 15px; cursor: pointer; text-transform: uppercase; letter-spacing: 1px; margin-top: 10px; }
        .links { text-align: center; margin-top: 18px; font-size: 13px; color: #718096; }
        .links a { color: #38bdf8; text-decoration: none; font-weight: 600; }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">📝 REGISTRATION</div>
        <div class="sub">Requires Admin Approval After Submission</div>
        <form action="/auth/register" method="post">
            <div class="input-group"><label>Desired Username</label><input name="username" placeholder="Enter username" required></div>
            <div class="input-group"><label>Password</label><input name="password" type="password" placeholder="••••••••" required></div>
            <button type="submit">Submit Request</button>
        </form>
        <div class="links">Already registered? <a href="/login">Sign In</a></div>
    </div>
</body>
</html>"""

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

    k_tr = "".join([f"<tr><td style='font-family:monospace;color:#00ff88;font-weight:600;'>{k['key']}</td><td>{k['duration_hours']}h</td><td><span class='badge {k['status']}'>{k['status'].upper()}</span></td><td style='font-family:monospace;font-size:11px;color:#94a3b8;'>{k['hwid'] or 'None'}</td><td style='font-size:11px;color:#94a3b8;'>{k['expiry_at'] or '-'}</td><td><a href='/hwid/{k['key']}' class='btn-sm btn-cyan'>Reset</a> <a href='/kdel/{k['key']}' class='btn-sm btn-red'>Del</a></td></tr>" for k in keys])
    p_tr = "".join([f"<tr><td style='font-weight:600;color:#38bdf8;'>{p['username']}</td><td><span class='badge pending'>PENDING</span></td><td><a href='/user/approve/{p['id']}' class='btn-sm btn-green'>Approve (+10 CR)</a> <a href='/udel/{p['id']}' class='btn-sm btn-red'>Reject</a></td></tr>" for p in pending_users]) if pending_users else ""
    u_tr = "".join([f"<tr><td style='font-weight:600;'>{x['username']}</td><td><span class='badge role'>{x['role'].upper()}</span></td><td style='color:#00ff88;font-weight:700;'>{x['credits']}</td><td><span class='badge active'>{x['status'].upper()}</span></td><td><a href='/udel/{x['id']}' class='btn-sm btn-red'>Delete</a></td></tr>" for x in active_users]) if active_users else ""

    p_table = f"<div class='table-card' style='border-color:#38bdf8;'><div class='box-title' style='color:#38bdf8;'>⏳ PENDING APPROVALS</div><div class='table-responsive'><table><thead><tr><th>Username</th><th>Status</th><th>Actions</th></tr></thead><tbody>{p_tr}</tbody></table></div></div>" if pending_users else ""
    u_table = f"<div class='table-card'><div class='box-title'>👥 RESELLERS DIRECTORY</div><div class='table-responsive'><table><thead><tr><th>Username</th><th>Role</th><th>Credits</th><th>Status</th><th>Actions</th></tr></thead><tbody>{u_tr}</tbody></table></div></div>" if active_users else ""
    admin_boxes = f"""<div class="action-box"><div class="box-title">👤 ADD RESELLER</div><form action="/user/create" method="post"><input name="username" placeholder="Username" required><input name="password" type="password" placeholder="Password" required><select name="role"><option value="reseller">Reseller</option><option value="admin">Admin</option></select><input name="credits" type="number" placeholder="Credits" value="50"><button type="submit" class="btn btn-cyan">+ Create User</button></form></div>
    <div class="action-box"><div class="box-title">🛡️ FIREWALL (BAN)</div><form action="/block/add" method="post"><input name="ident" placeholder="HWID or IP Address" required><button type="submit" class="btn btn-red">🚫 Ban Target</button></form></div>""" if u["role"] in ["super_owner", "owner"] else ""

    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>TARGET - Control Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
        body { background: #07090e; color: #f1f5f9; padding-bottom: 80px; }
        .header { background: #0b0f19; border-bottom: 1px solid #161f33; padding: 14px 18px; display: flex; justify-content: space-between; align-items: center; position: sticky; top:0; z-index: 100; }
        .brand { font-family: 'Rajdhani', sans-serif; font-size: 20px; font-weight: 800; color: #00ff88; letter-spacing: 2px; }
        .user-pill { background: #131b2e; border: 1px solid #1f2c4a; padding: 6px 12px; border-radius: 20px; font-size: 11px; display: flex; align-items: center; gap: 8px; }
        .container { padding: 14px; max-width: 1000px; margin: 0 auto; }
        .alert-banner { background: linear-gradient(90deg, rgba(0,255,136,0.1), rgba(14,19,31,0.9)); border: 1px solid rgba(0,255,136,0.3); border-left: 4px solid #00ff88; border-radius: 12px; padding: 12px 14px; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; }
        .stats-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 16px; }
        @media(min-width: 768px) { .stats-grid { grid-template-columns: repeat(4, 1fr); } }
        .stat-card { background: #0e1322; border: 1px solid #172036; border-radius: 12px; padding: 14px; position: relative; }
        .stat-card::after { content:''; position: absolute; top:0; left:0; width:100%; height:3px; }
        .stat-card.c-green::after { background: #00ff88; }
        .stat-card.c-blue::after { background: #38bdf8; }
        .stat-card.c-yellow::after { background: #f59e0b; }
        .stat-card.c-purple::after { background: #a855f7; }
        .stat-num { font-family: 'Rajdhani', sans-serif; font-size: 24px; font-weight: 800; color: #fff; margin: 4px 0; }
        .stat-lbl { font-size: 11px; color: #718096; }
        .actions-grid { display: grid; grid-template-columns: 1fr; gap: 12px; margin-bottom: 16px; }
        @media(min-width: 768px) { .actions-grid { grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); } }
        .action-box { background: #0e1322; border: 1px solid #172036; border-radius: 12px; padding: 16px; }
        .box-title { font-family: 'Rajdhani', sans-serif; font-size: 15px; font-weight: 700; color: #f8fafc; letter-spacing: 1px; margin-bottom: 12px; }
        select, input { width: 100%; padding: 10px; background: #07090e; border: 1px solid #1c263f; border-radius: 8px; color: #fff; font-size: 12px; margin-bottom: 8px; outline: none; }
        .btn { width: 100%; padding: 10px; border: none; border-radius: 8px; font-weight: 700; font-size: 12px; text-transform: uppercase; cursor: pointer; }
        .btn-green { background: #00ff88; color: #07090e; }
        .btn-cyan { background: #38bdf8; color: #07090e; }
        .btn-red { background: #ef4444; color: #fff; }
        .table-card { background: #0e1322; border: 1px solid #172036; border-radius: 12px; padding: 16px; margin-bottom: 16px; }
        .table-responsive { overflow-x: auto; width: 100%; margin-top: 8px; }
        table { width: 100%; border-collapse: collapse; min-width: 500px; }
        th { background: #07090e; color: #718096; font-size: 10px; text-transform: uppercase; padding: 10px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #141c2e; font-size: 12px; }
        .btn-sm { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-decoration: none; margin-right: 4px; }
        .badge { padding: 3px 6px; border-radius: 4px; font-size: 9px; font-weight: 800; }
        .badge.active { background: rgba(0,255,136,0.15); color: #00ff88; }
        .badge.unused { background: rgba(245,158,11,0.15); color: #f59e0b; }
        .badge.expired { background: rgba(239,68,68,0.15); color: #ef4444; }
        .badge.pending { background: rgba(56,189,248,0.15); color: #38bdf8; }
        .badge.role { background: rgba(168,85,247,0.15); color: #a855f7; }
    </style>
</head>
<body>
    <div class="header">
        <div class="brand">🛡️ TARGET PANEL</div>
        <div class="user-pill">
            <span>👤 __USERNAME__ (__ROLE__)</span>
            <span style="color:#00ff88;font-weight:bold;">⚡ __CREDITS__ CR</span>
            <a href="/logout" style="color:#ef4444;text-decoration:none;font-weight:bold;margin-left:4px;">Logout</a>
        </div>
    </div>
    <div class="container">
        <div class="alert-banner">
            <div>
                <div style="font-size:12px;font-weight:600;color:#00ff88;">🔥 SYSTEM ONLINE</div>
                <div style="font-size:10px;color:#94a3b8;">Verification Engine Active</div>
            </div>
            <div style="color:#00ff88;">✓</div>
        </div>
        <div class="stats-grid">
            <div class="stat-card c-green"><div class="stat-num">__TOT_KEYS__</div><div class="stat-lbl">Total Keys</div></div>
            <div class="stat-card c-blue"><div class="stat-num">__USED_KEYS__</div><div class="stat-lbl">Used Keys</div></div>
            <div class="stat-card c-yellow"><div class="stat-num">__UNUSED_KEYS__</div><div class="stat-lbl">Unused Keys</div></div>
            <div class="stat-card c-purple"><div class="stat-num">__TOT_RESELLERS__</div><div class="stat-lbl">Resellers</div></div>
        </div>
        <div class="actions-grid">
            <div class="action-box">
                <div class="box-title">⚡ GENERATE KEY</div>
                <form action="/key/create" method="post">
                    <select name="duration">
                        <option value="1">1 Hour (0.1 Credit)</option>
                        <option value="2">2 Hours (0.2 Credit)</option>
                        <option value="5">5 Hours (0.5 Credit)</option>
                        <option value="6">6 Hours (0.6 Credit)</option>
                        <option value="12">12 Hours (1 Credit)</option>
                        <option value="24">1 Day (2 Credits)</option>
                        <option value=

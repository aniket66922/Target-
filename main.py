import sqlite3, secrets, string, hashlib, time
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
        c.execute("CREATE TABLE IF NOT EXISTS referral_codes (code TEXT PRIMARY KEY, role TEXT, credits REAL, created_by TEXT, created_at TEXT)")
        if not c.execute("SELECT * FROM users WHERE username='owner'").fetchone():
            c.execute("INSERT INTO users (username, password_hash, role, credits, status, created_by) VALUES ('owner', ?, 'super_owner', 999999, 'active', 'system')", (hash_pw("owner1234"),))
init()

def get_user(token: str = Cookie(None)):
    if not token or ":" not in token: return None
    try:
        parts = token.split(":")
        if len(parts) != 3: return None
        user, role, login_time = parts
        
        # 10 Minutes (600 Seconds) Session Expiry Check
        if time.time() - float(login_time) > 600:
            return None

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

@app.get("/owner", response_class=HTMLResponse)
def owner_login_page():
    return """<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Owner Portal - Target Master</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;font-family:sans-serif;}
body{background:#05060a;color:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh;padding:20px;}
.box{background:#0b0e18;border:1px solid #ff0055;padding:32px 24px;border-radius:20px;width:100%;max-width:340px;text-align:center;box-shadow:0 0 30px rgba(255,0,85,0.25);}
h2{color:#ff0055;font-size:20px;letter-spacing:2px;margin-bottom:6px;}
p{font-size:11px;color:#94a3b8;margin-bottom:20px;}
input{width:100%;padding:12px;margin:8px 0;background:#05070e;border:1px solid #1f293d;color:#fff;border-radius:10px;font-size:13px;outline:none;}
button{width:100%;padding:12px;background:#ff0055;color:#fff;border:none;border-radius:10px;font-weight:bold;cursor:pointer;margin-top:10px;font-size:13px;}
</style>
</head>
<body>
<div class="box">
<h2>👑 MASTER ACCESS</h2>
<p>Authorized Super-Owners Only</p>
<form action="/auth/login" method="post">
<input name="username" placeholder="Master Username" required>
<input name="password" type="password" placeholder="Master Password" required>
<button type="submit">AUTHENTICATE MASTER</button>
</form>
</div>
</body>
</html>"""

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return """<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Reseller Portal - Target Core</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;font-family:sans-serif;}
body{background:#07090e;color:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh;padding:20px;}
.box{background:#0e131f;border:1px solid #1a233a;padding:32px 24px;border-radius:20px;width:100%;max-width:340px;text-align:center;}
h2{color:#00ff88;font-size:20px;letter-spacing:2px;margin-bottom:18px;}
input{width:100%;padding:12px;margin:8px 0;background:#070a12;border:1px solid #1f293d;color:#fff;border-radius:10px;font-size:13px;outline:none;}
button{width:100%;padding:12px;background:#00ff88;color:#07090e;border:none;border-radius:10px;font-weight:bold;cursor:pointer;margin-top:10px;font-size:13px;}
a{color:#00ff88;text-decoration:none;font-size:12px;font-weight:bold;}
</style>
</head>
<body>
<div class="box">
<h2>⚡ RESELLER LOGIN</h2>
<form action="/auth/login" method="post">
<input name="username" placeholder="Username" required>
<input name="password" type="password" placeholder="Password" required>
<button type="submit">SIGN IN</button>
</form>
<div style="margin-top:16px;"><a href="/register">Have Invite Code? Register</a></div>
</div>
</body>
</html>"""

@app.get("/register", response_class=HTMLResponse)
def register_page():
    return """<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Register - Target Core</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;font-family:sans-serif;}
body{background:#07090e;color:#fff;display:flex;justify-content:center;align-items:center;min-height:100vh;padding:20px;}
.box{background:#0e131f;border:1px solid rgba(56,189,248,0.3);padding:32px 24px;border-radius:20px;width:100%;max-width:340px;text-align:center;}
h2{color:#38bdf8;font-size:20px;letter-spacing:2px;margin-bottom:6px;}
p{font-size:11px;color:#94a3b8;margin-bottom:18px;}
input{width:100%;padding:12px;margin:8px 0;background:#070a12;border:1px solid #1f293d;color:#fff;border-radius:10px;font-size:13px;outline:none;}
button{width:100%;padding:12px;background:#38bdf8;color:#07090e;border:none;border-radius:10px;font-weight:bold;cursor:pointer;margin-top:10px;font-size:13px;}
a{color:#38bdf8;text-decoration:none;font-size:12px;font-weight:bold;}
</style>
</head>
<body>
<div class="box">
<h2>🎟️ INVITE REGISTER</h2>
<p>Valid 1-Time Referral Code Required</p>
<form action="/auth/register" method="post">
<input name="ref_code" placeholder="Referral Code (e.g. REF-XXXX)" required style="border-color:#38bdf8;">
<input name="username" placeholder="Choose Username" required>
<input name="password" type="password" placeholder="Choose Password" required>
<button type="submit">CREATE RESELLER ACCOUNT</button>
</form>
<div style="margin-top:16px;"><a href="/login">Back to Login</a></div>
</div>
</body>
</html>"""

@app.post("/auth/register")
def auth_register(ref_code: str = Form(...), username: str = Form(...), password: str = Form(...)):
    ref_code = ref_code.strip()
    with db() as c:
        ref = c.execute("SELECT * FROM referral_codes WHERE code=?", (ref_code,)).fetchone()
        if not ref:
            return HTMLResponse("<script>alert('Invalid or Expired Referral Code!');location.href='/register';</script>")
        exist = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if exist:
            return HTMLResponse("<script>alert('Username already taken');location.href='/register';</script>")
        
        c.execute("INSERT INTO users (username, password_hash, role, credits, status, created_by) VALUES (?, ?, ?, ?, 'active', ?)", 
                  (username, hash_pw(password), ref["role"], ref["credits"], f"ref_by_{ref['created_by']}"))
        c.execute("DELETE FROM referral_codes WHERE code=?", (ref_code,))
        
    return HTMLResponse("<script>alert('Account Created! You can login now.');location.href='/login';</script>")

@app.post("/auth/login")
def auth_login(username: str = Form(...), password: str = Form(...)):
    with db() as c:
        u = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not u or u["password_hash"] != hash_pw(password) or u["status"] == "banned":
        return HTMLResponse("<script>alert('Invalid Login Credentials');history.back();</script>")
        
    # Cookie with 10-minute validity timestamp
    current_time = str(time.time())
    token = f"{u['username']}:{u['role']}:{current_time}"
    res = RedirectResponse("/dashboard", status_code=302)
    res.set_cookie("token", token, max_age=600, httponly=True)
    return res

@app.get("/logout")
def logout():
    res = RedirectResponse("/login")
    res.delete_cookie("token")
    return res

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(u: dict = Depends(get_user)):
    if not u: return RedirectResponse("/login")
    is_master = u["role"] in ["super_owner", "owner"]
    
    with db() as c:
        if is_master:
            keys = c.execute("SELECT * FROM licenses ORDER BY rowid DESC").fetchall()
            active_users = c.execute("SELECT * FROM users WHERE username!='owner' ORDER BY id DESC").fetchall()
            referrals = c.execute("SELECT * FROM referral_codes ORDER BY rowid DESC").fetchall()
        else:
            keys = c.execute("SELECT * FROM licenses WHERE created_by=? ORDER BY rowid DESC", (u["username"],)).fetchall()
            active_users = []
            referrals = []
            
    tot_keys = len(keys)
    used_keys = sum(1 for k in keys if k["status"] == "active")
    unused_keys = sum(1 for k in keys if k["status"] == "unused")
    tot_resellers = len(active_users)

    k_tr = "".join([f"<tr><td style='color:#00f0ff;font-weight:bold;font-family:monospace;'>{k['key']}</td><td>{k['duration_hours']}h</td><td><span class='badge {k['status']}'>{k['status'].upper()}</span></td><td style='color:#94a3b8;font-family:monospace;font-size:11px;'>{k['hwid'] or '-'}</td><td style='color:#94a3b8;font-size:11px;'>{k['expiry_at'] or '-'}</td><td><button class='btn-copy' onclick=\"copyKey('{k['key']}', this)\">Copy</button><a href='/hwid/{k['key']}' style='color:#38bdf8;font-size:11px;text-decoration:none;margin-left:6px;'>Reset</a><a href='/kdel/{k['key']}' style='color:#ef4444;font-size:11px;text-decoration:none;margin-left:6px;'>Del</a></td></tr>" for k in keys])
    
    admin_boxes = ""
    ref_section = ""
    u_section = ""
    grid_html = ""

    if is_master:
        u_tr = "".join([f"<tr><td>{x['username']}</td><td>{x['role']}</td><td style='color:#00ff88;font-weight:bold;'>{x['credits']}</td><td>{x['status']}</td><td>{x['created_by']}</td><td><a href='/udel/{x['id']}' style='color:#ef4444;text-decoration:none;'>Del</a></td></tr>" for x in active_users]) if active_users else ""
        r_tr = "".join([f"<tr><td style='color:#38bdf8;font-weight:bold;font-family:monospace;'>{r['code']}</td><td>{r['role']}</td><td>{r['credits']}</td><td>{r['created_by']}</td><td><button class='btn-copy' onclick=\"copyKey('{r['code']}', this)\">Copy</button> <a href='/ref/del/{r['code']}' style='color:#ef4444;text-decoration:none;margin-left:6px;'>Revoke</a></td></tr>" for r in referrals]) if referrals else ""

        grid_html = f"""<div class="grid">
        <div class="stat"><span>TOTAL KEYS</span><b style="color:#00f0ff;">{tot_keys}</b></div>
        <div class="stat"><span>ACTIVE KEYS</span><b style="color:#00ff88;">{used_keys}</b></div>
        <div class="stat"><span>UNUSED KEYS</span><b style="color:#ffb703;">{unused_keys}</b></div>
        <div class="stat"><span>ALL USERS</span><b style="color:#a855f7;">{tot_resellers}</b></div>
        </div>"""

        admin_boxes = """<div class='card' style='border-color:rgba(56,189,248,0.3);'>
        <h3 style='color:#38bdf8;'>🎟️ CREATE 1-TIME REFERRAL CODE</h3>
        <form action='/ref/create' method='post'>
        <select name='role'><option value='reseller'>For Reseller</option><option value='admin'>For Admin</option></select>
        <input name='credits' type='number' placeholder='Starting Credits' value='20'>
        <button type='submit' style='background:#38bdf8;color:#07090e;'>+ Generate Invite Code</button>
        </form></div>
        <div class='card' style='border-color:rgba(239,68,68,0.3);'><h3 style='color:#ef4444;'>🚫 FIREWALL IP/HWID BAN</h3><form action='/block/add' method='post'><input name='ident' placeholder='Target HWID or IP' required><button type='submit' style='background:#ef4444;color:#fff;'>Block Permanently</button></form></div>"""

        if referrals:
            ref_section = f"""<div class='card' style='border-color:rgba(56,189,248,0.3);'><h3 style='color:#38bdf8;'>🎟️ ACTIVE 1-TIME REFERRAL CODES</h3><div class='tbl'><table><tr><th>Code</th><th>Role</th><th>Credits</th><th>Created By</th><th>Action</th></tr>{r_tr}</table></div></div>"""
        if active_users:
            u_section = f"<div class='card'><h3>👥 ALL RESELLERS / USERS</h3><div class='tbl'><table><tr><th>User</th><th>Role</th><th>Credits</th><th>Status</th><th>Source</th><th>Action</th></tr>{u_tr}</table></div></div>"
    else:
        grid_html = f"""<div class="grid" style="grid-template-columns: repeat(3, 1fr);">
        <div class="stat"><span>MY KEYS</span><b style="color:#00f0ff;">{tot_keys}</b></div>
        <div class="stat"><span>ACTIVE</span><b style="color:#00ff88;">{used_keys}</b></div>
        <div class="stat"><span>UNUSED</span><b style="color:#ffb703;">{unused_keys}</b></div>
        </div>"""

    tpl = """<!DOCTYPE html>
<html lang="en">
<head>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Dashboard - Target Core</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;font-family:sans-serif;}
body{background:#07090e;color:#f1f5f9;margin:0;padding:12px 14px 40px 14px;}
.header{display:flex;justify-content:space-between;align-items:center;background:#0e131f;padding:14px 16px;border-radius:14px;border:1px solid #1a233a;margin-bottom:12px;}
.brand{font-size:18px;font-weight:bold;color:#00ff88;letter-spacing:1px;}
.user-tag{display:flex;align-items:center;gap:10px;font-size:12px;}
.credits-pill{background:rgba(0, 255, 136, 0.12);border:1px solid rgba(0, 255, 136, 0.3);color:#00ff88;padding:4px 10px;border-radius:10px;font-weight:bold;}
.session-timer{font-size:11px;color:#f59e0b;font-weight:bold;}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:12px;}
.stat{background:#0e131f;border:1px solid #1a233a;padding:14px 10px;border-radius:12px;text-align:center;}
.stat b{font-size:22px;display:block;margin-top:4px;}
.stat span{font-size:10px;color:#94a3b8;font-weight:bold;}
.card{background:#0e131f;padding:16px;border-radius:14px;border:1px solid #1a233a;margin-bottom:12px;}
.card-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;}
.card h3{margin:0;font-size:14px;color:#f8fafc;font-weight:bold;}
.menu-container{position:relative;display:inline-block;}
.dots-btn{background:rgba(255,255,255,0.05);border:1px solid #1f293d;color:#fff;border-radius:6px;padding:4px 10px;font-size:14px;cursor:pointer;}
.dropdown-content{display:none;position:absolute;right:0;top:28px;background:#070a12;border:1px solid #1f293d;border-radius:8px;min-width:120px;box-shadow:0 10px 25px rgba(0,0,0,0.8);z-index:99;}
.dropdown-content a{color:#f8fafc;padding:8px 12px;text-decoration:none;font-size:11px;display:block;}
.dropdown-content a:hover{background:#1f293d;color:#00ff88;}
.show{display:block;}
.radio-group{display:flex;gap:15px;margin-bottom:10px;font-size:12px;}
.radio-group label{cursor:pointer;display:flex;align-items:center;gap:5px;}
input,select{{width:100%;padding:11px;margin:5px 0;background:#070a12;border:1px solid #1f293d;color:#fff;border-radius:8px;font-size:12px;outline:none;}
button{width:100%;padding:11px;border:none;border-radius:8px;font-weight:bold;font-size:12px;cursor:pointer;margin-top:6px;}
.tbl{overflow-x:auto;width:100%;margin-top:8px;}
table{width:100%;border-collapse:collapse;min-width:440px;font-size:12px;}
th{background:#070a12;color:#94a3b8;padding:8px;text-align:left;font-size:10px;text-transform:uppercase;}
td{padding:8px;border-bottom:1px solid #161f33;}
.btn-copy{display:inline-block;padding:4px 8px;background:rgba(0,255,136,0.15);border:1px solid #00ff88;color:#00ff88;border-radius:5px;font-size:10px;font-weight:bold;cursor:pointer;}
.btn-copy.copied{background:#00ff88;color:#07090e;}
.badge{padding:2px 6px;border-radius:4px;font-size:9px;font-weight:bold;}
.badge.active{background:rgba(0,255,136,0.15);color:#00ff88;}
.badge.unused{background:rgba(255,183,3,0.15);color:#ffb703;}
.badge.expired{background:rgba(239,68,68,0.15);color:#ef4444;}
</style>
</head>
<body>
<div class="header">
<div class="brand">⚡ TARGET CONTROL</div>
<div class="user-tag">
<span class="session-timer" id="timerDisplay">⏱️ 10:00</span>
<span class="credits-pill">⚡ __CREDITS__ CR</span>
<a href="/logout" style="color:#ef4444;font-weight:bold;text-decoration:none;font-size:12px;">Logout</a>
</div>
</div>

__GRID_HTML__

<div class="card" style="border-color:rgba(0,255,136,0.3);">
<div class="card-header">
<h3 style="color:#00ff88;">⚡ GENERATE LICENSE</h3>
<div class="menu-container">
<button class="dots-btn" onclick="toggleMenu()">⋮</button>
<div id="dotsDropdown" class="dropdown-content">
<a href="javascript:location.reload()">🔄 Refresh</a>
<a href="javascript:alert('Pricing: 1h=0.1, 12h=1, 1d=2, 30d=30 Credits')">💡 Rate List</a>
</div>
</div>
</div>

<form action="/key/create" method="post">
<div class="radio-group">
<label><input type="radio" name="key_type" value="random" checked onclick="toggleCustomBox(false)"> Random Key</label>
<label><input type="radio" name="key_type" value="custom" onclick="toggleCustomBox(true)"> Custom Key</label>
</div>

<div id="customKeyBox" style="display:none;">
<input name="custom_key_name" placeholder="Enter Custom Key (e.g. VIP-ROHAN)">
</div>

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
<button type="submit" style="background:#00ff88;color:#07090e;">+ CREATE KEY</button>
</form>
</div>

__ADMIN_BOXES__
__REF_SECTION__
__U_SECTION__

<div class="card">
<h3>🔑 LICENSE KEYS DIRECTORY</h3>
<div class="tbl">
<table>
<tr><th>Key</th><th>Duration</th><th>Status</th><th>HWID</th><th>Expiry</th><th>Action</th></tr>
__KEYS_ROWS__
</table>
</div>
</div>

<script>
// 10-Minute Auto-Logout Timer (600 Seconds)
var timeLeft = 600;
var timerElem = document.getElementById("timerDisplay");
var timerInterval = setInterval(function() {
  timeLeft--;
  var m = Math.floor(timeLeft / 60);
  var s = timeLeft % 60;
  timerElem.innerText = "⏱️ " + (m < 10 

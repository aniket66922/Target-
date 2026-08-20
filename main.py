    from fastapi import FastAPI, HTTPException, Request, Form, Depends, Cookie, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
import sqlite3
import secrets
import string
import time
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext

app = FastAPI(title="Licensing Control SaaS")
DB_NAME = "database.db"
SECRET_KEY = "SUPER_SECURE_JWT_SECRET_KEY_CHANGEME_IN_PRODUCTION"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ----------------- DATABASE INITIALIZATION -----------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    
    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            credits REAL DEFAULT 0,
            status TEXT DEFAULT 'active',
            created_by TEXT DEFAULT 'system',
            created_at TEXT NOT NULL
        )
    """)
    
    # Licenses table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            duration_hours REAL NOT NULL,
            credit_cost REAL NOT NULL,
            created_by TEXT NOT NULL,
            status TEXT DEFAULT 'unused',
            hwid TEXT DEFAULT NULL,
            created_at TEXT NOT NULL,
            activated_at TEXT DEFAULT NULL,
            expiry_at TEXT DEFAULT NULL
        )
    """)
    
    # Blacklist table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            identifier TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            reason TEXT DEFAULT 'Blocked by Super Owner',
            blocked_at TEXT NOT NULL
        )
    """)
    
    # Default Super Owner Check
    cursor.execute("SELECT * FROM users WHERE username = 'owner'")
    if not cursor.fetchone():
        default_hash = pwd_context.hash("owner1234")
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, credits, created_at) VALUES (?, ?, ?, ?, ?)",
            ("owner", default_hash, "super_owner", 999999, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
        )
    conn.commit()
    conn.close()

init_db()

# ----------------- SECURITY & HELPERS -----------------
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def is_blacklisted(identifier: str):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT identifier FROM blacklist WHERE identifier = ?", (identifier,))
    row = cursor.fetchone()
    conn.close()
    return bool(row)

def create_jwt_token(username: str, role: str):
    payload = {
        "sub": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(days=2)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Cookie(None)):
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        if user and user["status"] == "active":
            return dict(user)
    except Exception:
        return None
    return None

# Rate Limiter (IP Based)
request_history = {}
def check_rate_limit(ip: str, max_requests=20, window_seconds=60):
    now = time.time()
    if ip not in request_history:
        request_history[ip] = []
    request_history[ip] = [t for t in request_history[ip] if now - t < window_seconds]
    if len(request_history[ip]) >= max_requests:
        return False
    request_history[ip].append(now)
    return True

# ----------------- LOADER / CLIENT API -----------------
class VerifyRequest(BaseModel):
    key: str
    hwid: str

@app.post("/api/verify")
def verify_license(data: VerifyRequest, request: Request):
    client_ip = request.client.host
    
    if not check_rate_limit(client_ip, max_requests=10, window_seconds=60):
        raise HTTPException(status_code=429, detail="Too Many Requests. Try later.")
        
    if is_blacklisted(client_ip) or is_blacklisted(data.hwid):
        raise HTTPException(status_code=403, detail="Device or IP is permanently banned.")
        
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM licenses WHERE key = ?", (data.key,))
    lic = cursor.fetchone()
    
    if not lic:
        conn.close()
        raise HTTPException(status_code=404, detail="Invalid License Key.")
        
    status = lic["status"]
    stored_hwid = lic["hwid"]
    duration_hours = lic["duration_hours"]
    now = datetime.utcnow()
    
    if status == "banned":
        conn.close()
        raise HTTPException(status_code=403, detail="Key has been banned.")
        
    if status == "unused":
        expiry_time = now + timedelta(hours=duration_hours)
        act_str = now.strftime("%Y-%m-%d %H:%M:%S")
        exp_str = expiry_time.strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "UPDATE licenses SET status = 'active', hwid = ?, activated_at = ?, expiry_at = ? WHERE key = ?",
            (data.hwid, act_str, exp_str, data.key)
        )
        conn.commit()
        conn.close()
        return {"status": "success", "message": "Key activated successfully", "expiry": exp_str}
        
    if stored_hwid != data.hwid:
        conn.close()
        raise HTTPException(status_code=403, detail="HWID mismatch. Key locked to another device.")
        
    expiry_dt = datetime.strptime(lic["expiry_at"], "%Y-%m-%d %H:%M:%S")
    if now > expiry_dt:
        cursor.execute("UPDATE licenses SET status = 'expired' WHERE key = ?", (data.key,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=403, detail="License key expired.")
        
    conn.close()
    return {"status": "success", "message": "License valid", "expiry": lic["expiry_at"]}

# ----------------- UI & DASHBOARD TEMPLATE -----------------
@app.get("/login", response_class=HTMLResponse)
def login_page():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - License Control</title>
        <style>
            * { box-sizing: border-box; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; }
            body { background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; }
            .card { background: #1e293b; padding: 32px; border-radius: 12px; width: 100%; max-width: 400px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); border: 1px solid #334155; }
            h2 { color: #10b981; margin-bottom: 20px; text-align: center; }
            input { width: 100%; padding: 12px; margin-bottom: 16px; background: #0f172a; border: 1px solid #475569; border-radius: 6px; color: #fff; }
            button { width: 100%; padding: 12px; background: #10b981; border: none; border-radius: 6px; color: #0f172a; font-weight: bold; cursor: pointer; }
            button:hover { background: #059669; }
        </style>
    </head>
    <body>
        <div class="card">
            <h2>System Login</h2>
            <form action="/auth/login" method="post">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Secure Login</button>
            </form>
        </div>
    </body>
    </html>
    """

@app.post("/auth/login")
def auth_login(username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if not user or not pwd_context.verify(password, user["password_hash"]):
        return HTMLResponse("<script>alert('Invalid Credentials'); window.location.href='/login';</script>")
    
    if user["status"] == "banned":
        return HTMLResponse("<script>alert('Account Suspended'); window.location.href='/login';</script>")
        
    token = create_jwt_token(user["username"], user["role"])
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="token", value=token, httponly=True, max_age=172800)
    return response

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login")
    response.delete_cookie("token")
    return response

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
        
    conn = get_db()
    cursor = conn.cursor()
    
    # Stats logic based on role
    if user["role"] in ["super_owner", "owner"]:
        cursor.execute("SELECT COUNT(*) FROM licenses")
        total_keys = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM licenses WHERE status = 'active'")
        active_keys = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM licenses WHERE status = 'unused'")
        unused_keys = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM users")
        total_users = cursor.fetchone()[0]
        cursor.execute("SELECT * FROM licenses ORDER BY created_at DESC LIMIT 50")
        keys = cursor.fetchall()
        cursor.execute("SELECT * FROM users ORDER BY id DESC")
        all_users = cursor.fetchall()
        cursor.execute("SELECT * FROM blacklist")
        blacklists = cursor.fetchall()
    else:
        cursor.execute("SELECT COUNT(*) FROM licenses WHERE created_by = ?", (user["username"],))
        total_keys = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM licenses WHERE created_by = ? AND status = 'active'", (user["username"],))
        active_keys = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM licenses WHERE created_by = ? AND status = 'unused'", (user["username"],))
        unused_keys = cursor.fetchone()[0]
        total_users = 0
        cursor.execute("SELECT * FROM licenses WHERE created_by = ? ORDER BY created_at DESC", (user["username"],))
        keys = cursor.fetchall()
        all_users = []
        blacklists = []
        
    conn.close()
    
    # Render Tables
    keys_rows = "".join(f"""
        <tr>
            <td>{k['key']}</td>
            <td>{k['duration_hours']}h</td>
            <td><span class="badge {k['status']}">{k['status']}</span></td>
            <td>{k['hwid'] or 'None'}</td>
            <td>{k['expiry_at'] or 'Not Activated'}</td>
            <td>{k['created_by']}</td>
            <td>
                <a href="/reset-hwid/{k['key']}" style="color:#38bdf8; text-decoration:none; margin-right:8px;">Reset HWID</a>
                <a href="/delete-key/{k['key']}" style="color:#ef4444; text-decoration:none;">Delete</a>
            </td>
        </tr>
    """ for k in keys)

    user_rows = "".join(f"""
        <tr>
            <td>{u['username']}</td>
            <td><span class="badge role">{u['role']}</span></td>
            <td>{u['credits']}</td>
            <td>{u['status']}</td>
            <td>{u['created_by']}</td>
            <td>
                {f"<a href='/user/demote/{u['id']}' style='color:#f59e0b; margin-right:8px;'>Demote/Ban</a><a href='/user/delete/{u['id']}' style='color:#ef4444;'>Delete</a>" if user['role'] == 'super_owner' and u['role'] != 'super_owner' else '-'}
            </td>
        </tr>
    """ for u in all_users) if user["role"] in ["super_owner", "owner"] else ""

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Dashboard - Control Panel</title>
        <style>
            * {{ box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; }}
            body {{ background: #0b0f19; color: #f1f5f9; padding: 20px; }}
            .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; border-bottom: 1px solid #1e293b; padding-bottom: 16px; }}
            .brand {{ font-size: 22px; font-weight: bold; color: #10b981; letter-spacing: 1px; }}
            .user-tag {{ background: #1e293b; padding: 8px 16px; border-radius: 20px; font-size: 14px; }}
            .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 24px; }}
            .stat-card {{ background: #131d2e; border: 1px solid #1e293b; padding: 20px; border-radius: 10px; }}
            .stat-title {{ color: #94a3b8; font-size: 13px; margin-bottom: 8px; }}
            .stat-val {{ font-size: 24px; font-weight: bold; color: #38bdf8; }}
            .box {{ background: #131d2e; border: 1px solid #1e293b; border-radius: 10px; padding: 20px; margin-bottom: 24px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
            th, td {{ padding: 12px; border-bottom: 1px solid #1e293b; font-size: 13px; text-align: left; }}
            th {{ background: #0f172a; color: #94a3b8; }}
            .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }}
            .badge.active {{ background: rgba(16,185,129,0.2); color: #10b981; }}
            .badge.unused {{ background: rgba(245,158,11,0.2); color: #f59e0b; }}
            .badge.expired {{ background: rgba(239,68,68,0.2); color: #ef4444; }}
            .badge.role {{ background: rgba(56,189,248,0.2); color: #38bdf8; }}
            input, select, button {{ padding: 10px; background: #0b0f19; border: 1px solid #334155; border-radius: 6px; color: #fff; margin-right: 8px; margin-bottom: 8px; }}
            button {{ background: #10b981; color: #0b0f19; font-weight: bold; cursor: pointer; border: none; }}
        </style>
    </head>
    <body>
        <div class="header">
            <div class="brand">⚡ SYSTEM CONTROL PANEL</div>
            <div class="user-tag">Logged: <b>{user['username']}</b> ({user['role'].upper()}) | Credits: <b>{user['credits']}</b> | <a href="/logout" style="color:#ef4444; text-decoration:none; margin-left:10px;">Logout</a></div>
        </div>

        <div class="stats">
            <div class="stat-card"><div class="stat-title">Total Keys</div><div class="stat-val">{total_keys}</div></div>
            <div class="stat-card"><div class="stat-title">Active Keys</div><div class="stat-val" style="color:#10b981;">{active_keys}</div></div>
            <div class="stat-card"><div class="stat-title">Unused Keys</div><div class="stat-val" style="color:#f59e0b;">{unused_keys}</div></div>
            {'<div class="stat-card"><div class="stat-title">Total Users</div><div class="stat-val">' + str(total_users) + '</div></div>' if user['role'] in ['super_owner', 'owner'] else ''}
        </div>

        <!-- GENERATE KEY SECTION -->
        <div class="box">
            <h3>Generate License Key</h3>
            <form action="/key/create" method="post" style="margin-top: 14px;">
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
                <button type="submit">+ Create Key</button>
            </form>
        </div>

        <!-- USER CREATION FOR SUPER OWNER / OWNER -->
        {'<div class="box"><h3>Create User / Reseller</h3><form action="/user/create" method="post" style="margin-top:14px;"><input type="text" name="username" placeholder="Username" required><input type="password" name="password" placeholder="Password" required><select name="role"><option value="reseller">Reseller</option><option value="admin">Admin</option><option value="owner">Sub-Owner</option></select><input type="number" name="credits" placeholder="Credits" value="10" required><button type="submit">+ Create User</button></form></div>' if user['role'] in ['super_owner', 'owner'] else ''}

        <!-- DEVICE BLACKLIST SECTION -->
        {'<div class="box"><h3>Device & IP Firewall</h3><form action="/blacklist/add" method="post" style="margin-top:14px;"><input type="text" name="identifier" placeholder="HWID or IP Address" required><select name="type"><option value="hwid">Device HWID</option><option value="ip">IP Address</option></select><button type="submit" style="background:#ef4444; color:#fff;">Ban / Block Device</button></form></div>' if user['role'] in ['super_owner', 'owner'] else ''}

        <!-- USERS TABLE -->
        {'<div class="box"><h3>Manage Users</h3><div style="overflow-x:auto;"><table><thead><tr><th>Username</th><th>Role</th><th>Credits</th><th>Status</th><th>Created By</th><th>Actions</th></tr></thead><tbody>' + user_rows + '</tbody></table></div></div>' if user['role'] in ['super_owner', 'owner'] else ''}

        <!-- KEYS TABLE -->
        <div class="box">
            <h3>License Keys History</h3>
            <div style="overflow-x:auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Key</th><th>Duration</th><th>Status</th><th>HWID</th><th>Expiry</th><th>Creator</th><th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {keys_rows}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    """

# ----------------- ACTION ENDPOINTS -----------------
@app.post("/key/create")
def create_key(duration: float = Form(...), user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
        
    credit_costs = {1: 0.1, 2: 0.2, 5: 0.5, 6: 0.6, 12: 1.0, 24: 2.0, 168: 10.0, 360: 18.0, 720: 30.0}
    cost = credit_costs.get(int(duration), 1.0)
    
    if user["role"] != "super_owner" and user["credits"] < cost:
        return HTMLResponse("<script>alert('Insufficient Credits'); window.location.href='/dashboard';</script>")
        
    key_str = "KEY-" + "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT INTO licenses (key, duration_hours, credit_cost, created_by, created_at)
        VALUES (?, ?, ?, ?, ?)
    """, (key_str, duration, cost, user["username"], datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
    
    if user["role"] != "super_owner":
        cursor.execute("UPDATE users SET credits = credits - ? WHERE id = ?", (cost, user["id"]))
        
    conn.commit()
    conn.close()
    return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)

@app.get("/reset-hwid/{key}")
def reset_hwid(key: str, user: dict = Depends(get_current_user)):
    if not user:
        return RedirectResponse(url="/login")
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE licenses SET hwid = NULL WHERE key = ?", (key,))
    conn.commit()
    conn.close()
    return RedirectResponse(

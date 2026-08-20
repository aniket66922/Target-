from fastapi import FastAPI, HTTPException, Request, Form
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import sqlite3
import secrets
import string
from datetime import datetime, timedelta

app = FastAPI(title="License Key Management")
DB_NAME = "licenses.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            key TEXT PRIMARY KEY,
            status TEXT DEFAULT 'unused',
            hwid TEXT DEFAULT NULL,
            expiry_date TEXT DEFAULT NULL,
            duration_days INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

def generate_key_string():
    chars = string.ascii_uppercase + string.digits
    parts = [''.join(secrets.choice(chars) for _ in range(4)) for _ in range(4)]
    return '-'.join(parts)

class VerifyRequest(BaseModel):
    key: str
    hwid: str

@app.post("/api/verify")
def verify_license(data: VerifyRequest):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT status, hwid, expiry_date, duration_days FROM licenses WHERE key = ?", (data.key,))
    row = cursor.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Invalid license key.")

    status, stored_hwid, expiry_date, duration_days = row
    now = datetime.utcnow()

    if status == "unused":
        expiry = now + timedelta(days=duration_days)
        expiry_str = expiry.strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "UPDATE licenses SET status = 'active', hwid = ?, expiry_date = ? WHERE key = ?",
            (data.hwid, expiry_str, data.key)
        )
        conn.commit()
        conn.close()
        return {"status": "success", "message": "Key activated successfully", "expiry": expiry_str}

    if status == "banned":
        conn.close()
        raise HTTPException(status_code=403, detail="This key has been banned.")

    if stored_hwid != data.hwid:
        conn.close()
        raise HTTPException(status_code=403, detail="HWID mismatch. Key bound to another device.")

    expiry_dt = datetime.strptime(expiry_date, "%Y-%m-%d %H:%M:%S")
    if now > expiry_dt:
        cursor.execute("UPDATE licenses SET status = 'expired' WHERE key = ?", (data.key,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=403, detail="License key has expired.")

    conn.close()
    return {"status": "success", "message": "License is valid", "expiry": expiry_date}

@app.get("/admin", response_class=HTMLResponse)
def admin_panel():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT key, status, hwid, expiry_date, duration_days FROM licenses")
    rows = cursor.fetchall()
    conn.close()

    table_rows = "".join(f"""
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;">{r[0]}</td>
            <td style="padding: 8px; border: 1px solid #ddd;">{r[1]}</td>
            <td style="padding: 8px; border: 1px solid #ddd;">{r[2] or 'Not Bound'}</td>
            <td style="padding: 8px; border: 1px solid #ddd;">{r[3] or 'Not Activated'}</td>
            <td style="padding: 8px; border: 1px solid #ddd;">{r[4]} Days</td>
        </tr>
    """ for r in rows)

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>License Panel</title>
        <style>
            body {{ font-family: sans-serif; margin: 20px; background-color: #f4f4f9; }}
            .container {{ max-width: 900px; margin: auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th {{ background: #333; color: white; padding: 10px; }}
            input, button {{ padding: 8px; margin: 5px 0; }}
            button {{ background: #007bff; color: white; border: none; cursor: pointer; border-radius: 4px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>License Key Admin Panel</h2>
            <form action="/admin/create" method="post">
                <label>Validity (in days): </label>
                <input type="number" name="days" value="30" min="1" required>
                <button type="submit">Generate New Key</button>
            </form>
            <table>
                <thead>
                    <tr>
                        <th>License Key</th>
                        <th>Status</th>
                        <th>Bound HWID</th>
                        <th>Expiry Date</th>
                        <th>Duration</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """

@app.post("/admin/create")
def create_key(days: int = Form(...)):
    new_key = generate_key_string()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO licenses (key, duration_days) VALUES (?, ?)", (new_key, days))
    conn.commit()
    conn.close()
    return HTMLResponse(f"<script>alert('Key Created: {new_key}'); window.location.href='/admin';</script>")
  

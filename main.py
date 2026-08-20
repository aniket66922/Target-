import sqlite3, secrets, string, hashlib, time, base64
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
        c.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, role TEXT, credits REAL, status TEXT, created_by TEXT, used_code TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS licenses (key TEXT PRIMARY KEY, duration_hours REAL, credit_cost REAL, created_by TEXT, status TEXT, hwid TEXT, expiry_at TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS blacklist (identifier TEXT PRIMARY KEY)")
        c.execute("CREATE TABLE IF NOT EXISTS referral_codes (code TEXT PRIMARY KEY, role TEXT, credits REAL, created_by TEXT, created_at TEXT)")
        if not c.execute("SELECT * FROM users WHERE username='owner'").fetchone():
            c.execute("INSERT INTO users (username, password_hash, role, credits, status, created_by, used_code) VALUES ('owner', ?, 'super_owner', 999999, 'active', 'system', 'MASTER')", (hash_pw("owner1234"),))
init()

def get_user(token: str = Cookie(None)):
    if not token or ":" not in token: return None
    try:
        parts = token.split(":")
        if len(parts) != 3: return None
        user, role, login_time = parts
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

HTML_OWNER = base64.b64decode("PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PG1ldGEgbmFtZT0ndmlld3BvcnQnIGNvbnRlbnQ9J3dpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAnPjx0aXRsZT5Pd25lciBQb3J0YWw8L3RpdGxlPjxzdHlsZT4qe2JveC1zaXppbmc6Ym9yZGVyLWJveDttYXJnaW46MDtwYWRkaW5nOjA7Zm9udC1mYW1pbHk6c2Fucy1zZXJpZjt9Ym9keXtiYWNrZ3JvdW5kOiMwNTA2MGE7Y29sb3I6I2ZmZjtkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OmNlbnRlcjthbGlnbi1pdGVtczpjZW50ZXI7bWluLWhlaWdodDoxMDB2aDtwYWRkaW5nOjIwcHg7fS5ib3h7YmFja2dyb3VuZDojMGIwZTE4O2JvcmRlcjoxcHggc29saWQgI2ZmMDA1NTtwYWRkaW5nOjMycHggMjRweDtib3JkZXItcmFkaXVzOjIwcHg7d2lkdGg6MTAwJTttYXgtd2lkdGg6MzQwcHg7dGV4dC1hbGlnbjpjZW50ZXI7Ym94LXNoYWRvdzowIDAgMzBweCByZ2JhKDI1NSwwLDg1LDAuMjUpO31oMntjb2xvcjojZmYwMDU1O2ZvbnQtc2l6ZToyMHB4O2xldHRlci1zcGFjaW5nOjJweDttYXJnaW4tYm90dG9tOjZweDt9cHtmb250LXNpemU6MTFweDtjb2xvcjojOTRhM2I4O21hcmdpbi1ib3R0b206MjBweDt9aW5wdXR7d2lkdGg6MTAwJTtwYWRkaW5nOjEycHg7bWFyZ2luOjhweCAwO2JhY2tncm91bmQ6IzA1MDcwZTtib3JkZXI6MXB4IHNvbGlkICMxZjI5M2Q7Y29sb3I6I2ZmZjtib3JkZXItcmFkaXVzOjEwcHg7Zm9udC1zaXplOjEzcHg7b3V0bGluZTpub25lO31idXR0b257d2lkdGg6MTAwJTtwYWRkaW5nOjEycHg7YmFja2dyb3VuZDojZmYwMDU1O2NvbG9yOiNmZmY7Ym9yZGVyOm5vbmU7Ym9yZGVyLXJhZGl1czoxMHB4O2ZvbnQtd2VpZ2h0OmJvbGQ7Y3Vyc29yOnBvaW50ZXI7bWFyZ2luLXRvcDoxMHB4O2ZvbnQtc2l6ZToxM3B4O31hIHtjb2xvcjojZmYwMDU1O2ZvbnQtc2l6ZToxMnB4O308L3N0eWxlPjwvaGVhZD48Ym9keT48ZGl2IGNsYXNzPSdib3gnPjxoMj7imqAgTUFTVEVSIExPR0lOPC9oMj48cD5BdXRob3JpemVkIFN1cGVyLU93bmVycyBPbmx5PC9wPjxmb3JtIGFjdGlvbj0nL2F1dGgvbG9naW4nIG1ldGhvZD0ncG9zdCc+PGlucHV0IG5hbWU9J3VzZXJuYW1lJyBwbGFjZWhvbGRlcj0nTWFzdGVyIFVzZXJuYW1lJyByZXF1aXJlZD48aW5wdXQgbmFtZT0ncGFzc3dvcmQnIHR5cGU9J3Bhc3N3b3JkJyBwbGFjZWhvbGRlcj0nTWFzdGVyIFBhc3N3b3JkJyByZXF1aXJlZD48YnV0dG9uIHR5cGU9J3N1Ym1pdCc+QVVUSEVOVElDQVRFPC9idXR0b24+PC9mb3JtPjwvZGl2PjwvYm9keT48L2h0bWw+").decode('utf-8')

HTML_LOGIN = base64.b64decode("PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PG1ldGEgbmFtZT0ndmlld3BvcnQnIGNvbnRlbnQ9J3dpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAnPjx0aXRsZT5SZXNlbGxlciBQb3J0YWw8L3RpdGxlPjxzdHlsZT4qe2JveC1zaXppbmc6Ym9yZGVyLWJveDttYXJnaW46MDtwYWRkaW5nOjA7Zm9udC1mYW1pbHk6c2Fucy1zZXJpZjt9Ym9keXtiYWNrZ3JvdW5kOiMwNzA5MGU7Y29sb3I6I2ZmZjtkaXNwbGF5OmZsZXg7anVzdGlmeS1jb250ZW50OmNlbnRlcjthbGlnbi1pdGVtczpjZW50ZXI7bWluLWhlaWdodDoxMDB2aDtwYWRkaW5nOjIwcHg7fS5ib3h7YmFja2dyb3VuZDojMGUxMzFmO2JvcmRlcjoxcHggc29saWQgIzFhMjMzYTtwYWRkaW5nOjMycHggMjRweDtib3JkZXItcmFkaXVzOjIwcHg7d2lkdGg6MTAwJTttYXgtd2lkdGg6MzQwcHg7dGV4dC1hbGlnbjpjZW50ZXI7fWgye2NvbG9yOiMwMGZmODg7Zm9udC1zaXplOjIwcHg7bGV0dGVyLXNwYWNpbmc6MnB4O21hcmdpbi1ib3R0b206MThweDt9aW5wdXR7d2lkdGg6MTAwJTtwYWRkaW5nOjEycHg7bWFyZ2luOjhweCAwO2JhY2tncm91bmQ6IzA3MGExMjtib3JkZXI6MXB4IHNvbGlkICMxZjI5M2Q7Y29sb3I6I2ZmZjtib3JkZXItcmFkaXVzOjEwcHg7Zm9udC1zaXplOjEzcHg7b3V0bGluZTpub25lO31idXR0b257d2lkdGg6MTAwJTtwYWRkaW5nOjEycHg7YmFja2dyb3VuZDojMDBmZjg4O2NvbG9yOiMwNzA5MGU7Ym9yZGVyOm5vbmU7Ym9yZGVyLXJhZGl1czoxMHB4O2ZvbnQtd2VpZ2h0OmJvbGQ7Y3Vyc29yOnBvaW50ZXI7bWFyZ2luLXRvcDoxMHB4O2ZvbnQtc2l6ZToxM3B4O31he2NvbG9yOiMwMGZmODg7dGV4dC1kZWNvcmF0aW9uOm5vbmU7Zm9udC1zaXplOjEycHg7Zm9udC13ZWlnaHQ6Ym9sZDt9PC9zdHlsZT48L2hlYWQ+PGJvZHk+PGRpdiBjbGFzcz0nYm94Jz48aDI+4pqhIFJFU0VMTEVSIExPR0lOPC9oMj48Zm9ybSBhY3Rpb249Jy9hdXRoL2xvZ2luJyBtZXRob2Q9J3Bvc3QnPjxpbnB1dCBuYW1lPSd1c2VybmFtZScgcGxhY2Vob2xkZXI9J1VzZXJuYW1lJyByZXF1aXJlZD48aW5wdXQgbmFtZT0ncGFzc3dvcmQnIHR5cGU9J3Bhc3N3b3JkJyBwbGFjZWhvbGRlcj0nUGFzc3dvcmQnIHJlcXVpcmVkPjxidXR0b24gdHlwZT0nc3VibWl0Jz5TSUdOIElOPC9idXR0b24+PC9mb3JtPjxkaXYgc3R5bGU9J21hcmdpbi10b3A6MTZweDsnPjxhIGhyZWY9Jy9yZWdpc3Rlcic+SGF2ZSBJbnZpdGUgQ29kZT8gUmVnaXN0ZXI8L2E+PC9kaXY+PC9kaXY+PC9ib2R5PjwvaHRtbD4=").decode('utf-8')

HTML_REG = base64.b64decode("PCFET0NUWVBFIGh0bWw+PGh0bWw+PGhlYWQ+PG1ldGEgbmFtZT0ndmlld3BvcnQnIGNvbnRlbnQ9J3dpZHRoPWRldmljZS13aWR0aCwgaW5pdGlhbC1zY2FsZT0xLjAnPjx0aXRsZT5SZWdpc3RlciAtIFRhcmdldCBDb3JlPC90aXRsZT48c3R5bGU+Kntib3gtc2l6aW5nOmJvcmRlci1ib3g7bWFyZ2luOjA7cGFkZGluZzowO2ZvbnQtZmFtaWx5OnNhbnMtc2VyaWY7fWJvZHl7YmFja2dyb3VuZDojMDcwOTBlO2NvbG9yOiNmZmY7ZGlzcGxheTpmbGV4O2p1c3RpZnktY29udGVudDpjZW50ZXI7YWxpZ24taXRlbXM6Y2VudGVyO21pbi1oZWlnaHQ6MTAwdmg7cGFkZGluZzoyMHB4O30uYm94e2JhY2tncm91bmQ6IzBlMTMxZjtib3JkZXI6MXB4IHNvbGlkIHJnYmEoNTYsMTg5LDI0OCwwLjMpO3BhZGRpbmc6MzBweCAyNHB4O2JvcmRlci1yYWRpdXM6MjBweDt3aWR0aDoxMDAlO21heC13aWR0aDozNDBweDt0ZXh0LWFsaWduOmNlbnRlcjt9aDJ7Y29sb3I6IzM4YmRmODtmb250LXNpemU6MjBweDtsZXR0ZXItc3BhY2luZzoycHg7bWFyZ2luLWJvdHRvbTo2cHg7fXB7Zm9udC1zaXplOjExcHg7Y29sb3I6Izk0YTNjODttYXJnaW4tYm90dG9tOjE2cHg7fWlucHV0e3dpZHRoOjEwMCU7cGFkZGluZzoxMXB4O21hcmdpbjo2cHggMDtiYWNrZ3JvdW5kOiMwNzBhMTI7Ym9yZGVyOjFweCBzb2xpZCAjMWYyOTNKO2NvbG9yOiNmZmY7Ym9yZGVyLXJhZGl1czoxMHB4O2ZvbnQtc2l6ZToxM3B4O291dGxpbmU6bm9uZTt9YnV0dG9ue3dpZHRoOjEwMCU7cGFkZGluZzoxMnB4O2JhY2tncm91bmQ6IzM4YmRmODtjb2xvcjojMDcwOTBlO2JvcmRlcjpub25lO2JvcmRlci1yYWRpdXM6MTBweDtmb250LXdlaWdodDpib2xkO2N1cnNvcjpwb2ludGVyO21hcmdpbi10b3A6MTBweDtmb250LXNpemU6MTNweDt9YXtjb2xvcjojMzhiZGY4O3RleHQtZGVjb3JhdGlvbjpub25lO2ZvbnQtc2l6ZToxMnB4O2ZvbnQtd2VpZ2h0OmJvbGQ7fTwvc3R5bGU+PC9oZWFkPjxib2R5PjxkaXYgY2xhc3M9J2JveCc+PGgyPuKfjyBJTlZJVEUgUkVHSVNURVI8L2gyPjxwPlZhbGlkIEludml0ZSBDb2RlIFJlcXVpcmVkPC9wPjxmb3JtIGFjdGlvbj0nL2F1dGgvcmVnaXN0ZXInIG1ldGhvZD0ncG9zdCc+PGlucHV0IG5hbWU9J3JlZl9jb2RlJyBwbGFjZWhvbGRlcj0nRW50ZXIgSW52aXRlIENvZGUnIHJlcXVpcmVkIHN0eWxlPSdib3JkZXItY29sb3I6IzM4YmRmODsnPjxpbnB1dCBuYW1lPSd1c2VybmFtZScgcGxhY2Vob2xkZXI9J0Nob29zZSBVc2VybmFtZScgcmVxdWlyZWQ+PGlucHV0IG5hbWU9J3Bhc3N3b3JkJyB0eXBlPSdwYXNzd29yZCcgcGxhY2Vob2xkZXI9J0Nob29zZSBQYXNzd29yZCcgcmVxdWlyZWQ+PGlucHV0IG5hbWU9J2NvbmZpcm1fcGFzc3dvcmQnIHR5cGU9J3Bhc3N3b3JkJyBwbGFjZWhvbGRlcj0nQ29uZmlybSBQYXNzd29yZCcgcmVxdWlyZWQ+PGJ1dHRvbiB0eXBlPSdzdWJtaXQnPlNVQk1JVCBGT1IgQVBQUk9WQUw8L2J1dHRvbj48L2Zvcm0+PGRpdiBzdHlsZT0nbWFyZ2luLXRvcDoxNnB4Oyc+PGEgaHJlZj0nL2xvZ2luJz5CYWNrIHRvIExvZ2luPC9hPjwvZGl2PjwvZGl2PjwvYm9keT48L2h0bWw+").decode('utf-8')

HTML_DASHBOARD = base64.b64decode("PCFET0NUWVBFIGh0bWw+PGh0bWwgbGFuZz0nZW4nPjxoZWFkPjxtZXRhIG5hbWU9J3ZpZXdwb3J0JyBjb250ZW50PSd3aWR0aD1kZXZpY2Utd2lkdGgsIGluaXRpYWwtc2NhbGU9MS4wLCBtYXhpbXVtLXNjYWxlPTEuMCwgdXNlci1zY2FsYWJsZT1ubyc+PHRpdGxlPlRhcmdldCBDb250cm9sPC90aXRsZT48c3R5bGU+Kntib3gtc2l6aW5nOmJvcmRlci1ib3g7bWFyZ2luOjA7cGFkZGluZzowO2ZvbnQtZmFtaWx5OnNhbnMtc2VyaWY7fWJvZHl7YmFja2dyb3VuZDojMDcwOTBlO2NvbG9yOiNmMWY1Zjk7bWFyZ2luOjA7cGFkZGluZzoxMnB4IDE0cHggNDBweCAxNHB4O30uaGVhZGVye2Rpc3BsYXk6ZmxleDtqdXN0aWZ5LWNvbnRlbnQ6c3BhY2UtYmV0d2VlbjthbGlnbi1pdGVtczpjZW50ZXI7YmFja2dyb3VuZDojMGUxMzFmO3BhZGRpbmc6MTRweCAxNnB4O2JvcmRlci1yYWRpdXM6MTRweDtib3JkZXI6MXB4IHNvbGlkICMxYTIzM2E7bWFyZ2luLWJvdHRvbToxMnB4O30uYnJhbmR7Zm9udC1zaXplOjE4cHg7Zm9udC13ZWlnaHQ6Ym9sZDtjb2xvcjojMDBmZjg4O2xldHRlci1zcGFjaW5nOjFweDt9LnVzZXItdGFne2Rpc3BsYXk6ZmxleDthbGlnbi1pdGVtczpjZW50ZXI7Z2FwOjEwcHg7Zm9udC1zaXplOjEycHg7fS5jcmVkaXRzLXBpbGx7YmFja2dyb3VuZDpyZ2JhKDAsIDI1NSwgMTM2LCAwLjEyKTtib3JkZXI6MXB4IHNvbGlkIHJnYmEoMCwgMjU1LCAxMzYsIDAuMyk7Y29sb3I6IzAwZmY4ODtwYWRkaW5nOjRweCAxMHB4O2JvcmRlci1yYWRpdXM6MTBweDtmb250LXdlaWdodDpib2xkO30uc2Vzc2lvbi10aW1lcntmb250LXNpemU6MTFweDtjb2xvcjojZjU5ZTBiO2ZvbnQtd2VpZ2h0OmJvbGQ7fS5ncmlke2Rpc3BsYXk6Z3JpZDtncmlkLXRlbXBsYXRlLWNvbHVtbnM6cmVwZWF0KDIsMWZyKTtnYXA6MTBweDttYXJnaW4tYm90dG9tOjEycHg7fS5zdGF0e2JhY2tncm91bmQ6IzBlMTMxZjtib3JkZXI6MXB4IHNvbGlkICMxYTIzM2E7cGFkZGluZzoxNHB4IDEwcHg7Ym9yZGVyLXJhZGl1czoxMnB4O3RleHQtYWxpZ246Y2VudGVyO30uc3RhdCBie2ZvbnQtc2l6ZToyMnB4O2Rpc3BsYXk6YmxvY2s7bWFyZ2luLXRvcDo0cHg7fS5zdGF0IHNwYW57Zm9udC1zaXplOjEwcHg7Y29sb3I6Izk0YTNjODtmb250LXdlaWdodDpib2xkO30uY2FyZHtiYWNrZ3JvdW5kOiMwZTEzMWY7cGFkZGluZzoxNnB4O2JvcmRlci1yYWRpdXM6MTRweDtib3JkZXI6MXB4IHNvbGlkICMxYTIzM2E7bWFyZ2luLWJvdHRvbToxMnB4O30uY2FyZC1oZWFkZXJ7ZGlzcGxheTpmbGV4O2p1c3RpZnktY29udGVudDtzcGFjZS1iZXR3ZWVuO2FsaWduLWl0ZW1zOmNlbnRlcjttYXJnaW4tYm90dG9tOjEycHg7fS5jYXJkIGgze21hcmdpbjowO2ZvbnQtc2l6ZToxNHB4O2NvbG9yOiNmOGZhZmM7Zm9udC13ZWlnaHQ6Ym9sZDt9Lm1lbnUtY29udGFpbmVye3Bvc2l0aW9uOnJlbGF0aXZlO2Rpc3BsYXk6aW5saW5lLWJsb2NrO30uZG90cy1idG57YmFja2dyb3VuZDpyZ2JhKDI1NSwyNTUsMjU1LDAuMDUpO2JvcmRlcjoxcHggc29saWQgIzFmMjkzZDtjb2xvcjojZmZmO2JvcmRlci1yYWRpdXM6NnB4O3BhZGRpbmc6NHB4IDEwcHg7Zm9udC1zaXplOjE0cHg7Y3Vyc29yOnBvaW50ZXI7fS5kcm9wZG93bi1jb250ZW50e2Rpc3BsYXk6bm9uZTtwb3NpdGlvbjphYnNvbHV0ZTtyaWdodDowO3RvcDoyOHB4O2JhY2tncm91bmQ6IzA3MGExMjtib3JkZXI6MXB4IHNvbGlkICMxZjI5M2Q7Ym9yZGVyLXJhZGl1czo4cHg7bWluLXdpZHRoOjEyMHB4O2JveC1zaGFkb3c6MCAxMHB4IDI1cHggcmdiYSgwLDAsMCwwLjgpO3otaW5kZXg6OTk7fS5kcm9wZG93bi1jb250ZW50IGF7Y29sb3I6I2Y4ZmFmYztwYWRkaW5nOjhweCAxMnB4O3RleHQtZGVjb3JhdGlvbjpub25lO2ZvbnQtc2l6ZToxMXB4O2Rpc3BsYXk6YmxvY2s7fS5kcm9wZG93bi1jb250ZW50IGE6aG92ZXJ7YmFja2dyb3VuZDojMWYyOTNKO2NvbG9yOiMwMGZmODg7fS5zaG93e2Rpc3BsYXk6YmxvY2s7fS5yYWRpby1ncm91cHtkaXNwbGF5OmZsZXg7Z2FwOjE1cHg7bWFyZ2luLWJvdHRvbToxMHB4O2ZvbnQtc2l6ZToxMnB4O30ucmFkaW8tZ3JvdXAgbGFiZWx7Y3Vyc29yOnBvaW50ZXI7ZGlzcGxheTpmbGV4O2FsaWduLWl0ZW1zOmNlbnRlcjtnYXA6NXB4O31pbnB1dCxzZWxlY3R7d2lkdGg6MTAwJTtwYWRkaW5nOjExcHg7bWFyZ2luOjVweCAwO2JhY2tncm91bmQ6IzA3MGExMjtib3JkZXI6MXB4IHNvbGlkICMxZjI5M2Q7Y29sb3I6I2ZmZjtib3JkZXItcmFkaXVzOjhweDtmb250LXNpemU6MTJweDtvdXRsaW5lOm5vbmU7fWlucHV0OmZvY3VzLHNlbGVjdDpmb2N1c3tib3JkZXItY29sb3I6IzAwZmY4ODt9YnV0dG9ue3dpZHRoOjEwMCU7cGFkZGluZzoxMXB4O2JvcmRlcjpub25lO2JvcmRlci1yYWRpdXM6OHB4O2ZvbnQtd2VpZ2h0OmJvbGQ7Zm9udC1zaXplOjEycHg7Y3Vyc29yOnBvaW50ZXI7bWFyZ2luLXRvcDo2cHg7fS50Ymx7b3ZlcmZsb3cteDphdXRvO3dpZHRoOjEwMCU7bWFyZ2luLXRvcDo4cHg7fXRhYmxle3dpZHRoOjEwMCU7Ym9yZGVyLWNvbGxhcHNlOmNvbGxhcHNlO21pbi13aWR0aDo0NDBweDtmb250LXNpemU6MTJweDt9dGh7YmFja2dyb3VuZDojMDcwYTEyO2NvbG9yOiM5NGEzYjg7cGFkZGluZzo4cHg7dGV4dC1hbGlnbjpsZWZ0O2ZvbnQtc2l6ZToxMHB4O3RleHQtdHJhbnNmb3JtOnVwcGVyY2FzZTt9dGR7cGFkZGluZzo4cHg7Ym9yZGVyLWJvdHRvbToxcHggc29saWQgIzE2MWYzMzt9LmJ0bi1jb3B5e2Rpc3BsYXk6aW5saW5lLWJsb2NrO3BhZGRpbmc6NHB4IDhweDtiYWNrZ3JvdW5kOnJnYmEoMCwyNTUsMTM2LDAuMTUpO2JvcmRlcjoxcHggc29saWQgIzAwZmY4ODtjb2xvcjojMDBmZjg4O2JvcmRlci1yYWRpdXM6NXB4O2ZvbnQtc2l6ZToxMHB4O2ZvbnQtd2VpZ2h0OmJvbGQ7Y3Vyc29yOnBvaW50ZXI7fS5idG4tY29weS5jb3BpZWR7YmFja2dyb3VuZDojMDBmZjg4O2NvbG9yOiMwNzA5MGU7fS5iYWRnZXtwYWRkaW5nOjJweCA2cHg7Ym9yZGVyLXJhZGl1czo0cHg7Zm9udC1zaXplOjlweDtmb250LXdlaWdodDpib2xkO30uYmFkZ2UuYWN0aXZle2JhY2tncm91bmQ6cmdiYSgwLDI1NSwxMzYsMC4xNSk7Y29sb3I6IzAwZmY4ODt9LmJhZGdlLnVudXNlZHtiYWNrZ3JvdW5kOnJnYmEoMjU1LDE4MywzLDAuMTUpO2NvbG9yOiNmZmIxMDM7fS5iYWRnZS5leHBpcmVke2JhY2tncm91bmQ6cmdiYSgyNTUsMCw4NSwwLjE1KTtjb2xvcjojZmYwMDU1O308L3N0eWxlPjwvaGVhZD48Ym9keT48ZGl2IGNsYXNzPSdoZWFkZXInPjxkaXYgY2xhc3M9J2JyYW5kJz7imqEgVEFSR0VUIENPTlRST0w8L2Rpdj48ZGl2IGNsYXNzPSd1c2VyLXRhZyc+PHNwYW4gY2xhc3M9J3Nlc3Npb24tdGltZXInIGlkPSd0aW1lckRpc3BsYXknPuKPsCAxMDowMDwvc3Bhbj48c3BhbiBjbGFzcz0nY3JlZGl0cy1waWxsJz7imqEgX19DUkVESVRTX18gQ1I8L3NwYW4+PGEgaHJlZj0nL2xvZ291dCcgc3R5bGU9J2NvbG9yOiNlZjQ0NDQ7Zm9udC13ZWlnaHQ6Ym9sZDt0ZXh0LWRlY29yYXRpb246bm9uZTtmb250LXNpemU6MTJweDsnPkxvZ291dDwvYT48L2Rpdj48L2Rpdj5fX0dSSURfSFRNTF9fPGRpdiBjbGFzcz0nY2FyZCcgc3R5bGU9J2JvcmRlci1jb2xvcjpyZ2JhKDAsMjU1LDEzNiwwLjMpOyc+PGRpdiBjbGFzcz0nY2FyZC1oZWFkZXInPjxoMyBzdHlsZT0nY29sb3I6IzAwZmY4ODsnPuKaoSBHRU5FUkFURSBMSUNFTlNFPC9oMz48ZGl2IGNsYXNzPSdtZW51LWNvbnRhaW5lcic+PGJ1dHRvbiBjbGFzcz0nZG90cy1idG4nIG9uY2xpY2s9J3RvZ2dsZU1lbnUoKSc+4ouEPC9idXR0b24+PGRpdiBpZD0nZG90c0Ryb3Bkb3duJyBjbGFzcz0nZHJvcGRvd24tY29udGVudCc+PGEgaHJlZj0namF2YXNjcmlwdDpsb2NhdGlvbi5yZWxvYWQoKSc+8J+UpSBSZWZyZXNoPC9hPjxhIGhyZWY9ImphdmFzY3JpcHQ6YWxlcnQoJ1ByaWNpbmc6IDFoPTAuMSwgMTJoPTEsIDFkPTIsIDMwZD0zMCBDcmVkaXRzJykiPspZIFJhdGUgTGlzdDwvYT48L2Rpdj48L2Rpdj48L2Rpdj48Zm9ybSBhY3Rpb249Jy9rZXkvY3JlYXRlJyBtZXRob2Q9J3Bvc3QnPjxkaXYgY2xhc3M9J3JhZGlvLWdyb3VwJz48bGFiZWw+PGlucHV0IHR5cGU9J3JhZGlvJyBuYW1lPSdrZXlfdHlwZScgdmFsdWU9J3JhbmRvbScgY2hlY2tlZCBvbmNsaWNrPSd0b2dnbGVDdXN0b21Cb3goZmFsc2UpJz4gUmFuZG9tIEtleTwvbGFiZWw+PGxhYmVsPjxpbnB1dCB0eXBlPSdyYWRpbycgbmFtZT0na2V5X3R5cGUnIHZhbHVlPSdjdXN0b20nIG9uY2xpY2s9J3RvZ2dsZUN1c3RvbUJveCh0cnVlKSc+IEN1c3RvbSBLZXk8L2xhYmVsPjwvZGl2PjxkaXYgaWQ9J2N1c3RvbUtleUJveCcgc3R5bGU9J2Rpc3BsYXk6bm9uZTsnPjxpbnB1dCBuYW1lPSdjdXN0b21fa2V5X25hbWUnIHBsYWNlaG9sZGVyPSdFbnRlciBDdXN0b20gS2V5IChlLmcuIFZJUC1ST0hBTiknPjwvZGl2PjxzZWxlY3QgbmFtZT0nZHVyYXRpb24nPjxvcHRpb24gdmFsdWU9JzEnPjEgSG91ciAoMC4xIENyZWRpdDwvb3B0aW9uPjxvcHRpb24gdmFsdWU9JzInPjIgSG91cnMgKDAuMiBDcmVkaXQpPC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0nNSc+NSBIb3VycyAoMC41IENyZWRpdCk8L29wdGlvbj48b3B0aW9uIHZhbHVlPSc2Jz42IEhvdXJzICgwLjYgQ3JlZGl0KTwvb3B0aW9uPjxvcHRpb24gdmFsdWU9JzEyJz4xMiBIb3VycyAoMSBDcmVkaXQpPC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0nMjQnPjEgRGF5ICgyIENyZWRpdHMpPC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0nMTY4Jz43IERheXMgKDEwIENyZWRpdHMpPC9vcHRpb24+PG9wdGlvbiB2YWx1ZT0nMzYwJz4xNSBEYXlzICgxOCBDcmVkaXRzKTwvb3B0aW9uPjxvcHRpb24gdmFsdWU9JzcyMCc+MzAgRGF5cyAoMzAgQ3JlZGl0cyk8L29wdGlvbj48L3NlbGVjdD48YnV0dG9uIHR5cGU9J3N1Ym1pdCcgc3R5bGU9J2JhY2tncm91bmQ6IzAwZmY4ODtjb2xvcjojMDcwOTBlOyc+KyBDUkVBVEUgS0VZPC9idXR0b24+PC9mb3JtPjwvZGl2Pl9fQURNSU5fQk9YRVNfX19fUEVORElOR19TRUNUSU9OX19fX1JFRl9TRUNUSU9OX19fX1VfU0VDVElPTl9fPGRpdiBjbGFzcz0nY2FyZCc+PGgzPvCfspAgTElDRU5TRUtFWVNESVJFQ1RPUlk8L2gzPjxkaXYgY2xhc3M9J3RibCc+PHRhYmxlPjx0cj48dGg+S2V5PC90aD48dGg+RHVyYXRpb248L3RoPjx0aD5TdGF0dXM8L3RoPjx0aD5IV0lEPC90aD48dGg+RXhwaXJ5PC90aD48dGg+QWN0aW9uPC90aD48L3RyPl9fS0VZU19ST1dTX188L3RhYmxlPjwvZGl2PjwvZGl2PjxzY3JpcHQ+dmFyIHRpbWVMZWZ0ID0gNjAwO3ZhciB0aW1lckVsZW0gPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgndGltZXJEaXNwbGF5Jyk7dmFyIHRpbWVySW50ZXJ2YWwgPSBzZXRJbnRlcnZhbChmdW5jdGlvbigpIHt0aW1lTGVmdC0tO3ZhciBtID0gTWF0aC5mbG9vcih0aW1lTGVmdCAvIDYwKTt2YXIgcyA9IHRpbWVMZWZ0ICUgNjA7dGltZXJFbGVtLmlubmVyVGV4dCA9ICfij6MgJyArIChtIDwgMTAgPyAnMCcgKyBtIDogbSkgKyAnOicgKyAocyA8IDEwID8gJzAnICsgcyA6IHMpO2lmICh0aW1lTGVmdCA8PSAwKSB7Y2xlYXJJbnRlcnZhbCh0aW1lckludGVydmFsKTthbGVydCgnU2Vzc2lvbiBUaW1lZCBPdXQgKDEwIE1pbnV0ZXMgRXhjZWVkZWQpLiBQbGVhc2UgbG9naW4gYWdhaW4uJyk7bG9jYXRpb24uaHJlZiA9ICcvbG9nb3V0Jzt9fSwgMTAwMCk7ZnVuY3Rpb24gdG9nZ2xlTWVudSgpIHtkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgnZG90c0Ryb3Bkb3duJykuY2xhc3NMaXN0LnRvZ2dsZSgnd2hvdycpO31mdW5jdGlvbiB0b2dnbGVDdXN0b21Cb3goc2hvdykge2RvY3VtZW50LmdldEVsZW1lbnRCeUlkKCdjdXN0b21LZXlCb3gnKS5zdHlsZS5kaXNwbGF5ID0gc2hvdyA/ICdibG9jaycgOiAnbm9uZSc7fWZ1bmN0aW9uIGNvcHlLZXkodGV4dCwgYnRuKSB7bmF2aWdhdG9yLmNsaXBib2FyZC53cml0ZVRleHQodGV4dCkudGhlbihmdW5jdGlvbigpIHt2YXIgb3JpZyA9IGJ0bi5pbm5lclRleHQ7YnRuLmlubmVyVGV4dCA9ICdDb3BpZWQhJztidG4uY2xhc3NMaXN0LmFkZCgnY29waWVkJyk7c2V0VGltZW91dChmdW5jdGlvbigpIHtidG4uaW5uZXJUZXh0ID0gb3JpZztidG4uY2xhc3NMaXN0LnJlbW92ZSgnY29waWVkJyk7fSwgMTUwMCk7fSk7fXdpbmRvdy5vbmNsaWNrID0gZnVuY3Rpb24oZXZlbnQpIHtpZiAoIWV2ZW50LnRhcmdldC5tYXRjaGVzKCcuZG90cy1idG4nKSkge3ZhciBkcm9wZG93bnMgPSBkb2N1bWVudC5nZXRFbGVtZW50c0J5Q2xhc3NOYW1lKCdkcm9wZG93bi1jb250ZW50Jyk7Zm9yICh2YXIgaSA9IDA7IGkgPCBkcm9wZG93bnMubGVuZ3RoOyBpKyspIHt2YXIgb3BlbkRyb3Bkb3duID0gZHJvcGRvd25zW2ldO2lmIChvcGVuRHJvcGRvd24uY2xhc3NMaXN0LmNvbnRhaW5zKCdzaG93JykpIHtvcGVuRHJvcGRvd24uY2xhc3NMaXN0LnJlbW92ZSgnc2hvd2wnKTt9fX19PC9zY3JpcHQ+PC9ib2R5PjwvaHRtbD4=").decode('utf-8')

@app.get("/owner", response_class=HTMLResponse)
def owner_login_page():
    return HTML_OWNER

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return HTML_LOGIN

@app.get("/register", response_class=HTMLResponse)
def register_page():
    return HTML_REG

@app.post("/auth/register")
def auth_register(ref_code: str = Form(...), username: str = Form(...), password: str = Form(...), confirm_password: str = Form(...)):
    ref_code = ref_code.strip()
    if password != confirm_password:
        return HTMLResponse("<script>alert('Password and Confirm Password do not match!');history.back();</script>")
        
    with db() as c:
        ref = c.execute("SELECT * FROM referral_codes WHERE code=?", (ref_code,)).fetchone()
        if not ref:
            return HTMLResponse("<script>alert('Invalid or Expired Invite Code!');location.href='/register';</script>")
        exist = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if exist:
            return HTMLResponse("<script>alert('Username already taken! Choose another.');location.href='/register';</script>")
        
        # User created in 'pending' status waiting for Creator's approval
        c.execute("INSERT INTO users (username, password_hash, role, credits, status, created_by, used_code) VALUES (?, ?, ?, ?, 'pending', ?, ?)", 
                  (username, hash_pw(password), ref["role"], ref["credits"], ref["created_by"], ref_code))
        
    return HTMLResponse("<script>alert('Registration Submitted! Waiting for your Admin/Owner to approve.');location.href='/login';</script>")

@app.post("/auth/login")
def auth_login(username: str = Form(...), password: str = Form(...)):
    with db() as c:
        u = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not u or u["password_hash"] != hash_pw(password):
        return HTMLResponse("<script>alert('Invalid Login Credentials');history.back();</script>")
    if u["status"] == "pending":
        return HTMLResponse("<script>alert('Your account is Pending Approval from your Admin/Owner!');location.href='/login';</script>")
    if u["status"] == "banned":
        return HTMLResponse("<script>alert('Your account has been suspended!');location.href='/login';</script>")
        
    current_time = str(time.time())
    to

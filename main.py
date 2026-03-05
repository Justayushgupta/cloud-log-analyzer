from fastapi import FastAPI, UploadFile, File, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from datetime import datetime
import sqlite3
import re

app = FastAPI()

# -------------------------
# SECURITY
# -------------------------

app.add_middleware(SessionMiddleware, secret_key="supersecurekey")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE = "logs.db"


# -------------------------
# THREAT INTELLIGENCE
# -------------------------

KNOWN_MALICIOUS_IPS = {
    "185.220.101.1",
    "45.155.205.233",
    "103.27.186.45",
    "91.134.183.26",
    "192.42.116.16"
}


# -------------------------
# DATABASE CONNECTION
# -------------------------

def get_db():
    return sqlite3.connect(DATABASE, check_same_thread=False)


# -------------------------
# DATABASE INIT
# -------------------------

def init_db():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS reports(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        risk_level TEXT,
        severity_score INTEGER,
        attack_type TEXT,
        top_ip TEXT,
        malicious_ip TEXT,
        total_failed INTEGER,
        created_at TEXT
    )
    """)

    conn.commit()
    conn.close()


init_db()


# -------------------------
# LOG ANALYSIS ENGINE
# -------------------------

def analyze_log(content: str):

    lines = content.split("\n")

    failed_attempts = 0
    suspicious_ips = {}
    malicious_ip = None

    for line in lines:

        if "failed" in line.lower():
            failed_attempts += 1

        ip_matches = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)

        for ip in ip_matches:

            suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

            if ip in KNOWN_MALICIOUS_IPS:
                malicious_ip = ip

    top_ip = max(suspicious_ips, key=suspicious_ips.get) if suspicious_ips else "N/A"

    severity_score = failed_attempts * 5 + len(suspicious_ips) * 15
    severity_score = min(severity_score, 100)

    if malicious_ip:
        risk_level = "CRITICAL"
        attack_type = "Known Malicious IP"

    elif severity_score >= 75:
        risk_level = "CRITICAL"
        attack_type = "Active Intrusion Attempt"

    elif severity_score >= 50:
        risk_level = "HIGH"
        attack_type = "Brute Force Pattern"

    elif severity_score >= 25:
        risk_level = "MEDIUM"
        attack_type = "Suspicious Activity"

    else:
        risk_level = "LOW"
        attack_type = "Normal Traffic"

    return risk_level, severity_score, attack_type, top_ip, failed_attempts, malicious_ip


# -------------------------
# LOGIN SYSTEM
# -------------------------

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"


@app.get("/login", response_class=HTMLResponse)
def login_page():

    with open("frontend/login.html") as f:
        return HTMLResponse(content=f.read())


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):

    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        request.session["user"] = username
        return RedirectResponse("/dashboard", status_code=303)

    return HTMLResponse("<h3>Invalid credentials</h3><a href='/login'>Try again</a>")


@app.get("/logout")
def logout(request: Request):

    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# -------------------------
# PAGE ROUTES
# -------------------------

@app.get("/", response_class=HTMLResponse)
def home():

    with open("frontend/index.html") as f:
        return HTMLResponse(content=f.read())


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):

    if "user" not in request.session:
        return RedirectResponse("/login", status_code=303)

    with open("frontend/dashboard.html") as f:
        return HTMLResponse(content=f.read())


# -------------------------
# FILE UPLOAD
# -------------------------

@app.post("/upload/")
async def upload_log(file: UploadFile = File(...)):

    try:

        content = await file.read()
        log_text = content.decode("utf-8")

        risk_level, severity_score, attack_type, top_ip, failed_attempts, malicious_ip = analyze_log(log_text)

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("""
        INSERT INTO reports
        (risk_level, severity_score, attack_type, top_ip, malicious_ip, total_failed, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            risk_level,
            severity_score,
            attack_type,
            top_ip,
            malicious_ip if malicious_ip else "N/A",
            failed_attempts,
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()

        return JSONResponse({
            "risk_level": risk_level,
            "severity_score": severity_score,
            "attack_type": attack_type,
            "top_ip": top_ip,
            "failed_attempts": failed_attempts,
            "malicious_ip": malicious_ip
        })

    except Exception as e:

        return JSONResponse({"error": str(e)}, status_code=500)


# -------------------------
# REPORTS API
# -------------------------

@app.get("/reports/")
def get_reports():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
    SELECT id, risk_level, severity_score, attack_type,
           top_ip, malicious_ip, total_failed, created_at
    FROM reports
    ORDER BY id DESC
    """)

    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "id": row[0],
            "risk_level": row[1],
            "severity_score": row[2],
            "attack_type": row[3],
            "top_ip": row[4],
            "malicious_ip": row[5],
            "failed_attempts": row[6],
            "created_at": row[7]
        }
        for row in rows
    ]


# -------------------------
# ANALYTICS API
# -------------------------

@app.get("/analytics/")
def analytics():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM reports")
    total_logs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM reports WHERE risk_level IN ('HIGH','CRITICAL')")
    high_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT AVG(severity_score) FROM reports")
    avg_severity = cursor.fetchone()[0] or 0

    cursor.execute("""
    SELECT attack_type, COUNT(*)
    FROM reports
    GROUP BY attack_type
    ORDER BY COUNT(*) DESC
    LIMIT 1
    """)

    top_attack = cursor.fetchone()

    cursor.execute("SELECT risk_level, COUNT(*) FROM reports GROUP BY risk_level")
    distribution_data = cursor.fetchall()

    conn.close()

    distribution = {
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
        "CRITICAL": 0
    }

    for item in distribution_data:
        distribution[item[0]] = item[1]

    return {
        "total_logs": total_logs,
        "high_alerts": high_alerts,
        "average_severity": round(avg_severity, 2),
        "top_attack_type": top_attack[0] if top_attack else "N/A",
        "distribution": distribution
    }


# -------------------------
# TOP ATTACKING IPS
# -------------------------

@app.get("/top-ips/")
def top_ips():

    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT top_ip, COUNT(*) as attacks
        FROM reports
        WHERE top_ip != 'N/A'
        GROUP BY top_ip
        ORDER BY attacks DESC
        LIMIT 5
    """)

    rows = cursor.fetchall()
    conn.close()

    return [
        {"ip": row[0], "attacks": row[1]}
        for row in rows
    ]

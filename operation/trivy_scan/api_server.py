## python3 api_server.py --dbhost 192.168.100.11

#!/usr/bin/env python3
import argparse
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware # [추가] CORS 미들웨어
import mysql.connector
import os
import uvicorn
from datetime import datetime

# ---------------------------------------------------------
# 설정
# ---------------------------------------------------------
DB_CONFIG = {
    'host': '127.0.0.1', # DB가 다른 서버라면 IP 수정 필요
    'user': 'cve_user',
    'password': 'cve_password123!',
    'database': 'cve_db',
    'connect_timeout': 10,
    'ssl_disabled': True
}

TEMPLATE_DIR = "templates"
TEMPLATE_FILE = "trivy_dashboard.html"

app = FastAPI(title="Trivy Full Security API", version="1.1.0")

# [핵심 수정] CORS 설정 추가 (모든 출처 허용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 실제 운영 시에는 특정 도메인만 허용 권장
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

@app.get("/api/scans")
def get_scans_summary():
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 최신 스캔 데이터 조회
        sql = """
            SELECT
                s.id, s.hostname, s.ip_address, s.os_name, s.scan_date,
                s.total_vulns, s.total_misconfs, s.total_secrets
            FROM scans s
            INNER JOIN (
                SELECT hostname, MAX(scan_date) as max_date
                FROM scans
                GROUP BY hostname
            ) latest ON s.hostname = latest.hostname AND s.scan_date = latest.max_date
            ORDER BY s.scan_date DESC
        """
        cursor.execute(sql)
        rows = cursor.fetchall()

        result = []
        for row in rows:
            scan_dt = row['scan_date']
            if isinstance(scan_dt, datetime):
                scan_dt = scan_dt.strftime('%Y-%m-%d %H:%M:%S')

            result.append({
                "id": row['id'],
                "hostname": row['hostname'],
                "ip": row['ip_address'],
                "os": row['os_name'],
                "date": str(scan_dt),
                "stats": {
                    "vuln": row['total_vulns'],
                    "misconf": row['total_misconfs'],
                    "secret": row['total_secrets']
                }
            })

        return result

    except mysql.connector.Error as err:
        print(f"[DB Error] {err}")
        # 상세 에러를 반환하도록 수정
        raise HTTPException(status_code=500, detail=f"Database Error: {err}")
    finally:
        if conn and conn.is_connected():
            conn.close()

@app.get("/api/scans/{scan_id}/details")
def get_scan_details(scan_id: int):
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 1. Vulns
        cursor.execute("SELECT cve_id as id, pkg_name as pkg, severity as sev, installed_ver as cur, fixed_ver as fix, title FROM vuln_results WHERE scan_id = %s", (scan_id,))
        vulns = cursor.fetchall()

        # 2. Misconfs
        cursor.execute("SELECT type, rule_id as id, severity as sev, message as msg, status FROM misconf_results WHERE scan_id = %s", (scan_id,))
        misconfs = cursor.fetchall()

        # 3. Secrets
        cursor.execute("SELECT category, severity as sev, file_path as file, title FROM secret_results WHERE scan_id = %s", (scan_id,))
        secrets = cursor.fetchall()

        # 4. Licenses
        cursor.execute("SELECT pkg_name as pkg, license_name as lic, file_path as file, severity as sev FROM license_results WHERE scan_id = %s", (scan_id,))
        licenses = cursor.fetchall()

        return {"vulns": vulns, "misconfs": misconfs, "secrets": secrets, "licenses": licenses}

    except mysql.connector.Error as err:
        print(f"[DB Error] {err}")
        raise HTTPException(status_code=500, detail=f"Database Error: {err}")
    finally:
        if conn and conn.is_connected():
            conn.close()

@app.get("/web", response_class=HTMLResponse)
def serve_dashboard():
    path = os.path.join(TEMPLATE_DIR, TEMPLATE_FILE)
    if not os.path.exists(path):
        return f"<h1>Error: Template file not found at {path}</h1>"
    with open(path, "r", encoding="utf-8") as f:
        return f.read()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--dbhost', type=str, default='127.0.0.1')
    args = parser.parse_args()

    DB_CONFIG['host'] = args.dbhost

    if not os.path.exists(TEMPLATE_DIR):
        os.makedirs(TEMPLATE_DIR)

    print(f"[*] API Server Running on http://0.0.0.0:8000")
    print(f"[*] Dashboard Access: http://localhost:8000/web")

    uvicorn.run(app, host="0.0.0.0", port=8000)

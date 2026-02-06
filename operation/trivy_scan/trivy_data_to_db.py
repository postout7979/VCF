## trivy_data_to_db.py --dbhost 192.168.100.100
## scan 후, 바로 DB에 저장

#!/usr/bin/env python3
import json
import subprocess
import mysql.connector
import os
import socket
import argparse
import sys
from datetime import datetime
from tqdm import tqdm  # [추가됨] 진행률 표시 라이브러리

# ---------------------------------------------------------
# 설정
# ---------------------------------------------------------
DB_CONFIG = {
    'user': 'cve_user',
    'password': 'cve_password123!',
    'database': 'cve_db',
    'connect_timeout': 10,
    'ssl_disabled': True
}
TRIVY_OUTPUT_FILE = "trivy_full_report.json"
BATCH_SIZE = 2000  # 한 번에 INSERT할 행 개수

# ---------------------------------------------------------
# 유틸리티 함수
# ---------------------------------------------------------
def get_host_info():
    hostname = socket.gethostname()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except:
        ip = "127.0.0.1"
    return hostname, ip

def run_trivy_scan():
    print(f"[*] Trivy Full Scan 시작 (Timeout: 30m)...")

    cmd = [
        "trivy", "fs",
        "--scanners", "vuln,misconfig,secret,license",
        "--format", "json",
        "--output", TRIVY_OUTPUT_FILE,
        "--timeout", "30m",
        "--skip-dirs", "/proc",
        "--skip-dirs", "/sys",
        "--skip-dirs", "/dev",
        "--skip-dirs", "/run",
        "--skip-dirs", "/var/lib/docker",
        "--skip-dirs", "/var/lib/containerd",
        "/"
    ]

    try:
        # Trivy 자체의 진행률 바가 터미널에 나오도록 허용
        subprocess.run(cmd, check=True)
        print(f"\n[*] 스캔 완료. 결과 파싱 시작...")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[Error] Trivy 실행 실패: {e}")
        return False
    except FileNotFoundError:
        print("[Error] 'trivy' 명령어가 없습니다.")
        return False

def extract_cvss_score(vuln_data):
    cvss = vuln_data.get("CVSS", {})
    sources = ["nvd", "redhat", "ghsa"]
    for src in sources:
        if src in cvss:
            v3 = cvss[src].get("V3Score")
            if v3: return float(v3)
            v2 = cvss[src].get("V2Score")
            if v2: return float(v2)
    return 0.0

# ---------------------------------------------------------
# [핵심] 배치 삽입 함수 (Progress Bar 포함)
# ---------------------------------------------------------
def batch_insert(cursor, sql, data, desc):
    """데이터를 BATCH_SIZE만큼 잘라서 넣으며 진행률 표시"""
    if not data:
        return

    total = len(data)
    # tqdm으로 진행률 바 생성
    with tqdm(total=total, desc=desc, unit="row", ncols=80) as pbar:
        for i in range(0, total, BATCH_SIZE):
            batch = data[i : i + BATCH_SIZE]
            cursor.executemany(sql, batch)
            pbar.update(len(batch))

# ---------------------------------------------------------
# DB 저장 로직
# ---------------------------------------------------------
def parse_and_save_to_db(db_host):
    if not os.path.exists(TRIVY_OUTPUT_FILE):
        return

    # JSON 로딩
    with open(TRIVY_OUTPUT_FILE, 'r') as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return

    hostname, ip = get_host_info()
    scan_date = datetime.now()

    metadata = data.get("Metadata", {})
    os_info = metadata.get("OS", {})
    os_family = os_info.get("Family", "unknown")
    os_name = os_info.get("Name", "unknown")

    vuln_list = []
    misconf_list = []
    secret_list = []
    license_list = []

    results = data.get("Results", [])

    # 데이터 파싱 (순식간이라 진행바 불필요, 필요시 추가 가능)
    print("[*] JSON 데이터 분류 중...")
    for res in results:
        for v in res.get("Vulnerabilities", []):
            vuln_list.append((
                v.get("VulnerabilityID"), v.get("PkgName"), v.get("InstalledVersion"),
                v.get("FixedVersion", ""), v.get("Severity"), extract_cvss_score(v),
                v.get("Title", "")[:500], v.get("Description", "")[:2000], v.get("PrimaryURL", "")
            ))
        for m in res.get("Misconfigurations", []):
            misconf_list.append((
                res.get("Type", "unknown"), m.get("ID"), m.get("Severity"),
                m.get("Title", "")[:500], m.get("Message", "")[:2000], m.get("Status")
            ))
        for s in res.get("Secrets", []):
            secret_list.append((
                s.get("RuleID"), s.get("Category"), s.get("Severity"),
                s.get("Title", "")[:255], res.get("Target", "")[:2000], s.get("StartLine", 0)
            ))
        for l in res.get("Licenses", []):
            license_list.append((
                l.get("PkgName"), l.get("Name"), l.get("FilePath", "")[:2000],
                l.get("Severity", "UNKNOWN")
            ))

    # DB 저장 시작
    conn = None
    try:
        conn = mysql.connector.connect(host=db_host, **DB_CONFIG)
        conn.autocommit = False
        cursor = conn.cursor()

        # 1. 헤더 저장
        cursor.execute("""
            INSERT INTO scans
            (hostname, ip_address, os_family, os_name, scan_date, total_vulns, total_misconfs, total_secrets)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (hostname, ip, os_family, os_name, scan_date, len(vuln_list), len(misconf_list), len(secret_list)))
        scan_id = cursor.lastrowid

        print(f"[*] DB 업로드 시작 (Scan ID: {scan_id})")

        # 2. 각 항목 배치 저장 (with Progress Bar)
        if vuln_list:
            vuln_sql = "INSERT INTO vuln_results (scan_id, cve_id, pkg_name, installed_ver, fixed_ver, severity, cvss_score, title, description, primary_url) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            # scan_id 튜플 합치기
            vuln_data = [(scan_id,) + item for item in vuln_list]
            batch_insert(cursor, vuln_sql, vuln_data, "Vulnerabilities")

        if misconf_list:
            misconf_sql = "INSERT INTO misconf_results (scan_id, type, rule_id, severity, title, message, status) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            misconf_data = [(scan_id,) + item for item in misconf_list]
            batch_insert(cursor, misconf_sql, misconf_data, "Misconfigs     ")

        if secret_list:
            secret_sql = "INSERT INTO secret_results (scan_id, rule_id, category, severity, title, file_path, start_line) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            secret_data = [(scan_id,) + item for item in secret_list]
            batch_insert(cursor, secret_sql, secret_data, "Secrets        ")

        if license_list:
            license_sql = "INSERT INTO license_results (scan_id, pkg_name, license_name, file_path, severity) VALUES (%s, %s, %s, %s, %s)"
            license_data = [(scan_id,) + item for item in license_list]
            batch_insert(cursor, license_sql, license_data, "Licenses       ")

        conn.commit()
        print(f"\n[Success] 모든 데이터 저장 완료!")

    except mysql.connector.Error as err:
        print(f"\n[Error] DB 저장 실패: {err}")
        if conn: conn.rollback()
    finally:
        if conn and conn.is_connected():
            cursor.close()
            conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--dbhost', type=str, required=True)
    args = parser.parse_args()

    if run_trivy_scan():
        parse_and_save_to_db(args.dbhost)

## trivy_db_to_aop.py --dbhost 192.168.100.10
## DB에 접속해서 모든 데이터를 Operations로 전송

#!/usr/bin/env python3
import json
import socket
import requests
import urllib3
import sys
import time
import mysql.connector
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------
# 설정 (환경에 맞게 수정)
# ---------------------------------------------------------
# 1. MySQL DB 설정
DB_CONFIG = {
    'user': 'cve_user',
    'password': 'cve_password123!',
    'database': 'cve_db',
    'connect_timeout': 10,
    'ssl_disabled': True
}

# 2. Aria Operations 설정
AOP_HOST = "vcf-ops.vcf.local"
AOP_USER = "admin"
AOP_PASS = "VMware1!VMware1!"

# 3. 리소스 정의
MY_ADAPTER_KIND = "TrivyAdapter"
MY_RESOURCE_KIND = "TrivyReportObject"
VM_ADAPTER_KIND = "VMWARE"
VM_RESOURCE_KIND = "VirtualMachine"

def get_hostname():
    return socket.gethostname()

# ---------------------------------------------------------
# [Step 1] DB에서 실시간 통계 조회 (핵심 기능)
# ---------------------------------------------------------
def fetch_stats_from_db(db_host, hostname):
    print(f"[*] DB({db_host})에서 '{hostname}'의 최신 스캔 데이터 조회 중...")

    conn = None
    stats = {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0,
        "Unknown": 0, "Total": 0
    }

    try:
        conn = mysql.connector.connect(host=db_host, **DB_CONFIG)
        cursor = conn.cursor()

        # 1. 해당 호스트의 가장 최신 scan_id 조회
        sql_scan = """
            SELECT id FROM scans
            WHERE hostname = %s
            ORDER BY scan_date DESC LIMIT 1
        """
        cursor.execute(sql_scan, (hostname,))
        row = cursor.fetchone()

        if not row:
            print(f"[Warn] '{hostname}'에 대한 스캔 이력이 없습니다.")
            return stats # 모두 0 리턴

        scan_id = row[0]

        # 2. 해당 스캔의 등급별 취약점 개수 집계 (GROUP BY)
        sql_vuln = """
            SELECT severity, COUNT(*)
            FROM vuln_results
            WHERE scan_id = %s
            GROUP BY severity
        """
        cursor.execute(sql_vuln, (scan_id,))
        rows = cursor.fetchall()

        total_count = 0
        for severity, count in rows:
            # DB에는 'CRITICAL', 'HIGH' 등으로 저장됨 -> Key 매칭
            sev_key = severity.capitalize() # 'CRITICAL' -> 'Critical'
            if sev_key in stats:
                stats[sev_key] = count
            else:
                stats["Unknown"] += count

            total_count += count

        stats["Total"] = total_count
        print(f"[*] 조회 결과: {stats}")
        return stats

    except mysql.connector.Error as err:
        print(f"[Error] DB 조회 실패: {err}")
        return None
    finally:
        if conn and conn.is_connected():
            conn.close()

# ---------------------------------------------------------
# [Step 2] AOP API 함수들
# ---------------------------------------------------------
def get_aop_token():
    url = f"https://{AOP_HOST}/suite-api/api/auth/token/acquire"
    payload = {"username": AOP_USER, "password": AOP_PASS}
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    try:
        resp = requests.post(url, json=payload, headers=headers, verify=False, timeout=10)
        resp.raise_for_status()
        return resp.json()["token"]
    except Exception as e:
        print(f"[Fatal] Token 발급 실패: {e}")
        sys.exit(1)

def find_vm_id(token, hostname):
    # VM 조회 (부모 리소스)
    url = f"https://{AOP_HOST}/suite-api/api/resources"
    headers = {"Authorization": f"vRealizeOpsToken {token}", "Accept": "application/json"}
    params = {"name": hostname, "adapterKind": VM_ADAPTER_KIND, "resourceKind": VM_RESOURCE_KIND}

    try:
        resp = requests.get(url, headers=headers, params=params, verify=False)
        data = resp.json()
        if data.get("resourceList"):
            return data["resourceList"][0]["identifier"]
    except Exception:
        pass
    return None

def create_or_get_trivy_resource(token, hostname):
    # 커스텀 리소스 생성/조회 (VCF 9 API 준수)
    resource_name = f"Trivy-{hostname}"

    # 1. 조회
    search_url = f"https://{AOP_HOST}/suite-api/api/resources"
    headers = {"Authorization": f"vRealizeOpsToken {token}", "Accept": "application/json", "Content-Type": "application/json"}
    params = {"name": resource_name, "adapterKind": MY_ADAPTER_KIND, "resourceKind": MY_RESOURCE_KIND}

    resp = requests.get(search_url, headers=headers, params=params, verify=False)
    data = resp.json()
    if data.get("resourceList"):
        return data["resourceList"][0]["identifier"]

    # 2. 생성
    print(f"[*] AOP 리소스 생성 중: {resource_name}")
    create_url = f"https://{AOP_HOST}/suite-api/api/resources/adapterkinds/{MY_ADAPTER_KIND}"
    payload = {
        "name": resource_name,
        "resourceKey": {
            "name": resource_name,
            "adapterKindKey": MY_ADAPTER_KIND,
            "resourceKindKey": MY_RESOURCE_KIND,
            "resourceIdentifiers": [{"identifierType": {"name": "HostID", "dataType": "STRING"}, "value": hostname}]
        }
    }

    try:
        resp = requests.post(create_url, json=payload, headers=headers, verify=False)
        if resp.status_code in [200, 201]:
            return resp.json()['identifier']
    except Exception as e:
        print(f"[Error] 리소스 생성 실패: {e}")
    return None

def add_relationship(token, parent_id, child_id):
    url = f"https://{AOP_HOST}/suite-api/api/resources/{parent_id}/relationships"
    headers = {"Authorization": f"vRealizeOpsToken {token}", "Content-Type": "application/json", "Accept": "application/json"}
    requests.put(url, json={"add": [child_id]}, headers=headers, verify=False)

def push_metrics(token, resource_id, stats):
    url = f"https://{AOP_HOST}/suite-api/api/resources/{resource_id}/stats"
    headers = {"Authorization": f"vRealizeOpsToken {token}", "Content-Type": "application/json"}
    timestamp = int(time.time() * 1000)

    payload = {
        "stat-content": [
            {"statKey": "Security|Critical", "timestamps": [timestamp], "values": [float(stats["Critical"])]},
            {"statKey": "Security|High",     "timestamps": [timestamp], "values": [float(stats["High"])]},
            {"statKey": "Security|Medium",   "timestamps": [timestamp], "values": [float(stats["Medium"])]},
            {"statKey": "Security|Low",      "timestamps": [timestamp], "values": [float(stats["Low"])]},
            {"statKey": "Security|Total",    "timestamps": [timestamp], "values": [float(stats["Total"])]}
        ]
    }

    resp = requests.post(url, json=payload, headers=headers, verify=False)
    if resp.status_code in [200, 201, 202]:
        print(f"[Success] {stats['Total']}개의 취약점 통계 전송 완료")
    else:
        print(f"[Error] 전송 실패: {resp.text}")

# ---------------------------------------------------------
# 메인 실행
# ---------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--dbhost', type=str, required=True, help='MySQL Database IP')
    args = parser.parse_args()

    hostname = get_hostname()

    # 1. DB에서 실제 데이터 조회
    stats = fetch_stats_from_db(args.dbhost, hostname)

    if stats:
        # 2. AOP 연결 및 전송
        try:
            token = get_aop_token()

            # 리소스 생성/조회
            trivy_res_id = create_or_get_trivy_resource(token, hostname)

            if trivy_res_id:
                # 부모 VM 연결 (선택사항)
                vm_id = find_vm_id(token, hostname)
                if vm_id:
                    add_relationship(token, vm_id, trivy_res_id)
                else:
                    print(f"[Info] 부모 VM({hostname})을 찾지 못해 관계 설정은 건너뜁니다.")

                # 메트릭 푸시
                push_metrics(token, trivy_res_id, stats)

        except Exception as e:
            print(f"[Error] AOP 연동 중 오류: {e}")

#!/usr/bin/env python3
import json
import socket
import requests
import urllib3
import sys
import time
import os
import argparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------
# 설정 (환경에 맞게 수정)
# ---------------------------------------------------------
TRIVY_OUTPUT_FILE = "trivy_full_report.json"

AOP_HOST = "192.168.0.210"
AOP_USER = "admin"
AOP_PASS = "password123!"

# AOP 리소스 정의
MY_ADAPTER_KIND = "TrivyAdapter"
MY_RESOURCE_KIND = "TrivyReportObject"
VM_ADAPTER_KIND = "VMWARE"
VM_RESOURCE_KIND = "VirtualMachine"

def get_hostname():
    return socket.gethostname()

# ---------------------------------------------------------
# [Step 1] JSON 파일 파싱 및 통계 집계
# ---------------------------------------------------------
def parse_trivy_json(file_path):
    print(f"[*] JSON 파일 분석 중: {file_path}")
    
    if not os.path.exists(file_path):
        print(f"[Error] 파일이 없습니다: {file_path}")
        return None

    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"[Error] JSON 로딩 실패: {e}")
        return None

    # 통계 초기화
    # 구조: stats[Category][Severity] = Count
    categories = ["Vuln", "Misconf", "Secret", "License", "Total"]
    stats = {cat: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "TOTAL": 0} for cat in categories}

    results = data.get("Results", [])

    for res in results:
        # 1. Vulnerabilities
        for item in res.get("Vulnerabilities", []):
            update_stat(stats, "Vuln", item.get("Severity", "UNKNOWN"))

        # 2. Misconfigurations
        for item in res.get("Misconfigurations", []):
            update_stat(stats, "Misconf", item.get("Severity", "UNKNOWN"))

        # 3. Secrets
        for item in res.get("Secrets", []):
            update_stat(stats, "Secret", item.get("Severity", "UNKNOWN"))
            
        # 4. Licenses
        for item in res.get("Licenses", []):
            update_stat(stats, "License", item.get("Severity", "UNKNOWN"))

    print("[*] 분석 완료.")
    return stats

def update_stat(stats, category, severity):
    sev = severity.upper()
    if sev not in stats[category]:
        sev = "UNKNOWN"
    
    # 카테고리별 합계
    stats[category][sev] += 1
    stats[category]["TOTAL"] += 1
    
    # 전체 통합 합계
    stats["Total"][sev] += 1
    stats["Total"]["TOTAL"] += 1

# ---------------------------------------------------------
# [Step 2] AOP 연동 (API VCF 9 호환)
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
    url = f"https://{AOP_HOST}/suite-api/api/resources"
    headers = {"Authorization": f"vRealizeOpsToken {token}", "Accept": "application/json"}
    params = {"name": hostname, "adapterKind": VM_ADAPTER_KIND, "resourceKind": VM_RESOURCE_KIND}
    try:
        resp = requests.get(url, headers=headers, params=params, verify=False)
        data = resp.json()
        if data.get("resourceList"):
            return data["resourceList"][0]["identifier"]
    except:
        pass
    return None

def create_or_get_resource(token, hostname):
    resource_name = f"Trivy-{hostname}"
    
    # 조회
    search_url = f"https://{AOP_HOST}/suite-api/api/resources"
    headers = {"Authorization": f"vRealizeOpsToken {token}", "Accept": "application/json", "Content-Type": "application/json"}
    params = {"name": resource_name, "adapterKind": MY_ADAPTER_KIND, "resourceKind": MY_RESOURCE_KIND}
    
    resp = requests.get(search_url, headers=headers, params=params, verify=False)
    data = resp.json()
    if data.get("resourceList"):
        return data["resourceList"][0]["identifier"]
    
    # 생성 (VCF 9 스타일)
    create_url = f"https://{AOP_HOST}/suite-api/api/resources/adapterkinds/{MY_ADAPTER_KIND}"
    payload = {
        "name": resource_name,
        "description": "Generated from trivy_full_report.json",
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
    
    # 메트릭 페이로드 구성
    stat_content = []
    
    # 1. Total (전체 합계)
    stat_content.append({"statKey": "Security|Total|Critical", "timestamps": [timestamp], "values": [float(stats["Total"]["CRITICAL"])]})
    stat_content.append({"statKey": "Security|Total|High",     "timestamps": [timestamp], "values": [float(stats["Total"]["HIGH"])]})
    stat_content.append({"statKey": "Security|Total|Count",    "timestamps": [timestamp], "values": [float(stats["Total"]["TOTAL"])]})

    # 2. Vuln (취약점)
    stat_content.append({"statKey": "Security|Vuln|Critical", "timestamps": [timestamp], "values": [float(stats["Vuln"]["CRITICAL"])]})
    stat_content.append({"statKey": "Security|Vuln|High",     "timestamps": [timestamp], "values": [float(stats["Vuln"]["HIGH"])]})

    # 3. Misconf (설정오류)
    stat_content.append({"statKey": "Security|Misconf|Fail",  "timestamps": [timestamp], "values": [float(stats["Misconf"]["TOTAL"])]})
    
    # 4. Secret (비밀키 노출)
    stat_content.append({"statKey": "Security|Secret|Count",  "timestamps": [timestamp], "values": [float(stats["Secret"]["TOTAL"])]})

    payload = {"stat-content": stat_content}
    
    resp = requests.post(url, json=payload, headers=headers, verify=False)
    if resp.status_code in [200, 201, 202]:
        print(f"[Success] 메트릭 전송 완료 (Total Issues: {stats['Total']['TOTAL']})")
    else:
        print(f"[Error] 전송 실패: {resp.text}")

# ---------------------------------------------------------
# Main
# ---------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', type=str, default=TRIVY_OUTPUT_FILE, help='Path to Trivy JSON report')
    args = parser.parse_args()

    hostname = get_hostname()
    
    # 1. JSON 파일 파싱
    stats = parse_trivy_json(args.file)
    
    if stats:
        try:
            # 2. AOP 연결
            token = get_aop_token()
            
            # 3. 리소스 확보
            trivy_res_id = create_or_get_resource(token, hostname)
            
            if trivy_res_id:
                # 4. 부모 연결 (선택)
                vm_id = find_vm_id(token, hostname)
                if vm_id:
                    add_relationship(token, vm_id, trivy_res_id)
                
                # 5. 메트릭 전송
                push_metrics(token, trivy_res_id, stats)
                
        except Exception as e:
            print(f"[Error] AOP 작업 중 오류: {e}")

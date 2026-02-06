## python3 delete_trivy_resource.py --target "Trivy-web-server-02"

#!/usr/bin/env python3
import requests
import urllib3
import sys
import socket
import argparse

# SSL 경고 무시
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------
# 설정 (환경에 맞게 수정)
# ---------------------------------------------------------
AOP_HOST = "192.168.0.210"
AOP_USER = "admin"
AOP_PASS = "password123!"

# 삭제할 대상 리소스 정의 (이전 스크립트와 동일해야 함)
MY_ADAPTER_KIND = "TrivyAdapter"
MY_RESOURCE_KIND = "TrivyReportObject"

def get_hostname():
    return socket.gethostname()

def get_aop_token():
    url = f"https://{AOP_HOST}/suite-api/api/auth/token/acquire"
    payload = {"username": AOP_USER, "password": AOP_PASS}
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    try:
        resp = requests.post(url, json=payload, headers=headers, verify=False, timeout=10)
        resp.raise_for_status()
        return resp.json()["token"]
    except Exception as e:
        print(f"[Fatal] AOP 접속 실패: {e}")
        sys.exit(1)

# ---------------------------------------------------------
# [Step 1] 삭제 대상 리소스 ID 조회
# ---------------------------------------------------------
def find_resource_ids(token, target_name):
    print(f"[*] 리소스 검색 중: Name='{target_name}', Kind='{MY_RESOURCE_KIND}'")
    
    url = f"https://{AOP_HOST}/suite-api/api/resources"
    headers = {
        "Authorization": f"vRealizeOpsToken {token}",
        "Accept": "application/json"
    }
    params = {
        "name": target_name,
        "adapterKind": MY_ADAPTER_KIND,
        "resourceKind": MY_RESOURCE_KIND
    }
    
    try:
        resp = requests.get(url, headers=headers, params=params, verify=False)
        data = resp.json()
        
        ids = []
        if data.get("resourceList"):
            for res in data["resourceList"]:
                ids.append(res["identifier"])
        return ids
        
    except Exception as e:
        print(f"[Error] 리소스 검색 실패: {e}")
        return []

# ---------------------------------------------------------
# [Step 2] 리소스 삭제 요청
# ---------------------------------------------------------
def delete_resource(token, resource_id):
    url = f"https://{AOP_HOST}/suite-api/api/resources/{resource_id}"
    headers = {
        "Authorization": f"vRealizeOpsToken {token}",
        "Accept": "application/json"
    }
    
    try:
        print(f"[*] 삭제 요청 보내는 중 (ID: {resource_id})...")
        resp = requests.delete(url, headers=headers, verify=False)
        
        # 204 No Content (성공)
        if resp.status_code == 204:
            print(f"[Success] 리소스가 성공적으로 삭제되었습니다.")
        elif resp.status_code == 404:
            print(f"[Info] 이미 삭제된 리소스입니다.")
        else:
            print(f"[Error] 삭제 실패 (Code: {resp.status_code}) - {resp.text}")
            
    except Exception as e:
        print(f"[Error] API 호출 실패: {e}")

# ---------------------------------------------------------
# Main
# ---------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Delete Trivy Resource from AOP')
    parser.add_argument('--target', type=str, help='Specific Resource Name to delete (default: Trivy-<hostname>)')
    args = parser.parse_args()

    token = get_aop_token()
    
    # 1. 삭제할 리소스 이름 결정
    # 인자가 없으면 현재 호스트네임 기준, 있으면 해당 이름 사용
    if args.target:
        target_name = args.target
    else:
        target_name = f"Trivy-{get_hostname()}"
    
    # 2. ID 조회
    resource_ids = find_resource_ids(token, target_name)
    
    if not resource_ids:
        print(f"[Info] '{target_name}'에 해당하는 리소스를 찾을 수 없습니다.")
        sys.exit(0)

    print(f"[*] 총 {len(resource_ids)}개의 리소스가 발견되었습니다.")

    # 3. 삭제 수행
    for res_id in resource_ids:
        delete_resource(token, res_id)

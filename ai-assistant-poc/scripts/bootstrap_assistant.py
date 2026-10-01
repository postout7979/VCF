#!/usr/bin/env python3
"""Open WebUI 초기 구성: 문서 업로드 -> Knowledge 생성 -> 'VCF 운영 어시스턴트' 모델 프리셋 생성.

표준 라이브러리만 사용합니다 (폐쇄망 호환). 여러 번 실행해도 안전합니다
(Knowledge/모델은 이름·ID 로 재사용, 파일은 이미 올린 파일명은 건너뜁니다).

사용법:
  python3 scripts/bootstrap_assistant.py \
      --url http://localhost:3000 --email admin@example.local --password '...' \
      --docs docs_src --base-model vcf-llm
"""
import argparse
import json
import mimetypes
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

KNOWLEDGE_NAME = "VCF Docs"
MODEL_ID = "vcf-assistant"
EXTS = {".pdf", ".md", ".txt", ".html", ".htm", ".docx", ".csv", ".json"}


def call(base, method, path, token=None, body=None, raw=None, ctype=None):
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = raw
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if ctype:
        headers["Content-Type"] = ctype
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=600) as r:
            txt = r.read().decode()
            return json.loads(txt) if txt else {}
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{method} {path} -> {e.code}: {e.read().decode(errors='replace')}")


def upload(base, token, path):
    boundary = uuid.uuid4().hex
    name = os.path.basename(path)
    mime = mimetypes.guess_type(name)[0] or "application/octet-stream"
    with open(path, "rb") as f:
        content = f.read()
    raw = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
        f"Content-Type: {mime}\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    return call(base, "POST", "/api/v1/files/", token, raw=raw,
                ctype=f"multipart/form-data; boundary={boundary}")


def wait_processed(base, token, file_id, timeout=900):
    """신규 버전은 비동기 처리. 상태 API 가 없으면(404) 즉시 통과."""
    end = time.time() + timeout
    while time.time() < end:
        try:
            st = call(base, "GET", f"/api/v1/files/{file_id}/process/status", token)
        except RuntimeError as e:
            if " 404" in str(e):
                return
            raise
        if st.get("status") == "completed":
            return
        if st.get("status") == "failed":
            raise RuntimeError(f"file {file_id} processing failed: {st}")
        time.sleep(2)
    raise TimeoutError(file_id)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:3000")
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--docs", default="docs_src")
    ap.add_argument("--base-model", default="vcf-llm", help="LLM_SERVED_NAME (또는 PAIS 모델명)")
    ap.add_argument("--prompt", default="prompts/system_prompt_ko.txt")
    a = ap.parse_args()
    base = a.url.rstrip("/")

    token = call(base, "POST", "/api/v1/auths/signin", body={"email": a.email, "password": a.password})["token"]

    # 1) Knowledge
    kbs = call(base, "GET", "/api/v1/knowledge/", token)
    kbs = kbs.get("items", kbs) if isinstance(kbs, dict) else kbs
    kb = next((k for k in kbs if k["name"] == KNOWLEDGE_NAME), None)
    if not kb:
        kb = call(base, "POST", "/api/v1/knowledge/create", token,
                  body={"name": KNOWLEDGE_NAME, "description": "VCF 공식 문서/KB/Runbook"})
    kb_id = kb["id"]
    kb = call(base, "GET", f"/api/v1/knowledge/{kb_id}", token)
    existing = {f.get("meta", {}).get("name") for f in kb.get("files", [])}

    # 2) 문서 업로드
    files = []
    for root, _, names in os.walk(a.docs):
        for n in sorted(names):
            if os.path.splitext(n)[1].lower() in EXTS and n.lower() != "readme.md":
                files.append(os.path.join(root, n))
    for i, p in enumerate(files, 1):
        n = os.path.basename(p)
        if n in existing:
            print(f"[{i}/{len(files)}] skip   {n}")
            continue
        print(f"[{i}/{len(files)}] upload {n}")
        fid = upload(base, token, p)["id"]
        wait_processed(base, token, fid)
        call(base, "POST", f"/api/v1/knowledge/{kb_id}/file/add", token, body={"file_id": fid})

    # 3) 모델 프리셋 (시스템 프롬프트 + Knowledge 고정, 도구 없음 = 조회 전용)
    with open(a.prompt, encoding="utf-8") as f:
        system = f.read().strip()
    kb = call(base, "GET", f"/api/v1/knowledge/{kb_id}", token)
    payload = {
        "id": MODEL_ID,
        "name": "VCF 운영 어시스턴트",
        "base_model_id": a.base_model,
        "params": {"system": system, "temperature": 0.2},
        "meta": {"description": "VCF 문서 기반 조회 전용 어시스턴트", "knowledge": [kb], "toolIds": []},
        "access_control": None,
        "is_active": True,
    }
    try:
        call(base, "POST", "/api/v1/models/create", token, body=payload)
        print("model created")
    except RuntimeError:
        call(base, "POST", f"/api/v1/models/model/update?id={MODEL_ID}", token, body=payload)
        print("model updated")
    print(f"완료. {base} 에서 'VCF 운영 어시스턴트' 모델을 선택하세요.")


if __name__ == "__main__":
    sys.exit(main())

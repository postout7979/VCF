#!/usr/bin/env python3
"""Open WebUI 초기 구성: 문서 업로드 -> Knowledge 생성 -> 'VCF 운영 어시스턴트' 모델 프리셋 생성.

표준 라이브러리만 사용합니다 (폐쇄망 호환). 여러 번 실행해도 안전합니다
(Knowledge/모델은 이름·ID 로 재사용, 파일은 이미 올린 파일명은 건너뜁니다).
모델 프리셋에는 'VCF Docs'(정적 문서)와 'VCF Ops Live'(VCF Operations 구조/속성 색인) 두 Knowledge,
그리고 실시간 조회 도구(ops-tools, 읽기 전용)가 연결됩니다.

사용법:
  python3 scripts/bootstrap_assistant.py \
      --url http://localhost:3000 --email admin@example.local --password '...' \
      --docs docs_src --base-model vcf-llm
"""
import argparse
import os
import sys

from owui import OWUI

KB_DOCS = "VCF Docs"
KB_OPS = "VCF Ops Live"
MODEL_ID = "vcf-assistant"
EXTS = {".pdf", ".md", ".txt", ".html", ".htm", ".docx", ".csv", ".json"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:3000")
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--docs", default="docs_src")
    ap.add_argument("--base-model", default="vcf-llm", help="LLM_SERVED_NAME")
    ap.add_argument("--prompt", default="prompts/system_prompt_ko.txt")
    ap.add_argument("--tool-id", default="server:vcf-ops",
                    help="Open WebUI 도구 서버 ID (compose 의 TOOL_SERVER_CONNECTIONS info.id). 사용 안 하면 --no-tools")
    ap.add_argument("--no-tools", action="store_true", help="도구 연결 없이 RAG 전용으로 생성")
    a = ap.parse_args()

    ow = OWUI(a.url, a.email, a.password)

    # 1) Knowledge (정적 문서 / Ops 수집 데이터)
    docs_id = ow.get_or_create_knowledge(KB_DOCS, "VCF 공식 문서/KB/Runbook")
    ops_id = ow.get_or_create_knowledge(KB_OPS, "VCF Operations 수집 데이터 (ops_sync.py 가 주기적으로 갱신)")
    existing = set(ow.knowledge_files(docs_id))

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
        fid = ow.upload_path(p)["id"]
        ow.wait_processed(fid)
        ow.add_file(docs_id, fid)

    # 3) 모델 프리셋 (시스템 프롬프트 + Knowledge 고정 + 읽기 전용 VCF Ops 도구)
    with open(a.prompt, encoding="utf-8") as f:
        system = f.read().strip()
    payload = {
        "id": MODEL_ID,
        "name": "VCF 운영 어시스턴트",
        "base_model_id": a.base_model,
        "params": {"system": system, "temperature": 0.2, **({} if a.no_tools else {"function_calling": "native"})},
        "meta": {"description": "VCF 문서 + VCF Operations 수집 데이터 기반 조회 전용 어시스턴트",
                 "knowledge": [ow.knowledge(docs_id), ow.knowledge(ops_id)], "toolIds": [] if a.no_tools else [a.tool_id]},
        "access_control": None,
        "is_active": True,
    }
    try:
        ow.call("POST", "/api/v1/models/create", body=payload)
        print("model created")
    except RuntimeError:
        ow.call("POST", f"/api/v1/models/model/update?id={MODEL_ID}", body=payload)
        print("model updated")
    print(f"완료. {a.url} 에서 'VCF 운영 어시스턴트' 모델을 선택하세요.")


if __name__ == "__main__":
    sys.exit(main())

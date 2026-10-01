# docs_src

RAG로 색인할 문서를 이 디렉터리에 넣습니다 (PDF, HTML, MD, TXT, DOCX).
`scripts/bootstrap_assistant.py` 가 이 디렉터리를 Open WebUI Knowledge로 업로드합니다.

권장 구성 (버전 명시 필수 — 파일명에 VCF 버전을 포함하세요):

    docs_src/vcf-9.1/…            VCF/vSphere/NSX/vSAN/Operations 공식 문서
    docs_src/kb/…                 Broadcom KB 아티클
    docs_src/runbook/…            사내 Runbook, 장애 이력

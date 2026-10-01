#!/usr/bin/env bash
# 기동 후 백엔드 헬스/응답 확인
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
dc() { docker compose "$@"; }
echo "[1] LLM"
dc exec -T open-webui python - <<PY
import json,urllib.request,os
b=os.environ["OPENAI_API_BASE_URL"]
r=urllib.request.Request(b+"/chat/completions",json.dumps({"model":"${LLM_SERVED_NAME}","messages":[{"role":"user","content":"vSAN이 뭐야? 한 문장으로."}],"max_tokens":100}).encode(),{"Content-Type":"application/json","Authorization":"Bearer "+os.environ["OPENAI_API_KEY"]})
print(json.load(urllib.request.urlopen(r,timeout=120))["choices"][0]["message"]["content"])
PY
echo "[2] Embedding"
dc exec -T open-webui python - <<PY
import json,urllib.request,os
b=os.environ["RAG_OPENAI_API_BASE_URL"]
r=urllib.request.Request(b+"/embeddings",json.dumps({"model":"${EMBED_SERVED_NAME}","input":["테스트 문장"]}).encode(),{"Content-Type":"application/json","Authorization":"Bearer "+os.environ["RAG_OPENAI_API_KEY"]})
print("dim =",len(json.load(urllib.request.urlopen(r,timeout=60))["data"][0]["embedding"]))
PY
echo "OK"

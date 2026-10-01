#!/usr/bin/env bash
# [인터넷 연결된 반입용 호스트에서 실행]
# 컨테이너 이미지와 모델 가중치를 받아 폐쇄망 반입용 번들(./images, ./models)을 만듭니다.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -f .env ] || cp .env.example .env
set -a; . ./.env; set +a

IMAGES=(
  "vllm/vllm-openai:${VLLM_TAG}"
  "ghcr.io/open-webui/open-webui:${OPENWEBUI_TAG}"
  "${TEI_IMAGE}"
  "${PGVECTOR_IMAGE}"
  "${OPS_SYNC_IMAGE}"
)
mkdir -p images models
for img in "${IMAGES[@]}"; do docker pull "$img"; done
docker save "${IMAGES[@]}" | gzip > images/vcf-ai-assistant-images.tar.gz

# 모델 다운로드 (pip install -U "huggingface_hub[cli]")
# LLM_DIR 이 FP8 이면 repo 이름에 -FP8 이 포함된 저장소를 사용합니다.
hf download "Qwen/${LLM_DIR}"       --local-dir "models/${LLM_DIR}"
hf download "BAAI/bge-m3"           --local-dir "models/${EMBED_DIR}"
hf download "BAAI/bge-reranker-v2-m3" --local-dir "models/${RERANK_DIR}"

# 무결성 검증용 해시
( cd models && find . -type f ! -name '.gitkeep' -print0 | sort -z | xargs -0 sha256sum ) > models/SHA256SUMS
sha256sum images/*.tar.gz > images/SHA256SUMS
echo "완료: images/ 와 models/ 디렉터리를 폐쇄망으로 반입하세요."

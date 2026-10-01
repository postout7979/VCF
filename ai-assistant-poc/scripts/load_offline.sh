#!/usr/bin/env bash
# [폐쇄망 호스트에서 실행] 반입한 이미지 로드 및 해시 검증
set -euo pipefail
cd "$(dirname "$0")/.."
( cd images && sha256sum -c SHA256SUMS )
( cd models && sha256sum -c SHA256SUMS --quiet )
gunzip -c images/vcf-ai-assistant-images.tar.gz | docker load
[ -f .env ] || cp .env.example .env
echo "로드 완료. .env 의 비밀번호를 수정한 뒤 README 의 기동 절차를 따르세요."

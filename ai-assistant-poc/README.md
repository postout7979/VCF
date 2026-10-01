# VCF 운영 어시스턴트 PoC (폐쇄망 / 조회 전용 RAG / PAIS 미사용 단독 구성)

VCF 문서·KB·Runbook을 근거로 한국어로 답하는 **조회 전용** 어시스턴트를 docker-compose로 구성하는 PoC입니다.
동시 사용자 10명 이내, 한국어 질의 중심을 기준으로 설계했습니다.

> **검증 상태**: `docker compose config` 문법 검증과 스크립트 구문 검사까지만 했습니다. GPU가 없는 환경이라 **실제 기동·모델 응답·문서 업로드는 테스트하지 못했습니다.** 이미지 태그와 Open WebUI 환경변수/API는 버전에 따라 달라질 수 있으니, 반입 시점에 버전을 고정하고 아래 3장의 스모크 테스트로 확인하세요.

## 1. 구성

```
사용자 ──> Open WebUI (RAG/UI, 조회 전용) ──> vLLM (Qwen3-30B-A3B-Instruct-2507-FP8)
                │                                  
                ├──> TEI (bge-m3 임베딩)
                ├──> bge-reranker-v2-m3 (Open WebUI 내장, CPU)
                └──> PGVector (벡터DB + 앱 DB)
```

| 구성요소 | 역할 | 비고 |
|---|---|---|
| vLLM | LLM 추론 (OpenAI 호환 API) | GPU 1장 |
| TEI | 임베딩 (bge-m3) | 기본 CPU |
| Open WebUI | 채팅 UI, 하이브리드 검색(BM25+벡터), 리랭킹, 사용자 관리 | 도구/코드실행/웹검색 비활성 |
| PGVector | 벡터DB | PAIF의 PGVector와 같은 계열 |

**조회 전용 보장 방식**: 도구(Tool)·함수·코드 실행·웹 검색을 모두 끄고, 모델 프리셋에 `toolIds: []`를 지정했으며, vCenter/NSX 등 인프라 API를 연결하지 않았습니다. LLM이 시스템을 변경할 경로 자체가 없습니다. `backend` 네트워크는 `internal`이라 LLM/DB 컨테이너는 외부와 통신하지 않습니다(Open WebUI는 포트 게시를 위해 `frontend` 네트워크에 있으며 `OFFLINE_MODE`로 외부 조회를 막습니다).

## 2. 사양 가이드 (10명 이내)

| 항목 | 권장 |
|---|---|
| GPU | 48GB 1장 (L40S/A6000 등) — 기본 모델 FP8 약 31GB + KV 캐시 |
| 80GB 1장일 때 | `LLM_DIR`을 BF16 모델(`Qwen3-30B-A3B-Instruct-2507`)로 변경, 컨텍스트 여유 확대 |
| GPU 24GB급 | `gpt-oss-20b` 등 경량 모델로 교체 (품질은 사내 질문셋으로 재평가) |
| CPU/RAM/디스크 | 16 vCPU / 64GB / 200GB (모델 약 70GB + 문서/DB) |
| 동시성 | `LLM_MAX_SEQS=16`이면 10명 동시 질의에 충분 |

모델 선정 이유: Qwen3-30B-A3B-Instruct-2507은 **non-thinking 모델**이라 응답이 빠르고, MoE 구조(활성 3B)라 동시 사용자 처리에 유리하며, 한국어 품질이 양호합니다. 임베딩 bge-m3와 리랭커 bge-reranker-v2-m3는 한국어 다국어 검색에 적합합니다. **한국어 특화 모델(EXAONE, HyperCLOVA X SEED 등)** 은 라이선스(상업/조직 내 사용 조건)를 확인한 뒤 같은 방식으로 교체할 수 있습니다(`LLM_DIR`만 변경).

## 3. 절차

### 3.1 반입 번들 만들기 (인터넷 호스트)
```bash
cd ai-assistant-poc
pip install -U "huggingface_hub[cli]"
./scripts/prepare_offline.sh      # images/ + models/ 생성, SHA256SUMS 포함
```
`.env`가 없으면 `.env.example`에서 복사됩니다. **이 시점에 `VLLM_TAG`, `OPENWEBUI_TAG`를 검증된 구체 버전으로 고정**하세요(`latest`/`main` 금지 권장).

### 3.2 폐쇄망에서 기동
```bash
./scripts/load_offline.sh                 # 해시 검증 + 이미지 로드
vi .env                                   # 비밀번호 3종 변경 (WEBUI_SECRET_KEY, ADMIN, POSTGRES)
docker compose up -d
docker compose logs -f vllm-chat          # "Application startup complete" 까지 대기
./scripts/smoke_test.sh                   # LLM / 임베딩 응답 확인
```
GPU 컨테이너를 쓰려면 호스트에 NVIDIA Container Toolkit이 필요합니다. (VM에서 구동 시 vGPU 또는 DirectPath I/O 패스스루)

### 3.3 문서 색인 및 어시스턴트 생성
```bash
cp -r <VCF문서> docs_src/vcf-9.1/         # 파일명/폴더에 버전 포함
python3 scripts/bootstrap_assistant.py \
  --url http://localhost:3000 --email "$WEBUI_ADMIN_EMAIL" --password '<관리자PW>' \
  --docs docs_src --base-model vcf-llm
```
브라우저에서 `http://<호스트>:3000` → 모델 **"VCF 운영 어시스턴트"** 선택. 스크립트는 재실행해도 이미 올린 파일은 건너뜁니다. 시스템 프롬프트는 `prompts/system_prompt_ko.txt`에서 수정합니다(수정 후 스크립트 재실행).

### 3.4 일반 사용자 추가
관리자 패널에서 사용자를 생성합니다(가입은 비활성). 사내 LDAP/SSO 연동은 Open WebUI의 LDAP/OIDC 설정으로 확장합니다.

## 4. 품질 튜닝 (정확도는 여기서 결정됨)

1. **평가셋 먼저**: 실제 운영 질문 30~50개와 정답 문서를 준비하고, 모델/청크/Top-K를 바꿔 가며 비교합니다.
2. **청킹**: 기본 1000자/150 오버랩. 표·명령어가 많은 문서는 크기를 늘리고, KB처럼 짧은 문서는 줄입니다(`RAG_CHUNK_SIZE`).
3. **검색**: 하이브리드 + 리랭커가 기본 켜져 있습니다. 답이 부정확하면 `RAG_TOP_K`를 올리고 `RAG_TOP_K_RERANKER`로 최종 컨텍스트 수를 조절합니다.
4. **버전 혼선 방지**: 문서 버전별로 Knowledge를 분리하거나(예: `VCF 9.1`, `VCF 9.0`) 파일명에 버전을 넣어 출처 표기에서 구분되게 합니다.
5. **PDF 품질**: 스캔 PDF는 텍스트 추출이 안 되므로 사전에 OCR 처리합니다.
6. **갱신**: VCF 패치/버전 업데이트 때 문서를 교체하고 스크립트를 재실행합니다.

## 5. 단독 구성 범위 (PAIS 미사용)

이 구성은 PAIF/PAIS 서비스(Model Store, Model Endpoints, Data Indexing and Retrieval, Agent Builder)에 **의존하지 않습니다.** 필요한 기능은 모두 오픈소스 컨테이너로 대체합니다.

| 필요 기능 | 단독 구성의 대체 |
|---|---|
| 모델 저장/버전 관리 | `models/` 디렉터리 + `SHA256SUMS` 검증 (모델 교체 이력은 별도 기록) |
| 모델 서빙/API | vLLM, TEI (OpenAI 호환 API) |
| 색인·검색 | Open WebUI RAG + PGVector |
| RAG 앱 구성 | Open WebUI 모델 프리셋 (`bootstrap_assistant.py`) |

운영 시 직접 챙겨야 할 것 (PAIS가 해 주던 부분): GPU 드라이버/Container Toolkit 관리, 이미지·모델 버전 고정과 반입 검증, 사용자 인증(필요 시 LDAP/OIDC 연동), 백업, 접근 로그/감사. VM에 올릴 경우 GPU는 vGPU 또는 DirectPath I/O 패스스루로 연결합니다.

## 6. 운영/보안 체크리스트

- [ ] `.env`의 기본 비밀번호 변경, `.env` 권한 600, 저장소에 커밋 금지(`.gitignore` 처리됨)
- [ ] Open WebUI 앞단에 사내 TLS 종단(리버스 프록시) 적용 — 현재는 HTTP
- [ ] 모델/이미지 반입 시 `SHA256SUMS` 검증, 라이선스 기록
- [ ] 백업: `pgdata`, `webui-data` 볼륨 (스냅샷 또는 `pg_dump`)
- [ ] 답변에 출처·버전 표기 확인, 근거 없을 때 "확인할 수 없음" 응답 확인
- [ ] 변경 작업은 어시스턴트 범위 밖: 절차 안내만 하고 실행은 기존 변경관리 절차로

## 7. 트러블슈팅

| 증상 | 점검 |
|---|---|
| vLLM이 OOM/기동 실패 | `LLM_MAX_LEN` 축소(16384), `LLM_GPU_UTIL` 조정, FP8 모델 사용, GPU 드라이버/Container Toolkit 확인 |
| Open WebUI에 모델이 안 보임 | `docker compose logs open-webui`, vLLM 컨테이너 상태와 `smoke_test.sh` 결과 |
| 업로드한 문서가 검색 안 됨 | 임베딩 엔드포인트 확인, 로그의 처리 실패 여부, 스캔 PDF(OCR 필요) 여부 |
| 리랭커 로딩 실패 | `models/bge-reranker-v2-m3` 마운트 경로 확인, 오프라인 모드에서 외부 다운로드 시도 로그 확인 |
| 한국어 답변에 영어 섞임 | 시스템 프롬프트 규칙 1 강화, 모델 교체 평가 |
| `bootstrap_assistant.py` API 오류 | Open WebUI 버전에 따라 API 스키마가 다름 — 오류 메시지의 엔드포인트를 해당 버전 `/docs`(Swagger)와 대조해 수정 |

## 파일 구성

```
ai-assistant-poc/
├── docker-compose.yml          # 서비스 정의 
├── .env.example                # 설정 템플릿 (복사해서 .env 사용)
├── prompts/system_prompt_ko.txt
├── docs_src/                   # RAG 색인 대상 문서
├── models/                     # 모델 가중치 (git 제외)
└── scripts/
    ├── prepare_offline.sh      # 반입 번들 생성 (인터넷 호스트)
    ├── load_offline.sh         # 해시 검증 + 이미지 로드 (폐쇄망)
    ├── smoke_test.sh           # 기동 후 확인
    └── bootstrap_assistant.py  # Knowledge/모델 프리셋 자동 구성
```

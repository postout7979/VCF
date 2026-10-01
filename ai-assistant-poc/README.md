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

## 6. VCF Operations 연동 (하이브리드: 색인 + 질의 시점 조회)

데이터 성격에 따라 두 경로로 나눕니다. 5분마다 지표를 색인하면 매번 대부분의 문서를 재임베딩해야 하고, 의미 검색은 "CPU 80% 넘는 VM 상위 10개" 같은 숫자·집계 질의에 약하기 때문입니다. VCF Operations 자체의 수집 주기도 기본 약 5분이라 더 자주 가져와도 새 값이 없습니다(환경 설정으로 확인 필요).

| 데이터 | 경로 | 갱신 |
|---|---|---|
| 공식 문서, KB, Runbook | RAG (`VCF Docs`) | 변경 시 |
| 인벤토리 구조·속성(전원상태, vCPU, 메모리, 상위 클러스터/호스트) | RAG (`VCF Ops Live`, `ops-sync`) | 기본 6시간 |
| **헬스, 활성 알림, CPU/메모리 사용률, 상위 N개** | **질의 시점 조회 (`ops-tools`)** | 질의 때마다(60초 캐시) |

```
사용자 질문 ─> Open WebUI ─┬─ RAG 검색 ──────────> PGVector (문서 + 구조/속성)
                           └─ tool calling ──────> ops-tools ──(GET/조회 query)──> VCF Operations Suite API
                                (vLLM native)        읽기 전용 4개 함수
```

### 6.1 구성요소

- **`ops-tools`** (`scripts/ops_tools_server.py`): OpenAPI 도구 서버. 자유 API 접근이 아니라 **읽기 전용 GET 함수 4개**만 노출합니다.
  - `get_environment_summary` — 종류별 헬스 분포, 활성 알림 개수
  - `get_active_alerts(min_level, resource_name, limit)` — 활성 알림(심각도 순)
  - `find_resource_status(name, kind, limit)` — 이름으로 현재 헬스/상태/속성/최신 지표
  - `get_top_resources(kind, stat, order, limit)` — 지표 기준 상위/하위 N개
  - 지표는 허용 목록(`OPS_TOOL_STATS` 별칭)만 가능하고 OpenAPI **enum** 으로 노출되어 모델이 임의 키를 만들 수 없습니다. 결과 개수 상한, 응답의 `collected_at`/`truncated`, 60초 캐시, Bearer 키 인증을 적용했습니다. POST 등 쓰기 메서드는 405입니다.
- **`ops-sync`** (`scripts/ops_sync.py`): 구조/속성만 주기 색인. 해시가 바뀐 파일만 교체하고 더는 생성되지 않는 `vcfops-*` 문서는 삭제합니다(기존에 색인된 알림/요약 문서도 다음 동기화 때 정리됨).
- **모델 프리셋**: `bootstrap_assistant.py` 가 `VCF Docs` + `VCF Ops Live` Knowledge 와 도구 `server:vcf-ops`, `function_calling: native` 로 구성합니다. vLLM 은 `--enable-auto-tool-choice --tool-call-parser hermes` 로 기동됩니다.

### 6.2 환경 변수 (`.env`)

| 변수 | 설명 | 기본값 |
|---|---|---|
| `VCFOPS_URL`, `VCFOPS_USERNAME`, `VCFOPS_PASSWORD` | **읽기 전용 역할** 전용 계정 접속 정보 | (필수) |
| `VCFOPS_AUTH_SOURCE` | 외부 인증 소스명 (로컬 계정이면 비움) | 빈 값 |
| `VCFOPS_VERIFY_TLS`, `VCFOPS_CA_FILE` | TLS 검증, 사설 CA PEM(`./certs/`에 두고 `/certs/…`로 지정) | `true`, `/certs/vcfops-ca.pem` |
| `OPS_RESOURCE_KINDS` | 대상 리소스 종류 (색인·도구 공통) | `VirtualMachine,HostSystem,ClusterComputeResource,Datastore` |
| `OPS_TOOLS_API_KEY` | Open WebUI ↔ ops-tools Bearer 키 (**변경 필수**) | `change-me-tools-key` |
| `OPS_TOOL_STATS` | 도구가 노출할 지표 `별칭=stat key` | `cpu_usage_pct=cpu\|usage_average,mem_usage_pct=mem\|usage_average` |
| `OPS_TOOL_PROPERTY_KEYS` | 도구 응답에 넣을 속성 키 | `summary\|runtime\|powerState,summary\|parentCluster,summary\|parentHost` |
| `OPS_TOOL_MAX_LIMIT`, `OPS_TOOL_CACHE_TTL_SEC` | 결과 상한, 캐시(초) | `50`, `60` |
| `LLM_TOOL_PARSER` | vLLM tool-call 파서 (모델 교체 시 변경) | `hermes` |
| `OPS_SYNC_INTERVAL_MIN` | 색인 주기(분, 최소 5) | `360` |
| `OPS_COLLECT` | 색인 대상 (`inventory`, 차선책이면 `summary,alerts` 추가) | `inventory` |
| `OPS_INDEX_LIVE_VALUES` | 색인에 헬스/지표 포함 (비권장) | `false` |
| `OPS_PROPERTY_KEYS`, `OPS_MAX_RESOURCES_PER_KIND`, `OPS_CHUNK_ENTRIES` | 색인 속성 키, 종류당 상한, 문서당 항목 수 | (.env.example 참고) |

### 6.3 사용 절차
```bash
# 1) VCF Operations 에서 읽기 전용 계정 생성 → .env 입력, 사설 CA 는 certs/ 에 배치, OPS_TOOLS_API_KEY 변경
# 2) 실제 키 확인 (환경변수 로드 후, 컨테이너 밖에서)
set -a; . ./.env; set +a
python3 scripts/ops_sync.py --discover VirtualMachine        # stat/property 키 후보 -> OPS_TOOL_STATS 등에 반영
python3 scripts/ops_sync.py --dry-run                        # 색인될 문서를 ./ops_out/ 에서 확인
# 3) 기동 (vLLM 은 tool calling 옵션이 추가되었으므로 재생성)
docker compose --profile ops up -d
docker compose logs -f ops-tools ops-sync
# 4) 모델 프리셋 구성 (도구 연결 포함)
python3 scripts/bootstrap_assistant.py --email "$WEBUI_ADMIN_EMAIL" --password '<관리자PW>' --base-model vcf-llm
# 5) 도구 서버 직접 확인 (선택): compose 네트워크 안에서
docker compose exec open-webui python -c "import urllib.request as u;r=u.Request('http://ops-tools:8000/summary',headers={'Authorization':'Bearer $OPS_TOOLS_API_KEY'});print(u.urlopen(r).read()[:300])"
```
Open WebUI 채팅에서 "VCF 운영 어시스턴트"를 선택하고 "지금 CRITICAL 알림 알려줘", "CPU 사용률 높은 호스트 5개" 등으로 확인하세요. 도구가 호출되면 응답에 호출 내역이 표시됩니다.

### 6.4 알아둘 점 / 한계
- **PersistentConfig**: compose 의 `TOOL_SERVER_CONNECTIONS` 는 Open WebUI **최초 기동 시에만** 적용됩니다. 이후 키/주소를 바꾸려면 관리자 UI(설정 → 도구)에서 수정하거나 `ENABLE_PERSISTENT_CONFIG=false` 를 설정하세요. UI에서 수동 등록할 때는 URL `http://ops-tools:8000`, 경로 `openapi.json`, 인증 Bearer, ID `vcf-ops` 로 맞추면 bootstrap 이 그대로 동작합니다.
- **조회 전용**: 도구는 GET 4개뿐이고, VCF Operations 클라이언트는 GET·조회용 `…/query` POST·토큰 발급 외 호출을 코드에서 차단합니다. 계정 권한도 읽기 전용으로 제한하세요.
- **신선도**: "실시간"은 VCF Operations 수집 주기(약 5분) 한도입니다. 응답과 답변에 조회 시각이 표시됩니다.
- **모델 의존**: tool calling 정확도는 모델에 좌우됩니다. 평가셋(4장)에 "도구를 호출해야 하는 질문"을 포함해 확인하세요. 모델이 도구를 안 쓰고 추측하면 시스템 프롬프트 규칙 8을 강화하거나 모델을 교체하세요.
- **규모/부하**: `top_resources`, `summary` 는 종류별 전체 리소스를 조회합니다(상한 `OPS_MAX_RESOURCES_PER_KIND`). 캐시로 완화되지만 수천 개 규모라면 종류와 상한을 조정하세요.
- **도구 없이 쓰는 차선책**: `--no-tools` 로 프리셋을 만들고 `OPS_COLLECT=summary,alerts,inventory`, `OPS_INDEX_LIVE_VALUES=true`, 짧은 주기로 설정하면 색인만으로 동작합니다(재임베딩 비용과 숫자 질의 정확도 한계 있음).
- **민감 정보**: 리소스 이름은 Open WebUI 사용자에게 보입니다. 권한이 다른 사용자가 있다면 수집 종류를 줄이거나 접근 제어를 설정하세요. `.env` 에 비밀번호가 평문이므로 권한 600, 관리자 계정 재사용은 운영 전환 시 전용 계정으로 분리하세요.

> **검증 상태**: `ops-tools` 와 `ops-sync` 는 VCF Operations 를 모사한 **목(mock) 서버**로 동작을 확인했습니다(인증, enum 검증, 정렬, 캐시, 쓰기 메서드 차단, 변경 감지 교체). 목 서버는 제가 알고 있는 Suite API 응답 형태를 가정한 것이므로 **실제 VCF Operations 9.1.1 의 엔드포인트/응답 필드/지표 키는 검증하지 못했습니다.** 또한 **Open WebUI 의 `TOOL_SERVER_CONNECTIONS` 형식, `server:vcf-ops` 도구 ID, native function calling 과 vLLM hermes 파서 조합은 실제 GPU 환경에서 기동해 확인하지 못했습니다.** 버전에 따라 다를 수 있으니 처음에는 6.3 절 순서대로 단계별로 확인하세요.

## 7. 운영/보안 체크리스트

- [ ] `.env`의 기본 비밀번호 변경, `.env` 권한 600, 저장소에 커밋 금지(`.gitignore` 처리됨)
- [ ] Open WebUI 앞단에 사내 TLS 종단(리버스 프록시) 적용 — 현재는 HTTP
- [ ] 모델/이미지 반입 시 `SHA256SUMS` 검증, 라이선스 기록
- [ ] 백업: `pgdata`, `webui-data` 볼륨 (스냅샷 또는 `pg_dump`)
- [ ] 답변에 출처·버전 표기 확인, 근거 없을 때 "확인할 수 없음" 응답 확인
- [ ] 변경 작업은 어시스턴트 범위 밖: 절차 안내만 하고 실행은 기존 변경관리 절차로

## 8. 트러블슈팅

| 증상 | 점검 |
|---|---|
| vLLM이 OOM/기동 실패 | `LLM_MAX_LEN` 축소(16384), `LLM_GPU_UTIL` 조정, FP8 모델 사용, GPU 드라이버/Container Toolkit 확인 |
| Open WebUI에 모델이 안 보임 | `docker compose logs open-webui`, vLLM 컨테이너 상태와 `smoke_test.sh` 결과 |
| 업로드한 문서가 검색 안 됨 | 임베딩 엔드포인트 확인, 로그의 처리 실패 여부, 스캔 PDF(OCR 필요) 여부 |
| 리랭커 로딩 실패 | `models/bge-reranker-v2-m3` 마운트 경로 확인, 오프라인 모드에서 외부 다운로드 시도 로그 확인 |
| 한국어 답변에 영어 섞임 | 시스템 프롬프트 규칙 1 강화, 모델 교체 평가 |
| 모델이 도구를 호출하지 않고 추측함 | vLLM 기동 로그의 tool parser, 프리셋 `function_calling: native` 적용 여부, 프롬프트 규칙 8, 모델 교체 평가 |
| 도구 호출 401/연결 오류 | `OPS_TOOLS_API_KEY` 일치, PersistentConfig(6.4), `docker compose logs ops-tools` |
| `ops_sync` 가 "수집 실패/건너뜀" 로그 | `--discover` 로 실제 키 확인, 계정 권한/TLS(`VCFOPS_CA_FILE`) 확인 |
| `bootstrap_assistant.py` API 오류 | Open WebUI 버전에 따라 API 스키마가 다름 — 오류 메시지의 엔드포인트를 해당 버전 `/docs`(Swagger)와 대조해 수정 |

## 파일 구성

```
ai-assistant-poc/
├── docker-compose.yml          # 서비스 정의 
├── .env.example                # 설정 템플릿 (복사해서 .env 사용)
├── prompts/system_prompt_ko.txt
├── certs/                      # VCF Operations 사설 CA PEM (git 제외)
├── docs_src/                   # RAG 색인 대상 문서
├── models/                     # 모델 가중치 (git 제외)
└── scripts/
    ├── prepare_offline.sh      # 반입 번들 생성 (인터넷 호스트)
    ├── load_offline.sh         # 해시 검증 + 이미지 로드 (폐쇄망)
    ├── smoke_test.sh           # 기동 후 확인
    ├── bootstrap_assistant.py  # Knowledge/모델 프리셋 자동 구성
    ├── ops_sync.py             # VCF Operations 구조/속성 -> Knowledge 색인
    ├── ops_tools_server.py     # 실시간 조회 OpenAPI 도구 서버 (읽기 전용)
    ├── opslib.py               # VCF Operations 공용 클라이언트 (읽기 전용 가드)
    └── owui.py                 # Open WebUI API 클라이언트 (공용)
```

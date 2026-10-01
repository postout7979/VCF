#!/usr/bin/env python3
"""VCF Operations(Suite API) 조회 결과를 문서로 변환해 Open WebUI Knowledge('VCF Ops Live')에 색인.

- 읽기 전용: 토큰 발급(POST /auth/token/acquire), GET 조회, 그리고 조회용 bulk 'query' POST 만 허용합니다.
  그 외 쓰기성 호출은 클라이언트 레벨에서 차단됩니다. 계정도 VCF Operations 에서 읽기 전용 역할로 만드세요.
- 하이브리드 운영: 기본값은 느리게 변하는 "구조/속성"(inventory)만 색인합니다. 헬스/활성 알림/지표 같은 실시간 값은
  ops_tools_server.py(OpenAPI 도구 서버)가 질의 시점에 직접 조회합니다. 도구 없이 쓰려면
  OPS_COLLECT=summary,alerts,inventory + OPS_INDEX_LIVE_VALUES=true + 짧은 주기로 실시간 값을 색인할 수도 있습니다.
- 내용이 바뀐 문서만 교체(재임베딩)합니다. 수집 시각은 각 항목에 표기됩니다.

설정은 모두 환경변수 (.env.example 참고). 표준 라이브러리만 사용.

  python3 scripts/ops_sync.py --dry-run          # Open WebUI 에 올리지 않고 ./ops_out 에 문서만 생성 (검증용)
  python3 scripts/ops_sync.py --discover VirtualMachine   # 해당 종류의 사용 가능한 stat/property 키 출력
  python3 scripts/ops_sync.py                    # 1회 동기화
  python3 scripts/ops_sync.py --loop             # OPS_SYNC_INTERVAL_MIN 분마다 반복 (컨테이너 기본)
"""
import argparse
import hashlib
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone

from opslib import (OpsClient, bulk_properties, bulk_stats, env, fmt_num, log, ms_to_iso,
                    res_kind, res_name, resolve_names, split_csv)

KB_OPS = "VCF Ops Live"
PREFIX = "vcfops-"
TS_TOKEN = "@@TS@@"
BATCH = 100


# ---------------------------------------------------------------- 문서 생성
def header(title, desc):
    return (f"# {title}\n\n출처: VCF Operations Suite API ({env('VCFOPS_URL')}) / 수집 시각(UTC): {TS_TOKEN}\n"
            f"{desc}\n\n")


def collect_inventory(ops):
    """kind 별 문서 {파일명: 본문(@@TS@@ 포함)}, 요약용 카운터, id→이름 맵."""
    kinds = split_csv(env("OPS_RESOURCE_KINDS", "VirtualMachine,HostSystem,ClusterComputeResource,Datastore"))
    # 하이브리드 기본: 색인에는 "구조/속성"만 넣고, 헬스/지표 같은 실시간 값은 ops-tools 가 질의 시점에 조회
    live = env("OPS_INDEX_LIVE_VALUES", "false").lower() in ("1", "true", "yes")
    stat_keys = split_csv(env("OPS_STAT_KEYS", "cpu|usage_average,mem|usage_average")) if live else []
    prop_keys = split_csv(env("OPS_PROPERTY_KEYS",
                              "summary|runtime|powerState,config|hardware|num_Cpu,config|hardware|memoryKB,"
                              "summary|parentCluster,summary|parentHost"))
    max_n = int(env("OPS_MAX_RESOURCES_PER_KIND", "2000"))
    per_file = int(env("OPS_CHUNK_ENTRIES", "80"))

    docs, counters, names = {}, {}, {}
    for kind in kinds:
        try:
            resources = ops.paged("/resources", "resourceList", {"resourceKind": kind}, limit=max_n)
        except Exception as e:
            log(f"inventory[{kind}] 실패: {e}")
            continue
        ids = [r["identifier"] for r in resources]
        props, stats = {}, {}
        try:
            props = bulk_properties(ops, ids, prop_keys) if prop_keys and ids else {}
        except Exception as e:
            log(f"properties[{kind}] 건너뜀: {e}")
        try:
            stats = bulk_stats(ops, ids, stat_keys) if stat_keys and ids else {}
        except Exception as e:
            log(f"stats[{kind}] 건너뜀: {e}")

        counters[kind] = Counter(r.get("resourceHealth", "UNKNOWN") for r in resources)
        entries = []
        for r in sorted(resources, key=res_name):
            rid = r["identifier"]
            names[rid] = res_name(r)
            kv = {k: v for k, v in {**props.get(rid, {}), **stats.get(rid, {})}.items() if v is not None}
            extra = ", ".join(f"{k}={fmt_num(v)}" for k, v in kv.items())
            live_txt = (f", health={r.get('resourceHealth', '-')}, status="
                        f"{','.join(s.get('resourceState', '') for s in r.get('resourceStatusStates', [])) or '-'}") if live else ""
            entries.append(f"- [{kind}] {res_name(r)}" + live_txt
                           + (f" — {extra}" if extra and not live else (f", {extra}" if extra else ""))
                           + f" (수집 {TS_TOKEN})")
        for n, i in enumerate(range(0, max(len(entries), 1), per_file), 1):
            chunk = entries[i:i + per_file]
            if not chunk:
                continue
            docs[f"{PREFIX}inventory-{kind}-{n:03d}.md"] = (
                header(f"VCF Operations 인벤토리: {kind} ({n}번째 묶음)",
                       "각 항목은 수집 시점의 구조/속성 스냅샷입니다. "
                       + ("헬스/상태/지표 값이 포함됩니다 (usage_average=%)."
                          if live else "헬스·알림·사용률 같은 실시간 값은 포함하지 않으며 도구(ops-tools)로 조회해야 합니다."))
                + "\n".join(chunk) + "\n")
    return docs, counters, names


def collect_alerts(ops, names):
    alerts = ops.paged("/alerts", "alerts", {"activeOnly": "true"}, limit=int(env("OPS_MAX_ALERTS", "2000")))
    resolve_names(ops, [a.get("resourceId") for a in alerts], names)
    order = {"CRITICAL": 0, "IMMEDIATE": 1, "WARNING": 2, "INFORMATION": 3}
    alerts.sort(key=lambda a: (order.get(a.get("alertLevel"), 9), -(a.get("startTimeUTC") or 0)))
    lines = []
    for a in alerts:
        lines.append(f"- [ALERT/{a.get('alertLevel', '-')}] {a.get('alertDefinitionName', '-')} — 대상: "
                     f"{names.get(a.get('resourceId'), a.get('resourceId', '-'))}, 상태={a.get('status', '-')}, "
                     f"제어상태={a.get('controlState', '-')}, 영향={a.get('alertImpact', '-')}, "
                     f"발생={ms_to_iso(a.get('startTimeUTC'))} (수집 {TS_TOKEN})")
    body = "\n".join(lines) if lines else "- 현재 활성 알림이 없습니다."
    docs = {f"{PREFIX}alerts-active.md": header("VCF Operations 활성 알림", f"활성 알림 총 {len(alerts)}건 (심각도 순).") + body + "\n"}
    return docs, Counter(a.get("alertLevel", "-") for a in alerts)


def build_summary(counters, alert_counter):
    lines = ["## 종류별 헬스 분포"]
    for kind, c in counters.items():
        lines.append(f"- {kind}: 총 {sum(c.values())}개 — " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())))
    if alert_counter is not None:
        lines.append("\n## 활성 알림 분포")
        lines.append("- " + (", ".join(f"{k} {v}" for k, v in alert_counter.most_common()) or "없음"))
    return {f"{PREFIX}summary.md": header("VCF Operations 환경 요약", "수집 시점의 환경 전체 요약입니다.") + "\n".join(lines) + "\n"}


def generate_docs(ops):
    collect = set(split_csv(env("OPS_COLLECT", "inventory")))
    docs, counters, names, alert_counter = {}, {}, {}, None
    if collect & {"inventory", "summary"}:
        d, counters, names = collect_inventory(ops)
        if "inventory" in collect:
            docs.update(d)
    if "alerts" in collect or "summary" in collect:
        d, alert_counter = collect_alerts(ops, names)
        if "alerts" in collect:
            docs.update(d)
    if "summary" in collect:
        docs.update(build_summary(counters, alert_counter))
    return docs


# ---------------------------------------------------------------- 색인
def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()  # @@TS@@ 상태로 해시 -> 수집시각만 바뀐 경우 건너뜀


def sync_to_webui(docs, state_path, prune=True):
    from owui import OWUI
    ow = OWUI(env("WEBUI_URL", "http://open-webui:8080"), env("WEBUI_ADMIN_EMAIL"), os.environ.get("WEBUI_ADMIN_PASSWORD", ""))
    kb_id = ow.get_or_create_knowledge(KB_OPS, "VCF Operations 수집 데이터 (ops_sync.py 가 주기적으로 갱신)")
    try:
        state = json.load(open(state_path))
    except (OSError, ValueError):
        state = {}
    current = ow.knowledge_files(kb_id)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    changed = skipped = removed = 0

    for name, text in docs.items():
        h = digest(text)
        if name in current and state.get(name) == h:
            skipped += 1
            continue
        if name in current:  # 교체: 기존 파일 제거 후 재업로드
            ow.remove_file(kb_id, current[name])
            ow.delete_file(current[name])
        fid = ow.upload(name, text.replace(TS_TOKEN, now).encode())["id"]
        ow.wait_processed(fid)
        ow.add_file(kb_id, fid)
        state[name] = h
        changed += 1

    if prune:  # 더 이상 생성되지 않는 vcfops-* 문서 정리 (삭제된 종류/리소스 묶음)
        for name, fid in current.items():
            if name and name.startswith(PREFIX) and name not in docs:
                ow.remove_file(kb_id, fid)
                ow.delete_file(fid)
                state.pop(name, None)
                removed += 1
    os.makedirs(os.path.dirname(state_path) or ".", exist_ok=True)
    json.dump(state, open(state_path, "w"))
    log(f"색인 완료: 교체 {changed}, 변경없음 {skipped}, 삭제 {removed}")


def run_once(args):
    ops = OpsClient()
    docs = generate_docs(ops)
    if not docs:
        log("생성된 문서가 없습니다 (수집 실패 또는 OPS_COLLECT 설정 확인). 기존 색인은 유지합니다.")
        return 1
    log(f"문서 {len(docs)}개 생성")
    if args.dry_run:
        os.makedirs(args.out, exist_ok=True)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
        for name, text in docs.items():
            open(os.path.join(args.out, name), "w", encoding="utf-8").write(text.replace(TS_TOKEN, now))
        log(f"dry-run: {args.out}/ 에 저장 (Open WebUI 미변경)")
        return 0
    sync_to_webui(docs, args.state)
    return 0


def discover(kind):
    ops = OpsClient()
    res = ops.paged("/resources", "resourceList", {"resourceKind": kind}, limit=1)
    if not res:
        print(f"{kind} 리소스가 없습니다.")
        return 1
    rid = res[0]["identifier"]
    print(f"샘플 리소스: {res_name(res[0])} ({rid})")
    keys = ops.get(f"/resources/{rid}/statkeys").get("stat-key", [])
    print("\n[stat keys] OPS_STAT_KEYS 후보:")
    for k in keys[:200]:
        print("  ", k.get("key"))
    props = ops.get(f"/resources/{rid}/properties").get("property", [])
    print("\n[property keys] OPS_PROPERTY_KEYS 후보:")
    for p in props[:200]:
        print("  ", p.get("name"))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--out", default="ops_out")
    ap.add_argument("--state", default=env("OPS_STATE_FILE", "/state/ops_hashes.json"))
    ap.add_argument("--discover", metavar="RESOURCE_KIND")
    args = ap.parse_args()
    if args.discover:
        return discover(args.discover)
    if not args.loop:
        return run_once(args)
    interval = max(5, int(env("OPS_SYNC_INTERVAL_MIN", "360"))) * 60
    while True:
        try:
            run_once(args)
        except Exception as e:  # 일시 장애 시 다음 주기에 재시도, 기존 색인은 유지
            log(f"동기화 실패(다음 주기에 재시도): {e}")
        time.sleep(interval)


if __name__ == "__main__":
    sys.exit(main())

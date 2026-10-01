#!/usr/bin/env python3
"""VCF Operations 실시간 조회용 OpenAPI 도구 서버 (읽기 전용). Open WebUI 에 tool server 로 등록해 LLM 이 질의 시점에 호출.

노출 함수는 4개뿐이며 모두 GET 입니다 (자유 API 접근 없음):
  /summary         환경 요약 (종류별 헬스 분포, 활성 알림 분포)
  /alerts          활성 알림 목록
  /resource_status 이름으로 리소스 현재 상태/지표 조회
  /top_resources   지표 기준 상위/하위 N개

- 지표는 허용 목록(OPS_TOOL_STATS 별칭)만 조회 가능하고 OpenAPI enum 으로 노출되어 LLM 이 잘못된 키를 만들지 못합니다.
- 응답에는 항상 collected_at(조회 시각)이 들어가며, 결과 개수는 상한이 있습니다.
- 짧은 TTL 캐시(OPS_TOOL_CACHE_TTL_SEC)로 VCF Operations 부하를 제한합니다.
- 선택적 Bearer 인증: OPS_TOOLS_API_KEY 가 설정되면 필요합니다.

표준 라이브러리만 사용. 설정은 환경변수 (VCFOPS_* 는 ops_sync.py 와 공통).
"""
import json
import os
import sys
import threading
import time
import urllib.parse
from collections import Counter
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from opslib import (OpsClient, bulk_properties, bulk_stats, env, log, ms_to_iso, res_kind,
                    res_name, resolve_names, split_csv)

LEVELS = ["CRITICAL", "IMMEDIATE", "WARNING", "INFORMATION"]
KINDS = split_csv(env("OPS_RESOURCE_KINDS", "VirtualMachine,HostSystem,ClusterComputeResource,Datastore"))
# 별칭=실제 stat key
STATS = dict(p.split("=", 1) for p in split_csv(
    env("OPS_TOOL_STATS", "cpu_usage_pct=cpu|usage_average,mem_usage_pct=mem|usage_average")) if "=" in p)
PROPS = split_csv(env("OPS_TOOL_PROPERTY_KEYS", "summary|runtime|powerState,summary|parentCluster,summary|parentHost"))
MAX_RES = int(env("OPS_MAX_RESOURCES_PER_KIND", "2000"))
MAX_LIMIT = int(env("OPS_TOOL_MAX_LIMIT", "50"))
TTL = int(env("OPS_TOOL_CACHE_TTL_SEC", "60"))
API_KEY = env("OPS_TOOLS_API_KEY")

OPS = None
LOCK = threading.Lock()
CACHE = {}


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def envelope(data):
    return {"collected_at": now_iso(), "source": "VCF Operations Suite API",
            "note": "VCF Operations 수집 주기(기본 약 5분) 기준 최신값입니다.", **data}


def as_float(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def clamp(q, default):
    try:
        return max(1, min(int(q.get("limit", [default])[0]), MAX_LIMIT))
    except ValueError:
        return default


def first(q, k, default=None):
    return q.get(k, [default])[0]


def list_resources(kind):
    return OPS.paged("/resources", "resourceList", {"resourceKind": kind}, limit=MAX_RES)


# ---------------------------------------------------------------- 도구 구현
def summary(q):
    health = {}
    for kind in KINDS:
        c = Counter(r.get("resourceHealth", "UNKNOWN") for r in list_resources(kind))
        health[kind] = {"total": sum(c.values()), "health": dict(c)}
    alerts = OPS.paged("/alerts", "alerts", {"activeOnly": "true"}, limit=MAX_RES)
    return envelope({"health_by_kind": health,
                     "active_alerts": {"total": len(alerts), "by_level": dict(Counter(a.get("alertLevel", "-") for a in alerts))}})


def alerts(q):
    min_level = first(q, "min_level", "INFORMATION")
    if min_level not in LEVELS:
        raise ValueError(f"min_level 은 {LEVELS} 중 하나")
    limit = clamp(q, 20)
    sub = (first(q, "resource_name") or "").lower()
    items = OPS.paged("/alerts", "alerts", {"activeOnly": "true"}, limit=MAX_RES)
    names = {}
    resolve_names(OPS, [a.get("resourceId") for a in items], names)
    rank = {l: i for i, l in enumerate(LEVELS)}
    items = [a for a in items if rank.get(a.get("alertLevel"), 9) <= rank[min_level]
             and sub in names.get(a.get("resourceId"), "").lower()]
    items.sort(key=lambda a: (rank.get(a.get("alertLevel"), 9), -(a.get("startTimeUTC") or 0)))
    out = [{"level": a.get("alertLevel"), "alert": a.get("alertDefinitionName"),
            "resource": names.get(a.get("resourceId"), a.get("resourceId")), "status": a.get("status"),
            "control_state": a.get("controlState"), "impact": a.get("alertImpact"),
            "started": ms_to_iso(a.get("startTimeUTC"))} for a in items[:limit]]
    return envelope({"matched": len(items), "returned": len(out), "truncated": len(items) > len(out), "alerts": out})


def describe(r, props, stats):
    return {"name": res_name(r), "kind": res_kind(r), "health": r.get("resourceHealth"),
            "status": [s.get("resourceState") for s in r.get("resourceStatusStates", [])],
            "properties": {k: v for k, v in props.items() if v is not None},
            "metrics": {alias: stats.get(key) for alias, key in STATS.items() if stats.get(key) is not None}}


def resource_status(q):
    name, kind = first(q, "name"), first(q, "kind")
    if not name:
        raise ValueError("name 파라미터가 필요합니다")
    if kind and kind not in KINDS:
        raise ValueError(f"kind 는 {KINDS} 중 하나")
    limit = clamp(q, 5)
    found = []
    for k in ([kind] if kind else KINDS):
        found += [r for r in list_resources(k) if name.lower() in res_name(r).lower()]
    found.sort(key=lambda r: (res_name(r).lower() != name.lower(), res_name(r)))  # 정확히 일치하는 이름 우선
    shown = found[:limit]
    ids = [r["identifier"] for r in shown]
    props = bulk_properties(OPS, ids, PROPS) if ids and PROPS else {}
    stats = bulk_stats(OPS, ids, list(STATS.values())) if ids and STATS else {}
    return envelope({"matched": len(found), "returned": len(shown), "truncated": len(found) > len(shown),
                     "resources": [describe(r, props.get(r["identifier"], {}), stats.get(r["identifier"], {})) for r in shown]})


def top_resources(q):
    kind, stat = first(q, "kind"), first(q, "stat")
    order = first(q, "order", "desc")
    if kind not in KINDS or stat not in STATS or order not in ("asc", "desc"):
        raise ValueError(f"kind∈{KINDS}, stat∈{list(STATS)}, order∈[asc,desc] 필요")
    limit = clamp(q, 10)
    resources = list_resources(kind)
    stats = bulk_stats(OPS, [r["identifier"] for r in resources], [STATS[stat]])
    rows = []
    for r in resources:
        v = as_float(stats.get(r["identifier"], {}).get(STATS[stat]))
        if v is not None:
            rows.append((v, r))
    rows.sort(key=lambda x: x[0], reverse=(order == "desc"))
    return envelope({"kind": kind, "stat": stat, "order": order, "evaluated": len(rows), "total_resources": len(resources),
                     "results": [{"name": res_name(r), "value": round(v, 2), "health": r.get("resourceHealth")}
                                 for v, r in rows[:limit]]})


# ---------------------------------------------------------------- OpenAPI
def param(name, desc, schema, required=False):
    return {"name": name, "in": "query", "required": required, "description": desc, "schema": schema}


def openapi():
    lim = {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT}
    def op(oid, summ, desc, params):
        return {"get": {"operationId": oid, "summary": summ, "description": desc, "parameters": params,
                        "responses": {"200": {"description": "JSON 결과 (collected_at 포함)",
                                              "content": {"application/json": {"schema": {"type": "object"}}}}}}}
    return {
        "openapi": "3.0.3",
        "info": {"title": "VCF Operations (read-only)", "version": "1.0.0",
                 "description": "VCF Operations 의 현재 상태·알림·지표를 조회합니다. 모든 호출은 읽기 전용입니다. "
                                "답변할 때 반드시 응답의 collected_at 을 함께 알려주세요."},
        "paths": {
            "/summary": op("get_environment_summary", "환경 요약",
                           "종류별(VM/호스트/클러스터/데이터스토어) 헬스 분포와 활성 알림 개수를 반환합니다. 전반적인 상태 질문에 사용.", []),
            "/alerts": op("get_active_alerts", "활성 알림 목록",
                          "현재 활성 알림을 심각도 순으로 반환합니다. 특정 리소스 이름 일부로 필터할 수 있습니다.",
                          [param("min_level", "이 심각도 이상만 (기본 INFORMATION=전부)", {"type": "string", "enum": LEVELS}),
                           param("resource_name", "리소스 이름 일부 (부분 일치)", {"type": "string"}),
                           param("limit", f"최대 개수 (기본 20, 최대 {MAX_LIMIT})", lim)]),
            "/resource_status": op("find_resource_status", "리소스 현재 상태/지표",
                                   "이름(부분 일치)으로 VM/호스트/클러스터/데이터스토어를 찾아 헬스, 상태, 속성, 최신 지표를 반환합니다.",
                                   [param("name", "리소스 이름 (부분 일치)", {"type": "string"}, True),
                                    param("kind", "리소스 종류 (생략 시 전체 검색)", {"type": "string", "enum": KINDS}),
                                    param("limit", f"최대 개수 (기본 5, 최대 {MAX_LIMIT})", lim)]),
            "/top_resources": op("get_top_resources", "지표 기준 상위/하위 리소스",
                                 "특정 종류 리소스를 지표 값으로 정렬해 상위(desc) 또는 하위(asc) N개를 반환합니다. "
                                 "'CPU 사용률 높은 호스트 5개' 같은 질문에 사용.",
                                 [param("kind", "리소스 종류", {"type": "string", "enum": KINDS}, True),
                                  param("stat", "지표 별칭", {"type": "string", "enum": list(STATS)}, True),
                                  param("order", "정렬 (기본 desc)", {"type": "string", "enum": ["desc", "asc"]}),
                                  param("limit", f"최대 개수 (기본 10, 최대 {MAX_LIMIT})", lim)]),
        },
    }


ROUTES = {"/summary": summary, "/alerts": alerts, "/resource_status": resource_status, "/top_resources": top_resources}


class Handler(BaseHTTPRequestHandler):
    server_version = "ops-tools/1.0"

    def log_message(self, fmt, *a):
        log("http " + fmt % a)

    def _send(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _deny(self):
        return API_KEY and self.headers.get("Authorization") != f"Bearer {API_KEY}"

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if u.path == "/health":
            return self._send(200, {"status": "ok"})
        if self._deny():
            return self._send(401, {"error": "unauthorized"})
        if u.path == "/openapi.json":
            return self._send(200, openapi())
        fn = ROUTES.get(u.path)
        if not fn:
            return self._send(404, {"error": "not found"})
        q = urllib.parse.parse_qs(u.query)
        key = (u.path, tuple(sorted((k, tuple(v)) for k, v in q.items())))
        try:
            with LOCK:
                hit = CACHE.get(key)
                if hit and time.time() - hit[0] < TTL:
                    return self._send(200, hit[1])
                data = fn(q)
                CACHE[key] = (time.time(), data)
                if len(CACHE) > 500:
                    CACHE.clear()
            self._send(200, data)
        except ValueError as e:
            self._send(400, {"error": str(e)})
        except Exception as e:  # VCF Operations 장애/권한 오류 등
            log(f"{u.path} 실패: {e}")
            self._send(502, {"error": f"VCF Operations 조회 실패: {e}"})

    def _method_not_allowed(self):
        self._send(405, {"error": "read-only: GET 만 허용됩니다"})

    do_POST = do_PUT = do_PATCH = do_DELETE = _method_not_allowed


def main():
    global OPS
    OPS = OpsClient()
    port = int(env("OPS_TOOLS_PORT", "8000"))
    log(f"ops-tools 시작: :{port}, kinds={KINDS}, stats={list(STATS)}, auth={'on' if API_KEY else 'off'}")
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()


if __name__ == "__main__":
    sys.exit(main())

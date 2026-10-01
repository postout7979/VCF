"""VCF Operations(Suite API) 공용 클라이언트 (읽기 전용). ops_sync.py / ops_tools_server.py 가 공유. 표준 라이브러리만 사용."""
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

BATCH = 100


def env(name, default=""):
    return os.environ.get(name, default).strip()


def log(msg):
    print(f"{datetime.now(timezone.utc).strftime('%H:%M:%S')} {msg}", flush=True)


def split_csv(v):
    return [x.strip() for x in v.split(",") if x.strip()]


class OpsClient:
    def __init__(self):
        self.base = env("VCFOPS_URL").rstrip("/")
        self.user = env("VCFOPS_USERNAME")
        self.password = os.environ.get("VCFOPS_PASSWORD", "")
        self.auth_source = env("VCFOPS_AUTH_SOURCE")
        self.timeout = int(env("VCFOPS_TIMEOUT_SEC", "60"))
        if not (self.base and self.user and self.password):
            raise SystemExit("VCFOPS_URL / VCFOPS_USERNAME / VCFOPS_PASSWORD 환경변수가 필요합니다.")
        if env("VCFOPS_VERIFY_TLS", "true").lower() in ("0", "false", "no"):
            self.ctx = ssl._create_unverified_context()
            log("경고: TLS 검증이 꺼져 있습니다 (VCFOPS_VERIFY_TLS=false).")
        else:
            ca = env("VCFOPS_CA_FILE")
            if ca and not os.path.exists(ca):
                log(f"경고: VCFOPS_CA_FILE({ca})이 없어 시스템 기본 CA를 사용합니다. 사설 CA면 ./certs/ 에 PEM 을 두세요.")
                ca = None
            self.ctx = ssl.create_default_context(cafile=ca or None)
        self.token = None

    def _http(self, method, path, params=None, body=None, auth=True):
        url = self.base + "/suite-api/api" + path
        if params:
            url += "?" + urllib.parse.urlencode(params, doseq=True)
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if auth:
            headers["Authorization"] = f"OpenStackToken {self.token}"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
            txt = r.read().decode()
            return json.loads(txt) if txt else {}

    def login(self):
        body = {"username": self.user, "password": self.password}
        if self.auth_source:
            body["authSource"] = self.auth_source
        self.token = self._http("POST", "/auth/token/acquire", body=body, auth=False)["token"]

    def request(self, method, path, params=None, body=None):
        # 읽기 전용 가드: GET, 또는 조회용 bulk query 만 허용
        if method != "GET" and not (method == "POST" and path.endswith("/query")):
            raise PermissionError(f"read-only 정책으로 차단: {method} {path}")
        if not self.token:
            self.login()
        try:
            return self._http(method, path, params, body)
        except urllib.error.HTTPError as e:
            if e.code != 401:
                raise RuntimeError(f"{method} {path} -> {e.code}: {e.read().decode(errors='replace')[:300]}")
            self.login()  # 토큰 만료 시 1회 재발급
            return self._http(method, path, params, body)

    def get(self, path, params=None):
        return self.request("GET", path, params)

    def paged(self, path, key, params=None, limit=None):
        out, page, size = [], 0, 1000
        while True:
            p = dict(params or {}, page=page, pageSize=size)
            data = self.get(path, p)
            items = data.get(key, []) or []
            out.extend(items)
            total = (data.get("pageInfo") or {}).get("totalCount", len(out))
            if len(items) < size or len(out) >= total or (limit and len(out) >= limit):
                break
            page += 1
        return out[:limit] if limit else out


def ms_to_iso(ms):
    try:
        return datetime.fromtimestamp(int(ms) / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%MZ")
    except (TypeError, ValueError):
        return "-"


def last_value(item):
    """stat/property 항목에서 최신 값 추출 (응답 형태 차이에 관대하게)."""
    vals = item.get("values") or item.get("data") or []
    return vals[-1] if vals else None


def fmt_num(v):
    if isinstance(v, float):
        return f"{v:.1f}"
    return str(v)


def bulk_properties(ops, ids, keys):
    """{resourceId: {key: value}}"""
    res = {}
    for i in range(0, len(ids), BATCH):
        data = ops.request("POST", "/resources/properties/latest/query",
                           body={"resourceIds": ids[i:i + BATCH], "propertyKeys": keys})
        for v in data.get("values", []):
            contents = (v.get("property-contents") or {}).get("property-content", [])
            res[v.get("resourceId")] = {c.get("statKey"): last_value(c) for c in contents}
    return res


def bulk_stats(ops, ids, keys):
    res = {}
    for i in range(0, len(ids), BATCH):
        data = ops.request("POST", "/resources/stats/latest/query",
                           body={"resourceId": ids[i:i + BATCH], "statKey": keys, "currentOnly": True})
        for v in data.get("values", []):
            stats = (v.get("stat-list") or {}).get("stat", [])
            out = {}
            for s in stats:
                k = (s.get("statKey") or {}).get("key")
                if k:
                    out[k] = last_value(s)
            res[v.get("resourceId")] = out
    return res


def res_name(r):
    return (r.get("resourceKey") or {}).get("name") or r.get("identifier", "?")


def res_kind(r):
    return (r.get("resourceKey") or {}).get("resourceKindKey", "?")


def resolve_names(ops, ids, names):
    """names(dict, id->이름)에 없는 리소스 id 를 배치 조회로 채움."""
    missing = [i for i in set(ids) if i and i not in names]
    for i in range(0, len(missing), BATCH):
        try:
            for r in ops.get("/resources", {"resourceId": missing[i:i + BATCH], "pageSize": BATCH}).get("resourceList", []):
                names[r["identifier"]] = res_name(r)
        except Exception as e:
            log(f"리소스 이름 조회 실패: {e}")

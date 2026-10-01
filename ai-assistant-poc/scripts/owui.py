"""Open WebUI REST 클라이언트 (표준 라이브러리만 사용, 폐쇄망 호환)."""
import json
import mimetypes
import os
import time
import urllib.error
import urllib.request
import uuid


class OWUI:
    def __init__(self, base, email, password):
        self.base = base.rstrip("/")
        self.token = self.call("POST", "/api/v1/auths/signin",
                               body={"email": email, "password": password})["token"]

    def call(self, method, path, body=None, raw=None, ctype=None):
        headers = {"Accept": "application/json"}
        if getattr(self, "token", None):
            headers["Authorization"] = f"Bearer {self.token}"
        data = raw
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if ctype:
            headers["Content-Type"] = ctype
        req = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=600) as r:
                txt = r.read().decode()
                return json.loads(txt) if txt else {}
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"{method} {path} -> {e.code}: {e.read().decode(errors='replace')}")

    # --- files ---
    def upload(self, filename, content: bytes):
        boundary = uuid.uuid4().hex
        mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        raw = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
               f"Content-Type: {mime}\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
        return self.call("POST", "/api/v1/files/", raw=raw,
                         ctype=f"multipart/form-data; boundary={boundary}")

    def upload_path(self, path):
        with open(path, "rb") as f:
            return self.upload(os.path.basename(path), f.read())

    def wait_processed(self, file_id, timeout=900):
        """신규 버전은 비동기 처리. 상태 API 가 없으면(404) 즉시 통과."""
        end = time.time() + timeout
        while time.time() < end:
            try:
                st = self.call("GET", f"/api/v1/files/{file_id}/process/status")
            except RuntimeError as e:
                if " 404" in str(e):
                    return
                raise
            if st.get("status") == "completed":
                return
            if st.get("status") == "failed":
                raise RuntimeError(f"file {file_id} processing failed: {st}")
            time.sleep(2)
        raise TimeoutError(file_id)

    def delete_file(self, file_id):
        self.call("DELETE", f"/api/v1/files/{file_id}")

    # --- knowledge ---
    def get_or_create_knowledge(self, name, description=""):
        kbs = self.call("GET", "/api/v1/knowledge/")
        kbs = kbs.get("items", kbs) if isinstance(kbs, dict) else kbs
        kb = next((k for k in kbs if k["name"] == name), None)
        if not kb:
            kb = self.call("POST", "/api/v1/knowledge/create",
                           body={"name": name, "description": description})
        return kb["id"]

    def knowledge(self, kb_id):
        return self.call("GET", f"/api/v1/knowledge/{kb_id}")

    def knowledge_files(self, kb_id):
        """{파일명: file_id}"""
        kb = self.knowledge(kb_id)
        return {f.get("meta", {}).get("name"): f["id"] for f in kb.get("files", [])}

    def add_file(self, kb_id, file_id):
        self.call("POST", f"/api/v1/knowledge/{kb_id}/file/add", body={"file_id": file_id})

    def remove_file(self, kb_id, file_id):
        self.call("POST", f"/api/v1/knowledge/{kb_id}/file/remove", body={"file_id": file_id})

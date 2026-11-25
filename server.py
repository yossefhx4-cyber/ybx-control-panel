"""
خادم لوحة التحكم المركزية وواجهة برمجة التراخيص (YOSSEF BUSINESS X CONTROL PANEL)
يعمل مباشرة على أي استضافة سحابية (مثل Railway) أو خادم محلي بدون تعقيد
Developer: Yossef Ahmed
"""
import json
import os
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from central_db import CentralLicenseDB

ROOT_DIR = Path(__file__).resolve().parent
STATIC_DIR = ROOT_DIR / "static"


class ControlPanelHandler(BaseHTTPRequestHandler):
    db: CentralLicenseDB = None  # injected at server startup

    def log_message(self, format, *args):
        pass

    def _send_json(self, status_code: int, payload: dict, extra_headers: dict | None = None) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _send_bytes(self, status_code: int, content_type: str, data: bytes, filename: str = "") -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        body = self.rfile.read(length).decode("utf-8")
        return json.loads(body)

    def _get_session(self) -> dict | None:
        cookie_header = self.headers.get("Cookie", "")
        if not cookie_header:
            return None
        jar = cookies.SimpleCookie()
        jar.load(cookie_header)
        morsel = jar.get("ybx_admin_session")
        if not morsel:
            return None
        return self.db.validate_session(morsel.value)

    def _require_admin(self, check_csrf: bool = False) -> dict | None:
        sess = self._get_session()
        if not sess:
            self._send_json(401, {"ok": False, "message": "غير مصرح بالدخول. يرجى تسجيل الدخول أولًا."})
            return None
        if check_csrf:
            hdr_csrf = self.headers.get("X-CSRF-Token", "")
            if not hdr_csrf or hdr_csrf != sess["csrf_token"]:
                self._send_json(403, {"ok": False, "message": "رمز الحماية CSRF غير صالح."})
                return None
        return sess

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        # Static Frontend Files (Zero secrets inside!)
        if path in ("/", "/admin", "/login"):
            html = (STATIC_DIR / "index.html").read_bytes()
            self._send_bytes(200, "text/html; charset=utf-8", html)
            return
        if path == "/static/style.css":
            self._send_bytes(200, "text/css; charset=utf-8", (STATIC_DIR / "style.css").read_bytes())
            return
        if path == "/static/admin.js":
            self._send_bytes(200, "application/javascript; charset=utf-8", (STATIC_DIR / "admin.js").read_bytes())
            return

        if path == "/api/health":
            self._send_json(200, {"ok": True, "service": "YOSSEF BUSINESS X CONTROL PANEL"})
            return

        # Protected Admin GET Endpoints
        if path == "/api/admin/me":
            sess = self._require_admin()
            if sess:
                self._send_json(200, {"ok": True, "email": sess["admin_email"], "csrf_token": sess["csrf_token"]})
            return

        if path == "/api/admin/stats":
            sess = self._require_admin()
            if sess:
                self._send_json(200, self.db.get_dashboard_stats())
            return

        if path == "/api/admin/requests":
            sess = self._require_admin()
            if sess:
                st = qs.get("status", [""])[0]
                self._send_json(200, {"ok": True, "requests": self.db.list_activation_requests(st)})
            return

        if path == "/api/admin/codes":
            sess = self._require_admin()
            if sess:
                search = qs.get("search", [""])[0]
                st = qs.get("status", [""])[0]
                self._send_json(200, {"ok": True, "codes": self.db.list_codes(search, st)})
            return

        if path == "/api/admin/codes/export":
            sess = self._require_admin()
            if sess:
                fmt = qs.get("format", ["csv"])[0]
                if fmt == "xlsx":
                    self._send_bytes(
                        200,
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        self.db.export_codes_excel(),
                        "YBX_1000_Codes.xlsx",
                    )
                else:
                    self._send_bytes(200, "text/csv; charset=utf-8", self.db.export_codes_csv(), "YBX_1000_Codes.csv")
            return

        if path == "/api/admin/settings":
            sess = self._require_admin()
            if sess:
                self._send_json(200, {"ok": True, "settings": self.db.get_remote_settings()})
            return

        if path == "/api/admin/versions":
            sess = self._require_admin()
            if sess:
                self._send_json(200, {"ok": True, "versions": self.db.list_versions()})
            return

        self._send_json(404, {"ok": False, "message": "Endpoint not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path

        # 1. Public Desktop Client Activation Endpoints
        if path == "/api/client/request-activation":
            data = self._read_json()
            ok, msg = self.db.client_request_activation(
                data.get("username", ""), data.get("code", ""), data.get("hwid", "")
            )
            self._send_json(200 if ok else 400, {"ok": ok, "message": msg})
            return

        if path == "/api/client/check-status":
            data = self._read_json()
            res = self.db.client_check_status(data.get("hwid", ""), data.get("code", ""))
            self._send_json(200 if res.get("ok") else 400, res)
            return

        # 2. Triple-Factor Admin Login
        if path == "/api/admin/login":
            data = self._read_json()
            ok, msg, sess = self.db.authenticate_admin(
                data.get("email", ""), data.get("password_1", ""), data.get("password_2", "")
            )
            if not ok or not sess:
                self._send_json(401, {"ok": False, "message": msg})
                return
            cookie_val = f"ybx_admin_session={sess['token']}; Path=/; HttpOnly; SameSite=Strict"
            self._send_json(
                200,
                {"ok": True, "message": msg, "email": sess["email"], "csrf_token": sess["csrf_token"]},
                extra_headers={"Set-Cookie": cookie_val},
            )
            return

        if path == "/api/admin/logout":
            sess = self._get_session()
            if sess:
                self.db.logout_session(sess["token"])
            self._send_json(
                200,
                {"ok": True},
                extra_headers={"Set-Cookie": "ybx_admin_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"},
            )
            return

        # 3. Protected Admin Actions (Session + CSRF required)
        if path == "/api/admin/requests/review":
            sess = self._require_admin(check_csrf=True)
            if sess:
                data = self._read_json()
                ok, msg = self.db.review_activation_request(
                    int(data.get("request_id", 0)),
                    data.get("decision", "reject"),
                    int(data.get("duration_days", 365)),
                    data.get("admin_notes", ""),
                    sess["admin_email"],
                )
                self._send_json(200 if ok else 400, {"ok": ok, "message": msg})
            return

        if path == "/api/admin/codes/generate":
            sess = self._require_admin(check_csrf=True)
            if sess:
                data = self._read_json()
                cnt = self.db.generate_new_codes_batch(
                    int(data.get("count", 50)), int(data.get("duration_days", 365)), sess["admin_email"]
                )
                self._send_json(200, {"ok": True, "message": f"تم توليد {cnt} كود جديد وفريد بنجاح."})
            return

        if path == "/api/admin/codes/manage":
            sess = self._require_admin(check_csrf=True)
            if sess:
                data = self._read_json()
                ok, msg = self.db.manage_license_code(
                    data.get("code", ""),
                    data.get("action", ""),
                    sess["admin_email"],
                    int(data.get("extra_days", 365)),
                    data.get("new_hwid", ""),
                )
                self._send_json(200 if ok else 400, {"ok": ok, "message": msg})
            return

        if path == "/api/admin/settings":
            sess = self._require_admin(check_csrf=True)
            if sess:
                data = self._read_json()
                self.db.update_remote_settings(data.get("updates", {}), sess["admin_email"])
                self._send_json(200, {"ok": True, "message": "تم حفظ ونشر الإعدادات المركزية بنجاح."})
            return

        if path == "/api/admin/versions":
            sess = self._require_admin(check_csrf=True)
            if sess:
                data = self._read_json()
                self.db.publish_version(
                    data.get("version", ""), data.get("description", ""), data.get("download_url", ""), True, sess["admin_email"]
                )
                self._send_json(200, {"ok": True, "message": "تم نشر الإصدار الجديد بنجاح."})
            return

        if path == "/api/admin/change-passwords":
            sess = self._require_admin(check_csrf=True)
            if sess:
                data = self._read_json()
                ok, msg = self.db.change_admin_passwords(
                    sess["admin_email"],
                    data.get("current_p1", ""),
                    data.get("current_p2", ""),
                    data.get("new_p1", ""),
                    data.get("new_p2", ""),
                )
                self._send_json(200 if ok else 400, {"ok": ok, "message": msg})
            return

        self._send_json(404, {"ok": False, "message": "Endpoint not found"})


def run_server(host: str = "0.0.0.0", port: int | None = None, db_path: Path | None = None) -> None:
    port = port or int(os.environ.get("PORT", "8080"))
    db = CentralLicenseDB(db_path)

    class BoundHandler(ControlPanelHandler):
        pass

    BoundHandler.db = db
    server = ThreadingHTTPServer((host, port), BoundHandler)
    print(f"YOSSEF BUSINESS X CONTROL PANEL running on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()

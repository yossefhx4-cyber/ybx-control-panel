"""
قاعدة البيانات المركزية ونظام الأمان والتشفير للوحة تحكم YOSSEF BUSINESS X CONTROL PANEL
- مصادقة ثلاثية العناصر للمدير (البريد الإلكتروني + كلمة السر الأولى + كلمة السر الثانية)
- تخزين كلمات السر بصيغة PBKDF2-HMAC-SHA256 في SQLite فقط (بدون أي أسرار في الواجهة الأمامية)
- إدارة الـ 1000 كود وطلبات التفعيل والأجهزة والإعدادات المركزية والإصدارات وسجل الإدارة
Developer: Yossef Ahmed
"""
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import string
from datetime import datetime, timedelta
from pathlib import Path
import openpyxl

ROOT_DIR = Path(__file__).resolve().parent

DEFAULT_ADMIN_EMAIL = "yossef102101@gmail.com"
# كلمة السر الأولى تُقرأ من متغير البيئة ADMIN_PASSWORD_1 أو القيمة المبدئية القابلة للتغيير من لوحة التحكم
INITIAL_PASSWORD_1 = os.environ.get("ADMIN_PASSWORD_1", "YossefAdmin@2026")
INITIAL_PASSWORD_2 = os.environ.get("ADMIN_PASSWORD_2", "QUESTION123YOSSEF09")


def hash_secret(secret: str, salt_hex: str | None = None) -> tuple[str, str]:
    if not salt_hex:
        salt = os.urandom(16)
        salt_hex = salt.hex()
    else:
        salt = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, 180_000)
    return dk.hex(), salt_hex


def verify_secret(secret: str, expected_hash: str, salt_hex: str) -> bool:
    computed, _ = hash_secret(secret, salt_hex)
    return hmac.compare_digest(computed, expected_hash)


CENTRAL_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS admin_account (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    email TEXT UNIQUE NOT NULL,
    pass1_hash TEXT NOT NULL,
    pass1_salt TEXT NOT NULL,
    pass2_hash TEXT NOT NULL,
    pass2_salt TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT DEFAULT '',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    token TEXT PRIMARY KEY,
    csrf_token TEXT NOT NULL,
    admin_email TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS license_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'new', -- new | pending | active | rejected | expired | revoked
    duration_days INTEGER NOT NULL DEFAULT 365,
    hwid TEXT DEFAULT '',
    issued_at TEXT NOT NULL,
    requested_at TEXT DEFAULT '',
    activated_at TEXT DEFAULT '',
    expires_at TEXT DEFAULT '',
    admin_notes TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS activation_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL,
    hwid TEXT NOT NULL,
    client_username TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
    requested_at TEXT NOT NULL,
    reviewed_at TEXT DEFAULT '',
    admin_notes TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS remote_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version TEXT UNIQUE NOT NULL,
    release_date TEXT NOT NULL,
    description TEXT NOT NULL,
    download_url TEXT NOT NULL,
    notify_users INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_email TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_codes_status ON license_codes(status);
CREATE INDEX IF NOT EXISTS idx_codes_hwid ON license_codes(hwid);
CREATE INDEX IF NOT EXISTS idx_req_status ON activation_requests(status);
"""

DEFAULT_REMOTE_SETTINGS = {
    "app_name": "YOSSEF BUSINESS X",
    "welcome_message": "مرحبًا بك في نظام YOSSEF BUSINESS X لإدارة المبيعات والمخازن والحسابات",
    "expiry_message": "انتهت فترة الاشتراك الحالية. يرجى التواصل مع الإدارة لتجديد الترخيص.",
    "maintenance_mode": "0",
    "maintenance_message": "النظام في وضع الصيانة الدورية حاليًا.",
    "support_phone": "+201000000000",
    "support_url": "https://wa.me/201000000000",
    "announcement": "",
    "broadcast_message": "",
    "grace_days": "3",
}


class CentralLicenseDB:
    def __init__(self, db_path: Path | None = None):
        self.db_path = Path(db_path) if db_path else (ROOT_DIR / "data" / "ybx_central.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")
        return conn

    def _init_db(self) -> None:
        now_iso = datetime.now().isoformat(timespec="seconds")
        with self.connect() as conn:
            conn.executescript(CENTRAL_SCHEMA)

            # 1. تهيئة حساب المدير الثلاثي الآمن (البريد + كلمة السر 1 + كلمة السر 2)
            admin_row = conn.execute("SELECT id FROM admin_account WHERE id = 1").fetchone()
            if not admin_row:
                h1, s1 = hash_secret(INITIAL_PASSWORD_1)
                h2, s2 = hash_secret(INITIAL_PASSWORD_2)
                conn.execute(
                    """
                    INSERT INTO admin_account (id, email, pass1_hash, pass1_salt, pass2_hash, pass2_salt, updated_at)
                    VALUES (1, ?, ?, ?, ?, ?, ?)
                    """,
                    (DEFAULT_ADMIN_EMAIL.lower(), h1, s1, h2, s2, now_iso),
                )

            # 2. استيراد الـ 1000 كود الفريدة إلى قاعدة البيانات المركزية
            code_count = conn.execute("SELECT COUNT(*) FROM license_codes").fetchone()[0]
            if code_count == 0:
                seed_file = ROOT_DIR / "data" / "initial_1000_codes.txt"
                if seed_file.exists():
                    lines = [ln.strip() for ln in seed_file.read_text(encoding="utf-8").splitlines() if ln.strip()]
                    conn.executemany(
                        """
                        INSERT OR IGNORE INTO license_codes (code, status, duration_days, issued_at)
                        VALUES (?, 'new', 365, ?)
                        """,
                        [(c, now_iso) for c in lines],
                    )

            # 3. الإعدادات المركزية الافتراضية
            for k, v in DEFAULT_REMOTE_SETTINGS.items():
                conn.execute(
                    "INSERT OR IGNORE INTO remote_settings (key, value, updated_at) VALUES (?, ?, ?)",
                    (k, v, now_iso),
                )

            # 4. الإصدار الافتراضي الأول
            v_exists = conn.execute("SELECT id FROM app_versions LIMIT 1").fetchone()
            if not v_exists:
                conn.execute(
                    """
                    INSERT INTO app_versions (version, release_date, description, download_url, notify_users)
                    VALUES ('1.0.0', ?, 'الإصدار الرسمي الأول من YOSSEF BUSINESS X', '', 0)
                    """,
                    (now_iso[:10],),
                )
            conn.commit()

    def log_admin(self, conn: sqlite3.Connection, email: str, action: str, target: str, details: str) -> None:
        now_iso = datetime.now().isoformat(timespec="seconds")
        conn.execute(
            """
            INSERT INTO admin_audit_logs (admin_email, action_type, target, details, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (email, action, target, details, now_iso),
        )

    # --- المصادقة الثلاثية الآمنة للمدير ---
    def authenticate_admin(self, email: str, password_1: str, password_2: str) -> tuple[bool, str, dict | None]:
        email = email.strip().lower()
        if not email or not password_1 or not password_2:
            return False, "يجب إدخال البريد الإلكتروني وكلمة السر الأولى وكلمة السر الثانية.", None

        now = datetime.now()
        with self.connect() as conn:
            acc = conn.execute("SELECT * FROM admin_account WHERE id = 1").fetchone()
            if not acc:
                return False, "حساب الإدارة غير مهيأ.", None

            if acc["locked_until"]:
                lock_dt = datetime.fromisoformat(acc["locked_until"])
                if now < lock_dt:
                    mins = max(1, int((lock_dt - now).total_seconds() // 60) + 1)
                    return False, f"تم قفل الدخول مؤقتًا بسبب محاولات خاطئة. حاول بعد {mins} دقيقة.", None

            email_ok = hmac.compare_digest(email, acc["email"].lower())
            p1_ok = verify_secret(password_1, acc["pass1_hash"], acc["pass1_salt"])
            p2_ok = verify_secret(password_2, acc["pass2_hash"], acc["pass2_salt"])

            if not (email_ok and p1_ok and p2_ok):
                fails = int(acc["failed_attempts"]) + 1
                lock_str = (now + timedelta(minutes=10)).isoformat(timespec="seconds") if fails >= 5 else ""
                conn.execute(
                    "UPDATE admin_account SET failed_attempts = ?, locked_until = ? WHERE id = 1",
                    (0 if fails >= 5 else fails, lock_str),
                )
                self.log_admin(conn, email or "unknown", "LOGIN_FAILED", "admin_panel", "فشل التحقق الثلاثي للدخول")
                conn.commit()
                return False, "بيانات الدخول غير صحيحة. تأكد من البريد الإلكتروني وكلمتي السر.", None

            # نجاح المصادقة الثلاثية
            token = secrets.token_urlsafe(36)
            csrf = secrets.token_urlsafe(24)
            exp = (now + timedelta(hours=12)).isoformat(timespec="seconds")
            now_iso = now.isoformat(timespec="seconds")
            conn.execute("UPDATE admin_account SET failed_attempts = 0, locked_until = '' WHERE id = 1")
            conn.execute(
                "INSERT INTO admin_sessions (token, csrf_token, admin_email, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (token, csrf, acc["email"], now_iso, exp),
            )
            self.log_admin(conn, acc["email"], "LOGIN_SUCCESS", "admin_panel", "تسجيل دخول ناجح إلى لوحة التحكم المركزية")
            conn.commit()
            return True, "تم تسجيل الدخول بنجاح.", {"token": token, "csrf_token": csrf, "email": acc["email"]}

    def validate_session(self, token: str) -> dict | None:
        if not token:
            return None
        now_iso = datetime.now().isoformat(timespec="seconds")
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM admin_sessions WHERE token = ? AND expires_at > ?",
                (token, now_iso),
            ).fetchone()
            return dict(row) if row else None

    def logout_session(self, token: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM admin_sessions WHERE token = ?", (token,))
            conn.commit()

    def change_admin_passwords(
        self,
        admin_email: str,
        current_p1: str,
        current_p2: str,
        new_p1: str,
        new_p2: str,
    ) -> tuple[bool, str]:
        if len(new_p1) < 8 or len(new_p2) < 8:
            return False, "يجب أن تتكون كل من كلمة السر الأولى والثانية من 8 أحرف على الأقل."
        now_iso = datetime.now().isoformat(timespec="seconds")
        with self.connect() as conn:
            acc = conn.execute("SELECT * FROM admin_account WHERE id = 1").fetchone()
            if not (
                verify_secret(current_p1, acc["pass1_hash"], acc["pass1_salt"])
                and verify_secret(current_p2, acc["pass2_hash"], acc["pass2_salt"])
            ):
                return False, "كلمتا السر الحاليتان غير صحيحتين."
            h1, s1 = hash_secret(new_p1)
            h2, s2 = hash_secret(new_p2)
            conn.execute(
                """
                UPDATE admin_account
                SET pass1_hash = ?, pass1_salt = ?, pass2_hash = ?, pass2_salt = ?, updated_at = ?
                WHERE id = 1
                """,
                (h1, s1, h2, s2, now_iso),
            )
            self.log_admin(conn, admin_email, "CHANGE_PASSWORDS", "admin_account", "تم تحديث كلمتي السر الأولى والثانية بنجاح")
            conn.commit()
            return True, "تم تحديث كلمتي السر وحفظهما مشفرتين بنجاح."

    # --- واجهات العميل (Windows Desktop App API) ---
    def client_request_activation(self, username: str, code: str, hwid: str) -> tuple[bool, str]:
        username = username.strip()
        code = code.strip().upper()
        hwid = hwid.strip()
        if username != "admin":
            return False, "اسم المستخدم غير مصرح به لطلب التفعيل (المطلوب: admin)."
        if not code or not hwid:
            return False, "كود الاشتراك ومعرف الجهاز مطلوبان."

        now_iso = datetime.now().isoformat(timespec="seconds")
        with self.connect() as conn:
            c_row = conn.execute("SELECT * FROM license_codes WHERE code = ?", (code,)).fetchone()
            if not c_row:
                return False, "كود الاشتراك غير موجود في نظام التراخيص المركزي."

            status = c_row["status"]
            existing_hwid = c_row["hwid"] or ""

            if status == "revoked":
                return False, "هذا الكود ملغي من قِبل الإدارة ولا يمكن استخدامه."
            if status in ("active", "pending") and existing_hwid and existing_hwid != hwid:
                return False, "هذا الكود مستخدم أو مرتبط بجهاز آخر بالفعل. يلزم موافقة الإدارة لنقل الترخيص."

            conn.execute(
                """
                UPDATE license_codes
                SET status = 'pending', hwid = ?, requested_at = ?
                WHERE code = ?
                """,
                (hwid, now_iso, code),
            )
            conn.execute(
                """
                INSERT INTO activation_requests (code, hwid, client_username, status, requested_at)
                VALUES (?, ?, ?, 'pending', ?)
                """,
                (code, hwid, username, now_iso),
            )
            conn.commit()
            return True, "تم إرسال طلب التفعيل بنجاح، يرجى انتظار موافقة الإدارة."

    def client_check_status(self, hwid: str, code: str = "") -> dict:
        hwid = hwid.strip()
        code = code.strip().upper()
        now = datetime.now()
        with self.connect() as conn:
            cfg_rows = conn.execute("SELECT key, value FROM remote_settings").fetchall()
            remote_cfg = {r["key"]: r["value"] for r in cfg_rows}

            ver_row = conn.execute("SELECT * FROM app_versions ORDER BY id DESC LIMIT 1").fetchone()
            if ver_row and ver_row["notify_users"]:
                remote_cfg["latest_version"] = ver_row["version"]
                remote_cfg["download_url"] = ver_row["download_url"]
                remote_cfg["release_notes"] = ver_row["description"]

            c_row = None
            if code:
                c_row = conn.execute("SELECT * FROM license_codes WHERE code = ?", (code,)).fetchone()
            if not c_row and hwid:
                c_row = conn.execute(
                    "SELECT * FROM license_codes WHERE hwid = ? ORDER BY id DESC LIMIT 1", (hwid,)
                ).fetchone()

            if not c_row:
                return {
                    "ok": True,
                    "license_status": "trial",
                    "expires_at": "",
                    "message": "لا يوجد طلب تفعيل مرتبط بهذا الجهاز بعد.",
                    "remote_config": remote_cfg,
                }

            if c_row["hwid"] and hwid and c_row["hwid"] != hwid:
                return {
                    "ok": False,
                    "license_status": "revoked",
                    "message": "الكود غير مطابق لمعرف هذا الجهاز.",
                }

            status = c_row["status"]
            exp_str = c_row["expires_at"] or ""
            if status == "active" and exp_str:
                if now > datetime.fromisoformat(exp_str):
                    status = "expired"
                    conn.execute("UPDATE license_codes SET status = 'expired' WHERE id = ?", (c_row["id"],))
                    conn.commit()

            msg_map = {
                "pending": "طلب التفعيل ما زال قيد مراجعة الإدارة المركزية.",
                "active": f"الترخيص مفعّل ونشط حتى {exp_str[:10]}.",
                "rejected": "تم رفض طلب التفعيل من الإدارة.",
                "revoked": "تم إيقاف هذا الترخيص من الإدارة.",
                "expired": "انتهت مدة الاشتراك. يرجى تجديد الترخيص.",
            }
            return {
                "ok": True,
                "license_status": status,
                "expires_at": exp_str,
                "message": msg_map.get(status, "تم تحديث الحالة."),
                "remote_config": remote_cfg,
            }

    # --- عمليات لوحة تحكم الإدارة ---
    def get_dashboard_stats(self) -> dict:
        now = datetime.now()
        soon_str = (now + timedelta(days=15)).isoformat(timespec="seconds")
        now_iso = now.isoformat(timespec="seconds")
        with self.connect() as conn:
            total_codes = conn.execute("SELECT COUNT(*) FROM license_codes").fetchone()[0]
            unused_codes = conn.execute("SELECT COUNT(*) FROM license_codes WHERE status = 'new'").fetchone()[0]
            active_licenses = conn.execute("SELECT COUNT(*) FROM license_codes WHERE status = 'active'").fetchone()[0]
            expired_licenses = conn.execute("SELECT COUNT(*) FROM license_codes WHERE status = 'expired'").fetchone()[0]
            revoked_codes = conn.execute("SELECT COUNT(*) FROM license_codes WHERE status = 'revoked'").fetchone()[0]
            pending_requests = conn.execute("SELECT COUNT(*) FROM activation_requests WHERE status = 'pending'").fetchone()[0]
            registered_devices = conn.execute("SELECT COUNT(DISTINCT hwid) FROM license_codes WHERE hwid != ''").fetchone()[0]
            expiring_soon = conn.execute(
                "SELECT COUNT(*) FROM license_codes WHERE status = 'active' AND expires_at != '' AND expires_at <= ? AND expires_at >= ?",
                (soon_str, now_iso),
            ).fetchone()[0]

            recent_activations = [
                dict(r)
                for r in conn.execute(
                    "SELECT code, hwid, activated_at, expires_at FROM license_codes WHERE status = 'active' ORDER BY activated_at DESC LIMIT 8"
                ).fetchall()
            ]
            recent_logs = [
                dict(r)
                for r in conn.execute("SELECT * FROM admin_audit_logs ORDER BY id DESC LIMIT 10").fetchall()
            ]
            return {
                "total_codes": total_codes,
                "unused_codes": unused_codes,
                "active_licenses": active_licenses,
                "expired_licenses": expired_licenses,
                "revoked_codes": revoked_codes,
                "pending_requests": pending_requests,
                "registered_devices": registered_devices,
                "expiring_soon": expiring_soon,
                "recent_activations": recent_activations,
                "recent_logs": recent_logs,
            }

    def list_codes(self, search: str = "", status: str = "", limit: int = 250) -> list[dict]:
        sql = "SELECT * FROM license_codes WHERE 1=1"
        params: list = []
        if status:
            sql += " AND status = ?"
            params.append(status)
        if search.strip():
            sql += " AND (code LIKE ? OR hwid LIKE ? OR admin_notes LIKE ?)"
            t = f"%{search.strip()}%"
            params.extend([t, t, t])
        sql += " ORDER BY id ASC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def generate_new_codes_batch(self, count: int, duration_days: int, admin_email: str) -> int:
        count = max(1, min(2000, int(count)))
        duration_days = max(1, int(duration_days))
        now_iso = datetime.now().isoformat(timespec="seconds")
        alphabet = string.ascii_uppercase + string.digits
        created = 0
        with self.connect() as conn:
            while created < count:
                part1 = "".join(secrets.choice(alphabet) for _ in range(4))
                part2 = "".join(secrets.choice(alphabet) for _ in range(4))
                part3 = "".join(secrets.choice(alphabet) for _ in range(4))
                candidate = f"YBX-{part1}-{part2}-{part3}"
                cur = conn.execute(
                    """
                    INSERT OR IGNORE INTO license_codes (code, status, duration_days, issued_at)
                    VALUES (?, 'new', ?, ?)
                    """,
                    (candidate, duration_days, now_iso),
                )
                if cur.rowcount > 0:
                    created += 1
            self.log_admin(conn, admin_email, "GENERATE_CODES", f"{created} codes", f"توليد دفعة جديدة من {created} كود لمدة {duration_days} يوم")
            conn.commit()
        return created

    def list_activation_requests(self, status: str = "") -> list[dict]:
        sql = "SELECT * FROM activation_requests WHERE 1=1"
        params: list = []
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY id DESC LIMIT 200"
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(sql, params).fetchall()]

    def review_activation_request(
        self,
        request_id: int,
        decision: str,  # 'approve' | 'reject'
        duration_days: int,
        admin_notes: str,
        admin_email: str,
    ) -> tuple[bool, str]:
        now = datetime.now()
        now_iso = now.isoformat(timespec="seconds")
        with self.connect() as conn:
            req = conn.execute("SELECT * FROM activation_requests WHERE id = ?", (request_id,)).fetchone()
            if not req:
                return False, "طلب التفعيل غير موجود."

            code = req["code"]
            hwid = req["hwid"]

            if decision == "approve":
                exp_iso = (now + timedelta(days=max(1, int(duration_days)))).isoformat(timespec="seconds")
                conn.execute(
                    """
                    UPDATE license_codes
                    SET status = 'active', hwid = ?, duration_days = ?, activated_at = ?, expires_at = ?, admin_notes = ?
                    WHERE code = ?
                    """,
                    (hwid, duration_days, now_iso, exp_iso, admin_notes, code),
                )
                conn.execute(
                    """
                    UPDATE activation_requests
                    SET status = 'approved', reviewed_at = ?, admin_notes = ?
                    WHERE id = ?
                    """,
                    (now_iso, admin_notes, request_id),
                )
                self.log_admin(conn, admin_email, "APPROVE_REQUEST", code, f"الموافقة على تفعيل الكود {code} للجهاز {hwid} لمدة {duration_days} يوم")
                conn.commit()
                return True, f"تمت الموافقة وتفعيل الترخيص ({code}) لمدة {duration_days} يوم."
            else:
                conn.execute(
                    "UPDATE license_codes SET status = 'rejected', admin_notes = ? WHERE code = ?",
                    (admin_notes, code),
                )
                conn.execute(
                    """
                    UPDATE activation_requests
                    SET status = 'rejected', reviewed_at = ?, admin_notes = ?
                    WHERE id = ?
                    """,
                    (now_iso, admin_notes, request_id),
                )
                self.log_admin(conn, admin_email, "REJECT_REQUEST", code, f"رفض طلب تفعيل الكود {code}: {admin_notes}")
                conn.commit()
                return True, f"تم رفض طلب التفعيل للكود ({code})."

    def manage_license_code(
        self,
        code: str,
        action: str,  # 'revoke' | 'renew' | 'transfer'
        admin_email: str,
        extra_days: int = 365,
        new_hwid: str = "",
    ) -> tuple[bool, str]:
        code = code.strip().upper()
        now = datetime.now()
        now_iso = now.isoformat(timespec="seconds")
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM license_codes WHERE code = ?", (code,)).fetchone()
            if not row:
                return False, "الكود غير موجود."

            if action == "revoke":
                conn.execute("UPDATE license_codes SET status = 'revoked' WHERE code = ?", (code,))
                self.log_admin(conn, admin_email, "REVOKE_LICENSE", code, f"إيقاف/إلغاء الكود والترخيص {code}")
                conn.commit()
                return True, f"تم إيقاف وإلغاء الكود {code}."

            if action == "renew":
                base_dt = now
                if row["expires_at"]:
                    cur_exp = datetime.fromisoformat(row["expires_at"])
                    if cur_exp > now:
                        base_dt = cur_exp
                new_exp = (base_dt + timedelta(days=max(1, int(extra_days)))).isoformat(timespec="seconds")
                conn.execute(
                    "UPDATE license_codes SET status = 'active', expires_at = ? WHERE code = ?",
                    (new_exp, code),
                )
                self.log_admin(conn, admin_email, "RENEW_LICENSE", code, f"تجديد الكود {code} لمدة {extra_days} يوم حتى {new_exp[:10]}")
                conn.commit()
                return True, f"تم تجديد الاشتراك حتى {new_exp[:10]}."

            if action == "transfer":
                if not new_hwid.strip():
                    return False, "يرجى إدخال معرف الجهاز الجديد (HWID)."
                conn.execute(
                    "UPDATE license_codes SET hwid = ?, status = 'active' WHERE code = ?",
                    (new_hwid.strip(), code),
                )
                self.log_admin(conn, admin_email, "TRANSFER_LICENSE", code, f"نقل الترخيص {code} إلى الجهاز {new_hwid.strip()}")
                conn.commit()
                return True, f"تم نقل الترخيص {code} إلى الجهاز الجديد بنجاح."

        return False, "إجراء غير معروف."

    def get_remote_settings(self) -> dict[str, str]:
        with self.connect() as conn:
            return {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM remote_settings").fetchall()}

    def update_remote_settings(self, updates: dict[str, str], admin_email: str) -> None:
        now_iso = datetime.now().isoformat(timespec="seconds")
        with self.connect() as conn:
            for k, v in updates.items():
                conn.execute(
                    """
                    INSERT INTO remote_settings (key, value, updated_at)
                    VALUES (?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
                    """,
                    (k, str(v), now_iso),
                )
            self.log_admin(conn, admin_email, "UPDATE_SETTINGS", "remote_settings", "تحديث الإعدادات المركزية للبرنامج عن بُعد")
            conn.commit()

    def list_versions(self) -> list[dict]:
        with self.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM app_versions ORDER BY id DESC").fetchall()]

    def publish_version(self, version: str, description: str, download_url: str, notify_users: bool, admin_email: str) -> None:
        now_iso = datetime.now().isoformat(timespec="seconds")
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO app_versions (version, release_date, description, download_url, notify_users)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(version) DO UPDATE SET
                    release_date = excluded.release_date,
                    description = excluded.description,
                    download_url = excluded.download_url,
                    notify_users = excluded.notify_users
                """,
                (version.strip(), now_iso[:10], description.strip(), download_url.strip(), 1 if notify_users else 0),
            )
            self.log_admin(conn, admin_email, "PUBLISH_VERSION", version, f"نشر إصدار جديد {version}")
            conn.commit()

    def export_codes_csv(self) -> bytes:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["Code", "Status", "Duration_Days", "HWID", "Issued_At", "Activated_At", "Expires_At", "Notes"])
        with self.connect() as conn:
            for r in conn.execute("SELECT * FROM license_codes ORDER BY id ASC").fetchall():
                writer.writerow([r["code"], r["status"], r["duration_days"], r["hwid"], r["issued_at"], r["activated_at"], r["expires_at"], r["admin_notes"]])
        return ("﻿" + buf.getvalue()).encode("utf-8")

    def export_codes_excel(self) -> bytes:
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "YBX_Codes"
        ws.sheet_view.rightToLeft = True
        ws.append(["كود الاشتراك", "الحالة", "المدة (يوم)", "معرف الجهاز HWID", "تاريخ الإصدار", "تاريخ التفعيل", "تاريخ الانتهاء", "ملاحظات"])
        with self.connect() as conn:
            for r in conn.execute("SELECT * FROM license_codes ORDER BY id ASC").fetchall():
                ws.append([r["code"], r["status"], r["duration_days"], r["hwid"], r["issued_at"], r["activated_at"], r["expires_at"], r["admin_notes"]])
        out = io.BytesIO()
        wb.save(out)
        return out.getvalue()

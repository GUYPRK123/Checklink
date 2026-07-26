# -*- coding: utf-8 -*-
"""
app.py
เซิร์ฟเวอร์ Flask: ให้บริการทั้ง REST API และไฟล์ frontend

รันตอนพัฒนา:      python app.py            แล้วเปิด  http://127.0.0.1:5000
รันตอน production: อยู่หลัง Nginx reverse proxy เสมอ (ดู deploy/) —
                    waitress-serve --host=127.0.0.1 --port=5000 app:app
                    (ตั้ง FLASK_ENV=production, BEHIND_PROXY=true และค่าอื่นใน .env
                    ก่อนเสมอ ดู .env.example และ deploy/nginx.conf, deploy/phishing-checker.service)

API หลัก:  POST /api/check   body = {"url": "..."}   -> ผลการวิเคราะห์ (JSON)
"""
import os
import threading

from flask import Flask, send_from_directory, jsonify, request
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv

load_dotenv()

from config import Config
from extensions import db, login_manager, csrf, limiter
from auth import auth_bp
from billing import billing_bp
from check import check_bp

FRONTEND_DIR = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "frontend"))


def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        # script-src เป็น 'self' ล้วน: จาวาสคริปต์ทุกตัวรวมทั้ง jsQR ถูกเสิร์ฟจากเครื่องนี้เอง
        # (frontend/js/vendor/) ห้ามเติมโดเมน CDN กลับเข้ามา — ตัวถอด QR อ่านเลขบัญชีพร้อมเพย์
        # ถ้า CDN ถูกแทรกโค้ดเมื่อไหร่ ผลการถอดจะถูกคุมได้ทันที
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def _preload_blocklist():
    from analyzer.blacklist_api import load_blocklist
    n = load_blocklist()
    print(f"[blocklist] โหลดโดเมนอันตรายจาก สกมช. แล้ว {n} รายการ")


# คอลัมน์ที่ถูกเพิ่มเข้ามาทีหลัง (ตาราง -> {ชื่อคอลัมน์: นิยาม SQL})
# db.create_all() สร้างได้เฉพาะ "ตารางใหม่" ไม่เพิ่มคอลัมน์ให้ตารางที่มีอยู่แล้ว ฐานข้อมูลของ
# เครื่องที่รันเวอร์ชันเก่าอยู่จึงพังตอนอัปเดต ถ้าไม่เติมให้ — ตัวช่วยนี้เติมให้อัตโนมัติ
_ADDED_COLUMNS = {
    "scan_history": {
        "source": "VARCHAR(10) NOT NULL DEFAULT 'link'",
        "qr_type": "VARCHAR(20)",
        "qr_thumb": "TEXT",
    },
}


def _migrate_sqlite_columns() -> None:
    """เพิ่มคอลัมน์ที่ยังไม่มีให้ตารางเดิม (รองรับเฉพาะ SQLite ซึ่งเป็นค่าเริ่มต้นของโปรเจกต์นี้)
    ถ้าใช้ฐานข้อมูลอื่นผ่าน DATABASE_URL ให้ข้ามไป แล้วใช้เครื่องมือ migration ของฝั่งนั้นแทน"""
    from sqlalchemy import inspect, text

    if not db.engine.url.drivername.startswith("sqlite"):
        return
    inspector = inspect(db.engine)
    existing_tables = set(inspector.get_table_names())
    with db.engine.begin() as conn:
        for table, columns in _ADDED_COLUMNS.items():
            if table not in existing_tables:
                continue  # ตารางเพิ่งถูกสร้างใหม่ -> มีคอลัมน์ครบอยู่แล้ว
            have = {c["name"] for c in inspector.get_columns(table)}
            for name, ddl in columns.items():
                if name not in have:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
                    print(f"[db] เพิ่มคอลัมน์ {table}.{name} ให้ฐานข้อมูลเดิมแล้ว")


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config.from_object(Config)

    if app.config["BEHIND_PROXY"]:
        # เชื่อถือ header X-Forwarded-For/-Proto จาก reverse proxy 1 ชั้น (Nginx บนเครื่อง
        # เดียวกัน — ดู deploy/nginx.conf) เพื่อให้ request.remote_addr (ใช้ทำ rate limit)
        # และ request.is_secure (ใช้ตัดสิน HSTS header) ถูกต้อง แทนที่จะเห็นทุก request
        # เป็น 127.0.0.1/http เหมือนกันหมด — เปิดเฉพาะตอนมี Nginx อยู่หน้าจริงเท่านั้น
        # (ห้ามเปิดถ้า waitress เปิดสู่อินเทอร์เน็ตตรง ๆ เพราะ header นี้ปลอมได้)
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    origins = app.config["CORS_ORIGINS"]
    cors_origins = "*" if origins == "*" else [o.strip() for o in origins.split(",") if o.strip()]
    CORS(app, supports_credentials=True, origins=cors_origins)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(billing_bp)
    app.register_blueprint(check_bp)
    # check_bp ต้องรองรับ client ภายนอกที่ยิงมาด้วย API key (ไม่มี session/CSRF token)
    # ดูเหตุผลเต็มในคอมเมนต์หัวไฟล์ check.py
    csrf.exempt(check_bp)

    app.after_request(_security_headers)

    # ---------- เสิร์ฟ frontend (static) ----------
    @app.route("/")
    def index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.route("/<path:path>")
    def static_files(path):
        return send_from_directory(FRONTEND_DIR, path)

    @app.errorhandler(429)
    def rate_limited(e):
        return jsonify({"ok": False, "error": "เรียกใช้งานถี่เกินไป กรุณาลองใหม่ภายหลัง"}), 429

    with app.app_context():
        os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance"), exist_ok=True)
        _migrate_sqlite_columns()  # ต้องทำก่อน create_all() เพื่อให้เห็นตารางเวอร์ชันเดิมตามจริง
        db.create_all()

    _index = os.path.join(FRONTEND_DIR, "index.html")
    if not os.path.exists(_index):
        print("[frontend] !! หา index.html ไม่เจอ -> ตรวจว่าโครงสร้างโฟลเดอร์ครบ "
              "และรัน python app.py จากในโฟลเดอร์ backend")

    # โหลดบัญชีดำของ สกมช. ล่วงหน้าในเบื้องหลัง เพื่อให้การตรวจครั้งแรกไม่ช้า
    # (ถ้าโหลดไม่ได้ ระบบยังทำงานได้โดยใช้การวิเคราะห์สดในชั้นที่ 2)
    threading.Thread(target=_preload_blocklist, daemon=True).start()

    return app


app = create_app()

if __name__ == "__main__":
    # debug=True มาจาก Config (เปิดเฉพาะตอน FLASK_ENV != production) ห้ามเปิดเมื่อขึ้นจริง
    app.run(host="127.0.0.1", port=5000, debug=app.config["DEBUG"])

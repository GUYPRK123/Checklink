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
import sqlite3
import threading
import time

from flask import Flask, send_from_directory, jsonify, request
from flask_cors import CORS
from sqlalchemy import event
from sqlalchemy.engine import Engine
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


# ---------------------------------------------------------------------------
# ค่า PRAGMA ของ SQLite — ตั้งทุกครั้งที่เปิด connection ใหม่
# ---------------------------------------------------------------------------
# ปัญหาเดิม: SQLite โหมดมาตรฐาน (journal แบบ rollback) ให้ "คนเขียนล็อกทั้งไฟล์"
# ระหว่างเขียน คนอ่านที่มาพร้อมกันจะเจอ "database is locked" แล้วโยน error ออกทันที
# โดยไม่รอ (busy_timeout ค่าเริ่มต้น = 0) บนเครื่องนี้ที่ waitress เปิดไว้ 16 thread
# และ bulk ยิงเขียนประวัติพร้อมกันได้อีก อาการนี้โผล่ตอนคนใช้พร้อมกันเท่านั้น จึงไม่เคย
# เจอตอนทดสอบคนเดียว แต่เจอจริงตอนสาธิต
#
#   journal_mode=WAL  -> คนอ่านกับคนเขียนไม่บล็อกกันอีกต่อไป (คนอ่านเห็นภาพ ณ ตอน
#                        เริ่มอ่าน ส่วนคนเขียนเขียนต่อท้ายไฟล์ -wal แยก) ค่านี้ติดอยู่กับ
#                        ตัวไฟล์ฐานข้อมูลถาวร ตั้งครั้งเดียวก็พอ แต่สั่งซ้ำได้ไม่เสียหาย
#   busy_timeout=5000 -> ถ้ายังชนกันจริง ๆ ให้ "รอ 5 วินาที" ก่อนยอมแพ้ แทนที่จะ
#                        โยน error ทิ้งทันที (การเขียนของแอปนี้จบใน ~1 มิลลิวินาที)
#   synchronous=NORMAL-> คู่มาตรฐานของ WAL: ยังทนโปรเซสตาย/ถูก OOM killer ฆ่าได้ครบ
#                        เสียข้อมูลเฉพาะตอนไฟดับทั้งเครื่องและเสียแค่ธุรกรรมท้าย ๆ
#                        ซึ่งแลกกับการไม่ต้อง fsync ทุกครั้งที่เขียน (เครื่องนี้ดิสก์ช้า)
#
# ⚠️ กับดักของ WAL ที่ต้องรู้: ไฟล์ฐานข้อมูลไม่ใช่ไฟล์เดียวอีกต่อไป มี app.db-wal และ
# app.db-shm มาด้วย ใครเปิดฐานข้อมูลนี้ "เป็น root" จะสร้างสองไฟล์นั้นเป็นของ root
# แล้วแอป (รันเป็น checkurl) จะเขียนไม่ได้ทั้งระบบ — deploy.sh จึงสำรองฐานข้อมูลใน
# นามของ checkurl เสมอ ห้ามแก้กลับเป็นรันตรง ๆ ด้วย root
def _apply_sqlite_pragmas(dbapi_connection, connection_record) -> None:
    if not isinstance(dbapi_connection, sqlite3.Connection):
        return  # ใช้ฐานข้อมูลอื่นผ่าน DATABASE_URL -> ไม่เกี่ยวกับ PRAGMA ชุดนี้
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.execute("PRAGMA synchronous=NORMAL")
    finally:
        cursor.close()


# ผูกกับคลาส Engine (ไม่ใช่ engine ตัวใดตัวหนึ่ง) เพราะ Flask-SQLAlchemy สร้าง engine
# ทีหลังตอน init_app และสร้างใหม่ได้อีกในเทสต์ — ตัวกรอง isinstance ข้างบนทำให้ engine
# ที่ไม่ใช่ SQLite ไม่โดนผลกระทบ
event.listen(Engine, "connect", _apply_sqlite_pragmas)


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


def _startup_warmup():
    """อุ่นเครื่องในเบื้องหลังตอนสตาร์ต ทำ 2 อย่างเรียงกัน (ไม่ยิงพร้อมกันเพื่อไม่ให้
    เครือข่ายกระตุกตอนบูต):

      1) โหลดบัญชีดำของ สกมช. ล่วงหน้า เพื่อให้การตรวจครั้งแรกไม่ต้องรอดาวน์โหลด
         (ถ้าโหลดไม่ได้ ระบบยังทำงานได้โดยใช้การวิเคราะห์สดในชั้นที่ 2)
      2) ตรวจลิงก์จริงหนึ่งครั้งแบบทิ้งผล เพื่ออุ่น DNS resolver, TLS session cache
         และการเชื่อมต่อของ requests

    ข้อ 2 สำคัญกว่าที่คิด: การตรวจเชิงลึก "ครั้งแรก" หลัง process เพิ่งสตาร์ตวัดได้ราว
    16 วินาที ขณะที่ครั้งต่อ ๆ ไปเหลือ 0.3-4 วินาที ถ้าไม่อุ่นไว้ ผู้ใช้คนแรกหลังทุกครั้ง
    ที่ systemd รีสตาร์ตจะเป็นคนรับกรรมนั้นแทน

    ตั้ง WARMUP_URL="" เพื่อปิด (เช่นตอนรันในเครื่องที่ไม่มีเน็ต)
    """
    from analyzer.blacklist_api import load_blocklist

    n = load_blocklist()
    print(f"[blocklist] โหลดโดเมนอันตรายจาก สกมช. แล้ว {n} รายการ")

    url = os.environ.get("WARMUP_URL", "https://example.com").strip()
    if not url:
        return
    try:
        # ใช้ตัวที่ไม่ผ่านแคชโดยตั้งใจ ผลอุ่นเครื่องไม่ควรไปนั่งกินที่ในแคชของผู้ใช้จริง
        from analyzer.scanner import _scan_uncached
        started = time.perf_counter()
        _scan_uncached(url, run_deep=True)
        print(f"[warmup] อุ่นเครื่องด้วย {url} เสร็จใน {time.perf_counter() - started:.1f} วินาที")
    except Exception as e:
        # อุ่นเครื่องไม่สำเร็จไม่ใช่เรื่องคอขาดบาดตาย ระบบยังทำงานได้ปกติ แค่ช้าครั้งแรก
        print(f"[warmup] อุ่นเครื่องไม่สำเร็จ ({type(e).__name__}: {e}) — ข้ามไป")


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

    # CORS: เปิดเฉพาะเมื่อมีการระบุ origin ไว้จริง ๆ เท่านั้น
    # ถ้า CORS_ORIGINS ว่าง (ค่าเริ่มต้นของ production) จะไม่ติดตั้ง CORS เลย = same-origin
    # อย่างเดียว ซึ่งพอสำหรับการใช้งานปกติ เพราะ Flask ตัวนี้เสิร์ฟ frontend เองอยู่แล้ว
    origins = (app.config["CORS_ORIGINS"] or "").strip()
    if origins == "*":
        if not app.config["DEBUG"]:
            # "*" + supports_credentials=True = เว็บใดก็ได้ยิง API แทนผู้ใช้ที่ล็อกอินค้างได้
            raise RuntimeError(
                'ห้ามตั้ง CORS_ORIGINS="*" ตอน production — ให้ระบุ origin จริง เช่น '
                'CORS_ORIGINS=http://198.199.122.176:5000 (ดู .env.example)')
        CORS(app, supports_credentials=True, origins="*")
    elif origins:
        CORS(app, supports_credentials=True,
             origins=[o.strip() for o in origins.split(",") if o.strip()])

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

    threading.Thread(target=_startup_warmup, daemon=True).start()

    return app


app = create_app()

if __name__ == "__main__":
    # debug=True มาจาก Config (เปิดเฉพาะตอน FLASK_ENV != production) ห้ามเปิดเมื่อขึ้นจริง
    app.run(host="127.0.0.1", port=5000, debug=app.config["DEBUG"])

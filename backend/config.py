# -*- coding: utf-8 -*-
"""
config.py (root)
ตั้งค่าแอปที่อ่านจาก environment variable ทั้งหมด — ห้าม hardcode ความลับในไฟล์นี้
(อย่าสับสนกับ analyzer/config.py ซึ่งเป็นฐานความรู้เรื่องการวิเคราะห์ลิงก์ คนละเรื่องกัน)
"""
import os


def _bool_env(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


class Config:
    ENV = os.environ.get("FLASK_ENV", "development")
    DEBUG = ENV != "production"

    SECRET_KEY = os.environ.get("SECRET_KEY")
    if not SECRET_KEY:
        if ENV == "production":
            raise RuntimeError(
                "ต้องตั้งค่า SECRET_KEY ผ่าน environment variable ก่อนรันแบบ production "
                "(ดูตัวอย่างใน .env.example)")
        SECRET_KEY = "dev-only-secret-do-not-use-in-production"

    basedir = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(basedir, 'instance', 'app.db')}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # origin ที่อนุญาตให้เรียก API ข้าม origin ได้ (คั่นด้วย ,)
    # ค่าเริ่มต้นต่างกันตามโหมด และตั้งใจให้ต่างกัน:
    #   development -> "*"  สะดวกตอนเปิดหน้าเว็บจาก live-server/พอร์ตอื่นระหว่างพัฒนา
    #   production  -> ""   = ไม่เปิด CORS เลย (same-origin เท่านั้น)
    # เหตุผล: แอปนี้เสิร์ฟ frontend จาก Flask ตัวเดียวกันอยู่แล้วจึงไม่ต้องใช้ CORS
    # และ CORS เปิดกว้าง ("*") คู่กับ supports_credentials=True คือช่องให้เว็บอื่นยิง API
    # แทนผู้ใช้ที่ล็อกอินค้างไว้ได้ (ดู app.py ตอนเรียก CORS())
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "" if ENV == "production" else "*")

    # ที่เก็บตัวนับของ Flask-Limiter — "memory://" คือนับในหน่วยความจำของ process นั้น ๆ
    # ใช้ได้ดีกับการรันแบบปัจจุบัน (waitress process เดียว หลาย thread) แต่ถ้าวันไหน
    # รันหลาย process/หลายเครื่อง ตัวนับจะแยกกันคนละชุด ทำให้ลิมิตหลวมเป็นจำนวนเท่าของ
    # process -> ตอนนั้นให้ตั้ง RATELIMIT_STORAGE_URI เป็น redis://... แทน
    RATELIMIT_STORAGE_URI = os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

    # true เฉพาะตอนมี Nginx (หรือ reverse proxy อื่น) อยู่หน้า waitress บนเครื่องเดียวกัน
    # เท่านั้น (ดู deploy/) เพื่อให้ IP ผู้ใช้จริง/https ถูกอ่านถูกจาก X-Forwarded-*
    # ห้ามเปิดถ้า waitress เปิดสู่อินเทอร์เน็ตตรง ๆ เพราะ header นี้ปลอมได้ (จะทำให้
    # ข้าม rate limit ได้ง่าย ๆ ด้วยการปลอม X-Forwarded-For)
    BEHIND_PROXY = _bool_env("BEHIND_PROXY", False)

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool_env("SESSION_COOKIE_SECURE", ENV == "production")

    WTF_CSRF_TIME_LIMIT = None  # token อายุเท่ากับ session ไม่หมดอายุแยก

    PREMIUM_PRICE_THB = int(os.environ.get("PREMIUM_PRICE_THB", "99"))
    PREMIUM_DURATION_DAYS = int(os.environ.get("PREMIUM_DURATION_DAYS", "30"))
    BULK_CHECK_MAX_URLS = int(os.environ.get("BULK_CHECK_MAX_URLS", "20"))

    # จำนวนลิงก์ที่ยิงตรวจพร้อมกันในโหมด bulk (งานนี้รอเน็ตเป็นหลัก ไม่กิน CPU)
    # อย่าตั้งสูงเกินไป เพราะแต่ละลิงก์เปิดหลาย connection ในชั้นที่ 4 อยู่แล้ว
    BULK_CHECK_WORKERS = int(os.environ.get("BULK_CHECK_WORKERS", "5"))

    # ตัวแปรอื่นที่เกี่ยวข้อง อ่านจาก env โดยตรงในไฟล์ที่ใช้ (ไม่ผ่าน Flask config
    # เพราะโมดูลพวกนี้จงใจไม่ผูกกับ Flask จะได้เทสต์/ยกไปใช้ที่อื่นได้):
    #   SCAN_CACHE_TTL / SCAN_CACHE_MAX          -> analyzer/scan_cache.py
    #   BULK_JOB_CONCURRENCY / BULK_JOB_TTL      -> jobs.py
    #   WARMUP_URL                                -> app.py
    #   NCSA_BLOCKLIST_URL / NCSA_CACHE_TTL      -> analyzer/blacklist_api.py
    #   ANON_CHECKS_PER_DAY                       -> anon_quota.py

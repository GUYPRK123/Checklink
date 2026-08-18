# -*- coding: utf-8 -*-
"""
anon_quota.py
โควตาการตรวจรายวันของผู้ที่ "ไม่ได้ล็อกอิน" — นับต่อ IP นับรวมทุกการตรวจ
(ลิงก์และ QR ใช้ก้อนเดียวกัน)

กติกาปัจจุบัน (เปลี่ยนเมื่อ 2026-08: เดิมตัวนี้นับเฉพาะ "การตรวจเชิงลึก"):
  - ไม่ล็อกอิน   -> ตรวจได้ ANON_CHECKS_PER_DAY ครั้ง/วัน/IP (ชั้น 1-2) ครบแล้ว
                    ล็อกถึงวันถัดไป
  - ล็อกอินฟรี   -> ตรวจชั้น 1-2 ได้ไม่จำกัด (คุมด้วย rate limit ปกติเท่านั้น)
  - พรีเมียม     -> ได้การตรวจเชิงลึก (ชั้น 3-4) เพิ่ม ไม่จำกัด
เหตุผลของการจำกัดผู้ไม่ล็อกอิน: ให้คนที่กำลังจะกดลิงก์น่าสงสัย "ตอนนี้" ตรวจได้ทันที
โดยไม่บังคับสมัครก่อน แต่มีเพดานกันการยิงสุ่ม/สแกนอัตโนมัติจาก IP นิรนาม ส่วนการ
ตรวจเชิงลึกที่ยิงเครือข่ายออกจริง (0.3-8 วิ/ครั้ง) ถูกยกไปเป็นของพรีเมียมทั้งหมด

ใช้แนวเดียวกับ scan_cache.py/jobs.py: dict ในหน่วยความจำ + lock ไม่พึ่ง Redis
  - นับต่อ (IP, วัน) ขึ้นวันใหม่รีเซ็ตเอง
  - รีสตาร์ตเซิร์ฟเวอร์ = ตัวนับหาย ยอมรับได้ (โควตาหลวมขึ้นชั่วคราว ไม่ใช่ช่องโหว่ร้ายแรง)
  - ตั้ง ANON_CHECKS_PER_DAY=0 เพื่อปิดการตรวจแบบไม่ล็อกอินทั้งหมด (ต้องล็อกอินเท่านั้น)

หมายเหตุเรื่อง IP: ค่าที่ส่งเข้ามาคือ request.remote_addr ซึ่ง serve.py ตั้ง
trusted_proxy ให้เป็น IP จริงของผู้ใช้ (ไม่ใช่ 127.0.0.1 ของ Nginx) แล้ว — เงื่อนไข
เดียวกับ rate limiter ทั้งระบบ ผู้ใช้หลังเน็ตองค์กร/CGNAT เดียวกันจะแชร์โควตาก้อน
เดียวกัน เป็นข้อจำกัดที่รู้และยอมรับ (คนที่ต้องการมากกว่านี้สมัครสมาชิกฟรีได้)
"""
import os
import threading
from datetime import date

LIMIT = int(os.environ.get("ANON_CHECKS_PER_DAY", "5"))

# กันหน่วยความจำบวมจากการถูกกวาดด้วย IP จำนวนมากในวันเดียว (เก็บแค่ [วัน, ตัวนับ]
# ต่อ IP จึงเล็กมาก แต่ต้องมีเพดานไว้เสมอ — หลักเดียวกับ SCAN_CACHE_MAX)
MAX_TRACKED_IPS = 20000

_counts = {}   # ip -> [วันที่นับ, จำนวนที่ใช้ไปแล้ววันนั้น]
_lock = threading.Lock()


def _purge_old(today) -> None:
    """ทิ้งตัวนับของวันก่อน ๆ — ต้องเรียกใต้ _lock เท่านั้น"""
    for ip in [k for k, v in _counts.items() if v[0] != today]:
        del _counts[ip]


def _used_today(ip: str, today) -> int:
    """จำนวนที่ใช้ไปแล้ววันนี้ — ต้องเรียกใต้ _lock เท่านั้น"""
    entry = _counts.get(ip)
    if entry is None or entry[0] != today:
        return 0
    return entry[1]


def allow(ip: str) -> bool:
    """IP นี้ยังมีสิทธิ์ตรวจของวันนี้เหลือไหม (ดูอย่างเดียว ไม่หักสิทธิ์)"""
    if LIMIT <= 0 or not ip:
        return False
    with _lock:
        return _used_today(ip, date.today()) < LIMIT


def remaining(ip: str) -> int:
    """สิทธิ์ที่เหลือของวันนี้ — ไว้แสดงบนหน้าเว็บว่า "วันนี้เหลืออีกกี่ครั้ง" """
    if LIMIT <= 0 or not ip:
        return 0
    with _lock:
        return max(0, LIMIT - _used_today(ip, date.today()))


def record(ip: str) -> None:
    """หักสิทธิ์หนึ่งครั้ง — เรียกเฉพาะหลังการตรวจ "สำเร็จจริง" เท่านั้น
    (การตรวจที่ล้มเหลว เช่นลิงก์อ่านไม่ได้ ไม่ควรกินสิทธิ์ผู้ใช้)"""
    if LIMIT <= 0 or not ip:
        return
    today = date.today()
    with _lock:
        if len(_counts) > MAX_TRACKED_IPS:
            _purge_old(today)
        entry = _counts.get(ip)
        if entry is None or entry[0] != today:
            _counts[ip] = [today, 1]
        else:
            entry[1] += 1


def stats() -> dict:
    """ตัวเลขสุขภาพไว้ดูใน /api/health (ไม่เปิดเผย IP ใคร — แค่จำนวนรวม)"""
    with _lock:
        return {"limit_per_day": LIMIT, "tracked_ips": len(_counts)}


def clear() -> None:
    """ล้างตัวนับทั้งหมด (ใช้ในเทสต์)"""
    with _lock:
        _counts.clear()

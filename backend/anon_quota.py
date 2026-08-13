# -*- coding: utf-8 -*-
"""
anon_quota.py
โควตาการตรวจเชิงลึกรายวันสำหรับผู้ใช้ที่ "ไม่ได้ล็อกอิน" — นับต่อ IP

ทำไมต้องมี: เดิมชั้น 3-4 (ตาม redirect / อายุโดเมน / SSL / เนื้อหาเว็บ) ถูกล็อกไว้
หลังการล็อกอินทั้งหมด ผู้ใช้ทั่วไปที่กำลังจะกดลิงก์น่าสงสัย "ตอนนี้" จึงได้ผลแค่ชั้น 1-2
ซึ่งขัดกับจุดประสงค์ของเครื่องมือ (ช่วยคนให้ทันเวลา ไม่ใช่บังคับสมัครก่อน) จึงเปิดให้
ตรวจเชิงลึกได้จำนวนจำกัดต่อวันต่อ IP โดยไม่ต้องล็อกอิน — ที่ต้องจำกัดเพราะชั้น 3-4
ยิงเครือข่ายออกจริงและใช้เวลา 0.3-8 วิ/ครั้ง ปล่อยไม่จำกัดคือเปิดช่องให้ถูกใช้เป็น
เครื่องมือสแกนฟรีจนเครื่องอืด

ใช้แนวเดียวกับ scan_cache.py/jobs.py: dict ในหน่วยความจำ + lock ไม่พึ่ง Redis
  - นับต่อ (IP, วัน) ขึ้นวันใหม่รีเซ็ตเอง
  - รีสตาร์ตเซิร์ฟเวอร์ = ตัวนับหาย ยอมรับได้ (โควตาหลวมขึ้นชั่วคราว ไม่ใช่ช่องโหว่ร้ายแรง)
  - ตั้ง ANON_DEEP_CHECKS_PER_DAY=0 เพื่อปิด (กลับไปพฤติกรรมเดิม: ต้องล็อกอินเท่านั้น)

หมายเหตุเรื่อง IP: ค่าที่ส่งเข้ามาคือ request.remote_addr ซึ่ง serve.py ตั้ง
trusted_proxy ให้เป็น IP จริงของผู้ใช้ (ไม่ใช่ 127.0.0.1 ของ Nginx) แล้ว — เงื่อนไข
เดียวกับ rate limiter ทั้งระบบ ผู้ใช้หลังเน็ตองค์กร/CGNAT เดียวกันจะแชร์โควตาก้อน
เดียวกัน เป็นข้อจำกัดที่รู้และยอมรับ (คนที่ต้องการมากกว่านี้สมัครสมาชิกฟรีได้)
"""
import os
import threading
from datetime import date

LIMIT = int(os.environ.get("ANON_DEEP_CHECKS_PER_DAY", "3"))

# กันหน่วยความจำบวมจากการถูกกวาดด้วย IP จำนวนมากในวันเดียว (เก็บแค่ [วัน, ตัวนับ]
# ต่อ IP จึงเล็กมาก แต่ต้องมีเพดานไว้เสมอ — หลักเดียวกับ SCAN_CACHE_MAX)
MAX_TRACKED_IPS = 20000

_counts = {}   # ip -> [วันที่นับ, จำนวนที่ใช้ไปแล้ววันนั้น]
_lock = threading.Lock()


def _purge_old(today) -> None:
    """ทิ้งตัวนับของวันก่อน ๆ — ต้องเรียกใต้ _lock เท่านั้น"""
    for ip in [k for k, v in _counts.items() if v[0] != today]:
        del _counts[ip]


def allow(ip: str) -> bool:
    """IP นี้ยังมีสิทธิ์ตรวจเชิงลึกของวันนี้เหลือไหม (ดูอย่างเดียว ไม่หักสิทธิ์)"""
    if LIMIT <= 0 or not ip:
        return False
    today = date.today()
    with _lock:
        entry = _counts.get(ip)
        if entry is None or entry[0] != today:
            return True
        return entry[1] < LIMIT


def record(ip: str) -> None:
    """หักสิทธิ์หนึ่งครั้ง — เรียกเฉพาะหลังการตรวจเชิงลึก "สำเร็จจริง" เท่านั้น
    (แนวเดียวกับ User.record_deep_check ที่ไม่หักโควตาให้การตรวจที่ล้มเหลว)"""
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

# -*- coding: utf-8 -*-
"""
scan_cache.py
เก็บผลการตรวจลิงก์ไว้ใช้ซ้ำในช่วงเวลาสั้น ๆ

ทำไมต้องมี: ชั้นที่ 3-4 ยิงเน็ตออกนอกจริง (redirect + RDAP + TLS + ดึงหน้าเว็บ) ใช้เวลา
ประมาณ 0.3-4 วินาทีต่อลิงก์ ถ้าลิงก์หลอกใบเดียวถูกส่งต่อกันในไลน์แล้วคน 100 คนเอามาตรวจ
ระบบจะทำงานหนักเท่าเดิม 100 รอบเพื่อได้คำตอบเดิมเป๊ะ ๆ

ใช้แนวเดียวกับ blacklist_api.py (dict + เวลา + lock) ไม่ต้องพึ่ง Redis:
  - key แยกตาม (ลิงก์, ตรวจเชิงลึกหรือไม่) เพราะผลของ run_deep=True/False ไม่เหมือนกัน
  - TTL สั้น (ค่าเริ่มต้น 15 นาที) เพราะเว็บฟิชชิ่งเปลี่ยนพฤติกรรมเร็ว ของที่เพิ่งเช็ก
    เมื่อ 15 นาทีก่อนยังเชื่อได้ แต่ของเมื่อวานไม่แน่
  - จำกัดจำนวนรายการ (ค่าเริ่มต้น 2000) แล้วทิ้งตัวเก่าสุดก่อน กันหน่วยความจำบวม
    จากคนที่ยิงลิงก์สุ่มรัว ๆ

เก็บเฉพาะผลที่ ok=True เท่านั้น — ผลที่ล้มเหลว (เน็ตสะดุด ปลายทางล่มชั่วคราว) ไม่ควรถูก
ตรึงไว้ 15 นาที เพราะผู้ใช้ที่กดใหม่ควรได้โอกาสให้ระบบลองใหม่จริง ๆ
"""
import os
import threading
import time
from collections import OrderedDict

TTL = int(os.environ.get("SCAN_CACHE_TTL", 15 * 60))     # วินาที
MAX_ENTRIES = int(os.environ.get("SCAN_CACHE_MAX", 2000))

_entries = OrderedDict()   # key -> (เวลาที่เก็บ, ผลลัพธ์)
_lock = threading.Lock()
_stats = {"hits": 0, "misses": 0}


def _key(url: str, run_deep: bool) -> tuple:
    return (url.strip(), bool(run_deep))


def get(url: str, run_deep: bool):
    """คืนผลที่เก็บไว้ถ้ายังไม่หมดอายุ ไม่งั้นคืน None"""
    if TTL <= 0:
        return None
    key = _key(url, run_deep)
    now = time.time()
    with _lock:
        entry = _entries.get(key)
        if entry is None:
            _stats["misses"] += 1
            return None
        stored_at, result = entry
        if now - stored_at >= TTL:
            del _entries[key]              # หมดอายุแล้ว ทิ้งทันที
            _stats["misses"] += 1
            return None
        _entries.move_to_end(key)          # ใช้ล่าสุด -> ย้ายไปท้ายแถว (LRU)
        _stats["hits"] += 1
        # คืน copy ตื้น ๆ พร้อมติดธงว่ามาจาก cache เพื่อไม่ให้ผู้เรียกแก้ของในแคชโดยบังเอิญ
        return {**result, "cached": True, "cached_age_sec": round(now - stored_at)}


def put(url: str, run_deep: bool, result: dict) -> None:
    """เก็บผล — ข้ามให้เองถ้าเป็นผลที่ล้มเหลวหรือปิด cache ไว้"""
    if TTL <= 0 or not isinstance(result, dict) or not result.get("ok"):
        return
    key = _key(url, run_deep)
    with _lock:
        _entries[key] = (time.time(), result)
        _entries.move_to_end(key)
        while len(_entries) > MAX_ENTRIES:
            _entries.popitem(last=False)   # ทิ้งตัวที่ไม่ได้ใช้นานสุด
        _stats["misses"] += 0


def clear() -> None:
    """ล้างแคชทั้งหมด (ใช้ในเทสต์ และเผื่อไว้ตอนอยากบังคับตรวจใหม่)"""
    with _lock:
        _entries.clear()
        _stats["hits"] = _stats["misses"] = 0


def stats() -> dict:
    """สถิติไว้ดูว่าแคชได้ผลแค่ไหน (ใช้ใน /api/health)"""
    with _lock:
        total = _stats["hits"] + _stats["misses"]
        return {
            "entries": len(_entries),
            "hits": _stats["hits"],
            "misses": _stats["misses"],
            "hit_rate": round(_stats["hits"] / total, 3) if total else 0.0,
            "ttl_sec": TTL,
        }

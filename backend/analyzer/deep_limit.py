# -*- coding: utf-8 -*-
"""
deep_limit.py
============================================================================
  >>> เพดานจำนวน "การตรวจเชิงลึก" (ชั้น 3-4) ที่วิ่งพร้อมกันในโปรเซสนี้ <<<
============================================================================
**ปัญหาที่ตัวนี้แก้**

การตรวจเชิงลึกหนึ่งครั้งเปิดงานเครือข่ายพร้อมกันหลายทาง: ตาม redirect ได้ถึง 5 hop,
RDAP, TLS handshake, ดึงหน้าเว็บ (หรือส่งให้ sandbox เปิดด้วย Chromium) ใช้เวลา
0.3-4 วินาที และค้างค้างอยู่ในหน่วยความจำทั้งก้อนตลอดช่วงนั้น

ตัวเลขที่เป็นเพดานจริงของเครื่องนี้:

  * waitress ตั้ง threads=16 -> ผู้ใช้ 16 คนยิงพร้อมกัน = ตรวจเชิงลึก 16 ชุดพร้อมกัน
  * bulk อีกทาง: BULK_JOB_CONCURRENCY=2 งาน x BULK_CHECK_WORKERS=5 = อีก 10 ชุด
  * เครื่องมีแรมรวม 458 MB และต้องแบ่งให้ sandbox (MemoryMax=350M) ด้วย

รวมแล้วเกิน 25 ชุดพร้อมกันได้โดยไม่มีอะไรห้าม ซึ่งจบที่ OOM killer เลือกฆ่าโปรเซส
เว็บ แล้ว Restart=always ก็ปลุกขึ้นมาใหม่พร้อม state ที่หายทั้งหมด (แคช/โควตา/งาน bulk)
— อาการที่เห็นจากข้างนอกคือ "เว็บล่มเป็นช่วง ๆ ตอนคนใช้เยอะ" ซึ่งไล่ยากที่สุด

**พฤติกรรมที่เลือก: เข้าคิวก่อน แล้วค่อยถอยไปชั้น 1-2**

  1) มีที่ว่าง -> ทำเชิงลึกตามปกติ
  2) เต็ม     -> รอในคิวไม่เกิน DEEP_SCAN_WAIT_SEC (nginx ตั้ง proxy_read_timeout
                 ไว้ 120 วิ จึงรอได้สบาย ๆ) คิวเดินเร็วเพราะแต่ละชุดใช้ไม่กี่วินาที
  3) รอจนหมดเวลา -> **ข้ามชั้น 3-4 แล้วตอบผลชั้น 1-2 ไปเลย** ไม่ใช่ตอบ error

ข้อ 3 สำคัญที่สุดและตรงกับหลักของระบบ: "เช็กไม่ได้" ต้องไม่กลายเป็น "ปลอดภัย" และ
ต้องไม่กลายเป็น error ที่ผู้ใช้ไม่ได้อะไรเลย ผลชั้น 1-2 ยังจับ typosquat/homoglyph/
บัญชีดำ สกมช. ได้ครบ และ scanner จะติดธง skipped_reason ไว้ให้หน้าเว็บบอกผู้ใช้ตรง ๆ
ว่าชั้นลึกถูกข้ามเพราะระบบกำลังแน่น (ไม่ใช่เพราะสิทธิ์ไม่ถึง)

ปรับได้ด้วย env (ดู README):
    DEEP_SCAN_CONCURRENCY   จำนวนชุดที่ทำพร้อมกันได้ (0 = ไม่จำกัด, ค่าเริ่มต้น 4)
    DEEP_SCAN_WAIT_SEC      รอคิวนานสุดกี่วินาทีก่อนถอยไปชั้น 1-2 (ค่าเริ่มต้น 10)

**ข้อจำกัดเดียวกับ state อื่นทั้งหมดในโปรเจกต์นี้:** เพดานนี้นับใน process เดียว
ถ้าวันไหนรันหลาย process/หลายเครื่อง แต่ละตัวจะมีเพดานของตัวเองแยกกัน (เหมือน
rate limiter และ scan_cache) ตอนนั้นต้องย้ายไปนับที่ Redis พร้อมกันทั้งชุด
"""
import os
import threading
import time
from contextlib import contextmanager


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _float_env(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


MAX_CONCURRENT = _int_env("DEEP_SCAN_CONCURRENCY", 4)
WAIT_TIMEOUT = _float_env("DEEP_SCAN_WAIT_SEC", 10.0)

# 0 หรือน้อยกว่า = ปิดเพดานทิ้ง (ทางหนีไฟเวลาต้องพิสูจน์ว่าอาการที่เจอไม่ได้มาจากตัวนี้)
_slots = threading.BoundedSemaphore(MAX_CONCURRENT) if MAX_CONCURRENT > 0 else None

_lock = threading.Lock()
_stats = {
    "in_use": 0,        # กำลังทำอยู่กี่ชุดเดี๋ยวนี้
    "peak_in_use": 0,   # เคยขึ้นสูงสุดเท่าไร (ไว้ดูว่าเพดานตั้งพอดีหรือยัง)
    "granted": 0,       # ได้ที่ไปทำเชิงลึกกี่ครั้ง
    "skipped": 0,       # รอจนหมดเวลาแล้วถอยไปชั้น 1-2 กี่ครั้ง
    "queued": 0,        # ต้องเข้าคิวรอ (ไม่ได้ที่ทันที) กี่ครั้ง
    "wait_ms_max": 0,   # รอคิวนานสุดกี่มิลลิวินาที
}


def acquire() -> bool:
    """ขอที่หนึ่งชุด — True ถ้าได้ (ผู้เรียก **ต้อง** เรียก release() คู่กันใน finally)
    False ถ้ารอจนครบ DEEP_SCAN_WAIT_SEC แล้วยังไม่ว่าง (ผู้เรียกต้องไม่เรียก release())

    จงใจไม่ raise เวลาไม่ได้ที่: "ระบบแน่น" ไม่ใช่ความผิดของลิงก์ที่ผู้ใช้ส่งมา
    ผู้เรียกต้องถอยไปตอบผลชั้น 1-2 ไม่ใช่ตอบ error
    """
    if _slots is None:
        _enter()
        return True

    started = time.perf_counter()
    # acquire(timeout=...) ของ semaphore คืน False เมื่อหมดเวลา ไม่ raise — ตรงที่ต้องการ
    got = _slots.acquire(timeout=WAIT_TIMEOUT)
    waited_ms = round((time.perf_counter() - started) * 1000)
    with _lock:
        _stats["wait_ms_max"] = max(_stats["wait_ms_max"], waited_ms)
        if not got:
            _stats["skipped"] += 1
        elif waited_ms > 0:
            _stats["queued"] += 1   # ได้ที่ช้ากว่าทันที = เคยติดคิว (เกณฑ์หยาบ ๆ พอดูแนวโน้ม)
    if got:
        _enter()
    return got


def release() -> None:
    """คืนที่ — เรียกได้เฉพาะตอนที่ acquire() คืน True เท่านั้น"""
    _leave()
    if _slots is not None:
        _slots.release()


@contextmanager
def slot():
    """รูปแบบ context manager ของ acquire()/release() — yield True ถ้าได้ที่

        with deep_limit.slot() as granted:
            if granted:
                ...ชั้น 3-4...
    """
    granted = acquire()
    try:
        yield granted
    finally:
        if granted:
            release()


def _enter() -> None:
    with _lock:
        _stats["granted"] += 1
        _stats["in_use"] += 1
        _stats["peak_in_use"] = max(_stats["peak_in_use"], _stats["in_use"])


def _leave() -> None:
    with _lock:
        _stats["in_use"] = max(0, _stats["in_use"] - 1)


def stats() -> dict:
    """ตัวเลขสำหรับ /api/health — ดูว่าเพดานถูกชนบ่อยไหม (skipped ขึ้นเรื่อย ๆ =
    ถึงเวลาเพิ่ม DEEP_SCAN_CONCURRENCY หรือเพิ่มแรมเครื่อง)"""
    with _lock:
        return {"max_concurrent": MAX_CONCURRENT, "wait_timeout_sec": WAIT_TIMEOUT,
                **_stats}


def _reset_for_tests() -> None:
    """ล้างตัวนับ — ใช้ในเทสต์เท่านั้น เพื่อให้แต่ละเทสต์เริ่มจากศูนย์เหมือนกัน"""
    with _lock:
        for key in _stats:
            _stats[key] = 0

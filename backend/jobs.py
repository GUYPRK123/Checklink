# -*- coding: utf-8 -*-
"""
jobs.py
คิวงานเบื้องหลังแบบเบา ๆ สำหรับงานที่ "นานเกินกว่าจะให้ผู้ใช้รอในคำขอเดียว"

ปัญหาที่แก้: การตรวจแบบ bulk 20 ลิงก์ใช้เวลาได้ถึงราว 8 วินาที ตลอดเวลานั้นมันยึด
worker thread ของ waitress ไว้ 1 เส้น (จากทั้งหมดไม่กี่เส้น) ผลคือสมาชิกพรีเมียมไม่กี่คน
ที่กด bulk พร้อมกันทำให้ "ทั้งเว็บ" ช้าสำหรับทุกคน รวมถึงคนที่แค่จะเปิดหน้าแรก

วิธีแก้: endpoint ตอบ 202 พร้อม job_id ทันที แล้วให้หน้าเว็บถามความคืบหน้าเป็นระยะ
งานจริงไปทำใน thread pool แยกที่กำหนดขนาดไว้ชัดเจน — thread ของ waitress จึงว่าง
กลับไปเสิร์ฟคนอื่นได้ทันที และงานหนักถูกจำกัดเพดานไว้ในที่เดียว

ข้อจำกัดที่ยอมรับ (เหมาะกับขนาดของระบบตอนนี้: process เดียว เครื่องเดียว):
  - งานเก็บในหน่วยความจำ ถ้ารีสตาร์ตเซิร์ฟเวอร์ งานที่ค้างอยู่จะหายไป ผู้ใช้กดใหม่ได้
  - ถ้าวันหนึ่งต้องรันหลาย process ต้องย้ายไปใช้ Celery/RQ + Redis แทน (ตอนนี้ยังไม่คุ้ม)
"""
import os
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

# จำนวน "งาน bulk" ที่ยอมให้ทำพร้อมกันทั้งระบบ — ตั้งใจให้น้อย เพราะแต่ละงานเปิด
# thread ย่อยยิงเน็ตของตัวเองอีกชั้น (BULK_CHECK_WORKERS) งานที่เกินจะรอคิวอยู่ใน pool
MAX_CONCURRENT_JOBS = int(os.environ.get("BULK_JOB_CONCURRENCY", "2"))

# เก็บผลไว้ให้ดึงได้นานแค่ไหนหลังงานเสร็จ (วินาที) — นานพอให้หน้าเว็บที่ปิดไปแล้วเปิดใหม่
# ยังเห็นผล แต่ไม่นานจนกินหน่วยความจำ
JOB_TTL = int(os.environ.get("BULK_JOB_TTL", str(30 * 60)))

_pool = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_JOBS, thread_name_prefix="bulkjob")
_jobs = {}
_lock = threading.Lock()


def _purge_expired() -> None:
    """ทิ้งงานที่เก่าเกิน TTL — เรียกตอนสร้างงานใหม่ จึงไม่ต้องมี thread คอยกวาดต่างหาก"""
    cutoff = time.time() - JOB_TTL
    with _lock:
        for job_id in [k for k, v in _jobs.items() if v["created_at"] < cutoff]:
            del _jobs[job_id]


def submit(app, owner_id: int, total: int, work) -> str:
    """สร้างงานใหม่แล้วส่งเข้าคิว คืน job_id

    work(report) ถูกเรียกใน thread เบื้องหลังพร้อม app context เสมอ และต้องคืน list
    ของผลลัพธ์ — เรียก report() ทุกครั้งที่ทำเสร็จไปหนึ่งรายการเพื่ออัปเดตความคืบหน้า
    """
    _purge_expired()
    job_id = uuid.uuid4().hex
    with _lock:
        _jobs[job_id] = {
            "id": job_id, "owner_id": owner_id, "state": "queued",
            "done": 0, "total": total, "results": None, "error": None,
            "created_at": time.time(), "finished_at": None,
        }

    def report() -> None:
        with _lock:
            job = _jobs.get(job_id)
            if job is not None:
                job["done"] += 1

    def runner() -> None:
        with _lock:
            job = _jobs.get(job_id)
            if job is None:
                return           # ถูกล้างทิ้งไปแล้วระหว่างรอคิว
            job["state"] = "running"
        try:
            # ต้องมี app context เพราะงานเบื้องหลังแตะฐานข้อมูล/ค่าตั้งของแอป
            # (พอ context ปิด Flask-SQLAlchemy จะคืน session ของ thread นี้ให้เอง)
            with app.app_context():
                results = work(report)
            state, error = "done", None
        except Exception as exc:
            app.logger.exception("งาน bulk %s ล้มเหลว", job_id)
            results, state, error = None, "failed", f"{type(exc).__name__}: {exc}"
        with _lock:
            job = _jobs.get(job_id)
            if job is not None:
                job.update(state=state, results=results, error=error,
                           finished_at=time.time())

    _pool.submit(runner)
    return job_id


def get(job_id: str, owner_id: int):
    """ดึงสถานะงาน — คืน None ถ้าไม่มีงานนี้ หรือไม่ใช่งานของผู้ใช้คนนี้

    จงใจไม่แยกสองกรณีนี้ออกจากกัน เพื่อไม่ให้คนอื่นเดา job_id ไปเรื่อย ๆ แล้วรู้ได้ว่า
    id ไหนมีอยู่จริง
    """
    with _lock:
        job = _jobs.get(job_id)
        if job is None or job["owner_id"] != owner_id:
            return None
        return {
            "id": job["id"],
            "state": job["state"],           # queued | running | done | failed
            "done": job["done"],
            "total": job["total"],
            "results": job["results"],
            "error": job["error"],
            "elapsed_sec": round((job["finished_at"] or time.time()) - job["created_at"], 1),
        }


def stats() -> dict:
    """ไว้ดูใน /api/health ว่ามีงานค้างอยู่เท่าไร"""
    with _lock:
        states = {}
        for job in _jobs.values():
            states[job["state"]] = states.get(job["state"], 0) + 1
        return {"jobs": len(_jobs), "by_state": states,
                "max_concurrent": MAX_CONCURRENT_JOBS}

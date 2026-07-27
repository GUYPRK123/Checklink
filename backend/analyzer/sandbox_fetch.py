# -*- coding: utf-8 -*-
"""
sandbox_fetch.py
============================================================================
  >>> ตัวดึงหน้าเว็บตัวที่สอง: ส่งงานให้ sandbox บนอีกเครื่องหนึ่งรัน JavaScript ให้ <<<
============================================================================
ไฟล์นี้อยู่ฝั่ง **เครื่องหลัก** (เครื่องที่รันเว็บ) หน้าที่เดียวของมันคือส่ง URL ไปให้
บริการ sandbox บนอีกเครื่อง แล้วรับ page bundle กลับมา — **ตัวมันเองไม่รัน
JavaScript และไม่มี Chromium** จึงไม่ได้เพิ่มความเสี่ยงอะไรให้เครื่องหลักเลย

ทำไมต้องแยกเครื่อง (ตัดสินใจเมื่อ 27 ก.ค. 2026):
  1) ความปลอดภัย — การรัน JS ของหน้าเว็บ คือการเอาโค้ดของคนที่เราสงสัยว่าเป็น
     มิจฉาชีพมารัน ถ้ารันบนเครื่องเดียวกับที่เก็บ `app.db` และ `SECRET_KEY`
     ช่องโหว่ของ Chromium ครั้งเดียวก็ถึงข้อมูลผู้ใช้ได้
  2) แรม — เครื่องหลักมีแรมรวม 458 MB ส่วน Chromium ต้องการ 256-512 MB
     ฝืนรันพร้อมกันคือ OOM แล้ว systemd จะฆ่าโปรเซสเว็บทิ้ง

ตั้งค่าผ่าน .env (ถ้าไม่ตั้ง ระบบจะไม่เรียก sandbox เลยและทำงานเหมือนเดิมทุกอย่าง):

    SANDBOX_URL=http://10.0.0.5:8900/fetch
    SANDBOX_TOKEN=<ความลับที่ใช้ร่วมกันสองเครื่อง>
    SANDBOX_TIMEOUT=12

**หลักการที่ห้ามผิด: sandbox ล่มต้องไม่ทำให้การตรวจลิงก์ล่มตาม**
ทุกความผิดพลาดที่นี่คืนเป็น bundle ที่ ok=False ("เช็กไม่ได้") ไม่ใช่ raise ออกไป
เพราะตามหลักการของระบบ "เช็กไม่ได้" ต้องไม่ถูกนับเป็น "เสี่ยง" และไม่ใช่ "ปลอดภัย"
ผู้เรียกจะถอยไปใช้ผลจากตัวดึงแบบธรรมดาแทนได้เสมอ
"""
import os

from .page_fetch import empty_bundle

# คีย์ที่ต้องมีครบใน bundle ที่ sandbox ส่งกลับมา ถ้าขาดแปลว่าอีกฝั่งเวอร์ชันไม่ตรงกัน
_REQUIRED = ("ok", "final_url", "html", "raw_html")


def is_configured() -> bool:
    """ตั้งค่า sandbox ไว้แล้วหรือยัง — ถ้ายัง ระบบจะไม่พยายามเรียกเลย"""
    return bool(os.environ.get("SANDBOX_URL"))


def _timeout() -> float:
    """เวลารอสูงสุด ต้องมากกว่าเวลาที่ sandbox ตัดหน้าเว็บทิ้ง (8 วิ) พอสมควร
    ไม่งั้นเครื่องหลักจะเลิกรอทั้งที่อีกฝั่งกำลังจะตอบอยู่แล้ว"""
    try:
        return float(os.environ.get("SANDBOX_TIMEOUT", "12"))
    except ValueError:
        return 12.0


def fetch_page(url: str) -> dict:
    """ส่ง url ให้ sandbox รันแล้วคืน page bundle (รูปร่างเดียวกับ page_fetch.fetch_page)"""
    endpoint = os.environ.get("SANDBOX_URL")
    if not endpoint:
        return empty_bundle("ยังไม่ได้ตั้งค่า sandbox", source="sandbox")

    try:
        import requests
    except ImportError:
        return empty_bundle("ไม่มีไลบรารี requests", source="sandbox")

    headers = {"Content-Type": "application/json"}
    token = os.environ.get("SANDBOX_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = requests.post(endpoint, json={"url": url}, headers=headers,
                             timeout=_timeout())
    except Exception:
        return empty_bundle("ติดต่อ sandbox ไม่ได้", source="sandbox")

    if resp.status_code != 200:
        return empty_bundle(f"sandbox ตอบ HTTP {resp.status_code}", source="sandbox")

    try:
        data = resp.json()
    except Exception:
        return empty_bundle("sandbox ตอบกลับมาไม่ใช่ JSON", source="sandbox")

    if not isinstance(data, dict) or any(k not in data for k in _REQUIRED):
        return empty_bundle("sandbox ตอบกลับมาผิดรูปแบบ", source="sandbox")

    if not data.get("ok"):
        return empty_bundle(data.get("reason") or "sandbox ดึงหน้าเว็บไม่ได้",
                            source="sandbox")

    # สร้าง bundle ขึ้นใหม่จากค่าที่ต้องการเท่านั้น ไม่ยกของจากอีกฝั่งมาทั้งก้อน
    # เพื่อกันไม่ให้ฟิลด์แปลกปลอมหลุดเข้ามาในระบบ และบังคับชนิดข้อมูลให้ถูกเสมอ
    return {
        "ok": True,
        "reason": "",
        "source": "sandbox",
        "js_rendered": True,
        "final_url": str(data.get("final_url") or url),
        "status": data.get("status") if isinstance(data.get("status"), int) else None,
        "html": str(data.get("html") or ""),
        "raw_html": str(data.get("raw_html") or ""),
        "network_posts": _clean_posts(data.get("network_posts")),
    }


def _clean_posts(posts) -> list:
    """คัดเฉพาะรายการที่มีรูปร่างถูกต้องจาก network_posts ที่อีกฝั่งส่งมา"""
    if not isinstance(posts, list):
        return []
    out = []
    for p in posts[:50]:
        if isinstance(p, dict) and p.get("url"):
            out.append({"url": str(p["url"])[:300],
                        "cross_origin": bool(p.get("cross_origin"))})
    return out

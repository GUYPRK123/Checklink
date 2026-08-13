# -*- coding: utf-8 -*-
"""
page_fetch.py
============================================================================
  >>> ตัว "ดึง" หน้าเว็บ — ไม่วิเคราะห์อะไรทั้งสิ้น <<<
============================================================================
โมดูลนี้มีหน้าที่เดียว: เอา URL เข้า คืน "page bundle" ออก
การวิเคราะห์ทั้งหมดอยู่ที่ content_analyzer.py ซึ่งรับ bundle นี้เป็น input

**ทำไมต้องแยก** — เพราะแผนต่อไปคือใส่ sandbox (Chromium ที่รัน JavaScript จริง)
เข้ามาเป็นตัวดึงอีกตัวหนึ่ง ถ้าการวิเคราะห์ผูกอยู่กับ requests เหมือนเดิม พอเปลี่ยน
ตัวดึงก็ต้องรื้อตัววิเคราะห์ตามไปด้วย แต่ถ้าตกลง "สัญญา" (page bundle) กันไว้ก่อน
ตัวดึงจะเปลี่ยนเป็นอะไรก็ได้โดยที่ตัววิเคราะห์ไม่รู้เรื่องเลย และที่สำคัญที่สุดคือ
ตัววิเคราะห์ยัง **เทสต์ได้โดยไม่ต้องมีเน็ต** แค่ป้อน bundle ที่เขียนไว้ในไฟล์เทสต์

สัญญา page bundle (ทุกตัวดึงต้องคืนหน้าตานี้เหมือนกัน):

    {
      "ok": bool,            # ดึงมาได้หรือไม่ — False แปลว่า "เช็กไม่ได้" ไม่ใช่ "ปลอดภัย"
      "reason": str,         # ดึงไม่ได้เพราะอะไร (ตอน ok=False)
      "source": str,         # "requests" | "sandbox" — ใครเป็นคนดึง
      "js_rendered": bool,   # รัน JavaScript ของหน้าแล้วหรือยัง
      "final_url": str,      # URL สุดท้ายหลัง redirect
      "status": int|None,    # HTTP status
      "html": str,           # DOM ที่จะเอาไปวิเคราะห์ (ตัวนี้ = raw_html เพราะยังไม่รัน JS)
      "raw_html": str,       # HTML ดิบก่อนรัน JS (ไว้ให้ sandbox เทียบว่า JS วาดอะไรเพิ่ม)
      "network_posts": [],   # ปลายทางที่ JS ยิง POST — sandbox เท่านั้นที่เห็น
    }

ความปลอดภัย (SSRF): เช็ก IP ปลอดภัยก่อนต่อทุกครั้งผ่าน _resolve_safe_ips เหมือน
ชั้นที่ 3 จำกัดขนาดที่ดาวน์โหลด (MAX_BYTES) และมี timeout — ตัวนี้ **ไม่รัน**
JavaScript ใด ๆ ทั้งสิ้น จึงยังปลอดภัยพอที่จะรันในโปรเซสเดียวกับแอปได้
(ตัวที่รัน JS ต้องอยู่ในคอนเทนเนอร์แยกเสมอ ดู docs/content-analysis.md หัวข้อ 4)
"""
from urllib.parse import urlsplit

from .destination_checker import _resolve_safe_ips

MAX_BYTES = 512 * 1024   # 512KB พอสำหรับ head+body ส่วนต้น ไม่ต้องโหลดทั้งหน้า
TIMEOUT = (5, 10)        # (connect, read) วินาที — เหตุผลเดียวกับ destination_checker.py
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 checker-bot/1.0")


def empty_bundle(reason: str, source: str = "requests") -> dict:
    """bundle ของกรณี "ดึงไม่ได้" — ต้องมีรูปร่างเดียวกับตอนสำเร็จเสมอ เพื่อให้
    ตัววิเคราะห์ไม่ต้องเช็ก key ว่ามีหรือไม่มีทุกบรรทัด"""
    return {"ok": False, "reason": reason, "source": source, "js_rendered": False,
            "final_url": "", "status": None, "html": "", "raw_html": "",
            "network_posts": []}


def fetch_page(url: str) -> dict:
    """ดึงหน้าเว็บด้วย requests (ไม่รัน JavaScript) คืน page bundle

    เหตุผลที่คืน bundle แทนที่จะ raise: การดึงหน้าเว็บล้มเหลวเป็นเรื่องปกติมาก
    (เว็บล่ม, ไม่ใช่หน้า HTML, โดนบล็อก) และตามหลักการของระบบ "เช็กไม่ได้"
    ต้องไม่กลายเป็น "เสี่ยง" — ผู้เรียกจึงต้องเห็นความต่างนี้ชัด ๆ ผ่าน ok
    """
    try:
        import requests
    except ImportError:
        return empty_bundle("ไม่มีไลบรารี requests")

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return empty_bundle("ไม่ใช่ลิงก์ http/https")

    _, status, _ = _resolve_safe_ips(parts.hostname or "")
    if status:  # dns_fail หรือ blocked_ip -> ไม่ต่อ
        return empty_bundle(f"ไม่ปลอดภัยที่จะเชื่อมต่อ ({status})")

    try:
        resp = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT},
                            stream=True)
    except Exception:
        return empty_bundle("เชื่อมต่อหน้าเว็บไม่ได้")

    # หน้า error (403/404/500) ไม่ใช่เนื้อหาจริงของเว็บนั้น การเอาไปวิเคราะห์จะได้
    # สัญญาณขยะ เช่น "หน้าเล็กผิดปกติ" หรือ "ไม่มีลิงก์ไปหน้าอื่น" ซึ่งเป็นลักษณะของ
    # หน้า error ทุกหน้าในโลก ไม่ได้บอกอะไรเกี่ยวกับเว็บที่ผู้ใช้ถามเลย
    # กรณีที่เจอบ่อยที่สุดคือเว็บที่กันบอตแล้วตอบ 403 ให้เรา (เช่น pantip.com)
    # ตามหลักของระบบ กรณีแบบนี้ต้องเป็น "เช็กไม่ได้" ไม่ใช่ "ตรวจแล้วไม่พบอะไร"
    if resp.status_code >= 400:
        code = resp.status_code
        resp.close()
        return empty_bundle(f"ปลายทางตอบ HTTP {code}")

    ctype = resp.headers.get("Content-Type", "")
    if "html" not in ctype.lower():
        resp.close()
        return empty_bundle("ปลายทางไม่ใช่หน้า HTML")

    chunks, total = [], 0
    try:
        for chunk in resp.iter_content(8192):
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total >= MAX_BYTES:
                break
    except Exception:
        pass
    finally:
        resp.close()

    if not chunks:
        return empty_bundle("หน้าเว็บไม่มีเนื้อหา")

    encoding = resp.encoding or "utf-8"
    try:
        html = b"".join(chunks).decode(encoding, errors="ignore")
    except LookupError:
        html = b"".join(chunks).decode("utf-8", errors="ignore")

    return {
        "ok": True,
        "reason": "",
        "source": "requests",
        "js_rendered": False,
        "final_url": resp.url or url,
        "status": resp.status_code,
        "html": html,       # ยังไม่รัน JS -> DOM ที่วิเคราะห์ได้ก็คือ HTML ดิบนี่เอง
        "raw_html": html,
        "network_posts": [],
    }

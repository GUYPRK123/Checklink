# -*- coding: utf-8 -*-
"""
url_parser.py
แยกส่วนประกอบของ URL ออกมาเป็นชิ้น ๆ เพื่อให้ heuristics นำไปวิเคราะห์ต่อ

จุดสำคัญ: การหา "โดเมนจริง" (registrable domain / eTLD+1) ทำเองด้วยรายการ
นามสกุล 2 ชั้น (MULTI_SUFFIXES) เพื่อไม่ต้องพึ่งไลบรารีภายนอกที่ต้องโหลด
Public Suffix List จากอินเทอร์เน็ต  -> รันได้ทันทีแบบออฟไลน์
หากต้องการความครอบคลุมระดับโลกเต็มรูปแบบ สามารถสลับไปใช้ไลบรารี tldextract ได้
"""
import re
from urllib.parse import urlsplit

from .config import MULTI_SUFFIXES

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HAS_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
# scheme แบบไม่มี "//" เช่น data:, javascript:, mailto:, tel: — ต่างจาก _HAS_SCHEME
# ตรงที่ตัวนี้จับได้แม้ไม่มี "//" ใช้เพื่อ "กัน" ไม่ให้ค่าพวกนี้ถูกเข้าใจผิดว่าเป็น
# host แล้วเติม "http://" นำหน้าจนพังรูปแบบ (เจอตอน content_checker.py ส่ง href/action
# ของ <link>/<form> ที่ผู้เขียนหน้าเว็บใส่มาเป็น data: URI เข้ามา parse)
_HAS_NON_WEB_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:(?!//)")


def parse_url(raw: str) -> dict:
    """รับสตริงลิงก์ คืน dict ของส่วนประกอบ (valid=False ถ้าอ่านไม่ได้)"""
    if not raw or not raw.strip():
        return {"valid": False, "raw": raw}

    text = raw.strip()
    has_scheme = bool(_HAS_SCHEME.match(text))
    if not has_scheme and _HAS_NON_WEB_SCHEME.match(text):
        return {"valid": False, "raw": text}  # data:/javascript:/mailto: ฯลฯ ไม่ใช่ลิงก์เว็บ
    work = text if has_scheme else "http://" + text

    try:
        parts = urlsplit(work)
        host = (parts.hostname or "").lower()
        port = str(parts.port) if parts.port else ""
    except ValueError:
        # เช่น urlsplit คำนวณ .port ไม่ได้เพราะส่วนที่ควรเป็นตัวเลขพอร์ตกลับไม่ใช่ตัวเลข
        return {"valid": False, "raw": text}

    if not host:
        return {"valid": False, "raw": text}

    result = {
        "valid": True,
        "raw": text,
        "protocol_known": has_scheme,
        "protocol": parts.scheme.lower() if has_scheme else "(ไม่ระบุ)",
        "host": host,
        "port": port,
        "path": (parts.path or "") + (("?" + parts.query) if parts.query else ""),
        "userinfo": bool(parts.username or parts.password),
        "is_punycode": "xn--" in host,
    }

    # เลข IP -> ไม่มีโดเมน/นามสกุล
    if _IPV4.match(host) or ":" in host:
        result.update({"is_ip": True, "subdomain": "", "registrable": host,
                        "tld": "", "main_label": host})
        return result

    # ตรวจความถูกต้องของชื่อโฮสต์ที่ไม่ใช่ IP (ต้องไม่มีช่องว่าง มีจุด และใช้ตัวอักษรที่ถูกต้อง)
    if (" " in host) or ("." not in host) or (not re.match(r"^[a-z0-9.\-]+$", host)):
        return {"valid": False, "raw": text}

    labels = host.split(".")
    suffix_len = 1
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTI_SUFFIXES:
        suffix_len = 2
    reg_len = suffix_len + 1  # โดเมนจริง = ชื่อ + นามสกุล

    result.update({
        "is_ip": False,
        "registrable": ".".join(labels[-reg_len:]),
        "subdomain": ".".join(labels[:-reg_len]) if len(labels) > reg_len else "",
        "tld": ".".join(labels[-suffix_len:]),
        "main_label": labels[-reg_len] if len(labels) >= reg_len else host,
    })
    return result

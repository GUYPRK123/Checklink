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
import unicodedata
from urllib.parse import urlsplit

from .config import BRANDS, MULTI_SUFFIXES

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HAS_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
# scheme แบบไม่มี "//" เช่น data:, javascript:, mailto:, tel: — ต่างจาก _HAS_SCHEME
# ตรงที่ตัวนี้จับได้แม้ไม่มี "//" ใช้เพื่อ "กัน" ไม่ให้ค่าพวกนี้ถูกเข้าใจผิดว่าเป็น
# host แล้วเติม "http://" นำหน้าจนพังรูปแบบ (เจอตอน content_checker.py ส่ง href/action
# ของ <link>/<form> ที่ผู้เขียนหน้าเว็บใส่มาเป็น data: URI เข้ามา parse)
_HAS_NON_WEB_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:(?!//)")

# ---------------------------------------------------------------------------
# homoglyph: ตัวอักษรต่างภาษาที่หน้าตาเหมือนตัวละติน (Unicode confusables)
# ใช้จับโดเมนแบบ аpple.com (а ซีริลลิก) ที่ตามองไม่ออกว่าไม่ใช่ apple.com จริง
# คัดเฉพาะคู่ที่ "หน้าตาเหมือนจนใช้หลอกได้จริง" — ไม่เอาทั้งตาราง Unicode มา
# เพราะยิ่งกว้างยิ่งเสี่ยง false positive กับโดเมน IDN ภาษาจริง (ไทย/รัสเซีย ฯลฯ)
# ---------------------------------------------------------------------------
_CONFUSABLES = {
    # ซีริลลิก
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ѵ": "v", "ԝ": "w",
    "к": "k", "м": "m", "т": "t", "в": "b",
    # กรีก
    "ο": "o", "ν": "v", "α": "a", "ρ": "p", "τ": "t", "υ": "u", "ι": "i",
    "κ": "k", "ϲ": "c", "ε": "e",
}


def _skeleton(host: str) -> str:
    """ล้างการอำพรางออกจากชื่อโฮสต์ให้เหลือ "โครง" ตัวละตินที่ตาคนอ่านเห็น

    สามขั้นตามลำดับ (ลำดับสำคัญ):
      1) NFKC — ตัวอักษรเต็มความกว้าง/รูปพิเศษ -> รูปปกติ
      2) แทนที่ confusables ต่างภาษา -> ตัวละตินที่หน้าตาเหมือน
      3) NFKD + ตัด combining mark — ạ/á/â -> a (เทคนิคจุด/ขีดใต้ตัวอักษร
         ที่พบในเว็บฟิชชิ่งจริง เช่น ạpple.com)
    """
    s = unicodedata.normalize("NFKC", host.lower())
    s = "".join(_CONFUSABLES.get(ch, ch) for ch in s)
    s = unicodedata.normalize("NFKD", s)
    return "".join(ch for ch in s if not unicodedata.combining(ch))


def _homoglyph_brand(host: str):
    """ถ้าโฮสต์นี้ "หลังล้างการอำพราง" มีชื่อแบรนด์ที่รู้จักโผล่ขึ้นมา คืน label ของแบรนด์

    เงื่อนไขบังคับ: skeleton ต้องต่างจากโฮสต์เดิม (แปลว่ามีการอำพรางเกิดขึ้นจริง)
    โดเมน IDN ภาษาจริง (ไทย.com, почта.рф) skeleton จะยังมีอักขระภาษานั้นอยู่
    และไม่ตรงแบรนด์ใด จึงไม่ถูกจับ — คงหลัก fail-closed ของระบบไว้
    """
    if not host:
        return None
    skel = _skeleton(host)
    if skel == host:
        return None  # ไม่มีอะไรถูกอำพราง
    for b in BRANDS:
        if re.search(r"(^|[^a-z0-9])" + re.escape(b["label"]) + r"([^a-z0-9]|$)", skel):
            return b["label"]
    return None


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

    # ---- homoglyph/IDN (ตรวจ "ก่อน" ด่าน fail-closed ข้างล่าง) ----
    # ค่าเริ่มต้นของโฮสต์ที่มีอักขระนอก a-z0-9.- ยังคงเป็น "อ่านลิงก์ไม่ได้" (fail-closed)
    # ยกเว้นกรณีเดียว: อักขระแปลกเหล่านั้นถูกใช้เลียนแบบแบรนด์ที่รู้จัก — กรณีนั้น
    # เดินหน้าวิเคราะห์ต่อ (แปลงโฮสต์เป็น punycode ให้ขั้นต่อไปทำงานได้) เพื่อให้
    # ผู้ใช้ได้ "คำเตือนปลอมแปลง" ที่บอกอะไรจริง ๆ แทนคำตอบว่าอ่านไม่ได้
    if (" " not in host) and ("." in host) and not re.match(r"^[a-z0-9.\-]+$", host):
        brand = _homoglyph_brand(host)
        if brand:
            try:
                puny = host.encode("idna").decode("ascii")
            except UnicodeError:
                return {"valid": False, "raw": text}
            result.update({"host": puny, "is_punycode": True,
                           "homoglyph_brand": brand, "homoglyph_original": host})
            host = puny
    elif "xn--" in host:
        # ผู้ใช้ที่ก๊อปลิงก์จากเบราว์เซอร์มักได้รูป punycode มาแล้ว (เบราว์เซอร์แปลงให้)
        # ถอดกลับเป็น unicode เพื่อตรวจแบบเดียวกัน — โฮสต์เดิมเป็น ASCII อยู่แล้ว ใช้ต่อได้เลย
        try:
            uni = host.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            uni = ""
        brand = _homoglyph_brand(uni) if uni else None
        if brand:
            result.update({"homoglyph_brand": brand, "homoglyph_original": uni})

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

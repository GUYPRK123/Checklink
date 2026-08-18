# -*- coding: utf-8 -*-
"""
domain_intel.py
============================================================================
  >>> ชั้นที่ 4 ของระบบ (เสริม): ข้อมูลเชิงลึกของโดเมนที่ heuristics จาก
      รูปร่าง URL อย่างเดียวมองไม่เห็น <<<
============================================================================
ชั้น 2 (heuristics.py) วิเคราะห์ได้แค่ "หน้าตา" ของ URL เท่านั้น ไม่รู้ว่าโดเมนนี้
มีตัวตนอยู่จริงมานานแค่ไหน ชั้นนี้จึงเสริมข้อมูลที่ต้อง "ถามหน่วยงานภายนอก" 2 อย่าง:

  1) อายุโดเมน (ผ่าน RDAP - Registration Data Access Protocol)
     เว็บฟิชชิ่งส่วนใหญ่จดโดเมนมาใช้ไม่กี่วัน/ชั่วโมงก่อนเปิดใช้งานจริง เพราะพอถูก
     รายงาน/บล็อกก็ต้องทิ้งแล้วจดโดเมนใหม่วนไปเรื่อย ๆ (อายุโดเมนสั้นมาก คือสัญญาณ
     ที่งานวิจัยด้าน anti-phishing ใช้กันเป็นมาตรฐาน) ใช้ rdap.org เป็น bootstrap
     เดียว (มันจะหา RDAP server ที่ถูกต้องของแต่ละนามสกุลแล้ว redirect ให้เอง) จึง
     ไม่ต้องพึ่งไลบรารี whois ภายนอกที่รูปแบบผลลัพธ์ไม่มีมาตรฐานเดียวกัน
     นอกจากวันจดทะเบียนแล้ว ยังแกะ "จดผ่านใคร" (registrar) และ "ใครถือครอง"
     (registrant — ส่วนใหญ่ถูกปิดตามนโยบายความเป็นส่วนตัว) มาแสดงเป็นข้อมูล
     ประกอบด้วย โดยไม่มีผลต่อคะแนนความเสี่ยง

  2) ใบรับรอง SSL/TLS ต่อ handshake จริงเพื่อดู:
       - ตรวจสอบ certificate ผ่านหรือไม่ (self-signed / hostname ไม่ตรง ฯลฯ)
       - วันที่ออก certificate -> เว็บที่เพิ่งตั้งขึ้นชั่วคราวมักใช้ certificate ฟรี
         ที่เพิ่งออกไม่กี่วัน

หลักการสำคัญ: ทั้งสองอย่างนี้เรียกบริการภายนอก (RDAP / TLS handshake) จึงมี latency
และ "เช็กไม่ได้" เป็นเรื่องปกติ (นามสกุลบางตัวไม่รองรับ RDAP, ไฟร์วอลล์บล็อก 443 ฯลฯ)
กรณีเช็กไม่ได้ถือว่า "ไม่รู้" ไม่ใช่ "เสี่ยง" (หลักการเดียวกับ dns_fail ใน
destination_checker.py) จึงไม่เพิ่มคะแนนใด ๆ เพื่อไม่ให้ผลลัพธ์แกว่งไปตามความเสถียร
ของเครือข่าย ณ ขณะนั้น

ปลอดภัยจาก SSRF: ก่อนต่อ TLS ไปยัง host ใด ๆ จะเช็ก IP ปลอดภัยด้วยฟังก์ชันเดียวกับ
ชั้นที่ 3 (destination_checker._resolve_safe_ips) ก่อนเสมอ
"""
import socket
import ssl
from datetime import datetime, timezone

from .destination_checker import _resolve_safe_ips
from .config import WEIGHTS

RDAP_TIMEOUT = 4     # วินาที
SSL_TIMEOUT = 4       # วินาที
VERY_NEW_DAYS = 7     # อายุโดเมนต่ำกว่านี้ = critical
NEW_DAYS = 30         # อายุโดเมนต่ำกว่านี้ (แต่ >= VERY_NEW_DAYS) = high
CERT_NEW_DAYS = 3     # อายุ certificate ต่ำกว่านี้ = medium


def _signal(key: str, title: str, detail: str) -> dict:
    points, severity = WEIGHTS[key]
    return {"id": key, "title": title, "detail": detail,
            "points": points, "severity": severity}


def _parse_rdap_date(events, action="registration"):
    """หา event ประเภทที่ระบุ (registration/expiration) ใน events ของ RDAP
    คืน datetime (UTC) หรือ None"""
    for ev in events or []:
        if ev.get("eventAction") != action:
            continue
        raw = ev.get("eventDate")
        if not raw:
            continue
        try:
            dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    return None


# คำที่นายทะเบียนใช้แทนชื่อจริงเมื่อผู้ถือครองเลือกปิดข้อมูล (นโยบายความเป็นส่วนตัว
# ตาม GDPR/ICANN ตั้งแต่ปี 2018 โดเมนส่วนใหญ่จะเป็นแบบนี้) — เจอคำพวกนี้ให้ถือว่า
# "ไม่เปิดเผย" ไม่ใช่ชื่อจริง จะได้ไม่แสดงคำว่า REDACTED โต้ง ๆ ให้ผู้ใช้งง
_REDACTED_MARKERS = ("redact", "privacy", "private", "gdpr", "data protected",
                     "not disclosed", "withheld", "statutory masking")


def _is_redacted(name: str) -> bool:
    lower = name.lower()
    return any(m in lower for m in _REDACTED_MARKERS)


def _walk_entities(entities):
    """ไล่ entity ทุกตัวใน RDAP รวมที่ซ้อนอยู่ข้างใน (บาง registry ซ้อน registrant
    ไว้ใต้ entity ของ registrar อีกชั้น)"""
    for ent in entities or []:
        if not isinstance(ent, dict):
            continue
        yield ent
        yield from _walk_entities(ent.get("entities"))


def _vcard_text(vcard_array, *props):
    """ดึงค่า text แรกที่ไม่ว่างของ property ที่ระบุ (เรียงตามลำดับที่อยากได้ เช่น
    fn ก่อน org) จาก vcardArray ของ RDAP (รูปแบบ jCard: ["vcard", [[ชื่อ, พารามิเตอร์,
    ชนิด, ค่า], ...]])"""
    entries = vcard_array[1] if (isinstance(vcard_array, list)
                                 and len(vcard_array) >= 2
                                 and isinstance(vcard_array[1], list)) else []
    for want in props:
        for entry in entries:
            if (isinstance(entry, list) and len(entry) >= 4 and entry[0] == want
                    and isinstance(entry[3], str) and entry[3].strip()):
                return entry[3].strip()
    return ""


def _extract_registration(data: dict) -> dict:
    """แกะข้อมูลการจดทะเบียนจากก้อน RDAP JSON — แยกเป็นฟังก์ชันล้วน ๆ (ไม่ยิงเน็ต)
    เพื่อให้เทสต์ป้อน JSON ตัวอย่างแล้วตรวจผลได้ตรง ๆ

    หมายเหตุ registrar/registrant: เป็น "ข้อมูลประกอบ" ให้ผู้ใช้ดูเท่านั้น ไม่มีผลต่อ
    คะแนนความเสี่ยง — ชื่อผู้ถือครอง (registrant) ส่วนใหญ่ถูกปิดตามนโยบายความเป็น
    ส่วนตัว จึงต้องแยกให้ชัดระหว่าง "ไม่เปิดเผย" (registrant_private=True) กับ
    "ไม่มีข้อมูลมาเลย" (ทั้งคู่ว่าง) เพื่อให้หน้าเว็บอธิบายถูก"""
    registered = _parse_rdap_date(data.get("events"))
    if not registered:
        return {"checked": False}

    age_days = (datetime.now(timezone.utc) - registered).days
    if age_days < 0:
        return {"checked": False}  # นาฬิกาเซิร์ฟเวอร์เพี้ยน ไม่เอามาใช้

    expires = _parse_rdap_date(data.get("events"), "expiration")

    registrar = ""
    registrant = ""
    registrant_seen = False
    for ent in _walk_entities(data.get("entities")):
        roles = ent.get("roles") or []
        name = _vcard_text(ent.get("vcardArray"), "fn", "org")
        if "registrar" in roles and not registrar and name:
            registrar = name
        if "registrant" in roles:
            registrant_seen = True
            if name and not _is_redacted(name) and not registrant:
                registrant = name

    return {"checked": True, "age_days": age_days,
            "registered_on": registered.date().isoformat(),
            "expires_on": expires.date().isoformat() if expires else "",
            "registrar": registrar,
            "registrant": registrant,
            # เจอ entity ผู้ถือครองแต่ชื่อว่าง/ถูกปิด = เจ้าของเลือกไม่เปิดเผย
            # (ปกติของโดเมนยุคปัจจุบัน ไม่ใช่สัญญาณเสี่ยง)
            "registrant_private": registrant_seen and not registrant}


def check_domain_age(registrable: str) -> dict:
    """
    เช็กข้อมูลจดทะเบียนของโดเมนผ่าน RDAP: อายุ + วันหมดอายุ + จดผ่านใคร + ผู้ถือครอง
    คืน {"checked": True, "age_days": int, "registered_on": "YYYY-MM-DD",
         "expires_on": str, "registrar": str, "registrant": str,
         "registrant_private": bool}
    หรือ {"checked": False} ถ้าเช็กไม่ได้ (นามสกุลไม่รองรับ RDAP / ไม่มีข้อมูล /
    เครือข่ายมีปัญหา) — ถือว่า "ไม่รู้" ไม่ใช่ "เสี่ยง"
    """
    if not registrable:
        return {"checked": False}
    try:
        import requests
    except ImportError:
        return {"checked": False}
    try:
        resp = requests.get(
            f"https://rdap.org/domain/{registrable}",
            timeout=RDAP_TIMEOUT, headers={"Accept": "application/rdap+json"})
        if resp.status_code != 200:
            return {"checked": False}
        data = resp.json()
    except Exception:
        return {"checked": False}

    return _extract_registration(data)


def check_ssl_certificate(host: str, port: int = 443) -> dict:
    """
    ต่อ TLS handshake จริง (คนละทางกับ requests ที่ destination_checker ใช้) เพื่อ
    ดึงรายละเอียด certificate โดยตรง
    คืน {"checked": True, "valid": bool, "issuer": str, "not_before": str,
         "age_days": int|None} หรือ {"checked": False} ถ้าเช็กไม่ได้ (ไม่เปิดพอร์ต
         443 / ไม่ใช่ https / เครือข่ายมีปัญหา)
    ถ้า valid=False คือ handshake สำเร็จแต่ตรวจสอบ certificate ไม่ผ่าน (เช่น
    self-signed หรือชื่อโดเมนไม่ตรงกับ certificate) ซึ่งถือเป็นสัญญาณเสี่ยงจริง
    """
    if not host:
        return {"checked": False}

    _, status, _ = _resolve_safe_ips(host)
    if status:  # dns_fail หรือ blocked_ip -> ไม่ต่อ (กัน SSRF และลิงก์ที่ต่อไม่ได้อยู่แล้ว)
        return {"checked": False}

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=SSL_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return {"checked": True, "valid": False, "error": str(e)}
    except Exception:
        return {"checked": False}

    not_before_raw = cert.get("notBefore", "")
    age_days = None
    if not_before_raw:
        try:
            # รูปแบบจาก ssl module เช่น "Jun  1 00:00:00 2024 GMT" (เป็น GMT เสมอ)
            text = not_before_raw[:-4] if not_before_raw.endswith(" GMT") else not_before_raw
            not_before = datetime.strptime(text, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - not_before).days
        except ValueError:
            age_days = None

    issuer = dict(x[0] for x in cert.get("issuer", []))
    return {"checked": True, "valid": True,
            "issuer": issuer.get("organizationName") or issuer.get("commonName", ""),
            "not_before": not_before_raw, "age_days": age_days}


def analyze_domain_intel(registrable: str, host: str) -> dict:
    """รวมผลจากอายุโดเมน + SSL certificate ให้ scanner.py
    คืน {"signals": [...], "domain_age": {...}, "ssl": {...}}
    เก็บผลดิบ (domain_age/ssl) ไว้ด้วย ไม่ใช่แค่สัญญาณที่ถูกตีว่าเสี่ยง เพื่อให้
    หน้าเว็บแสดงผลได้แม้ในกรณีที่เช็กแล้ว "ปกติดี" (ไม่มีสัญญาณ แต่ผู้ใช้ควรเห็นว่า
    ระบบเช็กให้แล้วจริง ๆ ไม่ใช่แค่เงียบไปเฉย ๆ)"""
    signals = []

    age = check_domain_age(registrable)
    if age.get("checked"):
        days = age["age_days"]
        if days < VERY_NEW_DAYS:
            signals.append(_signal(
                "domain_very_new", "โดเมนเพิ่งจดทะเบียนไม่กี่วัน",
                f"จดทะเบียนเมื่อ {age['registered_on']} ({days} วันก่อน) "
                "เว็บฟิชชิ่งมักจดโดเมนใหม่มาใช้แล้วทิ้งเพราะถูกบล็อกเร็ว"))
        elif days < NEW_DAYS:
            signals.append(_signal(
                "domain_new", "โดเมนจดทะเบียนมาไม่ถึง 1 เดือน",
                f"จดทะเบียนเมื่อ {age['registered_on']} ({days} วันก่อน) "
                "เว็บทางการส่วนใหญ่มีอายุโดเมนหลายเดือนถึงหลายปีขึ้นไป"))

    cert = check_ssl_certificate(host)
    if cert.get("checked"):
        if not cert.get("valid"):
            signals.append(_signal(
                "ssl_invalid", "ใบรับรอง SSL ไม่ถูกต้อง",
                f"เชื่อมต่อแบบเข้ารหัสได้แต่ตรวจสอบใบรับรองไม่ผ่าน "
                f"({cert.get('error', '')}) อาจเป็นใบรับรองปลอม หรือไม่ตรงกับโดเมนนี้"))
        elif cert.get("age_days") is not None and cert["age_days"] < CERT_NEW_DAYS:
            signals.append(_signal(
                "ssl_cert_new", "ใบรับรอง SSL เพิ่งออกไม่กี่วัน",
                f"ออกเมื่อ {cert.get('not_before', '')} มักพบในเว็บที่เพิ่งตั้งขึ้น "
                "ชั่วคราวเพื่อใช้หลอกแล้วทิ้ง"))

    return {"signals": signals, "domain_age": age, "ssl": cert}

# -*- coding: utf-8 -*-
"""
content_checker.py
============================================================================
  >>> ชั้นที่ 4 ของระบบ (เสริม): วิเคราะห์เนื้อหาจริงของหน้าเว็บปลายทาง <<<
============================================================================
ทุกชั้นก่อนหน้านี้ดูแค่ "รูปร่างของ URL" เท่านั้น ไม่เคยเปิดดูว่าหน้าเว็บจริงมี
อะไรอยู่ข้างใน — แต่การหลอกเอาข้อมูล (credential harvesting) เกิดขึ้นที่ "ฟอร์ม"
ในหน้าเว็บ ไม่ใช่ที่ตัว URL ชั้นนี้จึงดึงเนื้อหาจริงมาดู (จำกัดขนาด+เวลา) แล้วหา
รูปแบบที่พบบ่อยในเว็บฟิชชิ่ง 3 อย่าง:

  1) ฟอร์มที่มีช่องรหัสผ่าน แต่ "action" (ปลายทางที่ข้อมูลจะถูกส่งไปจริง) เป็น
     คนละโดเมนกับหน้าเว็บที่เห็น -> สัญญาณร้ายแรงที่สุด เพราะแปลว่าข้อมูลที่กรอก
     จะถูกส่งไปเก็บที่เซิร์ฟเวอร์อื่น ไม่ใช่เจ้าของเว็บที่แสดงอยู่จริง
  2) favicon ที่ดึงมาจากโดเมนของแบรนด์จริง (hotlink ตรงจากเว็บจริง) ทั้งที่หน้านี้
     ไม่ใช่โดเมนของแบรนด์นั้น -> มิจฉาชีพขี้เกียจทำไอคอนเอง เลยลิงก์ตรงจากเว็บจริง
     เพื่อความเนียน
  3) หัวข้อ/เนื้อหาหน้าเว็บพูดถึงชื่อแบรนด์เด่นชัด ทั้งที่โดเมนไม่ใช่ของแบรนด์นั้น
     (เหมือนกฎ brand_impersonation ในชั้น 2 แต่คราวนี้ดูจาก "เนื้อหาในหน้า" แทน
     "ตัว URL")

ปลอดภัยจาก SSRF เหมือนชั้นที่ 3: เช็ก IP ปลอดภัยซ้ำก่อนต่อทุกครั้ง (ผ่าน
destination_checker._resolve_safe_ips) จำกัดขนาดที่ดาวน์โหลด (MAX_BYTES) และ
timeout ต่อการเชื่อมต่อ ไม่อ่านอะไรเกินความจำเป็น (ไม่รัน JavaScript ใด ๆ ในหน้า)

ต้องติดตั้ง beautifulsoup4 (ดู requirements.txt) ถ้ายังไม่มีจะข้ามชั้นนี้ไปเงียบ ๆ
(เหมือนกับที่ระบบข้ามชั้นบัญชีดำไปได้ถ้า requests ไม่มี)
"""
import re
from urllib.parse import urljoin, urlsplit

from .destination_checker import _resolve_safe_ips
from .url_parser import parse_url
from .config import BRANDS, WEIGHTS

MAX_BYTES = 512 * 1024   # 512KB พอสำหรับ head+body ส่วนต้น ไม่ต้องโหลดทั้งหน้า
TIMEOUT = 5              # วินาที
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 checker-bot/1.0")


def _signal(key: str, title: str, detail: str) -> dict:
    points, severity = WEIGHTS[key]
    return {"id": key, "title": title, "detail": detail,
            "points": points, "severity": severity}


def _fetch_html(url: str):
    """ดึง HTML แบบจำกัดขนาด คืน None ถ้าเช็กไม่ได้ / ไม่ใช่หน้า HTML"""
    try:
        import requests
    except ImportError:
        return None

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return None

    _, status, _ = _resolve_safe_ips(parts.hostname or "")
    if status:  # dns_fail หรือ blocked_ip -> ไม่ต่อ
        return None

    try:
        resp = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT},
                             stream=True)
    except Exception:
        return None

    ctype = resp.headers.get("Content-Type", "")
    if "html" not in ctype.lower():
        resp.close()
        return None

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
        return None
    encoding = resp.encoding or "utf-8"
    try:
        return b"".join(chunks).decode(encoding, errors="ignore")
    except LookupError:
        return b"".join(chunks).decode("utf-8", errors="ignore")


def _find_favicon_href(soup):
    """หา <link rel="icon" ...> โดยไม่พึ่งการ match แบบ regex บน attribute แบบ
    multi-valued (rel เป็น list ใน BeautifulSoup) เพื่อความชัวร์"""
    for link in soup.find_all("link"):
        rel = link.get("rel") or []
        if isinstance(rel, str):
            rel = [rel]
        if any("icon" in r.lower() for r in rel):
            href = link.get("href")
            if href:
                return href
    return None


def analyze_content(url: str, page_registrable: str) -> dict:
    """วิเคราะห์เนื้อหาหน้าเว็บปลายทาง (url) เทียบกับโดเมนจริงของหน้านั้น
    (page_registrable) คืน {"signals": [...], "checked": bool}
    checked=False หมายถึง "ดึงหน้าเว็บมาวิเคราะห์ไม่ได้" (ไม่มี bs4 / ต่อไม่ได้ /
    ไม่ใช่หน้า HTML) ต่างจาก checked=True + signals=[] ซึ่งหมายถึง "ดึงมาดูแล้ว
    ไม่พบสิ่งผิดปกติ" — หน้าเว็บควรแยกสองกรณีนี้ให้ผู้ใช้เห็น ไม่ใช่ปล่อยเงียบเหมือนกัน"""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return {"signals": [], "checked": False}

    if not page_registrable:
        return {"signals": [], "checked": False}

    html = _fetch_html(url)
    if not html:
        return {"signals": [], "checked": False}

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return {"signals": [], "checked": False}

    signals = []

    # 1) ฟอร์มรหัสผ่าน + action ข้ามโดเมน (สัญญาณสำคัญที่สุดของ credential harvesting)
    for form in soup.find_all("form"):
        has_password = form.find("input", attrs={"type": re.compile("^password$", re.I)})
        if not has_password:
            continue
        action = form.get("action")
        if not action:
            continue
        target_parsed = parse_url(urljoin(url, action))
        target_reg = target_parsed.get("registrable", "")
        if target_parsed.get("valid") and target_reg and target_reg != page_registrable:
            signals.append(_signal(
                "form_action_mismatch", "ฟอร์มกรอกรหัสผ่านส่งข้อมูลไปคนละโดเมน",
                f"ข้อมูลที่กรอกในฟอร์มจะถูกส่งไปที่ \"{target_reg}\" ซึ่งไม่ใช่โดเมนของ"
                f"หน้านี้ ({page_registrable}) — เป็นสัญญาณคลาสสิกของการขโมยข้อมูล"))
            break

    # 2) favicon hotlink จากโดเมนแบรนด์จริง ทั้งที่หน้านี้ไม่ใช่โดเมนนั้น
    href = _find_favicon_href(soup)
    if href:
        icon_parsed = parse_url(urljoin(url, href))
        icon_reg = icon_parsed.get("registrable", "")
        if icon_parsed.get("valid") and icon_reg and icon_reg != page_registrable:
            for b in BRANDS:
                if icon_reg in b["domains"]:
                    signals.append(_signal(
                        "favicon_brand_mismatch",
                        f"ไอคอนเว็บดึงมาจากโดเมนจริงของ {b['label'].upper()}",
                        f"หน้านี้ใช้ favicon จาก \"{icon_reg}\" (โดเมนทางการของ "
                        f"{b['label']}) ทั้งที่ตัวหน้าเว็บอยู่คนละโดเมน "
                        f"({page_registrable}) มักใช้เพื่อให้ดูน่าเชื่อถือโดยไม่ต้อง"
                        "ทำไอคอนเอง"))
                    break

    # 3) หัวข้อหน้าเว็บพูดถึงแบรนด์เด่นชัด ทั้งที่โดเมนไม่ตรง
    title = soup.title.get_text(strip=True).lower() if soup.title else ""
    if title:
        for b in BRANDS:
            if page_registrable in b["domains"]:
                continue
            if re.search(r"(^|[^a-z])" + re.escape(b["label"]) + r"([^a-z]|$)", title):
                signals.append(_signal(
                    "content_brand_mismatch", f"หัวข้อหน้าเว็บอ้างถึง {b['label'].upper()}",
                    f"ชื่อหน้าเว็บ (\"{title[:60]}\") กล่าวถึง \"{b['label']}\" ทั้งที่"
                    f"โดเมนจริงคือ {page_registrable} ซึ่งไม่ใช่เว็บทางการ"))
                break

    return {"signals": signals, "checked": True}

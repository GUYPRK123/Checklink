

# -*- coding: utf-8 -*-
"""
destination_checker.py
============================================================================
  >>> ชั้นที่ 3 ของระบบ: ตามลิงก์ (โดยเฉพาะลิงก์ย่อ) ไปจนถึง "ปลายทางจริง" <<<
============================================================================
เทคนิค: Redirect Resolution
  เดิมระบบเห็นแค่ตัวลิงก์ที่ผู้ใช้วาง ถ้าเป็นลิงก์ย่อ (bit.ly ฯลฯ) จะไม่รู้เลยว่า
  ปลายทางจริงคือเว็บอะไร ชั้นนี้จึงยิง HTTP แบบ "ไม่ auto-follow" ทีละ hop เอง
  เก็บ chain การ redirect ทั้งหมด แล้วส่ง URL ปลายทางจริงกลับไปให้ scanner.py
  นำไปวิเคราะห์ซ้ำในชั้นที่ 1 (บัญชีดำ) และชั้นที่ 2 (heuristics) อีกครั้ง

ป้องกัน SSRF (Server-Side Request Forgery) — สำคัญเพราะ backend ยิง URL ที่ผู้ใช้
พิมพ์เองไปยังปลายทางที่ผู้ใช้ (หรือมิจฉาชีพ) เป็นคนกำหนด:
  1) อนุญาตเฉพาะ scheme http/https เท่านั้น
  2) resolve DNS เองก่อนต่อทุกครั้ง แล้วเช็ก "ทุก" IP ที่ได้ว่าไม่ใช่ IP วง
     private/loopback/link-local/reserved/multicast — เช็กใหม่ทุก hop เพื่อกัน
     DNS rebinding (โดเมนสาธารณะที่ตอบ IP ภายในทีหลัง)
  3) จำกัดจำนวน hop สูงสุด (MAX_HOPS) และ timeout ต่อ hop
  4) ใช้ HEAD ก่อน (ไม่ดึง body) ถ้าเซิร์ฟเวอร์ไม่รองรับค่อย fallback เป็น GET
     แบบ stream แล้วปิดทันทีโดยไม่อ่านเนื้อหา
"""
import ipaddress
import re
import socket
from urllib.parse import urljoin, urlsplit

MAX_HOPS = 5
# แยกเป็น (connect, read): ปลายทางที่ "ต่อไม่ได้เลย" ควรรู้ผลเร็ว (5 วิ)
# ส่วนที่ต่อได้แต่ตอบช้าให้เวลามากกว่า (10 วิ) — requests รองรับ tuple โดยตรง
TIMEOUT = (5, 10)  # (connect, read) วินาทีต่อ hop
_HAS_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 checker-bot/1.0")


def _normalize(raw: str) -> str:
    text = raw.strip()
    return text if _HAS_SCHEME.match(text) else "http://" + text


def _final_response_facts(resp, final_url: str) -> dict:
    """สรุป "ข้อเท็จจริง" ของ response ปลายทาง (ไม่ตัดสินอะไร — scanner เป็นคนตัดสิน)
    ใช้ดูว่ากดลิงก์แล้วจะ "ได้ไฟล์" แทนที่จะเปิดหน้าเว็บหรือไม่ และไฟล์ชื่อ/ชนิดอะไร"""
    content_type = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
    disposition = resp.headers.get("Content-Disposition") or ""
    filename = ""
    m = re.search(r"filename\*?=(?:UTF-8'')?\"?([^\";]+)", disposition, re.IGNORECASE)
    if m:
        filename = m.group(1).strip()
    if not filename:
        # ไม่มีชื่อใน header -> ใช้ชื่อไฟล์ท้าย path ของ URL ปลายทาง
        filename = urlsplit(final_url).path.rsplit("/", 1)[-1]
    return {
        "content_type": content_type,
        "attachment": "attachment" in disposition.lower(),
        "filename": filename,
    }


def _is_blocked_ip(ip_str: str) -> bool:
    """True ถ้าเป็น IP ที่ไม่ควรให้ backend ยิงเข้าไปหา (วง internal/สงวนไว้)"""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # แปลงไม่ได้ -> กันไว้ก่อน
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def _resolve_safe_ips(host: str):
    """resolve DNS แล้วคืน (ips, status, reason)
    status: '' = ปลอดภัย, 'dns_fail' = โดเมนไม่มีอยู่จริง/resolve ไม่ได้ (ไม่ใช่ SSRF),
            'blocked_ip' = ชี้ไปยัง IP ภายใน/สงวนไว้ (สัญญาณ SSRF จริง)
    แยกสองกรณีนี้ออกจากกันเพราะ dns_fail ไม่ใช่สัญญาณอันตรายในตัวมันเอง (โดเมนอาจแค่
    เพิ่งถูกปิด/พิมพ์ผิด) ในขณะที่ blocked_ip แทบไม่มีเว็บทางการทำแบบนี้ ถือว่าอันตรายชัดเจน"""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return None, "dns_fail", "แปลงชื่อโดเมนเป็น IP ไม่ได้ (โดเมนอาจไม่มีอยู่จริงหรือถูกปิดไปแล้ว)"
    ips = {info[4][0] for info in infos}
    for ip in ips:
        if _is_blocked_ip(ip):
            return None, "blocked_ip", f"โดเมนนี้ชี้ไปยัง IP ภายใน/สงวนไว้ ({ip}) ซึ่งไม่อนุญาตให้ตรวจ"
    return ips, "", ""


def resolve_destination(raw_url: str) -> dict:
    """
    ตามลิงก์ไปทีละ hop จนสุดทาง (หรือครบ MAX_HOPS)
    คืน dict:
      resolved      = ตามได้สำเร็จอย่างน้อย 1 hop โดยไม่ถูกบล็อก
      chain         = ลำดับ URL ทุก hop ที่ผ่าน (รวมต้นทาง)
      final_url     = URL ปลายทางสุดท้ายที่ตามได้
      hops          = จำนวนครั้งที่ redirect (chain ยาวกว่า 1 เท่าไร)
      blocked       = True ถ้าหยุดเพราะเจอ IP ภายใน (สัญญาณผิดปกติร้ายแรง)
      blocked_reason= เหตุผลที่บล็อก (ไว้แสดงผล)
      error         = ข้อผิดพลาดเครือข่าย (ถ้ามี)
    """
    try:
        import requests
    except ImportError:
        return {"resolved": False, "chain": [raw_url], "final_url": raw_url,
                "hops": 0, "error": "ยังไม่ได้ติดตั้งไลบรารี requests"}

    current = _normalize(raw_url)
    chain = [current]
    final_resp = None  # response ของ hop สุดท้ายที่ไม่ใช่ redirect (ไว้ดูว่าปลายทางคือไฟล์ไหม)

    for hop in range(MAX_HOPS):
        parts = urlsplit(current)
        if parts.scheme not in ("http", "https"):
            return {"resolved": hop > 0, "chain": chain, "final_url": current,
                    "hops": len(chain) - 1, "error": f"ไม่รองรับโปรโตคอล {parts.scheme!r}"}

        host = parts.hostname or ""
        _, status, reason = _resolve_safe_ips(host)
        if status == "blocked_ip":
            return {"resolved": False, "chain": chain, "final_url": current,
                    "hops": len(chain) - 1, "blocked": True, "blocked_reason": reason}
        if status == "dns_fail":
            # หยุดตามต่อไม่ได้ (เชื่อมต่อไม่ได้) แต่ current คือ URL ปลายทางที่ได้จาก
            # Location header จริง ๆ แล้ว -> ยังส่งต่อให้ชั้น 2 วิเคราะห์เชิงข้อความได้
            # (ไม่ต้องพึ่งเครือข่าย) เพียงแต่ไม่ใช่ "blocked" แบบ SSRF
            return {"resolved": hop > 0, "chain": chain, "final_url": current,
                    "hops": len(chain) - 1, "error": reason}

        headers = {"User-Agent": USER_AGENT}
        try:
            resp = requests.head(current, timeout=TIMEOUT, allow_redirects=False,
                                  headers=headers)
        except requests.RequestException:
            try:
                resp = requests.get(current, timeout=TIMEOUT, allow_redirects=False,
                                     headers=headers, stream=True)
                resp.close()
            except requests.RequestException as e2:
                return {"resolved": hop > 0, "chain": chain, "final_url": current,
                        "hops": len(chain) - 1, "error": f"{type(e2).__name__}: {e2}"}

        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            if not location:
                break
            next_url = urljoin(current, location)
            if next_url == current:
                break
            chain.append(next_url)
            current = next_url
            continue
        final_resp = resp
        break

    result = {"resolved": True, "chain": chain, "final_url": current,
              "hops": len(chain) - 1}
    if final_resp is not None:
        result["final_response"] = _final_response_facts(final_resp, current)
    return result

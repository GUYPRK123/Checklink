# -*- coding: utf-8 -*-
"""
blacklist_api.py
============================================================================
  >>> ชั้นที่ 1 ของระบบ: เทียบกับ "บัญชีรายชื่อโดเมนอันตราย" ของ สกมช. <<<
============================================================================
แหล่งข้อมูลจริงเป็นไฟล์ข้อความ 1 บรรทัด/1 โดเมน:
    https://opendata.ncsa.or.th/domain/blocklist.txt
    ตัวอย่างบรรทัด:  08elec.purpledaily.com
                    1010technologies.com

วิธีเชื่อม (สำคัญ): ไม่ต้องยิงเน็ตทุกครั้งที่ตรวจลิงก์ แต่ใช้วิธี
  1) ดาวน์โหลดทั้งลิสต์มาเก็บเป็น set ในหน่วยความจำ (+ cache ลงดิสก์)
  2) รีเฟรชเมื่อลิสต์เก่าเกิน CACHE_TTL (ค่าเริ่มต้น 6 ชั่วโมง)
  3) เวลาตรวจลิงก์ ดึง "โดเมน" ออกมาแล้วเช็กสมาชิกใน set -> เร็วระดับ O(1)

หมายเหตุ: ลิสต์นี้บอกได้แค่ว่า "โดเมนไหนอันตราย" (blocklist) จึงคืนได้แค่
  found+malicious=True หรือ found=False เท่านั้น (ยืนยัน "ปลอดภัย" ไม่ได้จากแหล่งนี้)
  ถ้าไม่เจอในลิสต์ ระบบจะไปวิเคราะห์สดต่อในชั้นที่ 2 เอง
"""
import os
import time
import threading

from .url_parser import parse_url

BLOCKLIST_URL = os.environ.get(
    "NCSA_BLOCKLIST_URL", "https://opendata.ncsa.or.th/domain/blocklist.txt")
CACHE_TTL = int(os.environ.get("NCSA_CACHE_TTL", 6 * 3600))     # วินาที
CACHE_FILE = os.path.join(os.path.dirname(__file__), "blocklist_cache.txt")

_state = {"domains": set(), "loaded_at": 0.0}
_lock = threading.Lock()


def _parse_lines(text: str) -> set:
    """แปลงเนื้อไฟล์เป็น set ของโดเมน (กันรูปแบบแปลก ๆ ไว้ด้วย)"""
    domains = set()
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        # เผื่อรูปแบบ hosts-file เช่น "0.0.0.0 domain.com"
        if " " in line or "\t" in line:
            line = line.split()[-1]
        line = line.lstrip("*.").rstrip(".")   # ตัด wildcard/จุดท้าย
        if line:
            domains.add(line)
    return domains


def load_blocklist(force: bool = False) -> int:
    """
    โหลด/รีเฟรชบัญชีดำ คืนจำนวนโดเมนที่โหลดได้
    ลำดับ: ใช้ของในหน่วยความจำถ้ายังใหม่ -> ไฟล์ cache บนดิสก์ -> ดาวน์โหลดใหม่
    """
    with _lock:
        fresh = (time.time() - _state["loaded_at"]) < CACHE_TTL
        if _state["domains"] and fresh and not force:
            return len(_state["domains"])

        # 1) ลองใช้ cache บนดิสก์ถ้ายังไม่หมดอายุ
        if not force and os.path.exists(CACHE_FILE):
            if (time.time() - os.path.getmtime(CACHE_FILE)) < CACHE_TTL:
                try:
                    with open(CACHE_FILE, encoding="utf-8") as f:
                        _state["domains"] = _parse_lines(f.read())
                    _state["loaded_at"] = time.time()
                    return len(_state["domains"])
                except OSError:
                    pass

        # 2) ดาวน์โหลดจาก สกมช.
        try:
            import requests  # pip install requests
        except ImportError:
            print("[blocklist] ยังไม่ได้ติดตั้งไลบรารี requests — สั่ง: pip install requests")
            return len(_state["domains"])
        try:
            # ส่ง header แบบเบราว์เซอร์ให้ครบ (บางเซิร์ฟเวอร์เช็ก UA/Accept เพื่อกันบอท)
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/124.0 Safari/537.36",
                "Accept": "text/plain,text/html,*/*",
                "Accept-Language": "th,en;q=0.9",
            }
            resp = requests.get(BLOCKLIST_URL, timeout=30, headers=headers)
            resp.raise_for_status()
            text = resp.text
            domains = _parse_lines(text)
            if not domains:
                print(f"[blocklist] ดาวน์โหลดสำเร็จ ({len(text)} ไบต์) แต่แปลงเป็นโดเมนไม่ได้ "
                      f"— ลองเปิดดูตัวอย่างต้นไฟล์: {text[:120]!r}")
                return len(_state["domains"])
            _state["domains"] = domains
            _state["loaded_at"] = time.time()
            try:                                   # เก็บ cache ลงดิสก์
                with open(CACHE_FILE, "w", encoding="utf-8") as f:
                    f.write(text)
            except OSError:
                pass
            return len(_state["domains"])
        except Exception as e:
            # ดาวน์โหลดไม่ได้ -> พิมพ์สาเหตุจริง แล้วถ้ามีของเก่าก็ใช้ต่อ ไม่ให้ระบบพัง
            print(f"[blocklist] ดาวน์โหลดไม่สำเร็จ: {type(e).__name__}: {e}")
            print(f"[blocklist] วิธีแก้แบบชัวร์: เปิด {BLOCKLIST_URL} ในเบราว์เซอร์ "
                  f"แล้วเซฟไฟล์เป็น {CACHE_FILE} ระบบจะอ่านจากไฟล์นั้นให้เอง")
            return len(_state["domains"])


def _candidates(parsed: dict):
    """สร้างรายชื่อโดเมนที่ต้องเช็ก: ตัวโฮสต์เต็ม ไล่ตัดขึ้นไปจนถึงโดเมนจริง
    เช่น a.b.example.co.th -> [a.b.example.co.th, b.example.co.th, example.co.th]
    เพื่อให้ครอบคลุมทั้งกรณีลิสต์เก็บ subdomain เจาะจง และเก็บโดเมนหลัก"""
    host = parsed.get("host", "")
    if parsed.get("is_ip"):
        return [host]
    reg = parsed.get("registrable", host)
    reg_len = len(reg.split("."))
    labels = host.split(".")
    out = []
    for i in range(0, max(1, len(labels) - reg_len + 1)):
        out.append(".".join(labels[i:]))
    if reg not in out:
        out.append(reg)
    return out


def check_blacklist(url: str) -> dict:
    """ชั้นที่ 1: โดเมนของลิงก์นี้อยู่ในบัญชีดำของ สกมช. หรือไม่"""
    count = load_blocklist()
    if not count:
        # ยังไม่มีข้อมูลบัญชีดำ (โหลดไม่ได้) -> ข้ามไปวิเคราะห์สดชั้น 2
        return {"found": False, "api_error": True}

    parsed = parse_url(url)
    if not parsed.get("valid"):
        return {"found": False}

    domains = _state["domains"]
    for cand in _candidates(parsed):
        if cand in domains:
            return {"found": True, "malicious": True, "matched": cand}
    return {"found": False}

# -*- coding: utf-8 -*-
"""
heuristics.py
หัวใจของระบบ: วิเคราะห์ลิงก์จากตัว URL แล้วให้ "คะแนนความเสี่ยง" พร้อมเหตุผล
นี่คือส่วนที่ตอบโจทย์อาจารย์ว่า "ใช้อัลกอริทึมอะไรจับลิงก์ใหม่ที่ยังไม่ถูกรายงาน"

แต่ละกฎจะเพิ่มสัญญาณ (signal) ที่อธิบายได้ว่าเสี่ยงเพราะอะไร -> ไม่ใช่กล่องดำ
"""
import re
from urllib.parse import unquote

from .config import (BRANDS, RISKY_TLDS, SHORTENERS, LURE_KEYWORDS, WEIGHTS,
                     EXECUTABLE_EXTENSIONS)

# ร่องรอยของโค้ดสคริปต์ในพารามิเตอร์ลิงก์ (ลิงก์ยิง XSS ใส่เว็บปลายทาง)
# เลือกเฉพาะรูปแบบที่แทบไม่มีทางโผล่ใน URL ปกติ — "javascript" เฉย ๆ ไม่นับ
# (ชื่อบทความ/บล็อกใช้กันทั่วไป) ต้องเป็น "javascript:" ที่มี colon เท่านั้น
_SCRIPT_MARKERS = ("<script", "javascript:", "vbscript:", "onerror=", "onload=",
                   "srcdoc=", "document.cookie", "document.write(")


# ---------- เครื่องมือย่อย ----------
def levenshtein(a: str, b: str) -> int:
    """ระยะการแก้ไข (จำนวนตัวอักษรที่ต่างกัน) ใช้จับ typosquatting"""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost))
        prev = cur
    return prev[-1]


_GLYPH_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
    "7": "t", "8": "b", "9": "g", "$": "s",
})


def normalize_glyphs(s: str) -> str:
    """ทำให้ตัวอักษรหน้าตาคล้ายกันเป็นตัวเดียวกัน (g00gle -> google, paypa1 -> paypal)"""
    s = s.lower().translate(_GLYPH_MAP)
    return s.replace("rn", "m").replace("vv", "w")


# ---------- เครื่องมือสร้างสัญญาณ ----------
def _signal(key: str, title: str, detail: str) -> dict:
    points, severity = WEIGHTS[key]
    return {"id": key, "title": title, "detail": detail,
            "points": points, "severity": severity}


def analyze(parsed: dict) -> dict:
    """
    รับผลจาก parse_url คืน:
      { score, signals: [...], verified_safe: bool, legit_brand: str|None }
    """
    signals = []
    reg = parsed.get("registrable", "")
    host = parsed.get("host", "")
    path = parsed.get("path", "")
    main_label = parsed.get("main_label", "")
    haystack = (host + " " + path).lower()

    # 0) ตรงกับโดเมนจริงของแบรนด์เป๊ะ -> ปลอดภัย (ลัดออก)
    for b in BRANDS:
        if reg in b["domains"]:
            signals.append({
                "id": "verified_brand",
                "title": f"ตรงกับโดเมนทางการของ {b['label'].upper()}",
                "detail": f"โดเมน {reg} อยู่ในรายชื่อโดเมนจริงที่ตรวจสอบแล้ว",
                "points": 0, "severity": "good",
            })
            return {"score": 0, "signals": signals,
                    "verified_safe": True, "legit_brand": b["label"]}

    # 0.5) homoglyph: โฮสต์ใช้อักขระต่างภาษาที่หน้าตาเหมือนตัวละตินเพื่อปลอมเป็นแบรนด์
    # ตรวจพบมาจากชั้น parse (url_parser._homoglyph_brand) — โดเมนแบบนี้แทบไม่มีทาง
    # เป็นเว็บสุจริต เพราะการจดโดเมนอักขระผสมให้เหมือนแบรนด์คนอื่นคือเจตนาหลอกในตัวเอง
    hg = parsed.get("homoglyph_brand")
    if hg:
        sig = _signal(
            "homoglyph_brand",
            f"ตรวจพบความพยายามปลอมแปลง {hg.upper()}",
            f"ชื่อโดเมน \"{parsed.get('homoglyph_original', '')}\" ใช้ตัวอักษรต่างภาษา"
            f"ที่หน้าตาเหมือนตัวอักษรปกติเพื่อปลอมเป็น \"{hg}\" "
            f"ตามองแยกไม่ออก ให้ถือว่าเป็นลิงก์หลอกลวง")
        sig["brand"] = hg  # ให้ scanner ดึงโดเมนทางการมาแสดงเทียบได้
        signals.append(sig)

    # 1) เลียนแบบแบรนด์: มีชื่อแบรนด์ในลิงก์ แต่โดเมนจริงไม่ใช่ของแบรนด์นั้น
    # ตำแหน่งที่เจอชื่อแบรนด์สำคัญมาก น้ำหนักจึงต่างกันสามระดับ:
    #   - อยู่ในโฮสต์แบบผสมคำอื่น (facebook-alert.com)  -> เจตนาปลอมชัด = critical
    #   - โดเมนคือชื่อแบรนด์เป๊ะแต่ TLD ไม่อยู่ในลิสต์ (amazon.co.jp / amazon.xyz)
    #     -> แยกของจริงภูมิภาคกับของปลอมจากชื่อไม่ได้ = high ให้สัญญาณอื่นช่วยตัดสิน
    #   - อยู่แค่ใน path (/news/apple-iphone) -> เว็บข่าว/บล็อกพูดถึงแบรนด์เป็นเรื่อง
    #     ปกติ = medium และมี combo เพิ่มคะแนนถ้าหน้านั้นขอรหัสผ่านด้วย
    host_l = host.lower()
    path_l = path.lower()
    for b in BRANDS:
        names = [b["label"]] + b.get("aliases", [])
        found = next((n for n in names
                      if re.search(r"(^|[^a-z])" + re.escape(n) + r"([^a-z]|$)", host_l)), None)
        if found:
            if main_label == found:
                sig = _signal(
                    "brand_bare_domain",
                    f"โดเมนใช้ชื่อ {found.upper()} แต่ไม่ตรงกับโดเมนทางการในลิสต์",
                    f"โดเมน {reg} ใช้ชื่อแบรนด์ตรง ๆ แต่ไม่อยู่ในรายชื่อโดเมนทางการ "
                    f"อาจเป็นโดเมนภูมิภาคของจริงหรือของปลอมก็ได้ โปรดเทียบกับโดเมนทางการ")
            else:
                sig = _signal(
                    "brand_impersonation",
                    f"เลียนแบบแบรนด์ {b['label'].upper()}",
                    f"ชื่อโฮสต์มีคำว่า \"{found}\" แต่โดเมนจริงคือ {reg} ซึ่งไม่ใช่เว็บทางการ")
            sig["brand"] = b["label"]  # ให้ scanner ดึงโดเมนทางการมาแสดงเทียบได้
            signals.append(sig)
            break
        found_path = next((n for n in names
                           if re.search(r"(^|[^a-z])" + re.escape(n) + r"([^a-z]|$)", path_l)), None)
        if found_path:
            sig = _signal(
                "brand_in_path",
                f"ลิงก์กล่าวถึง {b['label'].upper()} ทั้งที่ไม่ใช่เว็บของแบรนด์",
                f"พบคำว่า \"{found_path}\" ในส่วน path ของลิงก์ พบได้ทั่วไปในเว็บข่าว/บทความ "
                f"แต่ถ้าหน้านี้ให้ล็อกอินหรือกรอกข้อมูล ให้ระวังเป็นพิเศษ")
            sig["brand"] = b["label"]
            signals.append(sig)
            break

    # 2) สะกดใกล้เคียงแบรนด์ (typosquatting / ตัวอักษรปลอม / ซ่อนแบรนด์ด้วยเลข)
    if not parsed.get("is_ip"):
        norm_label = normalize_glyphs(main_label)
        norm_host = normalize_glyphs(host)
        for b in BRANDS:
            label = b["label"]
            if main_label == label:
                continue
            dist = levenshtein(norm_label, label)
            glyph_same = norm_label == label and main_label != label
            # เดิมยอมรับ dist=1 ตั้งแต่แบรนด์ยาว 4 ตัว ทำให้คำสามัญโดนลูกหลง
            # (tree~true, lime~line, zoo~zoom ขึ้นแดงหมด) ชื่อสั้นมีคำเพี้ยน 1 ตัว
            # ที่เป็นคำจริงเยอะมาก จึงขยับเกณฑ์เป็น 5/8 — ยกเว้นโดเมนที่มีตัวเลขปน
            # (เช่น l1ne) ซึ่งไม่ใช่คำสามัญแน่ ๆ ให้คงเกณฑ์ 4 ไว้จับการแทนตัวอักษร
            # ด้วยเลขที่ normalize แล้วยังไม่ตรงเป๊ะ (1 อาจแทนได้ทั้ง l และ i)
            has_digit = any(c.isdigit() for c in main_label)
            close = (dist == 1 and len(label) >= (4 if has_digit else 5)) \
                    or (dist == 2 and len(label) >= 8)
            # แบรนด์ถูกซ่อนด้วยตัวอักษรปลอม: ชื่อแบรนด์โผล่ในโฮสต์ที่ normalize แล้ว
            # แต่ไม่โผล่ในโฮสต์ตัวจริง (เช่น g00gle-account, micros0ft-login)
            pat = r"(^|[^a-z])" + re.escape(label) + r"([^a-z]|$)"
            hidden = bool(re.search(pat, norm_host)) and not re.search(pat, host)
            if glyph_same or close or hidden:
                sig = _signal(
                    "typosquatting",
                    f"ชื่อโดเมนเลียนแบบ/สะกดใกล้เคียง {label.upper()}",
                    f"โดเมนจริง \"{reg}\" ใช้ตัวอักษรที่ทำให้เข้าใจผิดว่าเป็น \"{label}\" "
                    f"เป็นเทคนิคหลอกตา")
                sig["brand"] = label
                signals.append(sig)
                break

    # 3) ใช้เลข IP แทนชื่อเว็บ
    if parsed.get("is_ip"):
        signals.append(_signal(
            "ip_host", "ใช้เลข IP แทนชื่อเว็บ",
            f"เว็บทางการแทบไม่ใช้ตัวเลข IP ({host}) เป็นที่อยู่ มักพบในลิงก์หลอก"))

    # 4) มีเครื่องหมาย @ ซ่อนปลายทาง
    if parsed.get("userinfo"):
        signals.append(_signal(
            "userinfo_at", "ลิงก์ซ่อนปลายทางด้วย @",
            f"ทุกอย่างก่อน \"@\" เป็นแค่ตัวลวงตา ปลายทางจริงคือ {reg}"))

    # 5) Punycode (xn--)
    if parsed.get("is_punycode"):
        signals.append(_signal(
            "punycode", "โดเมนใช้รหัสตัวอักษรพิเศษ (xn--)",
            "อาจใช้ตัวอักษรต่างภาษาที่หน้าตาเหมือนภาษาอังกฤษเพื่อปลอมเป็นเว็บจริง"))

    # 6) นามสกุลที่มิจฉาชีพนิยม
    tld = parsed.get("tld", "")
    if tld and tld in RISKY_TLDS:
        signals.append(_signal(
            "risky_tld", f"ใช้นามสกุลที่มิจฉาชีพนิยม (.{tld})",
            "นามสกุลนี้จดง่ายและราคาถูก จึงพบในเว็บหลอกบ่อย"))

    # 7) subdomain ลึกผิดปกติ
    sub = parsed.get("subdomain", "")
    if sub and len(sub.split(".")) >= 3:
        signals.append(_signal(
            "deep_subdomain", "มีโดเมนย่อยซ้อนหลายชั้น",
            f"ส่วนหน้าโดเมน ({sub}) ซ้อนกันหลายชั้น มักใช้ทำให้ลิงก์ดูน่าเชื่อถือ"))

    # 8) ลิงก์ย่อ
    if reg in SHORTENERS:
        signals.append(_signal(
            "shortener", "เป็นลิงก์ย่อ",
            "มองไม่เห็นปลายทางจริงจนกว่าจะกด ควรระวังเป็นพิเศษ"))

    # 9) คำล่อในลิงก์ — เทียบแบบมีขอบเขตคำ (ไม่ใช่ substring) กันคำสามัญโดนลูกหลง
    # เช่น "win" ใน windows/darwin, "free" ใน freedom ("secure-login" ยังจับได้
    # เพราะขีด/ทับนับเป็นขอบเขตคำ)
    hits = [k for k in LURE_KEYWORDS
            if re.search(r"(^|[^a-z])" + re.escape(k) + r"([^a-z]|$)", haystack)]
    if hits:
        points, severity = WEIGHTS["lure_keyword"]
        capped = min(len(hits), 3)
        sample = ", ".join(f"\"{h}\"" for h in hits[:3])
        signals.append({"id": "lure_keyword", "title": "มีคำล่อให้กด",
                        "detail": f"พบคำเช่น {sample} ที่มักใช้สร้างความเร่งรีบ",
                        "points": capped * points, "severity": severity})

    # 10) ขีดเยอะในชื่อโดเมน
    if main_label.count("-") >= 2:
        signals.append(_signal(
            "many_hyphens", "ชื่อโดเมนมีขีดหลายตัว",
            "เช่น secure-login-verify มักพบในเว็บหลอก"))

    # 11) ไม่ใช่ https
    if parsed.get("protocol_known") and parsed.get("protocol") == "http":
        signals.append(_signal(
            "no_https", "ไม่ได้ใช้การเชื่อมต่อแบบเข้ารหัส (http)",
            "ข้อมูลที่กรอกอาจถูกดักได้ เว็บทางการส่วนใหญ่ใช้ https"))

    # 12) พอร์ตแปลก
    port = parsed.get("port", "")
    if port and port not in ("80", "443"):
        signals.append(_signal(
            "weird_port", f"ใช้พอร์ตที่ไม่ปกติ ({port})",
            "เว็บทั่วไปไม่ระบุพอร์ตแบบนี้"))

    # 13) ลิงก์ยาวผิดปกติ
    if len(parsed.get("raw", "")) > 90:
        signals.append(_signal(
            "long_url", "ลิงก์ยาวผิดปกติ",
            "ลิงก์ที่ยาวมากมักซ่อนปลายทางหรือพารามิเตอร์หลอก"))

    # 14) โค้ดสคริปต์ซ่อนในพารามิเตอร์ (ลิงก์ยิง XSS — กดแล้วสคริปต์ทำงานบนเว็บปลายทางทันที)
    # ถอด percent-encoding สองรอบก่อนหา เพราะ payload มักถูกเข้ารหัสซ้อน
    # (%3Cscript%3E หรือกระทั่ง %253Cscript%253E) เพื่อหลบตัวกรองของเว็บเป้าหมาย
    decoded = path
    for _ in range(2):
        decoded = unquote(decoded)
    decoded = decoded.lower()
    marker = next((mk for mk in _SCRIPT_MARKERS if mk in decoded), None)
    if marker:
        signals.append(_signal(
            "script_in_params", "มีโค้ดสคริปต์ซ่อนอยู่ในลิงก์",
            f"พบร่องรอยโค้ด (\"{marker}\") ฝังในพารามิเตอร์ของลิงก์ "
            "เป็นเทคนิคฝังคำสั่งให้ทำงานทันทีที่กด เพื่อขโมยข้อมูลหรือสวมรอยบัญชี"))

    # 15) path ชี้ไปยังไฟล์ที่รัน/ติดตั้งได้ — ยังเป็นแค่ "ชื่อ" จึงให้น้ำหนักกลาง
    # การยืนยันว่าปลายทางส่งไฟล์จริงเกิดที่ชั้น 3 (ดู Content-Type/Content-Disposition)
    filename = path.split("?")[0].rsplit("/", 1)[-1].lower()
    ext = filename.rsplit(".", 1)[-1] if "." in filename else ""
    if ext in EXECUTABLE_EXTENSIONS:
        signals.append(_signal(
            "executable_in_path", f"ลิงก์ชี้ไปยังไฟล์ .{ext} โดยตรง",
            "กดแล้วจะเป็นการดาวน์โหลดไฟล์ที่รัน/ติดตั้งได้ทันที ไม่ใช่การเปิดหน้าเว็บ "
            + ("แอป Android ที่ปลอดภัยควรติดตั้งผ่าน Play Store เท่านั้น" if ext == "apk"
               else "ควรแน่ใจว่าตั้งใจดาวน์โหลดและรู้จักผู้ให้บริการจริง ๆ")))

    score = sum(s["points"] for s in signals)
    return {"score": score, "signals": signals,
            "verified_safe": False, "legit_brand": None}

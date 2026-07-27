# -*- coding: utf-8 -*-
"""
content_analyzer.py
============================================================================
  >>> วิเคราะห์เนื้อหาหน้าเว็บจาก "page bundle" — ไม่ต่อเน็ตเลยแม้แต่ครั้งเดียว <<<
============================================================================
รับ page bundle (ดู page_fetch.py) คืนสัญญาณเสี่ยง + ข้อเท็จจริงของหน้านั้น

**คุณสมบัติสำคัญที่สุดของไฟล์นี้คือมันเป็น pure function** — ป้อน bundle เดิมเข้าไป
ต้องได้ผลเดิมเสมอ ไม่ว่าเน็ตจะล่มหรือเว็บปลายทางจะเปลี่ยนไปแล้ว เทสต์จึงเขียน HTML
ปลอมใส่ตรง ๆ ได้ (ดู tests/test_content_analyzer.py) เหมือนที่ heuristics.py กับ
qr_payload.py ทำอยู่ **อย่าเผลอ import requests หรือเรียก network ในไฟล์นี้เด็ดขาด**

สัญญาณแบ่งเป็น 4 กลุ่มตาม docs/content-analysis.md:

  กลุ่ม 1 การล้วงข้อมูล   — form_action_mismatch, password_outside_form, form_action_ip
  กลุ่ม 2 เลียนแบบแบรนด์  — favicon_brand_mismatch, content_brand_mismatch,
                            logo_hotlink_brand, brand_hidden_in_text
  กลุ่ม 3 การอำพราง       — js_obfuscated, instant_redirect, devtools_blocked
  กลุ่ม 4 คุณภาพหน้าเว็บ  — no_favicon, single_page_no_links, html_too_small

ยังทำไม่ได้จนกว่าจะมี sandbox (ต้องรัน JavaScript จริงถึงจะเห็น): js_post_cross_origin,
password_in_iframe, dom_differs_from_source — ดู docs/content-analysis.md หัวข้อ 5

นอกจากสัญญาณแล้วยังคืน "ข้อเท็จจริง" (facts) ซึ่ง **ไม่ใช่สัญญาณเสี่ยงและไม่มีคะแนน**
เช่น has_password_input — เว็บล็อกอินจริงทุกเว็บก็มีช่องรหัสผ่าน การมีช่องรหัสผ่าน
เฉย ๆ จึงไม่ผิดอะไร แต่มันเป็นเงื่อนไขสำคัญของกฎการรวมสัญญาณ (ดู combos.py)
"""
import re
from urllib.parse import urljoin

from .config import BRANDS, WEIGHTS
from .text_norm import contains_word, normalize_text
from .url_parser import parse_url

# ความยาวข้อความที่คนเห็นจริง ต่ำกว่านี้ถือว่า "หน้าแทบว่าง"
_EMPTY_PAGE_TEXT = 50
# ขนาด HTML ที่ถือว่าเล็กผิดปกติสำหรับหน้าเว็บจริง
_TINY_HTML = 1500
# ชื่อแบรนด์ที่สั้นกว่านี้จะไม่ใช้กับกฎ brand_hidden_in_text (ดูเหตุผลที่ฟังก์ชันนั้น)
_MIN_HIDDEN_BRAND_LEN = 4


def _signal(key: str, title: str, detail: str) -> dict:
    points, severity = WEIGHTS[key]
    return {"id": key, "title": title, "detail": detail,
            "points": points, "severity": severity}


def _brands_for(page_registrable: str) -> list:
    """แบรนด์ทั้งหมดที่ "ไม่ใช่เจ้าของ" โดเมนหน้านี้

    ต้องกรองเจ้าของออกก่อนเสมอ ไม่งั้น google.co.th ที่ฝัง favicon ของ google.com
    จะโดนตีว่าเลียนแบบตัวเอง (สองโดเมนนี้เป็นของแบรนด์เดียวกันแต่คนละ registrable)
    """
    return [b for b in BRANDS if page_registrable not in b["domains"]]


def _registrable_of(base_url: str, ref: str) -> str:
    """หา registrable domain ของลิงก์ที่อ้างถึงในหน้า (รองรับลิงก์แบบสัมพัทธ์)
    คืน "" ถ้าอ่านไม่ได้ หรือเป็นลิงก์ภายในหน้าเดียวกัน"""
    if not ref:
        return ""
    try:
        parsed = parse_url(urljoin(base_url or "", ref))
    except ValueError:
        return ""
    return parsed.get("registrable", "") if parsed.get("valid") else ""


# ---------------------------------------------------------------------------
# การดึงข้อความออกจากหน้า
# ---------------------------------------------------------------------------
def _identity_surfaces(soup) -> list:
    """จุดในหน้าเว็บที่ "ประกาศตัวตน" ของหน้านั้น คืน [(ชื่อจุด, ข้อความ), ...]

    เดิมกฎ content_brand_mismatch ดูแค่ <title> อย่างเดียว ซึ่งเลี่ยงได้ด้วยการ
    ปล่อย title ว่างแล้วเอาชื่อแบรนด์ไปไว้ใน <h1> หรือ alt ของโลโก้แทน

    **จงใจไม่รวมเนื้อความทั้งหน้า** เพราะบทความข่าวที่พูดถึงชื่อแบรนด์เป็นเรื่องปกติ
    ถ้าเอาทั้งหน้ามาเทียบจะได้ false positive มหาศาล จุดที่เลือกมาทั้งหมดนี้คือจุดที่
    "เอ่ยชื่อแบรนด์ = อ้างว่าตัวเองเป็นแบรนด์นั้น" ไม่ใช่แค่พูดถึง

    **และจงใจไม่รวม alt ของรูปด้วย** — เอกสารออกแบบเสนอไว้ แต่พอลองกับเว็บไทยจริง
    พบว่าพังทันที: sanook.com ติดเพราะ alt="Google Play" ของปุ่มโหลดแอป และ
    set.or.th ติดเพราะ alt="Facebook" ของไอคอนโซเชียลท้ายหน้า ทั้งสองเว็บไม่ได้
    เลียนแบบใครเลย เว็บทั่วไปแทบทุกเว็บมีไอคอนพวกนี้ จึงเป็นจุดที่ให้โทษมากกว่าให้คุณ
    """
    out = []
    if soup.title and soup.title.get_text(strip=True):
        out.append(("ชื่อหน้าเว็บ", soup.title.get_text(strip=True)))

    for meta in soup.find_all("meta"):
        key = (meta.get("property") or meta.get("name") or "").lower()
        content = (meta.get("content") or "").strip()
        if not content:
            continue
        if key in ("description", "og:title", "og:site_name", "application-name",
                   "twitter:title"):
            out.append((f"meta {key}", content))

    for h in soup.find_all(["h1", "h2"])[:3]:
        text = h.get_text(strip=True)
        if text:
            out.append(("หัวข้อในหน้า", text))

    return out


def _visible_text(soup) -> str:
    """ข้อความที่ผู้ใช้เห็นจริง — ตัด script/style/noscript ออกก่อน"""
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    return soup.get_text(" ", strip=True)


def _inline_scripts(html: str) -> str:
    """เนื้อของ <script> ทุกก้อนในหน้า ต่อกันเป็นก้อนเดียว

    ดึงด้วย regex จาก HTML ดิบโดยตั้งใจ ไม่ใช้ soup ที่ผ่าน _visible_text มาแล้ว
    เพราะฟังก์ชันนั้น decompose() ทิ้งไปหมดแล้ว (soup ตัวเดียวใช้ซ้ำไม่ได้)
    """
    return "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", html,
                                re.I | re.S))


# ---------------------------------------------------------------------------
# กลุ่ม 1 — การล้วงข้อมูล
# ---------------------------------------------------------------------------
def _check_credential_harvesting(soup, base_url: str, page_registrable: str) -> tuple:
    """คืน (signals, has_password_input)"""
    signals = []
    password_inputs = soup.find_all(
        "input", attrs={"type": re.compile("^password$", re.I)})
    has_password = bool(password_inputs)

    for form in soup.find_all("form"):
        if not form.find("input", attrs={"type": re.compile("^password$", re.I)}):
            continue
        action = form.get("action")
        if not action:
            continue
        target = parse_url(urljoin(base_url or "", action))
        target_reg = target.get("registrable", "")
        if not (target.get("valid") and target_reg):
            continue

        if target.get("is_ip"):
            signals.append(_signal(
                "form_action_ip", "ฟอร์มกรอกรหัสผ่านส่งข้อมูลไปที่เลข IP ตรง ๆ",
                f"ข้อมูลที่กรอกจะถูกส่งไปที่ \"{target_reg}\" ซึ่งเป็นเลข IP ไม่ใช่ชื่อเว็บ "
                "— บริการจริงแทบไม่ทำแบบนี้เพราะตรวจสอบตัวตนเจ้าของไม่ได้เลย"))
            break
        if target_reg != page_registrable:
            signals.append(_signal(
                "form_action_mismatch", "ฟอร์มกรอกรหัสผ่านส่งข้อมูลไปคนละโดเมน",
                f"ข้อมูลที่กรอกในฟอร์มจะถูกส่งไปที่ \"{target_reg}\" ซึ่งไม่ใช่โดเมนของ"
                f"หน้านี้ ({page_registrable}) — เป็นสัญญาณคลาสสิกของการขโมยข้อมูล"))
            break

    # ช่องรหัสผ่านที่ไม่ได้อยู่ใน <form> เลย: เบราว์เซอร์จะไม่ส่งข้อมูลให้เอง แปลว่า
    # ต้องมี JavaScript คอยเก็บค่าไปส่งเอง ซึ่งมองไม่เห็นปลายทางจากตัว HTML
    if any(inp.find_parent("form") is None for inp in password_inputs):
        signals.append(_signal(
            "password_outside_form", "ช่องกรอกรหัสผ่านไม่ได้อยู่ในฟอร์ม",
            "ช่องรหัสผ่านในหน้านี้อยู่นอก <form> แปลว่าต้องมีสคริปต์คอยเก็บค่าที่พิมพ์"
            "ไปส่งเอง จึงมองไม่เห็นว่าข้อมูลจะถูกส่งไปที่ไหน หน้าล็อกอินจริงส่วนใหญ่"
            "ใช้ฟอร์มปกติที่ตรวจสอบปลายทางได้"))

    return signals, has_password


# ---------------------------------------------------------------------------
# กลุ่ม 2 — เลียนแบบแบรนด์
# ---------------------------------------------------------------------------
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


def _check_brand_imitation(soup, html: str, base_url: str, page_registrable: str) -> list:
    signals = []
    brands = _brands_for(page_registrable)

    # 2.1 favicon ดึงตรงจากโดเมนจริงของแบรนด์
    href = _find_favicon_href(soup)
    icon_reg = _registrable_of(base_url, href) if href else ""
    if icon_reg and icon_reg != page_registrable:
        for b in brands:
            if icon_reg in b["domains"]:
                signals.append(_signal(
                    "favicon_brand_mismatch",
                    f"ไอคอนเว็บดึงมาจากโดเมนจริงของ {b['label'].upper()}",
                    f"หน้านี้ใช้ favicon จาก \"{icon_reg}\" (โดเมนทางการของ "
                    f"{b['label']}) ทั้งที่ตัวหน้าเว็บอยู่คนละโดเมน "
                    f"({page_registrable}) มักใช้เพื่อให้ดูน่าเชื่อถือโดยไม่ต้อง"
                    "ทำไอคอนเอง"))
                break

    # 2.2 (logo_hotlink_brand) ถอดออกแล้ว — เขียนไว้เตือนไม่ให้ใส่กลับมาแบบเดิม
    #
    # เอกสารออกแบบเสนอกฎ "รูปในหน้าโหลดตรงจากโดเมนแบรนด์" ไว้ ลองทำแล้ววัดกับเว็บ
    # ไทยจริงพบว่า false positive สูงเกินรับได้: thairath.co.th ติดเพราะฝังภาพปก
    # คลิปจาก youtube.com, sanook.com ติดเพราะไอคอนแชร์ของ facebook.com
    # การฝังรูปจากโดเมนแบรนด์เป็นเรื่องปกติมากของเว็บทั่วไป ต่างจาก favicon ที่เป็น
    # "ตัวตนของหน้า" จริง ๆ (กฎ favicon_brand_mismatch จึงเก็บไว้)
    #
    # กฎนี้จะกลับมาได้ก็ต่อเมื่อมี sandbox ซึ่งเห็นขนาดและตำแหน่งจริงของรูปหลังวาดหน้า
    # แล้วแยกได้ว่าเป็น "โลโก้กลางหน้า" หรือ "ไอคอนโซเชียล 16px ท้ายหน้า"

    # 2.3 / 2.4 ชื่อแบรนด์ในจุดที่ประกาศตัวตนของหน้า
    #
    # ต้องเทียบ 3 รูปแบบของข้อความเดียวกัน เพราะแต่ละแบบจับการอำพรางคนละท่า:
    #   text   = ข้อความหลัง BeautifulSoup แปลงให้แล้ว (คลาย &#nn; ให้อัตโนมัติ)
    #   norm   = ข้อความที่ล้างอักขระหลอกตาออกแล้ว (payp4l -> paypal)
    #   html   = ซอร์สดิบ ยังไม่ถูกแปลงอะไรเลย
    # ถ้าชื่อแบรนด์โผล่ใน text แต่ไม่โผล่ใน html ดิบ แปลว่าถูกเขียนเป็นรหัสไว้
    surfaces = _identity_surfaces(soup)
    plain_hit = None       # เขียนชื่อแบรนด์ตรง ๆ
    hidden_hit = None      # อ่านออกด้วยตาแต่ค้นหาไม่เจอ = จงใจอำพราง
    for where, text in surfaces:
        norm = normalize_text(text)
        for b in brands:
            label = b["label"]
            in_text = contains_word(text, label)
            if plain_hit is None and in_text:
                plain_hit = (b, where, text)

            if hidden_hit is not None or len(label) < _MIN_HIDDEN_BRAND_LEN:
                continue
            in_norm = contains_word(norm, label)
            if in_norm and not in_text:
                hidden_hit = (b, where, text,
                              "ใช้อักขระหลอกตา (เช่น ใช้เลขแทนตัวอักษร ตัวอักษรเต็ม"
                              "ความกว้าง หรือแทรกอักขระที่มองไม่เห็นกลางคำ)")
            elif in_text and not contains_word(html, label):
                hidden_hit = (b, where, text,
                              "เขียนเป็นรหัส HTML (เช่น &#103; แทนตัว g) ที่เบราว์เซอร์"
                              "แปลงกลับให้ตอนแสดงผล แต่การค้นหาในซอร์สหาไม่เจอ")
        if plain_hit and hidden_hit:
            break

    if plain_hit:
        b, where, text = plain_hit
        signals.append(_signal(
            "content_brand_mismatch", f"เนื้อหาในหน้าอ้างถึง {b['label'].upper()}",
            f"{where} (\"{text[:60]}\") กล่าวถึง \"{b['label']}\" ทั้งที่โดเมนจริงคือ "
            f"{page_registrable} ซึ่งไม่ใช่เว็บทางการ"))

    if hidden_hit:
        b, where, text, how = hidden_hit
        signals.append(_signal(
            "brand_hidden_in_text",
            f"จงใจซ่อนชื่อ {b['label'].upper()} ไม่ให้ระบบตรวจเจอ",
            f"{where} (\"{text[:60]}\") อ่านด้วยตาเป็นคำว่า \"{b['label']}\" แต่{how} "
            "เว็บทางการไม่มีเหตุผลที่จะเขียนชื่อตัวเองแบบนี้"))

    return signals


# ---------------------------------------------------------------------------
# กลุ่ม 3 — การอำพราง / หลบการตรวจ
# ---------------------------------------------------------------------------
# คำสั่งที่ใช้ "ถอดแล้วสั่งรัน" ข้อมูลที่ถูกเข้ารหัสไว้
_DECODER_MARKERS = ("eval(", "atob(", "unescape(", "String.fromCharCode",
                    "document.write(", "Function(")


def _encoded_payloads(scripts: str) -> list:
    """หา "ก้อนข้อมูลที่ถูกเข้ารหัสไว้" ในสคริปต์ คืนคำอธิบายของสิ่งที่เจอ

    ตัวนี้คือหลักฐานที่ขาดไม่ได้ของการอำพราง การมีแค่คำสั่งอย่าง eval หรือ unescape
    ยัง **ไม่พอ** — วัดกับเว็บจริงแล้วพบว่าสคริปต์โฆษณา/สถิติของเว็บดัง (เช่น
    stackoverflow.com) ก็มีคำสั่งพวกนี้ปนอยู่เป็นเรื่องปกติ สิ่งที่เว็บปกติไม่มีคือ
    "ก้อนข้อมูลยาว ๆ ที่อ่านไม่ออก" รอให้คำสั่งพวกนั้นถอดออกมาต่างหาก
    """
    found = []
    if len(re.findall(r"\\x[0-9a-fA-F]{2}", scripts)) >= 20:
        found.append("ข้อความที่เขียนเป็นรหัส \\xNN ต่อกันจำนวนมาก")
    if re.search(r"['\"][A-Za-z0-9+/]{200,}={0,2}['\"]", scripts):
        found.append("ก้อนข้อมูลเข้ารหัส base64 ขนาดใหญ่")
    if re.search(r"fromCharCode\(\s*(\d{1,3}\s*,\s*){9,}", scripts):
        found.append("ข้อความที่เขียนเป็นรหัสตัวเลขทีละตัวอักษร")
    return found


def _check_obfuscation(html: str, scripts: str, visible_len: int) -> list:
    signals = []

    # 3.1 โค้ดที่ถูกอำพราง = "ก้อนข้อมูลที่อ่านไม่ออก" + "คำสั่งที่เอามันไปรัน"
    #     ต้องเจอทั้งคู่เท่านั้น ขาดอย่างใดอย่างหนึ่งไม่นับ (ดูเหตุผลใน _encoded_payloads)
    payloads = _encoded_payloads(scripts)
    decoders = [m for m in _DECODER_MARKERS if m in scripts]
    if payloads and decoders:
        signals.append(_signal(
            "js_obfuscated", "สคริปต์ในหน้าถูกอำพรางไว้",
            f"พบ{payloads[0]} คู่กับคำสั่ง {decoders[0]} ที่เอาไปถอดและสั่งรัน "
            "ซึ่งเป็นวิธีซ่อนไม่ให้อ่านออกว่าโค้ดทำอะไร เว็บทั่วไปไม่จำเป็นต้องซ่อน"
            "การทำงานของตัวเอง"))

    # 3.2 เด้งออกทันทีที่เปิด
    meta_refresh = re.search(
        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*content=["\']?\s*(\d+)',
        html, re.I)
    if meta_refresh and int(meta_refresh.group(1)) <= 2:
        signals.append(_signal(
            "instant_redirect", "หน้านี้เด้งไปหน้าอื่นทันทีที่เปิด",
            f"มีคำสั่งให้ย้ายไปหน้าอื่นภายใน {meta_refresh.group(1)} วินาที "
            "มักใช้ให้ลิงก์ที่เห็นดูปลอดภัย แล้วค่อยพาไปหน้าจริงที่ไม่ปลอดภัย"))
    elif visible_len < _EMPTY_PAGE_TEXT and re.search(
            r"location\s*\.\s*(replace|assign|href\s*=)|window\s*\.\s*location\s*=",
            scripts):
        # หน้าที่แทบไม่มีข้อความให้อ่านเลยแต่มีคำสั่งย้ายหน้า = หน้าทางผ่านชัด ๆ
        # (ถ้ามีเนื้อหาปกติจะไม่นับ เพราะเว็บทั่วไปก็ใช้คำสั่งนี้ในปุ่มต่าง ๆ)
        signals.append(_signal(
            "instant_redirect", "หน้านี้เป็นหน้าทางผ่านที่พาไปหน้าอื่นด้วยสคริปต์",
            "หน้านี้แทบไม่มีเนื้อหาให้อ่าน มีแต่คำสั่งพาไปหน้าอื่น "
            "จึงตรวจสอบปลายทางจริงจากตัวลิงก์ไม่ได้"))

    # 3.3 กันไม่ให้ผู้ใช้เปิดดูโค้ดของหน้า
    blocks_menu = "contextmenu" in scripts and "preventDefault" in scripts
    blocks_f12 = bool(re.search(r"keyCode\s*===?\s*123|['\"]F12['\"]|devtools", scripts, re.I))
    if blocks_menu or blocks_f12:
        signals.append(_signal(
            "devtools_blocked", "หน้านี้ปิดกั้นการเปิดดูโค้ด",
            "มีสคริปต์ดักคลิกขวาหรือปุ่มเปิดเครื่องมือนักพัฒนา (F12) ไว้ "
            "เว็บทั่วไปไม่ได้ประโยชน์อะไรจากการทำแบบนี้"))

    return signals


# ---------------------------------------------------------------------------
# สัญญาณที่เห็นได้เฉพาะเมื่อตัวดึงรัน JavaScript จริง (sandbox)
# ---------------------------------------------------------------------------
def _words(text: str) -> set:
    """ชุดคำสำหรับเทียบว่าหน้าสองเวอร์ชันต่างกันแค่ไหน (ตัดคำสั้นมากทิ้ง)"""
    return {w for w in re.findall(r"[a-z0-9฀-๿]+", text.lower()) if len(w) >= 2}


def _check_sandbox_signals(bundle: dict, has_password: bool) -> list:
    """กฎที่ทำงานเฉพาะกับ bundle ที่มาจาก sandbox

    เขียนไว้ล่วงหน้าได้เพราะสัญญา page bundle นิ่งแล้ว — bundle ที่มาจาก requests
    ไม่มีข้อมูลพวกนี้ (js_rendered=False, network_posts=[]) กฎทั้งหมดในนี้จึงเงียบ
    สนิทโดยอัตโนมัติ ไม่ใช่เพราะ "ตรวจแล้วไม่เจอ" แต่เพราะ "ยังไม่ได้ตรวจ"
    """
    signals = []

    # ปลายทางที่สคริปต์ยิงข้อมูลออกไปจริง — สิ่งที่การอ่าน HTML เฉย ๆ มองไม่เห็นเลย
    # และเป็นเหตุผลหลักที่ต้องมี sandbox ตั้งแต่แรก
    if has_password:
        cross = [p for p in (bundle.get("network_posts") or []) if p.get("cross_origin")]
        if cross:
            targets = ", ".join(sorted({p.get("url", "") for p in cross})[:2])
            signals.append(_signal(
                "js_post_cross_origin", "สคริปต์ในหน้าส่งข้อมูลออกไปยังโดเมนอื่น",
                f"หน้านี้มีช่องกรอกรหัสผ่าน และสคริปต์ของหน้าส่งข้อมูลออกไปที่ {targets} "
                "ซึ่งเป็นคนละโดเมนกับหน้าเว็บ — ตรวจพบจากการรันหน้าเว็บจริง ไม่ใช่จาก"
                "การอ่านโค้ด จึงหลบด้วยการซ่อนโค้ดไม่ได้"))

    # หน้าที่ส่ง HTML เปล่ามาแล้วค่อยวาดด้วย JS ทั้งหมด: เจตนาอาจสุจริต (เว็บแอป)
    # หรือไม่สุจริตก็ได้ (หลบระบบตรวจที่อ่านแต่ HTML) จึงให้น้ำหนักแค่ระดับกลาง
    if bundle.get("js_rendered"):
        before, after = _words(bundle.get("raw_html") or ""), _words(bundle.get("html") or "")
        # เกณฑ์ขั้นต่ำตั้งไว้ต่ำโดยตั้งใจ เพราะภาษาไทยไม่มีช่องว่างคั่นคำ ทั้งประโยค
        # จึงนับเป็นคำเดียว หน้าไทยที่มีเนื้อหาพอสมควรอาจได้แค่ 10 กว่าคำเท่านั้น
        if len(after) >= 8:
            overlap = len(before & after) / len(before | after) if (before | after) else 1.0
            if overlap < 0.3:
                signals.append(_signal(
                    "dom_differs_from_source", "หน้าที่เห็นจริงไม่ตรงกับโค้ดที่ส่งมา",
                    "เนื้อหาที่แสดงจริงถูกสร้างขึ้นด้วยสคริปต์เกือบทั้งหมด ไม่ได้อยู่ใน"
                    "โค้ดที่เซิร์ฟเวอร์ส่งมา เว็บแอปสมัยใหม่ทำแบบนี้ได้ตามปกติ แต่ก็เป็น"
                    "วิธีมาตรฐานของหน้าหลอกที่ต้องการหลบระบบตรวจที่อ่านแต่โค้ดดิบ"))

    return signals


# ---------------------------------------------------------------------------
# กลุ่ม 4 — คุณภาพหน้าเว็บ (ตัวประกอบ ไม่ใช่หลักฐานเดี่ยว)
# ---------------------------------------------------------------------------
def _check_page_quality(soup, html: str, has_favicon: bool) -> list:
    signals = []

    if not has_favicon:
        signals.append(_signal(
            "no_favicon", "หน้านี้ไม่มีไอคอนประจำเว็บ",
            "เว็บที่ทำขึ้นจริงจัง ๆ มักตั้งไอคอนไว้ การไม่มีไอคอนพบบ่อยในหน้าที่ทำ"
            "ขึ้นแบบใช้แล้วทิ้ง (ข้อสังเกตเบา ๆ ไม่ได้แปลว่าอันตราย)"))

    links = [a for a in soup.find_all("a") if (a.get("href") or "").strip()
             not in ("", "#", "javascript:void(0)")]
    if not links:
        signals.append(_signal(
            "single_page_no_links", "หน้านี้ไม่มีลิงก์ไปหน้าอื่นเลย",
            "เว็บจริงมักมีลิงก์ไปหน้าอื่น (เกี่ยวกับเรา ติดต่อ นโยบาย) หน้าที่มีแต่"
            "ช่องให้กรอกข้อมูลอย่างเดียวเป็นรูปแบบที่พบบ่อยในหน้าหลอกเอาข้อมูล"))

    if len(html) < _TINY_HTML:
        signals.append(_signal(
            "html_too_small", "หน้าเว็บมีเนื้อหาน้อยผิดปกติ",
            f"ทั้งหน้ามีข้อมูลแค่ประมาณ {len(html)} ตัวอักษร ซึ่งน้อยกว่าหน้าเว็บทั่วไปมาก"))

    return signals


# ---------------------------------------------------------------------------
# ตัวหลัก
# ---------------------------------------------------------------------------
def analyze_page(bundle: dict, page_registrable: str) -> dict:
    """วิเคราะห์ page bundle เทียบกับโดเมนจริงของหน้านั้น คืน

        {"checked": bool, "signals": [...], "facts": [...]}

    checked=False แปลว่า "วิเคราะห์ไม่ได้" (ดึงหน้าเว็บไม่มา / ไม่มี bs4) ซึ่ง
    **ต่างจาก** checked=True + signals=[] ที่แปลว่า "ดูแล้วไม่พบสิ่งผิดปกติ"
    ตามหลักการของระบบ "เช็กไม่ได้" ต้องไม่ถูกนับเป็น "เสี่ยง" และต้องไม่ถูกนับเป็น
    "ปลอดภัย" ด้วย — หน้าเว็บจึงต้องแยกสองกรณีนี้ให้ผู้ใช้เห็น
    """
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return {"checked": False, "signals": [], "facts": []}

    if not bundle or not bundle.get("ok") or not page_registrable:
        return {"checked": False, "signals": [], "facts": []}

    html = bundle.get("html") or ""
    if not html:
        return {"checked": False, "signals": [], "facts": []}

    base_url = bundle.get("final_url") or ""
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return {"checked": False, "signals": [], "facts": []}

    signals = []
    harvest_signals, has_password = _check_credential_harvesting(
        soup, base_url, page_registrable)
    signals += harvest_signals
    signals += _check_brand_imitation(soup, html, base_url, page_registrable)

    has_favicon = _find_favicon_href(soup) is not None
    scripts = _inline_scripts(html)

    # _visible_text() ทำลาย soup (decompose script/style ทิ้ง) จึงต้องเรียกเป็นลำดับ
    # ท้ายสุดเสมอ — กฎอื่นที่ต้องอ่าน <script> ให้ใช้ scripts ที่ดึงไว้ข้างบนแทน
    quality_signals = _check_page_quality(soup, html, has_favicon)
    visible = _visible_text(soup)

    signals += _check_obfuscation(html, scripts, len(visible))
    signals += _check_sandbox_signals(bundle, has_password)
    signals += quality_signals

    facts = []
    if has_password:
        facts.append("has_password_input")
    if not bundle.get("js_rendered"):
        # บอกตรง ๆ ว่าผลนี้มาจากการอ่าน HTML ดิบ ยังไม่ได้รัน JavaScript
        facts.append("js_not_rendered")

    return {"checked": True, "signals": signals, "facts": facts}

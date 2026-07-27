# -*- coding: utf-8 -*-
"""
scanner.py
ตัวประสานงาน (orchestrator) ของระบบ cascade 4 ชั้น และตัวตัดสินผลเขียว/เหลือง/แดง

ลำดับการทำงาน:
  1) เรียก check_blacklist() (ชั้น 1 - ฐานข้อมูล สกมช.) กับลิงก์ต้นทาง
  2) parse_url() + analyze() (ชั้น 2 - วิเคราะห์สดจากรูปร่าง URL) กับลิงก์ต้นทาง
  3) resolve_destination() (ชั้น 3 - ตามปลายทางจริง/Redirect Resolution) แล้ว
     วิเคราะห์ซ้ำทั้งชั้น 1 และ 2 กับ URL ปลายทางที่แท้จริง (สำคัญมากสำหรับลิงก์ย่อ
     ที่ซ่อนปลายทางไว้) ผลที่เจอจากปลายทางจะถูกรวมเข้ากับสัญญาณของลิงก์ต้นทาง
  4) _run_layer4() (ชั้น 4 เสริม - domain_intel.py + content_checker.py) ยิงออก
     นอกเครือข่ายจริง 2 ทาง (RDAP หาอายุโดเมน + TLS handshake หา certificate,
     และ GET หน้าเว็บปลายทางมาหาฟอร์ม/favicon ที่ผิดปกติ) รันเฉพาะตอนที่ชั้น 1-3
     ยังชี้ขาดไม่ได้ เพราะช้ากว่าชั้นอื่นมากและไม่จำเป็นถ้ารู้ผลชัดเจนอยู่แล้ว
  5) decide() รวมผลทั้งหมดเป็นคำตัดสินสุดท้าย

กติกาตัดสิน (Analyst กำหนด):
  - เขียว (ปลอดภัย): ยืนยันว่าเป็นเว็บจริงเท่านั้น (ตรงลิสต์แบรนด์ หรือ API บอกปลอดภัย)
  - แดง (อันตราย): API บอกอันตราย / มีสัญญาณร้ายแรง / คะแนนรวมสูง
  - เหลือง (เสี่ยง): ที่เหลือทั้งหมด รวมถึง "ไม่พบสัญญาณ แต่ระบบไม่รู้จักเว็บนี้"
  จงใจไม่ปล่อยเขียวให้เว็บที่ไม่รู้จัก เพื่อกันการให้ความมั่นใจผิด ๆ
  (จงใจไม่ปล่อยเขียวจากผลของปลายทางเพียงอย่างเดียวด้วยเหตุผลเดียวกัน — ดู
  _merge_destination_analysis ด้านล่าง)
"""
import time
from concurrent.futures import ThreadPoolExecutor

from . import scan_cache
from .blacklist_api import check_blacklist
from .url_parser import parse_url
from .heuristics import analyze
from .destination_checker import resolve_destination
from .domain_intel import analyze_domain_intel
from .content_checker import analyze_content
from .config import RED_SCORE, YELLOW_SCORE, BRANDS, TLD_INFO, RISKY_TLDS, WEIGHTS


def _verdict(color, label, headline, message, source):
    return {"color": color, "label": label, "headline": headline,
            "message": message, "source": source}


def decide(api_result: dict, analysis: dict) -> dict:
    # ---- ชั้น 1: ผลจากฐานข้อมูล สกมช. มีน้ำหนักสูงสุด ----
    if api_result.get("found") and api_result.get("malicious"):
        return _verdict("red", "อันตราย", "พบในฐานข้อมูลของ สกมช.",
                        "ลิงก์นี้ถูกขึ้นบัญชีว่าเป็นเว็บอันตราย ห้ามกดเด็ดขาด", "blacklist")
    if api_result.get("found") and not api_result.get("malicious"):
        return _verdict("green", "ปลอดภัย", "ยืนยันโดยฐานข้อมูล สกมช.",
                        "ลิงก์นี้อยู่ในรายการที่ตรวจสอบแล้วว่าปลอดภัย", "blacklist")

    # ---- ชั้น 2: ผลจากการวิเคราะห์สด ----
    if analysis["verified_safe"]:
        brand = (analysis["legit_brand"] or "").upper()
        return _verdict("green", "ปลอดภัย", f"เป็นโดเมนทางการของ {brand}",
                        "โดเมนนี้ตรงกับเว็บทางการที่ตรวจสอบแล้ว", "realtime")

    has_critical = any(s["severity"] == "critical" for s in analysis["signals"])
    if has_critical or analysis["score"] >= RED_SCORE:
        return _verdict("red", "อันตราย", "พบสัญญาณของลิงก์หลอกลวง",
                        "อย่ากรอกข้อมูลส่วนตัวหรือรหัสผ่าน หากต้องการเข้าเว็บนี้ "
                        "ให้พิมพ์ชื่อเว็บเองหรือเข้าผ่านแอปทางการ", "realtime")

    if analysis["score"] >= YELLOW_SCORE:
        return _verdict("yellow", "เสี่ยง", "พบสัญญาณที่ควรระวังบางอย่าง",
                        "ยังไม่ฟันธงว่าหลอก แต่มีจุดน่าสงสัย ควรตรวจสอบให้แน่ใจก่อนกรอกข้อมูล",
                        "realtime")

    return _verdict("yellow", "เสี่ยง", "ระบบยังไม่รู้จักเว็บนี้",
                    "ไม่พบความผิดปกติจากตัวลิงก์ แต่ยังยืนยันไม่ได้ว่าปลอดภัย "
                    "หากต้องล็อกอินหรือโอนเงิน ให้เข้าผ่านช่องทางทางการแทน", "realtime")


def _tld_facts(tld: str) -> dict:
    """ข้อเท็จจริงของนามสกุลโดเมน: คำอธิบาย + ระดับความน่าไว้ใจ (สำหรับหน้าเว็บ)"""
    if not tld:
        return {"tld_note": "", "tld_risk": ""}
    if tld in RISKY_TLDS:
        return {"tld_note": f"นามสกุล .{tld} จดง่ายและราคาถูกมาก "
                            "เป็นกลุ่มที่มิจฉาชีพนิยมใช้ พบในเว็บหลอกบ่อย",
                "tld_risk": "warn"}
    note = TLD_INFO.get(tld)
    if note:
        # นามสกุลที่สงวนให้เฉพาะกลุ่ม (ราชการ/สถานศึกษา/ทหาร) ถือว่าน่าเชื่อถือ
        restricted = tld in ("go.th", "ac.th", "mi.th", "gov.uk")
        return {"tld_note": note, "tld_risk": "ok" if restricted else ""}
    return {"tld_note": f"นามสกุล .{tld} ไม่อยู่ในรายการที่ระบบรู้จัก "
                        "ควรตรวจสอบความน่าเชื่อถือเพิ่มเติม",
            "tld_risk": ""}


def build_anatomy(parsed: dict) -> dict:
    """ข้อมูลสำหรับวาดแผนภาพแยกส่วนของลิงก์ในหน้าเว็บ"""
    if not parsed.get("valid"):
        return {}
    anatomy = {
        "protocol": parsed.get("protocol", ""),
        "protocol_known": parsed.get("protocol_known", False),
        "subdomain": parsed.get("subdomain", ""),
        "registrable": parsed.get("registrable", ""),
        "tld": parsed.get("tld", ""),
        "path": parsed.get("path", ""),
        "is_ip": parsed.get("is_ip", False),
    }
    anatomy.update(_tld_facts(anatomy["tld"]))
    return anatomy


def build_reference(analysis: dict):
    """ถ้าตรวจพบการเลียนแบบแบรนด์ -> คืนโดเมนทางการที่ถูกต้องของแบรนด์นั้นมาแสดงเทียบ"""
    if analysis.get("verified_safe"):
        label = analysis.get("legit_brand")
    else:
        label = next((s.get("brand") for s in analysis.get("signals", [])
                      if s.get("brand")), None)
    if not label:
        return None
    for b in BRANDS:
        if b["label"] == label:
            return {"brand": label.upper(), "official_domains": b["domains"],
                    "impersonated": not analysis.get("verified_safe")}
    return None


def _destination_signals(destination: dict) -> list:
    """สัญญาณที่เกิดจากตัวการ redirect เอง (ไม่ใช่จากการวิเคราะห์ปลายทางซ้ำ)
    ตอนนี้มีกรณีเดียว: ปลายทางชี้ไปยัง IP ภายในเครือข่าย ซึ่งเว็บทั่วไปไม่ทำแบบนี้
    และเป็นสัญญาณของการโจมตีแบบ SSRF/พยายามหลบระบบตรวจ ถือว่าอันตรายชัดเจน"""
    if not destination.get("blocked"):
        return []
    points, severity = WEIGHTS["internal_redirect"]
    return [{
        "id": "internal_redirect",
        "title": "ลิงก์ redirect ไปยังที่อยู่ผิดปกติ",
        "detail": destination.get("blocked_reason", "ปลายทางชี้ไปยัง IP ที่สงวนไว้"),
        "points": points, "severity": severity,
    }]


def _merge_destination_analysis(final_analysis: dict) -> list:
    """เอาสัญญาณเสี่ยงที่เจอจากการวิเคราะห์ "ปลายทางจริง" (หลัง redirect) มารวมกับ
    สัญญาณของลิงก์ต้นทาง ไม่ดึงสัญญาณ verified_brand มาด้วย เพื่อไม่ให้ลิงก์ที่ redirect
    ผ่านโดเมนที่ไม่เกี่ยวข้องได้เขียวไปฟรี ๆ เพียงเพราะปลายทางบังเอิญตรงกับแบรนด์ใดแบรนด์หนึ่ง"""
    merged = []
    for s in final_analysis["signals"]:
        if s["id"] == "verified_brand":
            continue
        tagged = dict(s)
        tagged["detail"] = f'{s["detail"]} (พบที่ปลายทางจริงหลัง redirect ไม่ใช่จากลิงก์ที่วาง)'
        merged.append(tagged)
    return merged


def build_destination_view(destination: dict) -> dict:
    """ข้อมูลสำหรับแสดงเส้นทาง redirect ในหน้าเว็บ (โปร่งใส ไม่ใช่กล่องดำ)"""
    return {
        "redirected": destination.get("hops", 0) >= 1,
        "hops": destination.get("hops", 0),
        "chain": destination.get("chain", []),
        "final_url": destination.get("final_url", ""),
        "blocked": destination.get("blocked", False),
        "blocked_reason": destination.get("blocked_reason", ""),
        "error": destination.get("error", ""),
    }


def _ensure_scheme(parsed: dict) -> str:
    """คืน URL ที่มี scheme เสมอ (parse_url เก็บ "raw" ตามที่ผู้ใช้พิมพ์ ซึ่งอาจไม่มี
    http/https นำหน้าถ้าผู้ใช้พิมพ์แบบย่อ) ใช้สำหรับยิง request จริงในชั้นที่ 4"""
    raw = parsed.get("raw", "")
    return raw if parsed.get("protocol_known") else "http://" + raw


def _run_layer4(effective_parsed: dict):
    """ชั้นที่ 4 (เสริม): อายุโดเมน + SSL certificate + เนื้อหาหน้าเว็บจริง
    ทั้งสามงานเป็น I/O ที่ไม่เกี่ยวข้องกัน (RDAP, TLS handshake, HTTP GET) จึงรันพร้อม
    กันด้วย thread เพื่อไม่ให้ latency รวมเป็นผลรวมของทั้งสามอย่าง
    คืน (signals, diagnostics) — diagnostics เก็บผลดิบไว้ให้หน้าเว็บแสดงผลได้
    แม้ตอนที่ไม่มีสัญญาณเสี่ยงเลย (โปร่งใสว่า "เช็กแล้ว" ไม่ใช่แค่เงียบไป)"""
    reg = effective_parsed.get("registrable", "")
    host = effective_parsed.get("host", "")
    is_ip = effective_parsed.get("is_ip", False)
    url = _ensure_scheme(effective_parsed)

    empty_domain_result = {"signals": [], "domain_age": {"checked": False},
                            "ssl": {"checked": False}}
    with ThreadPoolExecutor(max_workers=2) as pool:
        domain_fut = None if is_ip else pool.submit(analyze_domain_intel, reg, host)
        content_fut = pool.submit(analyze_content, url, reg)
        content_result = content_fut.result()
        domain_result = domain_fut.result() if domain_fut is not None else empty_domain_result

    signals = domain_result["signals"] + content_result["signals"]
    diagnostics = {
        "ran": True,
        "domain_age": domain_result["domain_age"],
        "ssl": domain_result["ssl"],
        "content_checked": content_result["checked"],
    }
    return signals, diagnostics


def scan(url: str, run_deep: bool = True) -> dict:
    """ฟังก์ชันหลักที่ route /api/check เรียกใช้ คืนผลลัพธ์ครบสำหรับแสดงผล

    run_deep=False ข้ามชั้นที่ 3 (ตาม redirect) และชั้นที่ 4 (อายุโดเมน/SSL/เนื้อหาเว็บ)
    ทั้งคู่ เพราะเป็นชั้นที่ยิง request ออกนอกเครือข่ายจริงและกินทรัพยากรเซิร์ฟเวอร์มาก
    ใช้สำหรับผู้ใช้ที่ไม่ได้ล็อกอินหรือใช้โควตาฟรีหมดแล้ว (ยังได้ผลชั้น 1-2 ครบถ้วน)

    ผลลัพธ์ถูก cache ไว้ระยะสั้น (ดู scan_cache.py) ลิงก์เดียวกันที่ถูกตรวจซ้ำภายใน TTL
    จะได้ผลเดิมทันทีโดยไม่ยิงเน็ตใหม่ ผลที่มาจากแคชจะมี "cached": True ติดมาด้วย"""
    cached = scan_cache.get(url, run_deep)
    if cached is not None:
        return cached
    result = _scan_uncached(url, run_deep)
    scan_cache.put(url, run_deep, result)
    return result


def _scan_uncached(url: str, run_deep: bool = True) -> dict:
    """ตัวตรวจจริง — ไม่ผ่านแคช (แยกไว้เพื่อให้เทสต์/บังคับตรวจใหม่เรียกตรงได้)"""
    started = time.perf_counter()

    parsed = parse_url(url)
    if not parsed.get("valid"):
        return {"ok": False, "error": "อ่านลิงก์ไม่ได้ กรุณาตรวจรูปแบบลิงก์",
                "input": url}

    api_result = check_blacklist(url)      # ชั้น 1 (ลิงก์ต้นทาง)
    analysis = analyze(parsed)             # ชั้น 2 (ลิงก์ต้นทาง)

    extra_signals = []
    destination = {"resolved": False, "chain": [url], "final_url": url, "hops": 0}
    layer4 = {"ran": False, "domain_age": {"checked": False},
              "ssl": {"checked": False}, "content_checked": False}

    if run_deep:
        destination = resolve_destination(url)  # ชั้น 3 (ปลายทางจริง)
        extra_signals += _destination_signals(destination)

        final_url = destination.get("final_url")
        effective_parsed = parsed  # โดเมนที่จะใช้เป็น "ปลายทางจริง" สำหรับชั้นที่ 4
        if destination.get("hops", 0) >= 1 and final_url and not destination.get("blocked"):
            final_parsed = parse_url(final_url)
            if final_parsed.get("valid") and final_parsed.get("registrable") != parsed.get("registrable"):
                effective_parsed = final_parsed
                final_api = check_blacklist(final_url)
                final_analysis = analyze(final_parsed)
                if final_api.get("found") and final_api.get("malicious"):
                    api_result = final_api  # ปลายทางจริงอยู่ในบัญชีดำ -> ใช้ผลนี้แทน (สำคัญกว่า)
                extra_signals += _merge_destination_analysis(final_analysis)

        # ---- ชั้นที่ 4 (เสริม) ----
        # รันเฉพาะตอนที่ชั้น 1-3 ยังชี้ขาดไม่ได้ (ไม่ใช่ทั้งฟันธงแดงจากบัญชีดำ และไม่ใช่
        # เขียวที่ยืนยันจากโดเมนแบรนด์จริงของต้นทางอยู่แล้ว) เพื่อประหยัดเวลา เพราะชั้นนี้
        # ต้องออกนอกเครือข่ายหลายรอบ (RDAP, TLS handshake, ดึงหน้าเว็บ) ซึ่งช้ากว่าชั้น
        # ก่อนหน้ามาก และไม่จำเป็นถ้ารู้ผลชัดเจนแล้ว
        already_decided = (api_result.get("found") and api_result.get("malicious")) or analysis.get("verified_safe")
        if not already_decided and not destination.get("blocked") and effective_parsed.get("valid"):
            layer4_signals, layer4 = _run_layer4(effective_parsed)
            extra_signals += layer4_signals

    if extra_signals:
        analysis = {**analysis,
                    "signals": extra_signals + analysis["signals"],
                    "score": analysis["score"] + sum(s["points"] for s in extra_signals)}

    verdict = decide(api_result, analysis)
    elapsed_ms = max(1, round((time.perf_counter() - started) * 1000))

    return {
        "ok": True,
        "input": url,
        "verdict": verdict,                       # {color,label,headline,message,source}
        "anatomy": build_anatomy(parsed),         # ส่วนประกอบลิงก์
        "destination": build_destination_view(destination),  # เส้นทาง redirect (ชั้น 3)
        "layer4": layer4,                          # อายุโดเมน/SSL/เนื้อหาเว็บ (ชั้น 4 เสริม)
        "reference": build_reference(analysis),   # โดเมนทางการของแบรนด์ (ถ้าเกี่ยวข้อง)
        "reasons": analysis["signals"],           # รายการสัญญาณ + คำอธิบาย
        "score": analysis["score"],               # คะแนนรวม (ไว้ในรายละเอียดทางเทคนิค)
        "elapsed_ms": elapsed_ms,                  # เวลาที่ใช้ตรวจ (ไว้ทำส่วนวัดความเร็ว)
        "api_checked": api_result.get("found", False),
        "deep_check": {"ran": run_deep},
    }

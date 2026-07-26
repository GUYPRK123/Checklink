# -*- coding: utf-8 -*-
"""
qr_payload.py
จำแนก "เนื้อหาที่อยู่ใน QR Code" ว่าเป็นอะไร แล้วบอกความเสี่ยงตามชนิดนั้น

ทำไมต้องมีไฟล์นี้: QR Code ไม่ได้มีแต่ลิงก์เว็บ ของที่เจอบ่อยและอันตรายไม่แพ้กันคือ
QR พร้อมเพย์ (โอนเงิน), QR Wi-Fi (พาไปต่อเน็ตของคนอื่น), QR เบอร์โทร/SMS เดิมระบบ
ตอบแค่ "ไม่ใช่ลิงก์ ตรวจไม่ได้" ซึ่งเป็นทางตัน ทั้งที่ QR พร้อมเพย์ปลอม (สติกเกอร์แปะทับ
ของจริงตามร้าน) เป็นภัยที่เกิดจริงในไทย

จุดสำคัญทางเทคนิค: QR พร้อมเพย์ใช้มาตรฐาน EMVCo Merchant QR ซึ่งเป็นข้อมูลแบบ
TLV (Tag-Length-Value) และมี checksum CRC-16 อยู่ท้ายสุด เราจึง "ตรวจสอบความ
ถูกต้องของ QR ได้โดยไม่ต้องต่อเน็ต" — ถ้า CRC ไม่ตรง แปลว่า QR ถูกแก้ไข/เสียหาย

ทุกฟังก์ชันในไฟล์นี้เป็น pure function (ไม่ยิงเน็ต ไม่แตะฐานข้อมูล) จึงเทสต์ง่าย
"""
import re

# AID (Application Identifier) ของพร้อมเพย์ตามที่ธนาคารแห่งประเทศไทยกำหนด
_PROMPTPAY_AIDS = {
    "A000000677010111": "พร้อมเพย์ (โอนเงินระหว่างบุคคล)",
    "A000000677010112": "พร้อมเพย์ (Bill Payment)",
    "A000000677010113": "พร้อมเพย์ (Bill Payment ข้ามธนาคาร)",
    "A000000677012006": "พร้อมเพย์ (True Money / e-Wallet)",
}

# ชนิดของ QR ที่ระบบรู้จัก -> (ชื่อที่คนอ่านเข้าใจ, คำอธิบายว่ามันทำอะไรตอนสแกนด้วยแอปทั่วไป)
_TYPE_INFO = {
    "url": ("ลิงก์เว็บไซต์", "เปิดหน้าเว็บในเบราว์เซอร์"),
    "promptpay": ("QR ชำระเงิน / พร้อมเพย์", "เปิดแอปธนาคารเพื่อโอนเงินให้ผู้รับที่ระบุใน QR"),
    "emv_unknown": ("QR ชำระเงิน (มาตรฐาน EMVCo)", "เปิดแอปธนาคาร/แอปจ่ายเงินเพื่อโอนเงิน"),
    "wifi": ("การตั้งค่า Wi-Fi", "ให้เครื่องเชื่อมต่อ Wi-Fi ตามชื่อและรหัสผ่านที่อยู่ใน QR"),
    "tel": ("เบอร์โทรศัพท์", "เปิดแอปโทรออกพร้อมเบอร์ที่ระบุ"),
    "sms": ("ข้อความ SMS", "เปิดแอปข้อความพร้อมเบอร์ปลายทางและข้อความที่เตรียมไว้"),
    "email": ("อีเมล", "เปิดแอปอีเมลพร้อมผู้รับและเนื้อหาที่เตรียมไว้"),
    "vcard": ("นามบัตร (รายชื่อผู้ติดต่อ)", "เสนอให้บันทึกรายชื่อผู้ติดต่อลงเครื่อง"),
    "geo": ("พิกัดแผนที่", "เปิดแอปแผนที่ไปยังพิกัดที่ระบุ"),
    "text": ("ข้อความธรรมดา", "แสดงข้อความเฉย ๆ ไม่เปิดแอปอื่น"),
}


# ---------------------------------------------------------------- CRC-16
def crc16_ccitt(data: bytes) -> int:
    """CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF) ตามที่ EMVCo QR กำหนดไว้ใน tag 63"""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


# ---------------------------------------------------------------- TLV
def parse_tlv(payload: str) -> dict:
    """แตกข้อมูลรูปแบบ TLV ของ EMVCo: ต่อกันเป็นชุด ๆ ละ [tag 2 ตัว][ความยาว 2 ตัว][ค่า]
    คืน dict {tag: value} — ถ้ารูปแบบพังกลางทางจะคืนเท่าที่อ่านได้ (ไม่ throw)"""
    out, i, n = {}, 0, len(payload)
    while i + 4 <= n:
        tag, length_raw = payload[i:i + 2], payload[i + 2:i + 4]
        if not tag.isdigit() or not length_raw.isdigit():
            break
        length = int(length_raw)
        value = payload[i + 4:i + 4 + length]
        if len(value) < length:
            break  # ความยาวบอกไว้เกินกว่าข้อมูลที่มีจริง -> ข้อมูลไม่ครบ
        out[tag] = value
        i += 4 + length
    return out


def _mask_tail(value: str, keep: int = 4) -> str:
    """ปิดบังเลขบัญชี/เบอร์ เหลือให้เห็นแค่ท้าย 4 ตัว พอให้ผู้ใช้ยืนยันกับผู้รับได้
    แต่ไม่เปิดเผยเลขเต็ม (แนวเดียวกับที่แอปธนาคารแสดง)"""
    digits = re.sub(r"\D", "", value)
    if len(digits) <= keep:
        return digits
    return "x" * (len(digits) - keep) + digits[-keep:]


def _promptpay_target(mai: dict) -> dict:
    """อ่านข้อมูลผู้รับเงินจาก Merchant Account Information (sub-tag 01/02/03)"""
    if mai.get("01"):
        return {"kind": "เบอร์พร้อมเพย์", "masked": _mask_tail(mai["01"])}
    if mai.get("02"):
        return {"kind": "เลขบัตรประชาชน/เลขผู้เสียภาษี", "masked": _mask_tail(mai["02"])}
    if mai.get("03"):
        return {"kind": "บัญชี e-Wallet", "masked": _mask_tail(mai["03"])}
    return {"kind": "", "masked": ""}


def _analyze_emv(payload: str) -> dict:
    """ถอด QR ชำระเงินมาตรฐาน EMVCo (พร้อมเพย์ใช้มาตรฐานนี้)
    คืนทั้งข้อมูลพื้นฐาน (ใครก็ดูได้) และ details (เฉพาะพรีเมียม — ผู้เรียกเป็นคนกรอง)"""
    root = parse_tlv(payload)
    warnings, facts = [], []

    # ---- ตรวจ CRC: จุดแข็งของ QR ชำระเงิน คือแก้ข้อมูลแล้ว checksum จะไม่ตรงทันที ----
    crc_ok = None
    idx = payload.rfind("6304")
    if idx != -1 and len(payload) >= idx + 8:
        expected = crc16_ccitt(payload[:idx + 4].encode("ascii", "ignore"))
        crc_ok = f"{expected:04X}" == payload[idx + 4:idx + 8].upper()
    if crc_ok is False:
        warnings.append({
            "severity": "critical",
            "title": "ค่าตรวจสอบความถูกต้อง (CRC) ของ QR ไม่ตรง",
            "detail": "QR ชำระเงินมาตรฐานจะมีเลขตรวจสอบท้ายสุดเสมอ การที่เลขนี้ไม่ตรงแปลว่า "
                      "ข้อมูลใน QR ถูกแก้ไขหรือเสียหาย ห้ามใช้ QR นี้โอนเงิน",
        })
    elif crc_ok:
        facts.append({"label": "เลขตรวจสอบความถูกต้อง (CRC)", "value": "ตรงกัน — ข้อมูลใน QR ไม่ถูกแก้ไข", "state": "ok"})

    # ---- หา Merchant Account Information (tag 26-51) เพื่อดูว่าเป็นพร้อมเพย์ไหม ----
    aid, mai, qr_type = "", {}, "emv_unknown"
    for tag in (f"{t:02d}" for t in range(26, 52)):
        if tag not in root:
            continue
        sub = parse_tlv(root[tag])
        if sub.get("00", "").upper() in _PROMPTPAY_AIDS:
            aid, mai, qr_type = sub["00"].upper(), sub, "promptpay"
            break
        if not aid:
            aid, mai = sub.get("00", ""), sub

    if qr_type == "promptpay":
        facts.append({"label": "ประเภทบริการ", "value": _PROMPTPAY_AIDS[aid], "state": "ok"})

    # ---- static (สติกเกอร์ใช้ซ้ำได้) vs dynamic (สร้างครั้งเดียวจบ) ----
    # นี่คือจุดที่มิจฉาชีพโจมตี: QR แบบ static คือสติกเกอร์ที่แปะไว้ตามร้าน ถูกแปะทับได้ง่าย
    method = root.get("01", "")
    is_static = method != "12"
    facts.append({
        "label": "รูปแบบ QR",
        "value": "แบบใช้ซ้ำได้ (สติกเกอร์/ป้ายตั้งโต๊ะ)" if is_static else "แบบใช้ครั้งเดียว (สร้างสดจากแอป)",
        "state": "warn" if is_static else "ok",
    })

    amount = root.get("54", "")
    currency = root.get("53", "")
    country = root.get("58", "").upper()

    if is_static and not amount:
        # ตั้งใจให้เป็นระดับ "ควรระวัง" ไม่ใช่ "อันตราย" เพราะ QR สติกเกอร์ของร้านค้าที่ถูกต้อง
        # เกือบทั้งหมดก็เป็นแบบนี้ ถ้าตีเป็นอันตรายทุกใบ ผู้ใช้จะเลิกสนใจคำเตือนไปเลย
        warnings.append({
            "severity": "medium",
            "title": "เป็น QR แบบใช้ซ้ำได้ และไม่ได้ระบุจำนวนเงิน",
            "detail": "QR ประเภทนี้คือสติกเกอร์/ป้ายที่วางไว้หน้าร้าน ซึ่งมิจฉาชีพนิยมพิมพ์ QR ของตัวเอง "
                      "มาแปะทับของจริง ก่อนกดยืนยันให้ดูที่หน้าจอแอปธนาคารว่า \"ชื่อผู้รับเงิน\" "
                      "ตรงกับร้าน/คนที่คุณตั้งใจจะโอนให้จริงหรือไม่",
        })
    if currency and currency != "764":
        warnings.append({
            "severity": "high",
            "title": f"สกุลเงินไม่ใช่เงินบาท (รหัส {currency})",
            "detail": "QR ที่ใช้ในไทยตามปกติจะเป็นสกุลเงินบาท (รหัส 764) การเป็นสกุลอื่นถือว่าผิดปกติ",
        })
    if country and country != "TH":
        warnings.append({
            "severity": "medium",
            "title": f"QR ระบุประเทศเป็น {country} ไม่ใช่ไทย",
            "detail": "ถ้าคุณกำลังจะจ่ายเงินให้ร้านค้าในประเทศไทย ค่านี้ควรเป็น TH",
        })

    # ---- รายละเอียดเชิงลึก (พรีเมียม) ----
    target = _promptpay_target(mai) if mai else {"kind": "", "masked": ""}
    details = []
    if root.get("59"):
        details.append({"label": "ชื่อผู้รับเงินที่ระบุใน QR", "value": root["59"], "state": ""})
    if root.get("60"):
        details.append({"label": "เมือง/จังหวัดของผู้รับ", "value": root["60"], "state": ""})
    if target["masked"]:
        details.append({"label": target["kind"], "value": target["masked"], "state": ""})
    if amount:
        details.append({"label": "จำนวนเงินที่ระบุใน QR", "value": f"{amount} บาท", "state": "warn"})
    else:
        details.append({"label": "จำนวนเงินที่ระบุใน QR", "value": "ไม่ได้ระบุ (ผู้โอนกรอกเอง)", "state": ""})
    extra = parse_tlv(root.get("62", ""))
    if extra.get("01"):
        details.append({"label": "เลขที่ใบแจ้งหนี้", "value": extra["01"], "state": ""})
    if extra.get("07"):
        details.append({"label": "เลขอ้างอิง", "value": extra["07"], "state": ""})

    return {"type": qr_type, "facts": facts, "warnings": warnings, "details": details,
            "crc_ok": crc_ok}


# ---------------------------------------------------------------- ชนิดอื่น ๆ
def _parse_wifi(payload: str) -> dict:
    """WIFI:T:WPA;S:ชื่อเครือข่าย;P:รหัสผ่าน;H:false;;"""
    body = payload[5:]
    fields = {}
    for part in re.split(r"(?<!\\);", body):
        if ":" in part:
            k, _, v = part.partition(":")
            fields[k.upper()] = v.replace("\\;", ";").replace("\\:", ":")

    ssid, auth = fields.get("S", ""), (fields.get("T", "") or "nopass").upper()
    facts = [{"label": "ชื่อเครือข่าย (SSID)", "value": ssid or "(ไม่ระบุ)", "state": ""}]
    warnings = [{
        "severity": "medium",
        "title": "QR นี้จะพาเครื่องคุณไปต่อ Wi-Fi ของคนอื่น",
        "detail": "เจ้าของ Wi-Fi มองเห็นและเปลี่ยนเส้นทางการใช้เน็ตของคุณได้ "
                  "อย่าเข้าแอปธนาคารหรือกรอกรหัสผ่านขณะต่อ Wi-Fi ที่ไม่รู้จัก",
    }]
    if auth in ("NOPASS", ""):
        facts.append({"label": "การเข้ารหัส", "value": "ไม่มีรหัสผ่าน (เครือข่ายเปิด)", "state": "bad"})
        warnings.append({
            "severity": "medium",
            "title": "เป็นเครือข่ายเปิดที่ไม่มีการเข้ารหัส",
            "detail": "ข้อมูลที่รับส่งบนเครือข่ายแบบนี้ถูกดักอ่านได้ง่ายกว่าปกติมาก",
        })
    else:
        facts.append({"label": "การเข้ารหัส", "value": auth, "state": "ok"})
    return {"type": "wifi", "facts": facts, "warnings": warnings, "details": []}


def _parse_tel(payload: str) -> dict:
    number = payload.split(":", 1)[1].strip()
    return {
        "type": "tel",
        "facts": [{"label": "เบอร์ปลายทาง", "value": number, "state": ""}],
        "warnings": [{
            "severity": "medium",
            "title": "QR นี้ให้คุณโทรออกไปยังเบอร์ที่กำหนดไว้",
            "detail": "ถ้าเป็นเบอร์ที่มากับข้อความ/ใบปลิวที่อ้างว่าเป็นธนาคารหรือหน่วยงานรัฐ "
                      "ให้หาเบอร์ทางการจากเว็บไซต์หรือแอปทางการเองแทน อย่าโทรตามเบอร์ในสื่อที่ได้รับมา",
        }],
        "details": [],
    }


def _parse_sms(payload: str) -> dict:
    rest = payload.split(":", 1)[1]
    number, _, message = rest.partition(":")
    facts = [{"label": "เบอร์ปลายทาง", "value": number.strip(), "state": ""}]
    if message:
        facts.append({"label": "ข้อความที่ถูกเตรียมไว้ให้ส่ง", "value": message.strip(), "state": "warn"})
    return {
        "type": "sms",
        "facts": facts,
        "warnings": [{
            "severity": "medium",
            "title": "QR นี้เตรียมข้อความ SMS ไว้ให้คุณกดส่ง",
            "detail": "การส่ง SMS ไปเบอร์ที่ไม่รู้จักอาจถูกคิดค่าบริการพิเศษ หรือเป็นการยืนยันกับ "
                      "มิจฉาชีพว่าเบอร์คุณใช้งานอยู่จริง",
        }],
        "details": [],
    }


def _parse_email(payload: str) -> dict:
    addr = payload.split(":", 1)[1].split("?")[0].strip()
    return {
        "type": "email",
        "facts": [{"label": "อีเมลปลายทาง", "value": addr, "state": ""}],
        "warnings": [{
            "severity": "low",
            "title": "QR นี้เปิดแอปอีเมลพร้อมผู้รับที่กำหนดไว้",
            "detail": "ระวังการส่งข้อมูลส่วนตัวหรือเอกสารไปยังอีเมลที่ไม่ได้ตรวจสอบที่มา",
        }],
        "details": [],
    }


def _parse_vcard(payload: str) -> dict:
    name = ""
    m = re.search(r"^FN:(.+)$", payload, re.MULTILINE)
    if m:
        name = m.group(1).strip()
    return {
        "type": "vcard",
        "facts": [{"label": "ชื่อในนามบัตร", "value": name or "(ไม่ระบุ)", "state": ""}],
        "warnings": [{
            "severity": "low",
            "title": "QR นี้เสนอให้บันทึกรายชื่อผู้ติดต่อลงเครื่อง",
            "detail": "ชื่อที่แสดงตั้งเป็นอะไรก็ได้ การบันทึกไว้ไม่ได้ยืนยันว่าเป็นบุคคลนั้นจริง",
        }],
        "details": [],
    }


def _parse_geo(payload: str) -> dict:
    return {
        "type": "geo",
        "facts": [{"label": "พิกัด", "value": payload.split(":", 1)[1].strip(), "state": ""}],
        "warnings": [],
        "details": [],
    }


# ---------------------------------------------------------------- ทางเข้าหลัก
_URL_RE = re.compile(r"^[\w.-]+\.[a-z]{2,}([/?#]|$)", re.I)


def looks_like_url(text: str) -> bool:
    """ตัดสินว่าเนื้อหาใน QR ควรถูกส่งไปตรวจด้วยระบบตรวจลิงก์ 4 ชั้นหรือไม่
    (ให้ตรงกับ looksLikeUrl ฝั่งหน้าเว็บ เพื่อไม่ให้ผลลัพธ์สองฝั่งขัดกัน)"""
    t = text.strip()
    if re.match(r"^https?://", t, re.I):
        return True
    return bool(_URL_RE.match(t)) and not re.search(r"\s", t)


def classify(payload: str) -> dict:
    """จำแนกเนื้อหาใน QR แล้วคืนโครงเดียวกันเสมอ:
      {
        type, type_label, action,   ชนิด + ชื่อที่คนอ่านเข้าใจ + กดแล้วเกิดอะไร
        facts:    [...]             ข้อเท็จจริงพื้นฐาน (แสดงให้ทุกคนเห็น)
        warnings: [...]             คำเตือนตามชนิดของ QR (แสดงให้ทุกคนเห็น)
        details:  [...]             รายละเอียดเชิงลึก (ผู้เรียกเป็นคนตัดสินใจว่าจะโชว์ไหม)
      }
    """
    text = (payload or "").strip()
    if not text:
        return {"type": "text", "type_label": "(ว่าง)", "action": "", "facts": [],
                "warnings": [], "details": []}

    upper = text.upper()
    if looks_like_url(text):
        result = {"type": "url", "facts": [], "warnings": [], "details": []}
    elif upper.startswith("00020101") or upper.startswith("000201"):
        result = _analyze_emv(text)
    elif upper.startswith("WIFI:"):
        result = _parse_wifi(text)
    elif upper.startswith("TEL:"):
        result = _parse_tel(text)
    elif upper.startswith("SMSTO:") or upper.startswith("SMS:"):
        result = _parse_sms(text)
    elif upper.startswith("MAILTO:"):
        result = _parse_email(text)
    elif upper.startswith("BEGIN:VCARD") or upper.startswith("MECARD:"):
        result = _parse_vcard(text)
    elif upper.startswith("GEO:"):
        result = _parse_geo(text)
    else:
        result = {
            "type": "text",
            "facts": [{"label": "เนื้อหา", "value": text[:200], "state": ""}],
            "warnings": [],
            "details": [],
        }

    label, action = _TYPE_INFO.get(result["type"], _TYPE_INFO["text"])
    result["type_label"] = label
    result["action"] = action
    return result

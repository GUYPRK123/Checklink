# -*- coding: utf-8 -*-
"""
test_qr_payload.py — เทสต์การจำแนกเนื้อหาใน QR

ส่วนที่สำคัญที่สุดคือ QR พร้อมเพย์: ระบบอ้างกับผู้ใช้ว่า "ตรวจได้ว่า QR ถูกแก้ไขไหม"
โดยดูจาก CRC ถ้าตรรกะตรงนี้ผิด = โกหกผู้ใช้เรื่องเงิน จึงเทสต์ทั้งกรณี QR ปกติและ
กรณีถูกแก้ไข (จำลองการแปะสติกเกอร์ทับ/แก้เลขบัญชีปลายทาง)
"""
from analyzer.qr_payload import (crc16_ccitt, parse_tlv, classify, looks_like_url)

# QR พร้อมเพย์ที่ถูกต้อง (โอนเข้าเบอร์ 0066812345678, สกุลบาท, ประเทศ TH, CRC ถูกต้อง)
# ประกอบขึ้นตามมาตรฐาน EMVCo แล้วคำนวณ CRC ต่อท้าย — ไม่ใช่ QR ของคนจริง
PROMPTPAY_OK = ("00020101021129370016A00000067701011101130066812345678"
                "53037645802TH6304823E")


class TestCRC16:
    def test_ตรงกับค่ามาตรฐาน(self):
        """"123456789" -> 0x29B1 คือ check value ที่มาตรฐาน CRC-16/CCITT-FALSE กำหนดไว้
        ถ้าเทสต์นี้ผ่าน แปลว่าเราคำนวณ CRC แบบเดียวกับที่ธนาคารใช้จริง"""
        assert crc16_ccitt(b"123456789") == 0x29B1

    def test_ข้อมูลว่าง(self):
        assert crc16_ccitt(b"") == 0xFFFF

    def test_เปลี่ยนข้อมูลนิดเดียวค่าต้องเปลี่ยน(self):
        assert crc16_ccitt(b"00020101") != crc16_ccitt(b"00020102")


class TestParseTLV:
    def test_อ่านชุดปกติ(self):
        assert parse_tlv("000201010211") == {"00": "01", "01": "11"}

    def test_ค่าที่ยาวเกินสิบตัว(self):
        assert parse_tlv("0016A000000677010111") == {"00": "A000000677010111"}

    def test_ความยาวบอกเกินกว่าข้อมูลจริงต้องไม่พัง(self):
        """ข้อมูลไม่ครบต้องคืนเท่าที่อ่านได้ ไม่ throw (QR เสียหาย/ถูกตัดกลางคัน)"""
        assert parse_tlv("000201019999") == {"00": "01"}

    def test_ข้อมูลที่ไม่ใช่ตัวเลขต้องหยุดอ่าน(self):
        assert parse_tlv("000201ABCD") == {"00": "01"}

    def test_ค่าว่าง(self):
        assert parse_tlv("") == {}


class TestQRพร้อมเพย์:
    def test_จำแนกเป็นพร้อมเพย์และCRCตรง(self):
        r = classify(PROMPTPAY_OK)
        assert r["type"] == "promptpay"
        assert r["crc_ok"] is True
        assert r["type_label"].startswith("QR ชำระเงิน")

    def test_CRCตรงต้องไม่มีคำเตือนระดับcritical(self):
        r = classify(PROMPTPAY_OK)
        assert "critical" not in {w["severity"] for w in r["warnings"]}

    def test_QRถูกแก้ไขต้องขึ้นcritical(self):
        """เปลี่ยนเลขบัญชีปลายทางโดยไม่แก้ CRC = สิ่งที่เกิดเมื่อมิจฉาชีพแก้ QR
        ต้องถูกจับได้แบบออฟไลน์ ไม่ต้องต่อเน็ต"""
        tampered = PROMPTPAY_OK.replace("0066812345678", "0066899999999")
        r = classify(tampered)
        assert r["crc_ok"] is False
        assert "critical" in {w["severity"] for w in r["warnings"]}

    def test_เลขบัญชีถูกปิดบังเหลือท้ายสี่ตัว(self):
        """details ต้องไม่เปิดเผยเลขเต็ม แม้กับสมาชิกพรีเมียม"""
        details = classify(PROMPTPAY_OK)["details"]
        target = [d for d in details if "พร้อมเพย์" in d["label"]]
        assert target and target[0]["value"] == "xxxxxxxxx5678"

    def test_QRแบบใช้ซ้ำที่ไม่ระบุจำนวนเงินต้องเตือนระดับmedium(self):
        """สติกเกอร์หน้าร้าน = จุดที่ถูกแปะทับได้ แต่ต้องไม่ตีเป็น "อันตราย"
        เพราะของถูกกฎหมายเกือบทั้งหมดก็เป็นแบบนี้"""
        warnings = classify(PROMPTPAY_OK)["warnings"]
        assert any(w["severity"] == "medium" and "ใช้ซ้ำ" in w["title"] for w in warnings)


class TestQRชนิดอื่น:
    def test_wifiแบบมีรหัสผ่าน(self):
        r = classify("WIFI:T:WPA;S:CoffeeShop;P:secret123;;")
        assert r["type"] == "wifi"
        assert any(f["value"] == "CoffeeShop" for f in r["facts"])
        assert any(f["state"] == "ok" for f in r["facts"])

    def test_wifiเครือข่ายเปิดต้องเตือนเพิ่ม(self):
        r = classify("WIFI:T:nopass;S:FreeWiFi;;")
        assert r["type"] == "wifi"
        assert len(r["warnings"]) >= 2
        assert any(f["state"] == "bad" for f in r["facts"])

    def test_เบอร์โทร(self):
        r = classify("tel:+66812345678")
        assert r["type"] == "tel"
        assert r["facts"][0]["value"] == "+66812345678"

    def test_sms(self):
        r = classify("SMSTO:0812345678:กดยืนยันรับสิทธิ์")
        assert r["type"] == "sms"
        assert any("ข้อความ" in f["label"] for f in r["facts"])

    def test_อีเมล(self):
        r = classify("mailto:someone@example.com?subject=hi")
        assert r["type"] == "email"
        assert r["facts"][0]["value"] == "someone@example.com"

    def test_นามบัตร(self):
        r = classify("BEGIN:VCARD\nVERSION:3.0\nFN:สมชาย ใจดี\nEND:VCARD")
        assert r["type"] == "vcard"
        assert r["facts"][0]["value"] == "สมชาย ใจดี"

    def test_พิกัด(self):
        assert classify("geo:13.7563,100.5018")["type"] == "geo"

    def test_ข้อความธรรมดา(self):
        r = classify("สวัสดีครับ นี่คือข้อความเฉย ๆ")
        assert r["type"] == "text"
        assert r["warnings"] == []

    def test_ค่าว่าง(self):
        r = classify("")
        assert r["type"] == "text"
        assert r["warnings"] == []


class TestLooksLikeUrl:
    def test_ลิงก์เต็มรูปแบบ(self):
        assert looks_like_url("https://example.com/path") is True
        assert looks_like_url("http://example.com") is True

    def test_ลิงก์ที่ไม่มีscheme(self):
        assert looks_like_url("example.com") is True
        assert looks_like_url("example.com/a?b=1") is True

    def test_ไม่ใช่ลิงก์(self):
        assert looks_like_url("WIFI:T:WPA;S:x;;") is False
        assert looks_like_url("สวัสดี") is False
        assert looks_like_url("0812345678") is False

    def test_ข้อความที่มีช่องว่างไม่ใช่ลิงก์(self):
        assert looks_like_url("example.com กดเลย") is False

    def test_QRชำระเงินต้องไม่ถูกมองว่าเป็นลิงก์(self):
        """ถ้าหลุดไปเข้าระบบตรวจลิงก์ ผู้ใช้จะไม่ได้เห็นข้อมูลผู้รับเงินเลย"""
        assert looks_like_url(PROMPTPAY_OK) is False
        assert classify(PROMPTPAY_OK)["type"] == "promptpay"


def _ปิดท้ายด้วยCRC(body: str) -> str:
    """ต่อเลขตรวจสอบให้ถูกต้องท้าย payload (body ต้องจบด้วย "6304" แล้ว)"""
    return body + f"{crc16_ccitt(body.encode('utf-8')):04X}"


# QR พร้อมเพย์ที่มีชื่อผู้รับเงิน (tag 59) ไว้ทดสอบเรื่องชื่อโดยเฉพาะ
_ฐานมีชื่อ = ("00020101021129370016A00000067701011101130066812345678"
              "53037645802TH")


class TestเลขตรวจสอบCRC:
    def test_ไม่มีเลขตรวจสอบท้ายQRต้องเตือน(self):
        """QR ชำระเงินจริงมี CRC ทุกใบ ถ้าไม่มีแปลว่ายืนยันไม่ได้ว่าถูกแก้มาหรือไม่
        ต้องเป็น "ควรระวัง" ไม่ใช่เงียบไปเฉย ๆ"""
        r = classify(_ฐานมีชื่อ)
        assert r["crc_ok"] is None
        assert any(w["severity"] == "high" and "CRC" in w["title"] for w in r["warnings"])

    def test_มีข้อมูลต่อท้ายเลขตรวจสอบต้องไม่นับว่าผ่าน(self):
        """tag 63 ต้องเป็นชุดสุดท้ายเสมอ การมีอะไรต่อท้ายอีกคือรูปแบบที่ QR จริงไม่มี
        (ของเดิมใช้ rfind จึงยังตอบว่า CRC ตรงได้ทั้งที่ payload ผิดรูป)"""
        r = classify(PROMPTPAY_OK + "0208EXTRA123")
        assert r["crc_ok"] is not True
        assert any("CRC" in w["title"] for w in r["warnings"])

    def test_QRปกติต้องไม่ขึ้นคำเตือนเรื่องCRC(self):
        r = classify(PROMPTPAY_OK)
        assert not any("CRC" in w["title"] for w in r["warnings"])


class Testชื่อผู้รับเงิน:
    def test_ชื่อที่มีอักขระมองไม่เห็นต้องเตือน(self):
        """แทรกอักขระความกว้างศูนย์ในชื่อร้าน = ชื่อที่ตาเห็นไม่ตรงกับชื่อจริง
        ทำได้โดย CRC ยังตรงทุกประการ จึงต้องมีกฎแยกมาจับ"""
        r = classify(_ปิดท้ายด้วยCRC(_ฐานมีชื่อ + "5907SH​OP" + "6304"))
        assert r["crc_ok"] is True
        assert any("อักขระที่มองไม่เห็น" in w["title"] for w in r["warnings"])

    def test_ชื่อร้านปกติต้องไม่โดนเตือน(self):
        """ด้านกลับ: ชื่อภาษาไทยธรรมดาต้องไม่ถูกตีว่าอำพราง"""
        r = classify(_ปิดท้ายด้วยCRC(_ฐานมีชื่อ + "5927ร้านลุงมี" + "6304"))
        assert not any("อักขระที่มองไม่เห็น" in w["title"] for w in r["warnings"])


class Testจำนวนเงิน:
    def test_สกุลเงินอื่นต้องไม่เขียนว่าบาท(self):
        r = classify(_ปิดท้ายด้วยCRC(
            "00020101021229370016A0000006770101110113006681234567853038405802TH54071000.006304"))
        เงิน = [d for d in r["details"] if "จำนวนเงิน" in d["label"]][0]
        assert "บาท" not in เงิน["value"] and "840" in เงิน["value"]

    def test_สกุลเงินบาทยังเขียนว่าบาทเหมือนเดิม(self):
        r = classify(_ปิดท้ายด้วยCRC(
            "00020101021229370016A0000006770101110113006681234567853037645802TH54071000.006304"))
        เงิน = [d for d in r["details"] if "จำนวนเงิน" in d["label"]][0]
        assert เงิน["value"] == "1000.00 บาท"


class TestQRเปิดแอปและคริปโต:
    def test_ลิงก์เพิ่มเพื่อนLINE(self):
        r = classify("line://ti/p/~scammer01")
        assert r["type"] == "line"
        assert any(w["severity"] == "medium" for w in r["warnings"])

    def test_ลิงก์ติดตั้งแอปต้องเตือนแรงกว่า(self):
        """แอปดูดเงินมากับ QR ที่พาไปหน้าติดตั้งโดยตรง"""
        r = classify("market://details?id=com.example.fake")
        assert r["type"] == "app_link"
        assert any(w["severity"] == "high" for w in r["warnings"])

    def test_QRโอนคริปโต(self):
        r = classify("bitcoin:bc1qexampleaddress?amount=0.05")
        assert r["type"] == "crypto"
        assert any(w["severity"] == "high" for w in r["warnings"])

    def test_ลิงก์เว็บของLINEยังเป็นลิงก์ตามเดิม(self):
        """ด้านกลับ: https://line.me/... ต้องเข้าท่อตรวจลิงก์ 4 ชั้น ไม่ใช่ถูกดักเป็น app_link"""
        assert classify("https://line.me/ti/p/~shop")["type"] == "url"

    def test_ข้อความธรรมดาที่มีเครื่องหมายทวิภาคยังเป็นข้อความ(self):
        """ด้านกลับ: อย่าให้กฎ scheme ไปกินข้อความทั่วไปที่มี ":" อยู่ข้างใน"""
        assert classify("ราคา: 100 บาท")["type"] == "text"
        assert classify("Note:ประชุมพรุ่งนี้")["type"] == "text"


class TestQRที่มีภาษาไทยข้างใน:
    def test_ชื่อร้านภาษาไทยแล้วCRCต้องยังตรง(self):
        """ความยาวใน EMVCo นับเป็นไบต์ และ CRC คิดจากไบต์ ถ้าคิดผิดจะกลายเป็นว่า
        QR ของร้านจริงที่ตั้งชื่อเป็นภาษาไทยถูกตัดสินว่า "ถูกแก้ไข" ซึ่งคือการโกหกผู้ใช้"""
        r = classify(_ปิดท้ายด้วยCRC(_ฐานมีชื่อ + "5927ร้านลุงมี" + "6304"))
        assert r["crc_ok"] is True
        assert "critical" not in {w["severity"] for w in r["warnings"]}

    def test_ชุดข้อมูลหลังข้อความไทยต้องยังอ่านได้(self):
        """ถ้านับความยาวเป็นตัวอักษร ชุดที่อยู่ถัดจากชื่อไทยจะเลื่อนและอ่านไม่ออกทั้งหมด"""
        assert parse_tlv("5927ร้านลุงมี6002TH") == {"59": "ร้านลุงมี", "60": "TH"}

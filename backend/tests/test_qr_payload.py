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

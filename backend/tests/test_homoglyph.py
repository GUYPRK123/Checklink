# -*- coding: utf-8 -*-
"""
test_homoglyph.py — เทสต์การจับโดเมนอักขระเลียนแบบ (homoglyph/IDN)

ปลายทางไฟล์จริง: backend/tests/test_homoglyph.py

หลักที่เทสต์คุม (ตามที่ตกลงในการออกแบบ):
  1) โฮสต์ non-ASCII ที่ "ล้างการอำพรางแล้วชนแบรนด์" -> ต้อง parse ผ่าน พร้อมธง
     homoglyph_brand เพื่อให้ผู้ใช้ได้คำเตือนปลอมแปลง แทนคำตอบ "อ่านลิงก์ไม่ได้"
  2) โฮสต์ non-ASCII อื่นทั้งหมด (IDN ภาษาจริง) -> fail-closed เหมือนเดิมทุกประการ
  3) รูป punycode (xn--) ที่ก๊อปมาจากเบราว์เซอร์ ต้องถูกถอดกลับมาตรวจแบบเดียวกัน
  4) ลิงก์ ASCII ปกติต้องไม่ได้รับผลกระทบใด ๆ
"""
from analyzer.url_parser import parse_url
from analyzer.heuristics import analyze
from analyzer.scanner import decide


class Testจับโดเมนอักขระเลียนแบบ:
    def test_ซีริลลิกปลอม_apple(self):
        """а (U+0430 ซีริลลิก) หน้าตาเหมือน a ละติน — เคสคลาสสิกของ IDN homograph"""
        p = parse_url("https://аpple.com/login")
        assert p["valid"] is True
        assert p["homoglyph_brand"] == "apple"
        assert p["homoglyph_original"] == "аpple.com"
        assert p["host"].startswith("xn--")   # ถูกแปลงเป็น punycode เพื่อวิเคราะห์ต่อ
        assert p["is_punycode"] is True

    def test_ซีริลลิกกลางคำ_paypal(self):
        p = parse_url("https://pаypal.com/verify")
        assert p["valid"] is True
        assert p["homoglyph_brand"] == "paypal"

    def test_ธนาคารไทย(self):
        """แบรนด์ไทยในลิสต์ต้องถูกคุ้มครองด้วย และนามสกุลสองชั้นต้องตัดถูกหลังแปลง"""
        p = parse_url("https://ѕcb.co.th/promo")   # ѕ ซีริลลิก
        assert p["valid"] is True
        assert p["homoglyph_brand"] == "scb"
        assert p["tld"] == "co.th"

    def test_จุดใต้ตัวอักษร(self):
        """ạ (a + จุดใต้) — เทคนิคที่เว็บฟิชชิ่งจริงใช้ เพราะจุดเล็กจนตามองข้าม"""
        p = parse_url("https://ạpple.com/")
        assert p["valid"] is True
        assert p["homoglyph_brand"] == "apple"

    def test_แบรนด์ผสมคำอื่น(self):
        p = parse_url("https://fаcebook-login.xyz/")
        assert p["homoglyph_brand"] == "facebook"


class Testของเดิมต้องไม่เปลี่ยน:
    def test_idn_ภาษาจริงยัง_fail_closed(self):
        """โดเมน IDN สุจริต (ไทย/รัสเซีย/ฝรั่งเศส) ไม่ชนแบรนด์ -> "อ่านลิงก์ไม่ได้"
        เหมือนเดิมทุกประการ ตามแนวทาง fail-closed ที่เลือกไว้"""
        assert parse_url("https://ไทย.com/")["valid"] is False
        assert parse_url("https://почта.рф/")["valid"] is False
        assert parse_url("https://café.fr/")["valid"] is False

    def test_ascii_ปกติไม่ถูกแตะ(self):
        p = parse_url("https://www.google.com/")
        assert p["valid"] is True
        assert p.get("homoglyph_brand") is None

    def test_punycode_ที่ไม่ชนแบรนด์_พฤติกรรมเดิม(self):
        """xn-- ทั่วไปยังได้แค่ธง is_punycode (สัญญาณ medium เดิม) ไม่โดนตีเป็นปลอมแปลง"""
        p = parse_url("https://xn--80ak6aa92e.com/")
        assert p["valid"] is True
        assert p["is_punycode"] is True
        assert p.get("homoglyph_brand") in (None, "")  # ต้องไม่ถูกยัดแบรนด์ให้


class Testรูปpunycodeจากเบราว์เซอร์:
    def test_ถอด_xn_กลับมาตรวจ(self):
        """เบราว์เซอร์แปลง IDN เป็น punycode ตอนก๊อป — ผู้ใช้จึงมักวางรูปนี้มา
        ต้องจับได้เท่ากับรูป unicode (xn--pple-43d.com = аpple.com)"""
        p = parse_url("https://xn--pple-43d.com/login")
        assert p["valid"] is True
        assert p["homoglyph_brand"] == "apple"
        assert p["host"] == "xn--pple-43d.com"   # โฮสต์เดิมไม่ถูกแปลง (เป็น ASCII อยู่แล้ว)


class Testสัญญาณและคำตัดสิน:
    def test_สัญญาณ_critical_พร้อมแบรนด์(self):
        p = parse_url("https://pаypal.com/verify")
        a = analyze(p)
        sig = next(s for s in a["signals"] if s["id"] == "homoglyph_brand")
        assert sig["severity"] == "critical"
        assert sig["brand"] == "paypal"          # ให้หน้าเว็บโชว์โดเมนทางการเทียบ
        assert "ปลอมแปลง" in sig["title"]        # ข้อความตามที่ตกลง
        assert a["verified_safe"] is False

    def test_คำตัดสินสุดท้ายเป็นแดง(self):
        """critical -> decide() ต้องฟันธงแดงโดยไม่ต้องพึ่งชั้นอื่น (ผู้ใช้ไม่ล็อกอิน
        ที่ได้แค่ชั้น 1-2 ก็ยังได้คำเตือนเต็ม)"""
        p = parse_url("https://аpple.com/login")
        a = analyze(p)
        v = decide({"found": False}, a)
        assert v["color"] == "red"

    def test_แบรนด์จริงไม่โดนลูกหลง(self):
        """โดเมนทางการแท้ ๆ ต้องยังได้เขียวเหมือนเดิม (กัน regression สำคัญสุด)"""
        a = analyze(parse_url("https://www.paypal.com/signin"))
        assert a["verified_safe"] is True

# -*- coding: utf-8 -*-
"""
test_url_parser.py — เทสต์การแยกส่วนประกอบ URL

จุดที่ต้องคุมให้แน่นที่สุดคือ "โดเมนจริง" (registrable / eTLD+1) เพราะทั้งระบบใช้ค่านี้
ตัดสินว่าลิงก์เป็นของแบรนด์จริงหรือไม่ ถ้าอ่านผิดแม้แต่นิดเดียว เช่นอ่าน
google.com.evil.xyz เป็น google.com ระบบจะแจกป้ายเขียวให้เว็บหลอกทันที
"""
from analyzer.url_parser import parse_url


class TestโดเมนจริงEtld1:
    def test_โดเมนธรรมดา(self):
        p = parse_url("https://www.google.com/search?q=abc")
        assert p["valid"] is True
        assert p["registrable"] == "google.com"
        assert p["subdomain"] == "www"
        assert p["tld"] == "com"
        assert p["main_label"] == "google"

    def test_นามสกุลสองชั้นไทย(self):
        """co.th ต้องนับเป็นนามสกุล ไม่ใช่โดเมนจริง — ถ้าพลาด shopee.co.th จะกลายเป็น co.th"""
        p = parse_url("https://shopee.co.th/mall")
        assert p["registrable"] == "shopee.co.th"
        assert p["tld"] == "co.th"
        assert p["main_label"] == "shopee"
        assert p["subdomain"] == ""

    def test_นามสกุลสองชั้นพร้อมsubdomain(self):
        p = parse_url("https://reg.ac.chula.ac.th/login")
        assert p["registrable"] == "chula.ac.th"
        assert p["subdomain"] == "reg.ac"

    def test_แบรนด์ถูกใช้เป็นsubdomainของเว็บอื่น(self):
        """เทคนิคหลอกที่พบบ่อยที่สุด — โดเมนจริงต้องเป็น evil.xyz ไม่ใช่ google.com"""
        p = parse_url("https://google.com.secure-login.evil.xyz/verify")
        assert p["registrable"] == "evil.xyz"
        assert p["main_label"] == "evil"
        assert p["subdomain"] == "google.com.secure-login"


class TestรูปแบบพิเศษของURL:
    def test_ไม่ใส่scheme_ให้เดาว่าเป็นhttp(self):
        p = parse_url("example.com/path")
        assert p["valid"] is True
        assert p["protocol_known"] is False
        assert p["protocol"] == "(ไม่ระบุ)"
        assert p["host"] == "example.com"

    def test_เลขip(self):
        p = parse_url("http://203.0.113.10/login.php")
        assert p["is_ip"] is True
        assert p["registrable"] == "203.0.113.10"
        assert p["tld"] == ""

    def test_ซ่อนปลายทางด้วยเครื่องหมายat(self):
        """ทุกอย่างก่อน @ เป็นตัวลวง โฮสต์จริงคือส่วนหลัง @"""
        p = parse_url("http://www.google.com@evil.xyz/pay")
        assert p["userinfo"] is True
        assert p["registrable"] == "evil.xyz"

    def test_punycode(self):
        p = parse_url("https://xn--80ak6aa92e.com")
        assert p["is_punycode"] is True

    def test_พอร์ตแปลก(self):
        p = parse_url("http://example.com:8080/a")
        assert p["port"] == "8080"

    def test_โฮสต์ตัวใหญ่ถูกแปลงเป็นตัวเล็ก(self):
        p = parse_url("https://WWW.GOOGLE.COM/")
        assert p["host"] == "www.google.com"
        assert p["registrable"] == "google.com"

    def test_query_ติดมาในpath(self):
        p = parse_url("https://example.com/a?x=1")
        assert p["path"] == "/a?x=1"


class Testลิงก์ที่อ่านไม่ได้:
    def test_ค่าว่าง(self):
        assert parse_url("")["valid"] is False
        assert parse_url("   ")["valid"] is False
        assert parse_url(None)["valid"] is False

    def test_ไม่มีจุดในโฮสต์(self):
        assert parse_url("localhost")["valid"] is False

    def test_มีช่องว่างในโฮสต์(self):
        assert parse_url("http://exa mple.com")["valid"] is False

    def test_schemeที่ไม่ใช่เว็บ(self):
        """data:/javascript:/mailto: ต้องไม่ถูกเติม http:// นำหน้าจนกลายเป็นลิงก์ปลอม ๆ
        (เจอจริงตอน content_checker ส่ง href ของ <link> เข้ามา)"""
        for raw in ("data:text/html;base64,PHNjcmlwdD4=",
                    "javascript:alert(1)",
                    "mailto:someone@example.com",
                    "tel:0812345678"):
            assert parse_url(raw)["valid"] is False, raw

    def test_พอร์ตที่ไม่ใช่ตัวเลข(self):
        assert parse_url("http://example.com:abc/")["valid"] is False

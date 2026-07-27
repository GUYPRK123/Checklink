# -*- coding: utf-8 -*-
"""
test_text_norm.py — เทสต์การล้างข้อความก่อนเทียบชื่อแบรนด์

สิ่งที่ชุดนี้กันไว้: การเลี่ยงกฎ "หน้าเว็บอ้างถึงแบรนด์" ด้วยการเขียนชื่อแบรนด์ให้
เครื่องอ่านไม่ออกแต่คนอ่านออก ทุกเคสในนี้คือท่าที่ใช้กันจริงในหน้าฟิชชิ่ง
"""
from analyzer.text_norm import contains_word, flatten, normalize_text, strip_invisible

ZWSP = "​"      # zero width space
RLO = "‮"       # right-to-left override


class Testคลายรหัสที่เบราว์เซอร์แปลงกลับให้:
    def test_html_entity_แบบตัวเลข(self):
        assert normalize_text("&#103;oogle") == "google"

    def test_html_entity_แบบเลขฐานสิบหก(self):
        assert normalize_text("&#x67;oogle") == "google"

    def test_html_entity_ซ้อนสองชั้น(self):
        """&amp;#103; -> &#103; -> g  (ท่าหลบตัวคลายที่ทำงานรอบเดียว)"""
        assert normalize_text("&amp;#103;oogle") == "google"


class Testอักขระที่หน้าตาเหมือนแต่ไม่ใช่ตัวเดียวกัน:
    def test_ตัวอักษรเต็มความกว้าง(self):
        assert normalize_text("ｇｏｏｇｌｅ") == "google"

    def test_ตัวเลขแทนตัวอักษร(self):
        assert normalize_text("g00gle") == "google"
        assert normalize_text("paypa1") == "paypal"


class Testอักขระที่มองไม่เห็น:
    def test_ลบzerowidthกลางคำ(self):
        assert normalize_text("goo" + ZWSP + "gle") == "google"

    def test_ลบตัวคุมทิศทางข้อความ(self):
        assert strip_invisible("goo" + RLO + "gle") == "google"

    def test_ข้อความปกติไม่ถูกแตะ(self):
        assert strip_invisible("ธนาคารกรุงเทพ") == "ธนาคารกรุงเทพ"


class Testยุบช่องว่าง:
    def test_ยุบช่องว่างซ้ำและตัดหัวท้าย(self):
        assert normalize_text("  เข้าสู่ระบบ   ธนาคาร  ") == "เข้าสู่ระบบ ธนาคาร"

    def test_สตริงว่าง(self):
        assert normalize_text("") == ""
        assert normalize_text(None) == ""


class Testflattenลบตัวคั่น:
    def test_ตัวคั่นกลางชื่อแบรนด์(self):
        assert "google" in flatten("g-o-o-g-l-e")
        assert "google" in flatten("g.o.o.g.l.e")

    def test_เก็บอักษรไทยไว้(self):
        assert flatten("ธนาคาร ไทย") == "ธนาคารไทย"


class Testcontains_wordมีขอบเขตคำ:
    def test_เจอคำเต็ม(self):
        assert contains_word("เข้าสู่ระบบ LINE วันนี้", "line") is True

    def test_ไม่เจอเมื่อเป็นส่วนหนึ่งของคำอื่น(self):
        """"online" ต้องไม่ถูกนับว่าเป็นแบรนด์ "line" — false positive ที่เจ็บที่สุด"""
        assert contains_word("ซื้อของ online ราคาถูก", "line") is False
        assert contains_word("headline news", "line") is False

    def test_ติดกับอักษรไทยยังนับว่าเจอ(self):
        """ภาษาไทยไม่มีช่องว่างคั่นคำ ขอบเขตคำแบบ \\b ของ regex จึงใช้ไม่ได้"""
        assert contains_word("บัญชีlineของคุณ", "line") is True

    def test_ตัวเลขติดกันไม่นับ(self):
        assert contains_word("line2", "line") is False

    def test_อินพุตว่าง(self):
        assert contains_word("", "line") is False
        assert contains_word("line", "") is False

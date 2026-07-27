# -*- coding: utf-8 -*-
"""
test_scanner_combos.py — เทสต์ว่าสายไฟระหว่างชั้นต่อกันจริง

เทสต์ไฟล์อื่นตรวจแต่ละชิ้นแยกกัน (heuristics, content_analyzer, combos) แต่ชิ้นส่วน
ที่ถูกทุกชิ้นก็ยังประกอบผิดได้ ชุดนี้จึงตรวจเส้นทางเต็ม: ดึงหน้าเว็บ -> วิเคราะห์ ->
รวมสัญญาณทุกชั้น -> combo -> คำตัดสินเขียว/เหลือง/แดง

ทุกอย่างที่ต้องต่อเน็ต (บัญชีดำ, ตาม redirect, RDAP, ดึงหน้าเว็บ) ถูกแทนด้วยของปลอม
เทสต์จึงรันได้ออฟไลน์และให้ผลเดิมทุกครั้ง
"""
import pytest

from analyzer import scanner


@pytest.fixture(autouse=True)
def ปิดการต่อเน็ตทั้งหมด(monkeypatch):
    """ตัดขาทุกทางที่ scanner จะออกเน็ต + ล้างแคชผลตรวจก่อนทุกเทสต์

    ถ้าไม่ล้างแคช เทสต์ข้อที่สองที่ใช้ URL เดิมจะได้ผลของข้อแรกกลับมา
    """
    from analyzer import scan_cache
    scan_cache.clear()
    monkeypatch.setattr(scanner, "check_blacklist",
                        lambda url: {"found": False, "malicious": False})
    monkeypatch.setattr(scanner, "resolve_destination",
                        lambda url: {"resolved": True, "chain": [url],
                                     "final_url": url, "hops": 0, "blocked": False})
    monkeypatch.setattr(scanner, "analyze_domain_intel",
                        lambda reg, host: {"signals": [], "domain_age": {"checked": False},
                                           "ssl": {"checked": False}})


def ใช้หน้าเว็บปลอม(monkeypatch, html: str):
    """ให้ชั้นที่ 4 เห็น HTML ที่เรากำหนดเอง โดยไม่ต้องมีเว็บจริง

    ต้อง patch ที่ content_checker ไม่ใช่ที่ page_fetch เพราะ content_checker
    ดึงชื่อ fetch_page เข้ามาไว้ในตัวเองตั้งแต่ตอน import แล้ว
    """
    from analyzer import content_checker

    def fake_fetch(url):
        return {"ok": True, "reason": "", "source": "test", "js_rendered": False,
                "final_url": url, "status": 200, "html": html, "raw_html": html,
                "network_posts": []}

    monkeypatch.setattr(content_checker, "fetch_page", fake_fetch)


หน้าฟิชชิ่งอ้างแบรนด์ = """<html><head><title>Kbank - เข้าสู่ระบบ</title>
<link rel="icon" href="/favicon.ico"></head><body>
<h1>เข้าสู่ระบบเพื่อยืนยันตัวตน</h1>
<form action="/collect" method="post">
<input type="text" name="u"><input type="password" name="p">
<button>ยืนยัน</button></form>
<a href="/help">ช่วยเหลือ</a>
<p>กรุณายืนยันตัวตนภายใน 24 ชั่วโมง มิฉะนั้นบัญชีของท่านจะถูกระงับการใช้งาน
ขออภัยในความไม่สะดวก ฝ่ายบริการลูกค้า</p></body></html>"""

หน้าร้านค้าปกติ = """<html><head><title>ร้านต้นไม้ออนไลน์</title>
<link rel="icon" href="/favicon.ico"></head><body>
<h1>ยินดีต้อนรับ</h1>
<a href="/about">เกี่ยวกับเรา</a> <a href="/contact">ติดต่อ</a>
<p>เราขายต้นไม้มา 10 ปี ส่งทั่วประเทศ มีหน้าร้านจริงที่เชียงใหม่ ติดต่อได้ทุกวัน
ตั้งแต่ 9 โมงเช้าถึง 6 โมงเย็น รับประกันการขนส่ง เปลี่ยนใหม่ถ้าเสียหาย</p>
</body></html>"""


class Testcomboเปลี่ยนผลได้จริง:
    def test_หน้าอ้างแบรนด์พร้อมขอรหัสผ่านต้องได้แดง(self, monkeypatch):
        """นี่คือเคสที่ combo ถูกสร้างมาแก้โดยตรง — เดิมได้แค่เหลือง
        เพราะ content_brand_mismatch อย่างเดียวได้ 3 คะแนน ไม่ถึงเกณฑ์แดง (6)"""
        ใช้หน้าเว็บปลอม(monkeypatch, หน้าฟิชชิ่งอ้างแบรนด์)
        result = scanner.scan("https://kbank-verify-account.xyz/login")

        assert result["verdict"]["color"] == "red"
        assert "combo_brand_password" in result["layer4"]["combos_hit"]

    def test_รายงานที่มาของcomboให้ผู้ใช้เห็น(self, monkeypatch):
        """หลักการของระบบคือ "อธิบายได้ ไม่ใช่กล่องดำ" combo ต้องอยู่ใน reasons
        พร้อมบอกว่าเกิดจากสัญญาณคู่ไหน"""
        ใช้หน้าเว็บปลอม(monkeypatch, หน้าฟิชชิ่งอ้างแบรนด์)
        result = scanner.scan("https://kbank-verify-account.xyz/login")

        combo = next(r for r in result["reasons"] if r["id"] == "combo_brand_password")
        assert combo["combo_of"] == ["content_brand_mismatch", "has_password_input"]

    def test_ข้อเท็จจริงของหน้าถูกส่งขึ้นมาถึงชั้นบน(self, monkeypatch):
        ใช้หน้าเว็บปลอม(monkeypatch, หน้าฟิชชิ่งอ้างแบรนด์)
        result = scanner.scan("https://kbank-verify-account.xyz/login")

        assert result["layer4"]["content_checked"] is True
        assert "has_password_input" in result["layer4"]["content_facts"]


class Testไม่สร้างความตกใจเกินจริง:
    def test_หน้าร้านค้าปกติต้องไม่ได้แดง(self, monkeypatch):
        ใช้หน้าเว็บปลอม(monkeypatch, หน้าร้านค้าปกติ)
        result = scanner.scan("https://my-plant-shop.org/")

        assert result["verdict"]["color"] != "red"
        assert result["layer4"]["combos_hit"] == []

    def test_ดึงหน้าเว็บไม่ได้ต้องไม่กลายเป็นเสี่ยงเพิ่ม(self, monkeypatch):
        """"เช็กไม่ได้" ต้องไม่เท่ากับ "เสี่ยง" — และ combo ต้องไม่จุดจากการเดา"""
        from analyzer import content_checker, page_fetch
        monkeypatch.setattr(content_checker, "fetch_page",
                            lambda url: page_fetch.empty_bundle("เชื่อมต่อหน้าเว็บไม่ได้"))
        result = scanner.scan("https://my-plant-shop.org/")

        assert result["layer4"]["content_checked"] is False
        assert result["layer4"]["combos_hit"] == []
        assert result["verdict"]["color"] != "red"

    def test_ชั้น1_2ยังทำงานเหมือนเดิม(self, monkeypatch):
        """โดเมนทางการต้องได้เขียวโดยไม่ต้องแตะชั้นที่ 4 เลย"""
        ใช้หน้าเว็บปลอม(monkeypatch, หน้าฟิชชิ่งอ้างแบรนด์)
        result = scanner.scan("https://www.google.com/")

        assert result["verdict"]["color"] == "green"
        assert result["layer4"]["ran"] is False

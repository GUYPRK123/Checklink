# -*- coding: utf-8 -*-
"""
test_trust.py — เทสต์ "หลักฐานฝั่งปลอดภัย" (trust evidence) และการตัดสินสีเขียว

ก่อนมีกลไกนี้ ระบบมีทางตอบเขียวอยู่ทางเดียวคือโดเมนตรงลิสต์ BRANDS เป๊ะ ทำให้เว็บ
สุจริตที่ไม่ได้อยู่ในลิสต์ติดเหลืองตลอดกาล เทสต์ชุดนี้จึงกันความผิดพลาดสองทิศ:

  - false negative (อันตรายที่สุด): เว็บหลอกได้เขียวเพราะยืมเครดิตของคนอื่นมา
      * หน้าฟิชชิ่งที่ฝากบนแพลตฟอร์มดัง (amazonaws.com อันดับ 7 ของโลก, github.io)
      * ลิงก์ที่มีสัญญาณเสี่ยงอยู่แล้ว แต่โดเมนบังเอิญเป็น .co.th / ติดอันดับ
  - false positive: เว็บทางการที่สะอาดจริง ๆ ยังคงติดเหลือง (ผู้ใช้เลิกเชื่อระบบ)

และกันกฎเหล็กอีกข้อ: **หลักฐานฝั่งปลอดภัยต้องไม่หักคะแนนความเสี่ยงเด็ดขาด**
"""
import os

import pytest

from analyzer import popularity
from analyzer.config import GREEN_TRUST, RED_SCORE
from analyzer.heuristics import analyze, collect_trust
from analyzer.scanner import decide, trust_total
from analyzer.url_parser import parse_url

# อันดับสมมติที่ใช้ทั้งไฟล์ — ไม่พึ่งไฟล์จริงเพื่อให้ผลเทสต์คงที่ไม่ว่ารายการจะอัปเดตไปแค่ไหน
FAKE_LIST = """# รายการทดสอบ
wikipedia.org
somebank.example
""" + "\n".join(f"filler{i}.example" for i in range(3, 50_001)) + """
midrange.example
"""


@pytest.fixture(autouse=True)
def รายการอันดับปลอม(tmp_path, monkeypatch):
    """ชี้ POPULARITY_LIST ไปที่ไฟล์ปลอมเล็ก ๆ ตลอดทั้งไฟล์เทสต์นี้
    wikipedia.org = อันดับ 1 (ชั้นบนสุด) / midrange.example = อันดับ 50,001 (ชั้นรอง)
    """
    path = tmp_path / "popular.txt"
    path.write_text(FAKE_LIST, encoding="utf-8")
    monkeypatch.setenv("POPULARITY_LIST", str(path))
    popularity.reset()
    yield
    popularity.reset()


def trust_ids(url: str) -> set:
    return {t["id"] for t in analyze(parse_url(url))["trust"]}


def สี(url: str) -> str:
    """ยิงลิงก์ผ่านชั้น 2 แล้วให้ decide() ตัดสิน (ไม่แตะเน็ต ไม่มีผลบัญชีดำ)"""
    return decide({"found": False}, analyze(parse_url(url)))["color"]


class Testไฟล์รายการอันดับ:
    def test_อ่านอันดับตามลำดับบรรทัดโดยข้ามคอมเมนต์(self):
        assert popularity.rank("wikipedia.org") == 1
        assert popularity.rank("somebank.example") == 2
        assert popularity.rank("midrange.example") == 50_001

    def test_ไม่อยู่ในรายการคืนNone(self):
        assert popularity.rank("ไม่มีจริง.example") is None
        assert popularity.rank("") is None

    def test_ตัวพิมพ์ใหญ่เล็กไม่สำคัญ(self):
        assert popularity.rank("WIKIPEDIA.ORG") == 1

    def test_ไม่มีไฟล์รายการต้องไม่พังแค่เงียบไป(self, monkeypatch):
        monkeypatch.setenv("POPULARITY_LIST", "/ไม่มี/ไฟล์นี้/จริง.txt")
        popularity.reset()
        assert popularity.rank("wikipedia.org") is None
        assert popularity.status()["available"] is False
        # ที่สำคัญกว่า: การวิเคราะห์ทั้งหมดต้องยังทำงานได้ตามปกติ
        assert สี("https://www.google.com") == "green"     # ยังเขียวจากลิสต์แบรนด์
        assert สี("http://paypal-verify-login.tk/") == "red"

    def test_status_บอกจำนวนที่โหลดได้(self):
        st = popularity.status()
        assert st["available"] is True and st["entries"] == 50_001


class Testนามสกุลโดเมนที่ต้องพิสูจน์ตัวตนก่อนจด:
    def test_หน่วยงานราชการไทยได้หลักฐานเต็ม(self):
        trust = collect_trust(parse_url("https://www.rd.go.th/"))
        assert [t["id"] for t in trust] == ["restricted_tld"]
        assert trust[0]["trust"] >= GREEN_TRUST     # แรงพอให้เขียวได้ด้วยตัวเอง

    def test_สถานศึกษาและทหารก็ได้เหมือนกัน(self):
        assert "restricted_tld" in trust_ids("https://www.chula.ac.th/")
        assert "restricted_tld" in trust_ids("https://www.rtarf.mi.th/")

    def test_นามสกุลนิติบุคคลได้แค่ครึ่งเดียว(self):
        trust = collect_trust(parse_url("https://www.example.co.th/"))
        assert [t["id"] for t in trust] == ["verified_org_tld"]
        assert 0 < trust[0]["trust"] < GREEN_TRUST  # ต้องมีหลักฐานอื่นมาประกอบ

    def test_นามสกุลทั่วไปไม่ได้อะไร(self):
        assert trust_ids("https://www.unknown-site.com/") == set()
        assert trust_ids("https://www.unknown-site.xyz/") == set()


class Testความนิยมของโดเมน:
    def test_อันดับสูงได้หลักฐานเต็ม(self):
        trust = collect_trust(parse_url("https://wikipedia.org/wiki/A"))
        assert [t["id"] for t in trust] == ["popular_domain"]
        assert trust[0]["trust"] >= GREEN_TRUST

    def test_อันดับกลางได้แค่หลักฐานประกอบ(self):
        trust = collect_trust(parse_url("https://midrange.example/"))
        assert 0 < trust[0]["trust"] < GREEN_TRUST

    def test_เทียบจากโดเมนจริงไม่ใช่โฮสต์เต็ม(self):
        """www.wikipedia.org ต้องหาเจอ ทั้งที่ในรายการเก็บไว้เป็น wikipedia.org เฉย ๆ"""
        assert "popular_domain" in trust_ids("https://www.wikipedia.org/")

    def test_เลขIPไม่มีสิทธิ์ได้หลักฐานใด_ๆ(self):
        assert collect_trust(parse_url("http://1.2.3.4/login")) == []


class Testเครดิตของแพลตฟอร์มต้องไม่ตกไปถึงหน้าที่คนอื่นเอามาฝาก:
    """จุดที่พลาดแล้วอันตรายที่สุดของทั้งฟีเจอร์ — วัดกับ testset_100.json แล้วพบว่า
    ลิงก์ฟิชชิ่งที่ยังทำงานอยู่จริง 22/50 ลิงก์อยู่ในรายการอันดับ และทุกอันเป็นโดเมน
    ของแพลตฟอร์มฝากเว็บ ไม่ใช่โดเมนของคนหลอกเอง"""

    def test_พื้นที่ฝากเว็บฟรีไม่ได้หลักฐานแม้จะติดอันดับ(self, tmp_path, monkeypatch):
        path = tmp_path / "p.txt"
        path.write_text("github.io\namazonaws.com\n", encoding="utf-8")
        monkeypatch.setenv("POPULARITY_LIST", str(path))
        popularity.reset()
        assert popularity.rank("github.io") == 1        # อยู่ในรายการจริง
        assert collect_trust(parse_url("https://someone.github.io/login/")) == []
        assert collect_trust(parse_url("http://x.s3.amazonaws.com/a.html")) == []

    def test_หน้าฟิชชิ่งบนพื้นที่ฝากฟรีต้องไม่ได้เขียว(self, tmp_path, monkeypatch):
        path = tmp_path / "p.txt"
        path.write_text("github.io\n", encoding="utf-8")
        monkeypatch.setenv("POPULARITY_LIST", str(path))
        popularity.reset()
        assert สี("https://somestudent.github.io/my-portfolio/") != "green"

    def test_แพลตฟอร์มยอดนิยมที่ต้องอยู่ในลิสต์กรอง(self):
        """ไล่รายการอันดับ 10,000 แรกมาทีละอันแล้วเก็บกลุ่มนี้ไว้ — ถ้าใครเผลอลบออก
        หน้าฟิชชิ่งที่ฝากบนแพลตฟอร์มเหล่านี้จะได้เขียวทันทีเพราะอันดับของแพลตฟอร์ม"""
        from analyzer.config import USER_CONTENT_DOMAINS, SHORTENERS
        ต้องมี = {
            "amazonaws.com", "cloudfront.net", "sharepoint.com", "appspot.com",
            "windows.net", "linktr.ee", "forms.gle", "jotform.com", "typeform.com",
            "notion.site", "carrd.co", "000webhostapp.com", "codesandbox.io",
            "medium.com", "eu.org", "mybluehost.me",
        }
        assert ต้องมี <= USER_CONTENT_DOMAINS
        assert {"u.to", "tiny.cc", "onelink.me"} <= SHORTENERS
        # และต้องไม่มีตัวไหนหลุดไปอยู่สองลิสต์พร้อมกัน (กติกาคนละแบบ)
        assert not (USER_CONTENT_DOMAINS & SHORTENERS)

    def test_ลิงก์ย่อไม่ได้หลักฐานแม้จะติดอันดับ(self, tmp_path, monkeypatch):
        path = tmp_path / "p.txt"
        path.write_text("bit.ly\n", encoding="utf-8")
        monkeypatch.setenv("POPULARITY_LIST", str(path))
        popularity.reset()
        assert collect_trust(parse_url("https://bit.ly/3xYzAb")) == []
        assert สี("https://bit.ly/3xYzAb") != "green"


class Testแพลตฟอร์มเขียนบทความใช้กฎแบรนด์คนละแบบ:
    """บน medium/substack/soundcloud ตัว path คือ "ชื่อบทความ" ไม่ใช่โครงเว็บที่คนทำ
    หน้าปลอมออกแบบเอง ถ้าใช้กฎ user_content_brand (critical) กับ path ของกลุ่มนี้
    บทความข่าวทุกชิ้นที่พูดถึงแบรนด์จะกลายเป็นแดงทันที"""

    def test_บทความที่พูดถึงแบรนด์ต้องไม่แดง(self):
        for url in ("https://medium.com/@somebody/why-facebook-changed-its-name",
                    "https://substack.com/@writer/p/apple-vision-review",
                    "https://soundcloud.com/artist/spotify-mix"):
            result = analyze(parse_url(url))
            ids = {s["id"] for s in result["signals"]}
            assert "user_content_brand" not in ids, url
            assert "brand_in_path" in ids, url       # ยังเป็นข้อสังเกตอยู่ ไม่ได้เงียบไป
            assert สี(url) == "yellow", url

    def test_เอาชื่อแบรนด์มาตั้งเป็นโดเมนย่อยยังแดงเหมือนเดิม(self):
        ids = {s["id"] for s in analyze(parse_url("https://facebook-login.medium.com/verify"))["signals"]}
        assert "user_content_brand" in ids
        assert สี("https://facebook-login.medium.com/verify") == "red"

    def test_พื้นที่ฝากเว็บทั่วไปยังใช้กฎเดิมทุกอย่าง(self):
        """github.io ต้องไม่ถูกกระทบ — ชื่อแบรนด์ใน path ยังเป็นเจตนาปลอมเหมือนเดิม
        เพราะ path บน github.io คือโครงเว็บที่เจ้าของหน้าออกแบบเอง"""
        ids = {s["id"] for s in analyze(parse_url("https://aryama10.github.io/facebook-login-page"))["signals"]}
        assert "user_content_brand" in ids
        assert สี("https://aryama10.github.io/facebook-login-page") == "red"
        assert สี("https://somestudent.github.io/my-portfolio/") == "yellow"

    def test_แพลตฟอร์มบทความต้องเป็นสับเซ็ตของพื้นที่ฝากเว็บ(self):
        """ถ้าหลุดออกจาก USER_CONTENT_DOMAINS จะได้เขียวจากอันดับความนิยมทันที"""
        from analyzer.config import PUBLISHING_DOMAINS, USER_CONTENT_DOMAINS
        assert PUBLISHING_DOMAINS <= USER_CONTENT_DOMAINS


class Testหลักฐานฝั่งปลอดภัยต้องไม่ลดระดับความเสี่ยง:
    """กฎเหล็ก: trust มีไว้ยกจาก "เหลืองเพราะไม่รู้จัก" เป็นเขียวเท่านั้น
    ห้ามใช้กลบสัญญาณเสี่ยง ไม่งั้นระบบเตือนภัยจะถูกกล่อมให้เงียบได้"""

    def test_ทุกหลักฐานต้องมีคะแนนเป็นศูนย์(self):
        for url in ("https://www.rd.go.th/", "https://wikipedia.org/",
                    "https://www.example.co.th/"):
            for t in analyze(parse_url(url))["trust"]:
                assert t["points"] == 0, url
                assert t["severity"] == "good", url

    def test_คะแนนรวมยังเท่ากับผลรวมของสัญญาณเสี่ยงเท่านั้น(self):
        result = analyze(parse_url("https://wikipedia.org/wiki/Phishing"))
        assert result["score"] == sum(s["points"] for s in result["signals"])

    def test_โดเมนนิติบุคคลไทยที่มีสัญญาณอันตรายยังต้องแดง(self):
        """.co.th ได้หลักฐานฝั่งปลอดภัย แต่ถ้าลิงก์เลียนแบบแบรนด์ก็ต้องแดงอยู่ดี"""
        result = analyze(parse_url("https://scb-verify-login.co.th/otp"))
        assert result["score"] >= RED_SCORE
        assert สี("https://scb-verify-login.co.th/otp") == "red"

    def test_มีสัญญาณเสี่ยงแม้แต่ตัวเดียวก็ห้ามเขียว(self, tmp_path, monkeypatch):
        """โดเมนอันดับ 1 ของรายการ แต่ลิงก์เป็น http ธรรมดา (สัญญาณ no_https)
        -> ต้องไม่เขียว เพราะเงื่อนไขคือ "ไม่มีสัญญาณเสี่ยงเลยแม้แต่ตัวเดียว" """
        path = tmp_path / "p.txt"
        path.write_text("plainsite.example\n", encoding="utf-8")
        monkeypatch.setenv("POPULARITY_LIST", str(path))
        popularity.reset()
        assert สี("https://plainsite.example/") == "green"
        assert สี("http://plainsite.example/") != "green"


class Testผลตัดสินสีเขียวแบบใหม่:
    def test_หน่วยงานราชการและมหาวิทยาลัยได้เขียวแล้ว(self):
        for url in ("https://www.rd.go.th/", "https://www.moph.go.th/",
                    "https://www.chula.ac.th/", "https://www.ku.ac.th/"):
            assert สี(url) == "green", url

    def test_เว็บดังระดับโลกได้เขียวแล้ว(self):
        assert สี("https://wikipedia.org/") == "green"

    def test_เว็บที่ไม่รู้จักและไม่มีหลักฐานยังเป็นเหลืองเหมือนเดิม(self):
        """กติกาข้อสำคัญที่สุดของระบบ: "ไม่รู้จัก" ต้องไม่ใช่ "ปลอดภัย" """
        assert สี("https://some-random-company.com/") == "yellow"
        assert สี("https://www.example.co.th/") == "yellow"   # หลักฐานยังไม่พอ

    def test_ลิงก์หลอกยังแดงเหมือนเดิมทุกแบบ(self):
        for url in ("http://secure-paypal-verify-login.tk/account-suspended",
                    "http://1.2.3.4/login",
                    "https://facebook-security-alert.com/verify"):
            assert สี(url) == "red", url

    def test_trust_total_รวมน้ำหนักถูกต้อง(self):
        result = analyze(parse_url("https://www.rd.go.th/"))
        assert trust_total(result) == sum(t["trust"] for t in result["trust"])
        assert trust_total({"trust": []}) == 0
        assert trust_total({}) == 0

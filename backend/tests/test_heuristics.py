# -*- coding: utf-8 -*-
"""
test_heuristics.py — เทสต์ชั้นที่ 2 ของ cascade (วิเคราะห์รูปแบบ URL สด)

นี่คือชั้นเดียวที่จับ "ลิงก์ใหม่ที่ยังไม่มีใครรายงาน" ได้ จึงเป็นส่วนที่พังแล้วเจ็บที่สุด
สิ่งที่เทสต์ชุดนี้กันไว้คือ 2 ความผิดพลาดคนละทิศ:
  - false negative: เว็บหลอกเลียนแบบแบรนด์แล้วไม่ถูกจับ (อันตรายกับผู้ใช้)
  - false positive: โดเมนทางการโดนตีว่าปลอม (ผู้ใช้เลิกเชื่อระบบ)
"""
from analyzer.url_parser import parse_url
from analyzer.heuristics import analyze, levenshtein, normalize_glyphs


def signal_ids(url: str) -> set:
    """ยิงลิงก์เข้าไปหนึ่งอัน คืนเซ็ตของ id สัญญาณที่จับได้ — ใช้ช่วยให้เทสต์อ่านง่าย"""
    return {s["id"] for s in analyze(parse_url(url))["signals"]}


class TestLevenshtein:
    def test_เหมือนกันเป๊ะได้ศูนย์(self):
        assert levenshtein("google", "google") == 0

    def test_ต่างหนึ่งตัว(self):
        assert levenshtein("gogle", "google") == 1     # ขาดตัวอักษร
        assert levenshtein("googlee", "google") == 1   # เกินตัวอักษร
        assert levenshtein("goggle", "google") == 1    # สลับตัวอักษร

    def test_สตริงว่าง(self):
        assert levenshtein("", "abc") == 3
        assert levenshtein("abc", "") == 3
        assert levenshtein("", "") == 0


class TestNormalizeGlyphs:
    def test_ตัวเลขที่หน้าตาเหมือนตัวอักษร(self):
        assert normalize_glyphs("g00gle") == "google"
        assert normalize_glyphs("paypa1") == "paypal"
        assert normalize_glyphs("micr0s0ft") == "microsoft"

    def test_คู่ตัวอักษรที่รวมกันแล้วดูเป็นตัวเดียว(self):
        assert normalize_glyphs("rnicrosoft") == "microsoft"   # rn -> m
        assert normalize_glyphs("vvallet") == "wallet"         # vv -> w

    def test_แปลงเป็นตัวเล็กเสมอ(self):
        assert normalize_glyphs("GOOGLE") == "google"


class Testโดเมนทางการต้องไม่โดนตีว่าปลอม:
    def test_โดเมนแบรนด์ตรงเป๊ะได้ปลอดภัย(self):
        result = analyze(parse_url("https://www.google.com/search?q=a"))
        assert result["verified_safe"] is True
        assert result["legit_brand"] == "google"
        assert result["score"] == 0

    def test_โดเมนแบรนด์แบบไทย(self):
        result = analyze(parse_url("https://shopee.co.th/mall"))
        assert result["verified_safe"] is True
        assert result["legit_brand"] == "shopee"

    def test_ปลอดภัยแล้วต้องลัดออกทันทีไม่เก็บสัญญาณลบ(self):
        """แม้ลิงก์จะยาวหรือมีคำล่อ ถ้าโดเมนเป็นของทางการต้องไม่มีสัญญาณเสี่ยงติดมา"""
        result = analyze(parse_url("https://www.google.com/verify-account-urgent-" + "x" * 80))
        assert result["verified_safe"] is True
        assert [s["id"] for s in result["signals"]] == ["verified_brand"]


class Testจับการเลียนแบบแบรนด์:
    def test_ชื่อแบรนด์อยู่ในลิงก์แต่โดเมนไม่ใช่ของแบรนด์(self):
        result = analyze(parse_url("https://secure-facebook-login.xyz/"))
        assert "brand_impersonation" in {s["id"] for s in result["signals"]}
        assert result["verified_safe"] is False

    def test_แบรนด์เป็นsubdomainของเว็บอื่น(self):
        assert "brand_impersonation" in signal_ids("https://google.com.login.evil.xyz/")

    def test_typosquattingสะกดผิดหนึ่งตัว(self):
        assert "typosquatting" in signal_ids("https://gooogle.com/")

    def test_typosquattingซ่อนแบรนด์ด้วยเลข(self):
        """g00gle / micr0s0ft — จับได้จากการ normalize glyph ก่อนเทียบ"""
        assert "typosquatting" in signal_ids("https://g00gle.com/")
        assert "typosquatting" in signal_ids("https://paypa1.com/")


class Testสัญญาณเสี่ยงรายข้อ:
    def test_ใช้เลขipแทนชื่อเว็บ(self):
        assert "ip_host" in signal_ids("http://203.0.113.10/login.php")

    def test_ซ่อนปลายทางด้วยat(self):
        assert "userinfo_at" in signal_ids("http://www.paypal.com@evil.xyz/")

    def test_punycode(self):
        assert "punycode" in signal_ids("https://xn--80ak6aa92e.com/")

    def test_นามสกุลเสี่ยง(self):
        assert "risky_tld" in signal_ids("https://freegift.tk/")

    def test_subdomainซ้อนหลายชั้น(self):
        assert "deep_subdomain" in signal_ids("https://a.b.c.d.example.org/")

    def test_ลิงก์ย่อ(self):
        assert "shortener" in signal_ids("https://bit.ly/3xYz")

    def test_คำล่อให้กด(self):
        ids = signal_ids("https://unknown-site.org/verify-account-suspended/")
        assert "lure_keyword" in ids

    def test_ขีดหลายตัวในชื่อโดเมน(self):
        assert "many_hyphens" in signal_ids("https://secure-login-verify.org/")

    def test_ไม่ใช่https(self):
        assert "no_https" in signal_ids("http://example.org/")

    def test_httpsไม่ติดสัญญาณnohttps(self):
        assert "no_https" not in signal_ids("https://example.org/")

    def test_พอร์ตแปลก(self):
        assert "weird_port" in signal_ids("http://example.org:8888/")
        assert "weird_port" not in signal_ids("http://example.org:80/")

    def test_ลิงก์ยาวผิดปกติ(self):
        assert "long_url" in signal_ids("https://example.org/" + "a" * 100)


class Testการรวมคะแนน:
    def test_คะแนนเท่ากับผลรวมของสัญญาณ(self):
        result = analyze(parse_url("http://paypal-secure-verify.tk@1.2.3.4/urgent"))
        assert result["score"] == sum(s["points"] for s in result["signals"])

    def test_ลิงก์หลอกครบเครื่องต้องได้คะแนนสูง(self):
        """RED_SCORE = 6 — ลิงก์แบบนี้ต้องทะลุเกณฑ์แดงไปไกล"""
        result = analyze(parse_url("http://secure-paypal-verify-login.tk/account-suspended"))
        assert result["score"] >= 6

    def test_โดเมนธรรมดาที่ไม่รู้จักต้องไม่ได้คะแนนสูง(self):
        """เว็บทั่วไปที่ระบบไม่รู้จักควรลงเอยเป็น "เหลือง" ไม่ใช่ "แดง" """
        result = analyze(parse_url("https://somerandomblog.org/article/1"))
        assert result["score"] < 6


class Testแยกน้ำหนักตามตำแหน่งที่พบชื่อแบรนด์:
    """ชื่อแบรนด์ในโฮสต์ = เจตนาปลอม / ใน path = เว็บข่าวก็ทำ / โดเมนชื่อแบรนด์เป๊ะ
    บน TLD ที่ไม่รู้จัก = ตัดสินจากชื่อไม่ได้ — สามกรณีนี้ต้องได้คนละสัญญาณ"""

    def test_แบรนด์ในโฮสต์ยังเป็นimpersonation(self):
        assert "brand_impersonation" in signal_ids("https://facebook-security-alert.com/")

    def test_แบรนด์ในpathเป็นแค่ข้อสังเกตไม่ใช่critical(self):
        result = analyze(parse_url("https://www.bbc.com/news/technology-apple-iphone-review"))
        ids = {s["id"] for s in result["signals"]}
        assert "brand_in_path" in ids
        assert "brand_impersonation" not in ids
        assert not any(s["severity"] == "critical" for s in result["signals"])

    def test_เว็บสารานุกรมพูดถึงแบรนด์ต้องไม่แดง(self):
        result = analyze(parse_url("https://en.wikipedia.org/wiki/PayPal"))
        assert not any(s["severity"] == "critical" for s in result["signals"])
        assert result["score"] < 6

    def test_โดเมนชื่อแบรนด์เป๊ะบนTLDนอกลิสต์ได้bare_domain(self):
        result = analyze(parse_url("https://amazon.xyz/"))
        ids = {s["id"] for s in result["signals"]}
        assert "brand_bare_domain" in ids
        assert "brand_impersonation" not in ids


class Testจับแบรนด์ผ่านalias:
    """มิจฉาชีพใช้ชื่อเต็ม/ชื่อผลิตภัณฑ์ที่คนจำได้ ไม่ใช่ label สั้น ๆ ของเรา"""

    def test_ชื่อเต็มธนาคารไทย(self):
        assert "brand_impersonation" in signal_ids("https://kasikorn-bank-verify.com/login")
        assert "brand_impersonation" in signal_ids("https://krungthai-update.top/otp")
        assert "brand_impersonation" in signal_ids("https://scbeasy-net.com/login")

    def test_ชื่อผลิตภัณฑ์สากล(self):
        assert "brand_impersonation" in signal_ids("https://icloud-verify.com/")
        assert "brand_impersonation" in signal_ids("https://outlook-security.net/")

    def test_โดเมนจริงที่เพิ่มใหม่ต้องได้เขียว(self):
        assert analyze(parse_url("https://login.microsoftonline.com/x"))["verified_safe"] is True
        assert analyze(parse_url("https://www.amazon.co.jp/dp/B0"))["verified_safe"] is True


class Testtyposquattingต้องไม่กินคำสามัญ:
    """แบรนด์ชื่อสั้น (4 ตัว) มีคำจริงที่ห่างแค่ 1 ตัวอักษรเยอะมาก
    tree~true, lime~line, zoo~zoom เคยขึ้นแดงทั้งที่เป็นเว็บปกติ"""

    def test_คำสามัญใกล้แบรนด์สั้นไม่โดน(self):
        assert "typosquatting" not in signal_ids("https://www.tree.com/")
        assert "typosquatting" not in signal_ids("https://www.lime.com/")
        assert "typosquatting" not in signal_ids("https://www.zoo.org/")

    def test_แบรนด์ยาวสะกดเพี้ยนยังโดน(self):
        assert "typosquatting" in signal_ids("https://gooogle.com/")

    def test_แบรนด์สั้นที่ใช้เลขแทนตัวอักษรยังโดน(self):
        """glyph_same ไม่เกี่ยวกับเกณฑ์ความยาว — l1ne ต้องโดนเสมอ"""
        assert "typosquatting" in signal_ids("https://l1ne.me.evil.com/") or \
               "typosquatting" in signal_ids("https://l1ne.com/")


class Testคำล่อแบบมีขอบเขตคำ:
    def test_คำสามัญที่มีคำล่อฝังในตัวไม่โดน(self):
        """win ใน windows, free ใน freedom — substring เดิมกินหมด"""
        assert "lure_keyword" not in signal_ids("https://www.windows.com/download")
        assert "lure_keyword" not in signal_ids("https://freedomhouse.org/")

    def test_คำล่อคั่นด้วยขีดหรือทับยังโดน(self):
        assert "lure_keyword" in signal_ids("https://unknown-site.org/verify-account/")
        assert "lure_keyword" in signal_ids("https://example.org/login")

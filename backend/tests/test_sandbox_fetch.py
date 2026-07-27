# -*- coding: utf-8 -*-
"""
test_sandbox_fetch.py — เทสต์ตัวเรียก sandbox ฝั่งเครื่องหลัก

ยังไม่มีเครื่อง sandbox จริงตอนที่เขียนเทสต์ชุดนี้ แต่เทสต์ได้ครบเพราะสิ่งที่ต้อง
ตรวจคือ "เครื่องหลักรับมือกับคำตอบแบบต่าง ๆ ยังไง" ไม่ใช่ "Chromium ทำงานถูกไหม"

สิ่งที่กันไว้เป็นหลัก: **sandbox พังต้องไม่ทำให้การตรวจลิงก์พังตาม**
เครื่องที่สองล่ม/ตอบช้า/ตอบขยะ ต้องกลายเป็นแค่ "เช็กไม่ได้" ซึ่งตามหลักการของระบบ
ไม่ใช่ทั้ง "เสี่ยง" และไม่ใช่ "ปลอดภัย"
"""
import pytest

from analyzer import content_checker, sandbox_fetch


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text_body=None):
        self.status_code = status_code
        self._payload = payload
        self._text = text_body

    def json(self):
        if self._payload is None:
            raise ValueError("ไม่ใช่ JSON")
        return self._payload


GOOD_PAYLOAD = {
    "ok": True, "final_url": "https://evil.xyz/login", "status": 200,
    "html": "<html><body><form><input type=password></form></body></html>",
    "raw_html": "<html><body><div id=app></div></body></html>",
    "network_posts": [{"url": "https://collector.tk/x", "cross_origin": True}],
}


@pytest.fixture
def ตั้งค่าsandbox(monkeypatch):
    monkeypatch.setenv("SANDBOX_URL", "http://10.0.0.5:8900/fetch")
    monkeypatch.setenv("SANDBOX_TOKEN", "ความลับ")


def ให้sandboxตอบ(monkeypatch, response=None, raises=None):
    import requests

    def fake_post(url, **kwargs):
        if raises:
            raise raises
        return response

    monkeypatch.setattr(requests, "post", fake_post)


class Testยังไม่ได้ตั้งค่า:
    def test_ไม่ได้ตั้งค่าถือว่ายังไม่เปิดใช้(self, monkeypatch):
        monkeypatch.delenv("SANDBOX_URL", raising=False)
        assert sandbox_fetch.is_configured() is False

    def test_เรียกทั้งที่ยังไม่ตั้งค่าได้bundleเช็กไม่ได้(self, monkeypatch):
        monkeypatch.delenv("SANDBOX_URL", raising=False)
        b = sandbox_fetch.fetch_page("https://evil.xyz/")
        assert b["ok"] is False
        assert b["source"] == "sandbox"


class Testรับคำตอบที่ถูกต้อง:
    def test_แปลงเป็นbundleครบถ้วน(self, monkeypatch, ตั้งค่าsandbox):
        ให้sandboxตอบ(monkeypatch, FakeResponse(payload=GOOD_PAYLOAD))
        b = sandbox_fetch.fetch_page("https://evil.xyz/login")

        assert b["ok"] is True
        assert b["js_rendered"] is True          # จุดสำคัญ: บอกว่ารัน JS มาแล้ว
        assert b["source"] == "sandbox"
        assert b["network_posts"] == [{"url": "https://collector.tk/x",
                                       "cross_origin": True}]

    def test_ส่งtokenไปด้วย(self, monkeypatch, ตั้งค่าsandbox):
        captured = {}
        import requests

        def fake_post(url, **kwargs):
            captured.update(kwargs)
            return FakeResponse(payload=GOOD_PAYLOAD)

        monkeypatch.setattr(requests, "post", fake_post)
        sandbox_fetch.fetch_page("https://evil.xyz/login")
        assert captured["headers"]["Authorization"] == "Bearer ความลับ"

    def test_ไม่ยกฟิลด์แปลกปลอมจากอีกฝั่งเข้ามา(self, monkeypatch, ตั้งค่าsandbox):
        payload = dict(GOOD_PAYLOAD, เอาไปทำอะไรก็ไม่รู้="xxx", source="requests")
        ให้sandboxตอบ(monkeypatch, FakeResponse(payload=payload))
        b = sandbox_fetch.fetch_page("https://evil.xyz/login")

        assert "เอาไปทำอะไรก็ไม่รู้" not in b
        assert b["source"] == "sandbox"   # เชื่อค่าที่อีกฝั่งส่งมาไม่ได้


class Testsandboxพังต้องไม่ลากให้ระบบพังตาม:
    def test_ติดต่อไม่ได้(self, monkeypatch, ตั้งค่าsandbox):
        ให้sandboxตอบ(monkeypatch, raises=OSError("connection refused"))
        assert sandbox_fetch.fetch_page("https://evil.xyz/")["ok"] is False

    def test_ตอบhttpผิดพลาด(self, monkeypatch, ตั้งค่าsandbox):
        ให้sandboxตอบ(monkeypatch, FakeResponse(status_code=503))
        assert sandbox_fetch.fetch_page("https://evil.xyz/")["ok"] is False

    def test_ตอบมาไม่ใช่json(self, monkeypatch, ตั้งค่าsandbox):
        ให้sandboxตอบ(monkeypatch, FakeResponse(payload=None))
        assert sandbox_fetch.fetch_page("https://evil.xyz/")["ok"] is False

    def test_ตอบมาผิดรูปแบบ(self, monkeypatch, ตั้งค่าsandbox):
        ให้sandboxตอบ(monkeypatch, FakeResponse(payload={"ok": True}))
        assert sandbox_fetch.fetch_page("https://evil.xyz/")["ok"] is False

    def test_network_postsที่ผิดรูปแบบถูกคัดทิ้ง(self, monkeypatch, ตั้งค่าsandbox):
        payload = dict(GOOD_PAYLOAD, network_posts=["ไม่ใช่ dict", {}, {"url": "https://ok.tk/"}])
        ให้sandboxตอบ(monkeypatch, FakeResponse(payload=payload))
        posts = sandbox_fetch.fetch_page("https://evil.xyz/")["network_posts"]
        assert posts == [{"url": "https://ok.tk/", "cross_origin": False}]


class Testจังหวะที่ตัดสินใจเรียกsandbox:
    def ใช้หน้าเว็บเบา(self, monkeypatch, html):
        monkeypatch.setattr(content_checker, "fetch_page", lambda url: {
            "ok": True, "reason": "", "source": "requests", "js_rendered": False,
            "final_url": url, "status": 200, "html": html, "raw_html": html,
            "network_posts": []})

    def test_ไม่เรียกเมื่อยังไม่เปิดใช้(self, monkeypatch):
        monkeypatch.delenv("SANDBOX_URL", raising=False)
        self.ใช้หน้าเว็บเบา(monkeypatch, "<form><input type=password></form>")
        เรียกไปแล้ว = []
        monkeypatch.setattr(sandbox_fetch, "fetch_page",
                            lambda url: เรียกไปแล้ว.append(url))

        r = content_checker.analyze_content("https://evil.xyz/", "evil.xyz",
                                            allow_sandbox=True)
        assert เรียกไปแล้ว == []
        assert r["page_source"] == "requests"

    def test_ไม่เรียกเมื่อหน้าไม่มีช่องรหัสผ่าน(self, monkeypatch, ตั้งค่าsandbox):
        """หน้าธรรมดาไม่คุ้มกับการเสียเวลา 3-8 วินาที"""
        self.ใช้หน้าเว็บเบา(monkeypatch, "<html><body><p>หน้าเว็บธรรมดา</p></body></html>")
        เรียกไปแล้ว = []
        monkeypatch.setattr(sandbox_fetch, "fetch_page",
                            lambda url: เรียกไปแล้ว.append(url))

        content_checker.analyze_content("https://evil.xyz/", "evil.xyz", allow_sandbox=True)
        assert เรียกไปแล้ว == []

    def test_เรียกเมื่อเจอช่องรหัสผ่าน(self, monkeypatch, ตั้งค่าsandbox):
        self.ใช้หน้าเว็บเบา(monkeypatch, "<form><input type=password></form>")
        monkeypatch.setattr(sandbox_fetch, "fetch_page", lambda url: {
            "ok": True, "reason": "", "source": "sandbox", "js_rendered": True,
            "final_url": url, "status": 200, "html": GOOD_PAYLOAD["html"],
            "raw_html": GOOD_PAYLOAD["raw_html"],
            "network_posts": GOOD_PAYLOAD["network_posts"]})

        r = content_checker.analyze_content("https://evil.xyz/", "evil.xyz",
                                            allow_sandbox=True)
        assert r["page_source"] == "sandbox"
        assert "js_post_cross_origin" in {s["id"] for s in r["signals"]}

    def test_sandboxล่มให้ใช้ผลรอบแรกต่อ(self, monkeypatch, ตั้งค่าsandbox):
        """หัวใจของการออกแบบ: เครื่องที่สองล่มแล้วเว็บหลักต้องยังตรวจลิงก์ได้เหมือนเดิม"""
        self.ใช้หน้าเว็บเบา(
            monkeypatch,
            '<form action="https://collector.tk/x"><input type=password></form>')
        monkeypatch.setattr(sandbox_fetch, "fetch_page",
                            lambda url: sandbox_fetch.empty_bundle("ติดต่อ sandbox ไม่ได้",
                                                                   source="sandbox"))

        r = content_checker.analyze_content("https://evil.xyz/", "evil.xyz",
                                            allow_sandbox=True)
        assert r["checked"] is True
        assert r["page_source"] == "requests"
        assert "form_action_mismatch" in {s["id"] for s in r["signals"]}

    def test_ไม่เรียกเมื่อสั่งห้ามไว้(self, monkeypatch, ตั้งค่าsandbox):
        """ชั้น 1-3 ฟันธงแดงไปแล้ว การรัน JS เพิ่มไม่เปลี่ยนคำตอบ มีแต่ทำให้ช้า"""
        self.ใช้หน้าเว็บเบา(monkeypatch, "<form><input type=password></form>")
        เรียกไปแล้ว = []
        monkeypatch.setattr(sandbox_fetch, "fetch_page",
                            lambda url: เรียกไปแล้ว.append(url))

        content_checker.analyze_content("https://evil.xyz/", "evil.xyz", allow_sandbox=False)
        assert เรียกไปแล้ว == []

# -*- coding: utf-8 -*-
"""
test_sandbox_server.py — เทสต์บริการ sandbox ฝั่งที่ไม่ต้องใช้ Chromium

`sandbox_server.py` import playwright แบบ lazy (import ข้างในฟังก์ชัน) เทสต์ชุดนี้
จึงรันได้บนเครื่องที่ยังไม่ได้ติดตั้ง Chromium — ซึ่งสำคัญ เพราะส่วนที่เทสต์อยู่นี้คือ
**ส่วนที่กันไม่ให้เซิร์ฟเวอร์ตัวเองโดนหลอก** ไม่ใช่ส่วนที่วาดหน้าเว็บ

สิ่งที่กันไว้:
  - SSRF: หลอกให้ sandbox ยิงเข้าเครือข่ายภายในตัวเอง (127.x, 10.x, metadata คลาวด์)
  - เรียกใช้บริการโดยไม่มี token / token ผิด
  - ตั้งค่าพลาดจนบริการเปิดฟรีให้ใครก็เรียกได้
"""
import pytest

import sandbox_server as ss


class Testกันการยิงเข้าเครือข่ายภายใน:
    @pytest.mark.parametrize("host", [
        "127.0.0.1",          # ตัวเอง
        "10.0.0.5",           # วงภายใน
        "192.168.1.1",        # วงภายใน
        "172.16.0.1",         # วงภายใน
        "169.254.169.254",    # metadata ของผู้ให้บริการคลาวด์ — เป้าหมายยอดนิยม
        "0.0.0.0",
    ])
    def test_ipภายในต้องถูกปฏิเสธ(self, host):
        ip, reason = ss.resolve_safe_ip(host)
        assert ip is None
        assert reason

    def test_โฮสต์ว่างถูกปฏิเสธ(self):
        assert ss.resolve_safe_ip("")[0] is None

    def test_โดเมนที่ไม่มีจริงถูกปฏิเสธ(self):
        ip, reason = ss.resolve_safe_ip("ไม่มีโดเมนนี้จริง.invalid")
        assert ip is None

    def test_ipสาธารณะผ่านได้(self):
        ip, reason = ss.resolve_safe_ip("1.1.1.1")
        assert ip == "1.1.1.1"
        assert reason == ""


class Testบล็อกrequestที่ยิงไปยังipภายใน:
    @pytest.mark.parametrize("host,expected", [
        ("127.0.0.1", True),
        ("192.168.0.1", True),
        ("169.254.169.254", True),
        ("8.8.8.8", False),
        ("example.com", False),      # ชื่อโดเมนไม่ใช่เลข IP — ไม่ตัดสินที่ชั้นนี้
        ("", False),
    ])
    def test_ตรวจเลขipที่เขียนมาตรง(self, host, expected):
        assert ss._is_private_literal(host) is expected


class Testตัดสินว่าเป็นโดเมนเดียวกันไหม:
    def test_โดเมนเดียวกัน(self):
        assert ss._same_site("evil.xyz", "evil.xyz") is True

    def test_โดเมนย่อยนับเป็นเดียวกัน(self):
        assert ss._same_site("cdn.evil.xyz", "evil.xyz") is True
        assert ss._same_site("evil.xyz", "www.evil.xyz") is True

    def test_คนละโดเมน(self):
        assert ss._same_site("collector.tk", "evil.xyz") is False

    def test_ค่าว่าง(self):
        assert ss._same_site("", "evil.xyz") is False


class Testการตรวจtoken:
    def test_tokenถูกต้อง(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_TOKEN", "ความลับ")
        assert ss.token_ok("Bearer ความลับ") is True

    def test_tokenผิด(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_TOKEN", "ความลับ")
        assert ss.token_ok("Bearer เดามั่ว") is False

    def test_ไม่ส่งหัวข้อมาเลย(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_TOKEN", "ความลับ")
        assert ss.token_ok("") is False
        assert ss.token_ok(None) is False

    def test_ลืมคำว่าbearer(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_TOKEN", "ความลับ")
        assert ss.token_ok("ความลับ") is False

    def test_ยังไม่ได้ตั้งtokenต้องปฏิเสธทุกอย่าง(self, monkeypatch):
        """ตั้งค่าพลาดต้องกลายเป็น "ใช้ไม่ได้" ไม่ใช่ "เปิดให้ใครก็เรียกได้" """
        monkeypatch.delenv("SANDBOX_TOKEN", raising=False)
        assert ss.token_ok("Bearer อะไรก็ได้") is False
        assert ss.token_ok("Bearer ") is False


class Testรูปร่างของคำตอบตอนล้มเหลว:
    def test_มีคีย์ครบตามสัญญาpage_bundle(self):
        """ฝั่งเว็บหลักตรวจคีย์เหล่านี้ ถ้าขาดจะถือว่า sandbox ตอบผิดรูปแบบ"""
        b = ss._fail("ทดสอบ")
        assert set(b) >= {"ok", "final_url", "html", "raw_html"}
        assert b["ok"] is False
        assert b["reason"] == "ทดสอบ"

    def test_ลิงก์ที่ไม่ใช่httpถูกปฏิเสธก่อนเปิดเบราว์เซอร์(self):
        """ต้องไม่ไปถึงขั้น import playwright ด้วยซ้ำ"""
        assert ss.fetch_bundle("file:///etc/passwd")["ok"] is False
        assert ss.fetch_bundle("javascript:alert(1)")["ok"] is False

    def test_ลิงก์ชี้เข้าเครื่องตัวเองถูกปฏิเสธก่อนเปิดเบราว์เซอร์(self):
        b = ss.fetch_bundle("http://127.0.0.1:5000/api/health")
        assert b["ok"] is False
        assert "สงวนไว้" in b["reason"]


class Testอาร์กิวเมนต์ตอนเปิดchromium:
    def test_ปักหมุดdnsไว้ที่ipที่ตรวจแล้ว(self):
        """กัน DNS rebinding — Chromium ต้องไม่ resolve ชื่อโดเมนใหม่เอง"""
        args = ss._launch_args("evil.xyz", "93.184.216.34")
        assert "--host-resolver-rules=MAP evil.xyz 93.184.216.34" in args

    def test_ปกติต้องไม่ปิดsandboxของchromium(self, monkeypatch):
        monkeypatch.delenv("SANDBOX_NO_CHROME_SANDBOX", raising=False)
        assert "--no-sandbox" not in ss._launch_args("evil.xyz", "1.2.3.4")

    def test_ปิดได้เฉพาะเมื่อสั่งชัดเจน(self, monkeypatch):
        monkeypatch.setenv("SANDBOX_NO_CHROME_SANDBOX", "1")
        assert "--no-sandbox" in ss._launch_args("evil.xyz", "1.2.3.4")

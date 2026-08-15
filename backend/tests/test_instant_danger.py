# -*- coding: utf-8 -*-
"""
test_instant_danger.py — เทสต์การจับ "ลิงก์ที่อันตรายทันทีที่กด" ทั้งสามรูปแบบ:
  1) ตัวลิงก์คือโค้ด (javascript: / data: / vbscript:)
  2) โค้ดสคริปต์ซ่อนในพารามิเตอร์ (ลิงก์ยิง XSS)
  3) ปลายทางส่งไฟล์อันตรายทันที (.apk/.exe/ไฟล์บีบอัด) — ตัดสินจาก header จริง
ทุกเทสต์รันออฟไลน์ ไม่มีการยิงเครือข่าย
"""
from types import SimpleNamespace

from analyzer.url_parser import parse_url
from analyzer.heuristics import analyze
from analyzer.scanner import _scan_uncached, _destination_signals
from analyzer.destination_checker import _final_response_facts


def signal_ids(url: str) -> set:
    return {s["id"] for s in analyze(parse_url(url))["signals"]}


class Testลิงก์ที่ตัวมันเองคือโค้ด:
    def test_javascript_scheme_ถูกระบุว่าอันตรายไม่ใช่อ่านไม่ได้(self):
        p = parse_url("javascript:alert(document.cookie)")
        assert p["valid"] is False
        assert p["dangerous_scheme"] == "javascript"

    def test_จับได้ไม่สนตัวพิมพ์และรูปแบบมีslash(self):
        assert parse_url("JavaScript:void(0)")["dangerous_scheme"] == "javascript"
        assert parse_url("javascript://x%0aalert(1)")["dangerous_scheme"] == "javascript"

    def test_data_และ_vbscript(self):
        assert parse_url("data:text/html;base64,PHNjcmlwdD4=")["dangerous_scheme"] == "data"
        assert parse_url("vbscript:msgbox(1)")["dangerous_scheme"] == "vbscript"

    def test_scheme_ที่แค่ไม่ใช่เว็บยังเป็นแค่อ่านไม่ได้(self):
        """mailto:/tel: ไม่อันตราย — ต้องไม่ถูกเหมารวมเป็นแดง"""
        p = parse_url("mailto:someone@example.com")
        assert p["valid"] is False
        assert "dangerous_scheme" not in p

    def test_โดเมนที่มีพอร์ตต้องไม่ถูกเข้าใจผิดว่าเป็นschemeอันตราย(self):
        """regex จับ scheme จะ match "example.com:8080" ด้วย — แบบไม่มี http://
        นำหน้าถูกตีเป็นอ่านไม่ได้อยู่แล้ว (พฤติกรรมเดิม) แต่ต้องไม่กลายเป็น "อันตราย"
        และแบบมี scheme ครบต้องยังใช้งานได้ปกติ"""
        p = parse_url("example.com:8080/path")
        assert "dangerous_scheme" not in p
        assert parse_url("http://example.com:8080/path")["valid"] is True

    def test_scan_ให้คำตัดสินแดงเต็มรูปแบบโดยไม่ใช้เน็ต(self):
        result = _scan_uncached("javascript:alert(1)")
        assert result["ok"] is True
        assert result["verdict"]["color"] == "red"
        assert result["reasons"][0]["id"] == "script_scheme"
        # โครงผลลัพธ์ต้องครบให้ frontend ใช้ได้เหมือน scan ปกติ
        for key in ("anatomy", "destination", "layer4", "reasons", "score", "deep_check"):
            assert key in result


class Testโค้ดซ่อนในพารามิเตอร์:
    def test_payloadตรงๆ(self):
        assert "script_in_params" in signal_ids(
            "https://victim-site.com/search?q=<script>alert(1)</script>")

    def test_payloadเข้ารหัสpercent(self):
        assert "script_in_params" in signal_ids(
            "https://victim-site.com/page?x=%3Cscript%3Ealert(1)%3C%2Fscript%3E")

    def test_payloadเข้ารหัสซ้อนสองชั้น(self):
        assert "script_in_params" in signal_ids(
            "https://victim-site.com/page?x=%253Cscript%253Ealert(1)")

    def test_event_handler(self):
        assert "script_in_params" in signal_ids(
            "https://victim-site.com/img?src=x&y=1 onerror=alert(1)")

    def test_บทความเกี่ยวกับjavascriptต้องไม่โดน(self):
        """คำว่า javascript เฉย ๆ (ไม่มี colon) เป็นชื่อบทความ/หัวข้อปกติ"""
        assert "script_in_params" not in signal_ids(
            "https://blog.example.com/learn-javascript-in-30-days")
        assert "script_in_params" not in signal_ids(
            "https://en.wikipedia.org/wiki/JavaScript")


class Testลิงก์ชี้ไฟล์รันได้:
    def test_apkในpath(self):
        ids = signal_ids("https://files.example.com/app-update.apk")
        assert "executable_in_path" in ids

    def test_exeพร้อมquerystring(self):
        assert "executable_in_path" in signal_ids(
            "https://dl.example.com/setup.exe?token=abc")

    def test_ไฟล์เอกสารธรรมดาไม่โดน(self):
        assert "executable_in_path" not in signal_ids("https://example.com/report.pdf")
        assert "executable_in_path" not in signal_ids("https://example.com/page.html")


def _dest_with(content_type="", disposition_attachment=False, filename=""):
    return {"resolved": True, "chain": ["https://x.com"], "final_url": "https://x.com",
            "hops": 0, "final_response": {"content_type": content_type,
                                           "attachment": disposition_attachment,
                                           "filename": filename}}


class Testปลายทางส่งไฟล์ทันที:
    def test_apkจากชื่อไฟล์(self):
        sigs = _destination_signals(_dest_with(filename="update.apk"))
        assert sigs and sigs[0]["id"] == "instant_download_apk"
        assert sigs[0]["severity"] == "critical"

    def test_apkจากcontent_typeแม้ชื่อไฟล์เนียน(self):
        sigs = _destination_signals(_dest_with(
            content_type="application/vnd.android.package-archive",
            filename="document"))
        assert sigs and sigs[0]["id"] == "instant_download_apk"

    def test_exeจากcontent_type(self):
        sigs = _destination_signals(_dest_with(
            content_type="application/x-msdownload", filename="invoice.pdf.exe"))
        assert sigs and sigs[0]["id"] in ("instant_download_apk", "instant_download_exe")

    def test_zipแบบบังคับดาวน์โหลด(self):
        sigs = _destination_signals(_dest_with(
            content_type="application/zip", disposition_attachment=True,
            filename="photos.zip"))
        assert sigs and sigs[0]["id"] == "instant_download_archive"

    def test_หน้าเว็บปกติไม่มีสัญญาณ(self):
        assert _destination_signals(_dest_with(content_type="text/html",
                                                filename="")) == []

    def test_zipที่ไม่ได้บังคับโหลดไม่โดน(self):
        """ลิงก์ไปหน้าเว็บที่ *พูดถึง* zip (URL จบ .zip แต่เสิร์ฟ html) จัดการโดยเคสอื่น
        ที่นี่: zip แบบไม่มี attachment header = ผู้ใช้อาจตั้งใจโหลดเอง ให้ผ่าน"""
        assert _destination_signals(_dest_with(content_type="application/zip",
                                                filename="data.zip")) == []


class Testการอ่านheaderปลายทาง:
    def test_ชื่อไฟล์จากcontent_disposition(self):
        resp = SimpleNamespace(headers={
            "Content-Type": "application/octet-stream; charset=binary",
            "Content-Disposition": 'attachment; filename="malware.apk"'})
        facts = _final_response_facts(resp, "https://x.com/download?id=1")
        assert facts["filename"] == "malware.apk"
        assert facts["attachment"] is True
        assert facts["content_type"] == "application/octet-stream"

    def test_ชื่อไฟล์fallbackจากurl(self):
        resp = SimpleNamespace(headers={"Content-Type": "application/zip"})
        facts = _final_response_facts(resp, "https://x.com/files/backup.zip")
        assert facts["filename"] == "backup.zip"
        assert facts["attachment"] is False

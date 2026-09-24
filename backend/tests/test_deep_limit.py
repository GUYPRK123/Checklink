# -*- coding: utf-8 -*-
"""
test_deep_limit.py — เทสต์เพดานจำนวนการตรวจเชิงลึกที่ทำพร้อมกันได้

ปลายทางไฟล์จริง: backend/tests/test_deep_limit.py

สิ่งที่ต้องคุมไว้ให้แน่น มีสองข้อ:
  1) เต็มแล้วต้อง "ถอยไปตอบผลชั้น 1-2" ไม่ใช่ตอบ error และไม่ใช่รอค้างไม่มีกำหนด
     (หลักของระบบ: "เช็กไม่ได้" ต้องไม่กลายเป็นทั้ง "ปลอดภัย" และ "พัง")
  2) ผลที่ถอยแล้วต้องไม่ถูกเก็บลงช่องแคชของ "ผลเชิงลึก" ไม่งั้นลิงก์นั้นจะได้ผลตื้น
     ไปอีก 15 นาทีเต็มทั้งที่คิวว่างแล้ว — บั๊กที่หาไม่เจอถ้าไม่ได้ดักไว้ตรงนี้

ไม่แตะเครือข่ายเลย: ทุกทางที่ scanner จะออกเน็ตถูกแทนด้วยของปลอมเหมือน
test_scanner_combos.py
"""
import threading

import pytest

from analyzer import deep_limit, scan_cache, scanner


@pytest.fixture(autouse=True)
def เริ่มจากสถานะสะอาด(monkeypatch):
    deep_limit._reset_for_tests()
    scan_cache.clear()
    monkeypatch.setattr(scanner, "check_blacklist",
                        lambda url: {"found": False, "malicious": False})


class Testเพดานคิว:

    def test_ได้ที่ครบตามจำนวนแล้วตัวถัดไปต้องถูกปฏิเสธ(self, monkeypatch):
        """ตัวที่เกินเพดานต้องได้ False ภายในเวลาที่กำหนด ไม่ใช่รอค้างตลอดกาล"""
        monkeypatch.setattr(deep_limit, "WAIT_TIMEOUT", 0.05)
        ได้ = [deep_limit.acquire() for _ in range(deep_limit.MAX_CONCURRENT)]
        try:
            assert all(ได้)
            assert deep_limit.acquire() is False
            assert deep_limit.stats()["skipped"] == 1
        finally:
            for _ in ได้:
                deep_limit.release()

    def test_คืนที่แล้วคนถัดไปได้ที่ทันที(self):
        """คิวต้องเดินต่อได้ ไม่ใช่ตันถาวรหลังชนเพดานครั้งแรก"""
        ได้ = [deep_limit.acquire() for _ in range(deep_limit.MAX_CONCURRENT)]
        deep_limit.release()
        assert deep_limit.acquire() is True
        for _ in ได้:
            deep_limit.release()

    def test_นับจำนวนที่ใช้อยู่ถูกต้องเมื่อหลาย_thread_เข้าพร้อมกัน(self):
        """ตัวนับถูกอ่าน/เขียนจากหลาย thread จริง (waitress 16 thread + bulk)
        ถ้าลืม lock ตัวเลขจะเพี้ยนแบบสุ่มซึ่งไล่ยากมาก"""
        เสร็จ = threading.Barrier(deep_limit.MAX_CONCURRENT + 1, timeout=5)

        def ทำงาน():
            with deep_limit.slot() as ได้ที่:
                assert ได้ที่ is True
                เสร็จ.wait()

        threads = [threading.Thread(target=ทำงาน) for _ in range(deep_limit.MAX_CONCURRENT)]
        for t in threads:
            t.start()
        เสร็จ.wait()
        for t in threads:
            t.join(timeout=5)
        assert deep_limit.stats()["in_use"] == 0
        assert deep_limit.stats()["peak_in_use"] == deep_limit.MAX_CONCURRENT

    def test_ปิดเพดานได้ด้วยการตั้งเป็นศูนย์(self):
        """ทางหนีไฟเวลาต้องพิสูจน์ว่าอาการที่เจอไม่ได้มาจากตัวนี้ — ต้องยังนับสถิติอยู่"""
        เดิม = deep_limit._slots
        deep_limit._slots = None
        try:
            assert deep_limit.acquire() is True
            assert deep_limit.stats()["granted"] == 1
            deep_limit.release()
        finally:
            deep_limit._slots = เดิม


class Testscannerถอยไปชั้นตื้นเมื่อคิวเต็ม:

    def _ทำให้คิวเต็ม(self, monkeypatch):
        monkeypatch.setattr(deep_limit, "acquire", lambda: False)

    def test_ผลที่ได้คือชั้น_1_2_ครบ_ไม่ใช่_error(self, monkeypatch):
        self._ทำให้คิวเต็ม(monkeypatch)
        monkeypatch.setattr(scanner, "resolve_destination",
                            lambda url: pytest.fail("ต้องไม่ยิงชั้นที่ 3 เมื่อคิวเต็ม"))

        result = scanner.scan("http://example.com/promo", run_deep=True)

        assert result["ok"] is True
        assert result["verdict"]["color"] in ("green", "yellow", "red")
        assert result["anatomy"]                      # ผลชั้น 1-2 ยังครบ
        assert result["deep_check"]["ran"] is False
        assert result["deep_check"]["skipped_reason"] == "server_busy"
        assert result["deep_check"]["message"]
        assert result["layer4"]["ran"] is False

    def test_ไม่ใช้คำว่า_locked_reason_เพราะไม่ได้ติดเรื่องสิทธิ์(self, monkeypatch):
        """หน้าเว็บใช้ locked_reason เป็นตัวตัดสินว่าจะโชว์ปุ่มชวนอัพเกรดพรีเมียม
        ถ้าเอาคีย์นั้นมาใช้กับ "ระบบแน่น" สมาชิกที่จ่ายเงินแล้วจะโดนชวนให้จ่ายอีก"""
        self._ทำให้คิวเต็ม(monkeypatch)
        result = scanner.scan("http://example.com/promo", run_deep=True)
        assert "locked_reason" not in result["deep_check"]

    def test_ผลที่ถอยแล้วต้องไม่ไปนั่งในช่องแคชของผลเชิงลึก(self, monkeypatch):
        self._ทำให้คิวเต็ม(monkeypatch)
        url = "http://example.com/cached-shallow"

        scanner.scan(url, run_deep=True)

        assert scan_cache.get(url, True) is None, "ผลตื้นไปนั่งในช่องของผลเชิงลึก"
        เก็บไว้ = scan_cache.get(url, False)
        assert เก็บไว้ is not None and เก็บไว้["deep_check"]["ran"] is False

    def test_คิวว่างแล้วกลับมาตรวจเชิงลึกได้ตามปกติ(self, monkeypatch):
        """หลังจากคิวว่าง ลิงก์เดิมต้องได้ผลเชิงลึกจริง ไม่ติดผลตื้นค้างจากรอบก่อน"""
        url = "http://example.com/recover"
        self._ทำให้คิวเต็ม(monkeypatch)
        assert scanner.scan(url, run_deep=True)["deep_check"]["ran"] is False

        monkeypatch.setattr(deep_limit, "acquire", lambda: True)
        monkeypatch.setattr(deep_limit, "release", lambda: None)
        monkeypatch.setattr(scanner, "resolve_destination",
                            lambda u: {"resolved": True, "chain": [u], "final_url": u,
                                       "hops": 0, "blocked": False})
        monkeypatch.setattr(scanner, "_run_layer4",
                            lambda parsed, allow_sandbox=False: ([], {
                                "ran": True, "domain_age": {"checked": False},
                                "ssl": {"checked": False}, "content_checked": False,
                                "content_facts": [], "combos_hit": [], "page_source": ""}))

        ผลใหม่ = scanner.scan(url, run_deep=True)
        assert ผลใหม่["deep_check"]["ran"] is True

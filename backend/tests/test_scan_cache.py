# -*- coding: utf-8 -*-
"""
test_scan_cache.py — เทสต์แคชผลการตรวจ

แคชที่ผิดพลาดอันตรายกว่าไม่มีแคช เพราะมันจะ "จำคำตอบผิดไว้แล้วตอบซ้ำ" เทสต์ชุดนี้จึง
เน้น 3 เรื่องที่พลาดแล้วเจ็บ:
  - แยก key ระหว่างตรวจธรรมดากับตรวจเชิงลึก (คนละผลลัพธ์ ห้ามปนกัน)
  - ผลที่ล้มเหลวต้องไม่ถูกจำ (ไม่งั้นเน็ตสะดุดทีเดียวค้าง 15 นาที)
  - หมดอายุจริงตามเวลา
"""
import time

import pytest

from analyzer import scan_cache


@pytest.fixture(autouse=True)
def แคชสะอาดก่อนทุกเทสต์():
    scan_cache.clear()
    yield
    scan_cache.clear()


OK_RESULT = {"ok": True, "input": "https://example.com",
             "verdict": {"color": "green", "label": "ปลอดภัย"}}


class Testเก็บและดึง:
    def test_ยังไม่เคยเก็บต้องได้None(self):
        assert scan_cache.get("https://example.com", True) is None

    def test_เก็บแล้วดึงกลับมาได้(self):
        scan_cache.put("https://example.com", True, OK_RESULT)
        got = scan_cache.get("https://example.com", True)
        assert got["verdict"]["color"] == "green"

    def test_ผลที่มาจากแคชต้องติดธงบอก(self):
        """หน้าเว็บ/คนอ่าน log ต้องแยกออกว่าอันไหนตรวจสด อันไหนของเก่า"""
        scan_cache.put("https://example.com", True, OK_RESULT)
        got = scan_cache.get("https://example.com", True)
        assert got["cached"] is True
        assert got["cached_age_sec"] >= 0

    def test_ช่องว่างหัวท้ายไม่ทำให้พลาดแคช(self):
        scan_cache.put("https://example.com", True, OK_RESULT)
        assert scan_cache.get("  https://example.com  ", True) is not None

    def test_แก้ผลที่ได้มาต้องไม่กระทบของในแคช(self):
        scan_cache.put("https://example.com", True, OK_RESULT)
        got = scan_cache.get("https://example.com", True)
        got["verdict"] = {"color": "red"}
        assert scan_cache.get("https://example.com", True)["verdict"]["color"] == "green"


class Testแยกkeyให้ถูก:
    def test_ตรวจธรรมดากับตรวจเชิงลึกต้องคนละช่อง(self):
        """ผลของ run_deep=False ไม่มีข้อมูลชั้น 3-4 ถ้าปนกันผู้ใช้พรีเมียมจะได้ผลตื้น ๆ
        ของคนที่ไม่ได้ล็อกอินไปแทน"""
        scan_cache.put("https://example.com", False, OK_RESULT)
        assert scan_cache.get("https://example.com", False) is not None
        assert scan_cache.get("https://example.com", True) is None

    def test_คนละลิงก์คนละช่อง(self):
        scan_cache.put("https://a.com", True, OK_RESULT)
        assert scan_cache.get("https://b.com", True) is None


class Testสิ่งที่ต้องไม่ถูกจำ:
    def test_ผลที่ล้มเหลวต้องไม่ถูกเก็บ(self):
        scan_cache.put("https://x.com", True, {"ok": False, "error": "เน็ตล่ม"})
        assert scan_cache.get("https://x.com", True) is None

    def test_ของที่ไม่ใช่dictต้องไม่ทำให้พัง(self):
        scan_cache.put("https://x.com", True, None)
        assert scan_cache.get("https://x.com", True) is None


class Testหมดอายุและขนาด:
    def test_หมดอายุตามTTL(self, monkeypatch):
        monkeypatch.setattr(scan_cache, "TTL", 1)
        scan_cache.put("https://example.com", True, OK_RESULT)
        assert scan_cache.get("https://example.com", True) is not None
        time.sleep(1.05)
        assert scan_cache.get("https://example.com", True) is None

    def test_TTLศูนย์คือปิดแคช(self, monkeypatch):
        monkeypatch.setattr(scan_cache, "TTL", 0)
        scan_cache.put("https://example.com", True, OK_RESULT)
        assert scan_cache.get("https://example.com", True) is None

    def test_เกินจำนวนสูงสุดต้องทิ้งตัวเก่าสุดก่อน(self, monkeypatch):
        monkeypatch.setattr(scan_cache, "MAX_ENTRIES", 3)
        for i in range(5):
            scan_cache.put(f"https://site{i}.com", True, OK_RESULT)
        assert scan_cache.stats()["entries"] == 3
        assert scan_cache.get("https://site0.com", True) is None   # เก่าสุด ถูกทิ้ง
        assert scan_cache.get("https://site4.com", True) is not None

    def test_ตัวที่เพิ่งถูกใช้ต้องไม่ใช่ตัวที่ถูกทิ้งก่อน(self, monkeypatch):
        """LRU: อ่านแล้วต้องถือว่า "สด" ไม่งั้นลิงก์ยอดฮิตจะโดนทิ้งทั้งที่ใช้บ่อยที่สุด"""
        monkeypatch.setattr(scan_cache, "MAX_ENTRIES", 3)
        for i in range(3):
            scan_cache.put(f"https://site{i}.com", True, OK_RESULT)
        scan_cache.get("https://site0.com", True)      # แตะตัวเก่าสุดให้กลายเป็นตัวล่าสุด
        scan_cache.put("https://site3.com", True, OK_RESULT)
        assert scan_cache.get("https://site0.com", True) is not None
        assert scan_cache.get("https://site1.com", True) is None


class Testสถิติ:
    def test_นับhitและmiss(self):
        scan_cache.get("https://example.com", True)          # miss
        scan_cache.put("https://example.com", True, OK_RESULT)
        scan_cache.get("https://example.com", True)          # hit
        s = scan_cache.stats()
        assert s["hits"] == 1 and s["misses"] == 1
        assert s["hit_rate"] == 0.5

# -*- coding: utf-8 -*-
"""
test_anon_quota.py — เทสต์โควตาตรวจเชิงลึกต่อ IP ของผู้ไม่ล็อกอิน

จุดที่พังแล้วเจ็บ: ถ้านับพลาด ผู้ไม่ล็อกอินอาจตรวจเชิงลึกได้ไม่จำกัด (เครื่องโดนใช้เป็น
ตัวสแกนฟรีจนอืด) หรือกลับด้าน — ไม่ได้สิทธิ์เลยทั้งที่ควรได้ (ฟีเจอร์ที่ตั้งใจเปิดตายเงียบ)
เทสต์เป็น pure function ทั้งหมด: ไม่มีเน็ต ไม่มี Flask ไม่มีฐานข้อมูล
"""
from datetime import date, timedelta

import anon_quota


class Testโควตาต่อวัน:
    def setup_method(self):
        anon_quota.clear()

    def test_ใช้ได้จนถึงเพดานแล้วหยุด(self, monkeypatch):
        monkeypatch.setattr(anon_quota, "LIMIT", 2)
        ip = "198.51.100.7"
        assert anon_quota.allow(ip) is True
        anon_quota.record(ip)
        assert anon_quota.allow(ip) is True     # ใช้ไป 1 จาก 2
        anon_quota.record(ip)
        assert anon_quota.allow(ip) is False    # ครบเพดานของวันนี้แล้ว

    def test_คนละ_ip_คนละโควตา(self, monkeypatch):
        """IP หนึ่งใช้หมด ต้องไม่กระทบสิทธิ์ของ IP อื่น"""
        monkeypatch.setattr(anon_quota, "LIMIT", 1)
        anon_quota.record("198.51.100.7")
        assert anon_quota.allow("198.51.100.7") is False
        assert anon_quota.allow("198.51.100.8") is True

    def test_ขึ้นวันใหม่รีเซ็ตเอง(self, monkeypatch):
        """ตัวนับผูกกับวัน — ย้อนวันของ entry เป็นเมื่อวาน (white-box) แล้วสิทธิ์ต้องกลับมา
        และการใช้ครั้งแรกของวันใหม่ต้องเริ่มนับ 1 ไม่ใช่นับต่อจากเมื่อวาน"""
        monkeypatch.setattr(anon_quota, "LIMIT", 1)
        ip = "198.51.100.9"
        anon_quota.record(ip)
        assert anon_quota.allow(ip) is False
        anon_quota._counts[ip][0] = date.today() - timedelta(days=1)  # จำลองข้ามวัน
        assert anon_quota.allow(ip) is True
        anon_quota.record(ip)
        assert anon_quota._counts[ip] == [date.today(), 1]

    def test_ตั้งศูนย์คือปิดฟีเจอร์(self, monkeypatch):
        """ANON_DEEP_CHECKS_PER_DAY=0 = สวิตช์ถอยกลับพฤติกรรมเดิม (ต้องล็อกอิน)"""
        monkeypatch.setattr(anon_quota, "LIMIT", 0)
        assert anon_quota.allow("198.51.100.7") is False
        anon_quota.record("198.51.100.7")       # ต้องไม่พังและไม่เก็บอะไร
        assert anon_quota.stats()["tracked_ips"] == 0

    def test_ip_ว่างต้องไม่ได้สิทธิ์(self, monkeypatch):
        """fail-closed: ไม่รู้ว่าใครขอ = ไม่ให้ (remote_addr ว่างไม่ควรเกิด แต่กันไว้)"""
        monkeypatch.setattr(anon_quota, "LIMIT", 3)
        assert anon_quota.allow("") is False
        assert anon_quota.allow(None) is False

    def test_stats_ไม่เปิดเผย_ip(self, monkeypatch):
        monkeypatch.setattr(anon_quota, "LIMIT", 3)
        anon_quota.record("198.51.100.7")
        s = anon_quota.stats()
        assert s == {"limit_per_day": 3, "tracked_ips": 1}
        assert "198.51.100.7" not in str(s)

    def test_ตัวนับของวันเก่าถูกล้างเมื่อชนเพดานจำนวน_ip(self, monkeypatch):
        """กันหน่วยความจำบวม: เมื่อจำนวน IP ที่จำไว้เกินเพดาน entry ของวันก่อนต้องถูกทิ้ง"""
        monkeypatch.setattr(anon_quota, "LIMIT", 5)
        monkeypatch.setattr(anon_quota, "MAX_TRACKED_IPS", 2)
        yesterday = date.today() - timedelta(days=1)
        anon_quota._counts.update({
            "10.0.0.1": [yesterday, 5], "10.0.0.2": [yesterday, 5], "10.0.0.3": [yesterday, 5],
        })
        anon_quota.record("198.51.100.7")       # เกินเพดาน -> ล้างของเก่าก่อนบันทึก
        assert anon_quota.stats()["tracked_ips"] == 1
        assert "198.51.100.7" in anon_quota._counts

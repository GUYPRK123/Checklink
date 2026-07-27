# -*- coding: utf-8 -*-
"""
test_combos.py — เทสต์กฎการรวมสัญญาณ

กฎชุดนี้คือสิ่งที่เปลี่ยนหน้าฟิชชิ่งจริงจาก "เหลือง" เป็น "แดง" จึงต้องกัน 2 อย่าง:
  - ต้องจุดเมื่อสัญญาณมาครบชุดจริง ๆ
  - **ห้ามจุดจากการเดา** ถ้าชั้นไหนเช็กไม่ได้ สัญญาณของชั้นนั้นจะไม่อยู่ในเซ็ต
    ที่ส่งเข้ามา combo จึงต้องเงียบ ไม่ใช่คิดแทนผู้ใช้ว่า "น่าจะมี"
"""
from analyzer.combos import apply_combos
from analyzer.config import COMBO_RULES, RED_SCORE


def hit_ids(present: set) -> set:
    return {c["id"] for c in apply_combos(present)}


class Testจุดเมื่อครบชุด:
    def test_อ้างแบรนด์พร้อมขอรหัสผ่าน(self):
        assert "combo_brand_password" in hit_ids(
            {"content_brand_mismatch", "has_password_input"})

    def test_โดเมนใหม่เอี่ยมพร้อมขอรหัสผ่าน(self):
        assert "combo_new_domain_password" in hit_ids(
            {"has_password_input", "domain_very_new"})

    def test_ซ่อนแบรนด์พร้อมขอรหัสผ่านได้โบนัสสูงสุด(self):
        hits = apply_combos({"brand_hidden_in_text", "has_password_input"})
        assert hits[0]["points"] == 5

    def test_จุดหลายกฎพร้อมกันได้(self):
        got = hit_ids({"content_brand_mismatch", "js_obfuscated",
                       "has_password_input"})
        assert got == {"combo_brand_password", "combo_obfuscated_password"}


class Testห้ามจุดจากการเดา:
    def test_มีแค่ครึ่งเดียวไม่จุด(self):
        assert apply_combos({"content_brand_mismatch"}) == []
        assert apply_combos({"has_password_input"}) == []

    def test_เซ็ตว่างไม่จุด(self):
        assert apply_combos(set()) == []

    def test_ชั้นที่เช็กไม่ได้ไม่ถูกนับ(self):
        """ดึงหน้าเว็บไม่มา -> ไม่มี has_password_input ในเซ็ต แม้ RDAP จะบอกว่า
        โดเมนเพิ่งจดก็ตาม combo ต้องไม่จุด"""
        assert apply_combos({"domain_very_new", "risky_tld"}) == []

    def test_สัญญาณอื่นที่ไม่เกี่ยวไม่ทำให้จุด(self):
        assert apply_combos({"lure_keyword", "no_https", "long_url"}) == []


class Testรูปร่างของสัญญาณที่คืนมา:
    def test_มีครบทุกคีย์ที่หน้าเว็บต้องใช้(self):
        hit = apply_combos({"content_brand_mismatch", "has_password_input"})[0]
        assert set(hit) >= {"id", "title", "detail", "points", "severity"}

    def test_อธิบายได้ว่าเกิดจากอะไร(self):
        """หลักการของระบบคือ "อธิบายได้ ไม่ใช่กล่องดำ" — combo ต้องบอกที่มาได้"""
        hit = apply_combos({"content_brand_mismatch", "has_password_input"})[0]
        assert hit["combo_of"] == ["content_brand_mismatch", "has_password_input"]

    def test_ไม่ใช้severity_critical(self):
        """critical ทำให้ระบบฟันธงแดงทันทีโดยไม่ดูคะแนน ซึ่งแรงเกินไปสำหรับกฎที่
        สร้างจากสัญญาณอ่อนหลายตัวมารวมกัน ต้องปล่อยให้คะแนนรวมเป็นตัวตัดสิน"""
        for rule in COMBO_RULES:
            for hit in apply_combos(rule["needs"]):
                assert hit["severity"] != "critical"


class Testผลต่อคำตัดสินจริง:
    def test_อ้างแบรนด์บวกขอรหัสผ่านต้องทะลุเกณฑ์แดง(self):
        """content_brand_mismatch = 3 คะแนน ซึ่งเดิมได้แค่เหลือง
        พอบวกโบนัส combo 4 = 7 >= RED_SCORE จึงกลายเป็นแดงตามที่ตั้งใจ"""
        from analyzer.config import WEIGHTS
        base = WEIGHTS["content_brand_mismatch"][0]
        bonus = apply_combos({"content_brand_mismatch", "has_password_input"})[0]["points"]
        assert base + bonus >= RED_SCORE

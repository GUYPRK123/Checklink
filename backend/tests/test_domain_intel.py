# -*- coding: utf-8 -*-
"""
เทสต์การแกะข้อมูลจดทะเบียนโดเมนจาก RDAP JSON (_extract_registration)
ป้อนก้อน JSON ตัวอย่างตรง ๆ ไม่ยิงเน็ตจริง — โครง JSON อ้างอิงจากผลจริงของ
rdap.org (เช่น google.com -> registrar "MarkMonitor Inc.", scb.co.th ->
registrant มีตัวตนแต่ชื่อว่างเพราะถูกปิดตามนโยบายความเป็นส่วนตัว)
"""
from datetime import datetime, timedelta, timezone

from analyzer.domain_intel import _extract_registration


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _events(registered_days_ago=400, expires_in_days=None):
    now = datetime.now(timezone.utc)
    events = [{"eventAction": "registration",
               "eventDate": _iso(now - timedelta(days=registered_days_ago))}]
    if expires_in_days is not None:
        events.append({"eventAction": "expiration",
                       "eventDate": _iso(now + timedelta(days=expires_in_days))})
    return events


def _entity(roles, fn=None, org=None, entities=None):
    vcard_props = [["version", {}, "text", "4.0"]]
    if fn is not None:
        vcard_props.append(["fn", {}, "text", fn])
    if org is not None:
        vcard_props.append(["org", {}, "text", org])
    ent = {"roles": roles, "vcardArray": ["vcard", vcard_props]}
    if entities:
        ent["entities"] = entities
    return ent


class Testอายุโดเมนพื้นฐาน:
    def test_คำนวณอายุจากวันจดทะเบียน(self):
        res = _extract_registration({"events": _events(registered_days_ago=400)})
        assert res["checked"] is True
        assert res["age_days"] == 400

    def test_ไม่มีวันจดทะเบียน_ถือว่าเช็กไม่ได้(self):
        assert _extract_registration({"events": []}) == {"checked": False}
        assert _extract_registration({}) == {"checked": False}

    def test_วันจดทะเบียนอยู่ในอนาคต_ไม่เอามาใช้(self):
        res = _extract_registration({"events": _events(registered_days_ago=-5)})
        assert res == {"checked": False}

    def test_วันหมดอายุ(self):
        res = _extract_registration(
            {"events": _events(registered_days_ago=100, expires_in_days=265)})
        assert res["expires_on"] != ""
        # ไม่มี expiration event -> ช่องว่าง ไม่ใช่พัง
        res2 = _extract_registration({"events": _events()})
        assert res2["expires_on"] == ""


class Testผู้รับจดทะเบียน_registrar:
    def test_ดึงชื่อจาก_fn(self):
        data = {"events": _events(),
                "entities": [_entity(["registrar"], fn="MarkMonitor Inc.")]}
        res = _extract_registration(data)
        assert res["registrar"] == "MarkMonitor Inc."

    def test_ไม่มี_entity_ช่องว่าง(self):
        res = _extract_registration({"events": _events()})
        assert res["registrar"] == ""
        assert res["registrant"] == ""
        assert res["registrant_private"] is False


class Testผู้ถือครอง_registrant:
    def test_เปิดเผยชื่อ_แสดงตรง(self):
        data = {"events": _events(),
                "entities": [_entity(["registrant"], fn="Example Company Ltd.")]}
        res = _extract_registration(data)
        assert res["registrant"] == "Example Company Ltd."
        assert res["registrant_private"] is False

    def test_ชื่อว่าง_ถือว่าไม่เปิดเผย(self):
        # เคสจริงของ .th: มี entity registrant แต่ fn เป็นสตริงว่าง
        data = {"events": _events(),
                "entities": [_entity(["registrant", "administrative"], fn="")]}
        res = _extract_registration(data)
        assert res["registrant"] == ""
        assert res["registrant_private"] is True

    def test_ถูก_redact_ถือว่าไม่เปิดเผย(self):
        for masked in ("REDACTED FOR PRIVACY", "Private Person",
                       "Data Protected", "Whois Privacy Service"):
            data = {"events": _events(),
                    "entities": [_entity(["registrant"], fn=masked)]}
            res = _extract_registration(data)
            assert res["registrant"] == "", masked
            assert res["registrant_private"] is True, masked

    def test_ไม่มี_fn_ใช้_org_แทน(self):
        data = {"events": _events(),
                "entities": [_entity(["registrant"], org="Example Org")]}
        res = _extract_registration(data)
        assert res["registrant"] == "Example Org"

    def test_entity_ซ้อนใน_registrar_ก็เจอ(self):
        # บาง registry ซ้อน registrant ไว้ใต้ entity ของ registrar อีกชั้น
        inner = _entity(["registrant"], fn="Nested Owner Co.")
        data = {"events": _events(),
                "entities": [_entity(["registrar"], fn="Some Registrar",
                                     entities=[inner])]}
        res = _extract_registration(data)
        assert res["registrar"] == "Some Registrar"
        assert res["registrant"] == "Nested Owner Co."


class Testของแปลกต้องไม่พัง:
    def test_vcard_รูปร่างผิด_ไม่_crash(self):
        weird = [
            {"roles": ["registrar"]},                          # ไม่มี vcardArray
            {"roles": ["registrar"], "vcardArray": "junk"},    # ชนิดผิด
            {"roles": ["registrar"], "vcardArray": ["vcard"]}, # สั้นเกิน
            {"roles": ["registrant"],
             "vcardArray": ["vcard", [["fn", {}], ["fn", {}, "text", 42]]]},
            "not-a-dict",
        ]
        res = _extract_registration({"events": _events(), "entities": weird})
        assert res["checked"] is True
        assert res["registrar"] == ""
        # entity registrant รูปร่างผิดแต่มีตัวตน -> นับเป็น "ไม่เปิดเผย"
        assert res["registrant_private"] is True

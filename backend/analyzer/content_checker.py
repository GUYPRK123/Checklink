# -*- coding: utf-8 -*-
"""
content_checker.py
============================================================================
  >>> ชั้นที่ 4 ของระบบ (เสริม): วิเคราะห์เนื้อหาจริงของหน้าเว็บปลายทาง <<<
============================================================================
ทุกชั้นก่อนหน้านี้ดูแค่ "รูปร่างของ URL" เท่านั้น ไม่เคยเปิดดูว่าหน้าเว็บจริงมีอะไร
อยู่ข้างใน — แต่การหลอกเอาข้อมูล (credential harvesting) เกิดขึ้นที่ "ฟอร์ม" ใน
หน้าเว็บ ไม่ใช่ที่ตัว URL ชั้นนี้จึงดึงเนื้อหาจริงมาดู แล้วหารูปแบบที่พบบ่อยในเว็บ
ฟิชชิ่ง

**ตอนนี้ไฟล์นี้เป็นแค่ตัวประสานงานบาง ๆ** งานจริงถูกแยกออกเป็นสองส่วนที่ไม่รู้จักกัน:

    page_fetch.fetch_page(url)  ──► page bundle ──►  content_analyzer.analyze_page()
       (ดึงอย่างเดียว ต่อเน็ต)      (JSON ธรรมดา)         (วิเคราะห์ล้วน ไม่ต่อเน็ต)

เหตุผลของการแยก: ขั้นต่อไปคือใส่ sandbox (Chromium ที่รัน JavaScript จริง) มาเป็น
ตัวดึงอีกตัว เพราะชุดฟิชชิ่งสมัยใหม่ส่ง HTML เปล่ามาแล้วค่อยวาดหน้าล็อกอินด้วย JS
ซึ่งตัวดึงด้วย requests มองไม่เห็นเลย พอแยกกันแบบนี้แล้วการเปลี่ยนตัวดึงจะไม่กระทบ
ตัววิเคราะห์ และตัววิเคราะห์ยังเทสต์ได้โดยไม่ต้องมีเน็ต (ดู docs/content-analysis.md)

ปลอดภัยจาก SSRF เหมือนชั้นที่ 3: page_fetch เช็ก IP ปลอดภัยซ้ำก่อนต่อทุกครั้ง
จำกัดขนาดที่ดาวน์โหลด มี timeout และ **ไม่รัน JavaScript ใด ๆ ในหน้า**

ต้องติดตั้ง beautifulsoup4 (ดู requirements.txt) ถ้ายังไม่มีจะข้ามชั้นนี้ไปเงียบ ๆ
(เหมือนกับที่ระบบข้ามชั้นบัญชีดำไปได้ถ้า requests ไม่มี)
"""
from . import sandbox_fetch
from .content_analyzer import analyze_page
from .page_fetch import fetch_page


def _worth_sandbox(result: dict) -> bool:
    """คุ้มไหมที่จะเสียเวลา 3-8 วินาทีส่งหน้านี้เข้า sandbox

    sandbox ช้ากว่าการดึงแบบธรรมดาเกือบร้อยเท่า จึงห้ามเรียกทุกครั้ง เรียกเฉพาะ
    สองกรณีที่การรัน JavaScript จะเปลี่ยนคำตอบได้จริง:

      1) ดึงแบบเบา ๆ แล้วเจอช่องรหัสผ่าน — หน้าที่ขอรหัสผ่านคือหน้าที่ต้องรู้ให้แน่
         ว่าข้อมูลถูกส่งไปไหน ซึ่งดูจาก HTML อย่างเดียวไม่พอ
      2) ดึงแบบเบา ๆ ไม่สำเร็จเลย — บางเว็บกันบอตด้วยการบังคับให้รัน JS ก่อน
         Chromium จริงจึงอาจผ่านในกรณีที่ requests ไม่ผ่าน
    """
    return (not result["checked"]) or ("has_password_input" in result["facts"])


def analyze_content(url: str, page_registrable: str, allow_sandbox: bool = False) -> dict:
    """วิเคราะห์เนื้อหาหน้าเว็บปลายทาง (url) เทียบกับโดเมนจริงของหน้านั้น
    (page_registrable) คืน {"signals": [...], "checked": bool, "facts": [...],
    "page_source": str}

    checked=False หมายถึง "ดึงหน้าเว็บมาวิเคราะห์ไม่ได้" (ไม่มี bs4 / ต่อไม่ได้ /
    ไม่ใช่หน้า HTML) ต่างจาก checked=True + signals=[] ซึ่งหมายถึง "ดึงมาดูแล้ว
    ไม่พบสิ่งผิดปกติ" — หน้าเว็บควรแยกสองกรณีนี้ให้ผู้ใช้เห็น ไม่ใช่ปล่อยเงียบเหมือนกัน

    facts คือข้อเท็จจริงของหน้า (เช่น has_password_input) ที่ไม่ใช่สัญญาณเสี่ยงและ
    ไม่มีคะแนนในตัวเอง แต่ใช้เป็นเงื่อนไขของกฎการรวมสัญญาณ (ดู combos.py)

    ทำงานสองจังหวะเมื่อเปิดใช้ sandbox: ดึงเบา ๆ ด้วย requests ก่อนเสมอ (เร็วมาก
    ~0.05 วิ) แล้วค่อยตัดสินจากสิ่งที่เห็นว่าคุ้มจะส่งเข้า sandbox ต่อไหม
    **ถ้า sandbox ล้มเหลว ให้ใช้ผลจากรอบแรกต่อไป ไม่ทำให้การตรวจทั้งหมดพัง**
    """
    if not page_registrable:
        return {"signals": [], "checked": False, "facts": [], "page_source": ""}

    bundle = fetch_page(url)
    result = analyze_page(bundle, page_registrable)

    if allow_sandbox and sandbox_fetch.is_configured() and _worth_sandbox(result):
        sb_bundle = sandbox_fetch.fetch_page(url)
        if sb_bundle["ok"]:
            sb_result = analyze_page(sb_bundle, page_registrable)
            if sb_result["checked"]:
                bundle, result = sb_bundle, sb_result

    return {"signals": result["signals"], "checked": result["checked"],
            "facts": result["facts"], "page_source": bundle.get("source", "")}

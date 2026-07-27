# -*- coding: utf-8 -*-
"""
serve.py
จุดเริ่มของเซิร์ฟเวอร์ตอนใช้งานจริง (production) — ใช้แทนคำสั่ง waitress-serve

ทำไมต้องมีไฟล์นี้แทนที่จะสั่ง waitress-serve ตรง ๆ:

waitress **ลบ header X-Forwarded-* ทิ้งทั้งหมด** ก่อนส่งถึงแอปเป็นค่าเริ่มต้น
(clear_untrusted_proxy_headers=True, trusted_proxy=None) ซึ่งถูกต้องแล้วในแง่ความปลอดภัย
เพราะ header พวกนี้ปลอมได้ แต่ผลข้างเคียงคือเมื่อมี Nginx อยู่หน้าจริง ๆ แอปจะ:

  - เห็นผู้ใช้ทุกคนเป็น 127.0.0.1 (IP ของ Nginx) -> rate limit ทั้งเว็บใช้โควตาก้อนเดียวกัน
    คนเดียวยิงครบ 30 ครั้ง/นาที = ทุกคนโดนบล็อกตามไปด้วย
  - คิดว่าทุก request เป็น http -> ไม่ส่ง header HSTS แม้เว็บจะเป็น https แล้ว

การตั้งค่าที่ถูกคือบอก waitress ว่า "เชื่อ proxy ที่ 127.0.0.1 เท่านั้น" ซึ่งค่านี้ต้องเป็น
รายการที่คั่นด้วย **ช่องว่าง** (ไม่ใช่จุลภาค) และเขียนลง ExecStart ของ systemd ตรง ๆ แล้ว
เสี่ยงเรื่องเครื่องหมายคำพูด จึงย้ายมาไว้ในไฟล์นี้ให้อ่านง่ายและทดสอบได้

หมายเหตุ: เมื่อ waitress จัดการ X-Forwarded-* ให้แล้ว **ห้ามเปิด BEHIND_PROXY=true**
ใน .env อีก เพราะ ProxyFix จะไปตีความ header เดิมซ้ำอีกรอบ (ดูคอมเมนต์ใน config.py)

วิธีรัน:  cd backend && ./.venv/bin/python serve.py
"""
import os

from waitress import serve

from app import app

# IP ของ reverse proxy ที่เชื่อถือได้ — ตั้งเป็นค่าว่างเพื่อไม่เชื่อใครเลย
# (ใช้ตอนรันโดยไม่มี Nginx อยู่หน้า ซึ่งจะกลับไปใช้ IP ที่ต่อเข้ามาจริงตามปกติ)
TRUSTED_PROXY = os.environ.get("TRUSTED_PROXY", "127.0.0.1").strip() or None

# header ที่ยอมให้ proxy ที่เชื่อถือได้กำหนดมา คั่นด้วยช่องว่าง
TRUSTED_PROXY_HEADERS = set(
    os.environ.get("TRUSTED_PROXY_HEADERS",
                   "x-forwarded-for x-forwarded-proto x-forwarded-host").split())

if __name__ == "__main__":
    serve(
        app,
        # ผูกกับ 127.0.0.1 เท่านั้น: ให้เข้าถึงได้ผ่าน Nginx ทางเดียว
        # ถ้าจำเป็นต้องเปิดตรงชั่วคราว ตั้ง BIND_HOST=0.0.0.0 และอย่าลืมตั้ง
        # TRUSTED_PROXY="" ด้วย ไม่งั้นใครก็ปลอม X-Forwarded-For ข้าม rate limit ได้
        host=os.environ.get("BIND_HOST", "127.0.0.1"),
        port=int(os.environ.get("BIND_PORT", "5000")),
        # งานนี้รอเน็ตเป็นหลัก ไม่กิน CPU — thread ที่นั่งรออยู่เฉย ๆ แทบไม่เปลืองอะไร
        # ค่าเริ่มต้นของ waitress คือ 4 ซึ่งน้อยไปมากสำหรับการตรวจเชิงลึกที่ใช้เวลา 0.3-4 วิ
        threads=int(os.environ.get("WAITRESS_THREADS", "16")),
        trusted_proxy=TRUSTED_PROXY,
        trusted_proxy_headers=TRUSTED_PROXY_HEADERS,
        # ลบ X-Forwarded-* ที่มาจากที่อื่นนอกเหนือจาก proxy ที่เชื่อถือได้ทิ้งเสมอ
        clear_untrusted_proxy_headers=True,
    )

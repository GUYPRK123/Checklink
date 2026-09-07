# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

> เอกสาร คอมเมนต์ และ commit message ในโปรเจกต์นี้เป็นภาษาไทยทั้งหมด — เขียนของใหม่เป็นภาษาไทยให้เข้าชุดกัน
> README.md คือเอกสารหลัก (env vars ครบ, API, กับดัก) ไฟล์นี้เก็บเฉพาะสิ่งที่ต้องอ่านหลายไฟล์ถึงจะรู้

## ข้อจำกัดของสภาพแวดล้อมนี้ (สำคัญที่สุด — อ่านก่อน)

เครื่องนี้คือ **VPS ตัวเดียวกับ production** (https://checkurl.studiodup.com) ไม่ใช่เครื่องพัฒนา
Claude รันในชื่อผู้ใช้ `claudebot` ซึ่ง:

- **เขียนไฟล์ในรีโปไม่ได้** (`/home/checkurl/Checklink` เป็นของ `checkurl`) → Write/Edit ล้มด้วย `EACCES`
- **ไม่มี sudo** → `systemctl restart`, `journalctl -u`, log ของ nginx, `backend/.env`, `backend/instance/` เข้าไม่ได้ทั้งหมด

**วิธีทำงานที่ใช้ได้จริง:** เขียนไฟล์/สคริปต์ที่แก้แล้วลงที่ที่ผู้ใช้อ่านได้ (เช่น `/tmp/...` โหมด 755)
แล้วส่ง "ชุดคำสั่งพร้อมวาง" ให้ผู้ใช้รันเอง (พิมพ์ `! <คำสั่ง>` ในแชทเพื่อให้ผลกลับเข้ามาในบทสนทนา)
จากนั้น **ตรวจผลด้วยเครื่องมือ read-only ของตัวเอง** (`curl` ยิงเว็บจริง, `systemctl show`, `ss`) ไม่ใช่เชื่อคำบอกเล่า

ท่าที่ใช้ไล่ปัญหาได้แม้อ่าน journal ไม่ได้ — จำลอง import แอปโดยข้าม `.env` ที่อ่านไม่ได้:

```python
# python /tmp/impcheck.py  (รันด้วย backend/.venv/bin/python จากโฟลเดอร์ backend)
import dotenv, os, sys
dotenv.load_dotenv = lambda *a, **k: True          # .env อ่านไม่ได้ (โหมด 600 ของ checkurl)
os.environ.setdefault("SECRET_KEY", "x" * 32)
os.environ["WARMUP_URL"] = ""                       # ไม่ต้องยิงเน็ตตอนทดสอบ
os.environ["DATABASE_URL"] = "sqlite:///:memory:"   # instance/ อ่านไม่ได้
sys.path.insert(0, "/home/checkurl/Checklink/backend")
import app
```

เหมือนกัน — เทสต์รันในรีโปตรง ๆ ไม่ได้ถ้าต้องแก้ไฟล์ ให้ก๊อป `backend/{analyzer,tests,anon_quota.py,pytest.ini}`
กับ `sandbox/sandbox_server.py` ไปไว้ scratchpad ตามโครงเดิม แล้วรัน pytest จากตรงนั้นด้วย `.venv` ของจริง

## คำสั่งที่ใช้บ่อย

```bash
cd backend
./.venv/bin/python -m pytest                       # ทั้งชุด (~300 เทสต์, ไม่ยิงเน็ต, ไม่กี่วินาที)
./.venv/bin/python -m pytest tests/test_heuristics.py -q          # ไฟล์เดียว
./.venv/bin/python -m pytest -k homoglyph                          # กรองด้วยชื่อ (ชื่อเทสต์เป็นภาษาไทย)
./.venv/bin/python -m pytest "tests/test_heuristics.py::Testโดเมนพื้นที่ฝากเว็บฟรี" -q

./.venv/bin/python app.py                          # dev เท่านั้น (127.0.0.1:5000, DEBUG)
./.venv/bin/python serve.py                        # production — ห้ามใช้ waitress-serve ตรง ๆ
./.venv/bin/python run_eval.py --fast --limit 20   # ประเมินความแม่นกับ testset_100.json → .xlsx
```

**Deploy = `sudo /home/checkurl/Checklink/deploy/deploy.sh` เสมอ** (มี `DRY_RUN=1` ให้ลองก่อน)
สคริปต์รันเทสต์ → ลอง import แอป → สำรอง DB → restart → เช็ก `/api/health` + เฝ้า `NRestarts`
อย่ารีสตาร์ต service มือเปล่า เพราะ `Restart=always` จะซ่อนอาการ "สตาร์ตไม่ขึ้น" ไว้ในลูปรีสตาร์ตทุก 3 วินาที

ไม่มี build step / linter / formatter ฝั่ง frontend — vanilla ES modules เสิร์ฟจาก Flask ตรง ๆ

## เมื่อเว็บตอบ 502

502 = nginx ยังอยู่ แต่ waitress ไม่ได้ฟังที่ 127.0.0.1:5000 แปลว่าแอปสตาร์ตไม่ขึ้น (เกือบทุกครั้งคือพังตอน import)
ไล่ตามนี้: `systemctl show phishing-checker -p NRestarts` (เลขวิ่งขึ้น = ลูปรีสตาร์ต) → `ss -tlnp | grep 5000`
→ จำลอง import ด้วยสคริปต์ข้างบนเพื่อเอา traceback มาดูโดยไม่ต้องพึ่ง journal

## สถาปัตยกรรม

### backend — cascade 4 ชั้น
`analyzer/scanner.py` คือ orchestrator ตัวเดียวที่รู้ลำดับทั้งหมด โมดูลชั้นอื่นไม่รู้จักกันเอง และ
**ทั้งโฟลเดอร์ `analyzer/` จงใจไม่ผูกกับ Flask** (อ่าน env ตรง ๆ) เพื่อให้เทสต์ได้โดยไม่ต้องสร้างแอป

1. `blacklist_api.py` — บัญชีดำ สกมช. (`set` ในหน่วยความจำ + cache ลงดิสก์ TTL 6 ชม.)
2. `url_parser.py` → `heuristics.py` — วิเคราะห์รูปร่าง URL แบบออฟไลน์ (typosquat, homoglyph, `javascript:`, XSS ในพารามิเตอร์)
3. `destination_checker.py` — ตาม redirect หาปลายทางจริง แล้ววนชั้น 1-2 ซ้ำกับปลายทาง
4. `domain_intel.py` (RDAP + TLS) และ `content_checker.py`/`content_analyzer.py` (เนื้อหาหน้าเว็บ) รันขนานใน ThreadPool
   — ทำเฉพาะตอนชั้น 1-3 ยังไม่ฟันธง เพราะยิงเน็ตจริง 0.3-4 วิ. ถ้าตั้ง `SANDBOX_URL` จะดึงหน้าหลังรัน JS ผ่าน `sandbox_fetch.py`

จากนั้น `combos.py` ให้คะแนนเพิ่มกับ "ชุดสัญญาณที่มาด้วยกัน" (ต้องทำหลังรวมสัญญาณครบทุกชั้น) แล้ว `scanner.decide()` สรุปสี

**กติกาสีที่ห้ามแก้เล่น ๆ:** เขียว = *ยืนยันแล้วว่าปลอดภัย* เท่านั้น / แดง = อันตราย / **เหลือง = ที่เหลือทั้งหมด รวม "ไม่รู้จัก"**
ห้ามให้เขียวจากผลของ "ปลายทาง" อย่างเดียว และห้ามให้เขียวกับพื้นที่ฝากเว็บฟรี (`USER_CONTENT_DOMAINS`)
— เชื่อบริษัทเจ้าของโดเมนได้ แต่เชื่อเนื้อหาที่คนอื่นเอามาฝากไม่ได้ (github.io เคยได้เขียวให้หน้าฟิชชิงจริงมาแล้ว)

### จุดที่คนแก้โค้ดมักพลาด
- `backend/config.py` = ค่าตั้งของแอป (env) / `backend/analyzer/config.py` = ฐานความรู้การวิเคราะห์ (BRANDS, WEIGHTS, TLD) — คนละเรื่องกัน
  น้ำหนักคะแนนทุกตัวอยู่ใน `WEIGHTS` ที่เดียว พร้อมคอมเมนต์อธิบายเหตุผล — แก้ที่นั่น อย่ากระจายตัวเลขไปในกฎ
- `serve.py` มีอยู่เพราะ waitress ลบ `X-Forwarded-*` ทิ้งเป็นค่าเริ่มต้น ถ้าเลี่ยงไปใช้ `waitress-serve`
  ผู้ใช้ทุกคนจะกลายเป็น 127.0.0.1 คนเดียว → rate limit + โควตา anon พังทั้งระบบ
- เพราะ `serve.py` ตั้ง `trusted_proxy` ให้แล้ว **`BEHIND_PROXY` ใน `.env` ต้องเป็น false** ไม่งั้น ProxyFix ตีความ header ซ้ำสองรอบ
- สถานะทุกอย่างอยู่ใน "หน่วยความจำของ process เดียว" ทั้งหมด — `scan_cache.py`, `jobs.py`, `anon_quota.py`, rate limiter (`memory://`)
  รีสตาร์ต = หายหมด (ยอมรับได้) แต่ **ถ้าวันไหนรันหลาย process/หลายเครื่อง ทุกตัวนี้พังพร้อมกัน** ต้องย้ายไป Redis ก่อน
- bulk endpoint ตอบ **202 + `job_id`** แล้วให้ poll — ไม่ตอบผลตรง ๆ (กันงาน 8 วินาทีไปยึด thread ของ waitress)
- CSP เป็น `script-src 'self'` ล้วน ห้ามใส่ CDN กลับเข้ามา — jsQR ที่ถอดเลขบัญชีพร้อมเพย์ถูกเสิร์ฟจากเครื่องนี้เอง (`frontend/js/vendor/`)

### ระดับสิทธิ์ (ลิงก์และ QR ใช้กติกาเดียวกัน)
ไม่ล็อกอิน = ชั้น 1-2 จำกัด `ANON_CHECKS_PER_DAY` ครั้ง/วัน/IP · สมาชิกฟรี = ชั้น 1-2 ไม่จำกัด · พรีเมียม = เพิ่มชั้น 3-4 + bulk + export + API key
บังคับใช้ที่ `check.py` (`_anon_gate`, `_deep_check_decision`, `_premium_gate`) — การจ่ายเงินใน `billing.py` เป็น mock ทั้งหมด

### QR
`analyzer/qr_payload.py` ถอด payload ที่ไม่ใช่ลิงก์ได้ (พร้อมเพย์/EMVCo, Wi-Fi, tel, SMS, vCard, geo)
จุดสำคัญคือ **CRC-16 ของ QR พร้อมเพย์** — CRC ไม่ตรง = QR ถูกแก้ (เช่นเปลี่ยนเลขบัญชีปลายทาง) ตรวจได้โดยไม่ต้องต่อเน็ต
ถ้า payload เป็นลิงก์ จะถูกส่งเข้า cascade เดียวกันทุกประการ การถอด QR จากรูปทำที่ฝั่ง browser (`frontend/js/components/qrDecode.js`)

### sandbox/ — บริการแยก
เซิร์ฟเวอร์เล็ก ๆ ที่เปิดหน้าเว็บด้วย Chromium (Playwright) **ตั้งใจให้รันคนละเครื่องกับแอปหลัก** เพราะมันเปิดเว็บอันตรายจริง
แอปหลักคุยผ่าน `SANDBOX_URL` + `SANDBOX_TOKEN` และทำงานได้ตามปกติเมื่อไม่ได้ตั้งค่าไว้ (ตกไปอ่าน HTML ดิบแทน)
`pytest.ini` ใส่ `../sandbox` ไว้ใน pythonpath เพื่อให้เทสต์ของ sandbox รันรวมชุดเดียวกันได้

## แนวทางเทสต์
เทสต์ทั้งหมดเป็น pure function — **ห้ามยิงเน็ตหรือแตะฐานข้อมูล** ชื่อคลาส/ฟังก์ชันเทสต์เขียนเป็นภาษาไทย
เวลาเพิ่มกฎวิเคราะห์ใหม่ ต้องเทสต์ทั้งสองด้านเสมอ: เว็บหลอกต้องโดนจับ **และ** โดเมนทางการต้องไม่โดนตีว่าปลอม
`testset_100.json` + `run_eval.py` ใช้วัดความแม่นภาพรวม (ต้องมี pandas + openpyxl) — ลิงก์กลุ่ม `phish_fresh` ในนั้นเป็นเว็บหลอกที่ยังทำงานอยู่จริง อย่าเปิดเอง

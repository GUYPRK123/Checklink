# Checklink — เช็กก่อนกด

เว็บตรวจลิงก์/QR ว่าเป็นลิงก์หลอกลวงไหม (ภาษาไทย) — Flask เสิร์ฟทั้ง REST API และ frontend

Frontend เป็น vanilla JS + ES modules ไม่มี build step

---

## โปรเจกต์นี้ทำอะไร

รับ URL เข้ามาแล้ววิเคราะห์ผ่าน **cascade 4 ชั้น** (`backend/analyzer/scanner.py`):

1. เทียบ blocklist ของ สกมช. — cache เป็น `set` + ลงดิสก์ TTL 6 ชม.
2. วิเคราะห์รูปแบบ URL สดแบบออฟไลน์ — typosquatting ด้วย Levenshtein + normalize
   glyph (`g00gle` → `google`), โดเมน homoglyph ปลอมแบรนด์ (`ѕcb.co.th` ตัว ѕ
   ซีริลลิก), ลิงก์อันตรายทันทีที่กด (`javascript:`/`data:`, สคริปต์แฝงใน
   พารามิเตอร์, ไฟล์ `.apk`/`.exe` ในลิงก์)
3. ตาม redirect หาปลายทางจริง แล้ววนวิเคราะห์ชั้น 1-2 ซ้ำ + จับปลายทางที่สั่ง
   ดาวน์โหลดไฟล์ทันที (แพตเทิร์นแอปดูดเงิน)
4. อายุโดเมน + ข้อมูลจดทะเบียน registrar/ผู้ถือครอง (RDAP) + SSL cert + เนื้อหา
   หน้าเว็บจริง (ฟอร์มหลอก / แบรนด์แอบอ้าง / สคริปต์อำพราง) — รันขนาน เฉพาะตอน
   ชั้น 1-3 ยังไม่ฟันธง และถ้าตั้งค่า sandbox ไว้จะเปิดหน้าด้วย Chromium จริง
   (Playwright, แยกเครื่อง — ดู `sandbox/`) เพื่อเห็นหน้าเว็บ "หลังรัน JavaScript"

**กติกาตัดสิน:** เขียว = ยืนยันว่าปลอดภัยเท่านั้น / แดง = อันตราย / เหลือง = ที่เหลือทั้งหมด (รวม "ไม่รู้จัก")

**โหมดตรวจ QR** อ่าน QR ที่ไม่ใช่ลิงก์ได้ด้วย (`backend/analyzer/qr_payload.py`) — เด่นสุดคือ
QR พร้อมเพย์: ถอดมาตรฐาน EMVCo แล้วตรวจ CRC-16 ได้โดยไม่ต้องต่อเน็ต ถ้า CRC ไม่ตรง
แปลว่า QR ถูกแก้ไข รองรับ Wi-Fi / เบอร์โทร / SMS / อีเมล / นามบัตร / พิกัด ด้วย
QR ที่เป็นลิงก์ถูกส่งเข้า cascade 4 ชั้นเดียวกับโหมดลิงก์ทุกประการ

**ระดับการใช้งาน** (ลิงก์และ QR ใช้กติกาเดียวกัน):

| | ตรวจชั้น 1-2 | ตรวจเชิงลึก (ชั้น 3-4) |
|---|---|---|
| ไม่ล็อกอิน | `ANON_CHECKS_PER_DAY` ครั้ง/วัน/IP (ค่าเริ่มต้น 5) ครบแล้วล็อกถึงพรุ่งนี้ | — |
| สมาชิกฟรี | ไม่จำกัด | — |
| พรีเมียม | ไม่จำกัด | ไม่จำกัด + bulk + export + API key + รายละเอียด QR ชำระเงิน |

การจ่ายเงินเป็น **mock ทั้งหมด** ยังไม่ได้ต่อ payment gateway จริง

---

## ความต้องการของระบบ

- Python 3.12
- แพ็กเกจตาม `backend/requirements.txt` (Flask, waitress ฯลฯ)

> เครื่อง VPS ตัวนี้ **ไม่มี `pip`/`ensurepip` ติดมากับระบบ** ถ้าต้องสร้าง venv ใหม่ ดูหัวข้อ "สร้าง venv ใหม่" ด้านล่าง

---

## ติดตั้ง

```bash
cd backend
source .venv/bin/activate          # ถ้ายังไม่มี .venv ดูหัวข้อล่างสุด
pip install -r requirements.txt
```

ตั้งค่าตัวแปรสภาพแวดล้อม โดยก๊อป `.env.example` เป็น `.env` แล้วเติมค่าจริง:

```bash
cp .env.example .env
# แล้วแก้ SECRET_KEY ให้เป็นค่าที่สุ่มมาครั้งเดียว:
python -c 'import secrets;print(secrets.token_hex(32))'
```

> **อย่า commit `.env` จริงเข้า git** — มี `.gitignore` กันไว้ให้แล้ว

---

## วิธีรัน

### ตอนพัฒนา (เข้าจากเครื่องตัวเองเท่านั้น)

```bash
cd backend && source .venv/bin/activate
python app.py
# เปิด http://127.0.0.1:5000
```

### ตอนใช้งานจริง (production)

**วิธีปกติคือปล่อยให้ systemd ดูแล** (ดูหัวข้อ [Deploy](#deploy-nginx--systemd)) — เว็บจริง
อยู่ที่ **https://checkurl.studiodup.com**

ถ้าต้องรันมือ (เช่นตอนไล่ปัญหา) ให้หยุด service ก่อนแล้วสั่ง:

```bash
cd backend && source .venv/bin/activate
python serve.py
```

`serve.py` อ่านค่าทั้งหมดจาก `.env` แล้วตั้ง waitress ให้ถูกต้องสำหรับการอยู่หลัง Nginx
(ผูก `127.0.0.1`, 16 threads, `trusted_proxy` เพื่อให้เห็น IP ผู้ใช้จริง) — **อย่าสั่ง
`waitress-serve` ตรง ๆ** เพราะจะได้ค่าเริ่มต้นที่ลบ header `X-Forwarded-*` ทิ้ง ทำให้
rate limit เห็นผู้ใช้ทุกคนเป็น 127.0.0.1 คนเดียวกัน (เหตุผลเต็มอยู่ในหัวไฟล์ `serve.py`)

ปรับค่าได้ผ่าน env: `BIND_HOST`, `BIND_PORT`, `WAITRESS_THREADS`, `TRUSTED_PROXY`

### คำสั่งที่ใช้บ่อย

| งาน | คำสั่ง |
|---|---|
| ดูสถานะ | `systemctl status phishing-checker` |
| รีสตาร์ท (หลังแก้โค้ด/`.env`) | `sudo systemctl restart phishing-checker` |
| ดู log สด | `journalctl -u phishing-checker -f` |
| เช็กว่ารันอยู่ไหม | `ss -tlnp \| grep 5000` (ต้องเห็น `127.0.0.1:5000`) |
| รันเทสต์ | `cd backend && ./.venv/bin/python -m pytest` |

---

## ⚠️ กับดักที่ต้องรู้

1. **`SECRET_KEY` ต้องเป็นค่าเดิมตลอด** — อย่าสุ่มใหม่ทุกครั้งที่รัน ไม่งั้น session เก่าถอดรหัสไม่ได้ user ทุกคนหลุด login
2. **`SESSION_COOKIE_SECURE=false` ตอนเป็น HTTP** — ถ้าลืม ระบบ login จะพังแบบหาสาเหตุยาก (`config.py` ตั้งเป็น `True` อัตโนมัติเมื่อ `FLASK_ENV=production`)
3. **`python app.py` ผูกกับ `127.0.0.1`** — เข้าจากภายนอกไม่ได้ ต้องใช้ `waitress-serve --host=0.0.0.0` สำหรับ production
4. **เว็บจริงมี HTTPS แล้ว** (certbot ต่ออายุอัตโนมัติ) — แต่ถ้าติดตั้งเครื่องใหม่
   อย่าเปิดรับผู้ใช้ก่อนมี HTTPS เพราะรหัสผ่านจะวิ่งเป็น plain text
5. **`CORS_ORIGINS="*"` ตอน production แอปจะไม่ยอมสตาร์ต** — เพราะ `*` คู่กับ cookie login
   เท่ากับให้เว็บใดก็ได้ยิง API แทนผู้ใช้ที่ล็อกอินค้างไว้ ถ้าไม่ต้องใช้ CORS ให้ปล่อยว่าง

---

## เทสต์

เกือบ 300 เทสต์ ครอบคลุมส่วนที่เป็น pure function ล้วน (ไม่ยิงเน็ต ไม่แตะฐานข้อมูล)
จึงรันจบในไม่กี่วินาที — ตัวแยกส่วน URL, กฎวิเคราะห์ทั้งชุด (รวม homoglyph และลิงก์
อันตรายทันทีที่กด), ตัวถอด QR, กฎเนื้อหาเว็บ, combo rules, โควตาผู้ไม่ล็อกอิน,
การแกะข้อมูลจดทะเบียนจาก RDAP และตัวเรียก sandbox

```bash
cd backend
pip install -r requirements-dev.txt   # ครั้งแรกครั้งเดียว
./.venv/bin/python -m pytest          # หรือแค่ pytest ถ้า activate venv แล้ว
```

จุดที่จงใจเทสต์ไว้เพราะพังแล้วเจ็บที่สุด:

- **การหาโดเมนจริง (eTLD+1)** — `google.com.evil.xyz` ต้องอ่านได้ว่าโดเมนจริงคือ `evil.xyz`
  ไม่ใช่ `google.com` (ถ้าพลาด = แจกป้ายเขียวให้เว็บหลอก)
- **CRC ของ QR พร้อมเพย์** — เทียบกับค่ามาตรฐาน `CRC-16/CCITT-FALSE("123456789") = 0x29B1`
  และเทสต์ว่า QR ที่ถูกแก้เลขบัญชีปลายทางต้องขึ้นคำเตือนระดับ critical
- **ทั้ง false negative และ false positive** — เว็บหลอกต้องถูกจับ และโดเมนทางการต้องไม่โดนตีว่าปลอม

---

## Deploy (Nginx + systemd)

ไฟล์ตัวอย่างพร้อมใช้อยู่ในโฟลเดอร์ [`deploy/`](deploy/) — ทั้งสองไฟล์มีขั้นตอนติดตั้ง
เขียนไว้ในคอมเมนต์หัวไฟล์แล้ว

| ไฟล์ | หน้าที่ |
|---|---|
| [`deploy/phishing-checker.service`](deploy/phishing-checker.service) | รัน waitress เป็นบริการของระบบ — ไม่ดับตอนปิด SSH, ขึ้นเองหลังรีบูต |
| [`deploy/nginx.conf`](deploy/nginx.conf) | reverse proxy คั่นหน้า + เป็นทางไปสู่ HTTPS ด้วย certbot |

**เมื่อย้ายไปอยู่หลัง Nginx แล้วต้องแก้ `.env` 3 บรรทัด:**

```
BEHIND_PROXY=true            # ไม่งั้น rate limit เห็นทุกคนเป็น 127.0.0.1 คนเดียวกัน
CORS_ORIGINS=<origin จริง>
SESSION_COOKIE_SECURE=true   # ตั้งได้ "หลัง" มี HTTPS แล้วเท่านั้น
```

และเปลี่ยน waitress ให้ผูก `127.0.0.1` แทน `0.0.0.0` ไม่งั้นคนภายนอกยังยิงตรงเข้าพอร์ต
5000 ข้าม Nginx ได้อยู่ดี

> HTTPS ต้องมี **ชื่อโดเมนจริง** ก่อน — certbot ออกใบรับรองให้เลข IP ไม่ได้

---

## ตัวแปรสภาพแวดล้อม

ดูรายการเต็มพร้อมคำอธิบายใน [`backend/.env.example`](backend/.env.example)

| ตัวแปร | จำเป็น | ค่าเริ่มต้น |
|---|---|---|
| `FLASK_ENV` | - | `development` |
| `SECRET_KEY` | ✅ (production) | — |
| `CORS_ORIGINS` | - | `*` ตอน dev / ว่าง (same-origin) ตอน production |
| `SESSION_COOKIE_SECURE` | - | `true` เมื่อ production |
| `BEHIND_PROXY` | - | `false` |
| `DATABASE_URL` | - | SQLite ที่ `instance/app.db` |
| `RATELIMIT_STORAGE_URI` | - | `memory://` |
| `ANON_CHECKS_PER_DAY` | - | `5` (โควตาตรวจ/วัน/IP ของผู้ไม่ล็อกอิน, 0 = ต้องล็อกอิน) |
| `PREMIUM_PRICE_THB` | - | `99` |
| `PREMIUM_DURATION_DAYS` | - | `30` |
| `BULK_CHECK_MAX_URLS` | - | `20` |
| `BULK_CHECK_WORKERS` | - | `5` |
| `BULK_JOB_CONCURRENCY` | - | `2` |
| `BULK_JOB_TTL` | - | `1800` |
| `SCAN_CACHE_TTL` | - | `900` (0 = ปิดแคช) |
| `SCAN_CACHE_MAX` | - | `2000` |
| `WARMUP_URL` | - | `https://example.com` (ว่าง = ปิด) |
| `SANDBOX_URL` | - | ว่าง = ไม่ใช้ sandbox (อ่าน HTML ดิบอย่างเดียว) |
| `SANDBOX_TOKEN` / `SANDBOX_TIMEOUT` | - | — / `12` (วินาที) |

---

## API หลัก

| Endpoint | ใช้ได้กับ | หมายเหตุ |
|---|---|---|
| `POST /api/check` | ทุกคน | body = `{"url": "..."}` — ผู้ไม่ล็อกอินติดโควตา/วัน (ตอบ 429 เมื่อครบ) |
| `POST /api/check/qr` | ทุกคน | body = `{"payload": "<เนื้อหาที่ถอดจาก QR>"}` — โควตาเดียวกับ `/api/check` |
| `POST /api/check/bulk` | พรีเมียม | body = `{"urls": [...]}` — **ตอบ 202 + `job_id`** |
| `POST /api/check/qr/bulk` | พรีเมียม | body = `{"items": [{"payload": "..."}]}` — **ตอบ 202 + `job_id`** |
| `GET /api/check/bulk/<job_id>` | เจ้าของงาน | ถามความคืบหน้า/ผลของงาน bulk |
| `GET /api/history` | สมาชิก | 50 รายการล่าสุด |
| `GET /api/history/export` | พรีเมียม | CSV |
| `GET /api/health` | ทุกคน | สถานะ + สถิติแคชและงาน bulk |

ทุก endpoint ข้างบนรับได้ทั้ง **cookie จากการล็อกอิน** และ **header `X-API-Key`** (พรีเมียม)

### การตรวจแบบ bulk เป็นงานเบื้องหลัง

`POST /api/check/bulk` ไม่รอจนตรวจเสร็จแล้วค่อยตอบ แต่รับงานแล้วตอบทันที:

```bash
# 1) สั่งงาน -> ได้ job_id กลับมาใน ~0.02 วินาที
curl -s -X POST http://โดเมน/api/check/bulk -H 'X-API-Key: pfk_...' \
     -H 'Content-Type: application/json' -d '{"urls":["https://a.com","https://b.com"]}'
# {"ok":true,"job_id":"ae5c...","total":2,"state":"queued","poll_url":"/api/check/bulk/ae5c..."}

# 2) ถามความคืบหน้าเป็นระยะจนกว่า state จะเป็น done
curl -s http://โดเมน/api/check/bulk/ae5c... -H 'X-API-Key: pfk_...'
# {"ok":true,"state":"running","done":1,"total":2,"results":null}
# {"ok":true,"state":"done","done":2,"total":2,"results":[...]}
```

**ทำไมถึงเปลี่ยน:** การตรวจ 20 ลิงก์ใช้เวลาได้ราว 8 วินาที ตลอดเวลานั้นมันยึด worker
thread ของ waitress ไว้ 1 เส้นจากไม่กี่เส้น ผลคือสมาชิกพรีเมียมไม่กี่คนที่กด bulk พร้อมกัน
ทำให้ **ทั้งเว็บ** ช้าสำหรับทุกคน รวมถึงคนที่แค่จะเปิดหน้าแรก

`state` ไล่จาก `queued` → `running` → `done` (หรือ `failed`) และ `results` จะเป็น `null`
จนกว่าจะ `done` — งานเก็บในหน่วยความจำ ถ้ารีสตาร์ตเซิร์ฟเวอร์งานที่ค้างจะหาย ให้สั่งใหม่

---

## โครงสร้างโปรเจกต์

```
Checklink/
├─ backend/
│  ├─ app.py              # จุดเริ่ม Flask (สร้างแอป + เสิร์ฟ frontend)
│  ├─ serve.py            # จุดเริ่มตอน production (waitress หลัง Nginx)
│  ├─ config.py           # อ่านค่าจาก env ทั้งหมด
│  ├─ auth.py             # สมาชิก/ล็อกอิน
│  ├─ billing.py          # พรีเมียม (mock)
│  ├─ check.py            # endpoint การเช็กลิงก์/QR
│  ├─ anon_quota.py       # โควตาตรวจรายวันต่อ IP ของผู้ไม่ล็อกอิน
│  ├─ jobs.py             # คิวงาน bulk เบื้องหลัง
│  ├─ models.py           # ตารางฐานข้อมูล
│  ├─ analyzer/           # หัวใจการวิเคราะห์ (cascade 4 ชั้น + ตัวถอด QR)
│  ├─ tests/              # เทสต์ pure function (pytest)
│  └─ requirements.txt
├─ frontend/              # vanilla JS + ES modules (ไม่มี build step)
├─ sandbox/               # บริการเปิดหน้าเว็บด้วย Chromium (Playwright) — แยกเครื่อง
├─ docs/                  # เอกสารออกแบบ (เช่นกฎวิเคราะห์เนื้อหาเว็บ)
└─ deploy/                # ตัวอย่าง Nginx + systemd unit + สคริปต์ deploy
```

---

## สร้าง venv ใหม่ (เครื่องนี้ไม่มี pip ติดมา)

```bash
cd backend
python3 -m venv --without-pip .venv
curl -sS -o /tmp/get-pip.py https://bootstrap.pypa.io/get-pip.py
./.venv/bin/python /tmp/get-pip.py
source .venv/bin/activate && pip install -r requirements.txt
```

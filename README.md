# Checklink — เช็กก่อนกด

เว็บตรวจลิงก์/QR ว่าเป็นลิงก์หลอกลวงไหม (ภาษาไทย) — Flask เสิร์ฟทั้ง REST API และ frontend

Frontend เป็น vanilla JS + ES modules ไม่มี build step

---

## โปรเจกต์นี้ทำอะไร

รับ URL เข้ามาแล้ววิเคราะห์ผ่าน **cascade 4 ชั้น** (`backend/analyzer/scanner.py`):

1. เทียบ blocklist ของ สกมช. — cache เป็น `set` + ลงดิสก์ TTL 6 ชม.
2. วิเคราะห์รูปแบบ URL สด — typosquatting ด้วย Levenshtein + normalize glyph (`g00gle` → `google`)
3. ตาม redirect หาปลายทางจริง แล้ววนวิเคราะห์ชั้น 1-2 ซ้ำ
4. อายุโดเมน (RDAP) + SSL cert + เนื้อหาหน้าเว็บ — รันขนาน เฉพาะตอนชั้น 1-3 ยังไม่ฟันธง

**กติกาตัดสิน:** เขียว = ยืนยันว่าปลอดภัยเท่านั้น / แดง = อันตราย / เหลือง = ที่เหลือทั้งหมด (รวม "ไม่รู้จัก")

**โหมดตรวจ QR** อ่าน QR ที่ไม่ใช่ลิงก์ได้ด้วย (`backend/analyzer/qr_payload.py`) — เด่นสุดคือ
QR พร้อมเพย์: ถอดมาตรฐาน EMVCo แล้วตรวจ CRC-16 ได้โดยไม่ต้องต่อเน็ต ถ้า CRC ไม่ตรง
แปลว่า QR ถูกแก้ไข รองรับ Wi-Fi / เบอร์โทร / SMS / อีเมล / นามบัตร / พิกัด ด้วย

**ระบบสมาชิก:** free (เช็คเชิงลึก 5 ครั้ง/วัน) / premium (ไม่จำกัด + bulk + export + API key)
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

ถ้ามีไฟล์ `.env` ครบแล้ว รันสั้นๆ ได้เลย:

```bash
cd backend && source .venv/bin/activate
waitress-serve --host=0.0.0.0 --port=5000 app:app
```

เปิดเว็บที่ **http://198.199.122.176:5000**

ถ้าไม่ใช้ `.env` ก็ส่งค่าผ่าน env ตอนรันได้:

```bash
cd backend && source .venv/bin/activate
FLASK_ENV=production \
SECRET_KEY='ค่าคงที่ที่สุ่มมาครั้งเดียว' \
CORS_ORIGINS="http://198.199.122.176:5000" \
SESSION_COOKIE_SECURE=false \
waitress-serve --host=0.0.0.0 --port=5000 app:app
```

### รันค้างไว้แม้ปิด SSH

**วิธีที่แนะนำ:** ติดตั้งเป็น systemd service (ขึ้นเองหลังรีบูต + รีสตาร์ทให้เมื่อ process ตาย)
ดูขั้นตอนในหัวข้อ [Deploy](#deploy-nginx--systemd) ด้านล่าง

**วิธีชั่วคราว (nohup):**

```bash
cd backend && source .venv/bin/activate
nohup waitress-serve --host=0.0.0.0 --port=5000 app:app > ../../app.log 2>&1 &
tail -f ../../app.log      # ดู log
```

### คำสั่งที่ใช้บ่อย

| งาน | คำสั่ง |
|---|---|
| เช็กว่ารันอยู่ไหม | `ss -tlnp \| grep 5000` |
| หยุด (รันอยู่หน้า terminal) | `Ctrl+C` |
| หยุด (รันเบื้องหลัง/หา terminal ไม่เจอ) | `pkill -f waitress-serve` |
| รันเทสต์ | `cd backend && ./.venv/bin/python -m pytest` |

---

## ⚠️ กับดักที่ต้องรู้

1. **`SECRET_KEY` ต้องเป็นค่าเดิมตลอด** — อย่าสุ่มใหม่ทุกครั้งที่รัน ไม่งั้น session เก่าถอดรหัสไม่ได้ user ทุกคนหลุด login
2. **`SESSION_COOKIE_SECURE=false` ตอนเป็น HTTP** — ถ้าลืม ระบบ login จะพังแบบหาสาเหตุยาก (`config.py` ตั้งเป็น `True` อัตโนมัติเมื่อ `FLASK_ENV=production`)
3. **`python app.py` ผูกกับ `127.0.0.1`** — เข้าจากภายนอกไม่ได้ ต้องใช้ `waitress-serve --host=0.0.0.0` สำหรับ production
4. **ยังไม่มี HTTPS** — รหัสผ่าน user วิ่งเป็น plain text อย่าให้ใครใช้รหัสผ่านจริง
5. **`CORS_ORIGINS="*"` ตอน production แอปจะไม่ยอมสตาร์ต** — เพราะ `*` คู่กับ cookie login
   เท่ากับให้เว็บใดก็ได้ยิง API แทนผู้ใช้ที่ล็อกอินค้างไว้ ถ้าไม่ต้องใช้ CORS ให้ปล่อยว่าง

---

## เทสต์

เทสต์ครอบคลุมส่วนที่เป็น pure function ล้วน (ไม่ยิงเน็ต ไม่แตะฐานข้อมูล) จึงรันจบใน
ไม่ถึงวินาที — `analyzer/url_parser.py`, `analyzer/heuristics.py`, `analyzer/qr_payload.py`

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
| `FREE_DEEP_CHECKS_PER_DAY` | - | `5` |
| `PREMIUM_PRICE_THB` | - | `99` |
| `PREMIUM_DURATION_DAYS` | - | `30` |
| `BULK_CHECK_MAX_URLS` | - | `20` |
| `BULK_CHECK_WORKERS` | - | `5` |

---

## API หลัก

| Endpoint | ใช้ได้กับ | หมายเหตุ |
|---|---|---|
| `POST /api/check` | ทุกคน | body = `{"url": "..."}` |
| `POST /api/check/qr` | ทุกคน | body = `{"payload": "<เนื้อหาที่ถอดจาก QR>"}` |
| `POST /api/check/bulk` | พรีเมียม | body = `{"urls": [...]}` — ยิงขนาน |
| `POST /api/check/qr/bulk` | พรีเมียม | body = `{"items": [{"payload": "..."}]}` |
| `GET /api/history` | สมาชิก | 50 รายการล่าสุด |
| `GET /api/history/export` | พรีเมียม | CSV |
| `GET /api/health` | ทุกคน | เช็กว่าเซิร์ฟเวอร์ยังอยู่ |

ทุก endpoint ข้างบนรับได้ทั้ง **cookie จากการล็อกอิน** และ **header `X-API-Key`** (พรีเมียม)

---

## โครงสร้างโปรเจกต์

```
Checklink/
├─ backend/
│  ├─ app.py              # จุดเริ่ม Flask (สร้างแอป + เสิร์ฟ frontend)
│  ├─ config.py           # อ่านค่าจาก env ทั้งหมด
│  ├─ auth.py             # สมาชิก/ล็อกอิน
│  ├─ billing.py          # พรีเมียม (mock)
│  ├─ check.py            # endpoint การเช็กลิงก์/QR
│  ├─ models.py           # ตารางฐานข้อมูล
│  ├─ analyzer/           # หัวใจการวิเคราะห์ (cascade 4 ชั้น + ตัวถอด QR)
│  ├─ tests/              # เทสต์ pure function (pytest)
│  └─ requirements.txt
├─ frontend/              # vanilla JS + ES modules (ไม่มี build step)
└─ deploy/                # ตัวอย่าง Nginx + systemd unit
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

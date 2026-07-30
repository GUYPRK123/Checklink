# sandbox — ตัวเปิดหน้าเว็บด้วย Chromium จริง

บริการเล็ก ๆ ที่รับ URL แล้วเปิดด้วย Chromium จริง (รัน JavaScript) คืน "page bundle"
ให้เว็บหลักเอาไปวิเคราะห์ต่อ แก้ช่องโหว่ใหญ่ที่สุดของชั้นที่ 4 คือชุดฟิชชิ่งที่ส่ง
HTML เปล่ามาแล้ววาดหน้าล็อกอินด้วย JS ซึ่งตัวดึงแบบเดิมมองไม่เห็นเลย

```
เว็บหลัก (user: url)                          sandbox (user: checklink-sandbox)
  analyzer/sandbox_fetch.py  ──POST /fetch──▶  sandbox_server.py
                             ◀──page bundle──   └─ Chromium (เปิดใหม่ทุกครั้ง)
        127.0.0.1:8900 เท่านั้น ไม่เปิดออกเน็ต
```

---

## ทำไมต้องแยก user ทั้งที่อยู่เครื่องเดียวกัน

นี่คือการเอาโค้ดของคนที่เราสงสัยว่าเป็นมิจฉาชีพมารันบนเซิร์ฟเวอร์ตัวเอง ถ้ารันด้วย
user เดียวกับเว็บ ช่องโหว่ของ Chromium ครั้งเดียวก็อ่าน `.env` (มี `SECRET_KEY`)
และ `instance/app.db` (มีบัญชีผู้ใช้) ได้ทันที

การแยก user + systemd hardening ทำให้ต่อให้หลุดออกจาก Chromium ได้จริง
ก็ยังอ่านโฟลเดอร์แอปไม่ได้ เขียนไฟล์ได้แค่บ้านตัวเอง เพิ่มสิทธิ์ไม่ได้
และใช้แรมเกิน 350 MB ไม่ได้ (ถ้าเกิน kernel ฆ่าเฉพาะบริการนี้ ไม่แตะเว็บหลัก)

**ไม่เท่าการแยกเครื่องคนละใบ** แต่ได้ความปลอดภัยส่วนใหญ่โดยไม่ต้องดูแลสองเครื่อง
ซึ่งตรงกับหลักในโปรเจกต์นี้ว่าอย่าเพิ่มจุดที่พังได้โดยไม่จำเป็น

---

## ขั้นตอนติดตั้ง (ต้องรันด้วยสิทธิ์ root)

### 1. สร้าง user สำหรับ sandbox

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin checklink-sandbox
```

### 2. ติดตั้งไลบรารีที่ Chromium ต้องใช้

```bash
sudo apt update
sudo apt install -y python3-venv
```

### 3. สร้าง venv แล้วติดตั้ง Playwright + Chromium

เครื่องนี้ **ไม่มี pip ติดมากับระบบ** ต้อง bootstrap เหมือนที่ทำกับ venv ของเว็บหลัก

**รันทีละบรรทัด** อย่ารวมเป็นบล็อกเดียวที่มีเครื่องหมายคำพูดคร่อม เพราะถ้าวางแล้ว
เครื่องหมายปิดหาย bash จะค้างรอบรรทัดต่อ (ขึ้น `>`) แล้วทั้งบล็อกไม่ทำงานเลย

```bash
curl -sS -o /tmp/get-pip-sandbox.py https://bootstrap.pypa.io/get-pip.py
chmod 644 /tmp/get-pip-sandbox.py
sudo -u checklink-sandbox python3 -m venv --without-pip /home/checklink-sandbox/venv
sudo -H -u checklink-sandbox /home/checklink-sandbox/venv/bin/python /tmp/get-pip-sandbox.py
sudo -H -u checklink-sandbox /home/checklink-sandbox/venv/bin/pip install playwright
sudo -H -u checklink-sandbox /home/checklink-sandbox/venv/bin/playwright install chromium
```

> **ต้องมี `-H` เสมอ** — `sudo -u` เฉย ๆ ไม่เปลี่ยน `$HOME` ให้ Chromium จะพยายาม
> เขียนลง `/home/url/.cache` แล้วโดนปฏิเสธสิทธิ์

จากนั้นติดตั้งไลบรารีระบบที่ Chromium ต้องใช้ (บรรทัดเดียวที่ต้องเป็น root จริง ๆ
เพราะมันเรียก `apt` ข้างใน):

```bash
sudo /home/checklink-sandbox/venv/bin/playwright install-deps chromium
```

> ใช้เนื้อที่ราว 400-500 MB (ดิสก์ว่างอยู่ ~3.8 GB) ถ้าไม่พอให้ลบ backup เก่าก่อน

### 4. วางไฟล์บริการ

```bash
sudo cp /home/url/checkurl-app/Checklink/sandbox/sandbox_server.py \
        /home/checklink-sandbox/
sudo chown checklink-sandbox:checklink-sandbox /home/checklink-sandbox/sandbox_server.py
sudo chmod 0644 /home/checklink-sandbox/sandbox_server.py
```

> **จงใจคัดลอกไฟล์ออกมา ไม่ได้ชี้เข้าโฟลเดอร์โปรเจกต์** เพราะ user นี้ต้องอ่าน
> `/home/url/checkurl-app` ไม่ได้เลย เวลาแก้โค้ดต้องคัดลอกใหม่ทุกครั้ง

> ⚠️ **สิ่งเดียวที่กัน sandbox ไม่ให้อ่าน `.env` และ `app.db` คือสิทธิ์ของ `/home/url`**
> ซึ่งตอนนี้เป็น `drwxr-x---` (750, `other` ไม่มีสิทธิ์อะไรเลย) ส่วนไฟล์ข้างในเป็น
> world-readable เกือบทั้งหมด **ถ้าวันไหนมีใคร `chmod 755 /home/url` การแยกสิทธิ์นี้
> จะพังทันทีโดยไม่มีอะไรฟ้อง** ตรวจได้ด้วย:
>
> ```bash
> namei -lm /home/url/checkurl-app/Checklink/backend/.env | grep ' url$'
> # ต้องเห็น drwxr-x--- เท่านั้น
> ```

### 5. สร้าง token ที่ใช้ร่วมกันสองฝั่ง

```bash
TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
printf 'SANDBOX_TOKEN=%s\n' "$TOKEN" | sudo tee /etc/checklink-sandbox.env >/dev/null
sudo chown root:checklink-sandbox /etc/checklink-sandbox.env
sudo chmod 0640 /etc/checklink-sandbox.env
echo "เอาค่านี้ไปใส่ SANDBOX_TOKEN ใน backend/.env ด้วย: $TOKEN"
```

### 6. เปิดบริการ

```bash
sudo cp /home/url/checkurl-app/Checklink/sandbox/checklink-sandbox.service \
        /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now checklink-sandbox
systemctl status checklink-sandbox
```

### 7. ตรวจว่าใช้ได้จริง

```bash
curl -s http://127.0.0.1:8900/health
# {"ok": true, "service": "checklink-sandbox"}

curl -s -X POST http://127.0.0.1:8900/fetch \
     -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"url":"https://example.com"}' | head -c 300
```

### 8. บอกเว็บหลักให้เริ่มใช้

เติมใน `backend/.env` (ดูตัวอย่างใน `.env.example`) แล้ว deploy

```
SANDBOX_URL=http://127.0.0.1:8900/fetch
SANDBOX_TOKEN=<ค่าเดียวกับข้อ 5>
SANDBOX_TIMEOUT=12
```

```bash
sudo /home/url/checkurl-app/Checklink/deploy/deploy.sh
```

**ถ้าไม่เติมสองบรรทัดนี้ ระบบจะไม่เรียก sandbox เลยและทำงานเหมือนเดิมทุกอย่าง**
— เป็นสวิตช์ปิดที่ปลอดภัยเวลาต้องรีบถอย

---

## เวลาแก้โค้ด sandbox

โค้ดที่รันจริงคือ **สำเนา** ที่ `/home/checklink-sandbox/sandbox_server.py`
ไม่ใช่ไฟล์ในโปรเจกต์ แก้ในโปรเจกต์อย่างเดียวไม่มีผลอะไรทั้งสิ้น ต้องคัดลอกใหม่เสมอ:

```bash
sudo cp /home/url/checkurl-app/Checklink/sandbox/sandbox_server.py /home/checklink-sandbox/ \
  && sudo chown checklink-sandbox:checklink-sandbox /home/checklink-sandbox/sandbox_server.py \
  && sudo systemctl restart checklink-sandbox \
  && systemctl is-active checklink-sandbox
```

> พลาดตรงนี้มาแล้วตอนติดตั้งครั้งแรก: แก้เรื่องหน้า error ในโปรเจกต์แล้วลืมคัดลอก
> ทำให้ทดสอบไปเจอผลของโค้ดเก่าโดยไม่รู้ตัว

---

## สิ่งที่ sandbox ช่วยไม่ได้

**เว็บที่กันบอต** — Cloudflare และระบบกันบอตอื่น ๆ ตอบ 403 หรือหน้า "Just a moment..."
ให้ทั้ง requests และ Chromium ที่รันแบบ headless เหมือนกัน วัดจริงแล้ว `pantip.com`,
`blognone.com`, `stackoverflow.com/users/login` ล้วนโดนบล็อกทั้งคู่

ระบบจะรายงานว่า **"เช็กไม่ได้"** ซึ่งถูกต้องตามหลัก ไม่ใช่ทั้ง "เสี่ยง" และ "ปลอดภัย"
การพยายามเลี่ยงระบบกันบอต (ปลอม fingerprint, ใช้ proxy หมุน) ไม่คุ้มและไม่ใช่
เจตนาของเครื่องมือนี้ — เป้าหมายคือดูหน้าฟิชชิ่ง ซึ่งแทบไม่มีใครเอา Cloudflare มากั้น

---

## ปัญหาที่น่าจะเจอ

### บริการไม่ขึ้น: `Failed to move to new namespace`

Ubuntu 24.04 ปิด unprivileged user namespace ไว้ ทำให้ sandbox ในตัวของ Chromium
เปิดไม่ขึ้น ทางแก้ที่แนะนำคือเปิดให้ใช้ได้:

```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

ถ้ายังไม่ได้ ค่อยยอมปิด sandbox ในตัวของ Chromium (เพิ่มใน `/etc/checklink-sandbox.env`)

```
SANDBOX_NO_CHROME_SANDBOX=1
```

**แลกกับการเสียชั้นป้องกันไปหนึ่งชั้น** ที่เหลือคือ user แยก + systemd + การเช็ก IP
ในโค้ด ซึ่งยังกันเรื่องสำคัญที่สุด (เข้าถึง `app.db` / `SECRET_KEY`) ได้อยู่

### ถูกฆ่าเพราะแรม

```bash
journalctl -u checklink-sandbox | grep -i memory
systemctl show checklink-sandbox -p MemoryPeak --value
```

ปรับ `MemoryMax` ใน unit ขึ้นได้ แต่ **อย่าให้เกิน 400M** เพราะเครื่องมีแรมรวม 458 MB
ถ้าตั้งสูงกว่านั้น OOM killer อาจไปเลือกฆ่าโปรเซสเว็บหลักแทน

### เว็บหลักหน่วงตอน sandbox ทำงาน

เป็นเรื่องปกติของเครื่องแรมน้อย ถ้าหน่วงจนรับไม่ได้ให้ลด `CPUQuota` ลงเหลือ 40%
หรือปิด sandbox ชั่วคราวด้วยการลบ `SANDBOX_URL` ออกจาก `.env` แล้ว deploy ใหม่

---

## สิ่งที่ยังไม่ได้ทำ

- **`password_in_iframe`** — ต้องเพิ่มฟิลด์ `frames` เข้าไปในสัญญา page bundle
  แล้วให้ตัววิเคราะห์อ่านข้างในของ iframe ข้ามโดเมน
- **`logo_hotlink_brand`** — ถอดออกตอนขั้น 2 เพราะ false positive สูง แต่พอมี sandbox
  แล้วจะรู้ขนาด/ตำแหน่งจริงของรูป ทำให้แยก "โลโก้กลางหน้า" ออกจาก "ไอคอน 16px
  ท้ายหน้า" ได้ กฎนี้จึงกลับมาได้ (ดูเหตุผลเดิมใน `backend/analyzer/content_analyzer.py`)
- **ยังไม่เคยรันจริง** — ตอนที่เขียน เครื่องยังไม่ได้ติดตั้ง Chromium
  ส่วนที่เทสต์แล้วคือการกัน SSRF, การตรวจ token, และรูปร่างคำตอบ (เทสต์ 20 ข้อ)
  ส่วนที่ยังไม่ได้พิสูจน์คือ Chromium เปิดหน้าเว็บได้จริงและใช้แรมเท่าไหร่

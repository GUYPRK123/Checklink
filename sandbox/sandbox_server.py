#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sandbox_server.py
============================================================================
  >>> บริการ sandbox: เปิดหน้าเว็บด้วย Chromium จริง แล้วคืน page bundle <<<
============================================================================
รับ `POST /fetch {"url": "..."}` คืน page bundle ตามสัญญาที่ตกลงไว้ใน
`backend/analyzer/page_fetch.py` — ฝั่งเว็บหลักเรียกผ่าน `analyzer/sandbox_fetch.py`

**ทำไมต้องมีตัวนี้:** ชุดฟิชชิ่งสมัยใหม่ส่ง HTML เปล่ามาแล้วค่อยวาดหน้าล็อกอินด้วย
JavaScript ตอนโหลด ตัวดึงด้วย requests จึงเห็นหน้าว่างแล้วสรุปว่า "ไม่พบสิ่งผิดปกติ"
ซึ่งแย่กว่าไม่ตรวจเลยเพราะให้ความมั่นใจผิด ๆ ตัวนี้รัน JS จริงจึงเห็นหน้าอย่างที่
ผู้ใช้เห็น และเห็น "ปลายทางที่สคริปต์ยิงข้อมูลออกไป" ซึ่งอ่านจากโค้ดอย่างเดียวไม่มีทางรู้

**ตัวนี้คือส่วนที่อันตรายที่สุดของทั้งระบบ** เพราะมันคือการเอาโค้ดของคนที่เราสงสัยว่า
เป็นมิจฉาชีพมารันบนเซิร์ฟเวอร์ตัวเอง ชั้นการป้องกันจึงมี 4 ชั้นและ **ห้ามถอดชั้นไหนออก
โดยไม่เข้าใจว่ามันกันอะไร**:

  1) รันใต้ user แยกที่เข้าโฟลเดอร์แอปและ `app.db` ไม่ได้เลย (ดู README.md)
  2) systemd จำกัดแรม/สิทธิ์/การเขียนไฟล์ (ดู checklink-sandbox.service)
  3) ตัวโค้ดนี้เอง: เช็ก IP ปลอดภัยก่อนเปิด, ปักหมุด DNS, ปิดดาวน์โหลด/ป๊อปอัป,
     ตัดเวลาที่ 8 วินาที, จำกัดขนาด HTML
  4) Chromium เปิดใหม่ทุกครั้งแล้วปิดทิ้ง — ไม่มีสถานะข้ามคำขอ และไม่กินแรมตอนว่าง

**จงใจเปิด Chromium ใหม่ทุกคำขอ** ถึงจะช้ากว่าการเปิดค้างไว้ราว 0.5-1 วินาที
เพราะเครื่องนี้มีแรมรวมแค่ 458 MB การปล่อยให้ Chromium นั่งกินแรม 200-300 MB
ตลอดเวลาจะเบียดเว็บหลัก ส่วนแบบนี้ตอนไม่มีใครตรวจลิงก์ = ใช้แรม 0

ฟังผ่าน 127.0.0.1 เท่านั้น ไม่เปิดออกเน็ต และต้องมี token ตรงกันจึงจะเรียกได้
"""
import hmac
import ipaddress
import json
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

PAGE_TIMEOUT_MS = 8000      # ตัดหน้าเว็บทิ้งที่ 8 วินาที (รวมโหลด+รัน JS)
SETTLE_MS = 1500            # รอหลัง DOM พร้อม เผื่อสคริปต์วาดหน้าต่ออีกนิด
MAX_HTML = 512 * 1024       # จำกัดขนาดเท่ากับตัวดึงแบบเบา เพื่อให้ผลเทียบกันได้
MAX_POSTS = 50
BUSY_WAIT_SEC = 2           # รอคิวนานกว่านี้ตอบ 503 ดีกว่าปล่อยให้กองกัน
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# รันทีละหน้าเท่านั้น — เครื่องนี้ไม่มีแรมพอให้ Chromium สองตัวอยู่พร้อมกัน
_slot = threading.Semaphore(1)


# ---------------------------------------------------------------------------
# ความปลอดภัยของปลายทาง
# ---------------------------------------------------------------------------
# จงใจเขียนซ้ำแทนที่จะ import จาก backend/analyzer/ ทั้งที่ตรรกะเหมือนกัน
# เพราะ user ที่รันไฟล์นี้ต้องอ่านโฟลเดอร์แอปไม่ได้ ตามชั้นป้องกันข้อ 1
# ถ้าวันไหนแก้กฎ IP ที่ฝั่งโน้น **ต้องมาแก้ที่นี่ด้วย**
def resolve_safe_ip(host: str):
    """แปลงชื่อโฮสต์เป็น IP แล้วตรวจว่าเป็น IP สาธารณะจริง

    คืน (ip, "") ถ้าปลอดภัย หรือ (None, เหตุผล) ถ้าไม่
    กันการหลอกให้เซิร์ฟเวอร์ยิงเข้าเครือข่ายภายในตัวเอง (SSRF) เช่น
    127.0.0.1, 10.x, 192.168.x, 169.254.169.254 (metadata ของผู้ให้บริการคลาวด์)
    """
    if not host:
        return None, "ไม่มีชื่อโฮสต์"
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None, "หาที่อยู่ของโดเมนนี้ไม่เจอ"

    for info in infos:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return None, f"ปลายทางชี้ไปยัง IP ที่สงวนไว้ ({raw})"
        return str(ip), ""
    return None, "ไม่ได้ที่อยู่ที่ใช้งานได้"


def _is_private_literal(host: str) -> bool:
    """โฮสต์ที่เขียนเป็นเลข IP ภายในมาตรง ๆ — ใช้บล็อกทุก request ที่หน้าเว็บยิงออก
    โดยไม่ต้อง resolve DNS ใหม่ (ซึ่งจะช้าเกินไปถ้าทำทุก request)"""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def _same_site(request_host: str, page_host: str) -> bool:
    """นับว่าเป็นโดเมนเดียวกันไหม (รวมโดเมนย่อย) แบบหยาบ ๆ พอสำหรับติดธง
    cross_origin — การตัดสินจริงว่าเป็นคนละ registrable domain หรือไม่
    ทำที่ฝั่งตัววิเคราะห์ซึ่งมีรายการนามสกุลโดเมนครบกว่า"""
    if not request_host or not page_host:
        return False
    return (request_host == page_host
            or request_host.endswith("." + page_host)
            or page_host.endswith("." + request_host))


def _fail(reason: str) -> dict:
    return {"ok": False, "reason": reason, "final_url": "", "status": None,
            "html": "", "raw_html": "", "network_posts": []}


# ---------------------------------------------------------------------------
# ตัวเปิดหน้าเว็บ
# ---------------------------------------------------------------------------
def _launch_args(host: str, ip: str) -> list:
    """อาร์กิวเมนต์ตอนเปิด Chromium

    `--host-resolver-rules` คือหัวใจของการกัน DNS rebinding: เราเช็ก IP ไปแล้ว
    รอบหนึ่ง แต่ Chromium จะ resolve DNS เองใหม่ ซึ่งเจ้าของโดเมนสามารถเปลี่ยน
    คำตอบระหว่างสองครั้งให้ชี้กลับเข้าเครือข่ายภายในได้ การปักหมุดโฮสต์ให้ชี้ไปยัง
    IP ที่เราตรวจแล้วเท่านั้น ทำให้ช่องนั้นปิดสนิท
    """
    args = [
        f"--host-resolver-rules=MAP {host} {ip}",
        "--disable-dev-shm-usage",      # /dev/shm บนเครื่องเล็กมักไม่พอ
        "--disable-gpu",
        "--mute-audio",
        "--no-first-run",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-sync",
    ]
    # Ubuntu 24.04 ปิด unprivileged user namespace ไว้ ทำให้ sandbox ในตัวของ
    # Chromium เปิดไม่ขึ้น ถ้าเจอปัญหานั้นค่อยตั้งค่านี้ (ยังเหลือการกันชั้น 1, 2, 3)
    if os.environ.get("SANDBOX_NO_CHROME_SANDBOX") == "1":
        args.append("--no-sandbox")
    return args


def fetch_bundle(url: str) -> dict:
    """เปิดหน้าเว็บด้วย Chromium แล้วคืน page bundle"""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return _fail("ไม่ใช่ลิงก์ http/https")

    host = (parts.hostname or "").lower()
    ip, reason = resolve_safe_ip(host)
    if not ip:
        return _fail(reason)

    # import ที่นี่ไม่ใช่หัวไฟล์ เพื่อให้เทสต์ส่วนที่ไม่ต้องใช้เบราว์เซอร์
    # (การเช็ก IP, การตรวจ token) รันได้โดยไม่ต้องติดตั้ง playwright
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    posts, browser = [], None
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True, args=_launch_args(host, ip))
            context = browser.new_context(
                user_agent=USER_AGENT,
                viewport={"width": 1280, "height": 800},
                ignore_https_errors=True,   # ใบรับรองเสียมีชั้นอื่นตรวจอยู่แล้ว
                accept_downloads=False,
                java_script_enabled=True,
                bypass_csp=False,
            )
            context.grant_permissions([])   # ไม่ให้กล้อง/ไมค์/ตำแหน่ง/แจ้งเตือน

            def on_route(route, request):
                """บล็อกทุก request ที่ยิงตรงไปยังเลข IP ภายใน"""
                try:
                    target = (urlsplit(request.url).hostname or "").lower()
                    if _is_private_literal(target):
                        route.abort()
                        return
                    route.continue_()
                except PlaywrightError:
                    pass

            def on_request(request):
                if request.method != "POST" or len(posts) >= MAX_POSTS:
                    return
                posts.append({"url": request.url[:300], "host":
                              (urlsplit(request.url).hostname or "").lower()})

            context.route("**/*", on_route)
            context.on("request", on_request)

            page = context.new_page()
            page.on("popup", lambda p: p.close())
            page.on("dialog", lambda d: d.dismiss())

            try:
                resp = page.goto(url, timeout=PAGE_TIMEOUT_MS,
                                 wait_until="domcontentloaded")
            except PlaywrightError:
                return _fail("เปิดหน้าเว็บไม่สำเร็จหรือใช้เวลานานเกินไป")

            if resp is None:
                return _fail("ไม่ได้รับคำตอบจากหน้าเว็บ")

            # หน้า error ไม่ใช่เนื้อหาจริงของเว็บนั้น เอาไปวิเคราะห์จะได้แต่สัญญาณขยะ
            # เจอบ่อยมากกับเว็บที่กันบอตแล้วตอบ 403 กลับมา (เช่น pantip.com)
            # ต้องเป็น "เช็กไม่ได้" ไม่ใช่ "ตรวจแล้วไม่พบอะไร" — กฎเดียวกับ page_fetch.py
            if resp.status >= 400:
                return _fail(f"ปลายทางตอบ HTTP {resp.status}")

            try:
                raw_html = resp.text()[:MAX_HTML]
            except PlaywrightError:
                raw_html = ""

            page.wait_for_timeout(SETTLE_MS)   # ให้สคริปต์วาดหน้าจนนิ่ง

            final_url = page.url
            final_host = (urlsplit(final_url).hostname or "").lower()
            # เผื่อหน้าเว็บพาไปที่อื่นด้วย JS หลังโหลด — ต้องเช็กปลายทางสุดท้ายซ้ำ
            if final_host and final_host != host:
                ok_ip, why = resolve_safe_ip(final_host)
                if not ok_ip:
                    return _fail(f"หน้าเว็บพาไปยังปลายทางที่ไม่ปลอดภัย: {why}")

            html = page.content()[:MAX_HTML]
            status = resp.status
    except Exception as exc:                      # noqa: BLE001
        return _fail(f"sandbox ทำงานผิดพลาด: {type(exc).__name__}")
    finally:
        if browser is not None:
            try:
                browser.close()
            except Exception:                      # noqa: BLE001
                pass

    page_host = (urlsplit(final_url).hostname or "").lower()
    return {
        "ok": True,
        "reason": "",
        "final_url": final_url,
        "status": status,
        "html": html,
        "raw_html": raw_html,
        "network_posts": [
            {"url": p["url"], "cross_origin": not _same_site(p["host"], page_host)}
            for p in posts
        ],
    }


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def token_ok(header_value: str) -> bool:
    """ตรวจ token แบบเทียบเวลาคงที่ (กันการเดาทีละตัวอักษรจากเวลาที่ใช้ตอบ)

    ถ้าไม่ได้ตั้ง SANDBOX_TOKEN ไว้ = ไม่ยอมให้เรียกเลย ปลอดภัยกว่าเปิดฟรี
    """
    expected = os.environ.get("SANDBOX_TOKEN", "")
    if not expected:
        return False
    prefix = "Bearer "
    if not header_value or not header_value.startswith(prefix):
        return False
    # ต้องแปลงเป็น bytes ก่อนเทียบ — compare_digest ไม่รับสตริงที่มีอักขระนอก ASCII
    # ถ้าไม่แปลง คนที่ส่ง header ภาษาไทยมาจะทำให้บริการโยน error แทนที่จะตอบ 401
    return hmac.compare_digest(header_value[len(prefix):].encode("utf-8"),
                               expected.encode("utf-8"))


class Handler(BaseHTTPRequestHandler):
    server_version = "checklink-sandbox"

    def _send(self, code: int, payload: dict):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": True, "service": "checklink-sandbox"})
        else:
            self._send(404, {"ok": False, "reason": "ไม่มีเส้นทางนี้"})

    def do_POST(self):
        if self.path != "/fetch":
            self._send(404, {"ok": False, "reason": "ไม่มีเส้นทางนี้"})
            return
        if not token_ok(self.headers.get("Authorization", "")):
            self._send(401, {"ok": False, "reason": "token ไม่ถูกต้อง"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 4096:
            self._send(400, {"ok": False, "reason": "คำขอผิดรูปแบบ"})
            return

        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
            url = data["url"]
        except Exception:                          # noqa: BLE001
            self._send(400, {"ok": False, "reason": "อ่าน JSON ไม่ได้"})
            return
        if not isinstance(url, str) or len(url) > 2048:
            self._send(400, {"ok": False, "reason": "url ไม่ถูกต้อง"})
            return

        # เต็มคิวแล้วตอบปฏิเสธทันที ดีกว่าให้คำขอกองรอจนเครื่องแรมหมด
        if not _slot.acquire(timeout=BUSY_WAIT_SEC):
            self._send(503, {"ok": False, "reason": "sandbox ไม่ว่าง"})
            return
        try:
            self._send(200, fetch_bundle(url))
        finally:
            _slot.release()

    def log_message(self, fmt, *args):
        """ไม่บันทึก URL ที่ตรวจลง log — เป็นข้อมูลของผู้ใช้ ไม่ใช่ของเรา"""
        return


def main():
    host = os.environ.get("SANDBOX_BIND", "127.0.0.1")
    port = int(os.environ.get("SANDBOX_PORT", "8900"))
    if not os.environ.get("SANDBOX_TOKEN"):
        raise SystemExit("ต้องตั้ง SANDBOX_TOKEN ก่อน ไม่งั้นบริการนี้จะปฏิเสธทุกคำขอ")
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()

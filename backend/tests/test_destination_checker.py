# -*- coding: utf-8 -*-
"""
test_destination_checker.py — เทสต์การป้องกัน SSRF ของชั้นที่ 3 (Redirect Resolution)

ปลายทางไฟล์จริง: backend/tests/test_destination_checker.py

ทำไมชั้นนี้ต้องมีเทสต์คุมแน่นที่สุดรองจาก url_parser: destination_checker เป็นจุดเดียว
ในระบบที่ "ยิง HTTP ไปยังปลายทางที่ผู้ใช้ (หรือมิจฉาชีพ) เป็นคนกำหนด" ถ้าการเช็ก IP
พลาดแม้แต่ range เดียว เซิร์ฟเวอร์ของเราจะกลายเป็นเครื่องมือยิงเข้าเครือข่ายภายในตัวเอง
(SSRF) เช่นอ่าน cloud metadata (169.254.169.254) ที่เก็บ credential ของเครื่องได้

เทสต์ทั้งไฟล์นี้ **ไม่แตะเครือข่ายจริงเลย** — ใช้สองเทคนิค:
  1) IP ที่เขียนเป็นเลขตรง ๆ (literal): getaddrinfo แปลงได้โดยไม่ต้องถาม DNS
  2) โดเมนสมมุติ: monkeypatch getaddrinfo/requests.head ให้ตอบตามที่เทสต์กำหนด
จึงรันได้เร็วและผลไม่แกว่งตามสภาพเน็ต (หลักเดียวกับเทสต์อื่นทั้งโปรเจกต์)
"""
import socket

from analyzer.destination_checker import (
    MAX_HOPS, _is_blocked_ip, _resolve_safe_ips, resolve_destination)


def _addrinfo(ip: str) -> list:
    """สร้างผลลัพธ์รูปแบบเดียวกับ socket.getaddrinfo คืน (โค้ดจริงอ่าน info[4][0])"""
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return [(fam, socket.SOCK_STREAM, 6, "", (ip, 0))]


class TestIPที่ต้องถูกบล็อก:
    """_is_blocked_ip ต้องกัน "ทุก" range ภายใน/สงวน — พลาด range เดียว = ช่อง SSRF"""

    def test_loopback(self):
        """127.0.0.0/8 ทั้งวง ไม่ใช่แค่ 127.0.0.1 — บริการภายในเครื่องฟังบน IP วงนี้ได้ทุกตัว"""
        assert _is_blocked_ip("127.0.0.1") is True
        assert _is_blocked_ip("127.8.9.10") is True

    def test_private_ทุกวง(self):
        """RFC 1918 ทั้งสามวง — คือเครือข่ายภายในของ VPS/องค์กร"""
        assert _is_blocked_ip("10.0.0.5") is True
        assert _is_blocked_ip("172.16.0.1") is True
        assert _is_blocked_ip("172.31.255.254") is True
        assert _is_blocked_ip("192.168.1.1") is True

    def test_ขอบเขตของวง_172(self):
        """172.16.0.0/12 คือ 172.16-172.31 เท่านั้น — นอกวงต้องไม่ถูกบล็อก
        (บล็อกเกินขอบ = false positive กับเว็บจริงที่ใช้ IP สาธารณะย่านนั้น)"""
        assert _is_blocked_ip("172.15.255.255") is False
        assert _is_blocked_ip("172.32.0.1") is False

    def test_link_local_และ_cloud_metadata(self):
        """169.254.169.254 คือ endpoint ของ cloud metadata (AWS/GCP/DigitalOcean)
        ถ้ายิงถึงได้ = อ่าน credential/config ของเครื่องเราเองได้ — เคสอันตรายสุดของ SSRF"""
        assert _is_blocked_ip("169.254.169.254") is True
        assert _is_blocked_ip("169.254.0.1") is True

    def test_ipv6_loopback_และ_ula(self):
        """IPv6 มี range ภายในของตัวเอง: ::1 (loopback), fc00::/7 (unique-local),
        fe80::/10 (link-local) — ระบบที่เช็กแต่ IPv4 จะโดนเจาะผ่าน IPv6 แทน"""
        assert _is_blocked_ip("::1") is True
        assert _is_blocked_ip("fc00::1") is True
        assert _is_blocked_ip("fd12:3456::1") is True
        assert _is_blocked_ip("fe80::1") is True

    def test_unspecified_reserved_multicast(self):
        assert _is_blocked_ip("0.0.0.0") is True
        assert _is_blocked_ip("240.0.0.1") is True     # reserved
        assert _is_blocked_ip("224.0.0.1") is True     # multicast

    def test_ค่าที่แปลงไม่ได้ต้อง_fail_closed(self):
        """แปลงเป็น IP ไม่ได้ = บล็อกไว้ก่อน (ปลอดภัยกว่าปล่อยผ่านของที่ไม่เข้าใจ)"""
        assert _is_blocked_ip("not-an-ip") is True
        assert _is_blocked_ip("") is True

    def test_ip_สาธารณะต้องไม่ถูกบล็อก(self):
        """ฝั่งตรงข้ามก็ต้องคุม: บล็อกเกินไป = ตรวจเว็บจริงไม่ได้เลย"""
        assert _is_blocked_ip("8.8.8.8") is False
        assert _is_blocked_ip("1.1.1.1") is False
        assert _is_blocked_ip("93.184.216.34") is False
        assert _is_blocked_ip("2606:4700::1111") is False


class TestResolveSafeIps:
    """_resolve_safe_ips ต้องแยก 3 กรณีชัด: ปลอดภัย / dns_fail / blocked_ip
    เพราะสองกรณีหลังมีความหมายต่างกันมาก (เช็กไม่ได้ ≠ อันตราย)"""

    def test_dns_ตอบ_private_ip(self, monkeypatch):
        """เคสสำคัญที่สุดในสเปก: โดเมนสาธารณะหน้าตาปกติ แต่ DNS ชี้เข้าเครือข่ายภายใน
        (เทคนิคหลบระบบตรวจ/โจมตี SSRF ที่ใช้จริง) ต้องได้ blocked_ip"""
        monkeypatch.setattr(socket, "getaddrinfo",
                            lambda host, *a, **kw: _addrinfo("192.168.1.50"))
        ips, status, reason = _resolve_safe_ips("innocent-looking.example")
        assert status == "blocked_ip"
        assert ips is None
        assert reason  # ต้องมีเหตุผลไว้แสดงผู้ใช้ ไม่ใช่บล็อกเงียบ ๆ

    def test_dns_ตอบหลาย_ip_มี_private_ปนต้องบล็อก(self, monkeypatch):
        """ต้องเช็ก "ทุก" IP ที่ resolve ได้ ไม่ใช่แค่ตัวแรก — round-robin DNS ที่มี
        IP ภายในปนอยู่แม้ตัวเดียวก็ใช้ทำ SSRF ได้ (client เลือก IP ตัวไหนก็ได้)"""
        answers = _addrinfo("93.184.216.34") + _addrinfo("10.0.0.7")
        monkeypatch.setattr(socket, "getaddrinfo", lambda host, *a, **kw: answers)
        _, status, _ = _resolve_safe_ips("mixed.example")
        assert status == "blocked_ip"

    def test_dns_fail_ไม่ใช่_blocked(self, monkeypatch):
        """หลักของระบบ: "เช็กไม่ได้" ≠ "เสี่ยง" — โดเมนที่ resolve ไม่ได้ (พิมพ์ผิด/
        เพิ่งถูกปิด) ต้องเป็น dns_fail ไม่ใช่ blocked_ip"""
        def boom(host, *a, **kw):
            raise socket.gaierror(-2, "Name or service not known")
        monkeypatch.setattr(socket, "getaddrinfo", boom)
        ips, status, reason = _resolve_safe_ips("no-such-domain.example")
        assert status == "dns_fail"
        assert ips is None

    def test_dns_ตอบ_public_ล้วนต้องผ่าน(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo",
                            lambda host, *a, **kw: _addrinfo("93.184.216.34"))
        ips, status, _ = _resolve_safe_ips("normal.example")
        assert status == ""
        assert ips == {"93.184.216.34"}


class _FakeResp:
    def __init__(self, status: int, location: str = None):
        self.status_code = status
        self.headers = {"Location": location} if location else {}


class TestResolveDestination:
    """เทสต์ทั้งเส้นทางของ resolve_destination — จุดที่ SSRF ต้องถูกกันจริง"""

    def test_localhost_ตรง_ๆ_ถูกบล็อกก่อนยิง(self):
        """URL ที่ชี้ loopback ตรง ๆ ต้องถูกบล็อก "ก่อน" มี request ออกไปแม้แต่ครั้งเดียว
        (literal IP ไม่ต้องถาม DNS — เทสต์นี้จึงไม่แตะเน็ตจริง)"""
        result = resolve_destination("http://127.0.0.1/admin")
        assert result["blocked"] is True
        assert result["resolved"] is False
        assert result["blocked_reason"]

    def test_cloud_metadata_ถูกบล็อก(self):
        """169.254.169.254 = ประตูสู่ credential ของเครื่องบนคลาวด์ทุกเจ้า"""
        result = resolve_destination("http://169.254.169.254/latest/meta-data/")
        assert result["blocked"] is True

    def test_private_ip_ถูกบล็อก(self):
        result = resolve_destination("http://192.168.0.1/router")
        assert result["blocked"] is True

    def test_ipv6_loopback_ถูกบล็อก(self):
        result = resolve_destination("http://[::1]:8080/")
        assert result["blocked"] is True

    def test_scheme_ที่ไม่ใช่เว็บถูกปฏิเสธ(self):
        """สเปกข้อ 1: อนุญาตเฉพาะ http/https — ftp/gopher ฯลฯ ใช้ทำ SSRF รูปแบบอื่นได้"""
        result = resolve_destination("ftp://example.com/file")
        assert result["resolved"] is False
        assert "โปรโตคอล" in result.get("error", "")
        assert not result.get("blocked")   # ไม่ใช่การเจอ IP อันตราย แค่ไม่รองรับ

    def test_redirect_ไป_private_ip_ถูกบล็อกที่_hop_ที่สอง(self, monkeypatch):
        """เคสหัวใจของสเปก: hop แรกเป็นเว็บสาธารณะปกติ แล้ว redirect เข้า 127.0.0.1
        — การเช็กครั้งแรกครั้งเดียวจะพลาดเคสนี้ ต้องเช็กซ้ำ "ทุก hop"
        และถือโอกาสยืนยันไปด้วยว่า header ที่ส่งออกไม่มี Cookie/Authorization ติดไป
        (สเปกข้อ 2: ไม่ forward credential ใด ๆ ไปยังปลายทางที่ผู้ใช้กำหนด)"""
        sent = []

        def fake_getaddrinfo(host, *a, **kw):
            table = {"promo.example": "93.184.216.34", "127.0.0.1": "127.0.0.1"}
            return _addrinfo(table[host])

        def fake_head(url, timeout=None, allow_redirects=None, headers=None):
            sent.append({"url": url, "timeout": timeout, "headers": headers})
            return _FakeResp(302, "http://127.0.0.1/admin")

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        monkeypatch.setattr("requests.head", fake_head)

        result = resolve_destination("http://promo.example/win-prize")

        assert result["blocked"] is True
        assert result["hops"] == 1
        assert result["chain"] == ["http://promo.example/win-prize",
                                   "http://127.0.0.1/admin"]
        assert result["final_url"] == "http://127.0.0.1/admin"
        # ยิงออกไปแค่ hop แรก (hop สองถูกบล็อกก่อนยิง) และไม่มี credential ติดไป
        assert len(sent) == 1
        assert set(sent[0]["headers"].keys()) == {"User-Agent"}
        assert sent[0]["timeout"] is not None   # ทุก request ต้องมี timeout เสมอ

    def test_จำกัดจำนวน_hop(self, monkeypatch):
        """redirect วนไม่รู้จบต้องหยุดที่ MAX_HOPS — กัน resource exhaustion
        และกันมิจฉาชีพใช้ chain ยาว ๆ ถ่วงเวลาระบบ"""
        counter = {"n": 0}

        def fake_head(url, timeout=None, allow_redirects=None, headers=None):
            counter["n"] += 1
            return _FakeResp(302, f"http://hop{counter['n']}.example/")

        monkeypatch.setattr(socket, "getaddrinfo",
                            lambda host, *a, **kw: _addrinfo("93.184.216.34"))
        monkeypatch.setattr("requests.head", fake_head)

        result = resolve_destination("http://hop0.example/")
        assert result["hops"] == MAX_HOPS
        assert len(result["chain"]) == MAX_HOPS + 1
        assert result["resolved"] is True
        assert not result.get("blocked")

    def test_ปลายทางตอบ_200_จบปกติ(self, monkeypatch):
        monkeypatch.setattr(socket, "getaddrinfo",
                            lambda host, *a, **kw: _addrinfo("93.184.216.34"))
        monkeypatch.setattr("requests.head",
                            lambda url, **kw: _FakeResp(200))
        result = resolve_destination("http://normal.example/page")
        assert result["resolved"] is True
        assert result["hops"] == 0
        assert result["chain"] == ["http://normal.example/page"]
        assert not result.get("blocked")

    def test_redirect_ไปโดเมนที่_resolve_ไม่ได้_เป็น_dns_fail_ไม่ใช่_blocked(self, monkeypatch):
        """redirect ไปโดเมนที่ตายแล้ว: ตามหลัก "เช็กไม่ได้ ≠ เสี่ยง" ต้องได้ error
        (dns_fail) ไม่ใช่ blocked และ final_url ต้องเป็น URL จาก Location จริง
        เพื่อให้ชั้น 2 ยังวิเคราะห์เชิงข้อความต่อได้โดยไม่ต้องพึ่งเครือข่าย"""
        def fake_getaddrinfo(host, *a, **kw):
            if host == "alive.example":
                return _addrinfo("93.184.216.34")
            raise socket.gaierror(-2, "Name or service not known")

        monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
        monkeypatch.setattr("requests.head",
                            lambda url, **kw: _FakeResp(302, "http://gone.example/x"))

        result = resolve_destination("http://alive.example/short")
        assert not result.get("blocked")
        assert result["error"]
        assert result["final_url"] == "http://gone.example/x"
        assert result["resolved"] is True   # ตามสำเร็จไปแล้ว 1 hop ก่อนเจอทางตัน

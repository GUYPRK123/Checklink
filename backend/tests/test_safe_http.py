# -*- coding: utf-8 -*-
"""
test_safe_http.py — เทสต์ด่านสุดท้ายกัน SSRF: เช็ก IP ปลายทางจริงหลัง socket ต่อติด

ปลายทางไฟล์จริง: backend/tests/test_safe_http.py

ทำไมต้องมีด่านนี้ทั้งที่ชั้นที่ 3 เช็ก IP ก่อนต่ออยู่แล้ว: การเช็กก่อนต่อถาม DNS
คนละรอบกับตอนที่ requests ต่อจริง เจ้าของโดเมนสลับคำตอบระหว่างสองรอบนั้นได้
(DNS rebinding) ด่านนี้จึงเช็กที่ getpeername() ซึ่งเป็น IP ที่ kernel ต่อไปจริง ๆ
โกงไม่ได้ — เหตุผลเต็มอยู่ในหัวไฟล์ analyzer/safe_http.py

เทสต์ชุดนี้ไม่แตะอินเทอร์เน็ต: ใช้ socket ปลอม, ตรวจการต่อสายภายใน urllib3,
และเปิดผู้ฟังบน 127.0.0.1 ของเครื่องเทสต์เอง (loopback ล้วน ไม่ออกนอกเครื่อง)
"""
import socket
import threading

import pytest

from analyzer.safe_http import (
    BlockedAddressError, assert_peer_allowed, is_blocked_ip, safe_adapter_cls,
    safe_session)


class _FakeSock:
    """socket ปลอมที่บอกได้ว่าปลายทางคือ IP อะไร และถูกสั่งปิดไปแล้วหรือยัง"""

    def __init__(self, peer, raises=False):
        self._peer, self._raises = peer, raises
        self.closed = False

    def getpeername(self):
        if self._raises:
            raise OSError("socket ปิดไปแล้ว")
        return self._peer

    def close(self):
        self.closed = True


class TestIPที่ต้องถูกบล็อก:
    """เกณฑ์ต้องเหมือนกับด่านก่อนต่อเป๊ะ ๆ (โค้ดจริงใช้ฟังก์ชันเดียวกันทั้งสองด่าน)"""

    def test_วงภายในและที่สงวนไว้(self):
        for ip in ("127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254",
                   "::1", "fc00::1", "0.0.0.0", "224.0.0.1"):
            assert is_blocked_ip(ip) is True, ip

    def test_IP_สาธารณะผ่านได้(self):
        for ip in ("8.8.8.8", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"):
            assert is_blocked_ip(ip) is False, ip

    def test_loopback_ที่เขียนในรูป_IPv6_ก็ต้องโดน(self):
        """::ffff:127.0.0.1 คือ 127.0.0.1 ที่เขียนอีกแบบ — ipaddress ไม่ได้มองรูปนี้
        เป็นวงภายในให้เอง ถ้าไม่คลี่กลับมาเช็กเป็น IPv4 จะเป็นช่องข้ามด่านทันที"""
        assert is_blocked_ip("::ffff:127.0.0.1") is True
        assert is_blocked_ip("::ffff:169.254.169.254") is True
        assert is_blocked_ip("::ffff:8.8.8.8") is False

    def test_อ่านไม่ออกถือว่าบล็อก(self):
        """ของที่แปลงเป็น IP ไม่ได้ต้องไม่ถูกปล่อยผ่านโดยปริยาย"""
        assert is_blocked_ip("") is True
        assert is_blocked_ip("ไม่ใช่ไอพี") is True


class Testตรวจปลายทางของsocket:

    def test_ปลายทางสาธารณะผ่านและคืน_IP(self):
        sock = _FakeSock(("93.184.216.34", 443))
        assert assert_peer_allowed(sock) == "93.184.216.34"
        assert sock.closed is False

    def test_ปลายทางภายในถูกตัดและ_socket_ถูกปิด(self):
        """ต้องปิด socket ให้ด้วย ไม่ใช่แค่ raise — ผู้เรียกที่รับ exception ไม่มี
        handle ของ socket ตัวนี้แล้ว ถ้าไม่ปิดคือปล่อย connection ค้างไว้ทุกครั้งที่โดนโจมตี"""
        sock = _FakeSock(("127.0.0.1", 5000))
        with pytest.raises(BlockedAddressError) as err:
            assert_peer_allowed(sock)
        assert "127.0.0.1" in str(err.value)
        assert sock.closed is True

    def test_อ่าน_getpeername_ไม่ได้ก็ต้องตัด(self):
        """เช็กไม่ได้ = ไม่ปล่อยผ่าน (หลักเดียวกับ is_blocked_ip ของที่อ่านไม่ออก)"""
        sock = _FakeSock(None, raises=True)
        with pytest.raises(BlockedAddressError):
            assert_peer_allowed(sock)
        assert sock.closed is True

    def test_ไม่ใช่ข้อผิดพลาดของเครือข่าย(self):
        """จงใจไม่ให้ BlockedAddressError เป็น OSError: ถ้าเป็น urllib3 จะนับเป็น
        "เน็ตสะดุด" แล้ว retry ให้เอง และผู้เรียกจะแยกไม่ออกจากเว็บล่มธรรมดา
        ทั้งที่กรณีนี้คือสัญญาณอันตรายที่ต้องเอาไปให้คะแนน"""
        assert not issubclass(BlockedAddressError, OSError)


class Testสายไฟเข้ากับrequests:
    """ด่านนี้ต้องไปฝังอยู่ในชั้น urllib3 จริง ๆ ไม่ใช่แค่มีฟังก์ชันไว้เฉย ๆ
    ถ้า urllib3 เวอร์ชันใหม่เปลี่ยน API ภายใน เทสต์กลุ่มนี้คือตัวที่จะดังขึ้นก่อน"""

    def test_session_ใช้_adapter_ของเรากับทั้ง_http_และ_https(self):
        with safe_session() as session:
            for url in ("http://x.example/", "https://x.example/"):
                assert isinstance(session.get_adapter(url), safe_adapter_cls())

    def test_pool_ถูกเปลี่ยนเป็นคลาสที่ตรวจปลายทาง(self):
        adapter = safe_adapter_cls()()
        pools = adapter.poolmanager.pool_classes_by_scheme
        for scheme in ("http", "https"):
            conn_cls = pools[scheme].ConnectionCls
            # ต้องมีทั้งสองจุดตรวจ (_new_conn = ก่อนส่งไบต์แรก, connect = กันเหนียว)
            assert "_new_conn" in dir(conn_cls) and "connect" in dir(conn_cls)
            assert any(c.__name__ == "_PeerCheckMixin" for c in conn_cls.__mro__)

    def test_ต่อไป_loopback_ถูกตัดก่อนส่งไบต์แรก(self):
        """เปิดผู้ฟังบน 127.0.0.1 ของเครื่องเทสต์เอง (ไม่ออกนอกเครื่อง) แล้วยิงผ่าน
        requests จริงทั้งกอง — พิสูจน์สองอย่างพร้อมกัน: ด่านทำงานผ่าน requests ได้จริง
        และผู้ฟังปลายทาง "ไม่ได้รับอะไรเลย" คือไม่มี HTTP request หลุดออกไปถึงบริการภายใน"""
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        received = []

        def รับสาย():
            try:
                conn, _ = server.accept()
                conn.settimeout(1)
                try:
                    received.append(conn.recv(64))
                except OSError:
                    received.append(b"")
                conn.close()
            except OSError:
                pass

        thread = threading.Thread(target=รับสาย, daemon=True)
        thread.start()
        try:
            with safe_session() as session:
                with pytest.raises(BlockedAddressError):
                    session.get(f"http://127.0.0.1:{port}/", timeout=3)
        finally:
            thread.join(timeout=2)
            server.close()

        assert received in ([], [b""]), f"มีข้อมูลหลุดไปถึงปลายทาง: {received!r}"

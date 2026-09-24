# -*- coding: utf-8 -*-
"""
safe_http.py
============================================================================
  >>> ประตูเดียวที่ทุกชั้นต้องใช้เวลาจะ "ต่อออกนอก" ไปหา URL ของผู้ใช้ <<<
============================================================================
โมดูลนี้มีหน้าที่เดียว: ทำให้แน่ใจว่า **socket ที่ต่อติดจริง** ปลายอยู่ที่ IP สาธารณะ
ไม่ใช่ IP ภายในของเครื่องเราเอง

**ทำไมการ resolve DNS ก่อนต่อจึงยังไม่พอ (ช่องที่ปิดในไฟล์นี้)**

เดิมทุกชั้นทำสองขั้นแยกกัน:

    1) _resolve_safe_ips(host)   -> ถาม DNS เอง เช็กว่าทุก IP ไม่ใช่วงภายใน
    2) requests.get(url)          -> requests ไป **ถาม DNS ใหม่อีกรอบ** แล้วต่อ

ระหว่างขั้น 1 กับ 2 เจ้าของโดเมนเปลี่ยนคำตอบของ DNS ได้ (ตั้ง TTL=0 แล้วสลับ
เป็น 127.0.0.1) ขั้นที่ 1 จึงไม่ได้การันตีอะไรกับ "การต่อจริง" ในขั้นที่ 2 เลย —
ช่องนี้มีชื่อเรียกว่า **DNS rebinding** และเป็นท่ามาตรฐานที่ใช้ข้ามด่านกัน SSRF
ที่เช็กแต่ชื่อโดเมน ถ้าสำเร็จ ผู้โจมตีสั่งให้เครื่องเรายิงไปที่ 127.0.0.1:5000
(ตัวเว็บเราเอง) หรือ 169.254.169.254 (metadata ของผู้ให้บริการคลาวด์ ซึ่งคายคีย์
เข้าเครื่องได้) โดยส่งมาแค่ลิงก์ให้ระบบ "ตรวจ" เท่านั้น

วิธีปิด: ตรวจอีกครั้งที่ "จุดที่โกงไม่ได้" คือ **หลัง TCP ต่อติดแล้ว** ด้วย
`getpeername()` ซึ่งคืน IP ที่ kernel ต่อไปจริง ๆ ไม่ใช่สิ่งที่ DNS บอก ถ้าปลายทาง
เป็นวงภายใน ให้ปิด socket แล้วโยน BlockedAddressError ออกไปทันที — **ก่อน**
ส่งไบต์แรกและก่อนทำ TLS handshake

ยังคง _resolve_safe_ips ไว้ตามเดิมทั้งหมด ไม่ใช่ของซ้ำซ้อน: มันคัดทิ้งได้เร็วกว่า
โดยไม่ต้องเปิด TCP เลย และแยกกรณี dns_fail (โดเมนไม่มีจริง — ไม่ใช่อันตราย) ออกจาก
blocked_ip (สัญญาณ SSRF จริง) ได้ ส่วนไฟล์นี้คือ "ด่านสุดท้าย" ที่ไม่มีช่องเวลาให้โกง

ข้อจำกัดที่ต้องรู้: ถ้าวันไหนตั้ง HTTP(S)_PROXY ให้โปรเซสนี้ getpeername() จะเห็น
IP ของ proxy ไม่ใช่ปลายทางจริง การกันจะย้ายไปเป็นหน้าที่ของ proxy ทันที
(ตอนนี้ไม่ได้ตั้ง และไม่ควรตั้ง)
"""
import ipaddress
import socket


class BlockedAddressError(Exception):
    """socket ต่อติดแล้วแต่ปลายทางจริงเป็น IP ภายใน/สงวนไว้ -> ตัดทิ้งกลางทาง

    จงใจ **ไม่** สืบทอดจาก OSError: ถ้าเป็น OSError urllib3 จะนับเป็น "เน็ตสะดุด"
    แล้ว retry ให้อีกหลายรอบ และสุดท้ายผู้เรียกจะเห็นแค่ ConnectionError ธรรมดา
    แยกไม่ออกจากเว็บล่ม — ซึ่งต่างกันมาก เพราะกรณีนี้คือ "สัญญาณอันตรายชัดเจน"
    ที่ scanner ต้องเอาไปให้คะแนน ไม่ใช่ "เช็กไม่ได้"
    """


def is_blocked_ip(ip_str: str) -> bool:
    """True ถ้าเป็น IP ที่ไม่ควรให้ backend ยิงเข้าไปหา (วง internal/สงวนไว้)

    แปลงไม่ได้ก็ถือว่าบล็อก — ของที่อ่านไม่ออกต้องไม่ถูกปล่อยผ่านโดยปริยาย
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if ip.version == 6 and ip.ipv4_mapped is not None:
        # ::ffff:127.0.0.1 คือ 127.0.0.1 ที่เขียนในรูป IPv6 — ตัว flag ของ ipaddress
        # (is_private ฯลฯ) มองรูปนี้ไม่เป็นวงภายใน จึงต้องคลี่กลับมาเช็กเป็น IPv4 เอง
        return is_blocked_ip(str(ip.ipv4_mapped))
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def assert_peer_allowed(sock) -> str:
    """เช็ก IP ปลายทางจริงของ socket ที่ต่อติดแล้ว คืน IP นั้นถ้าผ่าน

    ไม่ผ่าน = ปิด socket ทิ้งก่อน แล้ว raise BlockedAddressError (ปิดเองที่นี่เพราะ
    ผู้เรียกที่รับ exception ไปจะไม่มี handle ของ socket ตัวนี้แล้ว)
    """
    try:
        peer = sock.getpeername()
    except OSError as e:
        _close_quietly(sock)
        raise BlockedAddressError(f"อ่านปลายทางของ connection ไม่ได้ ({e})") from e

    ip = peer[0] if peer else ""
    if is_blocked_ip(ip):
        _close_quietly(sock)
        raise BlockedAddressError(
            f"ปลายทางจริงของ connection เป็น IP ภายใน/สงวนไว้ ({ip}) "
            "— โดเมนสลับคำตอบ DNS หลังถูกตรวจ (DNS rebinding)")
    return ip


def _close_quietly(sock) -> None:
    try:
        sock.close()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# ผูกการตรวจข้างบนเข้ากับ requests
# ---------------------------------------------------------------------------
# requests ไม่มี hook ให้ดูตัว socket ตรง ๆ ต้องลงไปถึงชั้น urllib3 ที่มันใช้อยู่
# ข้างใน คลาสพวกนี้จึงถูกสร้างแบบ lazy (ตอนเรียกใช้ครั้งแรก) ด้วยเหตุผลเดียวกับที่
# ทุกไฟล์ในโฟลเดอร์นี้ import requests แบบ lazy: analyzer/ ต้อง import ได้และเทสต์ได้
# แม้ในเครื่องที่ยังไม่ได้ลง requests
_adapter_cls = None


def _build_adapter_cls():
    from requests.adapters import HTTPAdapter
    from urllib3.connection import HTTPConnection, HTTPSConnection
    from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool

    class _PeerCheckMixin:
        """ตรวจ IP ปลายทางจริงสองจุด (จงใจซ้ำ — คนละเหตุผล)"""

        def _new_conn(self):
            # จุดหลัก: urllib3 เปิด TCP ที่นี่ แล้วถึงเอา socket ไปทำ TLS handshake
            # ต่อใน connect() ตรวจที่นี่จึงได้ก่อน "ไบต์แรกออกจากเครื่อง" จริง ๆ
            sock = super()._new_conn()
            assert_peer_allowed(sock)
            return sock

        def connect(self):
            # กันเหนียว: _new_conn() เป็น API ภายในของ urllib3 ถ้าวันหนึ่งมันเปลี่ยนชื่อ
            # เมธอดข้างบนจะไม่ถูกเรียกเลย "แบบเงียบ ๆ" ซึ่งเป็นความล้มเหลวที่แย่ที่สุด
            # ของโค้ดความปลอดภัย -> ตรวจซ้ำที่ connect() ซึ่งเป็น API ที่มีทุกเวอร์ชัน
            # (ตรงนี้ TLS handshake จบแล้ว แต่ยังไม่ได้ส่ง HTTP request ออกไป)
            super().connect()
            assert_peer_allowed(self.sock)

    class _SafeHTTPConnection(_PeerCheckMixin, HTTPConnection):
        pass

    class _SafeHTTPSConnection(_PeerCheckMixin, HTTPSConnection):
        pass

    class _SafeHTTPConnectionPool(HTTPConnectionPool):
        ConnectionCls = _SafeHTTPConnection

    class _SafeHTTPSConnectionPool(HTTPSConnectionPool):
        ConnectionCls = _SafeHTTPSConnection

    class SafeHTTPAdapter(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            super().init_poolmanager(*args, **kwargs)
            # pool_classes_by_scheme เป็น attribute ของ "instance" (ไม่ใช่ของคลาส)
            # จึงเปลี่ยนได้โดยไม่กระทบ PoolManager ตัวอื่นในโปรเซสเดียวกัน
            self.poolmanager.pool_classes_by_scheme = {
                "http": _SafeHTTPConnectionPool,
                "https": _SafeHTTPSConnectionPool,
            }

    return SafeHTTPAdapter


def safe_adapter_cls():
    """คลาส HTTPAdapter ที่ตรวจ IP ปลายทางจริงทุก connection (สร้างครั้งเดียว)"""
    global _adapter_cls
    if _adapter_cls is None:
        _adapter_cls = _build_adapter_cls()
    return _adapter_cls


def safe_session():
    """requests.Session ที่ทุก connection ผ่านการตรวจ getpeername()

    ใช้เป็น context manager เสมอ:  with safe_session() as s: s.get(...)

    สร้างใหม่ทุกครั้งโดยตั้งใจ — เท่ากับพฤติกรรมเดิมของโค้ดนี้ที่เรียก requests.get()
    ตรง ๆ (ตัวนั้นก็สร้าง Session ใหม่ทุกครั้งอยู่แล้ว) จึงไม่ต้องมาคิดเรื่อง
    Session ที่ไม่ thread-safe ในชั้นที่ 4 ซึ่งรันหลาย thread
    """
    import requests

    session = requests.Session()
    adapter = safe_adapter_cls()()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    # trust_env=False: ไม่ให้ตัวแปรแวดล้อม (HTTP_PROXY/NO_PROXY) แทรกกลางทางได้
    # เพราะถ้ามี proxy คั่น getpeername() จะเห็นแต่ IP ของ proxy แล้วด่านนี้จะเป็นโมฆะ
    session.trust_env = False
    return session


def safe_create_connection(host: str, port: int, timeout=None):
    """socket.create_connection ที่ตรวจ IP ปลายทางจริงให้ก่อนคืน

    มีไว้ให้ทางที่ไม่ได้ใช้ requests — ตอนนี้คือ TLS handshake ใน domain_intel.py
    """
    sock = socket.create_connection((host, port), timeout=timeout)
    assert_peer_allowed(sock)
    return sock

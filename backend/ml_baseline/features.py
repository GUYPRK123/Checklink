# -*- coding: utf-8 -*-
"""
features.py — แปลง URL หนึ่งเส้นให้เป็นตัวเลขชุดหนึ่ง สำหรับให้โมเดล ML เรียนรู้

ที่มาของแนวคิด: Mohammad, Thabtah & McCluskey (2014) IET Information Security
"Predicting phishing websites based on self-structuring neural network" —
งานนั้นเสนอ "รายการสิ่งที่ควรดูจากตัว URL" ไว้ (ความยาว, จำนวนขีด, มี IP แทนชื่อ,
จำนวนโดเมนย่อย ฯลฯ) ไฟล์นี้หยิบเฉพาะฟีเจอร์ที่ดูจาก URL ได้อย่างเดียวมาใช้

*** จุดสำคัญที่ต้องเข้าใจก่อนอ่านผล ***
ฟีเจอร์ในไฟล์นี้จงใจเป็น "ลักษณะทางตัวอักษร" ล้วน ๆ — ไม่มีการเอาลิสต์แบรนด์
(BRANDS) หรือลิสต์พื้นที่ฝากเว็บฟรี (USER_CONTENT_DOMAINS) ของระบบเดิมมาใส่เลย
เพราะถ้าใส่ ผลที่ได้จะไม่ใช่ "ML เทียบกับ rule-based" แต่กลายเป็น "rule-based
ที่มี ML ต่อท้าย" ซึ่งตอบคำถามที่อาจารย์ถามไม่ได้

ใช้ parse_url ของโปรเจกต์เองในการแยกส่วน URL เพื่อให้ทั้งสองระบบ "มองเห็น
โครงสร้าง URL เหมือนกันเป๊ะ" ต่างกันแค่วิธีตัดสินเท่านั้น
"""
import math
import os
import re
import sys
from collections import Counter
from urllib.parse import urlsplit, parse_qs

# ให้ import analyzer จากโฟลเดอร์ backend ได้ ไม่ว่าจะรันจากที่ไหน
_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_HERE)
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from analyzer.url_parser import parse_url          # noqa: E402

_DIGIT = re.compile(r"\d")
_HEX_ENCODED = re.compile(r"%[0-9a-fA-F]{2}")

# ชื่อฟีเจอร์ เรียงตามลำดับที่ vectorize() คืนค่า (ต้องตรงกันเสมอ)
FEATURE_NAMES = [
    "url_len", "host_len", "path_len", "query_len",
    "num_dots", "num_hyphens_host", "num_slashes_path", "num_at", "num_qmark",
    "num_equals", "num_percent_encoded", "num_digits_host", "digit_ratio_host",
    "num_subdomain_labels", "longest_label_len", "tld_len",
    "is_https", "is_ip_host", "is_punycode", "has_userinfo", "has_port",
    "host_entropy", "path_entropy",
    "num_query_params", "has_url_in_query", "path_depth",
    "num_vowelless_runs", "consonant_ratio_main_label",
]


def _entropy(s: str) -> float:
    """ค่าความไม่เป็นระเบียบของข้อความ (Shannon entropy)

    ชื่อโดเมนที่คนตั้งให้คนอ่าน (kasikornbank) จะมีค่าต่ำ ส่วนชื่อที่เครื่อง
    สุ่มขึ้นมา (x7k2ppq9zm) จะมีค่าสูง ใช้แยกโดเมนที่ generate อัตโนมัติได้
    """
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _consonant_ratio(s: str) -> float:
    """สัดส่วนพยัญชนะติดกัน — ชื่อที่สุ่มมามักมีพยัญชนะเรียงกันผิดธรรมชาติ"""
    letters = [c for c in s.lower() if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c not in "aeiou") / len(letters)


def _vowelless_runs(s: str, min_len: int = 4) -> int:
    """นับจำนวนช่วงที่ไม่มีสระเลยยาวเกิน min_len ตัว (สัญญาณของชื่อที่สุ่มมา)"""
    return len([m for m in re.findall(r"[bcdfghjklmnpqrstvwxyz]+", s.lower())
                if len(m) >= min_len])


def vectorize(url: str) -> list:
    """คืนค่าฟีเจอร์เป็น list ของตัวเลข เรียงตาม FEATURE_NAMES

    URL ที่ parse ไม่ได้จะคืนศูนย์ทั้งหมด — ไม่โยน exception เพราะชุดข้อมูลจริง
    มีบรรทัดเสียปนมาเสมอ และการทิ้งทั้งแถวจะทำให้จำนวนตัวอย่างสองฝั่งไม่เท่ากัน
    """
    p = parse_url(url)
    if not p.get("valid"):
        return [0.0] * len(FEATURE_NAMES)

    host = p.get("host") or ""
    path = p.get("path") or ""
    sub = p.get("subdomain") or ""
    main = p.get("main_label") or ""
    tld = p.get("tld") or ""

    # แยก path กับ query ออกจากกัน (parse_url รวมไว้ด้วยกันในคีย์ path)
    split = urlsplit(url if "://" in url else "http://" + url)
    only_path = split.path or ""
    query = split.query or ""

    labels = [x for x in host.split(".") if x]
    digits_in_host = len(_DIGIT.findall(host))

    try:
        params = parse_qs(query)
    except Exception:
        params = {}
    # มี URL ซ้อนอยู่ในพารามิเตอร์ไหม (รูปแบบของ open redirect)
    has_url_in_query = int(any(
        "http" in v.lower() or "www." in v.lower()
        for vals in params.values() for v in vals
    ))

    return [
        float(len(url)),
        float(len(host)),
        float(len(only_path)),
        float(len(query)),
        float(host.count(".")),
        float(host.count("-")),
        float(only_path.count("/")),
        float(url.count("@")),
        float(url.count("?")),
        float(url.count("=")),
        float(len(_HEX_ENCODED.findall(url))),
        float(digits_in_host),
        float(digits_in_host / len(host)) if host else 0.0,
        float(len([x for x in sub.split(".") if x])),
        float(max((len(x) for x in labels), default=0)),
        float(len(tld)),
        float(p.get("protocol") == "https"),
        float(bool(p.get("is_ip"))),
        float(bool(p.get("is_punycode"))),
        float(bool(p.get("userinfo"))),
        float(bool(p.get("port"))),
        _entropy(host),
        _entropy(only_path),
        float(len(params)),
        float(has_url_in_query),
        float(len([x for x in only_path.split("/") if x])),
        float(_vowelless_runs(host)),
        _consonant_ratio(main),
    ]


def vectorize_many(urls) -> list:
    return [vectorize(u) for u in urls]


if __name__ == "__main__":
    # ลองดูค่าฟีเจอร์ของลิงก์ที่ใส่มาทาง argument
    for u in (sys.argv[1:] or ["https://kasikornbank.com.security-check.info/login"]):
        print(f"\n{u}")
        for name, val in zip(FEATURE_NAMES, vectorize(u)):
            print(f"  {name:<28} {val:>10.3f}")

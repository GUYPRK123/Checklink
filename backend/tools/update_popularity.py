# -*- coding: utf-8 -*-
"""
update_popularity.py
สร้าง/อัปเดตไฟล์รายการโดเมนยอดนิยมที่ analyzer/popularity.py ใช้เทียบ

    cd backend && ./.venv/bin/python tools/update_popularity.py

ทำไมใช้ Tranco:
  เป็นรายการอันดับเว็บที่ทำขึ้นเพื่องานวิจัยด้านความปลอดภัยโดยเฉพาะ (KU Leuven +
  TU Delft) โดยเฉลี่ยอันดับจากหลายแหล่งย้อนหลัง 30 วัน จึงไม่แกว่งไปมาแบบรายการ
  อันดับเชิงพาณิชย์ และไม่ถูกปั่นอันดับได้ง่าย — อ้างอิงในรายงานได้
  เอกสาร: https://tranco-list.eu/  (งานตีพิมพ์: NDSS 2019)

ข้อควรรู้:
  - รายการนี้บอกแค่ "มีคนเข้าเยอะ" ไม่ได้บอกว่า "ปลอดภัย" โดเมนของบริการฝากเว็บฟรี
    ก็ติดอันดับต้น ๆ ด้วย (amazonaws.com อันดับ 7, github.io อันดับ 121) การกรอง
    พวกนี้ออกทำที่ heuristics.collect_trust ผ่าน USER_CONTENT_DOMAINS — ไม่ใช่ที่นี่
  - ตัดเก็บแค่ TOP_N อันดับแรกพอ เพราะน้ำหนักหลักฐานต่ำสุดใน POPULARITY_TIERS
    อยู่ที่อันดับ 100,000 อยู่แล้ว เก็บครบ 1 ล้านมีแต่กินแรมเปล่า ๆ
  - ควรรันซ้ำปีละครั้งสองครั้งก็พอ อันดับระดับแสนไม่ได้เปลี่ยนเร็ว
"""
import io
import os
import sys
import zipfile
from datetime import date
from urllib.request import urlopen

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
TOP_N = 100_000
OUT_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "analyzer", "data", "popular_domains.txt")


def main() -> int:
    print(f"ดาวน์โหลด {TRANCO_URL} ...")
    try:
        with urlopen(TRANCO_URL, timeout=120) as resp:
            blob = resp.read()
    except OSError as exc:
        print(f"ดาวน์โหลดไม่สำเร็จ: {exc}", file=sys.stderr)
        return 1

    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        raw = z.read(z.namelist()[0]).decode("utf-8", "replace")

    domains = []
    for line in raw.splitlines():
        # รูปแบบไฟล์: "<อันดับ>,<โดเมน>"
        _, _, dom = line.partition(",")
        dom = dom.strip().lower()
        if dom:
            domains.append(dom)
        if len(domains) >= TOP_N:
            break

    if len(domains) < 1000:
        print(f"ได้ข้อมูลมาแค่ {len(domains)} บรรทัด ดูผิดปกติ — ไม่เขียนทับไฟล์เดิม",
              file=sys.stderr)
        return 1

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as fh:
        fh.write(f"# รายการโดเมนยอดนิยม {len(domains):,} อันดับแรก\n")
        fh.write(f"# ที่มา: Tranco ({TRANCO_URL}) ดึงเมื่อ {date.today().isoformat()}\n")
        fh.write("# อันดับ = ลำดับบรรทัด (ไม่นับบรรทัดที่ขึ้นต้นด้วย #)\n")
        fh.write("# สร้างใหม่ด้วย: ./.venv/bin/python tools/update_popularity.py\n")
        fh.write("\n".join(domains) + "\n")

    size_mb = os.path.getsize(OUT_PATH) / 1024 / 1024
    print(f"เขียน {len(domains):,} โดเมนลง {OUT_PATH} ({size_mb:.1f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

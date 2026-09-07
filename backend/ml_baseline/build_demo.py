# -*- coding: utf-8 -*-
"""
build_demo.py — สร้าง/อัปเดตข้อมูลในหน้าเว็บสาธิต demo-compare.html
============================================================================

หน้าเว็บสาธิตไม่ได้คิดเลขเอง มันแค่ "แสดง" ตัวเลขที่สคริปต์นี้คำนวณไว้ให้
สคริปต์นี้จึงเป็นที่มาของทุกตัวเลขในหน้านั้น รันซ้ำได้ตลอดเพื่อตรวจสอบเอง

    python ml_baseline/build_demo.py \
        --data ml_baseline/PhiUSIIL_Phishing_URL_Dataset.csv --flip-label \
        --page demo-compare.html

สคริปต์ทำ 3 อย่าง:

  1. รันระบบของโครงงาน (ชั้น 1-2) กับชุดทดสอบ 100 ลิงก์ ผ่าน scanner ตัวจริง
     เก็บสี คะแนนรวม และรายการสัญญาณที่เจอของทุกลิงก์
  2. ฝึกโมเดล Logistic Regression และ Random Forest จากชุดข้อมูลที่ระบุ
     (ตัดทั้งสองฝั่งให้เหลือชื่อโฮสต์ก่อน — ดูเหตุผลใน train_eval.py)
     แล้วให้โมเดลทำนายลิงก์ทั้ง 100 เส้น
  3. เขียนผลทั้งหมดลงในบล็อก <script id="data"> ของไฟล์หน้าเว็บ

ลิงก์ในชุดทดสอบที่บังเอิญอยู่ในชุดข้อมูลฝึกด้วย จะถูกตัดออกจากชุดฝึกก่อนเสมอ
เพื่อไม่ให้โมเดลเคยเห็นข้อสอบมาก่อน

*** สคริปต์นี้ไม่เปิดเว็บใด ๆ ทั้งสิ้น ***
ระบบถูกสั่งให้ทำงานเฉพาะชั้น 1-2 ซึ่งวิเคราะห์จากตัวอักษรใน URL อย่างเดียว
ไม่มีแพ็กเก็ตวิ่งไปหาเว็บที่กำลังตรวจ
"""
import argparse
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_HERE)
for p in (_HERE, _BACKEND):
    if p not in sys.path:
        sys.path.insert(0, p)

MARKER = re.compile(
    r'(<script id="data" type="application/json">)(.*?)(</script>)', re.S)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="CSV ชุดข้อมูลฝึก (คอลัมน์ url, label)")
    ap.add_argument("--flip-label", action="store_true",
                    help="ใส่เสมอถ้าใช้ชุด PhiUSIIL จาก UCI")
    ap.add_argument("--page", default=os.path.join(_BACKEND, "..", "demo-compare.html"),
                    help="ไฟล์หน้าเว็บสาธิตที่จะอัปเดต")
    ap.add_argument("--sample", type=int, default=0,
                    help="สุ่มข้อมูลฝึกมาบางส่วนให้รันเร็วขึ้น (0 = ใช้ทั้งหมด)")
    args = ap.parse_args()

    os.environ["SCAN_CACHE_TTL"] = "0"      # ปิดแคช ให้ทุกลิงก์ถูกตรวจใหม่จริง

    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    from features import vectorize_many
    from train_eval import load_data, to_host_only
    from analyzer import scanner

    page = os.path.abspath(args.page)
    if not os.path.exists(page):
        sys.exit(f"หาไฟล์หน้าเว็บไม่เจอ: {page}")

    testset = os.path.join(_BACKEND, "testset_100.json")
    items = json.load(open(testset, encoding="utf-8"))
    print(f"ชุดทดสอบ: {len(items)} ลิงก์")

    # ---------- 1) รันระบบของโครงงาน ----------
    print("\n[1/3] รันระบบของโครงงาน (ชั้น 1-2) กับชุดทดสอบ...")
    rows = []
    for it in items:
        r = scanner._scan_uncached(it["url"], run_deep=False)
        ok = r.get("ok")
        rows.append({
            "u": it["url"],
            "l": it["label"],
            "s": it["stratum"],
            "c": r["verdict"]["color"] if ok else "error",
            "sc": float(r.get("score", 0)) if ok else 0.0,
            "cr": any(x["severity"] == "critical" for x in r.get("reasons", [])) if ok else False,
            "rs": [[x.get("title") or x["id"], x.get("points", 0), x["severity"]]
                   for x in r.get("reasons", [])] if ok else [],
        })
    colors = {}
    for r in rows:
        colors[r["c"]] = colors.get(r["c"], 0) + 1
    print(f"      สีที่ได้: {colors}")

    # ---------- 2) ฝึกโมเดลแล้วทำนาย ----------
    print("\n[2/3] ฝึกโมเดลจากชุดข้อมูล...")
    df = load_data(args.data, flip=args.flip_label)
    ban = {it["url"].strip().rstrip("/") for it in items}
    before = len(df)
    df = df[~df["url"].str.strip().str.rstrip("/").isin(ban)].reset_index(drop=True)
    if before != len(df):
        print(f"      ตัดลิงก์ที่ซ้ำกับชุดทดสอบออก {before - len(df)} อัน (กันข้อมูลรั่ว)")
    if args.sample and args.sample < len(df):
        df = df.sample(args.sample, random_state=42).reset_index(drop=True)
        print(f"      สุ่มมาใช้ {args.sample:,} แถว")
    print(f"      ข้อมูลฝึก {len(df):,} แถว")

    X = np.asarray(vectorize_many([to_host_only(u) for u in df["url"]]))
    y = df["label"].to_numpy()
    HX = np.asarray(vectorize_many([to_host_only(r["u"]) for r in rows]))

    lr = make_pipeline(StandardScaler(),
                       LogisticRegression(max_iter=2000, class_weight="balanced")).fit(X, y)
    rf = RandomForestClassifier(n_estimators=300, min_samples_leaf=2,
                                class_weight="balanced", random_state=42,
                                n_jobs=-1).fit(X, y)
    p_lr = lr.predict_proba(HX)[:, 1]
    p_rf = rf.predict_proba(HX)[:, 1]
    for r, a, b in zip(rows, p_lr, p_rf):
        r["lr"] = round(float(a), 9)
        r["rf"] = round(float(b), 9)
    print("      ฝึกเสร็จ ทำนายครบ 100 ลิงก์")

    # ---------- สรุปให้ดูก่อนเขียนไฟล์ ----------
    def stats(key, fp):
        s = [(99.0 if r["cr"] else r["sc"]) if key == "rule" else r[key] for r in rows]
        neg = [v for v, r in zip(s, rows) if r["l"] == "safe"]
        thr = float("inf")
        for t in sorted(set(s)):
            if sum(1 for v in neg if v >= t) / len(neg) <= fp + 1e-9:
                thr = t
                break
        caught = sum(1 for v, r in zip(s, rows) if r["l"] != "safe" and v >= thr)
        alarm = sum(1 for v in neg if v >= thr)
        return caught, alarm

    print("\n      ตรวจสอบตัวเลขที่จะไปโผล่ในหน้าเว็บ:")
    print(f"      {'ยอมให้เตือนผิด':<18}{'ระบบเรา':>10}{'LogReg':>10}{'RandForest':>12}")
    for fp in (0.0, 0.02, 0.04, 0.06, 0.10, 0.20):
        cells = "".join(f"{stats(k, fp)[0]*2:>9}%" for k in ("rule", "lr", "rf"))
        label = "ไม่เตือนผิดเลย" if fp == 0 else f"{int(fp*100)}%"
        print(f"      {label:<18}{cells}")

    # ---------- 3) เขียนลงหน้าเว็บ ----------
    print("\n[3/3] เขียนข้อมูลลงหน้าเว็บ...")
    html = open(page, encoding="utf-8").read()
    if not MARKER.search(html):
        sys.exit('ไม่พบบล็อก <script id="data"> ในไฟล์หน้าเว็บ')
    blob = json.dumps({"rows": rows}, ensure_ascii=False, separators=(",", ":"))
    html = MARKER.sub(lambda m: m.group(1) + blob + m.group(3), html, count=1)
    open(page, "w", encoding="utf-8").write(html)
    print(f"      อัปเดตแล้ว: {page}")
    print("\nเปิดไฟล์นั้นในเบราว์เซอร์เพื่อดูผล")


if __name__ == "__main__":
    main()

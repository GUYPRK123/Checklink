# -*- coding: utf-8 -*-
"""
check_one.py — พิมพ์ลิงก์แล้วดูว่าสองระบบตอบว่าอะไร
============================================================================

ครั้งแรกที่รัน จะเทรนโมเดลจากชุดข้อมูลแล้วเก็บไว้เป็นไฟล์ (ใช้เวลาสองสามนาที)
ครั้งต่อ ๆ ไปจะโหลดโมเดลที่เก็บไว้ ตอบได้ทันที

    # ครั้งแรก — บอกที่อยู่ชุดข้อมูลด้วย
    python ml_baseline/check_one.py --data ml_baseline/PhiUSIIL_Phishing_URL_Dataset.csv --flip-label

    # ครั้งต่อไป — ไม่ต้องบอกแล้ว
    python ml_baseline/check_one.py

    # ถามลิงก์เดียวจบ ไม่ต้องเข้าโหมดพิมพ์ต่อเนื่อง
    python ml_baseline/check_one.py https://kasikornbank.com.security-check.info/login

เทรนใหม่เมื่อไรก็ได้ด้วย --retrain

*** โปรแกรมนี้ไม่เปิดเว็บที่คุณพิมพ์เข้ามา ***
ระบบทำงานเฉพาะชั้น 1-2 ซึ่งวิเคราะห์จากตัวอักษรใน URL อย่างเดียว
ไม่มีแพ็กเก็ตวิ่งไปหาเว็บนั้น เจ้าของเว็บไม่รู้ว่าถูกตรวจ
"""
import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_HERE)
for p in (_HERE, _BACKEND):
    if p not in sys.path:
        sys.path.insert(0, p)

MODEL_PATH = os.path.join(_HERE, "model_cache.joblib")

# เกณฑ์ตัดของโมเดล วัดจากชุดทดสอบ 100 ลิงก์ ที่จุด "ห้ามเตือนเว็บจริงผิดเลย"
# (คำนวณใหม่ทุกครั้งที่เทรน แล้วเก็บไว้ในไฟล์โมเดลด้วย)


def train(data_path, flip, sample=0):
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    import joblib
    import json

    from features import vectorize_many
    from train_eval import load_data, to_host_only

    print("กำลังเทรนโมเดล (ทำครั้งเดียว รอสักครู่)...")
    df = load_data(data_path, flip=flip)

    testset = os.path.join(_BACKEND, "testset_100.json")
    items = json.load(open(testset, encoding="utf-8"))
    ban = {it["url"].strip().rstrip("/") for it in items}
    df = df[~df["url"].str.strip().str.rstrip("/").isin(ban)].reset_index(drop=True)
    if sample and sample < len(df):
        df = df.sample(sample, random_state=42).reset_index(drop=True)
    print(f"  ข้อมูลฝึก {len(df):,} แถว")

    X = np.asarray(vectorize_many([to_host_only(u) for u in df["url"]]))
    y = df["label"].to_numpy()
    lr = make_pipeline(StandardScaler(),
                       LogisticRegression(max_iter=2000, class_weight="balanced")).fit(X, y)
    rf = RandomForestClassifier(n_estimators=300, min_samples_leaf=2,
                                class_weight="balanced", random_state=42,
                                n_jobs=-1).fit(X, y)

    # หาเกณฑ์ตัดจากชุดทดสอบ: ต่ำสุดที่ยังไม่เตือนเว็บจริงผิดเลย
    HX = np.asarray(vectorize_many([to_host_only(it["url"]) for it in items]))
    safe = np.array([it["label"] == "safe" for it in items])
    thr = {}
    for name, m in (("lr", lr), ("rf", rf)):
        p = m.predict_proba(HX)[:, 1]
        t = float("inf")
        for cand in sorted(set(p)):
            if (p[safe] >= cand).mean() <= 0:
                t = float(cand)
                break
        thr[name] = t

    joblib.dump({"lr": lr, "rf": rf, "thr": thr, "n": len(df)}, MODEL_PATH)
    print(f"  เก็บโมเดลไว้ที่ {MODEL_PATH}")
    return lr, rf, thr


def load_model():
    import joblib
    d = joblib.load(MODEL_PATH)
    return d["lr"], d["rf"], d["thr"]


BAR = "=" * 66


def check(url, lr, rf, thr):
    import numpy as np
    from features import vectorize_many
    from train_eval import to_host_only
    from analyzer import scanner

    print("\n" + BAR)
    print(f"  {url}")
    print(BAR)

    # ---------- ระบบของโครงงาน ----------
    r = scanner._scan_uncached(url, run_deep=False)
    print("\n[ ระบบของโครงงาน — ชั้น 1-2 ]")
    if not r.get("ok"):
        print(f"  อ่านลิงก์ไม่ได้: {r.get('error', '')}")
    else:
        v = r["verdict"]
        name = {"green": "เขียว = ปลอดภัย",
                "yellow": "เหลือง = ควรระวัง",
                "red": "แดง = อันตราย"}.get(v["color"], v["color"])
        print(f"  ผลตัดสิน : {name}")
        print(f"  คะแนนรวม : {r.get('score', 0)}")
        reasons = r.get("reasons", [])
        if reasons:
            print("  เจออะไรบ้าง:")
            for s in reasons:
                pts = s.get("points", 0)
                mark = f"+{pts}" if pts else " ·"
                flag = "  << ระดับร้ายแรง" if s["severity"] == "critical" else ""
                print(f"    {mark:>4}  {s.get('title') or s['id']}{flag}")
        else:
            print("  ไม่พบสัญญาณผิดปกติจากตัวลิงก์")

    # ---------- โมเดล ML ----------
    X = np.asarray(vectorize_many([to_host_only(url)]))
    p_lr = float(lr.predict_proba(X)[0, 1])
    p_rf = float(rf.predict_proba(X)[0, 1])
    print("\n[ โมเดลที่เรียนจากข้อมูล — เห็นแค่ชื่อโดเมน ]")
    for label, p, t in (("Logistic Regression", p_lr, thr["lr"]),
                        ("Random Forest", p_rf, thr["rf"])):
        call = "เตือนว่าอันตราย" if p >= t else "ไม่เตือน"
        bar = "#" * int(round(p * 30))
        print(f"  {label:<22} {p:>6.1%}  {bar:<30} -> {call}")
    print("  (โมเดลบอกได้แค่ตัวเลข ไม่สามารถบอกได้ว่าตัดสินจากอะไร)")
    print()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", nargs="*", help="ลิงก์ที่จะตรวจ (เว้นว่างเพื่อพิมพ์ต่อเนื่อง)")
    ap.add_argument("--data", help="CSV ชุดข้อมูลฝึก (จำเป็นเฉพาะครั้งแรก)")
    ap.add_argument("--flip-label", action="store_true")
    ap.add_argument("--sample", type=int, default=0)
    ap.add_argument("--retrain", action="store_true", help="เทรนใหม่ทับของเดิม")
    args = ap.parse_args()

    os.environ["SCAN_CACHE_TTL"] = "0"

    if args.retrain or not os.path.exists(MODEL_PATH):
        if not args.data:
            sys.exit("ยังไม่มีโมเดลที่เทรนไว้ — รันครั้งแรกต้องใส่ --data ชี้ไปที่ไฟล์ CSV\n"
                     "ตัวอย่าง: python ml_baseline/check_one.py "
                     "--data ml_baseline/PhiUSIIL_Phishing_URL_Dataset.csv --flip-label")
        lr, rf, thr = train(args.data, args.flip_label, args.sample)
    else:
        lr, rf, thr = load_model()

    if args.url:
        for u in args.url:
            check(u, lr, rf, thr)
        return

    print("\nพิมพ์ลิงก์แล้วกด Enter (พิมพ์ q เพื่อออก)")
    print("อย่าคัดลอกลิงก์จากที่นี่ไปเปิดในเบราว์เซอร์")
    while True:
        try:
            u = input("\nลิงก์> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not u:
            continue
        if u.lower() in ("q", "quit", "exit"):
            break
        check(u, lr, rf, thr)


if __name__ == "__main__":
    main()

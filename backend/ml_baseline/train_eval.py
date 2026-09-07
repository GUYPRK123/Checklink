# -*- coding: utf-8 -*-
"""
train_eval.py — เทรนโมเดล ML จากตัว URL แล้วเทียบกับระบบให้คะแนนแบบตั้งกฎเอง
============================================================================

วิธีใช้
-------
    python ml_baseline/train_eval.py --data ชุดข้อมูล.csv

ไฟล์ชุดข้อมูลต้องเป็น CSV ที่มีอย่างน้อย 2 คอลัมน์:
    url    = ลิงก์เต็ม (ต้องมี path ทั้งสองฝั่ง — อ่านหมายเหตุข้างล่าง)
    label  = 0 คือเว็บจริง / 1 คือลิงก์หลอก
              (รับคำว่า benign, legitimate, good, safe, phishing, malicious ด้วย)

ตัวเลือกอื่น:
    --test-size 0.25      สัดส่วนข้อมูลที่กันไว้ทดสอบ
    --no-holdout          ไม่ต้องวัดกับ testset_100.json
    --out ผลML.xlsx       ไฟล์ผลลัพธ์
    --flip-label          สลับความหมายของ 0/1
    --normalize-host      ตัด URL ทั้งสองฝั่งให้เหลือแค่ชื่อโฮสต์ (แก้กับดักข้อ 1)

*** ถ้าใช้ชุด PhiUSIIL จาก UCI ต้องใส่ --flip-label เสมอ ***
ชุดนั้นนิยาม label กลับด้านกับที่นี่: ของเขา 1 = เว็บจริง, 0 = ลิงก์หลอก
ถ้าลืมใส่ ผลจะออกมากลับหัวกลับหางโดยไม่มีอะไรฟ้องให้เห็น

*** ข้อควรระวังที่สำคัญที่สุดของการทดลองนี้ ***

1) ข้อมูลสองฝั่งต้องมาจากการเก็บแบบเดียวกัน
   ถ้าฝั่งเว็บจริงเป็นชื่อโดเมนเปล่า ๆ (google.com) แต่ฝั่งลิงก์หลอกเป็น URL เต็ม
   ที่มี path ยาว โมเดลจะเรียนแค่ว่า "มี path = หลอก" แล้วได้ความแม่นสูงลิ่วที่
   ไม่มีความหมายอะไรเลย สคริปต์นี้จะเตือนให้ถ้าตรวจพบความต่างแบบนี้

2) ห้ามให้ข้อมูลเทรนซ้ำกับ testset_100.json
   ลิงก์หลอกในชุดทดสอบ 100 ลิงก์มาจาก OpenPhish ถ้าชุดเทรนมีลิงก์เดียวกันปนอยู่
   ผลจะสวยเกินจริง สคริปต์นี้ตัดลิงก์ที่ซ้ำออกจากชุดเทรนให้อัตโนมัติและรายงานว่า
   ตัดไปกี่อัน

3) เทียบกันที่ระดับการเตือนผิดเท่ากัน ไม่ใช่เทียบความแม่นรวม
   ทั้งสองระบบปรับความเข้มงวดได้ทั้งคู่ ถ้าวัดที่ค่าตั้งต้นของใครของมันแล้วบอกว่า
   ใครชนะ จะไม่ยุติธรรม สคริปต์นี้จึงหาจุดที่ "เตือนผิดเท่ากัน" แล้วค่อยเทียบว่า
   ใครจับลิงก์หลอกได้มากกว่า

4) ระบบเดิมที่เอามาเทียบถูกจำกัดไว้แค่ชั้น 1-2 (run_deep=False)
   เพราะโมเดล ML เห็นแค่ตัว URL การเอาไปเทียบกับ cascade ครบ 4 ชั้นที่เปิดเว็บ
   จริงด้วยจะไม่ยุติธรรมกับฝั่ง ML
"""
import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_HERE)
for p in (_HERE, _BACKEND):
    if p not in sys.path:
        sys.path.insert(0, p)

POSITIVE_WORDS = {"1", "phishing", "phish", "malicious", "bad", "danger",
                  "dangerous", "defacement", "malware", "spam"}
NEGATIVE_WORDS = {"0", "benign", "legitimate", "legit", "good", "safe"}


def to_label(v) -> int:
    s = str(v).strip().lower()
    if s in POSITIVE_WORDS:
        return 1
    if s in NEGATIVE_WORDS:
        return 0
    return -1                      # ไม่รู้จัก -> ทิ้งแถวนั้น


def load_data(path: str, flip: bool = False):
    import pandas as pd
    df = pd.read_csv(path)
    cols = {c.lower().strip(): c for c in df.columns}
    url_col = next((cols[c] for c in ("url", "urls", "link", "domain") if c in cols), None)
    lab_col = next((cols[c] for c in ("label", "type", "class", "result", "status")
                    if c in cols), None)
    if not url_col or not lab_col:
        sys.exit(f"หาคอลัมน์ url/label ไม่เจอ — คอลัมน์ที่มีคือ {list(df.columns)}")

    df = df[[url_col, lab_col]].rename(columns={url_col: "url", lab_col: "label"})
    df["label"] = df["label"].map(to_label)
    df = df[df["label"] >= 0].dropna().drop_duplicates(subset=["url"])
    if flip:
        df["label"] = 1 - df["label"]
        print("  สลับความหมาย label แล้ว (1 = ลิงก์หลอก ตามที่สคริปต์นี้ใช้)")
    return df.reset_index(drop=True)


def warn_if_shape_differs(df):
    """เตือนถ้าสองฝั่งมีรูปร่างต่างกันจนโมเดลเดาจากรูปร่างได้เลย (ดูข้อ 1 ข้างบน)"""
    def has_path(u):
        s = str(u)
        body = s.split("://", 1)[-1]
        return "/" in body.rstrip("/")

    good = df[df.label == 0]["url"].map(has_path).mean()
    bad = df[df.label == 1]["url"].map(has_path).mean()
    print(f"  มี path: เว็บจริง {good:.0%} / ลิงก์หลอก {bad:.0%}")
    if abs(good - bad) > 0.4:
        print("  *** เตือน: สองฝั่งมีรูปร่างต่างกันมาก ***")
        print("      โมเดลอาจเรียนแค่ 'มี path หรือไม่' แทนที่จะเรียนลักษณะของลิงก์หลอก")
        print("      ควรหาชุดข้อมูลที่เก็บสองฝั่งแบบเดียวกันก่อนเชื่อผลที่ได้")


def to_host_only(url: str) -> str:
    """ตัด URL ให้เหลือแค่ "http://ชื่อโฮสต์" — ใช้ปรับสองฝั่งให้รูปร่างเท่ากัน

    ทำไมต้องมี: ชุดข้อมูลสาธารณะหลายชุดเก็บฝั่งเว็บจริงเป็นชื่อโดเมนเปล่า แต่เก็บ
    ฝั่งลิงก์หลอกเป็น URL เต็มพร้อม path ถ้าเทรนตรง ๆ โมเดลจะเรียนแค่ "มี path
    หรือไม่" แล้วได้ความแม่นสูงลิ่วที่ไม่ได้แปลว่ามันแยกฟิชชิงเป็น การตัดให้เหลือ
    ชื่อโฮสต์เท่ากันหมดทำให้โมเดลถูกบังคับให้ตัดสินจากชื่อโดเมนจริง ๆ
    """
    from urllib.parse import urlsplit
    s = str(url).strip()
    if "://" not in s:
        s = "http://" + s
    return "http://" + (urlsplit(s).hostname or "")


def load_holdout():
    """ชุดทดสอบ 100 ลิงก์ของโปรเจกต์ ใช้เป็นข้อสอบที่โมเดลไม่เคยเห็น"""
    import json
    path = os.path.join(_BACKEND, "testset_100.json")
    if not os.path.exists(path):
        return None
    items = json.load(open(path, encoding="utf-8"))
    return [(it["url"], 0 if it["label"] == "safe" else 1) for it in items]


def rule_based_scores(urls):
    """คะแนนดิบจากระบบเดิม (ชั้น 1-2) + ธงว่าเจอสัญญาณระดับ critical ไหม

    คืนค่าเป็นคะแนนที่ 'ปรับให้เทียบได้' — สัญญาณ critical ถูกดันเป็น 99 เพราะใน
    scanner.decide() มันฟันแดงทันทีโดยไม่สนคะแนนรวมอยู่แล้ว
    """
    os.environ["SCAN_CACHE_TTL"] = "0"
    from analyzer import scanner
    out = []
    for u in urls:
        try:
            r = scanner._scan_uncached(u, run_deep=False)
            if not r.get("ok"):
                out.append(0.0)
                continue
            crit = any(s["severity"] == "critical" for s in r.get("reasons", []))
            out.append(99.0 if crit else float(r.get("score", 0)))
        except Exception:
            out.append(0.0)
    return out


def recall_at_fp(y_true, scores, target_fp: float):
    """จับลิงก์หลอกได้กี่ % ณ จุดที่เตือนผิดไม่เกิน target_fp

    นี่คือหัวใจของการเทียบให้ยุติธรรม: บังคับให้ทั้งสองระบบยอมเตือนผิดเท่ากัน
    แล้วค่อยดูว่าใครจับได้มากกว่า
    """
    import numpy as np
    y = np.asarray(y_true)
    s = np.asarray(scores, dtype=float)
    neg, pos = s[y == 0], s[y == 1]
    if len(pos) == 0 or len(neg) == 0:
        return float("nan"), float("nan")
    # เกณฑ์ต่ำสุดที่ยังทำให้ FP ไม่เกินเป้า
    for thr in sorted(set(s)):
        if (neg >= thr).mean() <= target_fp:
            return (pos >= thr).mean(), thr
    return 0.0, float("inf")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="ไฟล์ CSV ชุดข้อมูลเทรน")
    ap.add_argument("--test-size", type=float, default=0.25)
    ap.add_argument("--no-holdout", action="store_true")
    ap.add_argument("--out", default="ผลเทียบML.xlsx")
    ap.add_argument("--flip-label", action="store_true",
                    help="สลับ 0/1 — ต้องใส่ถ้าใช้ชุด PhiUSIIL จาก UCI")
    ap.add_argument("--normalize-host", action="store_true",
                    help="ตัดให้เหลือแค่ชื่อโฮสต์ทั้งสองฝั่ง กันโมเดลเดาจากรูปร่าง")
    args = ap.parse_args()

    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import average_precision_score, roc_auc_score
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    from features import FEATURE_NAMES, vectorize_many

    print("=" * 70)
    print("เทรนโมเดล ML จากตัว URL แล้วเทียบกับระบบให้คะแนนแบบตั้งกฎเอง")
    print("=" * 70)

    df = load_data(args.data, flip=args.flip_label)
    print(f"\nชุดข้อมูล: {len(df):,} แถว "
          f"(เว็บจริง {(df.label == 0).sum():,} / ลิงก์หลอก {(df.label == 1).sum():,})")
    warn_if_shape_differs(df)

    # ---- กันข้อมูลรั่ว: ตัดลิงก์ที่อยู่ในชุดทดสอบ 100 ลิงก์ออกจากชุดเทรน ----
    holdout = None if args.no_holdout else load_holdout()
    if holdout:
        ban = {u.strip().rstrip("/") for u, _ in holdout}
        before = len(df)
        df = df[~df["url"].str.strip().str.rstrip("/").isin(ban)].reset_index(drop=True)
        if before != len(df):
            print(f"  ตัดลิงก์ที่ซ้ำกับชุดทดสอบออก {before - len(df)} อัน (กันข้อมูลรั่ว)")

    urls = df["url"].tolist()
    if args.normalize_host:
        urls = [to_host_only(u) for u in urls]
        print("  ตัดให้เหลือแค่ชื่อโฮสต์แล้วทั้งสองฝั่ง (กันโมเดลเดาจากรูปร่าง)")
    X = np.asarray(vectorize_many(urls))
    y = df["label"].to_numpy()
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y)
    print(f"  แบ่งเทรน {len(ytr):,} / ทดสอบ {len(yte):,}")

    models = {
        "Logistic Regression": make_pipeline(
            StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced")),
        "Random Forest": RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2, class_weight="balanced",
            random_state=42, n_jobs=-1),
    }

    print("\n" + "-" * 70)
    print("1) ผลบนชุดทดสอบที่แบ่งจากข้อมูลเดียวกัน")
    print("-" * 70)
    rows = []
    fitted = {}
    for name, m in models.items():
        m.fit(Xtr, ytr)
        fitted[name] = m
        p = m.predict_proba(Xte)[:, 1]
        auc = roc_auc_score(yte, p)
        ap_ = average_precision_score(yte, p)
        r1, _ = recall_at_fp(yte, p, 0.01)
        r5, _ = recall_at_fp(yte, p, 0.05)
        print(f"  {name:<22} AUC {auc:.3f} | AP {ap_:.3f} | "
              f"จับได้ที่ FP 1% = {r1:.1%} | ที่ FP 5% = {r5:.1%}")
        rows.append({"โมเดล": name, "ชุด": "in-domain", "AUC": auc, "AP": ap_,
                     "Recall@FP1%": r1, "Recall@FP5%": r5})

    # ---- ฟีเจอร์ไหนสำคัญ (ใช้ตอบว่าโมเดลเรียนรู้อะไร) ----
    rf = fitted["Random Forest"]
    imp = sorted(zip(FEATURE_NAMES, rf.feature_importances_),
                 key=lambda t: -t[1])[:10]
    print("\n  ฟีเจอร์ที่ Random Forest ใช้มากที่สุด 10 อันดับ:")
    for n, v in imp:
        print(f"    {n:<28} {v:.3f}")

    # ---- ข้อสอบจริง: ชุดทดสอบ 100 ลิงก์ที่โมเดลไม่เคยเห็น ----
    if holdout:
        print("\n" + "-" * 70)
        print("2) วัดกับชุดทดสอบ 100 ลิงก์ของโปรเจกต์ (โมเดลไม่เคยเห็น)")
        print("-" * 70)
        hu = [u for u, _ in holdout]
        hu_ml = [to_host_only(u) for u in hu] if args.normalize_host else hu
        hy = np.asarray([l for _, l in holdout])
        HX = np.asarray(vectorize_many(hu_ml))

        print("  กำลังรันระบบเดิม (ชั้น 1-2) เพื่อเอาคะแนนมาเทียบ...")
        rs = rule_based_scores(hu)
        base_r6, _ = recall_at_fp(hy, rs, 0.0)
        print(f"\n  {'ระบบ':<24} {'จับได้ที่ FP 0%':>16} {'ที่ FP 2%':>12} {'AUC':>8}")
        print("  " + "-" * 62)
        rb_auc = roc_auc_score(hy, rs)
        rb0, _ = recall_at_fp(hy, rs, 0.0)
        rb2, _ = recall_at_fp(hy, rs, 0.02)
        print(f"  {'ระบบเดิม (ตั้งกฎเอง)':<24} {rb0:>15.1%} {rb2:>11.1%} {rb_auc:>8.3f}")
        rows.append({"โมเดล": "ระบบเดิม (rule-based)", "ชุด": "holdout 100",
                     "AUC": rb_auc, "AP": average_precision_score(hy, rs),
                     "Recall@FP1%": rb0, "Recall@FP5%": rb2})
        for name, m in fitted.items():
            p = m.predict_proba(HX)[:, 1]
            a = roc_auc_score(hy, p)
            r0, _ = recall_at_fp(hy, p, 0.0)
            r2, _ = recall_at_fp(hy, p, 0.02)
            print(f"  {name:<24} {r0:>15.1%} {r2:>11.1%} {a:>8.3f}")
            rows.append({"โมเดล": name, "ชุด": "holdout 100", "AUC": a,
                         "AP": average_precision_score(hy, p),
                         "Recall@FP1%": r0, "Recall@FP5%": r2})

        print("\n  หมายเหตุ: ตัวเลขฝั่งระบบเดิมเป็นชั้น 1-2 เท่านั้น (ไม่มีบัญชีดำ")
        print("  ไม่ได้ตรวจชั้น 3-4) เพราะโมเดล ML เห็นแค่ตัว URL เหมือนกัน")
        print("  กลุ่มตัวอย่างละ 50 ลิงก์ ต่างกันไม่ถึง 10% ถือว่ายังสรุปไม่ได้")

    pd.DataFrame(rows).to_excel(args.out, index=False)
    print(f"\nบันทึกผลแล้ว: {args.out}")


if __name__ == "__main__":
    main()

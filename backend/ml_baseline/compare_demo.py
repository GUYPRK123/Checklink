# -*- coding: utf-8 -*-
"""
compare_demo.py — รันการเปรียบเทียบทั้งหมดจบในคำสั่งเดียว สำหรับใช้สาธิต
============================================================================

    python ml_baseline/compare_demo.py --data ml_baseline/PhiUSIIL_Phishing_URL_Dataset.csv

สคริปต์นี้ทำ 5 อย่างต่อกันแล้วพิมพ์ผลออกมาเป็นขั้น ๆ ให้ดูสด:

  ขั้นที่ 1  ตรวจชุดข้อมูลก่อนใช้ — สองฝั่งถูกเก็บมาเหมือนกันหรือไม่
  ขั้นที่ 2  พิสูจน์ด้วยกฎข้อเดียวที่ไม่เกี่ยวกับฟิชชิงเลย ว่าได้ความถูกต้องเท่าไร
  ขั้นที่ 3  ฝึกด้วยข้อมูลดิบ แล้วดูว่าแบบจำลองใช้อะไรตัดสิน
  ขั้นที่ 4  ฝึกใหม่หลังปรับข้อมูลให้รูปร่างเท่ากัน แล้วดูว่าใช้อะไรตัดสิน
  ขั้นที่ 5  เทียบกับระบบของโครงงาน ณ ระดับการเตือนผิดเท่ากัน

ผลลัพธ์: พิมพ์บนหน้าจอ + ไฟล์ Excel + กราฟ .png (ถ้ามี matplotlib)

ตัวเลือก:
    --data ไฟล์.csv     ชุดข้อมูลฝึก (คอลัมน์ url, label)
    --flip-label        สลับ 0/1 — ใส่เสมอถ้าใช้ชุด PhiUSIIL จาก UCI
    --sample 50000      สุ่มมาแค่บางส่วนให้รันเร็วขึ้นตอนสาธิต
    --out ชื่อไฟล์      ชื่อไฟล์ผลลัพธ์ (ไม่ต้องใส่นามสกุล)
    --pause             หยุดรอกด Enter ระหว่างแต่ละขั้น (เวลานำเสนอ)
"""
import argparse
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_HERE)
for p in (_HERE, _BACKEND):
    if p not in sys.path:
        sys.path.insert(0, p)

W = 78


def rule(char="="):
    print(char * W)


def step(n, title):
    print()
    rule()
    print(f"  ขั้นที่ {n}  {title}")
    rule()


def wait(on):
    if on:
        try:
            input("\n   [ กด Enter เพื่อไปขั้นถัดไป ]")
        except EOFError:
            pass


def has_path(u):
    body = str(u).split("://", 1)[-1]
    return "/" in body.rstrip("/")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True)
    ap.add_argument("--flip-label", action="store_true")
    ap.add_argument("--sample", type=int, default=0)
    ap.add_argument("--out", default="ผลเปรียบเทียบอัลกอริทึม")
    ap.add_argument("--pause", action="store_true")
    args = ap.parse_args()

    os.environ["SCAN_CACHE_TTL"] = "0"

    import json
    import numpy as np
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    from features import FEATURE_NAMES, vectorize_many
    from train_eval import load_data, to_host_only, rule_based_scores, recall_at_fp

    t0 = time.time()
    print()
    rule()
    print("  เปรียบเทียบอัลกอริทึม: ระบบให้คะแนนแบบตั้งกฎเอง  vs  การเรียนรู้ของเครื่อง")
    print("  โครงงาน Check Before Click — กลุ่มที่ 34")
    rule()

    # ================= ขั้นที่ 1 =================
    step(1, "ตรวจชุดข้อมูลก่อนนำไปใช้")
    df = load_data(args.data, flip=args.flip_label)
    if args.sample and args.sample < len(df):
        df = df.sample(args.sample, random_state=42).reset_index(drop=True)
        print(f"  (สุ่มมาใช้ {args.sample:,} แถวเพื่อให้รันเร็วขึ้น)")

    n_good = int((df.label == 0).sum())
    n_bad = int((df.label == 1).sum())
    print(f"\n  จำนวนข้อมูล : เว็บไซต์จริง {n_good:,} / ลิงก์หลอก {n_bad:,}")

    g = df[df.label == 0]
    b = df[df.label == 1]
    print(f"\n  {'ลักษณะที่ตรวจสอบ':<32}{'เว็บไซต์จริง':>16}{'ลิงก์หลอก':>16}")
    print("  " + "-" * (W - 4))
    stats = [
        ("มีเส้นทางย่อย (path)", g.url.map(has_path).mean(), b.url.map(has_path).mean(), "%"),
        ("ใช้ https", g.url.str.startswith("https").mean(),
         b.url.str.startswith("https").mean(), "%"),
        ("ความยาวเฉลี่ย", g.url.str.len().mean(), b.url.str.len().mean(), "ตัว"),
        ("ความยาวสูงสุด", g.url.str.len().max(), b.url.str.len().max(), "ตัว"),
    ]
    for name, a, c, unit in stats:
        fa = f"{a:.0%}" if unit == "%" else f"{a:,.0f} {unit}"
        fc = f"{c:.0%}" if unit == "%" else f"{c:,.0f} {unit}"
        print(f"  {name:<32}{fa:>16}{fc:>16}")

    gap = abs(g.url.map(has_path).mean() - b.url.map(has_path).mean())
    if gap > 0.4:
        print("\n  >> พบปัญหา: ข้อมูลสองฝั่งถูกเก็บมาด้วยวิธีที่ต่างกัน")
        print("     แบบจำลองอาจเรียนแค่ 'รูปร่างของข้อมูล' แทนลักษณะของลิงก์หลอก")
    wait(args.pause)

    # ================= ขั้นที่ 2 =================
    step(2, "พิสูจน์ปัญหาด้วยกฎข้อเดียวที่ไม่เกี่ยวกับฟิชชิงเลย")
    print('\n  กฎที่ใช้ทาย: "ถ้าเป็น https และไม่มีเส้นทางย่อย = เว็บไซต์จริง"')
    print("  กฎนี้ไม่มีความหมายทางความมั่นคงปลอดภัยใด ๆ ทั้งสิ้น\n")
    pred = (~(df.url.str.startswith("https") & (~df.url.map(has_path)))).astype(int)
    ct = pd.crosstab(df.label, pred)
    acc = float((pred == df.label).mean())
    print(f"  {'':<26}{'ทายว่าเว็บจริง':>18}{'ทายว่าลิงก์หลอก':>18}")
    print("  " + "-" * (W - 4))
    for lab, name in ((0, "ความจริง: เว็บไซต์จริง"), (1, "ความจริง: ลิงก์หลอก")):
        r0 = int(ct.loc[lab, 0]) if 0 in ct.columns else 0
        r1 = int(ct.loc[lab, 1]) if 1 in ct.columns else 0
        print(f"  {name:<26}{r0:>18,}{r1:>18,}")
    print(f"\n  >> ความถูกต้องรวม = {acc:.1%}  จากกฎที่ไม่ได้ดูเรื่องการหลอกลวงเลย")
    wait(args.pause)

    # ---- เตรียมข้อสอบ: ชุดทดสอบ 100 ลิงก์ ----
    hp = os.path.join(_BACKEND, "testset_100.json")
    items = json.load(open(hp, encoding="utf-8"))
    ban = {it["url"].strip().rstrip("/") for it in items}
    before = len(df)
    df = df[~df.url.str.strip().str.rstrip("/").isin(ban)].reset_index(drop=True)
    hu = [it["url"] for it in items]
    hy = np.array([0 if it["label"] == "safe" else 1 for it in items])
    y = df.label.to_numpy()

    def build_models():
        return {
            "Logistic Regression": make_pipeline(
                StandardScaler(),
                LogisticRegression(max_iter=2000, class_weight="balanced")),
            "Random Forest": RandomForestClassifier(
                n_estimators=300, min_samples_leaf=2, class_weight="balanced",
                random_state=42, n_jobs=-1),
        }

    def train_round(urls_train, urls_holdout, title):
        X = np.asarray(vectorize_many(urls_train))
        HX = np.asarray(vectorize_many(urls_holdout))
        Xtr, Xte, ytr, yte = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y)
        out, fitted = {}, {}
        print(f"\n  {'แบบจำลอง':<24}{'AUC':>8}{'จับได้ที่ FP 1%':>18}{'จับได้ที่ FP 5%':>18}")
        print("  " + "-" * (W - 4))
        for name, m in build_models().items():
            m.fit(Xtr, ytr)
            fitted[name] = m
            p = m.predict_proba(Xte)[:, 1]
            r1 = recall_at_fp(yte, p, 0.01)[0]
            r5 = recall_at_fp(yte, p, 0.05)[0]
            print(f"  {name:<24}{roc_auc_score(yte, p):>8.3f}{r1:>17.1%}{r5:>17.1%}")
            out[name] = m.predict_proba(HX)[:, 1]
        rf = fitted["Random Forest"]
        imp = sorted(zip(FEATURE_NAMES, rf.feature_importances_), key=lambda t: -t[1])[:5]
        print(f"\n  แบบจำลองใช้อะไรตัดสิน (5 อันดับแรกของ Random Forest):")
        for n, v in imp:
            bar = "#" * int(round(v * 60))
            print(f"    {n:<26}{v:>6.3f}  {bar}")
        return out, imp

    # ================= ขั้นที่ 3 =================
    step(3, "ฝึกด้วยข้อมูลดิบตามที่ชุดข้อมูลให้มา")
    raw_scores, raw_imp = train_round(df.url.tolist(), hu, "ดิบ")
    print("\n  ผลกับชุดทดสอบ 100 ลิงก์ของโครงงาน:")
    for n, s in raw_scores.items():
        print(f"    {n:<24} AUC {roc_auc_score(hy, s):.3f} | "
              f"จับได้ที่ไม่เตือนผิดเลย = {recall_at_fp(hy, s, 0.0)[0]:.0%}")
    print("\n  >> ผลดูสมบูรณ์แบบเกินจริง เพราะตัวแปรที่ใช้ตัดสินคือคุณสมบัติที่ต่างกัน")
    print("     เพราะวิธีเก็บข้อมูล ไม่ใช่ลักษณะของลิงก์หลอก — ตัวเลขรอบนี้ใช้อ้างอิงไม่ได้")
    wait(args.pause)

    # ================= ขั้นที่ 4 =================
    step(4, "ฝึกใหม่ หลังตัดทั้งสองฝั่งให้เหลือแค่ชื่อโฮสต์เท่ากัน")
    host_scores, host_imp = train_round(
        [to_host_only(u) for u in df.url], [to_host_only(u) for u in hu], "ปรับแล้ว")
    print("\n  >> ตัวแปรที่ใช้เปลี่ยนเป็นคุณสมบัติของชื่อโดเมนจริง ๆ แล้ว")
    wait(args.pause)

    # ================= ขั้นที่ 5 =================
    step(5, "เทียบกับระบบของโครงงาน ณ ระดับการเตือนผิดเท่ากัน")
    print("\n  กำลังรันระบบของโครงงาน (ชั้น 1-2) กับชุดทดสอบ 100 ลิงก์...")
    rs = np.asarray(rule_based_scores(hu))

    fps = [0.0, 0.02, 0.04, 0.06, 0.10, 0.20]
    systems = {"ระบบของโครงงาน (ตั้งกฎเอง)": rs}
    systems.update(host_scores)

    header = f"  {'ระบบ':<28}" + "".join(f"{int(f*100):>7}%" for f in fps) + f"{'AUC':>9}"
    print("\n" + header)
    print("  " + "-" * (len(header) - 2))
    rows = []
    for n, s in systems.items():
        vals = [recall_at_fp(hy, s, f)[0] for f in fps]
        auc = roc_auc_score(hy, s)
        print(f"  {n:<28}" + "".join(f"{v:>7.0%}" for v in vals) + f"{auc:>9.3f}")
        rows.append({"ระบบ": n, **{f"เตือนผิด {int(f*100)}%": round(v * 100)
                                   for f, v in zip(fps, vals)}, "AUC": round(auc, 3)})

    best_auc = max(systems, key=lambda k: roc_auc_score(hy, systems[k]))
    best_strict = max(systems, key=lambda k: recall_at_fp(hy, systems[k], 0.0)[0])
    print()
    print(f"  >> AUC สูงสุดคือ  : {best_auc}")
    print(f"  >> แต่ที่จุดห้ามเตือนผิดเลย ระบบที่จับได้มากที่สุดคือ : {best_strict}")
    if best_auc != best_strict:
        print("     สองอย่างนี้ไม่ใช่ระบบเดียวกัน — การตัดสินด้วย AUC อย่างเดียวจึงทำให้สรุปผิดได้")

    # ================= บันทึกผล =================
    xlsx = f"{args.out}.xlsx"
    with pd.ExcelWriter(xlsx) as w:
        pd.DataFrame(rows).to_excel(w, sheet_name="เทียบที่ FP เท่ากัน", index=False)
        pd.DataFrame(raw_imp, columns=["ตัวแปร", "ความสำคัญ"]).to_excel(
            w, sheet_name="ตัวแปรรอบดิบ", index=False)
        pd.DataFrame(host_imp, columns=["ตัวแปร", "ความสำคัญ"]).to_excel(
            w, sheet_name="ตัวแปรรอบปรับแล้ว", index=False)
        pd.DataFrame([{"ลักษณะ": n,
                       "เว็บไซต์จริง": f"{a:.2f}", "ลิงก์หลอก": f"{c:.2f}"}
                      for n, a, c, _ in stats] +
                     [{"ลักษณะ": "ความถูกต้องของกฎข้อเดียว",
                       "เว็บไซต์จริง": "", "ลิงก์หลอก": f"{acc:.1%}"}]
                     ).to_excel(w, sheet_name="ตรวจชุดข้อมูล", index=False)

    png = None
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(7.5, 4.3), dpi=160)
        x = [f * 100 for f in fps]
        # ป้ายในกราฟใช้ภาษาอังกฤษ เพราะฟอนต์เริ่มต้นของ matplotlib ไม่มีตัวอักษรไทย
        en = {"ระบบของโครงงาน (ตั้งกฎเอง)": "Rule-based (this project)"}
        for n, s in systems.items():
            ax.plot(x, [recall_at_fp(hy, s, f)[0] * 100 for f in fps],
                    marker="o", linewidth=2, label=en.get(n, n))
        ax.set_xlabel("False positive rate allowed (%)")
        ax.set_ylabel("Phishing links caught (%)")
        ax.set_title("Detection rate at matched false-positive rate")
        ax.set_ylim(-3, 103)
        ax.grid(alpha=.3)
        ax.legend(fontsize=8)
        fig.tight_layout()
        png = f"{args.out}.png"
        fig.savefig(png)
    except ImportError:
        pass

    print()
    rule()
    print(f"  ใช้เวลาทั้งหมด {time.time()-t0:.0f} วินาที")
    print(f"  บันทึกผลแล้ว: {xlsx}" + (f" และ {png}" if png else ""))
    if before != len(df) + 0:
        pass
    rule()


if __name__ == "__main__":
    main()

# -*- coding: utf-8 -*-
"""
c1.py — ลองเช็กลิงก์ด้วยมือ ไฟล์เดียวจบ ไม่ต้องมีไฟล์อื่นประกอบ
============================================================================

วิธีใช้ (วางไฟล์นี้ไว้ในโฟลเดอร์ backend แล้วสั่ง):

    python c1.py

แล้วพิมพ์ลิงก์ที่อยากลองได้เลย พิมพ์ q เพื่อออก

--------------------------------------------------------------------------
โหมดการทำงาน — เลือกเองอัตโนมัติตามของที่มีในเครื่อง
--------------------------------------------------------------------------
  ไม่มีอะไรเพิ่ม      -> แสดงผลของระบบโครงงานอย่างเดียว (ใช้ได้ทันที)
  มีไฟล์ CSV ชุดข้อมูล -> แสดงผลของวิธีคู่แข่งเทียบข้าง ๆ ด้วย

ถ้าอยากได้ส่วนเทียบ ให้เอาไฟล์ CSV ของ PhiUSIIL มาวางไว้โฟลเดอร์เดียวกับ
ไฟล์นี้ แล้วรันใหม่ (ครั้งแรกจะเทรนสักสองสามนาที ครั้งต่อไปเร็ว)
โหลดได้จาก https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

*** โปรแกรมนี้ไม่เปิดเว็บที่พิมพ์เข้ามา ***
ทำงานเฉพาะชั้น 1-2 ซึ่งอ่านจากตัวอักษรใน URL อย่างเดียว ไม่มีแพ็กเก็ตวิ่งออกไป
เจ้าของเว็บที่ถูกตรวจไม่รู้ตัว
"""
import glob
import math
import os
import re
import sys
from collections import Counter
from urllib.parse import urlsplit, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

BAR = "=" * 68


# ===========================================================================
# ส่วนที่ 1 — เชื่อมกับระบบของโครงงาน
# ===========================================================================
def load_scanner():
    os.environ.setdefault("SCAN_CACHE_TTL", "0")
    try:
        from analyzer import scanner
        from analyzer.url_parser import parse_url
        return scanner, parse_url
    except ImportError:
        sys.exit(
            "หาโมดูล analyzer ไม่เจอ\n\n"
            "ไฟล์นี้ต้องวางไว้ในโฟลเดอร์ backend (โฟลเดอร์เดียวกับที่มี analyzer อยู่)\n"
            f"ตอนนี้ไฟล์อยู่ที่: {HERE}\n"
            f"ในโฟลเดอร์นี้มี: {', '.join(sorted(os.listdir(HERE))[:12])}"
        )


# ===========================================================================
# ส่วนที่ 2 — สกัดลักษณะของ URL เป็นตัวเลข (สำหรับวิธีคู่แข่ง)
# ===========================================================================
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
_DIGIT = re.compile(r"\d")
_HEX = re.compile(r"%[0-9a-fA-F]{2}")


def _entropy(s):
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def vectorize(url, parse_url):
    p = parse_url(url)
    if not p.get("valid"):
        return [0.0] * len(FEATURE_NAMES)
    host = p.get("host") or ""
    sub = p.get("subdomain") or ""
    main = p.get("main_label") or ""
    tld = p.get("tld") or ""
    split = urlsplit(url if "://" in url else "http://" + url)
    only_path, query = split.path or "", split.query or ""
    labels = [x for x in host.split(".") if x]
    dg = len(_DIGIT.findall(host))
    try:
        params = parse_qs(query)
    except Exception:
        params = {}
    has_url_q = int(any("http" in v.lower() or "www." in v.lower()
                        for vals in params.values() for v in vals))
    letters = [c for c in main.lower() if c.isalpha()]
    cons = sum(1 for c in letters if c not in "aeiou") / len(letters) if letters else 0.0
    vowelless = len([m for m in re.findall(r"[bcdfghjklmnpqrstvwxyz]+", host.lower())
                     if len(m) >= 4])
    return [
        float(len(url)), float(len(host)), float(len(only_path)), float(len(query)),
        float(host.count(".")), float(host.count("-")), float(only_path.count("/")),
        float(url.count("@")), float(url.count("?")), float(url.count("=")),
        float(len(_HEX.findall(url))), float(dg),
        float(dg / len(host)) if host else 0.0,
        float(len([x for x in sub.split(".") if x])),
        float(max((len(x) for x in labels), default=0)), float(len(tld)),
        float(p.get("protocol") == "https"), float(bool(p.get("is_ip"))),
        float(bool(p.get("is_punycode"))), float(bool(p.get("userinfo"))),
        float(bool(p.get("port"))),
        _entropy(host), _entropy(only_path),
        float(len(params)), float(has_url_q),
        float(len([x for x in only_path.split("/") if x])),
        float(vowelless), cons,
    ]


def host_only(url):
    """ตัดให้เหลือแค่ชื่อโฮสต์ ทำกับทั้งข้อมูลฝึกและลิงก์ที่ตรวจเหมือนกัน

    เหตุผล: ชุดข้อมูลสาธารณะเก็บฝั่งเว็บจริงเป็นชื่อโดเมนเปล่า แต่เก็บฝั่งลิงก์หลอก
    เป็น URL เต็ม ถ้าไม่ตัดให้เท่ากัน โมเดลจะเรียนแค่ "มี path หรือไม่"
    """
    s = str(url).strip()
    if "://" not in s:
        s = "http://" + s
    return "http://" + (urlsplit(s).hostname or "")


# ===========================================================================
# ส่วนที่ 3 — วิธีคู่แข่ง (ทำงานเฉพาะเมื่อหาไฟล์ชุดข้อมูลเจอ)
# ===========================================================================
MODEL_FILE = os.path.join(HERE, "model_cache.joblib")
POS = {"1", "phishing", "phish", "malicious", "bad", "dangerous", "defacement", "malware"}
NEG = {"0", "benign", "legitimate", "legit", "good", "safe"}


def find_dataset():
    for pat in ("*PhiUSIIL*.csv", "*phiusiil*.csv", "*phishing*.csv"):
        hits = glob.glob(os.path.join(HERE, pat)) + \
               glob.glob(os.path.join(HERE, "ml_baseline", pat))
        if hits:
            return hits[0]
    return None


def train_model(csv_path, parse_url):
    import numpy as np
    import pandas as pd
    import joblib
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    print(f"  พบชุดข้อมูล: {os.path.basename(csv_path)}")
    print("  กำลังเทรนโมเดล ทำครั้งเดียว รอสักครู่...")

    df = pd.read_csv(csv_path)
    cols = {c.lower().strip(): c for c in df.columns}
    ucol = next((cols[c] for c in ("url", "urls", "link") if c in cols), None)
    lcol = next((cols[c] for c in ("label", "type", "class", "status") if c in cols), None)
    if not ucol or not lcol:
        print("  ข้ามส่วน ML: หาคอลัมน์ url/label ในไฟล์ไม่เจอ")
        return None
    df = df[[ucol, lcol]].rename(columns={ucol: "url", lcol: "label"})

    def lab(v):
        s = str(v).strip().lower()
        return 1 if s in POS else (0 if s in NEG else -1)

    df["label"] = df["label"].map(lab)
    df = df[df.label >= 0].dropna().drop_duplicates(subset=["url"]).reset_index(drop=True)

    # ชุด PhiUSIIL นิยาม 1 = เว็บจริง ซึ่งกลับกับที่นี่ ตรวจแล้วสลับให้เอง
    # วิธีตรวจ: ฝั่งเว็บจริงใช้ https มากกว่าฝั่งลิงก์หลอกเสมอ ถ้ากลุ่มที่ติดป้าย 1
    # (ซึ่งที่นี่แปลว่า "หลอก") กลับใช้ https มากกว่ากลุ่ม 0 แสดงว่าป้ายกลับด้านอยู่
    a = df[df.label == 0].url.str.startswith("https").mean()
    b = df[df.label == 1].url.str.startswith("https").mean()
    if b > a:
        df["label"] = 1 - df["label"]
        print("  ตรวจพบว่าไฟล์นี้นิยาม label กลับด้าน สลับให้อัตโนมัติแล้ว")

    if len(df) > 60000:
        df = df.sample(60000, random_state=42).reset_index(drop=True)
    print(f"  ข้อมูลฝึก {len(df):,} แถว")

    X = np.asarray([vectorize(host_only(u), parse_url) for u in df.url])
    y = df.label.to_numpy()
    lr = make_pipeline(StandardScaler(),
                       LogisticRegression(max_iter=2000, class_weight="balanced")).fit(X, y)
    bundle = {"lr": lr, "n": len(df)}
    try:
        joblib.dump(bundle, MODEL_FILE)
        print(f"  เก็บโมเดลไว้แล้ว ครั้งหน้าไม่ต้องเทรนซ้ำ")
    except Exception:
        pass
    return bundle


def get_model(parse_url):
    try:
        import joblib, sklearn      # noqa: F401
    except ImportError:
        return None, "ยังไม่ได้ลง scikit-learn กับ joblib จึงข้ามส่วนเปรียบเทียบ"
    if os.path.exists(MODEL_FILE):
        try:
            import joblib
            return joblib.load(MODEL_FILE), None
        except Exception:
            pass
    csv = find_dataset()
    if not csv:
        return None, ("ไม่พบไฟล์ CSV ชุดข้อมูล จึงแสดงเฉพาะผลของระบบโครงงาน\n"
                      "   (เอาไฟล์ PhiUSIIL_Phishing_URL_Dataset.csv มาวางไว้ข้าง ๆ "
                      "ไฟล์นี้แล้วรันใหม่ ถ้าอยากเห็นส่วนเปรียบเทียบ)")
    return train_model(csv, parse_url), None


# ===========================================================================
# ส่วนที่ 4 — แสดงผล
# ===========================================================================
COLOR_TH = {"green": "เขียว = ปลอดภัย",
            "yellow": "เหลือง = ควรระวัง",
            "red": "แดง = อันตราย"}

# คำอธิบายผลแต่ละสี บอกผู้ใช้ว่าควรทำอะไรต่อ
COLOR_ADVICE = {
    "green": "ยืนยันได้ว่าเป็นเว็บของจริง กดเข้าได้ตามปกติ",
    "yellow": "ยังฟันธงไม่ได้ว่าหลอก แต่ยืนยันไม่ได้ว่าปลอดภัย "
              "ถ้าต้องล็อกอินหรือโอนเงิน ให้เข้าผ่านแอปทางการแทน",
    "red": "อย่ากดเข้า และห้ามกรอกรหัสผ่านหรือข้อมูลส่วนตัวเด็ดขาด",
}


def risk_word(p):
    """แปลตัวเลขความน่าจะเป็นเป็นคำพูด เพื่อให้อ่านง่ายขึ้น"""
    if p < 0.20:
        return "ปลอดภัย"
    if p < 0.40:
        return "เอนไปทางปลอดภัย"
    if p < 0.60:
        return "ก้ำกึ่ง ตัดสินไม่ได้"
    if p < 0.80:
        return "น่าสงสัย"
    if p < 0.90:
        return "เสี่ยงสูง"
    return "หลอกแน่"


def check(url, scanner, parse_url, model):
    print("\n" + BAR)
    print("  " + url)
    print(BAR)

    r = scanner._scan_uncached(url, run_deep=False)
    print("\n[ ระบบของโครงงาน — ชั้น 1-2 ]")
    if not r.get("ok"):
        print("  อ่านลิงก์ไม่ได้: " + str(r.get("error", ""))[:70])
    else:
        color = r["verdict"]["color"]
        print("  ผลตัดสิน : " + COLOR_TH.get(color, color))
        print("  คะแนนรวม : " + str(r.get("score", 0)))
        advice = COLOR_ADVICE.get(color)
        if advice:
            print("  ควรทำ    : " + advice)
        reasons = r.get("reasons", [])
        if reasons:
            print("  เจออะไรบ้าง:")
            for s in reasons:
                pts = s.get("points", 0)
                mark = ("+%d" % pts) if pts else " ·"
                flag = "   << ระดับร้ายแรง" if s["severity"] == "critical" else ""
                print("    %4s  %s%s" % (mark, s.get("title") or s["id"], flag))
        else:
            print("  ไม่พบสัญญาณผิดปกติจากตัวลิงก์")

    if model:
        import numpy as np
        X = np.asarray([vectorize(host_only(url), parse_url)])
        print("\n[ วิธีคู่แข่ง: เรียนน้ำหนักเองจากข้อมูล — เห็นแค่ชื่อโดเมน ]")
        print("  ตัวเลขข้างล่างคือ % ที่คิดว่าลิงก์นี้เป็นเว็บหลอกลวง")
        print("  ยิ่งสูงยิ่งคิดว่าหลอก · ยิ่งต่ำยิ่งคิดว่าปลอดภัย")
        print()
        p = float(model["lr"].predict_proba(X)[0, 1])
        print("  %-21s %5.1f%%  %-24s %s"
              % ("Logistic Regression", p * 100, "#" * int(round(p * 24)), risk_word(p)))
        print()
        print("  วิธีนี้บอกได้แค่ตัวเลข ไม่สามารถบอกได้ว่าตัดสินจากอะไร")
    print()


def main():
    scanner, parse_url = load_scanner()

    print()
    print(BAR)
    print("  คู่แข่ง Check Before Click")
    print(BAR)

    model, note = get_model(parse_url)
    if note:
        print("\n  หมายเหตุ: " + note)
    if model:
        print("\n  โหมด: เทียบสองระบบ (ฝึกจาก %s แถว)" % format(model["n"], ","))
    else:
        print("\n  โหมด: แสดงผลของระบบโครงงานอย่างเดียว")

    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if args:
        for u in args:
            check(u, scanner, parse_url, model)
        return

    print("\n  พิมพ์ลิงก์แล้วกด Enter · พิมพ์ q เพื่อออก")
    print("  อย่าคัดลอกลิงก์ที่ผลออกมาแดงไปเปิดในเบราว์เซอร์")
    while True:
        try:
            u = input("\nลิงก์> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not u:
            continue
        if u.lower() in ("q", "quit", "exit", "ออก"):
            return
        try:
            check(u, scanner, parse_url, model)
        except Exception as e:
            print("  เกิดข้อผิดพลาด: %s: %s" % (type(e).__name__, e))


if __name__ == "__main__":
    main()

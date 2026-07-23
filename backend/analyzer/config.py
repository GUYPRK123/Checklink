# -*- coding: utf-8 -*-
"""
config.py
ค่าคงที่และฐานความรู้สำหรับการวิเคราะห์ลิงก์
ส่วนนี้คือ "ฐานข้อมูลภัย" ที่ Security Analyst เป็นผู้ดูแลและเพิ่มเติม
แก้ไขที่นี่ที่เดียวเพื่อปรับความแม่นยำของระบบ โดยไม่ต้องไปยุ่งกับตรรกะ
"""

# ---------------------------------------------------------------------------
# โดเมนจริงของแบรนด์ (สากล + ไทย)
#   label   = ชื่อที่คนใช้เรียก (ใช้จับการเลียนแบบ/สะกดเพี้ยน)
#   domains = โดเมนทางการทั้งหมดของแบรนด์ (ต้องเก็บให้ครบเพื่อกัน false positive)
# ---------------------------------------------------------------------------
BRANDS = [
    {"label": "google",    "domains": ["google.com", "google.co.th", "youtube.com", "gmail.com"]},
    {"label": "facebook",  "domains": ["facebook.com", "fb.com", "messenger.com"]},
    {"label": "instagram", "domains": ["instagram.com"]},
    {"label": "line",      "domains": ["line.me", "linecorp.com"]},
    {"label": "microsoft", "domains": ["microsoft.com", "live.com", "outlook.com", "office.com"]},
    {"label": "apple",     "domains": ["apple.com", "icloud.com"]},
    {"label": "amazon",    "domains": ["amazon.com"]},
    {"label": "netflix",   "domains": ["netflix.com"]},
    {"label": "paypal",    "domains": ["paypal.com"]},
    {"label": "shopee",    "domains": ["shopee.co.th", "shopee.com"]},
    {"label": "lazada",    "domains": ["lazada.co.th", "lazada.com"]},
    # ---- โซเชียล / แชท ----
    {"label": "tiktok",    "domains": ["tiktok.com"]},
    {"label": "twitter",   "domains": ["twitter.com", "x.com", "t.co"]},
    {"label": "whatsapp",  "domains": ["whatsapp.com", "wa.me"]},
    {"label": "telegram",  "domains": ["telegram.org", "t.me"]},
    {"label": "discord",   "domains": ["discord.com", "discord.gg"]},
    {"label": "linkedin",  "domains": ["linkedin.com"]},
    # ---- เทคโนโลยี / บริการออนไลน์ ----
    {"label": "github",    "domains": ["github.com", "github.io"]},
    {"label": "adobe",     "domains": ["adobe.com"]},
    {"label": "dropbox",   "domains": ["dropbox.com"]},
    {"label": "zoom",      "domains": ["zoom.us", "zoom.com"]},
    {"label": "spotify",   "domains": ["spotify.com"]},
    {"label": "samsung",   "domains": ["samsung.com"]},
    # ---- เกม ----
    {"label": "steam",     "domains": ["steampowered.com", "steamcommunity.com"]},
    {"label": "roblox",    "domains": ["roblox.com"]},
    {"label": "epicgames", "domains": ["epicgames.com"]},
    {"label": "playstation", "domains": ["playstation.com", "sony.com"]},
    {"label": "garena",    "domains": ["garena.com", "garena.co.th"]},
    # ---- การเงิน / คริปโต สากล ----
    {"label": "visa",      "domains": ["visa.com", "visa.co.th"]},
    {"label": "mastercard", "domains": ["mastercard.com", "mastercard.co.th"]},
    {"label": "binance",   "domains": ["binance.com", "binance.th"]},
    {"label": "coinbase",  "domains": ["coinbase.com"]},
    {"label": "westernunion", "domains": ["westernunion.com"]},
    {"label": "citibank",  "domains": ["citibank.com", "citibank.co.th", "citi.com"]},
    {"label": "hsbc",      "domains": ["hsbc.com", "hsbc.co.th"]},
    {"label": "uob",       "domains": ["uob.co.th", "uobgroup.com"]},
    # ---- ช้อปปิ้ง / เดินทาง / ขนส่ง ----
    {"label": "ebay",      "domains": ["ebay.com"]},
    {"label": "aliexpress", "domains": ["aliexpress.com", "alibaba.com"]},
    {"label": "temu",      "domains": ["temu.com"]},
    {"label": "agoda",     "domains": ["agoda.com"]},
    {"label": "booking",   "domains": ["booking.com"]},
    {"label": "airbnb",    "domains": ["airbnb.com", "airbnb.co.th"]},
    {"label": "grab",      "domains": ["grab.com"]},
    {"label": "dhl",       "domains": ["dhl.com", "dhl.co.th"]},
    {"label": "fedex",     "domains": ["fedex.com"]},
    {"label": "ups",       "domains": ["ups.com"]},
    {"label": "flashexpress", "domains": ["flashexpress.com", "flashexpress.co.th"]},
    {"label": "kerry",     "domains": ["kerryexpress.com", "th.kerryexpress.com"]},
    {"label": "thailandpost", "domains": ["thailandpost.co.th", "thailandpost.com"]},
    # ---- ธนาคาร / บริการในไทย ----
    {"label": "scb",       "domains": ["scb.co.th", "scbeasy.com"]},
    {"label": "kbank",     "domains": ["kasikornbank.com", "kbank.co.th", "kasikorn.com"]},
    {"label": "ktb",       "domains": ["krungthai.com", "ktb.co.th"]},
    {"label": "bbl",       "domains": ["bangkokbank.com"]},
    {"label": "krungsri",  "domains": ["krungsri.com"]},
    {"label": "ttb",       "domains": ["ttbbank.com"]},
    {"label": "gsb",       "domains": ["gsb.or.th"]},
    {"label": "baac",      "domains": ["baac.or.th"]},
    {"label": "promptpay", "domains": ["promptpay.io"]},
    {"label": "true",      "domains": ["true.th", "truecorp.co.th", "trueid.net"]},
    {"label": "ais",       "domains": ["ais.th", "ais.co.th"]},
    {"label": "dtac",      "domains": ["dtac.co.th"]},
]

# นามสกุลโดเมน 2 ชั้น ที่ต้องรู้จัก (กันปัญหา co.th / go.th ถูกตัดผิด)
MULTI_SUFFIXES = {
    "co.th", "go.th", "ac.th", "or.th", "in.th", "net.th", "mi.th",
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au", "com.sg", "com.my", "com.cn",
}

# ข้อมูลความรู้ของนามสกุลโดเมนที่พบบ่อย (ใช้อธิบายในรายละเอียดทางเทคนิค)
#   ให้ข้อเท็จจริงว่านามสกุลนั้น "ใครจดได้" เพื่อให้ผู้ใช้ประเมินความน่าเชื่อถือเอง
TLD_INFO = {
    "com":   "นามสกุลสากลที่พบมากที่สุด ใครก็จดได้ ไม่ยืนยันตัวตนเจ้าของ",
    "net":   "นามสกุลสากลทั่วไป ใครก็จดได้ ไม่ยืนยันตัวตนเจ้าของ",
    "org":   "นิยมใช้โดยองค์กรไม่แสวงกำไร แต่ความจริงใครก็จดได้",
    "info":  "นามสกุลสากลราคาถูก ใครก็จดได้ พบในเว็บหลอกบ่อยพอสมควร",
    "io":    "นิยมในสายเทคโนโลยี ใครก็จดได้",
    "me":    "ใครก็จดได้ นิยมใช้ทำลิงก์ส่วนตัว/ลิงก์ย่อ",
    "co":    "นามสกุลของประเทศโคลอมเบีย แต่ใครก็จดได้ มักใช้เลียนแบบ .com",
    "th":    "โดเมนระดับประเทศไทย (จดตรงชั้นเดียวได้ ต้องมีเครื่องหมายการค้า)",
    "co.th": "จดทะเบียนในไทย ต้องใช้เอกสารนิติบุคคล/เครื่องหมายการค้า เชื่อถือได้ค่อนข้างสูง",
    "go.th": "สงวนให้หน่วยงานราชการไทยเท่านั้น",
    "ac.th": "สงวนให้สถานศึกษาในไทยเท่านั้น",
    "or.th": "สำหรับองค์กร/มูลนิธิ/สมาคมที่จดทะเบียนในไทย",
    "in.th": "บุคคลทั่วไปในไทยจดได้ ไม่ยืนยันว่าเป็นองค์กร",
    "net.th": "สำหรับผู้ให้บริการเครือข่ายที่ได้รับอนุญาตในไทย",
    "mi.th": "สงวนให้หน่วยงานทางทหารของไทยเท่านั้น",
    "co.uk": "จดทะเบียนในสหราชอาณาจักร ใครก็จดได้",
    "gov.uk": "สงวนให้หน่วยงานรัฐบาลสหราชอาณาจักรเท่านั้น",
    "co.jp": "จดทะเบียนในญี่ปุ่น ต้องเป็นบริษัทที่จดทะเบียนในญี่ปุ่น",
    "dev":   "นิยมในสายนักพัฒนา ใครก็จดได้ (บังคับ https เสมอ)",
    "app":   "นิยมใช้กับแอปพลิเคชัน ใครก็จดได้ (บังคับ https เสมอ)",
    "shop":  "นิยมใช้กับร้านค้าออนไลน์ ใครก็จดได้",
    "online": "นามสกุลราคาถูก ใครก็จดได้ พบในเว็บหลอกบ่อยพอสมควร",
    "site":  "นามสกุลราคาถูก ใครก็จดได้ พบในเว็บหลอกบ่อยพอสมควร",
}

# นามสกุลที่มิจฉาชีพนิยม (จดง่าย/ราคาถูก)
RISKY_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "work",
    "fit", "loan", "rest", "zip", "mov", "country", "kim", "date", "buzz",
}

# บริการย่อลิงก์ (มองไม่เห็นปลายทางจริง)
SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "lin.ee", "s.id", "rb.gy",
}

# คำล่อที่มักโผล่ในลิงก์หลอก
LURE_KEYWORDS = [
    "login", "signin", "logon", "verify", "verifi", "secure", "account",
    "update", "confirm", "password", "passwd", "wallet", "bank", "banking",
    "otp", "reset", "support", "billing", "gift", "free", "bonus", "prize",
    "win", "claim", "unlock", "payment", "refund",
]

# ---------------------------------------------------------------------------
# น้ำหนักคะแนนของแต่ละสัญญาณ และเกณฑ์ตัดสิน (Analyst ปรับได้)
# severity: critical / high / medium / low / good
# ---------------------------------------------------------------------------
WEIGHTS = {
    "brand_impersonation": (6, "critical"),
    "typosquatting":       (6, "critical"),
    "ip_host":             (5, "critical"),
    "userinfo_at":         (5, "critical"),
    "internal_redirect":   (6, "critical"),  # ชั้น 3: redirect ไปยัง IP ภายในเครือข่าย
    "punycode":            (4, "high"),
    "risky_tld":           (3, "high"),
    "deep_subdomain":      (2, "medium"),
    "shortener":           (0, "medium"),   # ไม่บวกคะแนน แต่บังคับให้อย่างน้อยเป็นเหลือง
    "lure_keyword":        (1, "medium"),   # ต่อคำ, รวมไม่เกิน 3
    "many_hyphens":        (1, "low"),
    "no_https":            (1, "low"),
    "weird_port":          (2, "medium"),
    "long_url":            (1, "low"),

    # ---- ชั้นที่ 4 (เสริม): อายุโดเมน (RDAP) + ใบรับรอง SSL ----
    "domain_very_new":     (6, "critical"),  # จดทะเบียนมาไม่ถึง 7 วัน
    "domain_new":          (3, "high"),      # จดทะเบียนมาไม่ถึง 30 วัน
    "ssl_invalid":         (5, "critical"),  # handshake ผ่านแต่ตรวจสอบ certificate ไม่ผ่าน
    "ssl_cert_new":        (2, "medium"),    # certificate เพิ่งออกไม่ถึง 3 วัน

    # ---- ชั้นที่ 4 (เสริม): วิเคราะห์เนื้อหาจริงของหน้าเว็บปลายทาง ----
    "form_action_mismatch":  (6, "critical"),  # ฟอร์มรหัสผ่านส่งข้อมูลไปคนละโดเมน
    "favicon_brand_mismatch": (5, "critical"),  # favicon hotlink จากโดเมนแบรนด์จริง
    "content_brand_mismatch": (3, "high"),      # หัวข้อ/เนื้อหาอ้างถึงแบรนด์ทั้งที่โดเมนไม่ตรง
}

# คะแนนรวมเท่าไรถึงนับเป็นแต่ละระดับ
RED_SCORE = 6      # >= แดง
YELLOW_SCORE = 2   # >= เหลือง  (ต่ำกว่านี้และไม่รู้จัก = เหลือง "ควรระวัง" เช่นกัน)

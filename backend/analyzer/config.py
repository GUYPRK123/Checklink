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
#   aliases = ชื่ออื่นที่คนรู้จักแบรนด์นี้ (ชื่อเต็ม/ชื่อผลิตภัณฑ์) ใช้จับการเลียนแบบ
#             เพิ่มจาก label เช่น "kasikorn-bank-verify.com" ไม่มีคำว่า kbank
#             แต่คนไทยจำธนาคารด้วยคำว่า kasikorn — ต้องจับได้เหมือนกัน
# ---------------------------------------------------------------------------
BRANDS = [
    {"label": "google",    "domains": ["google.com", "google.co.th", "youtube.com", "gmail.com"],
     "aliases": ["youtube", "gmail"]},
    {"label": "facebook",  "domains": ["facebook.com", "fb.com", "messenger.com"]},
    {"label": "instagram", "domains": ["instagram.com"]},
    {"label": "line",      "domains": ["line.me", "linecorp.com"]},
    {"label": "microsoft", "domains": ["microsoft.com", "live.com", "outlook.com", "office.com",
                                        "microsoftonline.com"],
     "aliases": ["outlook", "hotmail", "office365"]},
    {"label": "apple",     "domains": ["apple.com", "icloud.com"], "aliases": ["icloud"]},
    {"label": "amazon",    "domains": ["amazon.com", "amazon.co.jp"]},
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
    {"label": "github",    "domains": ["github.com"]},
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
    {"label": "scb",       "domains": ["scb.co.th", "scbeasy.com"], "aliases": ["scbeasy"]},
    {"label": "kbank",     "domains": ["kasikornbank.com", "kbank.co.th", "kasikorn.com"],
     "aliases": ["kasikorn", "kplus"]},
    {"label": "ktb",       "domains": ["krungthai.com", "ktb.co.th"], "aliases": ["krungthai"]},
    {"label": "bbl",       "domains": ["bangkokbank.com"], "aliases": ["bangkokbank"]},
    {"label": "krungsri",  "domains": ["krungsri.com"]},
    {"label": "ttb",       "domains": ["ttbbank.com"]},
    {"label": "gsb",       "domains": ["gsb.or.th"]},
    {"label": "baac",      "domains": ["baac.or.th"]},
    {"label": "promptpay", "domains": ["promptpay.io"]},
    {"label": "true",      "domains": ["true.th", "truecorp.co.th", "trueid.net", "truemoney.com"],
     "aliases": ["truemoney"]},
    {"label": "ais",       "domains": ["ais.th", "ais.co.th"]},
    {"label": "dtac",      "domains": ["dtac.co.th"]},
]

# ---------------------------------------------------------------------------
# โดเมนประเภท "ให้ใครก็ได้เอาเว็บมาฝาก" (user-generated content)
# ---------------------------------------------------------------------------
# โดเมนกลุ่มนี้ต่างจากโดเมนแบรนด์ตรงที่ "เจ้าของโดเมนไม่ได้คุมเนื้อหาข้างใน"
# ใครสมัครก็ได้พื้นที่ของตัวเองภายในไม่กี่นาที เช่น ใครก็ตั้ง ชื่ออะไรก็ได้.github.io
#
# ที่มา: จากการทดสอบ 100 ลิงก์ (20 ส.ค. 2569) พบว่า github.io เคยถูกใส่ไว้ใน
# domains ของแบรนด์ GitHub ทำให้หน้าฟิชชิงจริง 5 อันที่ฝากอยู่บน github.io
# (หน้าล็อกอิน Facebook ปลอม / โคลน Amazon / โคลน Netflix / ปลอม Ledger)
# ได้ผลเป็น "เขียว = ปลอดภัย" ซึ่งอันตรายกว่าการจับไม่ได้ เพราะระบบไปรับรอง
# ให้ผู้ใช้กดเข้าเว็บหลอกด้วยตัวเอง
#
# กติกา: โดเมนในลิสต์นี้ **ห้ามให้ผลเขียวเด็ดขาด** อย่างมากได้แค่เหลือง
# และต้องตรวจชื่อโดเมนย่อย/path ต่อว่ามีการอ้างแบรนด์อื่นหรือไม่
#
# หมายเหตุสำหรับคนดูแลลิสต์: ห้ามเอาโดเมนกลุ่มนี้กลับไปใส่ใน BRANDS อีก
# แม้บริษัทเจ้าของจะน่าเชื่อถือแค่ไหนก็ตาม เพราะสิ่งที่เราเชื่อได้คือ "ตัวบริษัท"
# ไม่ใช่ "เนื้อหาที่คนอื่นเอามาฝากบนโดเมนของบริษัท"
USER_CONTENT_DOMAINS = {
    # โฮสต์หน้าเว็บฟรีจากผู้ให้บริการใหญ่
    "github.io", "gitbook.io", "gitlab.io", "pages.dev", "vercel.app",
    "netlify.app", "netlify.com", "web.app", "firebaseapp.com",
    "replit.app", "repl.co", "glitch.me", "surge.sh", "onrender.com",
    "framer.app", "framer.website", "webflow.io", "wixsite.com",
    "weebly.com", "square.site", "blogspot.com", "wordpress.com",
    "tumblr.com", "myshopify.com", "zapier.app", "azurewebsites.net",
    "herokuapp.com", "workers.dev", "r2.dev", "trycloudflare.com",
    # DNS ฟรี/ไดนามิก ที่มิจฉาชีพใช้บ่อย
    "duckdns.org", "no-ip.org", "ddns.net", "serveo.net", "ngrok.io",
    "ngrok-free.app", "loca.lt",
    # ---- เพิ่มจากการวัดผลกับ testset_100.json (ลิงก์ฟิชชิ่งที่ยังทำงานอยู่จริง) ----
    # ทั้งกลุ่มนี้ "อันดับความนิยมสูง" เพราะเป็นแพลตฟอร์ม แต่หน้าที่อยู่ข้างในเป็นของ
    # ผู้ใช้คนไหนก็ได้ ถ้าไม่ใส่ไว้ตรงนี้ คะแนนความนิยม (popularity.py) จะยกเครดิตของ
    # แพลตฟอร์มไปให้หน้าฟิชชิ่งที่ฝากอยู่ข้างใน — amazonaws.com อยู่อันดับ 7 ของโลก
    "amazonaws.com",      # S3 bucket สาธารณะ ใครก็อัปหน้าเว็บขึ้นได้
    "mybluehost.me",      # โดเมนชั่วคราวที่ Bluehost แจกให้ลูกค้าตอนยังไม่ผูกโดเมนจริง
    "tempurl.host",       # โดเมนชั่วคราวของโฮสติ้ง ลักษณะเดียวกัน
    "eu.org",             # แจกโดเมนย่อยฟรี
    "dweb.link",          # IPFS gateway — เนื้อหามาจากผู้อัปโหลด ไม่ใช่เจ้าของโดเมน
    "avnam.net", "tepuyserver.net",   # shared hosting ที่พบว่าถูกใช้ฝากหน้าฟิชชิ่ง

    # ---- จากการไล่รายการโดเมนยอดนิยม 10,000 อันดับแรกทีละอัน ----
    # ทุกอันในกลุ่มนี้คือ "โดเมนของแพลตฟอร์ม แต่หน้าเว็บเป็นของผู้ใช้คนไหนก็ได้"
    # ถ้าไม่ใส่ไว้ หน้าฟิชชิ่งที่ฝากอยู่ข้างในจะได้เขียวจากอันดับของแพลตฟอร์มทันที
    # (อันดับในวงเล็บ = ตอนที่ตรวจ ก.ย. 2026)
    # CDN / ที่เก็บไฟล์ที่ใครก็อัปได้
    "cloudfront.net", "b-cdn.net", "cloudflarestorage.com", "windows.net",
    "appspot.com", "sharepoint.com", "box.com", "mediafire.com",
    "ipfs.io", "pinata.cloud",
    # ลิงก์รวมโปรไฟล์ (link-in-bio) — หน้าเดียวที่เจ้าของใส่ลิงก์อะไรก็ได้
    "linktr.ee", "bio.link", "beacons.ai", "taplink.cc", "linkin.bio", "carrd.co",
    # ฟอร์มออนไลน์ — ใช้ทำหน้าเก็บรหัสผ่าน/เลขบัตรได้ตรง ๆ โดยไม่ต้องเขียนเว็บเอง
    "forms.gle", "g.page", "jotform.com", "typeform.com", "wufoo.com", "formspree.io",
    # เครื่องมือสร้างเว็บ/โน้ตสาธารณะ
    "notion.site", "notion.so", "canva.site", "strikingly.com", "jimdosite.com",
    "yolasite.com", "tilda.ws", "readymag.com", "webnode.page",
    # โฮสต์ฟรีที่มิจฉาชีพใช้บ่อย
    "000webhostapp.com", "infinityfree.com", "byethost.com", "rf.gd", "epizy.com",
    "hpage.com",
    # sandbox ของนักพัฒนา (รันหน้าเว็บของใครก็ได้บนโดเมนของแพลตฟอร์ม)
    "codesandbox.io", "stackblitz.io", "gitee.io", "vercel.sh",
    # แพลตฟอร์มเนื้อหา — เชื่อบริษัทได้ แต่หน้าที่ผู้ใช้เขียนเองยืนยันให้ไม่ได้
    # (กลุ่มนี้ใช้กฎเรื่องแบรนด์ต่างจากกลุ่มอื่น — ดู PUBLISHING_DOMAINS ข้างล่าง)
    "medium.com", "substack.com", "soundcloud.com", "bsky.app",
}

# กลุ่มย่อยของ USER_CONTENT_DOMAINS: แพลตฟอร์ม "เผยแพร่บทความ/สื่อ"
# ต่างจากแพลตฟอร์มฝากเว็บตรงที่ **path คือชื่อบทความที่คนเขียนตั้งเอง ไม่ใช่โครงเว็บ
# ที่เจ้าของหน้าออกแบบ** — บทความชื่อ /why-facebook-changed-its-name เป็นเรื่องปกติ
# ที่สุดของเว็บเขียนบทความ ถ้าใช้กฎ user_content_brand (critical) กับ path ของกลุ่มนี้
# บทความทุกชิ้นที่พูดถึงแบรนด์จะกลายเป็นแดงทันที ซึ่งผิดชัดเจน
#
# กลุ่มนี้จึงดูชื่อแบรนด์เฉพาะใน "โดเมนย่อย" (facebook-login.medium.com = เจตนาปลอม
# เหมือนเดิม) ส่วนชื่อแบรนด์ใน path ตกไปใช้กฎ brand_in_path ปกติซึ่งเป็นแค่ข้อสังเกต
# — และยังไม่ได้เขียวอยู่ดีเพราะติด user_content_host
PUBLISHING_DOMAINS = {
    "medium.com", "substack.com", "soundcloud.com", "bsky.app",
}

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
    # เพิ่มจากการไล่รายการโดเมนยอดนิยม (ดูหมายเหตุใน USER_CONTENT_DOMAINS)
    "tiny.cc", "v.gd", "u.to", "onelink.me",
}

# นามสกุลไฟล์ที่ "รันหรือติดตั้งได้" — ลิงก์ที่ปลายทางเป็นไฟล์พวกนี้ = กดแล้วได้
# ไฟล์อันตรายทันที (.apk แยกไปให้น้ำหนักหนักกว่าใน WEIGHTS เพราะเป็นรูปแบบ
# "แอปดูดเงิน" ที่มิจฉาชีพไทยใช้จริง — แอป Android ปกติมาจาก Play Store ไม่ใช่ลิงก์แชต)
EXECUTABLE_EXTENSIONS = {
    "apk", "exe", "msi", "scr", "bat", "cmd", "ps1", "jar", "vbs", "hta", "pif",
}
# ไฟล์บีบอัด/อิมเมจที่นิยมใช้ห่อมัลแวร์หลบระบบสแกน
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "iso", "img"}

# ประเภทเนื้อหา (Content-Type) ที่บ่งบอกไฟล์รันได้ — ใช้คู่กับนามสกุลไฟล์
# เพราะบางเซิร์ฟเวอร์ตั้งชื่อไฟล์เนียน ๆ แต่ Content-Type โกหกไม่ได้ง่ายเท่า
APK_CONTENT_TYPE = "application/vnd.android.package-archive"
EXECUTABLE_CONTENT_TYPES = {
    "application/x-msdownload", "application/x-dosexec",
    "application/x-executable", "application/x-msi", "application/java-archive",
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
    # brand_impersonation = ชื่อแบรนด์อยู่ใน "โฮสต์" ของโดเมนที่ไม่ใช่ของแบรนด์
    # (เช่น facebook-security-alert.com) เว็บสุจริตแทบไม่มีเหตุผลตั้งชื่อโฮสต์แบบนี้
    "brand_impersonation": (6, "critical"),
    # brand_in_path = ชื่อแบรนด์โผล่ใน "path" เท่านั้น (เช่น /news/apple-iphone)
    # เว็บข่าว/บล็อก/วิกิพูดถึงแบรนด์ใน path เป็นเรื่องปกติมาก จึงเป็นแค่ข้อสังเกต
    # แต่ถ้าหน้านั้นขอรหัสผ่านด้วย combo ด้านล่างจะดันคะแนนขึ้น
    "brand_in_path":       (2, "medium"),
    # brand_bare_domain = โดเมนคือชื่อแบรนด์เป๊ะ ๆ แต่ TLD ไม่อยู่ในลิสต์ทางการ
    # (เช่น amazon.co.jp ของจริงที่ลิสต์เราไม่ครบ vs amazon.xyz ของปลอม)
    # ตัดสินจากชื่ออย่างเดียวไม่ได้ ให้ระดับกลางแล้วพึ่งสัญญาณอื่นร่วมตัดสิน
    "brand_bare_domain":   (3, "high"),
    # หน้าเว็บฝากอยู่บนโดเมนที่ใครก็สมัครได้ — ไม่ผิดในตัวเอง (นักเรียน/นักพัฒนาใช้กันปกติ)
    # จึงให้คะแนนต่ำ หน้าที่หลักของสัญญาณนี้คือ "กันไม่ให้ได้เขียว" มากกว่าการทำให้แดง
    "user_content_host":   (1, "low"),
    # แต่ถ้าเอาชื่อแบรนด์อื่นมาตั้งเป็นชื่อโดเมนย่อย/path บนพื้นที่ฝากฟรี = เจตนาปลอมชัด
    # (เช่น aryama10.github.io/facebook-login-page) ไม่มีเหตุผลสุจริตที่จะทำแบบนี้
    "user_content_brand":  (6, "critical"),
    "typosquatting":       (6, "critical"),
    "ip_host":             (5, "critical"),
    "userinfo_at":         (5, "critical"),
    "internal_redirect":   (6, "critical"),  # ชั้น 3: redirect ไปยัง IP ภายในเครือข่าย
    "punycode":            (4, "high"),
    "homoglyph_brand":     (6, "critical"),  # อักขระต่างภาษาเลียนแบบแบรนด์ (จับตั้งแต่ชั้น parse)
    "risky_tld":           (3, "high"),
    "deep_subdomain":      (2, "medium"),
    "shortener":           (0, "medium"),   # ไม่บวกคะแนน แต่บังคับให้อย่างน้อยเป็นเหลือง
    "lure_keyword":        (1, "medium"),   # ต่อคำ, รวมไม่เกิน 3
    "many_hyphens":        (1, "low"),
    "no_https":            (1, "low"),
    "weird_port":          (2, "medium"),
    "long_url":            (1, "low"),

    # ---- ลิงก์ที่ "อันตรายทันทีที่กด" ----
    "script_scheme":       (6, "critical"),  # ตัวลิงก์คือโค้ด (javascript:/data:/vbscript:)
    "script_in_params":    (5, "critical"),  # โค้ดสคริปต์ซ่อนในพารามิเตอร์ (ลิงก์ยิง XSS)
    "executable_in_path":  (2, "medium"),    # path ชี้ไปไฟล์รันได้ (ยืนยันจริงอีกทีชั้น 3)
    # สามตัวล่างตัดสินจาก Content-Type/Content-Disposition ของปลายทางจริง (ชั้น 3)
    "instant_download_apk":     (6, "critical"),  # กดแล้วได้ไฟล์ .apk ทันที = สูตรแอปดูดเงิน
    "instant_download_exe":     (4, "high"),      # กดแล้วได้ไฟล์รันได้ทันที (มีเว็บ download
                                                  # จริงอยู่บ้าง จึงไม่ฟันแดงเดี่ยว ๆ)
    "instant_download_archive": (2, "medium"),    # กดแล้วได้ไฟล์บีบอัดทันที

    # ---- ชั้นที่ 4 (เสริม): อายุโดเมน (RDAP) + ใบรับรอง SSL ----
    "domain_very_new":     (6, "critical"),  # จดทะเบียนมาไม่ถึง 7 วัน
    "domain_new":          (3, "high"),      # จดทะเบียนมาไม่ถึง 30 วัน
    "ssl_invalid":         (5, "critical"),  # handshake ผ่านแต่ตรวจสอบ certificate ไม่ผ่าน
    "ssl_cert_new":        (2, "medium"),    # certificate เพิ่งออกไม่ถึง 3 วัน

    # ---- ชั้นที่ 4 (เสริม): วิเคราะห์เนื้อหาจริงของหน้าเว็บปลายทาง ----
    # กลุ่ม 1 — การล้วงข้อมูล (สัญญาณแรงที่สุด เพราะเห็นปลายทางของข้อมูลที่ผู้ใช้กรอก)
    "form_action_mismatch":  (6, "critical"),  # ฟอร์มรหัสผ่านส่งข้อมูลไปคนละโดเมน
    "form_action_ip":        (4, "high"),      # ฟอร์มรหัสผ่านส่งข้อมูลไปที่เลข IP ตรง ๆ
    "password_outside_form": (3, "high"),      # ช่องรหัสผ่านอยู่นอกฟอร์ม (ต้องมี JS มาเก็บ)
    # กลุ่ม 2 — เลียนแบบแบรนด์
    "favicon_brand_mismatch": (5, "critical"),  # favicon hotlink จากโดเมนแบรนด์จริง
    "content_brand_mismatch": (3, "high"),      # เนื้อหาในหน้าอ้างถึงแบรนด์ทั้งที่โดเมนไม่ตรง
    "brand_hidden_in_text":   (4, "high"),      # เจอชื่อแบรนด์เฉพาะหลัง normalize = จงใจอำพราง
    # (logo_hotlink_brand ถอดออกแล้ว false positive สูงเกินรับได้ ดูเหตุผลใน content_analyzer.py)
    # กลุ่ม 1 (ต่อ) — สัญญาณที่เห็นได้เฉพาะเมื่อรัน JavaScript จริงใน sandbox
    "js_post_cross_origin":  (6, "critical"),  # สคริปต์ส่งข้อมูลข้ามโดเมนจากหน้าที่ขอรหัสผ่าน
    # กลุ่ม 3 — การอำพราง/หลบการตรวจ
    "dom_differs_from_source": (2, "medium"),  # หน้าที่เห็นจริงต่างจาก HTML ที่ส่งมาเกือบทั้งหมด
    "js_obfuscated":         (2, "medium"),    # สคริปต์ถูกอำพรางไว้หลายชั้น
    "instant_redirect":      (2, "medium"),    # เด้งไปหน้าอื่นทันทีที่เปิด
    "devtools_blocked":      (1, "low"),       # ดักคลิกขวา/ปุ่ม F12
    # กลุ่ม 4 — คุณภาพหน้าเว็บ (ตัวประกอบล้วน ห้ามใช้เป็นหลักฐานเดี่ยว)
    "no_favicon":            (0, "low"),       # ไม่บวกคะแนน แสดงเป็นข้อสังเกตอย่างเดียว
    "single_page_no_links":  (1, "low"),
    "html_too_small":        (1, "low"),
}

# ---------------------------------------------------------------------------
# หลักฐานฝั่ง "ปลอดภัย" (trust evidence)
# ---------------------------------------------------------------------------
# ปัญหาที่ตารางข้างบนแก้ไม่ได้: WEIGHTS ทั้งหมดเป็นคะแนน "เสี่ยง" ล้วน ระบบจึงมีทาง
# ตอบเขียวอยู่ทางเดียวคือโดเมนตรงกับลิสต์ BRANDS เป๊ะ ผลคือเว็บสุจริตที่ไม่ได้อยู่ในลิสต์
# — มหาวิทยาลัยไทย หน่วยงานราชการ วิกิพีเดีย — ได้ "เหลือง" ทั้งหมดตลอดกาล
# ไม่ว่าจะสะอาดแค่ไหน (วัดกับ testset_100.json: safe 50 ลิงก์ ได้เขียวแค่ 18)
#
# ตารางนี้คือหลักฐานอีกด้าน "อะไรบ้างที่ยืนยันได้ว่าเว็บนี้เป็นของจริง"
#
# กติกาสำคัญ 3 ข้อ (ห้ามแก้โดยไม่คิดให้ครบ):
#   1) **หลักฐานฝั่งปลอดภัยไม่หักคะแนนความเสี่ยง** ทุกสัญญาณในกลุ่มนี้ points = 0 เสมอ
#      ถ้ายอมให้หักคะแนนได้ เว็บอันตรายที่บังเอิญมีจุดน่าเชื่อถือ (เช่นโดเมนเก่า) จะ
#      ลดตัวเองจากแดงเป็นเหลืองได้ — ระบบเตือนภัยต้องไม่มีทางถูกกล่อมให้เงียบลง
#   2) เขียวได้ต้อง "ไม่มีสัญญาณเสี่ยงเหลืออยู่เลยแม้แต่ตัวเดียว" จากทุกชั้นรวมกัน
#      หลักฐานฝั่งนี้ใช้ยกระดับจาก "เหลืองเพราะไม่รู้จัก" เป็นเขียวเท่านั้น
#      ไม่ได้ใช้กลบสัญญาณเสี่ยง (บังคับใช้ที่ scanner._trust_grants_green)
#   3) พื้นที่ฝากเว็บฟรี (USER_CONTENT_DOMAINS) และลิงก์ย่อ ไม่มีสิทธิ์ได้หลักฐานฝั่งนี้
#      เลยไม่ว่าข้อไหน — เชื่อบริษัทเจ้าของโดเมนได้ แต่เชื่อของที่คนอื่นเอามาฝากไม่ได้

# นามสกุลที่ "นายทะเบียนบังคับให้พิสูจน์ตัวตนก่อนถึงจะจดได้ และผู้จดต้องเป็นหน่วยงาน
# ของรัฐหรือสถานศึกษาเท่านั้น" — มิจฉาชีพจดไม่ได้จริง ๆ ไม่ใช่แค่จดยาก
# จึงเป็นหลักฐานที่หนักพอจะให้เขียวได้ด้วยตัวเองถ้าไม่มีสัญญาณเสี่ยงอื่นเลย
# ที่มา: ระเบียบการจดทะเบียนโดเมน .th ของ THNIC (ต้องยื่นหนังสือจากหน่วยงานต้นสังกัด)
RESTRICTED_TLDS = {
    "go.th":  "สงวนให้หน่วยงานราชการไทย ต้องยื่นหนังสือจากหน่วยงานต้นสังกัดถึงจะจดได้",
    "ac.th":  "สงวนให้สถานศึกษาในไทย ต้องมีหนังสือรับรองจากหน่วยงานที่กำกับดูแล",
    "mi.th":  "สงวนให้หน่วยงานทางทหารของไทยเท่านั้น",
    "gov.uk": "สงวนให้หน่วยงานรัฐบาลสหราชอาณาจักรเท่านั้น",
}

# นามสกุลที่ต้องใช้เอกสารนิติบุคคลถึงจะจดได้ — พิสูจน์ได้แค่ว่า "มีตัวตนตามกฎหมาย
# และตามตัวได้" ไม่ได้แปลว่าเนื้อหาปลอดภัย (บริษัทจริงถูกแฮกได้ และจดบริษัทเพื่อหลอก
# ก็ทำได้ถ้ายอมทิ้งหลักฐาน) จึงให้ครึ่งเดียว ต้องมีหลักฐานอื่นมาประกอบถึงจะเขียว
VERIFIED_ORG_TLDS = {
    "co.th":  "ต้องใช้หนังสือรับรองบริษัทหรือเครื่องหมายการค้าที่จดทะเบียนในไทย",
    "or.th":  "ต้องใช้เอกสารจดทะเบียนองค์กร/มูลนิธิ/สมาคมในไทย",
    "net.th": "สงวนให้ผู้ให้บริการเครือข่ายที่ได้รับใบอนุญาตในไทย",
    "co.jp":  "ต้องเป็นบริษัทที่จดทะเบียนในญี่ปุ่น",
}

# ความนิยมของโดเมน (ดู popularity.py) — (อันดับไม่เกิน, น้ำหนักหลักฐาน)
# เรียงจากเข้มไปอ่อน ใช้อันแรกที่เข้าเงื่อนไข
#   top 10,000  = เว็บที่คนทั้งโลกใช้จริงทุกวัน ของปลอมไม่มีทางไต่มาถึงตรงนี้
#   top 100,000 = มีคนใช้จริงพอสมควร เป็นหลักฐานประกอบได้ แต่ไม่พอให้เขียวเดี่ยว ๆ
#                 (โฮสติ้งที่ถูกแฮกแล้วเอามาฝากหน้าฟิชชิ่งตกอยู่ในช่วงนี้ได้ — วัดจาก
#                  testset พบ avnam.net อันดับ 52,939 และ tepuyserver.net 34,179)
POPULARITY_TIERS = ((10_000, 4), (100_000, 2))

# น้ำหนักของหลักฐานแต่ละชนิด (points ในสัญญาณเป็น 0 เสมอ — ดูกติกาข้อ 1 ข้างบน)
TRUST_WEIGHTS = {
    "restricted_tld":   4,   # นามสกุลสงวนสำหรับราชการ/สถานศึกษา -> เขียวได้เดี่ยว
    "verified_org_tld": 2,   # นามสกุลที่ต้องใช้เอกสารนิติบุคคล -> เป็นหลักฐานประกอบ
    # popular_domain ใช้น้ำหนักจาก POPULARITY_TIERS ตามอันดับที่ค้นเจอ
}

# ต้องมีน้ำหนักหลักฐานฝั่งปลอดภัยรวมถึงเท่านี้ถึงจะยกจากเหลืองเป็นเขียวได้
GREEN_TRUST = 4

# ---------------------------------------------------------------------------
# กฎการรวมสัญญาณ (combination rules)
# ---------------------------------------------------------------------------
# ปัญหาของการบวกคะแนนตรง ๆ: หน้าเว็บที่ ① อ้างชื่อธนาคาร ② มีช่องรหัสผ่าน ③ โดเมน
# อายุ 3 วัน — แต่ละอย่างเป็นแค่ medium/high พอบวกกันอาจยังไม่ถึงแดง ทั้งที่รวมกัน
# แล้วมันคือหน้าฟิชชิ่งเต็มรูปแบบที่ไม่ควรปล่อยเป็นเหลือง
#
# กติกา (บังคับใช้ใน combos.py):
#   - combo ทำงานเฉพาะเมื่อสัญญาณที่ต้องการถูก "ตรวจแล้วว่าเจอจริง" เท่านั้น
#     ชั้นไหนเช็กไม่ได้ (checked=False) สัญญาณของชั้นนั้นจะไม่อยู่ในเซ็ตตั้งแต่แรก
#     จึงไม่มีทางถูกนับ — ระบบจะไม่เดาแทนผู้ใช้
#   - has_password_input เป็น "ข้อเท็จจริง" ไม่ใช่สัญญาณเสี่ยง ไม่มีคะแนนในตัวเอง
#     (เว็บล็อกอินจริงทุกเว็บก็มี) แต่ใช้เป็นเงื่อนไขของ combo ได้
COMBO_RULES = [
    {
        "id": "combo_brand_password",
        "needs": {"content_brand_mismatch", "has_password_input"},
        "bonus": 4,
        "title": "หน้านี้ขอรหัสผ่านโดยอ้างชื่อแบรนด์ที่ไม่ใช่เจ้าของโดเมน",
        "detail": "แยกกันแล้วสองอย่างนี้ยังพออธิบายได้ แต่การขอรหัสผ่านบนหน้าที่อ้าง"
                  "ชื่อแบรนด์อื่นพร้อมกัน คือรูปแบบมาตรฐานของหน้าหลอกขโมยบัญชี",
    },
    {
        "id": "combo_new_domain_password",
        "needs": {"has_password_input", "domain_very_new"},
        "bonus": 3,
        "title": "หน้าขอรหัสผ่านบนโดเมนที่เพิ่งจดไม่กี่วัน",
        "detail": "บริการจริงไม่ย้ายหน้าล็อกอินไปโดเมนที่เพิ่งจดใหม่ ส่วนเว็บหลอก"
                  "ต้องเปลี่ยนโดเมนบ่อยเพราะโดนปิดเรื่อย ๆ",
    },
    {
        "id": "combo_obfuscated_password",
        "needs": {"js_obfuscated", "has_password_input"},
        "bonus": 3,
        "title": "หน้าขอรหัสผ่านที่ซ่อนโค้ดการทำงานไว้",
        "detail": "หน้าล็อกอินจริงไม่มีเหตุผลต้องซ่อนว่าโค้ดของตัวเองทำอะไรกับรหัสผ่าน"
                  "ที่ผู้ใช้พิมพ์",
    },
    {
        "id": "combo_bare_brand_password",
        "needs": {"brand_bare_domain", "has_password_input"},
        "bonus": 3,
        "title": "โดเมนใช้ชื่อแบรนด์บนนามสกุลที่ไม่ใช่ทางการ และหน้าขอรหัสผ่าน",
        "detail": "ถ้าเป็นโดเมนภูมิภาคของแบรนด์จริง หน้าล็อกอินมักถูกยืนยันจากลิสต์ทางการ"
                  "ไปแล้ว การขอรหัสผ่านบนโดเมนชื่อแบรนด์ที่ระบบไม่รู้จักจึงน่าสงสัยเป็นพิเศษ",
    },
    {
        "id": "combo_brand_path_password",
        "needs": {"brand_in_path", "has_password_input"},
        "bonus": 4,
        "title": "ลิงก์อ้างชื่อแบรนด์ใน path และหน้าปลายทางขอรหัสผ่าน",
        "detail": "ชื่อแบรนด์ใน path เฉย ๆ เจอได้ทั่วไปในเว็บข่าว/บทความ แต่เมื่อหน้า"
                  "นั้นขอรหัสผ่านด้วยทั้งที่โดเมนไม่ใช่ของแบรนด์ คือรูปแบบหน้าหลอกขโมยบัญชี",
    },
    {
        "id": "combo_hidden_brand_password",
        "needs": {"brand_hidden_in_text", "has_password_input"},
        "bonus": 5,
        "title": "จงใจซ่อนชื่อแบรนด์ไม่ให้ระบบตรวจเจอ พร้อมขอรหัสผ่าน",
        "detail": "การเขียนชื่อแบรนด์ด้วยอักขระหลอกตาเพื่อให้คนอ่านออกแต่ระบบตรวจ"
                  "หาไม่เจอ เป็นการตั้งใจหลบการตรวจสอบโดยตรง",
    },
]

# คะแนนรวมเท่าไรถึงนับเป็นแต่ละระดับ
RED_SCORE = 6      # >= แดง
YELLOW_SCORE = 2   # >= เหลือง  (ต่ำกว่านี้และไม่รู้จัก = เหลือง "ควรระวัง" เช่นกัน)

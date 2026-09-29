const L = require('./lib');
const { d, P, PL, chapter, H2, H3, bullet, numbered, table, callout, code, ref, FrontTitle, fill, setChapter } = L;
const { Paragraph, TextRun, AlignmentType, HeadingLevel } = d;

const ch5 = () => {
  setChapter(5);
  return [
    chapter(5, 'สรุปผล อภิปรายผล และข้อเสนอแนะ'),

    H2('5.1 สรุปผลการดำเนินงาน'),
    P('โครงงานนี้พัฒนาเว็บแอปพลิเคชัน “เช็กก่อนกด” สำหรับตรวจความเสี่ยงของลิงก์และ QR Code เป็นภาษาไทย และเปิดให้บริการจริงที่ https://checkurl.studiodup.com เมื่อเทียบกับวัตถุประสงค์ทั้งสี่ข้อ สรุปผลได้ดังตารางที่ 5.1'),
    ...table('สรุปผลการดำเนินงานเทียบกับวัตถุประสงค์', ['วัตถุประสงค์', 'ผลที่ได้', 'สถานะ'], [
      ['1. ตรวจลิงก์แบบทันทีโดยไม่ต้องเปิดลิงก์ แสดงผล 3 ระดับพร้อมเหตุผลภาษาไทย', 'ระบบตรวจ 4 ชั้นทำงานบนเว็บจริง ชั้นที่ 1–2 ตอบภายใน 34–72 มิลลิวินาที พร้อมแผนภาพโดเมนจริงและเหตุผลรายข้อ', 'บรรลุ'],
      ['2. ตรวจ QR Code ทั้งแบบลิงก์และไม่ใช่ลิงก์ โดยเฉพาะ QR พร้อมเพย์', 'รองรับ QR 7 กลุ่ม ตรวจ CRC-16 ของพร้อมเพย์และจับ QR ที่ถูกแก้เลขบัญชีได้โดยไม่ต้องต่อเครือข่าย', 'บรรลุ'],
      ['3. เกณฑ์ตัดสินที่เตือนเว็บจริงผิดต่ำที่สุด และไม่ให้เขียวกับสิ่งที่พิสูจน์ไม่ได้', 'อัตราการเตือนเว็บจริงเป็นสีแดงผิดร้อยละ 0 และไม่มีลิงก์หลอกได้สีเขียว', 'บรรลุ'],
      ['4. ประเมินกับลิงก์หลอกจริงและเปรียบเทียบกับการเรียนรู้ของเครื่อง', 'ประเมินกับลิงก์หลอกที่ยังทำงาน 50 รายการ และเปรียบเทียบกับ Logistic Regression ที่ฝึกจากข้อมูล 235,795 รายการ', 'บรรลุ'],
    ], [36, 50, 14], { align: [undefined, undefined, 'center'] }),

    H2('5.2 อภิปรายผล'),
    H3('5.2.1 ความสำคัญของการไม่เตือนผิด'),
    P('ระบบที่เตือนประชาชนก่อนกดลิงก์มีต้นทุนของการเตือนผิดสูงมาก หากเว็บไซต์ธนาคารจริงถูกขึ้นสีแดงเพียงไม่กี่ครั้ง ผู้ใช้จะเลิกเชื่อคำเตือนทั้งหมดของระบบ ซึ่งสอดคล้องกับหลักการของ CANTINA+ ที่เน้นการกรองเพื่อลดการเตือนผิด (Xiang et al., 2011) ผลการทดลองในหัวข้อ 4.4 สนับสนุนการเลือกใช้ระบบกำหนดกฎเป็นแกนหลัก เพราะ ณ จุดที่ห้ามเตือนผิด ระบบจัดอันดับลิงก์หลอกได้ร้อยละ 72 เทียบกับร้อยละ 34 ของแบบจำลอง ขณะที่การเรียนรู้ของเครื่องจะเหมาะกว่าในงานที่ยอมให้เตือนผิดได้ เช่น การคัดกรองชั้นต้นก่อนส่งต่อให้เจ้าหน้าที่ตรวจสอบ ผลนี้ชี้ว่าคำถามที่ถูกต้องไม่ใช่ “วิธีใดดีกว่า” แต่เป็น “วิธีใดเหมาะกับจุดทำงานที่ระบบจะถูกใช้จริง”'),
    H3('5.2.2 สีเหลืองคือคำตอบที่ซื่อตรง'),
    P('ลิงก์หลอก 36 จาก 50 รายการได้สีเหลืองแทนสีแดง เมื่อมองเผิน ๆ อาจดูเหมือนระบบพลาด แต่การวิเคราะห์ในตารางที่ 4.5 แสดงว่าลิงก์เหล่านี้ส่วนใหญ่ “ดูปกติ” จากตัว URL เช่น หน้าเว็บบนพื้นที่ฝากเว็บฟรีที่ไม่มีชื่อแบรนด์ หรือเว็บไซต์จริงที่ถูกแฮก การบังคับให้เป็นสีแดงจะต้องแลกกับการเตือนเว็บไซต์จริงผิด สิ่งที่ระบบทำได้ถูกต้องคือไม่รับรองว่าลิงก์เหล่านี้ปลอดภัย ผู้ใช้จึงยังได้รับคำเตือนให้ระวังครบทั้ง 50 รายการ'),
    H3('5.2.3 ความสามารถในการอธิบายเหตุผล'),
    P('ระบบกำหนดกฎบอกผู้ใช้ได้ว่า “ทำไม” เช่น พบชื่อธนาคารในโดเมนที่ไม่ใช่ของธนาคาร พร้อมชี้ให้เห็นโดเมนจริงในแผนภาพ ข้อมูลนี้ช่วยให้ผู้ใช้เรียนรู้วิธีสังเกตลิงก์หลอกด้วยตนเอง ขณะที่แบบจำลองการเรียนรู้ของเครื่องให้ได้เพียงค่าความน่าจะเป็น สำหรับระบบที่มุ่งเตือนประชาชนทั่วไป คุณสมบัตินี้มีน้ำหนักมากในการเลือกใช้งานจริง'),
    H3('5.2.4 ข้อควรระวังเรื่องชุดข้อมูลสาธารณะ'),
    P('ชุดข้อมูล PhiUSIIL รายงานความแม่นยำสูงถึงร้อยละ 99.79 (Prasad & Chandra, 2024) แต่การตรวจสอบของคณะผู้จัดทำพบว่ากฎข้อเดียวที่ไม่เกี่ยวกับการหลอกลวงก็ได้ความถูกต้องร้อยละ 87.9 เพราะข้อมูลสองฝั่งถูกเก็บมาคนละรูปแบบ ข้อค้นพบนี้ชี้ว่าการตรวจลักษณะของข้อมูลก่อนฝึกเป็นขั้นตอนที่ข้ามไม่ได้ และตัวเลขความแม่นยำที่สูงเกินจริงอาจมาจากข้อมูล ไม่ใช่ความสามารถของแบบจำลอง'),

    H2('5.3 ปัญหาและอุปสรรคที่พบระหว่างการพัฒนา'),
    ...table('ปัญหาที่พบและวิธีแก้ไข', ['ปัญหา', 'สาเหตุ', 'วิธีแก้ไข'], [
      ['ระบบเคยให้สีเขียวกับหน้าฟิชชิงจริงบน github.io', 'โดเมนแพลตฟอร์มติดอันดับความนิยมสูง จึงได้หลักฐานฝั่งปลอดภัย', 'ตัดสิทธิ์พื้นที่ฝากเว็บฟรีและลิงก์ย่อจากหลักฐานฝั่งปลอดภัยทั้งหมด และเพิ่มเทสต์ล็อกไว้'],
      ['บทความข่าวที่พูดถึงแบรนด์ถูกตีเป็นสีแดง', 'กฎเดิมไม่แยกว่าชื่อแบรนด์อยู่ในชื่อโฮสต์หรือในพาธ', 'แยกสัญญาณ `brand_in_path` (2 คะแนน) ออกจาก `brand_impersonation` (6 คะแนน)'],
      ['`tree.com` ถูกมองว่าปลอม `true`', 'คำสั้นมีระยะ Levenshtein ใกล้กันโดยบังเอิญ', 'กำหนดความยาวขั้นต่ำของชื่อแบรนด์ตามระยะทาง'],
      ['คำว่า “win” ใน windows ถูกนับเป็นคำล่อ', 'ค้นหาคำล่อแบบสตริงย่อย', 'เปลี่ยนเป็นการค้นหาแบบทั้งคำ'],
      ['QR ของร้านที่ตั้งชื่อภาษาไทยถูกตัดสินว่าถูกแก้ไข', 'นับความยาวใน TLV เป็นตัวอักษรแทนไบต์', 'ถอดข้อมูลบนระดับไบต์ UTF-8 ทั้งหมด'],
      ['โหมด QR ใช้งานไม่ได้บนเว็บจริง', 'นโยบาย CSP ไม่อนุญาตสคริปต์จาก CDN', 'เก็บไลบรารี jsQR ไว้ในเครื่องแม่ข่ายของโครงงาน'],
      ['ระบบจำกัดอัตราเห็นผู้ใช้ทุกคนเป็นคนเดียวกัน', 'Waitress ลบ header `X-Forwarded-*` ทิ้งเป็นค่าเริ่มต้น', 'สร้าง `serve.py` ตั้งค่า `trusted_proxy` ให้ถูกต้อง'],
      ['เว็บช้าทั้งระบบเมื่อมีผู้ใช้ตรวจแบบ bulk', 'งาน 8 วินาทียึด thread ของเว็บเซิร์ฟเวอร์', 'ย้ายงาน bulk ไปทำเบื้องหลังและตอบ 202 + job_id'],
      ['ช่องโหว่ DNS rebinding', 'การตรวจ IP กับการเชื่อมต่อจริงถาม DNS คนละรอบ', 'ตรวจที่อยู่ปลายทางหลังเชื่อมต่อด้วย `getpeername()`'],
      ['ผลความแม่นยำของ ML สูงเกินจริง', 'ข้อมูลสองฝั่งของชุดข้อมูลเก็บมาต่างรูปแบบ', 'ตัด URL ให้เหลือชื่อโฮสต์ก่อนฝึก และรายงานทั้งสองรอบอย่างโปร่งใส'],
    ], [30, 32, 38]),

    H2('5.4 ข้อจำกัดของระบบและการทดลอง'),
    ...numbered([
      'ชุดทดสอบมีกลุ่มละ 50 รายการ ผลต่างที่ต่ำกว่าประมาณร้อยละ 10 ยังไม่มีนัยสำคัญทางสถิติ',
      'การประเมินรอบล่าสุดใช้เฉพาะชั้นที่ 1–2 และโหลดบัญชีดำของ สกมช. ไม่สำเร็จ ยังไม่ได้วัดว่าชั้นที่ 3–4 เพิ่มความสามารถขึ้นเท่าใด',
      'เว็บไซต์จริงในชุดทดสอบเป็นหน้าแรกของโดเมนที่ใช้ HTTPS ทั้งหมด ยังขาดกรณียาก เช่น เว็บจริงที่ URL ยาวหรือใช้นามสกุลราคาถูก',
      'ฐานความรู้แบรนด์มี 74 แบรนด์ ลิงก์ที่ปลอมแบรนด์นอกรายการจะตรวจจับได้จากสัญญาณอื่นเท่านั้น',
      'สถานะแคช คิวงาน และโควตาเก็บในหน่วยความจำของโปรเซสเดียว หากขยายเป็นหลายโปรเซสหรือหลายเครื่องต้องย้ายไปใช้ระบบเก็บข้อมูลกลาง',
      'ระบบชำระเงินพรีเมียมเป็นการจำลอง ยังไม่ได้เชื่อมต่อผู้ให้บริการชำระเงินจริง',
    ]),

    H2('5.5 ข้อเสนอแนะและแนวทางการพัฒนาต่อ'),
    ...numbered([
      'รันการประเมินแบบครบ 4 ชั้นพร้อมบัญชีดำ สกมช. บนชุดทดสอบที่ใหญ่ขึ้น (หลายร้อยรายการ) และเก็บลิงก์หลอกต่อเนื่องจากหลายแหล่ง เพื่อให้ได้ตัวเลขที่มีนัยสำคัญทางสถิติ',
      'ปรับน้ำหนักคะแนนเชิงประจักษ์จากข้อมูลจริง เช่น วัดความถี่ของแต่ละสัญญาณในลิงก์หลอกเทียบกับเว็บจริง แล้วใช้กำหนดน้ำหนักแทนการกำหนดด้วยระดับความรุนแรง',
      'ใช้การเรียนรู้ของเครื่องเป็น “ชั้นเสริม” ที่ยกลิงก์จากเขียวหรือไม่รู้จักเป็นเหลืองได้ แต่ไม่มีสิทธิ์ทำให้เป็นแดงหรือเขียว เพื่อรับจุดแข็งของทั้งสองวิธีโดยไม่เสียอัตราการเตือนผิดร้อยละ 0',
      'ขยายฐานความรู้แบรนด์และหน่วยงานรัฐไทย เช่น เพิ่ม `bot.or.th` และ `ncsa.or.th` ที่ยังได้สีเหลือง',
      'พัฒนาช่องทางที่ผู้ใช้เข้าถึงง่ายขึ้น เช่น LINE Official Account ที่ส่งลิงก์มาตรวจได้ทันที หรือส่วนขยายเบราว์เซอร์ที่ตรวจก่อนเปิดลิงก์',
      'ย้ายสถานะที่อยู่ในหน่วยความจำไปใช้ Redis เพื่อรองรับการขยายระบบ และเชื่อมต่อผู้ให้บริการชำระเงินจริงพร้อมระบบยืนยันตัวตนด้วยอีเมลหรือ OTP',
    ]),
  ];
};

// ---------------------------------------------------------------- บรรณานุกรม (APA 7)
const biblio = () => [
  new Paragraph({ heading: HeadingLevel.HEADING_1, pageBreakBefore: true, alignment: AlignmentType.CENTER, spacing: { after: 360 }, children: [new TextRun('บรรณานุกรม')] }),
  ref('กรมประชาสัมพันธ์. (2567, 8 พฤศจิกายน). *รองโฆษกรัฐบาล เผย สถิติแจ้งความออนไลน์ ตั้งแต่ 1 มีนาคม 65 – 31 ตุลาคม 67 มูลค่าความเสียหายรวม 74,893,134,395 บาท*. https://www.prd.go.th/th/content/category/detail/id/39/iid/338190'),
  ref('ไทยโพสต์. (2569, 8 มิถุนายน). *สายด่วน 1441 ช่วยเหยื่อสแกมเมอร์ พบโทรแจ้งเพิ่ม ตัวเลขเสียหายลดลง*. https://www.thaipost.net/general-news/1010043/'),
  ref('ธนาคารแห่งประเทศไทย. (2562). *แนวนโยบายการใช้มาตรฐาน Thai QR Code ในธุรกรรมการชำระเงิน (Policy Guideline: Standardized Thai QR Code for Payment Transactions)*. https://www.bot.or.th/content/dam/bot/documents/th/our-roles/payment-systems/payment/payment-all-hearing/policy-guideline-thai-qr-code-02.pdf'),
  ref('มูลนิธิศูนย์สารสนเทศเครือข่ายไทย [THNIC]. (2567). *.th & .ไทย Domain Name Registration Policy*. https://thnic.or.th/doc/thPolicy-EN-MAR2024.pdf'),
  ref('สำนักงานคณะกรรมการการรักษาความมั่นคงปลอดภัยไซเบอร์แห่งชาติ [สกมช.]. (ม.ป.ป.). *รายการโดเมนอันตราย (Domain blocklist)* [ชุดข้อมูลเปิด]. สืบค้นเมื่อ 29 กันยายน 2569, จาก https://opendata.ncsa.or.th/domain/blocklist.txt'),
  ref('Agten, P., Joosen, W., Piessens, F., & Nikiforakis, N. (2015). Seven months’ worth of mistakes: A longitudinal study of typosquatting abuse. In *Proceedings of the 22nd Network and Distributed System Security Symposium (NDSS 2015)*. Internet Society.'),
  ref('Anti-Phishing Working Group [APWG]. (2025). *Phishing activity trends report, 1st quarter 2025*. https://docs.apwg.org/reports/apwg_trends_report_q1_2025.pdf'),
  ref('Berners-Lee, T., Fielding, R., & Masinter, L. (2005). *Uniform resource identifier (URI): Generic syntax* (RFC 3986). Internet Engineering Task Force. https://doi.org/10.17487/RFC3986'),
  ref('Cooper, D., Santesson, S., Farrell, S., Boeyen, S., Housley, R., & Polk, W. (2008). *Internet X.509 public key infrastructure certificate and certificate revocation list (CRL) profile* (RFC 5280). Internet Engineering Task Force. https://doi.org/10.17487/RFC5280'),
  ref('Costello, A. (2003). *Punycode: A bootstring encoding of Unicode for internationalized domain names in applications (IDNA)* (RFC 3492). Internet Engineering Task Force. https://doi.org/10.17487/RFC3492'),
  ref('EMVCo. (2020). *EMV QR code specification for payment systems (EMV QRCPS): Merchant-presented mode* (Version 1.1). https://www.emvco.com/emv-technologies/qr-codes/'),
  ref('Fawcett, T. (2006). An introduction to ROC analysis. *Pattern Recognition Letters, 27*(8), 861–874. https://doi.org/10.1016/j.patrec.2005.10.010'),
  ref('Hollenbeck, S., & Newton, A. (2021a). *Registration data access protocol (RDAP) query format* (RFC 9082). Internet Engineering Task Force. https://doi.org/10.17487/RFC9082'),
  ref('Hollenbeck, S., & Newton, A. (2021b). *JSON responses for the registration data access protocol (RDAP)* (RFC 9083). Internet Engineering Task Force. https://doi.org/10.17487/RFC9083'),
  ref('Interisle Consulting Group. (2024). *Phishing landscape 2024: An annual study of the scope and distribution of phishing*. https://interisle.net/insights/phishing-landscape-2024-an-annual-study-of-the-scope-and-distribution-of-phishing'),
  ref('Kintis, P., Miramirkhani, N., Lever, C., Chen, Y., Romero-Gómez, R., Pitropakis, N., Nikiforakis, N., & Antonakakis, M. (2017). Hiding in plain sight: A longitudinal study of combosquatting abuse. In *Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security* (pp. 569–586). ACM. https://doi.org/10.1145/3133956.3134002'),
  ref('Le Pochat, V., Van Goethem, T., Tajalizadehkhoob, S., Korczyński, M., & Joosen, W. (2019). Tranco: A research-oriented top sites ranking hardened against manipulation. In *Proceedings of the 26th Network and Distributed System Security Symposium (NDSS 2019)*. Internet Society. https://doi.org/10.14722/ndss.2019.23386'),
  ref('Levenshtein, V. I. (1966). Binary codes capable of correcting deletions, insertions, and reversals. *Soviet Physics Doklady, 10*(8), 707–710.'),
  ref('Mohammad, R. M., Thabtah, F., & McCluskey, L. (2014). Predicting phishing websites based on self-structuring neural network. *Neural Computing and Applications, 25*(2), 443–458. https://doi.org/10.1007/s00521-013-1490-z'),
  ref('Mozilla Foundation. (ม.ป.ป.). *Public suffix list*. สืบค้นเมื่อ 29 กันยายน 2569, จาก https://publicsuffix.org/'),
  ref('OpenPhish. (ม.ป.ป.). *OpenPhish: Phishing intelligence*. สืบค้นเมื่อ 3 กันยายน 2569, จาก https://openphish.com/'),
  ref('OWASP Foundation. (ม.ป.ป.-ก). *Server side request forgery prevention cheat sheet*. สืบค้นเมื่อ 29 กันยายน 2569, จาก https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'),
  ref('OWASP Foundation. (ม.ป.ป.-ข). *Cross site scripting prevention cheat sheet*. สืบค้นเมื่อ 29 กันยายน 2569, จาก https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'),
  ref('Prasad, A., & Chandra, S. (2024). PhiUSIIL: A diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning. *Computers & Security, 136*, 103545. https://doi.org/10.1016/j.cose.2023.103545'),
  ref('Sheng, S., Wardman, B., Warner, G., Cranor, L. F., Hong, J., & Zhang, C. (2009). An empirical analysis of phishing blacklists. In *Proceedings of the Sixth Conference on Email and Anti-Spam (CEAS 2009)*.'),
  ref('Unicode Consortium. (ม.ป.ป.). *Unicode technical standard #39: Unicode security mechanisms*. สืบค้นเมื่อ 29 กันยายน 2569, จาก https://www.unicode.org/reports/tr39/'),
  ref('Xiang, G., Hong, J., Rose, C. P., & Cranor, L. (2011). CANTINA+: A feature-rich machine learning framework for detecting phishing web sites. *ACM Transactions on Information and System Security, 14*(2), 1–28. https://doi.org/10.1145/2019599.2019606'),
  ref('Zhang, Y., Hong, J. I., & Cranor, L. F. (2007). CANTINA: A content-based approach to detecting phishing web sites. In *Proceedings of the 16th International Conference on World Wide Web* (pp. 639–648). ACM. https://doi.org/10.1145/1242572.1242659'),
];

// ---------------------------------------------------------------- ภาคผนวก
const appx = (letter, title) => new Paragraph({ heading: HeadingLevel.HEADING_1, pageBreakBefore: true, alignment: AlignmentType.CENTER, spacing: { after: 360 }, children: [new TextRun(`ภาคผนวก ${letter}`), new TextRun({ text: title, break: 1 })] });

const appendices = () => {
  setChapter('ก');
  const a = [
    appx('ก', 'คู่มือการใช้งานระบบ'),
    H2('ก.1 การตรวจลิงก์'),
    ...numbered([
      'เปิดเว็บไซต์ https://checkurl.studiodup.com ด้วยเบราว์เซอร์บนคอมพิวเตอร์หรือโทรศัพท์มือถือ',
      'เลือกแถบ “ตรวจลิงก์” แล้ววางลิงก์ที่ได้รับลงในช่อง “วางลิงก์ที่ต้องการตรวจ” (หรือกดปุ่มตัวอย่างเพื่อทดลอง)',
      'กดปุ่ม “ตรวจลิงก์” หรือกดปุ่ม Enter',
      'อ่านผลตรวจ: สีเขียว = ยืนยันว่าปลอดภัย, สีเหลือง = ควรระวังหรือระบบยังไม่รู้จัก, สีแดง = อันตราย ห้ามกรอกข้อมูล',
      'ดูหัวข้อ “ส่วนประกอบของลิงก์” เพื่อดูโดเมนจริง และหัวข้อ “เหตุผลที่ระบบเตือน” เพื่อดูรายละเอียดของสัญญาณแต่ละข้อ',
    ]),
    H2('ก.2 การตรวจ QR Code'),
    ...numbered([
      'เลือกแถบ “ตรวจ QR Code”',
      'กด “อัปโหลดรูป QR” เพื่อเลือกภาพจากเครื่อง หรือกด “ใช้กล้อง” เพื่อสแกนสด (ภาพไม่ถูกส่งไปยังเซิร์ฟเวอร์ ระบบถอดข้อมูลในเบราว์เซอร์)',
      'ระบบแสดงชนิดของ QR สิ่งที่จะเกิดขึ้นเมื่อสแกนด้วยแอปทั่วไป เนื้อหาจริงใน QR และคำเตือน',
      'สำหรับ QR พร้อมเพย์ หากพบคำเตือน “ค่าตรวจสอบความถูกต้อง (CRC) ของ QR ไม่ตรง” ห้ามใช้ QR นั้นโอนเงิน',
    ]),
    H2('ก.3 ระดับสมาชิก'),
    P('ผู้ใช้ที่ไม่เข้าสู่ระบบตรวจได้วันละ 5 ครั้ง การสมัครสมาชิกฟรีทำให้ตรวจชั้นที่ 1–2 ได้ไม่จำกัดและดูประวัติได้ สมาชิกพรีเมียมใช้การตรวจเชิงลึก การตรวจหลายลิงก์พร้อมกัน การส่งออก CSV และสร้าง API key ได้จากหน้า “บัญชีของฉัน”'),

    appx('ข', 'ตัวอย่างการเรียกใช้ API'),
    P('ตัวอย่างการตรวจลิงก์เดียว (ผลตอบกลับตัดให้สั้นลงเพื่อความกระชับ)'),
    ...code([
      'curl -s -X POST https://checkurl.studiodup.com/api/check \\',
      '     -H "Content-Type: application/json" \\',
      '     -d \'{"url": "https://kasikorn-bank-verify.com/login"}\'',
      '',
      '{ "ok": true,',
      '  "input": "https://kasikorn-bank-verify.com/login",',
      '  "verdict": { "color": "red", "label": "อันตราย",',
      '               "headline": "พบสัญญาณของลิงก์หลอกลวง", ... },',
      '  "anatomy": { "registrable": "kasikorn-bank-verify.com", ... },',
      '  "reasons": [ { "id": "brand_impersonation", "points": 6,',
      '                 "severity": "critical", ... }, ... ],',
      '  "score": 10, "elapsed_ms": 34, ... }',
    ]),
    P('ตัวอย่างการตรวจแบบ bulk สำหรับสมาชิกพรีเมียม ระบบตอบกลับทันทีด้วยหมายเลขงาน แล้วผู้ใช้สอบถามความคืบหน้าจนสถานะเป็น done'),
    ...code([
      '# 1) สั่งงาน -> ได้ job_id กลับมาทันที',
      'curl -s -X POST https://checkurl.studiodup.com/api/check/bulk \\',
      '     -H "X-API-Key: pfk_..." -H "Content-Type: application/json" \\',
      '     -d \'{"urls": ["https://a.example", "https://b.example"]}\'',
      '{"ok":true,"job_id":"ae5c...","total":2,"state":"queued","poll_url":"/api/check/bulk/ae5c..."}',
      '',
      '# 2) ถามความคืบหน้าเป็นระยะ',
      'curl -s https://checkurl.studiodup.com/api/check/bulk/ae5c... -H "X-API-Key: pfk_..."',
      '{"ok":true,"state":"running","done":1,"total":2,"results":null}',
      '{"ok":true,"state":"done","done":2,"total":2,"results":[...]}',
    ]),

    appx('ค', 'การติดตั้งและรันระบบ'),
    P('ระบบต้องการ Python 3.12 ขึ้นไป ขั้นตอนการติดตั้งสำหรับการพัฒนามีดังนี้'),
    ...code([
      'git clone <repository> Checklink && cd Checklink/backend',
      'python3 -m venv .venv && source .venv/bin/activate',
      'pip install -r requirements.txt -r requirements-dev.txt',
      'cp .env.example .env        # แล้วตั้งค่า SECRET_KEY ด้วยค่าสุ่ม',
      'python -m pytest            # รันชุดทดสอบ (367 กรณี)',
      'python app.py               # เปิด http://127.0.0.1:5000',
    ]),
    P('การรันบนเครื่องให้บริการจริงใช้ `python serve.py` ภายใต้ systemd หลัง Nginx และนำโค้ดใหม่ขึ้นใช้งานด้วย `sudo deploy/deploy.sh` เท่านั้น (หัวข้อ 3.9) การประเมินความแม่นยำซ้ำใช้คำสั่งต่อไปนี้'),
    ...code([
      'python run_eval.py --fast                 # ชั้น 1-2 (ไม่เปิดเว็บใด ๆ)',
      'python run_eval.py --workers 8            # ครบ 4 ชั้น',
      'python ml_baseline/train_eval.py --data PhiUSIIL_Phishing_URL_Dataset.csv \\',
      '       --flip-label --normalize-host      # ทดลองเปรียบเทียบกับ ML',
    ]),
    ...callout('ข้อควรระวัง', [
      'ชุดทดสอบ `testset_100.json` และชุดข้อมูล PhiUSIIL มี URL ของเว็บหลอกที่ยังทำงานอยู่จริง ห้ามคัดลอกไปเปิดด้วยเบราว์เซอร์ สคริปต์ประเมินในโหมด `--fast` ไม่เปิดเว็บใด ๆ',
      'ชุดข้อมูล PhiUSIIL กำหนดป้ายกำกับ 1 = เว็บไซต์จริง ซึ่งกลับด้านกับสคริปต์ของโครงงาน จึงต้องใส่ตัวเลือก `--flip-label` ทุกครั้ง',
    ], { fill: 'FFF4E5', edge: 'C55A11' }),

    appx('ง', 'ประวัติผู้จัดทำ'),
    ...[1, 2, 3].flatMap(i => [
      new Paragraph({ spacing: { before: 240 }, children: [new TextRun({ text: 'ชื่อ-นามสกุล  ', bold: true }), fill(`[ผู้จัดทำคนที่ ${i}]`)] }),
      new Paragraph({ children: [new TextRun({ text: 'รหัสนักศึกษา  ', bold: true }), fill('[รหัส]')] }),
      new Paragraph({ children: [new TextRun({ text: 'หน้าที่ในโครงงาน  ', bold: true }), fill('[เช่น พัฒนาแกนวิเคราะห์ / ส่วนติดต่อผู้ใช้ / การทดสอบ]')] }),
      new Paragraph({ children: [new TextRun({ text: 'อีเมล  ', bold: true }), fill('[อีเมล]')] }),
    ]),
  ];
  return a;
};

module.exports = { ch5, biblio, appendices };

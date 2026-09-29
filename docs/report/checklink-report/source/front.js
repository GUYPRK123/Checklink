const L = require('./lib');
const { d, P, PL, FrontTitle, fill, blank } = L;
const { Paragraph, TextRun, AlignmentType, TableOfContents, StyleLevel, TabStopType } = d;
const TABS = [{ type: TabStopType.LEFT, position: 2600 }];

const C = (children, o = {}) => new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: o.after ?? 0, before: o.before ?? 0 }, children });
const T = (s, o = {}) => new TextRun({ text: s, ...o });

// ---------------------------------------------------------------- ปก
const cover = [
  ...blank(2),
  C([T('รายงานโครงงาน', { bold: true, size: 40 })], { after: 480 }),
  C([T('เช็กก่อนกด:', { bold: true, size: 44 })]),
  C([T('ระบบตรวจความเสี่ยงลิงก์และ QR Code แบบเรียลไทม์', { bold: true, size: 44 })]),
  C([T('Check Before Click: Realtime Link Risk Checker', { bold: true, size: 40 })], { after: 1200 }),
  C([T('จัดทำโดย', { bold: true, size: 36 })], { after: 120 }),
  C([fill('[ชื่อ-นามสกุล ผู้จัดทำคนที่ 1]'), T('   รหัสนักศึกษา '), fill('[รหัส]')]),
  C([fill('[ชื่อ-นามสกุล ผู้จัดทำคนที่ 2]'), T('   รหัสนักศึกษา '), fill('[รหัส]')]),
  C([fill('[ชื่อ-นามสกุล ผู้จัดทำคนที่ 3]'), T('   รหัสนักศึกษา '), fill('[รหัส]')]),
  C([T('กลุ่มที่ 34')], { after: 600 }),
  C([T('อาจารย์ที่ปรึกษา', { bold: true, size: 36 })], { after: 120 }),
  C([fill('[ชื่อ-นามสกุล อาจารย์ที่ปรึกษา]')], { after: 1200 }),
  C([T('รายงานนี้เป็นส่วนหนึ่งของรายวิชา '), fill('[รหัสวิชา ชื่อวิชา]')]),
  C([fill('[สาขาวิชา]'), T(' '), fill('[คณะ]'), T(' '), fill('[มหาวิทยาลัย/สถาบัน]')]),
  C([T('ภาคการศึกษาที่ '), fill('[1]'), T(' ปีการศึกษา 2569')]),
];

// ---------------------------------------------------------------- ใบรับรอง
const approval = [
  FrontTitle('ใบรับรองโครงงาน'),
  new Paragraph({ tabStops: TABS, indent: { left: 2600, hanging: 2600 }, children: [T('หัวข้อโครงงาน', { bold: true }), T('\tเช็กก่อนกด: ระบบตรวจความเสี่ยงลิงก์และ QR Code แบบเรียลไทม์')] }),
  new Paragraph({ tabStops: TABS, indent: { left: 2600 }, children: [T('Check Before Click: Realtime Link Risk Checker')] }),
  new Paragraph({ tabStops: TABS, children: [T('ผู้จัดทำ', { bold: true }), T('\t'), fill('[รายชื่อผู้จัดทำ]')] }),
  new Paragraph({ tabStops: TABS, children: [T('อาจารย์ที่ปรึกษา', { bold: true }), T('\t'), fill('[ชื่ออาจารย์ที่ปรึกษา]')] }),
  new Paragraph({ tabStops: TABS, children: [T('ปีการศึกษา', { bold: true }), T('\t2569')], spacing: { after: 480 } }),
  P('คณะกรรมการสอบโครงงานได้พิจารณารายงานฉบับนี้แล้ว เห็นสมควรรับเป็นส่วนหนึ่งของการศึกษารายวิชา', { after: 600 }),
  ...['ประธานกรรมการ', 'กรรมการ', 'อาจารย์ที่ปรึกษา'].flatMap(r => [
    new Paragraph({ alignment: AlignmentType.RIGHT, spacing: { before: 360 }, children: [T('ลงชื่อ ..................................................... ' + r)] }),
    new Paragraph({ alignment: AlignmentType.RIGHT, indent: { right: 1500 }, children: [T('(.....................................................)')] }),
  ]),
];

// ---------------------------------------------------------------- บทคัดย่อ
const abstractTh = [
  FrontTitle('บทคัดย่อ'),
  PL('**ชื่อโครงงาน**  เช็กก่อนกด: ระบบตรวจความเสี่ยงลิงก์และ QR Code แบบเรียลไทม์', { align: AlignmentType.LEFT }),
  new Paragraph({ children: [T('ผู้จัดทำ', { bold: true }), T('  '), fill('[รายชื่อผู้จัดทำ]')] }),
  new Paragraph({ children: [T('อาจารย์ที่ปรึกษา', { bold: true }), T('  '), fill('[ชื่ออาจารย์ที่ปรึกษา]')] }),
  PL('**ปีการศึกษา**  2569', { after: 240 }),
  P('ภัยจากลิงก์หลอกลวงสร้างความเสียหายต่อประชาชนไทยอย่างต่อเนื่อง สถิติการแจ้งความออนไลน์ระหว่างวันที่ 1 มีนาคม 2565 ถึง 31 ตุลาคม 2567 มีจำนวน 708,141 เรื่อง มูลค่าความเสียหายรวมกว่า 74,893 ล้านบาท หรือเฉลี่ยวันละ 77 ล้านบาท ขณะที่ผู้ใช้ทั่วไปไม่มีเครื่องมือที่ตอบได้ทันทีว่าลิงก์หรือ QR Code ที่ได้รับนั้นปลอดภัยหรือไม่ โครงงานนี้จึงพัฒนาเว็บแอปพลิเคชัน “เช็กก่อนกด” ที่ตรวจความเสี่ยงของลิงก์และ QR Code ได้โดยผู้ใช้ไม่ต้องกดเข้าไปในลิงก์นั้นเอง'),
  P('ระบบวิเคราะห์ลิงก์ผ่านกระบวนการ 4 ชั้นแบบลดหลั่น (cascade) ได้แก่ (1) การเทียบกับบัญชีดำของสำนักงานคณะกรรมการการรักษาความมั่นคงปลอดภัยไซเบอร์แห่งชาติ (สกมช.) (2) การวิเคราะห์รูปแบบของ URL แบบออฟไลน์ เช่น การปลอมชื่อแบรนด์ การสะกดเพี้ยน (typosquatting) และการใช้อักษรต่างภาษาที่หน้าตาเหมือนกัน (homoglyph) (3) การติดตามปลายทางจริงของลิงก์ย่อและการเปลี่ยนเส้นทาง และ (4) การตรวจอายุโดเมน ใบรับรอง SSL และเนื้อหาของหน้าเว็บจริง ผลการตรวจสรุปเป็นสามสี โดยสีเขียวจะให้เฉพาะเมื่อยืนยันได้ว่าปลอดภัยเท่านั้น สำหรับ QR Code ระบบสามารถถอดข้อมูลพร้อมเพย์ตามมาตรฐาน EMVCo และตรวจค่า CRC-16 เพื่อตรวจจับ QR ที่ถูกแก้ไขเลขบัญชีผู้รับได้โดยไม่ต้องเชื่อมต่ออินเทอร์เน็ต'),
  P('ผลการทดสอบกับชุดข้อมูล 100 ลิงก์ (เว็บไซต์จริง 50 รายการ และลิงก์หลอกที่ยังทำงานอยู่จริง 50 รายการ) โดยใช้เพียงชั้นที่ 1–2 พบว่าระบบไม่เตือนเว็บไซต์จริงเป็นสีแดงผิดเลย (อัตราการเตือนผิดร้อยละ 0) ไม่มีลิงก์หลอกรายการใดได้รับสีเขียว และเตือนลิงก์หลอกทั้งหมดเป็นสีแดงหรือเหลือง เมื่อเปรียบเทียบกับแบบจำลอง Logistic Regression ที่ฝึกจากชุดข้อมูล PhiUSIIL จำนวน 235,795 รายการ ณ เงื่อนไขที่ห้ามเตือนเว็บไซต์จริงผิด ระบบของโครงงานจัดอันดับลิงก์หลอกได้ร้อยละ 72 ขณะที่แบบจำลองทำได้ร้อยละ 34 นอกจากนี้ระบบผ่านการทดสอบหน่วย (unit test) ทั้งหมด 367 กรณี และเปิดให้บริการจริงที่ https://checkurl.studiodup.com'),
  PL('**คำสำคัญ:** ฟิชชิง, ลิงก์หลอกลวง, การตรวจจับ URL, QR Code พร้อมเพย์, typosquatting, homoglyph', { before: 240 }),
];

const abstractEn = [
  FrontTitle('Abstract'),
  PL('**Project Title**  Check Before Click: Realtime Link Risk Checker', { align: AlignmentType.LEFT }),
  new Paragraph({ children: [T('Authors', { bold: true }), T('  '), fill('[Authors]')] }),
  new Paragraph({ children: [T('Advisor', { bold: true }), T('  '), fill('[Advisor]')] }),
  PL('**Academic Year**  2026', { after: 240 }),
  P('Fraudulent links continue to cause severe losses in Thailand: between 1 March 2022 and 31 October 2024, 708,141 online fraud cases were reported with total damages of over 74.9 billion baht, or about 77 million baht per day. Ordinary users, however, have no tool that can instantly tell whether a link or QR code they received is safe. This project developed “Check Before Click”, a web application that assesses the risk of links and QR codes without requiring the user to open them.', { align: AlignmentType.JUSTIFIED }),
  P('Each link passes through a four-layer cascade: (1) lookup in the blocklist of Thailand’s National Cyber Security Agency (NCSA); (2) offline URL analysis that detects brand impersonation, typosquatting, homoglyph domains, and links that are dangerous on click; (3) redirect following to reveal the real destination of shortened links; and (4) domain age, TLS certificate, and live page-content analysis. Results are summarized as green, yellow, or red, where green is granted only when safety can be positively confirmed. For QR codes, the system decodes PromptPay payloads according to the EMVCo specification and verifies their CRC-16 checksum, detecting QR codes whose recipient account has been altered without any network access.', { align: AlignmentType.JUSTIFIED }),
  P('On a test set of 100 links (50 legitimate websites and 50 live phishing links) using only layers 1–2, the system produced no false red verdicts on legitimate sites (0% false-positive rate), gave no phishing link a green verdict, and flagged every phishing link as red or yellow. Compared with a logistic regression model trained on the 235,795-URL PhiUSIIL dataset at zero false positives, the project’s system ranked 72% of phishing links above all legitimate sites, versus 34% for the model. The system passes all 367 unit tests and is deployed at https://checkurl.studiodup.com.', { align: AlignmentType.JUSTIFIED }),
  PL('**Keywords:** phishing, malicious URL detection, PromptPay QR code, typosquatting, homoglyph', { before: 240 }),
];

const ack = [
  FrontTitle('กิตติกรรมประกาศ'),
  P('โครงงานนี้สำเร็จลุล่วงได้ด้วยความกรุณาจาก ' + '[ชื่ออาจารย์ที่ปรึกษา]' + ' อาจารย์ที่ปรึกษาโครงงาน ซึ่งได้ให้คำแนะนำ ตรวจสอบ และชี้ให้เห็นความสำคัญของการอ้างอิงแหล่งที่มาของน้ำหนักคะแนนและการเปรียบเทียบกับอัลกอริทึมทางเลือก อันเป็นส่วนที่ทำให้งานมีหลักฐานรองรับมากขึ้น คณะผู้จัดทำขอขอบพระคุณเป็นอย่างสูง'),
  P('ขอขอบคุณสำนักงานคณะกรรมการการรักษาความมั่นคงปลอดภัยไซเบอร์แห่งชาติ (สกมช.) ที่เปิดเผยรายการโดเมนอันตรายเป็นข้อมูลเปิด ขอบคุณผู้จัดทำชุดข้อมูล PhiUSIIL ผ่าน UCI Machine Learning Repository ผู้พัฒนารายการอันดับ Tranco และ OpenPhish ที่เผยแพร่ข้อมูลให้นำมาใช้ในการศึกษา ตลอดจนผู้พัฒนาซอฟต์แวร์โอเพนซอร์สทุกโครงการที่ระบบนี้ใช้งาน'),
  P('สุดท้ายนี้ขอขอบคุณครอบครัวและเพื่อน ๆ ที่ให้กำลังใจและช่วยทดลองใช้งานระบบตลอดระยะเวลาการพัฒนา หากรายงานฉบับนี้มีข้อบกพร่องประการใด คณะผู้จัดทำขอน้อมรับไว้เพื่อปรับปรุงต่อไป'),
  new Paragraph({ alignment: AlignmentType.RIGHT, spacing: { before: 480 }, children: [T('คณะผู้จัดทำ')] }),
  new Paragraph({ alignment: AlignmentType.RIGHT, children: [fill('[วันที่ เดือน]'), T(' 2569')] }),
];

const tocs = [
  FrontTitle('สารบัญ'),
  new TableOfContents('สารบัญ', { hyperlink: true, headingStyleRange: '1-3' }),
  FrontTitle('สารบัญตาราง'),
  new TableOfContents('สารบัญตาราง', { hyperlink: true, stylesWithLevels: [new StyleLevel('TableCaption', 1)] }),
  FrontTitle('สารบัญภาพ'),
  new TableOfContents('สารบัญภาพ', { hyperlink: true, stylesWithLevels: [new StyleLevel('FigureCaption', 1)] }),
];

module.exports = { cover, approval, abstractTh, abstractEn, ack, tocs };

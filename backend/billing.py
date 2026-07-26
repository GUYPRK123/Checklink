# -*- coding: utf-8 -*-
"""
billing.py
Blueprint ระบบพรีเมียม + "จำลอง" การชำระเงิน

สำคัญ: นี่คือ mock payment เพื่อการสาธิต/โปรเจกต์จบเท่านั้น ไม่ได้ต่อกับผู้ให้บริการรับชำระ
เงินจริงเจ้าใด (Omise/2C2P/Stripe ฯลฯ) การรับเงินจริงต้องจดทะเบียนนิติบุคคลและผ่าน
กระบวนการ KYC ของผู้ให้บริการก่อน — ฟอร์มนี้แค่ validate รูปแบบข้อมูลแล้วถือว่าจ่ายสำเร็จ
ทันที ไม่มีการส่งเลขบัตร/ข้อมูลชำระเงินไปที่ไหนทั้งสิ้น (ห้ามใช้เป็นระบบรับเงินจริง)
"""
import re

from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user

from extensions import db, limiter
from models import Payment, ApiKey

billing_bp = Blueprint("billing", __name__, url_prefix="/api/billing")

_CARD_RE = re.compile(r"^\d{16}$")
_PROMPTPAY_REF_RE = re.compile(r"^\d{10,15}$")


@billing_bp.route("/plans", methods=["GET"])
def plans():
    cfg = current_app.config
    return jsonify({
        "ok": True,
        "plans": [
            {
                "id": "free", "name": "ฟรี", "price_thb": 0,
                "features": [
                    f"เช็คลิงก์พื้นฐาน (บัญชีดำ + วิเคราะห์รูปแบบ) ไม่จำกัด",
                    f"เช็คเชิงลึก (ตาม redirect / อายุโดเมน / SSL / เนื้อหาเว็บ) "
                    f"{cfg['FREE_DEEP_CHECKS_PER_DAY']} ครั้ง/วัน",
                    "สแกน QR ได้ทั้งจากกล้อง อัปโหลดรูป และวางภาพที่ก๊อปมา",
                    "อ่าน QR ที่ไม่ใช่ลิงก์ได้ (พร้อมเพย์ / Wi-Fi / เบอร์โทร / SMS) "
                    "พร้อมคำเตือนตามชนิด",
                    "ตรวจว่า QR ชำระเงินถูกแก้ไขหรือไม่ ด้วยเลขตรวจสอบ (CRC) ในตัว QR",
                ],
            },
            {
                "id": "premium", "name": "พรีเมียม", "price_thb": cfg["PREMIUM_PRICE_THB"],
                "duration_days": cfg["PREMIUM_DURATION_DAYS"],
                "features": [
                    "เช็คเชิงลึกไม่จำกัดจำนวนครั้ง",
                    f"เช็คแบบ bulk ได้ครั้งละสูงสุด {cfg['BULK_CHECK_MAX_URLS']} ลิงก์",
                    "ดูรายละเอียดเต็มของ QR พร้อมเพย์ (ชื่อผู้รับเงิน จำนวนเงิน "
                    "บัญชีปลายทาง เลขอ้างอิง) ก่อนตัดสินใจโอน",
                    f"สแกน QR หลายรูปพร้อมกันได้ครั้งละสูงสุด {cfg['BULK_CHECK_MAX_URLS']} รายการ",
                    "เตือนอัตโนมัติเมื่อเจอ QR หรือลิงก์ที่คุณเคยสแกนแล้วพบว่าอันตราย",
                    "เก็บภาพ QR ที่สแกนไว้ในประวัติ ย้อนดูได้ภายหลัง",
                    "ดูและ export ประวัติการตรวจย้อนหลัง",
                    "API key สำหรับเรียกใช้งานแบบโปรแกรม",
                ],
            },
        ],
    })


@billing_bp.route("/status", methods=["GET"])
@login_required
def status():
    limit = current_app.config["FREE_DEEP_CHECKS_PER_DAY"]
    return jsonify({
        "ok": True,
        "plan": current_user.plan,
        "is_premium": current_user.is_premium,
        "premium_until": current_user.premium_until.isoformat() if current_user.premium_until else None,
        "deep_checks_remaining": current_user.deep_checks_remaining(limit),
        "free_daily_limit": limit,
    })


@billing_bp.route("/checkout", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def checkout():
    data = request.get_json(silent=True) or {}
    method = data.get("method")

    if method == "card":
        card_number = re.sub(r"\s+", "", data.get("card_number") or "")
        expiry = (data.get("expiry") or "").strip()
        cvc = (data.get("cvc") or "").strip()
        if not _CARD_RE.match(card_number):
            return jsonify({"ok": False, "error": "หมายเลขบัตรต้องเป็นตัวเลข 16 หลัก (ข้อมูลจำลอง ไม่ต้องใช้บัตรจริง)"}), 400
        if not re.match(r"^\d{2}/\d{2}$", expiry):
            return jsonify({"ok": False, "error": "รูปแบบวันหมดอายุต้องเป็น MM/YY"}), 400
        if not re.match(r"^\d{3,4}$", cvc):
            return jsonify({"ok": False, "error": "CVC ต้องเป็นตัวเลข 3-4 หลัก"}), 400
    elif method == "promptpay":
        ref = (data.get("promptpay_ref") or "").strip()
        if not _PROMPTPAY_REF_RE.match(ref):
            return jsonify({"ok": False, "error": "หมายเลขอ้างอิงพร้อมเพย์ไม่ถูกต้อง (ข้อมูลจำลอง)"}), 400
    else:
        return jsonify({"ok": False, "error": "กรุณาเลือกวิธีชำระเงิน (card หรือ promptpay)"}), 400

    cfg = current_app.config
    payment = Payment(
        user_id=current_user.id, plan="premium", method=method,
        amount_thb=cfg["PREMIUM_PRICE_THB"], fake_txn_id=Payment.new_fake_txn_id(),
    )
    db.session.add(payment)
    current_user.activate_premium(cfg["PREMIUM_DURATION_DAYS"])
    db.session.commit()

    return jsonify({
        "ok": True,
        "demo_notice": "นี่คือธุรกรรมจำลองเพื่อการสาธิต ไม่มีการตัดเงินจริงเกิดขึ้น",
        "txn_id": payment.fake_txn_id,
        "user": current_user.to_public_dict(),
    })


@billing_bp.route("/api-key", methods=["GET"])
@login_required
def get_api_key():
    key = current_user.api_keys.filter_by(revoked=False).first()
    if not key:
        return jsonify({"ok": True, "has_key": False})
    return jsonify({"ok": True, "has_key": True, "key_prefix": key.key_prefix,
                     "created_at": key.created_at.isoformat()})


@billing_bp.route("/api-key", methods=["POST"])
@login_required
def create_api_key():
    if not current_user.is_premium:
        return jsonify({"ok": False, "error": "ต้องเป็นสมาชิกพรีเมียมก่อนถึงจะสร้าง API key ได้"}), 403

    for old in current_user.api_keys.filter_by(revoked=False):
        old.revoked = True

    raw_key, key_hash, key_prefix = ApiKey.generate()
    db.session.add(ApiKey(user_id=current_user.id, key_hash=key_hash, key_prefix=key_prefix))
    db.session.commit()

    return jsonify({
        "ok": True,
        "api_key": raw_key,
        "notice": "บันทึกกุญแจนี้ไว้ให้ดี ระบบจะไม่แสดงค่าเต็มอีกครั้ง",
    })

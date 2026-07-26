# -*- coding: utf-8 -*-
"""
check.py
Blueprint หลักของฟีเจอร์ตรวจลิงก์ (ย้ายมาจาก app.py เดิม) + ฟีเจอร์ที่ผูกกับแผนสมาชิก:
  - จำกัดการเช็คเชิงลึก (ชั้น 3-4) ตามแผน/โควตา ต้องล็อกอินก่อนถึงจะใช้ได้เลย
  - /api/check/bulk        เช็คหลายลิงก์พร้อมกัน (พรีเมียมเท่านั้น)
  - /api/history            ประวัติการตรวจของผู้ใช้ที่ล็อกอิน
  - /api/history/export     export ประวัติเป็น CSV (พรีเมียมเท่านั้น)

หมายเหตุเรื่อง CSRF: blueprint นี้ยกเว้น CSRF protection (ดู app.py ตอน register blueprint)
เพราะต้องรองรับ client ภายนอกที่เรียกด้วย API key (ไม่มี session/CSRF token) ความเสี่ยงที่
เหลือ (เช่นถูก forge ให้เช็คลิงก์เกินโควตาโดยไม่ตั้งใจ) ผลกระทบต่ำ และถูกลดทอนด้วย
SameSite=Lax cookie + rate limit อยู่แล้ว
"""
import csv
import io

from flask import Blueprint, request, jsonify, current_app, Response
from flask_login import current_user

from extensions import db, limiter
from models import ApiKey, ScanHistory
from analyzer import scan
from analyzer.qr_payload import classify as classify_qr

check_bp = Blueprint("check", __name__, url_prefix="/api")


def _resolve_api_key_user():
    raw_key = request.headers.get("X-API-Key")
    if not raw_key:
        return None
    key_row = ApiKey.query.filter_by(key_hash=ApiKey.hash_key(raw_key), revoked=False).first()
    if not key_row:
        return None
    from datetime import datetime
    key_row.last_used_at = datetime.utcnow()
    db.session.commit()
    return key_row.user


def _current_actor():
    """คืน (user หรือ None, via_api_key: bool) — รองรับทั้ง session login และ API key header"""
    api_user = _resolve_api_key_user()
    if api_user is not None:
        return api_user, True
    if current_user.is_authenticated:
        return current_user._get_current_object(), False
    return None, False


def _deep_check_decision(user):
    """ตัดสินว่าจะรันการเช็คเชิงลึกให้คำขอนี้ได้ไหม คืน (run_deep, locked_reason)"""
    if user is None:
        return False, "login_required"
    limit = current_app.config["FREE_DEEP_CHECKS_PER_DAY"]
    if user.can_run_deep_check(limit):
        return True, None
    return False, "quota_exhausted"


def _save_history(user, result: dict, ran_deep: bool,
                  source: str = "link", qr_type: str = None, qr_thumb: str = None) -> None:
    if user is None or not result.get("ok"):
        return
    verdict = result.get("verdict", {})
    db.session.add(ScanHistory(
        user_id=user.id, url=result.get("input", ""),
        verdict_color=verdict.get("color", ""), verdict_label=verdict.get("label", ""),
        ran_deep_check=ran_deep,
        source=source, qr_type=qr_type, qr_thumb=qr_thumb,
    ))
    db.session.commit()


def _clean_thumb(raw) -> str:
    """รับภาพย่อของ QR จากเบราว์เซอร์ — ยอมรับเฉพาะ data URI ของรูปที่ขนาดไม่เกินที่กำหนด
    (ฝั่งหน้าเว็บย่อให้เล็กมาก่อนส่งแล้ว ตัวนี้เป็นด่านกันฝั่งเซิร์ฟเวอร์อีกชั้น)"""
    if not isinstance(raw, str) or not raw.startswith("data:image/"):
        return None
    return raw if len(raw) <= ScanHistory.MAX_THUMB_CHARS else None


def _seen_before(user, identifier: str):
    """เคยสแกนเนื้อหาชิ้นนี้มาก่อนไหม (ฟีเจอร์พรีเมียม)
    ต้องเรียก "ก่อน" บันทึกประวัติรอบปัจจุบัน ไม่งั้นจะนับรอบนี้รวมไปด้วย"""
    if user is None or not identifier:
        return None
    rows = (user.history.filter(ScanHistory.url == identifier)
            .order_by(ScanHistory.created_at.desc()).limit(50).all())
    if not rows:
        return None
    dangerous = [r for r in rows if r.verdict_color == "red"]
    return {
        "count": len(rows),
        "last_seen": rows[0].created_at.isoformat(),
        "was_dangerous": bool(dangerous),
        "last_verdict_label": rows[0].verdict_label,
        "last_verdict_color": rows[0].verdict_color,
    }


@check_bp.route("/check", methods=["POST"])
@limiter.limit("30 per minute")
def api_check():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"ok": False, "error": "กรุณาส่งลิงก์ที่ต้องการตรวจ"}), 400

    user, via_api_key = _current_actor()
    run_deep, locked_reason = _deep_check_decision(user)

    result = scan(url, run_deep=run_deep)
    if not result.get("ok"):
        return jsonify(result)

    if run_deep and user is not None:
        user.record_deep_check()
        db.session.commit()
    _save_history(user, result, run_deep)

    if locked_reason:
        limit = current_app.config["FREE_DEEP_CHECKS_PER_DAY"]
        result["deep_check"] = {
            "ran": False, "locked_reason": locked_reason,
            "message": ("สมัครสมาชิกฟรีเพื่อปลดล็อกการตรวจเชิงลึก (ตาม redirect, "
                        "อายุโดเมน, SSL, เนื้อหาเว็บจริง)" if locked_reason == "login_required"
                        else f"ใช้โควตาการตรวจเชิงลึกฟรี {limit} ครั้ง/วันหมดแล้ว "
                             "อัพเกรดเป็นพรีเมียมเพื่อตรวจเชิงลึกไม่จำกัด"),
        }
    return jsonify(result)


_PREMIUM_QR_LOCK_MSG = ("อัพเกรดเป็นพรีเมียมเพื่อดูรายละเอียดเต็มของ QR ชำระเงิน "
                        "(ชื่อผู้รับเงิน จำนวนเงิน เลขบัญชีปลายทาง เลขอ้างอิง)")


def _warnings_color(warnings) -> str:
    """แปลงคำเตือนของ QR เป็นสีเดียวสำหรับป้ายสรุป/ประวัติ

    เฉพาะ critical เท่านั้นที่ถือเป็น "อันตราย" (แดง) — ตอนนี้มีกรณีเดียวคือ CRC ของ
    QR ชำระเงินไม่ตรง ซึ่งแปลว่า QR ถูกแก้ไขจริง ส่วน high/medium เป็นเรื่องที่ "ควรระวัง"
    แต่พบได้ในของถูกกฎหมายด้วย (เช่น สติกเกอร์พร้อมเพย์ของร้านค้าทั่วไป) ถ้าตีเป็นแดงหมด
    ผู้ใช้จะชินและเลิกอ่านคำเตือน ซึ่งอันตรายกว่าการไม่เตือนเลย
    """
    levels = {w.get("severity") for w in (warnings or [])}
    if "critical" in levels:
        return "red"
    if levels & {"high", "medium"}:
        return "yellow"
    return "green"


def _analyze_qr_payload(payload: str, user, thumb: str = None, save: bool = True) -> dict:
    """ตรวจเนื้อหาที่ถอดได้จาก QR หนึ่งอัน — ใช้ร่วมกันทั้งแบบทีละอันและแบบหลายอันพร้อมกัน

    ทำสองทางตามชนิดของเนื้อหา:
      - เป็นลิงก์  -> ส่งเข้าระบบตรวจลิงก์ 4 ชั้นเดิม (scan) เหมือนโหมดตรวจลิงก์ทุกประการ
      - ไม่ใช่ลิงก์ -> จำแนกชนิด (พร้อมเพย์/Wi-Fi/เบอร์โทร/...) แล้วเตือนตามชนิดนั้น

    รายละเอียดเชิงลึกของ QR ชำระเงิน (details) ถูกกรองที่ฝั่งเซิร์ฟเวอร์ ไม่ใช่แค่ซ่อนใน
    หน้าเว็บ เพื่อไม่ให้ผู้ใช้แผนฟรีเปิดดูได้จาก network tab
    """
    is_premium = bool(user is not None and user.is_premium)
    qr = classify_qr(payload)

    seen = _seen_before(user, payload) if is_premium else None

    scan_result = None
    if qr["type"] == "url":
        run_deep, locked_reason = _deep_check_decision(user)
        scan_result = scan(payload, run_deep=run_deep)
        if scan_result.get("ok"):
            if run_deep and user is not None:
                user.record_deep_check()
                db.session.commit()
            if locked_reason:
                limit = current_app.config["FREE_DEEP_CHECKS_PER_DAY"]
                scan_result["deep_check"] = {
                    "ran": False, "locked_reason": locked_reason,
                    "message": ("สมัครสมาชิกฟรีเพื่อปลดล็อกการตรวจเชิงลึก (ตาม redirect, "
                                "อายุโดเมน, SSL, เนื้อหาเว็บจริง)" if locked_reason == "login_required"
                                else f"ใช้โควตาการตรวจเชิงลึกฟรี {limit} ครั้ง/วันหมดแล้ว "
                                     "อัพเกรดเป็นพรีเมียมเพื่อตรวจเชิงลึกไม่จำกัด"),
                }
            if save:
                _save_history(user, scan_result, run_deep,
                              source="qr", qr_type="url", qr_thumb=thumb)
    elif save and user is not None:
        # QR ที่ไม่ใช่ลิงก์ก็ควรอยู่ในประวัติด้วย — ใช้คำเตือนที่แรงที่สุดเป็นสีของรายการ
        color = _warnings_color(qr["warnings"])
        label = {"red": "อันตราย", "yellow": "ควรระวัง", "green": "ไม่พบสิ่งผิดปกติ"}[color]
        _save_history(user, {"ok": True, "input": payload,
                              "verdict": {"color": color, "label": label}},
                      ran_deep=False, source="qr", qr_type=qr["type"], qr_thumb=thumb)

    payload_details = qr.pop("details", [])
    qr["details"] = payload_details if is_premium else []
    qr["details_locked"] = bool(payload_details) and not is_premium
    qr["details_locked_message"] = _PREMIUM_QR_LOCK_MSG if qr["details_locked"] else ""
    qr["payload"] = payload

    return {"ok": True, "qr": qr, "scan": scan_result, "seen_before": seen,
            "seen_before_locked": not is_premium}


@check_bp.route("/check/qr", methods=["POST"])
@limiter.limit("30 per minute")
def api_check_qr():
    """ตรวจเนื้อหาที่ถอดได้จาก QR หนึ่งอัน (เบราว์เซอร์เป็นคนถอดภาพ -> ส่งมาแต่ข้อความ)"""
    data = request.get_json(silent=True) or {}
    payload = (data.get("payload") or "").strip()
    if not payload:
        return jsonify({"ok": False, "error": "ไม่พบเนื้อหาใน QR ที่ส่งมา"}), 400

    user, _ = _current_actor()
    thumb = _clean_thumb(data.get("thumb")) if (user is not None and user.is_premium) else None
    return jsonify(_analyze_qr_payload(payload, user, thumb=thumb))


@check_bp.route("/check/qr/bulk", methods=["POST"])
@limiter.limit("5 per minute")
def api_check_qr_bulk():
    """ตรวจ QR หลายอันพร้อมกัน (พรีเมียมเท่านั้น) — เบราว์เซอร์ถอดหลายรูป/หลาย QR มาให้แล้ว"""
    user, _ = _current_actor()
    if user is None or not user.is_premium:
        return jsonify({"ok": False, "error": "การสแกน QR หลายอันพร้อมกันใช้ได้เฉพาะสมาชิกพรีเมียม"}), 403

    data = request.get_json(silent=True) or {}
    items = data.get("items") or []
    max_items = current_app.config["BULK_CHECK_MAX_URLS"]
    if not isinstance(items, list) or not items:
        return jsonify({"ok": False, "error": "กรุณาส่งรายการ QR อย่างน้อย 1 รายการ"}), 400
    if len(items) > max_items:
        return jsonify({"ok": False, "error": f"ตรวจได้ครั้งละไม่เกิน {max_items} รายการ"}), 400

    results = []
    for item in items:
        if not isinstance(item, dict):
            continue
        payload = (item.get("payload") or "").strip()
        if not payload:
            continue
        results.append({
            "name": str(item.get("name") or "")[:120],
            **_analyze_qr_payload(payload, user, thumb=_clean_thumb(item.get("thumb"))),
        })

    if not results:
        return jsonify({"ok": False, "error": "ไม่พบเนื้อหา QR ที่ใช้ตรวจได้ในรายการที่ส่งมา"}), 400
    return jsonify({"ok": True, "results": results})


@check_bp.route("/check/bulk", methods=["POST"])
@limiter.limit("5 per minute")
def api_check_bulk():
    user, _ = _current_actor()
    if user is None or not user.is_premium:
        return jsonify({"ok": False, "error": "ฟีเจอร์เช็คแบบ bulk ใช้ได้เฉพาะสมาชิกพรีเมียม"}), 403

    data = request.get_json(silent=True) or {}
    urls = [u.strip() for u in (data.get("urls") or []) if isinstance(u, str) and u.strip()]
    max_urls = current_app.config["BULK_CHECK_MAX_URLS"]
    if not urls:
        return jsonify({"ok": False, "error": "กรุณาส่งรายการลิงก์อย่างน้อย 1 ลิงก์"}), 400
    if len(urls) > max_urls:
        return jsonify({"ok": False, "error": f"เช็คได้ครั้งละไม่เกิน {max_urls} ลิงก์"}), 400

    results = []
    for u in urls:
        r = scan(u, run_deep=True)
        _save_history(user, r, True)
        results.append(r)

    return jsonify({"ok": True, "results": results})


@check_bp.route("/history", methods=["GET"])
def api_history():
    if not current_user.is_authenticated:
        return jsonify({"ok": False, "error": "กรุณาล็อกอินก่อน"}), 401
    page_size = 50
    rows = (current_user.history.order_by(ScanHistory.created_at.desc())
            .limit(page_size).all())
    return jsonify({"ok": True, "history": [r.to_dict() for r in rows]})


@check_bp.route("/history/export", methods=["GET"])
def api_history_export():
    if not current_user.is_authenticated:
        return jsonify({"ok": False, "error": "กรุณาล็อกอินก่อน"}), 401
    if not current_user.is_premium:
        return jsonify({"ok": False, "error": "การ export ประวัติใช้ได้เฉพาะสมาชิกพรีเมียม"}), 403

    rows = current_user.history.order_by(ScanHistory.created_at.desc()).all()
    buf = io.StringIO()
    writer = csv.writer(buf)
    # ไม่ใส่ qr_thumb ลง CSV เพราะเป็นรูป base64 ยาวมาก เปิดใน Excel แล้วอ่านไม่รู้เรื่อง
    writer.writerow(["url", "verdict_color", "verdict_label", "ran_deep_check",
                      "source", "qr_type", "created_at"])
    for r in rows:
        writer.writerow([r.url, r.verdict_color, r.verdict_label, r.ran_deep_check,
                          r.source or "link", r.qr_type or "", r.created_at.isoformat()])

    return Response(buf.getvalue(), mimetype="text/csv", headers={
        "Content-Disposition": "attachment; filename=scan_history.csv"})


@check_bp.route("/health")
def health():
    return jsonify({"ok": True, "service": "phishing-link-checker"})

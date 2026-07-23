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


def _save_history(user, result: dict, ran_deep: bool) -> None:
    if user is None or not result.get("ok"):
        return
    verdict = result.get("verdict", {})
    db.session.add(ScanHistory(
        user_id=user.id, url=result.get("input", ""),
        verdict_color=verdict.get("color", ""), verdict_label=verdict.get("label", ""),
        ran_deep_check=ran_deep,
    ))
    db.session.commit()


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
    writer.writerow(["url", "verdict_color", "verdict_label", "ran_deep_check", "created_at"])
    for r in rows:
        writer.writerow([r.url, r.verdict_color, r.verdict_label, r.ran_deep_check,
                          r.created_at.isoformat()])

    return Response(buf.getvalue(), mimetype="text/csv", headers={
        "Content-Disposition": "attachment; filename=scan_history.csv"})


@check_bp.route("/health")
def health():
    return jsonify({"ok": True, "service": "phishing-link-checker"})

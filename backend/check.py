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
from concurrent.futures import ThreadPoolExecutor

from flask import Blueprint, request, jsonify, current_app, Response
from flask_login import current_user

import anon_quota
import jobs
from extensions import db, limiter
from models import ApiKey, ScanHistory, User
from analyzer import scan, scan_cache
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
        # ไม่ล็อกอินก็ตรวจเชิงลึกได้ แต่จำกัดต่อวันต่อ IP (เหตุผลใน anon_quota.py)
        # หมายเหตุ: สาขานี้ถูกเรียกเฉพาะใน request จริงเสมอ (งาน bulk เบื้องหลัง
        # เป็นของสมาชิกพรีเมียมเท่านั้น user ไม่มีทางเป็น None ที่นั่น)
        if anon_quota.allow(request.remote_addr):
            return True, None
        return False, "anon_quota_exhausted"
    limit = current_app.config["FREE_DEEP_CHECKS_PER_DAY"]
    if user.can_run_deep_check(limit):
        return True, None
    return False, "quota_exhausted"


def _locked_deep_check_payload(locked_reason: str) -> dict:
    """ก้อน deep_check ที่บอกผู้ใช้ว่าการตรวจเชิงลึกถูกล็อกเพราะอะไร + ทางไปต่อ
    (รวมไว้ที่เดียว — เดิมข้อความชุดนี้ถูกก๊อปไว้สองที่ใน api_check และ QR)"""
    limit = current_app.config["FREE_DEEP_CHECKS_PER_DAY"]
    if locked_reason == "anon_quota_exhausted":
        msg = (f"ใช้สิทธิ์ตรวจเชิงลึกฟรีแบบไม่ล็อกอิน {anon_quota.LIMIT} ครั้ง/วันครบแล้ว "
               f"สมัครสมาชิกฟรีเพื่อได้ {limit} ครั้ง/วัน")
    elif locked_reason == "login_required":
        # เกิดได้เมื่อปิดโควตาผู้ไม่ล็อกอิน (ANON_DEEP_CHECKS_PER_DAY=0)
        msg = ("สมัครสมาชิกฟรีเพื่อปลดล็อกการตรวจเชิงลึก (ตาม redirect, "
               "อายุโดเมน, SSL, เนื้อหาเว็บจริง)")
    else:
        msg = (f"ใช้โควตาการตรวจเชิงลึกฟรี {limit} ครั้ง/วันหมดแล้ว "
               "อัพเกรดเป็นพรีเมียมเพื่อตรวจเชิงลึกไม่จำกัด")
    return {"ran": False, "locked_reason": locked_reason, "message": msg}


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

    if run_deep:
        if user is not None:
            user.record_deep_check()
            db.session.commit()
        else:
            anon_quota.record(request.remote_addr)
    _save_history(user, result, run_deep)

    if locked_reason:
        result["deep_check"] = _locked_deep_check_payload(locked_reason)
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
            if run_deep:
                if user is not None:
                    user.record_deep_check()
                    db.session.commit()
                else:
                    # ถึงตรงนี้ได้เฉพาะจาก /api/check/qr (มี request จริงเสมอ) —
                    # งาน bulk เบื้องหลังเป็นของพรีเมียม user ไม่มีทางเป็น None
                    anon_quota.record(request.remote_addr)
            if locked_reason:
                scan_result["deep_check"] = _locked_deep_check_payload(locked_reason)
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


def _premium_gate(error_message: str):
    """ด่านเดียวกันของทุก endpoint แบบ bulk คืน (user, error_response)"""
    user, _ = _current_actor()
    if user is None or not user.is_premium:
        return None, (jsonify({"ok": False, "error": error_message}), 403)
    return user, None


def _accepted(job_id: str, total: int):
    """ตอบกลับแบบเดียวกันของทุกงาน bulk: รับงานแล้ว ไปถามความคืบหน้าที่ poll_url"""
    return jsonify({
        "ok": True, "job_id": job_id, "total": total, "state": "queued",
        "poll_url": f"/api/check/bulk/{job_id}",
    }), 202


@check_bp.route("/check/qr/bulk", methods=["POST"])
@limiter.limit("5 per minute")
def api_check_qr_bulk():
    """ตรวจ QR หลายอันพร้อมกัน (พรีเมียมเท่านั้น) — เบราว์เซอร์ถอดหลายรูป/หลาย QR มาให้แล้ว

    ตอบ 202 + job_id ทันที แล้วให้หน้าเว็บถามความคืบหน้าที่ /api/check/bulk/<job_id>
    """
    user, err = _premium_gate("การสแกน QR หลายอันพร้อมกันใช้ได้เฉพาะสมาชิกพรีเมียม")
    if err:
        return err

    data = request.get_json(silent=True) or {}
    items = data.get("items") or []
    max_items = current_app.config["BULK_CHECK_MAX_URLS"]
    if not isinstance(items, list) or not items:
        return jsonify({"ok": False, "error": "กรุณาส่งรายการ QR อย่างน้อย 1 รายการ"}), 400
    if len(items) > max_items:
        return jsonify({"ok": False, "error": f"ตรวจได้ครั้งละไม่เกิน {max_items} รายการ"}), 400

    # แกะข้อมูลที่ต้องใช้ออกมาให้ครบตั้งแต่ตอนนี้ เพราะในเธรดเบื้องหลังไม่มี request แล้ว
    prepared = []
    for item in items:
        if not isinstance(item, dict):
            continue
        payload = (item.get("payload") or "").strip()
        if not payload:
            continue
        prepared.append({"name": str(item.get("name") or "")[:120], "payload": payload,
                         "thumb": _clean_thumb(item.get("thumb"))})
    if not prepared:
        return jsonify({"ok": False, "error": "ไม่พบเนื้อหา QR ที่ใช้ตรวจได้ในรายการที่ส่งมา"}), 400

    user_id = user.id

    def work(report):
        # โหลด user ใหม่ในเธรดนี้ ไม่ส่ง object ข้ามเธรดเพราะผูกกับ session ของเธรดเดิม
        job_user = db.session.get(User, user_id)
        results = []
        for item in prepared:
            # ทำทีละอันตามลำดับ ไม่ขนาน เพราะ _analyze_qr_payload เขียนประวัติลง DB
            # ระหว่างทาง ซึ่ง session ของ SQLAlchemy ใช้ข้ามเธรดไม่ได้
            results.append({
                "name": item["name"],
                **_analyze_qr_payload(item["payload"], job_user, thumb=item["thumb"]),
            })
            report()
        return results

    job_id = jobs.submit(current_app._get_current_object(), user_id, len(prepared), work)
    return _accepted(job_id, len(prepared))


@check_bp.route("/check/bulk", methods=["POST"])
@limiter.limit("5 per minute")
def api_check_bulk():
    """ตรวจหลายลิงก์พร้อมกัน (พรีเมียมเท่านั้น) — ตอบ 202 + job_id ทันที

    เดิม endpoint นี้ตรวจให้จบก่อนแล้วค่อยตอบ ซึ่งยึด worker thread ของ waitress ไว้
    ได้นานถึงราว 8 วินาที ทำให้คนอื่นทั้งเว็บรอตาม ตอนนี้งานย้ายไปทำเบื้องหลัง (jobs.py)
    """
    user, err = _premium_gate("ฟีเจอร์เช็คแบบ bulk ใช้ได้เฉพาะสมาชิกพรีเมียม")
    if err:
        return err

    data = request.get_json(silent=True) or {}
    urls = [u.strip() for u in (data.get("urls") or []) if isinstance(u, str) and u.strip()]
    max_urls = current_app.config["BULK_CHECK_MAX_URLS"]
    if not urls:
        return jsonify({"ok": False, "error": "กรุณาส่งรายการลิงก์อย่างน้อย 1 ลิงก์"}), 400
    if len(urls) > max_urls:
        return jsonify({"ok": False, "error": f"เช็คได้ครั้งละไม่เกิน {max_urls} ลิงก์"}), 400

    workers = max(1, min(current_app.config["BULK_CHECK_WORKERS"], len(urls)))
    logger = current_app.logger
    user_id = user.id

    def work(report):
        def scan_one(u: str) -> dict:
            try:
                return scan(u, run_deep=True)
            except Exception as exc:  # ลิงก์เดียวพังต้องไม่ทำให้ทั้งชุดพัง
                logger.exception("bulk scan ล้มเหลวที่ลิงก์ %s", u)
                return {"ok": False, "input": u,
                        "error": f"ตรวจลิงก์นี้ไม่สำเร็จ ({type(exc).__name__})"}
            finally:
                report()

        # ยิงตรวจพร้อมกัน: งานนี้ "รอเน็ต" เป็นหลัก (DNS/redirect/SSL/โหลดหน้าเว็บ)
        # ไม่กิน CPU — pool.map คืนผลตามลำดับ input เสมอ ลำดับจึงไม่สลับ
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(scan_one, urls))

        # เขียนประวัติทีหลังในเธรดของงานนี้เธรดเดียว (db.session ใช้ข้ามเธรดไม่ได้)
        job_user = db.session.get(User, user_id)
        for r in results:
            _save_history(job_user, r, True)  # ข้ามรายการที่ ok=False ให้เองอยู่แล้ว
        return results

    job_id = jobs.submit(current_app._get_current_object(), user_id, len(urls), work)
    return _accepted(job_id, len(urls))


@check_bp.route("/check/bulk/<job_id>", methods=["GET"])
@limiter.limit("240 per minute")   # หน้าเว็บถามทุก ~1 วินาที ต้องไม่ชนลิมิตเอง
def api_check_bulk_status(job_id):
    """ถามความคืบหน้าของงาน bulk (ใช้ร่วมกันทั้งโหมดลิงก์และโหมด QR)

    state: queued -> running -> done | failed
    results จะเป็น null จนกว่า state จะเป็น done
    """
    user, _ = _current_actor()
    if user is None:
        return jsonify({"ok": False, "error": "กรุณาล็อกอินก่อน"}), 401

    job = jobs.get(job_id, user.id)
    if job is None:
        return jsonify({"ok": False, "error": "ไม่พบงานนี้ (อาจหมดอายุแล้ว) กรุณาตรวจใหม่"}), 404
    if job["state"] == "failed":
        return jsonify({"ok": False, "error": "ตรวจไม่สำเร็จ กรุณาลองใหม่", **job}), 500
    return jsonify({"ok": True, **job})


@check_bp.route("/history", methods=["GET"])
def api_history():
    # รองรับทั้ง session login และ API key ให้ตรงกับ /api/check — เดิมรับแต่ session
    # ทำให้ client ที่ถือ API key ตรวจลิงก์ได้แต่ดึงประวัติของตัวเองไม่ได้
    user, _ = _current_actor()
    if user is None:
        return jsonify({"ok": False, "error": "กรุณาล็อกอินก่อน"}), 401
    page_size = 50
    rows = (user.history.order_by(ScanHistory.created_at.desc())
            .limit(page_size).all())
    return jsonify({"ok": True, "history": [r.to_dict() for r in rows]})


@check_bp.route("/history/export", methods=["GET"])
def api_history_export():
    user, _ = _current_actor()
    if user is None:
        return jsonify({"ok": False, "error": "กรุณาล็อกอินก่อน"}), 401
    if not user.is_premium:
        return jsonify({"ok": False, "error": "การ export ประวัติใช้ได้เฉพาะสมาชิกพรีเมียม"}), 403

    rows = user.history.order_by(ScanHistory.created_at.desc()).all()
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
    """เช็กว่าเซิร์ฟเวอร์ยังอยู่ + ตัวเลขสุขภาพระบบ (ไม่มีข้อมูลผู้ใช้ จึงเปิดให้ทุกคนดูได้)"""
    return jsonify({"ok": True, "service": "phishing-link-checker",
                    "scan_cache": scan_cache.stats(), "bulk_jobs": jobs.stats(),
                    "anon_quota": anon_quota.stats()})

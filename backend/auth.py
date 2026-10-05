# -*- coding: utf-8 -*-
"""
auth.py
Blueprint ระบบสมัคร/ล็อกอิน — ใช้ session cookie (Flask-Login) ไม่ใช่ JWT
เพราะ frontend อยู่ origin เดียวกับ backend อยู่แล้ว (เสิร์ฟจาก Flask เดียวกัน)
session cookie แบบ httponly ปลอดภัยกว่าเก็บ token ใน localStorage (กัน XSS ขโมย token)
"""
import re

from flask import Blueprint, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf.csrf import generate_csrf

from extensions import db, login_manager, limiter
from models import User

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def _validate_credentials(email: str, password: str):
    if not email or not _EMAIL_RE.match(email):
        return "อีเมลไม่ถูกต้อง"
    if not password or len(password) < 8:
        return "รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร"
    return None


@auth_bp.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    err = _validate_credentials(email, password)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    # กัน Email Enumeration: ต้องไม่บอกว่าอีเมลนี้มีในระบบแล้วหรือยัง ไม่งั้นผู้โจมตี
    # ยิงอีเมลจำนวนมากเข้ามาแล้วดูจากคำตอบว่าใครเป็นสมาชิก (กวาดรายชื่อสมาชิกได้)
    # จึงตอบข้อความกลาง ๆ เหมือนกันทุกกรณี และไม่ auto-login (ผู้สมัครจริงไป login เอง)
    existing = User.query.filter_by(email=email).first()
    if existing is None:
        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
    # ถ้าอีเมลมีอยู่แล้ว ไม่ทำอะไร แต่ตอบเหมือนกรณีสมัครใหม่ทุกประการ
    return jsonify({
        "ok": True,
        "message": "หากอีเมลนี้ยังไม่เคยสมัคร ระบบได้สร้างบัญชีให้แล้ว "
                   "กรุณาเข้าสู่ระบบด้วยอีเมลและรหัสผ่านที่กรอก",
    })


@auth_bp.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"ok": False, "error": "อีเมลหรือรหัสผ่านไม่ถูกต้อง"}), 401

    login_user(user, remember=True)
    return jsonify({"ok": True, "user": user.to_public_dict()})


@auth_bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"ok": True})


@auth_bp.route("/me", methods=["GET"])
def me():
    if not current_user.is_authenticated:
        return jsonify({"ok": True, "user": None})
    return jsonify({"ok": True, "user": current_user.to_public_dict()})


@auth_bp.route("/csrf-token", methods=["GET"])
def csrf_token():
    """frontend เรียกครั้งแรกก่อนส่ง POST ใดๆ ที่ต้องใช้ session (login แล้ว) เสมอ
    แนบค่าที่ได้กลับมาในทุก POST ผ่าน header X-CSRFToken"""
    return jsonify({"ok": True, "csrf_token": generate_csrf()})

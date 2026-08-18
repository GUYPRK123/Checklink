# -*- coding: utf-8 -*-
"""
models.py
โครงสร้างฐานข้อมูล (SQLite ผ่าน SQLAlchemy)

User            บัญชีผู้ใช้ + สถานะแผน (free/premium)
ScanHistory     ประวัติการเช็คลิงก์ของผู้ใช้ที่ล็อกอิน (ไม่เก็บของ anonymous)
Payment         บันทึกการชำระเงิน "จำลอง" แต่ละครั้ง (ไม่ใช่ธุรกรรมจริง)
ApiKey          กุญแจสำหรับเรียก /api/check แบบโปรแกรม (เฉพาะพรีเมียม)
"""
import hashlib
import secrets
from datetime import datetime, date, timedelta

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from extensions import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    plan = db.Column(db.String(20), nullable=False, default="free")  # 'free' | 'premium'
    premium_until = db.Column(db.DateTime, nullable=True)

    # เลิกใช้แล้ว (เดิมคือตัวนับโควตาเช็คเชิงลึกรายวันของแผนฟรี — ตอนนี้การตรวจ
    # เชิงลึกเป็นของพรีเมียมทั้งหมด) คอลัมน์คงไว้เพราะฐานข้อมูลจริงมีอยู่แล้ว
    # และ SQLite ไม่มีระบบ migration ในโปรเจกต์นี้ — อย่าเอาไปใช้ต่อ
    deep_checks_today = db.Column(db.Integer, nullable=False, default=0)
    deep_checks_date = db.Column(db.Date, nullable=False, default=date.today)

    history = db.relationship("ScanHistory", backref="user", lazy="dynamic",
                               cascade="all, delete-orphan")
    payments = db.relationship("Payment", backref="user", lazy="dynamic",
                                cascade="all, delete-orphan")
    api_keys = db.relationship("ApiKey", backref="user", lazy="dynamic",
                                cascade="all, delete-orphan")

    def set_password(self, raw_password: str) -> None:
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)

    @property
    def is_premium(self) -> bool:
        return self.plan == "premium" and bool(self.premium_until) and self.premium_until > datetime.utcnow()

    def activate_premium(self, duration_days: int) -> None:
        now = datetime.utcnow()
        base = self.premium_until if (self.premium_until and self.premium_until > now) else now
        self.plan = "premium"
        self.premium_until = base + timedelta(days=duration_days)

    def to_public_dict(self) -> dict:
        return {
            "email": self.email,
            "plan": self.plan,
            "is_premium": self.is_premium,
            "premium_until": self.premium_until.isoformat() if self.premium_until else None,
        }


class ScanHistory(db.Model):
    __tablename__ = "scan_history"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    url = db.Column(db.Text, nullable=False)
    verdict_color = db.Column(db.String(10), nullable=False)
    verdict_label = db.Column(db.String(50), nullable=False)
    ran_deep_check = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # ---- ข้อมูลเสริมสำหรับรายการที่มาจากการสแกน QR ----
    source = db.Column(db.String(10), nullable=False, default="link")  # 'link' | 'qr'
    qr_type = db.Column(db.String(20), nullable=True)   # url/promptpay/wifi/tel/... (ดู analyzer/qr_payload.py)
    # ภาพย่อของ QR ที่สแกน เก็บเป็น data URI ขนาดเล็ก (ย่อจากฝั่งเบราว์เซอร์ก่อนส่งมาแล้ว)
    # เก็บลง DB ตรง ๆ เพราะภาพเล็กมากและทำให้ไม่ต้องจัดการไฟล์แยก/สิทธิ์การเข้าถึงไฟล์
    qr_thumb = db.Column(db.Text, nullable=True)

    # ความยาวสูงสุดของ data URI ที่ยอมรับ (กันไม่ให้ client ยัดภาพใหญ่มาถ่วง DB)
    MAX_THUMB_CHARS = 30_000

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "verdict_color": self.verdict_color,
            "verdict_label": self.verdict_label,
            "ran_deep_check": self.ran_deep_check,
            "created_at": self.created_at.isoformat(),
            "source": self.source or "link",
            "qr_type": self.qr_type,
            "qr_thumb": self.qr_thumb,
        }


class Payment(db.Model):
    __tablename__ = "payments"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    plan = db.Column(db.String(20), nullable=False, default="premium")
    method = db.Column(db.String(20), nullable=False)  # 'card' | 'promptpay'
    amount_thb = db.Column(db.Integer, nullable=False)
    fake_txn_id = db.Column(db.String(40), nullable=False, unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @staticmethod
    def new_fake_txn_id() -> str:
        return "DEMO-" + secrets.token_hex(8).upper()


class ApiKey(db.Model):
    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    key_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    key_prefix = db.Column(db.String(12), nullable=False)  # ไว้โชว์บางส่วนในหน้าเว็บ
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_used_at = db.Column(db.DateTime, nullable=True)
    revoked = db.Column(db.Boolean, nullable=False, default=False)

    @staticmethod
    def hash_key(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    @staticmethod
    def generate() -> tuple:
        """คืน (raw_key, key_hash, key_prefix) — raw_key ให้ผู้ใช้ครั้งเดียวตอนสร้าง เก็บแต่ hash"""
        raw_key = "pfk_" + secrets.token_urlsafe(32)
        return raw_key, ApiKey.hash_key(raw_key), raw_key[:12]

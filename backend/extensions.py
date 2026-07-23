# -*- coding: utf-8 -*-
"""
extensions.py
สร้าง instance กลางของ Flask extension ต่างๆ ไว้ที่นี่ที่เดียว (แยกจาก app.py)
เพื่อกันปัญหา circular import — ไฟล์ที่ต้องใช้ db/login_manager/csrf/limiter
ให้ import จากที่นี่ แล้วค่อยไป init_app(app) ใน create_app()
"""
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=[])

login_manager.login_view = None  # API-only: ไม่ redirect ไปหน้า login, คืน 401 แทน

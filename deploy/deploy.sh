#!/usr/bin/env bash
# ============================================================================
# deploy.sh — ขั้นตอน deploy หลังแก้โค้ดฝั่ง backend เสร็จ
#
# วิธีใช้ (จากที่ไหนก็ได้):
#   sudo /home/checkurl/Checklink/deploy/deploy.sh
#
# ดูว่าจะทำอะไรบ้างโดยไม่แตะของจริง:
#   DRY_RUN=1 /home/checkurl/Checklink/deploy/deploy.sh
#
# ------------------------------------------------------------
# กับดักที่สคริปต์นี้มีไว้กัน:
#
# systemd ตั้ง Restart=always ไว้ ซึ่งดีตอน process ตายเพราะเหตุสุดวิสัย แต่ถ้าโค้ดมี
# ปัญหาจน "สตาร์ตไม่ขึ้นเลย" (เช่นพิมพ์ผิด, .env ผิด, import พัง) มันจะวนรีสตาร์ตทุก 3
# วินาทีไม่รู้จบ และเว็บดับตลอดเวลานั้น
#
# สคริปต์จึง "ลอง import แอปดูก่อน" ในโปรเซสแยก ถ้า import ไม่ผ่านก็หยุดตั้งแต่ต้น
# โดยที่ service เดิมยังวิ่งอยู่ตามปกติ — ผู้ใช้ไม่รู้สึกอะไรเลย
# ============================================================================
set -euo pipefail

APP_DIR=/home/checkurl/Checklink/backend
PY="$APP_DIR/.venv/bin/python"
SERVICE=phishing-checker
SITE=https://checkurl.studiodup.com
BACKUP_DIR=/home/checkurl
# ผู้ใช้ที่เป็นเจ้าของฐานข้อมูล (ต้องตรงกับ User= ใน deploy/phishing-checker.service)
APP_USER=checkurl

# รันคำสั่งในนาม APP_USER เมื่อสคริปต์ถูกเรียกด้วย sudo — เหตุผลอยู่ที่ "กับดักของ WAL"
# ในขั้นที่ 4 ถ้าไม่ได้เป็น root อยู่ (เช่นตอน DRY_RUN=1 ที่รันในนามผู้ใช้เอง) ก็รันตรง ๆ
as_app_user() {
    if [ "$(id -u)" = "0" ]; then
        runuser -u "$APP_USER" -- "$@"
    else
        "$@"
    fi
}

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
fail() { printf '\033[31m!! %s\033[0m\n' "$1" >&2; exit 1; }

cd "$APP_DIR"

step "1/6 โค้ดที่กำลังจะ deploy"
git -c safe.directory=/home/checkurl/Checklink log --oneline -1 || true
if ! git -c safe.directory=/home/checkurl/Checklink diff --quiet 2>/dev/null; then
    echo "   (มีไฟล์ที่แก้แล้วแต่ยังไม่ commit — deploy ได้ แต่ถ้าพังจะย้อนกลับยาก)"
fi

step "2/6 รันเทสต์"
"$PY" -m pytest -q || fail "เทสต์ไม่ผ่าน — ยกเลิก deploy (service เดิมยังทำงานอยู่ตามปกติ)"

step "3/6 ลองโหลดแอปดูว่าสตาร์ตขึ้นไหม"
# WARMUP_URL="" เพื่อไม่ให้เสียเวลายิงเน็ตตอนทดสอบ import
if WARMUP_URL="" "$PY" -c "import app; print('   โหลดแอปสำเร็จ')" 2>&1 | tail -3; then
    :
else
    fail "แอปโหลดไม่ขึ้น — ยกเลิก deploy ก่อนที่จะทำให้เว็บดับ"
fi

step "4/6 สำรองฐานข้อมูล"
# ------------------------------------------------------------
# กับดักของ WAL (ฐานข้อมูลเปิด journal_mode=WAL ไว้ ดูเหตุผลใน backend/app.py)
#
# โหมด WAL ทำให้ฐานข้อมูลไม่ใช่ไฟล์เดียวอีกต่อไป: มี app.db-wal กับ app.db-shm มาด้วย
# และ SQLite "สร้างสองไฟล์นั้นให้เอง" ทันทีที่มีใครเปิดฐานข้อมูล ถ้าคนที่เปิดคือ root
# (เช่น deploy ตัวนี้) สองไฟล์นั้นจะกลายเป็นของ root แล้วแอปที่รันเป็น checkurl จะเขียน
# ฐานข้อมูลไม่ได้อีกเลย — อาการคือเว็บยังขึ้นปกติแต่สมัครสมาชิก/บันทึกประวัติพังทั้งระบบ
# จึงต้องสำรองในนาม checkurl เสมอ ห้ามแก้กลับเป็นให้ root เปิดฐานข้อมูลตรง ๆ
#
# ตัวสำรองใช้ Online Backup API ของ SQLite ซึ่งรวมข้อมูลที่ยังค้างใน -wal มาให้ครบ
# และปลอดภัยกับไฟล์ที่ service กำลังใช้อยู่ (ไม่ต้องหยุด service ก่อน)
# ------------------------------------------------------------
for WALFILE in "$APP_DIR/instance/app.db-wal" "$APP_DIR/instance/app.db-shm"; do
    [ -e "$WALFILE" ] || continue
    OWNER=$(stat -c %U "$WALFILE")
    [ "$OWNER" = "$APP_USER" ] && continue
    if [ "$(id -u)" = "0" ]; then
        chown "$APP_USER:$APP_USER" "$WALFILE"
        echo "   แก้เจ้าของ $(basename "$WALFILE") จาก $OWNER เป็น $APP_USER แล้ว"
    else
        fail "$(basename "$WALFILE") เป็นของ $OWNER ไม่ใช่ $APP_USER -> แอปเขียนฐานข้อมูลไม่ได้ (รันด้วย sudo เพื่อให้แก้ให้)"
    fi
done

BACKUP="$BACKUP_DIR/app.db.backup-$(date +%Y%m%d-%H%M%S)"
as_app_user "$PY" - "$BACKUP" <<'PY'
import sqlite3, sys
src = sqlite3.connect("instance/app.db")
dst = sqlite3.connect(sys.argv[1])
src.backup(dst)
dst.close(); src.close()
PY
echo "   $BACKUP"
# เก็บย้อนหลัง 10 ชุดพอ ที่เหลือลบทิ้งกันดิสก์เต็ม
ls -1t "$BACKUP_DIR"/app.db.backup-* 2>/dev/null | tail -n +11 | xargs -r rm --

step "5/6 รีสตาร์ต service"
if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "   (DRY_RUN — ข้ามการรีสตาร์ตจริง)"
else
    systemctl restart "$SERVICE"
    sleep 3
fi

step "6/6 ตรวจว่ากลับมาแล้วจริง"
if [ "${DRY_RUN:-0}" = "1" ]; then
    echo "   (DRY_RUN — ข้ามการตรวจ)"
    exit 0
fi
systemctl is-active --quiet "$SERVICE" || fail "service ไม่ทำงาน -> journalctl -u $SERVICE -n 50"

CODE=$(curl -s -o /dev/null -m 15 -w '%{http_code}' "$SITE/api/health")
[ "$CODE" = "200" ] || fail "เว็บตอบ HTTP $CODE -> journalctl -u $SERVICE -n 50"

# NRestarts เพิ่มขึ้นเรื่อย ๆ = สตาร์ตไม่ขึ้นแล้ววนรีสตาร์ต (อาการที่ร้ายที่สุด)
R1=$(systemctl show "$SERVICE" -p NRestarts --value); sleep 5
R2=$(systemctl show "$SERVICE" -p NRestarts --value)
[ "$R1" = "$R2" ] || fail "service วนรีสตาร์ตอยู่ ($R1 -> $R2) -> journalctl -u $SERVICE -n 50"

printf '\n\033[32m✓ deploy สำเร็จ\033[0m  %s ตอบ 200 และ service นิ่งดี\n' "$SITE"
echo "  ถ้าพบปัญหาทีหลัง ย้อนกลับด้วย:"
echo "    cd /home/checkurl/Checklink && git -c safe.directory=\$PWD reset --hard <commit เดิม>"
echo "  เฉพาะกรณีข้อมูลเสียหาย — ต้องหยุด service ก่อน และลบ WAL เก่าทิ้งด้วย ไม่งั้นข้อมูล"
echo "  ที่ค้างอยู่ใน app.db-wal จะถูกเล่นซ้ำทับไฟล์ที่กู้มา:"
echo "    sudo systemctl stop $SERVICE"
echo "    sudo rm -f $APP_DIR/instance/app.db-wal $APP_DIR/instance/app.db-shm"
echo "    sudo runuser -u $APP_USER -- cp $BACKUP $APP_DIR/instance/app.db"
echo "    sudo systemctl start $SERVICE"

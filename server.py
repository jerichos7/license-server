# server.py
# Minimal real-time license server (Flask + Flask-SocketIO)
import os, time, sqlite3, threading, jwt
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room

JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-please")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "change-admin-token")
DB_PATH = os.environ.get("DB_PATH", "licenses.db")
EXPIRE_CHECK_INTERVAL = int(os.environ.get("EXPIRE_CHECK_INTERVAL", "5"))

app = Flask(__name__)
app.config["SECRET_KEY"] = JWT_SECRET
socketio = SocketIO(app, cors_allowed_origins="*")

def now_ts(): return int(time.time())

def db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    c = db()
    c.execute("""CREATE TABLE IF NOT EXISTS licenses(
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        expire_ts INTEGER NOT NULL,
        hwid_lock INTEGER NOT NULL DEFAULT 1,
        hwid TEXT,
        active INTEGER NOT NULL DEFAULT 1
    )""")
    c.commit(); c.close()
init_db()

def require_admin(req):
    tok = req.headers.get("Authorization", "").replace("Bearer ","").strip()
    return tok == ADMIN_TOKEN

@app.post("/admin/add_license")
def admin_add():
    if not require_admin(request):
        return jsonify({"ok": False, "err": "unauthorized"}), 401
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password_hash = data.get("password_hash")
    expire_date_iso = data.get("expire_date")
    hwid_lock = 1 if data.get("hwid_lock", True) else 0
    active = 1 if data.get("active", True) else 0
    if not username or not password_hash or not expire_date_iso:
        return jsonify({"ok": False, "err": "missing_fields"}), 400
    try:
        expire_ts = int(datetime.fromisoformat(expire_date_iso).replace(tzinfo=timezone.utc).timestamp())
    except Exception:
        try:
            expire_ts = int(datetime.fromisoformat(expire_date_iso).timestamp())
        except Exception:
            return jsonify({"ok": False, "err": "bad_expire_date"}), 400
    conn = db()
    conn.execute("""INSERT INTO licenses(username,password_hash,expire_ts,hwid_lock,active)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(username) DO UPDATE SET
                     password_hash=excluded.password_hash,
                     expire_ts=excluded.expire_ts,
                     hwid_lock=excluded.hwid_lock,
                     active=excluded.active
                """, (username, password_hash, expire_ts, hwid_lock, active))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.post("/admin/revoke")
def admin_revoke():
    if not require_admin(request):
        return jsonify({"ok": False, "err": "unauthorized"}), 401
    data = request.json or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"ok": False, "err": "missing_username"}), 400
    conn = db()
    conn.execute("UPDATE licenses SET active=0 WHERE username=?", (username,))
    conn.commit(); conn.close()
    socketio.emit("revoked", {"username": username, "reason": "admin"}, room=f"user:{username}")
    return jsonify({"ok": True})

@app.post("/admin/reset_hwid")
def admin_reset_hwid():
    if not require_admin(request):
        return jsonify({"ok": False, "err": "unauthorized"}), 401
    data = request.json or {}
    username = (data.get("username") or "").strip()
    if not username:
        return jsonify({"ok": False, "err": "missing_username"}), 400
    conn = db()
    conn.execute("UPDATE licenses SET hwid=NULL WHERE username=?", (username,))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.post("/auth")
def auth():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password_hash = data.get("password")
    hwid = (data.get("hwid") or "").strip()
    if not username or not password_hash:
        return jsonify({"ok": False, "err": "missing_fields"}), 400
    row = db().execute("SELECT * FROM licenses WHERE username=?", (username,)).fetchone()
    if not row:
        return jsonify({"ok": False, "err": "not_found"}), 401
    if row["password_hash"] != password_hash:
        return jsonify({"ok": False, "err": "bad_credentials"}), 401
    if row["active"] == 0:
        return jsonify({"ok": False, "err": "revoked"}), 403
    if row["expire_ts"] < now_ts():
        return jsonify({"ok": False, "err": "expired"}), 403
    if row["hwid_lock"] and row["hwid"] and row["hwid"] != hwid:
        return jsonify({"ok": False, "err": "hwid_mismatch"}), 403
    if row["hwid_lock"] and (row["hwid"] is None or row["hwid"] == "") and hwid:
        conn = db()
        conn.execute("UPDATE licenses SET hwid=? WHERE username=?", (hwid, username))
        conn.commit(); conn.close()
    payload = {"sub": username, "iat": now_ts(), "exp": now_ts() + 600}
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return jsonify({"ok": True, "token": token, "expire_ts": row["expire_ts"]})

@socketio.on("connect")
def on_connect(auth):
    try:
        environ = request.environ
        authz = environ.get("HTTP_AUTHORIZATION", "")
        token = authz.replace("Bearer ","").strip()
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        username = payload["sub"]
    except Exception:
        return False
    row = db().execute("SELECT active, expire_ts FROM licenses WHERE username=?", (username,)).fetchone()
    if not row or row["active"] == 0 or row["expire_ts"] < now_ts():
        return False
    join_room(f"user:{username}")
    emit("ok", {"msg": "connected", "user": username})

def expire_watcher():
    while True:
        try:
            conn = db()
            ts = now_ts()
            rows = conn.execute("SELECT username FROM licenses WHERE expire_ts <= ? AND active=1", (ts,)).fetchall()
            for r in rows:
                u = r["username"]
                conn.execute("UPDATE licenses SET active=0 WHERE username=?", (u,))
                socketio.emit("expired", {"username": u}, room=f"user:{u}")
            conn.commit(); conn.close()
        except Exception as e:
            print("expire_watcher error:", e)
        time.sleep(EXPIRE_CHECK_INTERVAL)

threading.Thread(target=expire_watcher, daemon=True).start()

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)

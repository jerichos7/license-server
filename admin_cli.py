# admin_cli.py
import os, requests, hashlib
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN","change-admin-token")
BASE = os.environ.get("BASE","http://127.0.0.1:5000")
def sha256(s): return hashlib.sha256(s.encode()).hexdigest()
def add(username, password_plain, expire_iso, hwid_lock=True, active=True):
    payload = {
        "username": username,
        "password_hash": sha256(password_plain),
        "expire_date": expire_iso,
        "hwid_lock": hwid_lock,
        "active": active
    }
    r = requests.post(f"{BASE}/admin/add_license", json=payload, headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    print("ADD:", r.status_code, r.text)
def revoke(username):
    r = requests.post(f"{BASE}/admin/revoke", json={"username": username}, headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    print("REVOKE:", r.status_code, r.text)
def reset_hwid(username):
    r = requests.post(f"{BASE}/admin/reset_hwid", json={"username": username}, headers={"Authorization": f"Bearer {ADMIN_TOKEN}"})
    print("RESET HWID:", r.status_code, r.text)

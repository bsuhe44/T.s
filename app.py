#!/usr/bin/env python3
"""SIWANKURDSH - Telegram MTProto proxy panel.

Manages users of alexbers/mtprotoproxy: per-user secret, data quota,
expiry date and connection limit. The panel rewrites the proxy config.py
and restarts the proxy whenever the set of allowed users changes.
"""
import hmac
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from functools import wraps

from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.environ.get("DATA_DIR", os.path.join(BASE, "data"))
os.makedirs(DATA, exist_ok=True)
DB_PATH = os.path.join(DATA, "panel.db")

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "")
SERVER_HOST = os.environ.get("SERVER_HOST", "")
PROXY_PORT = int(os.environ.get("PROXY_PORT", "443"))
TLS_DOMAIN = os.environ.get("TLS_DOMAIN", "www.google.com")
PROXY_DIR = os.environ.get("PROXY_DIR", "/opt/mtprotoproxy")
PROXY_SERVICE = os.environ.get("PROXY_SERVICE", "mtprotoproxy")
METRICS_PORT = int(os.environ.get("METRICS_PORT", "9100"))
PANEL_PORT = int(os.environ.get("PANEL_PORT") or os.environ.get("PORT") or 8080)
# port shown in links (Railway TCP proxy gives a different public port)
PUBLIC_PORT = int(os.environ.get("PUBLIC_PROXY_PORT") or PROXY_PORT)
# "systemd" (VPS) or "process" (Docker / Railway: panel starts the proxy itself)
PROXY_MODE = os.environ.get("PROXY_MODE", "systemd")
DRY_RUN = os.environ.get("DRY_RUN") == "1"  # do not call systemctl (for testing)
SYNC_INTERVAL = 15

GB = 1024 ** 3
METRIC_RE = re.compile(
    r'mtproxy_user_octets_(?:from|to)_client\{user="([^"]+)"\}\s+([0-9.eE+-]+)'
)

app = Flask(__name__)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

_key_path = os.path.join(DATA, "secret.key")
if not os.path.exists(_key_path):
    with open(_key_path, "w") as f:
        f.write(secrets.token_hex(32))
    os.chmod(_key_path, 0o600)
app.secret_key = open(_key_path).read().strip()

_lock = threading.RLock()
_state = {"proxy_up": False}


# ------------------------------------------------------------ embedded pages
LOGIN_HTML = """<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIWANKURDSH - ورود</title>
<style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0f1419;color:#e6e9ee;font-family:Tahoma,system-ui,sans-serif}
.card{width:100%;max-width:340px;background:#1a212b;border:1px solid #2a3340;border-radius:14px;padding:28px}
h1{margin:0 0 20px;font-size:20px;text-align:center;letter-spacing:1px}
input{width:100%;padding:11px 12px;margin-bottom:12px;background:#0f1419;border:1px solid #2a3340;border-radius:8px;color:#e6e9ee;font-size:15px}
input:focus{outline:none;border-color:#3b82f6}
button{width:100%;padding:11px;background:#3b82f6;border:0;border-radius:8px;color:#fff;font-size:15px;cursor:pointer}
.err{background:#3a1d1d;color:#ffb4b4;padding:9px 11px;border-radius:8px;margin-bottom:12px;font-size:13px}
</style></head><body>
<form class="card" method="post">
<h1>SIWANKURDSH</h1>
{% if error %}<div class="err">{{ error }}</div>{% endif %}
<input name="username" placeholder="نام کاربری" autocomplete="username" required autofocus dir="ltr">
<input name="password" type="password" placeholder="رمز عبور" autocomplete="current-password" required dir="ltr">
<button type="submit">ورود</button>
</form></body></html>"""

PANEL_HTML = """<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SIWANKURDSH</title>
<style>
*{box-sizing:border-box}
body{margin:0;background:#0f1419;color:#e6e9ee;font-family:Tahoma,system-ui,sans-serif;font-size:14px}
header{display:flex;justify-content:space-between;align-items:center;padding:14px 18px;background:#1a212b;border-bottom:1px solid #2a3340}
header h1{margin:0;font-size:17px;letter-spacing:1px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:#ef4444;margin-left:6px}
.dot.up{background:#22c55e}
a{color:#7aa7ff;text-decoration:none}
main{max-width:980px;margin:0 auto;padding:16px}
.box{background:#1a212b;border:1px solid #2a3340;border-radius:12px;padding:16px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
label{display:block;font-size:12px;color:#9aa6b5;margin-bottom:4px}
input{width:100%;padding:9px 10px;background:#0f1419;border:1px solid #2a3340;border-radius:8px;color:#e6e9ee;font-size:14px}
input:focus{outline:none;border-color:#3b82f6}
button{padding:8px 12px;background:#3b82f6;border:0;border-radius:8px;color:#fff;font-size:13px;cursor:pointer}
button.g{background:#2a3340}button.r{background:#b91c1c}
.row{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
.user{border:1px solid #2a3340;border-radius:10px;padding:12px;margin-bottom:10px;background:#141a22}
.top{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}
.name{font-weight:bold;font-size:15px}
.badge{padding:2px 9px;border-radius:99px;font-size:12px}
.active{background:#14532d;color:#86efac}.disabled{background:#374151;color:#d1d5db}
.expired{background:#7c2d12;color:#fdba74}.limited{background:#7f1d1d;color:#fca5a5}
.bar{height:7px;background:#0f1419;border-radius:99px;overflow:hidden;margin:9px 0 5px}
.bar>div{height:100%;background:#3b82f6}
.meta{color:#9aa6b5;font-size:12px;display:flex;gap:14px;flex-wrap:wrap}
.note{color:#9aa6b5;font-size:12px;margin-top:4px}
.empty{text-align:center;color:#9aa6b5;padding:24px}
#toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#22c55e;color:#04210f;padding:9px 16px;border-radius:8px;display:none;font-size:13px}
#toast.e{background:#ef4444;color:#fff}
</style></head><body>
<header><h1>SIWANKURDSH</h1>
<div><span id="st" class="dot"></span><span id="stt">پروکسی</span> &nbsp;|&nbsp; <a href="/logout">خروج</a></div></header>
<main>
<div class="box"><b>ساخت کاربر جدید</b>
<div class="grid" style="margin-top:10px">
<div><label>نام</label><input id="n_name"></div>
<div><label>حجم (GB) - 0 = نامحدود</label><input id="n_quota" type="number" min="0" step="any" value="0"></div>
<div><label>انقضا (روز) - 0 = نامحدود</label><input id="n_days" type="number" min="0" step="any" value="0"></div>
<div><label>اتصال همزمان - 0 = نامحدود</label><input id="n_conns" type="number" min="0" value="0"></div>
<div><label>یادداشت</label><input id="n_note"></div>
</div>
<div class="row"><button onclick="createUser()">ساخت کاربر</button></div></div>
<div id="list"></div>
</main><div id="toast"></div>
<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ST={active:'فعال',disabled:'غیرفعال',expired:'منقضی',limited:'حجم تمام'};
let USERS=[];
function toast(m,e){const t=$('toast');t.textContent=m;t.className=e?'e':'';t.style.display='block';setTimeout(()=>t.style.display='none',2200)}
async function api(url,method,body){
  const r=await fetch(url,{method:method||'GET',headers:{'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined});
  if(r.status===401){location='/login';return null}
  const d=await r.json().catch(()=>({}));
  if(!r.ok){toast(d.error||'خطا',true);return null}
  return d}
function fmt(b){const u=['B','KB','MB','GB','TB'];let i=0;b=Number(b);while(b>=1024&&i<4){b/=1024;i++}return b.toFixed(i?2:0)+' '+u[i]}
function exp(t){if(!t)return 'بدون انقضا';const d=Math.ceil((t*1000-Date.now())/864e5);return d>0?d+' روز مانده':'منقضی شده'}
async function load(){
  const d=await api('/api/users');if(!d)return;
  USERS=d.users;$('st').className='dot'+(d.proxy_up?' up':'');
  $('stt').textContent=d.proxy_up?'پروکسی روشن':'پروکسی خاموش';
  const l=$('list');
  if(!USERS.length){l.innerHTML='<div class="empty">هنوز کاربری ساخته نشده</div>';return}
  l.innerHTML=USERS.map(u=>{
    const p=u.quota_bytes?Math.min(100,u.used_bytes/u.quota_bytes*100):0;
    return `<div class="user"><div class="top"><span class="name">${esc(u.name)}</span>
<span class="badge ${u.status}">${ST[u.status]}</span></div>
<div class="bar"><div style="width:${p}%"></div></div>
<div class="meta"><span>مصرف: ${fmt(u.used_bytes)} / ${u.quota_bytes?fmt(u.quota_bytes):'نامحدود'}</span>
<span>${exp(u.expire_at)}</span><span>اتصال: ${u.max_conns||'نامحدود'}</span></div>
${u.note?`<div class="note">${esc(u.note)}</div>`:''}
<div class="row">
<button onclick="cp(${u.id},'tg_link')">کپی لینک tg</button>
<button class="g" onclick="cp(${u.id},'web_link')">کپی لینک t.me</button>
<button class="g" onclick="edit(${u.id})">ویرایش</button>
<button class="g" onclick="toggle(${u.id},${!u.enabled})">${u.enabled?'غیرفعال':'فعال'}</button>
<button class="g" onclick="resetU(${u.id})">ریست مصرف</button>
<button class="r" onclick="del(${u.id})">حذف</button></div></div>`}).join('')}
async function createUser(){
  const d=await api('/api/users','POST',{name:$('n_name').value,quota_gb:$('n_quota').value,
    expire_days:$('n_days').value,max_conns:$('n_conns').value,note:$('n_note').value});
  if(d){toast('ساخته شد');$('n_name').value='';$('n_note').value='';load()}}
function cp(id,k){
  const u=USERS.find(x=>x.id===id),t=u[k];
  (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(()=>toast('کپی شد'),()=>prompt('لینک را کپی کنید:',t))}
async function edit(id){
  const u=USERS.find(x=>x.id===id);
  const q=prompt('حجم (GB) - 0 = نامحدود',u.quota_bytes/1073741824);if(q===null)return;
  const d=prompt('انقضا از امروز (روز) - 0 = نامحدود، خالی = بدون تغییر','');if(d===null)return;
  const c=prompt('اتصال همزمان - 0 = نامحدود',u.max_conns);if(c===null)return;
  const body={quota_gb:q,max_conns:c};if(d!=='')body.expire_days=d;
  if(await api('/api/users/'+id,'PATCH',body)){toast('ذخیره شد');load()}}
async function toggle(id,en){if(await api('/api/users/'+id,'PATCH',{enabled:en}))load()}
async function resetU(id){if(confirm('مصرف صفر شود؟')&&await api('/api/users/'+id+'/reset','POST'))load()}
async function del(id){if(confirm('کاربر حذف شود؟')&&await api('/api/users/'+id,'DELETE'))load()}
load();setInterval(load,15000);
</script></body></html>"""


# ---------------------------------------------------------------- database
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                secret TEXT NOT NULL,
                quota_bytes INTEGER NOT NULL DEFAULT 0,
                used_bytes INTEGER NOT NULL DEFAULT 0,
                last_raw REAL NOT NULL DEFAULT 0,
                expire_at INTEGER NOT NULL DEFAULT 0,
                max_conns INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                note TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            )"""
        )


def status_of(u):
    if not u["enabled"]:
        return "disabled"
    if u["expire_at"] and time.time() >= u["expire_at"]:
        return "expired"
    if u["quota_bytes"] and u["used_bytes"] >= u["quota_bytes"]:
        return "limited"
    return "active"


# ------------------------------------------------------------ proxy control
def poll_usage(conn):
    """Read proxy metrics and add the traffic delta to each user."""
    try:
        url = f"http://127.0.0.1:{METRICS_PORT}/metrics"
        text = urllib.request.urlopen(url, timeout=3).read().decode()
    except Exception:
        _state["proxy_up"] = False
        return False
    _state["proxy_up"] = True
    totals = {}
    for m in METRIC_RE.finditer(text):
        totals[m.group(1)] = totals.get(m.group(1), 0.0) + float(m.group(2))
    for name, raw in totals.items():
        if not re.fullmatch(r"u\d+", name):
            continue
        row = conn.execute(
            "SELECT used_bytes,last_raw FROM users WHERE id=?", (int(name[1:]),)
        ).fetchone()
        if not row:
            continue
        # proxy counters restart from zero when the proxy restarts
        delta = raw - row["last_raw"] if raw >= row["last_raw"] else raw
        conn.execute(
            "UPDATE users SET used_bytes=?, last_raw=? WHERE id=?",
            (row["used_bytes"] + int(delta), raw, int(name[1:])),
        )
    conn.commit()
    return True


def build_config(conn):
    rows = conn.execute("SELECT * FROM users ORDER BY id").fetchall()
    active = [r for r in rows if status_of(r) == "active"]
    users = {f"u{r['id']}": r["secret"] for r in active} or {"idle": "00" * 16}
    conns = {f"u{r['id']}": r["max_conns"] for r in active if r["max_conns"] > 0}
    lines = [
        "# Generated by SIWANKURDSH panel - do not edit by hand",
        f"PORT = {PROXY_PORT}",
        f"USERS = {json.dumps(users, indent=4)}",
        'MODES = {"classic": False, "secure": False, "tls": True}',
        f"TLS_DOMAIN = {json.dumps(TLS_DOMAIN)}",
        f"USER_MAX_TCP_CONNS = {json.dumps(conns)}",
        f"METRICS_PORT = {METRICS_PORT}",
        'METRICS_LISTEN_ADDR_IPV4 = "127.0.0.1"',
        'METRICS_PREFIX = "mtproxy_"',
        "METRICS_EXPORT_LINKS = False",
        "",
    ]
    return "\n".join(lines)


_proc = None


def restart_proxy():
    global _proc
    if DRY_RUN:
        return
    if PROXY_MODE == "process":
        if _proc and _proc.poll() is None:
            _proc.terminate()
            try:
                _proc.wait(5)
            except subprocess.TimeoutExpired:
                _proc.kill()
        _proc = subprocess.Popen(
            [sys.executable, os.path.join(PROXY_DIR, "mtprotoproxy.py")], cwd=PROXY_DIR
        )
    else:
        subprocess.run(["systemctl", "restart", PROXY_SERVICE], check=False)


def sync_proxy(force=False):
    with _lock:
        conn = db()
        try:
            poll_usage(conn)
            cfg = build_config(conn)
            os.makedirs(PROXY_DIR, exist_ok=True)
            path = os.path.join(PROXY_DIR, "config.py")
            old = open(path).read() if os.path.exists(path) else None
            dead = PROXY_MODE == "process" and not DRY_RUN and (_proc is None or _proc.poll() is not None)
            if cfg != old or force or dead:
                tmp = path + ".tmp"
                with open(tmp, "w") as f:
                    f.write(cfg)
                os.replace(tmp, path)
                conn.execute("UPDATE users SET last_raw=0")
                conn.commit()
                restart_proxy()
        finally:
            conn.close()


def worker():
    while True:
        time.sleep(SYNC_INTERVAL)
        try:
            sync_proxy()
        except Exception as e:  # keep the loop alive
            print("sync error:", e, flush=True)


# --------------------------------------------------------------------- auth
_fails = {}


def login_required(page=False):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not session.get("ok"):
                if page:
                    return redirect(url_for("login"))
                return jsonify(error="unauthorized"), 401
            return fn(*a, **kw)

        return wrapper

    return deco


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        ip = request.remote_addr
        count, until = _fails.get(ip, (0, 0))
        if time.time() < until:
            error = "تلاش‌های ناموفق زیاد بود. چند دقیقه بعد دوباره امتحان کنید."
        else:
            u_ok = hmac.compare_digest(request.form.get("username", ""), ADMIN_USER)
            p_ok = hmac.compare_digest(request.form.get("password", ""), ADMIN_PASS)
            if u_ok and p_ok:
                _fails.pop(ip, None)
                session["ok"] = True
                session.permanent = True
                return redirect(url_for("index"))
            count += 1
            _fails[ip] = (count, time.time() + 300 if count >= 5 else 0)
            error = "نام کاربری یا رمز عبور اشتباه است."
    return render_template_string(LOGIN_HTML, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------- API
def host_for_links():
    return SERVER_HOST or request.host.split(":")[0]


def serialize(u, host):
    secret = "ee" + u["secret"] + TLS_DOMAIN.encode().hex()
    q = f"server={host}&port={PUBLIC_PORT}&secret={secret}"
    return {
        "id": u["id"],
        "name": u["name"],
        "note": u["note"],
        "quota_bytes": u["quota_bytes"],
        "used_bytes": u["used_bytes"],
        "expire_at": u["expire_at"],
        "max_conns": u["max_conns"],
        "enabled": bool(u["enabled"]),
        "status": status_of(u),
        "created_at": u["created_at"],
        "tg_link": f"tg://proxy?{q}",
        "web_link": f"https://t.me/proxy?{q}",
    }


@app.route("/")
@login_required(page=True)
def index():
    return PANEL_HTML


@app.route("/api/users", methods=["GET"])
@login_required()
def list_users():
    with db() as c:
        rows = c.execute("SELECT * FROM users ORDER BY id DESC").fetchall()
    host = host_for_links()
    return jsonify(
        users=[serialize(r, host) for r in rows],
        proxy_up=_state["proxy_up"],
        server={"host": host, "port": PUBLIC_PORT, "domain": TLS_DOMAIN},
    )


def _num(data, key, default=0, cast=float):
    try:
        v = cast(data.get(key, default) or 0)
    except (TypeError, ValueError):
        raise ValueError(key)
    if v < 0:
        raise ValueError(key)
    return v


@app.route("/api/users", methods=["POST"])
@login_required()
def create_user():
    d = request.get_json(silent=True) or {}
    name = str(d.get("name", "")).strip()[:40]
    if not name:
        return jsonify(error="نام کاربر را وارد کنید."), 400
    try:
        quota = int(_num(d, "quota_gb") * GB)
        days = _num(d, "expire_days")
        conns = int(_num(d, "max_conns"))
    except ValueError:
        return jsonify(error="مقدار عددی نامعتبر است."), 400
    expire = int(time.time() + days * 86400) if days > 0 else 0
    try:
        with _lock, db() as c:
            c.execute(
                "INSERT INTO users(name,secret,quota_bytes,expire_at,max_conns,note,created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (name, secrets.token_hex(16), quota, expire, conns,
                 str(d.get("note", ""))[:200], int(time.time())),
            )
    except sqlite3.IntegrityError:
        return jsonify(error="این نام قبلاً استفاده شده است."), 409
    sync_proxy()
    with db() as c:
        row = c.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone()
    return jsonify(serialize(row, host_for_links())), 201


@app.route("/api/users/<int:uid>", methods=["PATCH"])
@login_required()
def update_user(uid):
    d = request.get_json(silent=True) or {}
    sets, vals = [], []
    try:
        if "quota_gb" in d:
            sets.append("quota_bytes=?"); vals.append(int(_num(d, "quota_gb") * GB))
        if d.get("expire_days") is not None:
            days = _num(d, "expire_days")
            sets.append("expire_at=?"); vals.append(int(time.time() + days * 86400) if days > 0 else 0)
        if "max_conns" in d:
            sets.append("max_conns=?"); vals.append(int(_num(d, "max_conns")))
    except ValueError:
        return jsonify(error="مقدار عددی نامعتبر است."), 400
    if "enabled" in d:
        sets.append("enabled=?"); vals.append(1 if d["enabled"] else 0)
    if "note" in d:
        sets.append("note=?"); vals.append(str(d["note"])[:200])
    if "name" in d and str(d["name"]).strip():
        sets.append("name=?"); vals.append(str(d["name"]).strip()[:40])
    if not sets:
        return jsonify(error="چیزی برای ذخیره نیست."), 400
    try:
        with _lock, db() as c:
            cur = c.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", vals + [uid])
            if cur.rowcount == 0:
                return jsonify(error="کاربر پیدا نشد."), 404
    except sqlite3.IntegrityError:
        return jsonify(error="این نام قبلاً استفاده شده است."), 409
    sync_proxy()
    return jsonify(ok=True)


@app.route("/api/users/<int:uid>/reset", methods=["POST"])
@login_required()
def reset_usage(uid):
    with _lock, db() as c:
        c.execute("UPDATE users SET used_bytes=0 WHERE id=?", (uid,))
    sync_proxy()
    return jsonify(ok=True)


@app.route("/api/users/<int:uid>", methods=["DELETE"])
@login_required()
def delete_user(uid):
    with _lock, db() as c:
        c.execute("DELETE FROM users WHERE id=?", (uid,))
    sync_proxy()
    return jsonify(ok=True)


def main():
    if not ADMIN_PASS:
        raise SystemExit("ADMIN_PASS is not set")
    init_db()
    sync_proxy(force=True)
    threading.Thread(target=worker, daemon=True).start()
    try:
        from waitress import serve
        serve(app, host="0.0.0.0", port=PANEL_PORT, threads=4)
    except ImportError:
        app.run(host="0.0.0.0", port=PANEL_PORT)


if __name__ == "__main__":
    main()

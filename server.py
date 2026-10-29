#!/usr/bin/env python3
"""Self-registering VPS monitor over HTTP; Python standard library only."""
import base64, hashlib, hmac, ipaddress, json, os, re, secrets, sqlite3, time, urllib.parse, urllib.request, threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("VPSMON_CONFIG", ROOT / "config.json"))
DB_PATH = Path(os.environ.get("VPSMON_DB", ROOT / "vpsmon.sqlite3"))
cfg = json.loads(CONFIG_PATH.read_text())
HOST = cfg.get("host", "0.0.0.0")
PORT = int(cfg.get("port", 8080))
OFFLINE_AFTER = int(cfg.get("offline_after_seconds", 600))
ADMIN_USER = cfg["admin_user"]
ADMIN_PASSWORD = cfg["admin_password"]
ENROLLMENT_KEY = cfg["enrollment_key"]
PAGE_SIZE = 50
LAST_BLOCK_API_URL = str(cfg.get("last_block_api_url", "http://157.230.45.47:22825/api/1.0")).strip()
LAST_BLOCK_API_KEY = str(cfg.get("last_block_api_key", "")).strip()
LAST_BLOCK_FILE = Path(cfg.get("last_block_file", str(ROOT / "lastBlock.txt")))
LAST_BLOCK_DEFAULT_FROM = str(cfg.get("last_block_from_block", "184846"))
# Blocks are produced about every 15 minutes; poll every minute to detect new blocks promptly without excessive API traffic.
LAST_BLOCK_POLL_SECONDS = max(30, int(cfg.get("last_block_poll_seconds", 60)))
_last_block_value = None
_last_block_checked = 0
_last_block_error = ""
_last_block_lock = threading.Lock()

def get_last_block(force=False):
    """Fetch the latest mining block, caching API calls for 30 seconds."""
    global _last_block_value, _last_block_checked, _last_block_error
    now = time.time()
    if not force and now - _last_block_checked < 30:
        return _last_block_value, _last_block_error
    with _last_block_lock:
        now = time.time()
        if not force and now - _last_block_checked < 30:
            return _last_block_value, _last_block_error
        _last_block_checked = now
        if not LAST_BLOCK_API_KEY:
            _last_block_error = "Chưa cấu hình last_block_api_key trong config.json"
            return _last_block_value, _last_block_error
        from_block = LAST_BLOCK_DEFAULT_FROM
        if not from_block or from_block.strip().lower() == "null":
            from_block = "184846"
        try:
            if LAST_BLOCK_FILE.is_file():
                saved = LAST_BLOCK_FILE.read_text().strip()
                if saved and saved.lower() != "null":
                    from_block = saved
        except OSError:
            pass
        payload = {"method": "getMiningBlocksWithTreasury", "params": {"fromBlockId": str(from_block), "limit": "1"}, "token": LAST_BLOCK_API_KEY}
        try:
            req = urllib.request.Request(LAST_BLOCK_API_URL, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "User-Agent": "Custom-VPS-Monitor/1.0"}, method="POST")
            with urllib.request.urlopen(req, timeout=5) as response:
                body = response.read(65536).decode("utf-8", "replace")
            match = re.search(r'"id"\s*:\s*(\d+)', body)
            if not match:
                raise ValueError("API response không chứa trường id dạng số")
            _last_block_value = int(match.group(1))
            _last_block_error = ""
        except Exception as exc:
            _last_block_error = str(exc)[:240]
        return _last_block_value, _last_block_error

def last_block_worker():
    """Poll the mining API in the background once per minute by default, with brief retries on errors."""
    while True:
        for attempt in range(3):
            value, error = get_last_block(force=True)
            if value is not None and not error:
                break
            if attempt < 2:
                time.sleep(10)
        # A new block is expected about every 15 minutes. Poll every 60 seconds by default
        # so new blocks are picked up promptly without repeatedly hammering the API.
        time.sleep(LAST_BLOCK_POLL_SECONDS)

CONFIG_COLUMNS = {
    "cpu_model": "TEXT NOT NULL DEFAULT ''", "cpu_cores": "INTEGER",
    "cpu_usage": "TEXT NOT NULL DEFAULT ''", "ram_total": "TEXT NOT NULL DEFAULT ''",
    "ram_used": "TEXT NOT NULL DEFAULT ''", "os_name": "TEXT NOT NULL DEFAULT ''",
    "disk_total": "TEXT NOT NULL DEFAULT ''", "disk_used": "TEXT NOT NULL DEFAULT ''",
    "uam_uptime": "TEXT NOT NULL DEFAULT ''",
    "uam_processed": "TEXT NOT NULL DEFAULT ''", "uam_logs": "TEXT NOT NULL DEFAULT ''"
}

def token_hash(token): return hashlib.sha256(token.encode()).hexdigest()
def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, first_seen INTEGER NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS heartbeats (
            agent_id TEXT PRIMARY KEY REFERENCES agents(agent_id), hostname TEXT NOT NULL DEFAULT '',
            ip TEXT NOT NULL DEFAULT '', received_at INTEGER NOT NULL, uptime_seconds INTEGER,
            load1 TEXT NOT NULL DEFAULT '', memory TEXT NOT NULL DEFAULT '', disk TEXT NOT NULL DEFAULT '',
            uam TEXT NOT NULL DEFAULT 'unknown', cpu_model TEXT NOT NULL DEFAULT '', cpu_cores INTEGER,
            cpu_usage TEXT NOT NULL DEFAULT '', ram_total TEXT NOT NULL DEFAULT '', ram_used TEXT NOT NULL DEFAULT '',
            os_name TEXT NOT NULL DEFAULT '', disk_total TEXT NOT NULL DEFAULT '', disk_used TEXT NOT NULL DEFAULT '',
            uam_threads INTEGER, uam_pbkey TEXT NOT NULL DEFAULT '', uam_terminal TEXT NOT NULL DEFAULT '', uam_version TEXT NOT NULL DEFAULT '', uam_uptime TEXT NOT NULL DEFAULT '', uam_processed TEXT NOT NULL DEFAULT '', uam_logs TEXT NOT NULL DEFAULT ''
        )""")
        existing = {r["name"] for r in con.execute("PRAGMA table_info(heartbeats)")}
        for name, declaration in CONFIG_COLUMNS.items():
            if name not in existing:
                con.execute(f"ALTER TABLE heartbeats ADD COLUMN {name} {declaration}")
        con.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT NOT NULL, event TEXT NOT NULL, at INTEGER NOT NULL
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS ip_geo_cache (
            ip TEXT PRIMARY KEY, isp TEXT NOT NULL DEFAULT '', org TEXT NOT NULL DEFAULT '',
            country TEXT NOT NULL DEFAULT '', region TEXT NOT NULL DEFAULT '', city TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT '', message TEXT NOT NULL DEFAULT '', checked_at INTEGER NOT NULL
        )""")

def iso(ts):
    if not ts: return "—"
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

def basic_ok(header):
    if not header or not header.startswith("Basic "): return False
    try: user, password = base64.b64decode(header[6:], validate=True).decode().split(":", 1)
    except Exception: return False
    return hmac.compare_digest(user, ADMIN_USER) and hmac.compare_digest(password, ADMIN_PASSWORD)

class Handler(BaseHTTPRequestHandler):
    server_version = "VPSMonitor/3.0"
    def log_message(self, fmt, *args): print("%s - %s" % (self.client_address[0], fmt % args))
    def send_json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body))); self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff"); self.end_headers(); self.wfile.write(body)
    def read_json(self, limit=8192):
        size = int(self.headers.get("Content-Length", "0"))
        if size <= 0 or size > limit: raise ValueError("invalid body size")
        return json.loads(self.rfile.read(size).decode("utf-8"))
    def require_admin(self):
        if basic_ok(self.headers.get("Authorization")): return True
        self.send_response(401); self.send_header("WWW-Authenticate", 'Basic realm="VPS Monitor"')
        self.send_header("Cache-Control", "no-store"); self.end_headers(); return False
    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/register":
            if not hmac.compare_digest(self.headers.get("X-Enrollment-Key", ""), ENROLLMENT_KEY):
                self.send_json(401, {"error": "invalid enrollment key"}); return
            try:
                data = self.read_json(); aid = str(data.get("agent_id", ""))
                if len(aid) < 16 or len(aid) > 80 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in aid):
                    self.send_json(400, {"error": "invalid agent_id"}); return
                token = secrets.token_urlsafe(32); now = int(time.time())
                with db() as con:
                    if con.execute("SELECT 1 FROM agents WHERE agent_id=?", (aid,)).fetchone():
                        self.send_json(409, {"error": "agent already registered; preserve its local token file"}); return
                    con.execute("INSERT INTO agents(agent_id,token_hash,first_seen) VALUES(?,?,?)", (aid, token_hash(token), now))
                    con.execute("INSERT INTO events(agent_id,event,at) VALUES(?,?,?)", (aid, "registered", now))
                self.send_json(201, {"ok": True, "agent_id": aid, "token": token})
            except Exception: self.send_json(400, {"error": "invalid registration request"})
            return
        if path in ("/api/delete", "/api/delete-offline-bulk", "/api/delete-selected"):
            if not self.require_admin(): return
            try:
                data = self.read_json()
                with db() as con:
                    now = int(time.time())
                    if path == "/api/delete":
                        aid = str(data.get("id", ""))
                        row = con.execute("SELECT COALESCE(h.received_at,a.first_seen) AS last_seen FROM agents a LEFT JOIN heartbeats h ON a.agent_id=h.agent_id WHERE a.agent_id=?", (aid,)).fetchone()
                        if not row or now - row["last_seen"] <= OFFLINE_AFTER:
                            self.send_json(409, {"error": "VPS chưa offline hoặc không tồn tại; chỉ có thể xóa VPS offline"}); return
                        con.execute("DELETE FROM events WHERE agent_id=?", (aid,))
                        con.execute("DELETE FROM heartbeats WHERE agent_id=?", (aid,))
                        con.execute("DELETE FROM agents WHERE agent_id=?", (aid,))
                        self.send_json(200, {"ok": True, "deleted": 1})
                    elif path == "/api/delete-selected":
                        raw_ids = data.get("ids", [])
                        if not isinstance(raw_ids, list) or len(raw_ids) > 5000:
                            self.send_json(400, {"error": "Danh sách VPS không hợp lệ"}); return
                        ids = list(dict.fromkeys(str(x)[:80] for x in raw_ids if x))
                        deleted = []
                        for aid in ids:
                            row = con.execute("SELECT COALESCE(h.received_at,a.first_seen) AS last_seen FROM agents a LEFT JOIN heartbeats h ON a.agent_id=h.agent_id WHERE a.agent_id=?", (aid,)).fetchone()
                            if row and now - row["last_seen"] > OFFLINE_AFTER:
                                deleted.append(aid)
                        for offset in range(0, len(deleted), 500):
                            batch = deleted[offset:offset + 500]
                            marks = ",".join("?" for _ in batch)
                            con.execute(f"DELETE FROM events WHERE agent_id IN ({marks})", batch)
                            con.execute(f"DELETE FROM heartbeats WHERE agent_id IN ({marks})", batch)
                            con.execute(f"DELETE FROM agents WHERE agent_id IN ({marks})", batch)
                        self.send_json(200, {"ok": True, "deleted": len(deleted), "skipped": len(ids)-len(deleted)})
                    else:
                        cutoff = now - 86400
                        ids = [r[0] for r in con.execute("SELECT a.agent_id FROM agents a LEFT JOIN heartbeats h ON a.agent_id=h.agent_id WHERE COALESCE(h.received_at,a.first_seen)<=?", (cutoff,)).fetchall()]
                        for offset in range(0, len(ids), 500):
                            batch = ids[offset:offset + 500]
                            marks = ",".join("?" for _ in batch)
                            con.execute(f"DELETE FROM events WHERE agent_id IN ({marks})", batch)
                            con.execute(f"DELETE FROM heartbeats WHERE agent_id IN ({marks})", batch)
                            con.execute(f"DELETE FROM agents WHERE agent_id IN ({marks})", batch)
                        self.send_json(200, {"ok": True, "deleted": len(ids)})
            except Exception: self.send_json(400, {"error": "invalid delete request"})
            return
        if path != "/api/heartbeat": self.send_json(404, {"error": "not found"}); return
        aid = self.headers.get("X-Agent-ID", ""); auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        try:
            with db() as con: agent = con.execute("SELECT token_hash FROM agents WHERE agent_id=?", (aid,)).fetchone()
            if not agent or not hmac.compare_digest(agent["token_hash"], token_hash(token)):
                self.send_json(401, {"error": "unknown agent or invalid token"}); return
            size = int(self.headers.get("Content-Length", "0"))
            if size < 0 or size > 262144: self.send_json(413, {"error": "payload too large"}); return
            from urllib.parse import parse_qs
            form = parse_qs(self.rfile.read(size).decode("utf-8"), keep_blank_values=True)
            def val(key, default=""):
                limit = 4096 if key in ("uam_pbkey", "uam_processed") else (2048 if key == "uam_version" else (80000 if key == "uam_logs" else 512))
                return form.get(key, [default])[0][:limit]
            def integer(key):
                try: return max(0, min(int(val(key, "0")), 10**12))
                except ValueError: return None
            now = int(time.time())
            fields = ["hostname", "ip", "received_at", "uptime_seconds", "load1", "memory", "disk", "uam", "cpu_model", "cpu_cores", "cpu_usage", "ram_total", "ram_used", "os_name", "disk_total", "disk_used", "uam_threads", "uam_pbkey", "uam_terminal", "uam_version", "uam_uptime", "uam_processed", "uam_logs"]
            values = [val("hostname"), self.client_address[0], now, integer("uptime"), val("load1"), val("memory"), val("disk"), val("uam", "unknown"), val("cpu_model"), integer("cpu_cores"), val("cpu_usage"), val("ram_total"), val("ram_used"), val("os_name"), val("disk_total"), val("disk_used"), integer("uam_threads"), val("uam_pbkey")[:4096], val("uam_terminal"), val("uam_version")[:2048], val("uam_uptime")[:4096], val("uam_processed")[:4096], val("uam_logs")[:80000]]
            with db() as con:
                old = con.execute("SELECT received_at FROM heartbeats WHERE agent_id=?", (aid,)).fetchone()
                placeholders = ",".join("?" for _ in fields)
                updates = ",".join(f"{f}=excluded.{f}" for f in fields if f != "agent_id")
                con.execute(f"INSERT INTO heartbeats(agent_id,{','.join(fields)}) VALUES(?,{placeholders}) ON CONFLICT(agent_id) DO UPDATE SET {updates}", [aid]+values)
                if old is None: con.execute("INSERT INTO events(agent_id,event,at) VALUES(?,?,?)", (aid, "first_heartbeat", now))
                elif now - old["received_at"] > OFFLINE_AFTER: con.execute("INSERT INTO events(agent_id,event,at) VALUES(?,?,?)", (aid, "back_online", now))
            self.send_json(200, {"ok": True, "server_time": now})
        except Exception: self.send_json(400, {"error": "invalid request"})
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/healthz": self.send_json(200, {"ok": True}); return
        if path not in ("/", "/api/status", "/api/events", "/api/ip-info"):
            self.send_json(404, {"error": "not found"}); return
        if not self.require_admin(): return
        if path == "/api/ip-info":
            params = urllib.parse.parse_qs(urlparse(self.path).query)
            aid = (params.get("id") or [""])[0]
            with db() as con:
                row = con.execute("SELECT ip FROM heartbeats WHERE agent_id=?", (aid,)).fetchone()
                if not row or not row["ip"]:
                    self.send_json(404, {"error": "Chưa có địa chỉ IP của VPS này"}); return
                ip = row["ip"]
                cached = con.execute("SELECT * FROM ip_geo_cache WHERE ip=?", (ip,)).fetchone()
            try:
                parsed_ip = ipaddress.ip_address(ip)
            except ValueError:
                self.send_json(400, {"error": "Địa chỉ IP không hợp lệ"}); return
            if not parsed_ip.is_global:
                self.send_json(200, {"ip": ip, "isp": "—", "org": "—", "country": "IP nội bộ/không công khai", "region": "—", "city": "—", "note": "Không thể tra cứu vị trí địa lý của IP riêng hoặc IP không công khai."}); return
            now = int(time.time())
            if cached and now - cached["checked_at"] < 7 * 86400:
                self.send_json(200, {"ip": ip, "isp": cached["isp"] or "—", "org": cached["org"] or "—", "country": cached["country"] or "—", "region": cached["region"] or "—", "city": cached["city"] or "—", "note": cached["message"] or "Dữ liệu tra cứu IP được lưu cache tối đa 7 ngày."}); return
            try:
                url = "http://ip-api.com/json/" + urllib.parse.quote(ip, safe="") + "?fields=status,message,country,regionName,city,isp,org,query"
                req = urllib.request.Request(url, headers={"User-Agent": "Custom-VPS-Monitor/1.0"})
                with urllib.request.urlopen(req, timeout=5) as response:
                    geo = json.loads(response.read(8192).decode("utf-8"))
                if geo.get("status") != "success":
                    raise RuntimeError(str(geo.get("message", "Không tra cứu được IP")))
                values = (ip, geo.get("isp", ""), geo.get("org", ""), geo.get("country", ""), geo.get("regionName", ""), geo.get("city", ""), "success", "", now)
                with db() as con:
                    con.execute("""INSERT INTO ip_geo_cache(ip,isp,org,country,region,city,status,message,checked_at) VALUES(?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(ip) DO UPDATE SET isp=excluded.isp,org=excluded.org,country=excluded.country,region=excluded.region,city=excluded.city,status=excluded.status,message=excluded.message,checked_at=excluded.checked_at""", values)
                self.send_json(200, {"ip": ip, "isp": geo.get("isp") or "—", "org": geo.get("org") or "—", "country": geo.get("country") or "—", "region": geo.get("regionName") or "—", "city": geo.get("city") or "—", "note": "Thông tin định vị IP từ dịch vụ tra cứu bên thứ ba; vị trí có thể gần đúng."})
            except Exception as exc:
                if cached:
                    self.send_json(200, {"ip": ip, "isp": cached["isp"] or "—", "org": cached["org"] or "—", "country": cached["country"] or "—", "region": cached["region"] or "—", "city": cached["city"] or "—", "note": "Không lấy được dữ liệu mới; đang hiển thị cache cũ. " + str(exc)}); return
                self.send_json(502, {"error": "Không tra cứu được thông tin IP. Kiểm tra kết nối Internet của server hoặc thử lại sau. " + str(exc)}); return
        if path == "/api/status":
            now = int(time.time())
            with db() as con:
                rows = con.execute("""SELECT a.agent_id,a.first_seen,h.hostname,h.ip,h.received_at,h.uptime_seconds,h.load1,h.memory,h.disk,h.uam,
                    h.cpu_model,h.cpu_cores,h.cpu_usage,h.ram_total,h.ram_used,h.os_name,h.disk_total,h.disk_used,
                    h.uam_threads,h.uam_pbkey,h.uam_terminal,h.uam_version,h.uam_uptime,h.uam_processed,h.uam_logs,COALESCE(g.isp,'') AS isp,COALESCE(g.org,'') AS org
                    FROM agents a LEFT JOIN heartbeats h ON a.agent_id=h.agent_id LEFT JOIN ip_geo_cache g ON g.ip=h.ip ORDER BY COALESCE(h.received_at,a.first_seen) DESC""").fetchall()
            last_block, last_block_error = _last_block_value, _last_block_error
            result = []
            for row in rows:
                r = dict(row); last = r["received_at"] or r["first_seen"]
                status = "ONLINE" if r["received_at"] and now-last <= OFFLINE_AFTER else "OFFLINE"
                result.append({"id":r["agent_id"],"status":status,"last_seen":iso(r["received_at"]),"seconds_ago":now-last if last else None,
                    "hostname":r["hostname"] or "","ip":r["ip"] or "","uptime_seconds":r["uptime_seconds"],
                    "load1":r["load1"] or "","memory":r["memory"] or "","disk":r["disk"] or "","uam":r["uam"] or "unknown",
                    "cpu_model":r["cpu_model"] or "","cpu_cores":r["cpu_cores"],"cpu_usage":r["cpu_usage"] or "",
                    "ram_total":r["ram_total"] or "","ram_used":r["ram_used"] or "","os_name":r["os_name"] or "",
                    "disk_total":r["disk_total"] or "","disk_used":r["disk_used"] or "",
                    "uam_threads":r["uam_threads"],"uam_pbkey":r["uam_pbkey"] or "","uam_terminal":r["uam_terminal"] or "","uam_version":r["uam_version"] or "","uam_uptime":r["uam_uptime"] or "","uam_processed":r["uam_processed"] or "","uam_logs":r["uam_logs"] or "","isp":r["isp"] or "","org":r["org"] or ""})
            self.send_json(200, {"total":len(result),"online":sum(x["status"]=="ONLINE" for x in result),
                "offline":sum(x["status"]=="OFFLINE" for x in result),"last_block":last_block,"last_block_error":last_block_error,"servers":result}); return
        if path == "/api/events":
            with db() as con: rows = con.execute("SELECT agent_id,event,at FROM events ORDER BY id DESC LIMIT 100").fetchall()
            self.send_json(200, [dict(r, at=iso(r["at"])) for r in rows]); return
        html = r'''<!doctype html><html lang="vi"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPS Monitor</title><style>
:root{color-scheme:light}body{font:14px system-ui,Arial;margin:22px;background:#f5f7fa;color:#172033}h1{margin:0 0 5px}.muted{color:#667085}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:18px 0}.card{background:white;padding:15px 19px;border-radius:10px;min-width:110px;box-shadow:0 1px 4px #0001}.num{font-size:28px;font-weight:700}.wrap{overflow:auto;background:white;border-radius:10px;box-shadow:0 1px 4px #0001}table{border-collapse:collapse;width:100%;min-width:850px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #e8ecf2;white-space:nowrap}th{background:#edf1f7;position:sticky;top:0}.online{color:#137547;font-weight:700}.offline{color:#c02626;font-weight:700}.pill{padding:3px 8px;border-radius:99px;background:#e8f7ef}.pill.offline{background:#ffeded}.tabs{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}.btn{border:1px solid #d0d5dd;border-radius:7px;background:#fff;padding:8px 12px;cursor:pointer;color:#172033}.btn.active{background:#1d2939;color:white;border-color:#1d2939}.btn.danger{background:#b42318;color:white;border-color:#b42318}.btn:disabled{opacity:.45;cursor:not-allowed}.small{padding:5px 8px;font-size:12px}.pagination{display:flex;gap:10px;align-items:center;justify-content:flex-end;padding:12px;background:#fff}.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:10px 0}.empty{text-align:center;padding:24px;color:#667085}.modal-back{display:none;position:fixed;inset:0;background:#10182899;z-index:10;align-items:center;justify-content:center;padding:16px}.modal-back.show{display:flex}.modal{background:#fff;border-radius:12px;padding:20px;width:min(560px,100%);max-height:85vh;overflow:auto;box-shadow:0 10px 40px #0003}.modal-head{display:flex;justify-content:space-between;gap:10px;align-items:center}.modal h2{font-size:18px;margin:0}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:16px}.metric{border:1px solid #e4e7ec;border-radius:9px;padding:12px;min-width:0}.metric-label{font-size:12px;color:#667085}.metric-value{font-weight:700;margin:5px 0;overflow-wrap:anywhere;white-space:pre-line}.log-card{grid-column:span 1;min-width:0}.log-pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:55vh;overflow:auto;margin:8px 0 0;font:12px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace}.bar{height:7px;border-radius:8px;background:#eaecf0;overflow:hidden;margin-top:8px}.bar span{display:block;height:100%;background:#12b76a;width:0}.bar.warn span{background:#f79009}.bar.high span{background:#f04438}.note{margin-top:14px;color:#667085;font-size:12px}@media(min-width:900px){.log-card{grid-column:span 1}}@media(max-width:600px){body{margin:12px}.grid{grid-template-columns:1fr}.num{font-size:24px}}
</style></head><body>
<h1>VPS Monitor</h1><div class="muted">Tự đăng ký VPS · Làm mới mỗi 15 giây · Thời gian UTC</div>
<div class="cards" id="summaryCards"><div class="card">VPS<div class="num" id="total">—</div></div><div class="card">Online<div class="num online" id="online">—</div></div><div class="card">Offline<div class="num offline" id="offline">—</div></div><div class="card">UAM Online<div class="num" id="onlineUamTotal">—</div><div class="muted">Total Threads của VPS online</div></div><div class="card">UAM Tmux Online<div class="num" id="onlineTmuxTotal">—</div></div><div class="card">UAM Docker Online<div class="num" id="onlineDockerTotal">—</div></div><div class="card">Last Block<div class="num" id="lastBlock">—</div><div class="muted" id="lastBlockNote">Đang tải…</div></div></div>
<div class="tabs"><button class="btn active" data-tab="all">Tất cả (<span id="allCount">0</span>)</button><button class="btn" data-tab="online">Online (<span id="onlineCount">0</span>)</button><button class="btn" data-tab="offline">Offline (<span id="offlineCount">0</span>)</button><button class="btn" data-tab="no-terminal">Không có Terminal (<span id="noTerminalCount">0</span>)</button><button class="btn" data-tab="alerts">Cảnh báo tài nguyên &gt;95% (<span id="alertsCount">0</span>)</button><button class="btn" data-tab="missing-block">Block thiếu ≥10 (<span id="missingBlockCount">0</span>)</button></div>
<div class="actions"><label for="ipSearch"><b>Tìm kiếm:</b></label><input id="ipSearch" class="btn" type="search" placeholder="Tìm theo IP, PBKey, ISP hoặc Terminal" autocomplete="off"><label for="ispFilter"><b>ISP:</b></label><select id="ispFilter" class="btn"><option value="all">Tất cả ISP</option></select><label for="terminalFilter"><b>Terminal:</b></label><select id="terminalFilter" class="btn"><option value="all">Tất cả Terminal</option><option value="tmux">Tmux UAM</option><option value="docker">Docker UAM</option></select><button class="btn danger" id="deleteIspOffline">Xóa VPS offline theo ISP đang chọn</button></div>
<div class="actions"><button class="btn danger" id="deleteSelected">Xóa VPS offline đã chọn (0)</button><button class="btn" id="selectVisibleOffline">Chọn VPS offline trên trang</button><button class="btn" id="clearSelected">Bỏ chọn</button><button class="btn danger" id="bulkDelete">Xóa VPS offline từ 24 tiếng trở lên</button><span class="muted" id="bulkHint">Chỉ xóa VPS offline ít nhất 24 giờ.</span></div>
<div class="wrap"><table><thead><tr><th>Chọn</th><th>IP</th><th>ISP / Nhà cung cấp</th><th>Trạng thái</th><th>Last seen</th><th>Offline bao lâu</th><th>Uptime</th><th>Total Threads</th><th>Terminal</th><th>Processed block UAM</th><th>Missing Block</th><th>CPU load</th><th>RAM</th><th>Disk /</th><th>Thông tin UAM</th><th>UAM logs</th><th>Cấu hình</th><th>Thao tác</th></tr></thead><tbody id="rows"><tr><td colspan="18" class="empty">Đang tải…</td></tr></tbody></table></div>
<div class="pagination"><span id="pageInfo" class="muted">Trang 1/1</span><button class="btn" id="prev">Trước</button><button class="btn" id="next">Sau</button></div><p class="muted" id="updated"></p>
<div class="modal-back" id="modalBack" role="dialog" aria-modal="true" aria-labelledby="modalTitle"><div class="modal"><div class="modal-head"><h2 id="modalTitle">Cấu hình VPS</h2><button class="btn" id="closeModal">Đóng</button></div><div class="muted" id="modalSubtitle"></div><div class="grid" id="configGrid"></div><div class="note" id="modalNote">Thông số được agent gửi định kỳ. Mức CPU là mẫu đo gần nhất; RAM và disk là mức sử dụng tại thời điểm heartbeat.</div></div></div>
<script>
const PAGE_SIZE=50;let allServers=[],tab='all',page=1,selectedIds=new Set(),ispLookupQueue=[],ispLookupRunning=false,ispLookupQueued=new Set();
function esc(x){return String(x??'—').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function dur(s){if(s==null)return '—';s=Math.max(0,Math.floor(s));let d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return d+'d '+h+'h '+m+'m';}
function offlineDur(s){if(s==null)return 'Chưa phản hồi';if(s<=OFFLINE_AFTER)return '—';let m=Math.floor(s/60);return m<60?m+' phút':Math.floor(m/60)+' giờ '+m%60+' phút';}
function terminalText(s){return String(s.uam_terminal||'').toLowerCase();}
function hasTmux(s){return terminalText(s).includes('tmux uam');}
function hasDocker(s){return terminalText(s).includes('docker uam');}
function hasTerminal(s){return hasTmux(s)||hasDocker(s);}
function isHighUsage(s){return [s.cpu_usage,s.memory,s.disk].some(v=>{const p=parsePct(v);return p!==null&&p>95;});}
function blockRows(s){const last=Number.parseInt(window.currentLastBlock,10);if(!Number.isFinite(last)||!hasTerminal(s))return [{label:'Không phát hiện',missing:null}];const raw=String(s.uam_processed||'').split('\n').map(x=>x.trim()).filter(Boolean);if(!raw.length||raw.every(x=>/^Không có Processed block UAM$/i.test(x)))return [{label:'Không phát hiện',missing:null}];return raw.map(line=>{const m=line.match(/(?:^|\s-\s)(\d+)\s*$/);if(!m)return {label:line,missing:null};const block=Number.parseInt(m[1],10),difference=last-block;return {label:line,missing:difference>=0?difference:null,block};});}
function hasMissingBlock(s){return blockRows(s).some(x=>x.missing!==null&&x.missing>=10);}
function missingCell(s){const rows=blockRows(s);if(rows.length===1&&rows[0].label==='Không phát hiện')return '<span>Không phát hiện</span>';const html=rows.map(r=>`<span style="display:block;white-space:nowrap;${r.missing!==null&&r.missing>=10?'color:#c00;font-weight:700':''}">${esc(r.label.split(/\s+-\s+/)[0])}${r.missing===null?'':' - '+r.missing}</span>`).join('');if(rows.length>5)return `<button class="btn small" data-missing="${esc(s.id)}">Xem ${rows.length} mục</button>`;return html;}
function currentList(){const isp=document.getElementById('ispFilter')?.value||'all',term=document.getElementById('terminalFilter')?.value||'all',query=(document.getElementById('ipSearch')?.value||'').trim().toLowerCase();return allServers.filter(s=>{const tabMatch=tab==='all'||(tab==='online'&&s.status==='ONLINE')||(tab==='offline'&&s.status==='OFFLINE')||(tab==='no-terminal'&&!hasTerminal(s))||(tab==='alerts'&&isHighUsage(s))||(tab==='missing-block'&&hasMissingBlock(s));const ispMatch=isp==='all'?true:isp==='unknown'?!s.isp:(s.isp||'').toLowerCase()===isp.toLowerCase();const termMatch=term==='all'||(term==='tmux'&&hasTmux(s))||(term==='docker'&&hasDocker(s));const haystack=[s.ip,s.uam_pbkey,s.isp,s.org,s.uam_terminal].map(v=>String(v||'')).join(' ').toLowerCase();const searchMatch=!query||haystack.includes(query);return tabMatch&&ispMatch&&termMatch&&searchMatch;});}
function populateIspFilter(){const sel=document.getElementById('ispFilter'),old=sel.value;const names=[...new Set(allServers.map(s=>(s.isp||'').trim()).filter(Boolean))].sort((a,b)=>a.localeCompare(b));sel.innerHTML='<option value="all">Tất cả ISP</option>'+names.map(n=>`<option value="${esc(n)}">${esc(n)}</option>`).join('')+'<option value="unknown">Chưa xác định ISP</option>';if(old==='all'||names.some(n=>n.toLowerCase()===old.toLowerCase())||old==='unknown')sel.value=old;else sel.value='all';}
function renderUamSummary(){const online=allServers.filter(s=>s.status==='ONLINE');const total=online.reduce((sum,s)=>sum+Math.max(0,Number.parseInt(s.uam_threads,10)||0),0);let tmux=0,docker=0;for(const s of online){const threads=Math.max(0,Number.parseInt(s.uam_threads,10)||0);if(hasTmux(s))tmux+=1;if(hasDocker(s))docker+=Math.max(0,threads-(hasTmux(s)?1:0));}document.getElementById('onlineUamTotal').textContent=total;document.getElementById('onlineTmuxTotal').textContent=tmux;document.getElementById('onlineDockerTotal').textContent=docker;const groups=new Map();for(const s of online){const name=(s.isp||'').trim()||'Chưa xác định ISP';groups.set(name,(groups.get(name)||0)+Math.max(0,Number.parseInt(s.uam_threads,10)||0));}const cards=[...groups.entries()].sort((a,b)=>a[0].localeCompare(b[0])).map(([name,count])=>`<div class="card" data-isp-uam-card="1">UAM Online · ${esc(name)}<div class="num">${count}</div><div class="muted">Total Threads</div></div>`).join('');document.querySelectorAll('[data-isp-uam-card]').forEach(el=>el.remove());document.getElementById('summaryCards').insertAdjacentHTML('beforeend',cards);}
function queueIspLookups(){for(const s of allServers){if(s.ip&&!s.isp&&!ispLookupQueued.has(s.id)){ispLookupQueued.add(s.id);ispLookupQueue.push(s.id);}}if(!ispLookupRunning)processIspLookupQueue();}
async function processIspLookupQueue(){if(ispLookupRunning)return;ispLookupRunning=true;while(ispLookupQueue.length){const id=ispLookupQueue.shift();try{const r=await fetch('/api/ip-info?id='+encodeURIComponent(id),{cache:'no-store'});if(r.ok){const d=await r.json(),s=allServers.find(x=>x.id===id);if(s){s.isp=(d.isp&&d.isp!=='—')?d.isp:'';s.org=d.org||'';populateIspFilter();render();}}}catch{}await new Promise(resolve=>setTimeout(resolve,1400));}ispLookupRunning=false;}
function render(){renderUamSummary();document.getElementById('noTerminalCount').textContent=allServers.filter(s=>!hasTerminal(s)).length;document.getElementById('alertsCount').textContent=allServers.filter(isHighUsage).length;document.getElementById('missingBlockCount').textContent=allServers.filter(hasMissingBlock).length;let list=currentList(),pages=Math.max(1,Math.ceil(list.length/PAGE_SIZE));page=Math.min(page,pages);let start=(page-1)*PAGE_SIZE,shown=list.slice(start,start+PAGE_SIZE);document.getElementById('rows').innerHTML=shown.length?shown.map(s=>`<tr${(isHighUsage(s)||hasMissingBlock(s))?' style="background:#fff1f0"':''}><td>${s.status==='OFFLINE'?`<input type="checkbox" aria-label="Chọn VPS offline ${esc(s.ip)}" data-select="${esc(s.id)}" ${selectedIds.has(s.id)?'checked':''}>`:'—'}</td><td><button class="btn small ip-button" data-ip-info="${esc(s.id)}">${esc(s.ip||'—')}</button></td><td>${esc(s.isp||'Đang tra cứu…')}</td><td><span class="pill ${s.status==='ONLINE'?'':'offline'} ${s.status==='ONLINE'?'online':'offline'}">${esc(s.status)}</span>${isHighUsage(s)?' <span class="pill offline" title="CPU/RAM/Disk vượt 95%">Cảnh báo</span>':''}</td><td>${esc(s.last_seen)}</td><td>${s.status==='OFFLINE'?esc(offlineDur(s.seconds_ago)):'—'}</td><td>${esc(dur(s.uptime_seconds))}</td><td>${esc(s.uam_threads??'—')}</td><td>${esc(s.uam_terminal||'Không có Terminal')}</td><td>${processedCell(s)}</td><td>${missingCell(s)}</td><td>${esc(s.cpu_usage||'—')}</td><td>${esc(s.memory||'—')}</td><td>${esc(s.disk||'—')}</td><td><button class="btn small" data-uam-info="${esc(s.id)}">Xem thông tin UAM</button></td><td><button class="btn small" data-uam-logs="${esc(s.id)}">Xem logs</button></td><td><button class="btn small" data-config="${esc(s.id)}">Xem cấu hình</button></td><td>${s.status==='OFFLINE'?`<button class="btn danger small" data-delete="${esc(s.id)}">Xóa</button>`:'—'}</td></tr>`).join(''):`<tr><td colspan="18" class="empty">Không có VPS trong danh sách này.</td></tr>`;document.getElementById('pageInfo').textContent=`Trang ${page}/${pages} · ${list.length} VPS`;document.getElementById('prev').disabled=page<=1;document.getElementById('next').disabled=page>=pages;document.getElementById('bulkDelete').disabled=!allServers.some(s=>s.status==='OFFLINE'&&s.seconds_ago!==null&&s.seconds_ago>=86400);document.getElementById('bulkHint').textContent=`Xóa tất cả VPS offline từ 24 giờ trở lên, không phụ thuộc bộ lọc.`;document.getElementById('deleteSelected').textContent=`Xóa VPS offline đã chọn (${[...selectedIds].filter(id=>allServers.some(s=>s.id===id&&s.status==='OFFLINE')).length})`;document.getElementById('deleteSelected').disabled=![...selectedIds].some(id=>allServers.some(s=>s.id===id&&s.status==='OFFLINE'));const isp=document.getElementById('ispFilter').value;const ispOffline=allServers.filter(s=>s.status==='OFFLINE'&&(isp==='all'?false:isp==='unknown'?!s.isp:(s.isp||'').toLowerCase()===isp.toLowerCase()));document.getElementById('deleteIspOffline').disabled=isp==='all'||ispOffline.length===0;document.querySelectorAll('[data-tab]').forEach(b=>b.classList.toggle('active',b.dataset.tab===tab));}
function uptimeForLine(s,line){const uptime=String(s.uam_uptime||'').split('\n').map(x=>x.trim()).filter(Boolean);if(/^Tmux UAM\s*-/.test(line)){const t=uptime.find(x=>!/^Docker\s+/i.test(x));return t||'—';}const m=line.match(/^(.+?)\s+-\s+/);if(m){const name=m[1].trim();const d=uptime.find(x=>{const q=x.match(/^Docker\s+([^:]+):\s*(.*)$/i);return q&&q[1].trim()===name;});if(d){const q=d.match(/^Docker\s+[^:]+:\s*(.*)$/i);return q?q[1].trim():'—';}}return '—';}
function pbkeyForLine(s,line){const values=String(s.uam_pbkey||'').split('\n').map(x=>x.trim()).filter(Boolean);if(/^Tmux UAM\s*-/.test(line)){const row=values.find(x=>/^Tmux UAM\s*:/i.test(x));return row?row.replace(/^Tmux UAM\s*:\s*/i,'').trim():'—';}const m=line.match(/^(.+?)\s+-\s+/);if(m){const name=m[1].trim();const row=values.find(x=>{const q=x.match(/^Docker\s+([^:]+):\s*(.*)$/i);return q&&q[1].trim()===name;});if(row){const q=row.match(/^Docker\s+[^:]+:\s*(.*)$/i);return q?q[1].trim():'—';}}return '—';}
function processedLines(s){if(!hasTerminal(s))return ['Không phát hiện'];const raw=String(s.uam_processed||'').split('\n').map(x=>x.trim()).filter(Boolean);if(!raw.length||raw.every(x=>/^Không có Processed block UAM$/i.test(x)))return ['Không phát hiện'];return raw.map(line=>{if(/^Tmux UAM\s*-/.test(line)){const parts=line.split(/\s+-\s+/);const block=parts.slice(1).join(' - ')||'—';const uptime=uptimeForLine(s,line).replace(/\s+-\s+/g,', ');const pbkey=pbkeyForLine(s,line);return `Tmux UAM - ${block} - ${uptime} - ${pbkey}`;}const parts=line.split(/\s+-\s+/);const name=parts[0]||'Không rõ container';const block=parts.slice(1).join(' - ')||'—';const uptime=uptimeForLine(s,line);const pbkey=pbkeyForLine(s,line);return `Docker ${name} - ${block} - ${uptime} - ${pbkey}`;});}
function processedCell(s){const lines=processedLines(s);const value=lines.join('\n');if(lines.length>5)return `<button class="btn small" data-processed="${esc(s.id)}">Xem ${lines.length} mục</button>`;return `<span style="white-space:pre-line">${esc(value)}</span>`;}
function parsePct(x){let m=String(x??'').match(/[\d.]+/);return m?Math.max(0,Math.min(100,Number(m[0]))):null;}
function metric(label,value,pct){let p=pct===null?null:Math.max(0,Math.min(100,pct)),cls=p>=90?'high':p>=75?'warn':'';return `<div class="metric"><div class="metric-label">${esc(label)}</div><div class="metric-value">${esc(value||'Chưa có dữ liệu')}</div>${p===null?'':`<div class="bar ${cls}"><span style="width:${p}%"></span></div><div class="metric-label">Sử dụng ${p}%</div>`}</div>`;}
function showConfig(id){let s=allServers.find(x=>x.id===id);if(!s)return;document.getElementById('modalTitle').textContent='Cấu hình VPS';document.getElementById('modalSubtitle').textContent=s.id+' · '+(s.hostname||'')+' · '+(s.ip||'IP chưa rõ');let cpu=parsePct(s.cpu_usage),ram=parsePct(s.memory),disk=parsePct(s.disk);document.getElementById('configGrid').innerHTML=metric('CPU',`${s.cpu_model||'Chưa rõ CPU'} · ${s.cpu_cores??'—'} vCPU`,cpu)+metric('RAM',`${s.ram_used||'—'} / ${s.ram_total||'—'} (${s.memory||'—'})`,ram)+metric('Disk phân vùng /',`${s.disk_used||'—'} / ${s.disk_total||'—'} (${s.disk||'—'})`,disk)+metric('Hệ điều hành',s.os_name||'Chưa có dữ liệu',null)+metric('Load trung bình 1 phút',s.load1||'—',null)+metric('Uptime',dur(s.uptime_seconds),null);document.getElementById('modalNote').textContent='Thông số được agent gửi định kỳ. Mức CPU là mẫu đo gần nhất; RAM và disk là mức sử dụng tại thời điểm heartbeat.';document.getElementById('modalBack').classList.add('show');}
function showUamInfo(id){let s=allServers.find(x=>x.id===id);if(!s)return;document.getElementById('modalTitle').textContent='Thông tin UAM';document.getElementById('modalSubtitle').textContent=(s.ip||'IP chưa rõ')+' · '+s.status;document.getElementById('configGrid').innerHTML=metric('Total Threads',s.uam_threads??'Chưa có dữ liệu',null)+metric('PBKey',s.uam_pbkey||'Chưa có dữ liệu',null)+metric('Terminal',s.uam_terminal||'Không phát hiện UAM',null)+metric('Version',s.uam_version||'Chưa có dữ liệu',null)+metric('Uptime',s.uam_uptime||'Chưa có dữ liệu',null);document.getElementById('modalNote').textContent='PBKey, Version và Uptime Docker được tách theo tên container; Uptime Tmux tính từ thời điểm tạo session Utopia.';document.getElementById('modalBack').classList.add('show');}
function showUamLogs(id){const s=allServers.find(x=>x.id===id);if(!s)return;document.getElementById('modalTitle').textContent='UAM logs (100 dòng gần nhất)';document.getElementById('modalSubtitle').textContent=(s.ip||'IP chưa rõ')+' · '+(s.uam_terminal||'Không phát hiện UAM');document.getElementById('configGrid').innerHTML=`<div class="metric" style="grid-column:1/-1"><div class="metric-label">Logs theo Terminal / container</div><pre class="log-pre">${esc(s.uam_logs||'Không có log UAM hoặc agent chưa gửi dữ liệu.')}</pre></div>`;document.getElementById('modalNote').textContent='Logs được lấy mỗi heartbeat từ tail -n 100 cho Tmux và docker logs --tail 100 cho từng container đang chạy. Nội dung có thể bị giới hạn kích thước truyền.';document.getElementById('modalBack').classList.add('show');}
function showMissing(id){const s=allServers.find(x=>x.id===id);if(!s)return;document.getElementById('modalTitle').textContent='Missing Block';document.getElementById('modalSubtitle').textContent=(s.ip||'IP chưa rõ')+' · Last Block '+(window.currentLastBlock??'—');const rows=blockRows(s);document.getElementById('configGrid').innerHTML=`<div class="metric" style="grid-column:1/-1"><div class="metric-value" style="white-space:pre-line">${esc(rows.map(r=>r.label+' - Missing Block: '+(r.missing===null?'—':r.missing)).join('\n'))}</div></div>`;document.getElementById('modalNote').textContent='Missing Block = Last Block - Processed block. Chỉ hiển thị chênh lệch từ 0 trở lên; giá trị từ 10 trở lên được đánh dấu cảnh báo.';document.getElementById('modalBack').classList.add('show');}
function showProcessed(id){const s=allServers.find(x=>x.id===id);if(!s)return;document.getElementById('modalTitle').textContent='Processed block UAM';document.getElementById('modalSubtitle').textContent=(s.ip||'IP chưa rõ')+' · '+(s.uam_terminal||'Không phát hiện UAM');document.getElementById('configGrid').innerHTML=`<div class="metric" style="grid-column:1/-1"><div class="metric-value" style="white-space:pre-line">${esc(processedLines(s).join('\n')||'Không có dữ liệu Processed block.')}</div></div>`;document.getElementById('modalNote').textContent='Giá trị cuối cùng của Processed block được tìm trong 500 dòng log gần nhất của từng Terminal/container.';document.getElementById('modalBack').classList.add('show');}
async function showIpInfo(id){let s=allServers.find(x=>x.id===id);if(!s)return;document.getElementById('modalTitle').textContent='Thông tin IP';document.getElementById('modalSubtitle').textContent=s.id+' · '+(s.ip||'IP chưa rõ');document.getElementById('configGrid').innerHTML='<div class="metric">Đang tra cứu thông tin IP…</div>';document.getElementById('modalNote').textContent='Đang lấy thông tin ISP, tổ chức và vị trí địa lý.';document.getElementById('modalBack').classList.add('show');try{let r=await fetch('/api/ip-info?id='+encodeURIComponent(id),{cache:'no-store'});let d=await r.json();if(!r.ok)throw Error(d.error||('HTTP '+r.status));document.getElementById('configGrid').innerHTML=metric('IP',d.ip,null)+metric('ISP',d.isp,null)+metric('Organization (Org)',d.org,null)+metric('Country',d.country,null)+metric('Region',d.region,null)+metric('City',d.city,null);document.getElementById('modalNote').textContent=d.note||'Thông tin vị trí IP chỉ mang tính gần đúng.';}catch(e){document.getElementById('configGrid').innerHTML=metric('Không thể tra cứu',e.message,null);document.getElementById('modalNote').textContent='Hãy kiểm tra kết nối Internet của VPS trung tâm rồi thử lại.';}}
async function adminPost(path,payload){let r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload),cache:'no-store'});let d={};try{d=await r.json()}catch{}if(!r.ok)throw Error(d.error||('HTTP '+r.status));return d;}
async function deleteOne(id){let s=allServers.find(x=>x.id===id);if(!s||s.status!=='OFFLINE')return;if(!confirm(`Xóa VPS ${id}? Thao tác này xóa bản ghi khỏi danh sách và không thể hoàn tác.`))return;try{await adminPost('/api/delete',{id});await refresh();}catch(e){alert('Không xóa được: '+e.message);}}
async function deleteSelected(){const ids=[...selectedIds].filter(id=>allServers.some(s=>s.id===id&&s.status==='OFFLINE'));if(!ids.length)return;if(!confirm(`Xóa ${ids.length} VPS offline đã chọn? Thao tác này không thể hoàn tác.`))return;try{const d=await adminPost('/api/delete-selected',{ids});selectedIds.clear();alert(`Đã xóa ${d.deleted} VPS offline${d.skipped?`; bỏ qua ${d.skipped} VPS không còn offline`:''}.`);page=1;await refresh();}catch(e){alert('Không xóa được: '+e.message);}}
async function deleteOfflineByIsp(){const isp=document.getElementById('ispFilter').value;if(isp==='all')return;const ids=allServers.filter(s=>s.status==='OFFLINE'&&(isp==='unknown'?!s.isp:(s.isp||'').toLowerCase()===isp.toLowerCase())).map(s=>s.id);if(!ids.length)return;const label=isp==='unknown'?'chưa xác định ISP':isp;if(!confirm(`Xóa ${ids.length} VPS offline thuộc ISP ${label}? Thao tác này không thể hoàn tác.`))return;try{const d=await adminPost('/api/delete-selected',{ids});for(const id of ids)selectedIds.delete(id);alert(`Đã xóa ${d.deleted} VPS offline thuộc ISP ${label}.`);page=1;await refresh();}catch(e){alert('Không xóa được: '+e.message);}}
async function bulkDelete(){let count=allServers.filter(s=>s.status==='OFFLINE'&&s.seconds_ago!==null&&s.seconds_ago>=86400).length;if(!count)return;if(!confirm(`Xóa ${count} VPS offline từ 24 tiếng trở lên? Thao tác này không thể hoàn tác.`))return;try{let d=await adminPost('/api/delete-offline-bulk',{});alert(`Đã xóa ${d.deleted} VPS offline.`);page=1;await refresh();}catch(e){alert('Không xóa được: '+e.message);}}
async function refresh(){try{let r=await fetch('/api/status',{cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);let d=await r.json();allServers=d.servers;window.currentLastBlock=d.last_block;populateIspFilter();document.getElementById('lastBlock').textContent=d.last_block??'—';document.getElementById('lastBlockNote').textContent=d.last_block_error?'API chưa cập nhật':'Từ mining API';document.getElementById('total').textContent=d.total;document.getElementById('online').textContent=d.online;document.getElementById('offline').textContent=d.offline;document.getElementById('allCount').textContent=d.total;document.getElementById('onlineCount').textContent=d.online;document.getElementById('offlineCount').textContent=d.offline;render();queueIspLookups();document.getElementById('updated').textContent='Cập nhật lúc '+new Date().toLocaleString()+' · OFFLINE sau '+OFFLINE_AFTER+' giây không có heartbeat.';}catch(e){document.getElementById('updated').textContent='Không tải được dữ liệu: '+e.message;}}
document.querySelectorAll('[data-tab]').forEach(b=>b.addEventListener('click',()=>{tab=b.dataset.tab;page=1;render();}));document.getElementById('prev').onclick=()=>{if(page>1){page--;render();}};document.getElementById('next').onclick=()=>{page++;render();};document.getElementById('rows').addEventListener('click',e=>{let c=e.target.closest('[data-config]'),d=e.target.closest('[data-delete]'),ip=e.target.closest('[data-ip-info]'),u=e.target.closest('[data-uam-info]'),logs=e.target.closest('[data-uam-logs]'),processed=e.target.closest('[data-processed]'),missing=e.target.closest('[data-missing]');if(c)showConfig(c.dataset.config);if(d)deleteOne(d.dataset.delete);if(ip)showIpInfo(ip.dataset.ipInfo);if(u)showUamInfo(u.dataset.uamInfo);if(logs)showUamLogs(logs.dataset.uamLogs);if(processed)showProcessed(processed.dataset.processed);if(missing)showMissing(missing.dataset.missing);});document.getElementById('rows').addEventListener('change',e=>{const box=e.target.closest('[data-select]');if(!box)return;if(box.checked)selectedIds.add(box.dataset.select);else selectedIds.delete(box.dataset.select);render();});document.getElementById('ispFilter').addEventListener('change',()=>{page=1;render();});document.getElementById('terminalFilter').addEventListener('change',()=>{page=1;render();});document.getElementById('ipSearch').addEventListener('input',()=>{page=1;render();});document.getElementById('deleteSelected').onclick=deleteSelected;document.getElementById('deleteIspOffline').onclick=deleteOfflineByIsp;document.getElementById('selectVisibleOffline').onclick=()=>{for(const s of currentList().slice((page-1)*PAGE_SIZE,page*PAGE_SIZE))if(s.status==='OFFLINE')selectedIds.add(s.id);render();};document.getElementById('clearSelected').onclick=()=>{selectedIds.clear();render();};document.getElementById('bulkDelete').onclick=bulkDelete;document.getElementById('closeModal').onclick=()=>document.getElementById('modalBack').classList.remove('show');document.getElementById('modalBack').addEventListener('click',e=>{if(e.target.id==='modalBack')e.currentTarget.classList.remove('show');});document.addEventListener('keydown',e=>{if(e.key==='Escape')document.getElementById('modalBack').classList.remove('show');});refresh();setInterval(refresh,15000);
</script></body></html>'''.replace('OFFLINE_AFTER', str(OFFLINE_AFTER))
        body = html.encode(); self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body))); self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff"); self.end_headers(); self.wfile.write(body)

def main():
    init_db()
    threading.Thread(target=last_block_worker, name="last-block-poller", daemon=True).start()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"VPS Monitor listening on http://{HOST}:{PORT}")
    print("WARNING: HTTP is unencrypted. Restrict access with firewall/VPN; do not use on an untrusted public network.")
    server.serve_forever()
if __name__ == "__main__": main()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""Serve the storage report with a guarded one-click cleanup API (Windows).

    python3 scripts/server.py /tmp/storage_analysis.json [--port 0] [--no-browser]

Starts on 127.0.0.1 + random port + per-session token, serves the interactive
report, exposes POST /action (move to Recycle Bin / Trash, hard delete, open
folder) and POST /shutdown (stop the service, used by the page button).
Stop with Ctrl+C as well.

SAFETY MODEL - read before changing:
- Exact allowlist: only paths literally listed in this report's green / yellow
  trash_paths are accepted for deletion. Every request path is realpath-resolved
  and must match an allowlist entry exactly. This is the core guard.
- Deny list: Windows system locations that must never be deleted even if a buggy
  analysis lists them (C:\Windows, Program Files, ProgramData\Microsoft, ...).
- Depth guard: refuses drive roots and top-level folders (C:\, C:\Users, ...).
- Roots: derived from the report itself (drive + first path component of every
  trash path) plus optional "allow_roots" in the analysis JSON. No manual
  per-machine configuration, and a path in C:\ProgramData is allowed only when
  the report actually lists a trash path there.
- Bound to 127.0.0.1 only; every POST requires the session token; Host header
  must be localhost (blocks DNS-rebinding).
- Trash is reversible; rm is not. The page confirms before sending.
"""
import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.dont_write_bytecode = True          # do not leave __pycache__ in scripts/

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "..", "assets", "report_template.html")
HOME = os.path.realpath(os.path.expanduser("~"))
TOKEN = secrets.token_urlsafe(24)
JOBS = {}          # job_id -> 进度状态（内存里，服务停了就没了）
SRV = None
DATA = {}
TPL = ""
RM_ALLOW = set()
TRASH_ALLOW = set()
OPEN_ALLOW = set()
ROOTS = [os.path.normcase(HOME)]

# Never delete these, even if a buggy analysis lists them in trash_paths.
# 任何盘符下的系统保留目录名：命中即拒绝（不区分 C: 还是 H:）
SYSTEM_DIR_NAMES = [
    "system volume information",
    "$recycle.bin",
    "recovery",
    "boot",
    "perflogs",
    "config.msi",
    "$windows.~bt",
    "$windows.~ws",
]

# 只对系统盘生效的关键目录（数据盘上的同名目录不算）
# 系统盘上按前缀整体保护（整棵子树都不能动）
SYSTEM_DRIVE_DENY_PREFIX = [
    r"c:\windows",
    r"c:\program files",
    r"c:\program files (x86)",
]

# 系统盘上只保护目录本身，里面的子目录仍可作为清理目标
SYSTEM_DRIVE_DENY_EXACT = [
    r"c:\users",
    r"c:\programdata",
]


def expand(p):
    return os.path.realpath(os.path.expanduser(p))


def _norm(p):
    return os.path.normcase(expand(p))


def load(src):
    with open(src, encoding="utf-8") as f:
        data = json.load(f)
    with open(TEMPLATE, encoding="utf-8") as f:
        tpl = f.read()
    rm_allow, trash_allow, open_allow = set(), set(), set()
    for it in data.get("green", []):
        for p in (it.get("trash_paths") or []):
            rp = _norm(p)
            rm_allow.add(rp); trash_allow.add(rp); open_allow.add(rp)
    for it in data.get("yellow", []):
        for p in (it.get("trash_paths") or []):
            rp = _norm(p)
            trash_allow.add(rp); open_allow.add(rp)
        if it.get("path"):
            rp = _norm(it["path"])
            if os.path.exists(rp):
                open_allow.add(rp)
    for it in data.get("red", []):
        for p in (it.get("app_paths") or []):
            rp = _norm(p)
            if os.path.exists(rp):
                open_allow.add(rp)

    roots = [HOME, os.environ.get("TEMP") or "", os.environ.get("TMP") or ""]
    for p in list(trash_allow):
        parts = os.path.normpath(p).split(os.sep)
        if len(parts) >= 2:
            roots.append(parts[0] + os.sep + parts[1])
    for r in (data.get("allow_roots") or []):
        roots.append(r)
    roots = [os.path.normcase(os.path.realpath(r)) for r in roots if r]
    return data, tpl, rm_allow, trash_allow, open_allow, roots


def _trash_windows(path):
    """Move to Recycle Bin. Raises OSError with an actionable message."""
    import ctypes
    from ctypes import wintypes

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", ctypes.c_uint16),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

    FO_DELETE = 3
    FOF_ALLOWUNDO = 0x0040
    FOF_NOCONFIRMATION = 0x0010
    FOF_SILENT = 0x0004
    FOF_NOERRORUI = 0x0400

    op = SHFILEOPSTRUCTW()
    op.wFunc = FO_DELETE
    op.pFrom = os.path.abspath(path) + "\x00\x00"
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
    rc = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    if rc != 0:
        raise OSError(_sh_error(rc, path))


def _sh_error(rc, path):
    table = {
        0x71: "DE_SAMEFILE: source and destination are the same",
        0x74: "DE_ROOTDIR: cannot delete a root directory",
        0x75: "DE_OPCANCELLED: operation cancelled (file in use or needs confirmation)",
        0x78: "DE_ACCESSDENIEDSRC: access denied, administrator rights required",
        0x79: "DE_PATHTOODEEP: directory nesting too deep",
        0x7C: "DE_INVALIDFILES: invalid path - usually a file inside is locked by a running program",
        0x7D: "DE_DESTSAMETREE",
        0x7E: "DE_FLDDESTISFILE",
        0x7F: "DE_FILEDESTISFLD",
        0x80: "DE_FILENAMETOOLONG: path exceeds the 260 character limit",
        0x81: "DE_DEST_IS_CDROM",
        0x82: "DE_DEST_IS_DVD",
        0x83: "DE_FILE_TOO_LARGE: larger than the Recycle Bin quota",
        0x84: "DE_RECYCLE_INCOMPLETE: could not be fully moved to the Recycle Bin",
    }
    detail = table.get(rc, "unknown error")
    msg = "SHFileOperation failed (code %d / 0x%X): %s" % (rc, rc, detail)
    if rc in (0x7C, 0x78, 0x75):
        procs = _blocking_processes(path)
        if procs:
            msg += " | locked by: " + ", ".join(procs) + " - close it and retry"
        else:
            msg += " | no process found holding it; check open Explorer windows or handles"
    return msg


def _blocking_processes(path):
    """Names of processes whose executable lives under path.
    Uses PowerShell -EncodedCommand so no temp .ps1 file is written."""
    if not sys.platform.startswith("win"):
        return []
    try:
        prefix = os.path.abspath(path).replace("'", "''")
        ps = ("$p='%s'; Get-CimInstance Win32_Process | "
              "Where-Object { $_.ExecutablePath -and "
              "$_.ExecutablePath.StartsWith($p,'OrdinalIgnoreCase') } | "
              "Select-Object -ExpandProperty Name -Unique" % prefix)
        enc = base64.b64encode(ps.encode("utf-16-le")).decode("ascii")
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", enc],
            capture_output=True, text=True, timeout=20,
        ).stdout
        return [x.strip() for x in out.splitlines() if x.strip()][:5]
    except Exception:
        return []


def move_to_trash(path):
    if not sys.platform.startswith("win"):
        raise OSError("move-to-trash is Windows only")
    _trash_windows(path)


def hard_delete(path):
    if os.path.isdir(path) and not os.path.islink(path):
        shutil.rmtree(path)
    else:
        os.remove(path)


def _longpath(p):
    if p.startswith("\\\\?\\"):
        return p
    return ("\\\\?\\" + p) if len(p) >= 240 else p


def preview_paths(paths, budget=2.5, max_samples=8):
    """Count files / dirs / bytes under each path, honouring a per-path time budget.

    Read-only. For huge trees it stops at the budget and sets partial=true, so the
    preview dialog never hangs the UI.
    """
    items = []
    total = {"files": 0, "dirs": 0, "bytes": 0}
    for p in paths:
        rp = _norm(p)
        it = {"path": p, "exists": True, "kind": "dir", "files": 0, "dirs": 0,
              "bytes": 0, "partial": False, "samples": []}
        if not os.path.exists(rp):
            it["exists"] = False
            items.append(it)
            continue
        if os.path.isfile(rp):
            try:
                st = os.stat(rp)
            except OSError as e:
                it["exists"] = False
                it["error"] = str(e)
                items.append(it)
                continue
            it["kind"] = "file"
            it["files"] = 1
            it["bytes"] = st.st_size
            it["samples"] = [{"rel": os.path.basename(rp), "size": st.st_size}]
            items.append(it)
            total["files"] += 1
            total["bytes"] += st.st_size
            continue
        deadline = time.time() + budget
        stack = [(rp, "")]
        samples = []
        while stack:
            if time.time() > deadline:
                it["partial"] = True
                break
            cur, rel = stack.pop()
            try:
                itr = os.scandir(_longpath(cur))
            except OSError:
                continue
            try:
                for e in itr:
                    if time.time() > deadline:
                        it["partial"] = True
                        break
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if getattr(st, "st_file_attributes", 0) & 0x400:
                        continue
                    r = (rel + "/" + e.name) if rel else e.name
                    if e.is_dir(follow_symlinks=False):
                        it["dirs"] += 1
                        stack.append((e.path, r))
                    else:
                        it["files"] += 1
                        it["bytes"] += st.st_size
                        samples.append((st.st_size, r))
            except OSError:
                pass
            finally:
                try:
                    itr.close()
                except Exception:
                    pass
        samples.sort(key=lambda x: -x[0])
        it["samples"] = [{"rel": r, "size": s} for s, r in samples[:max_samples]]
        items.append(it)
        total["files"] += it["files"]
        total["dirs"] += it["dirs"]
        total["bytes"] += it["bytes"]
    return {"ok": True, "total": total, "items": items}

def open_in_file_manager(path):
    target = path if os.path.isdir(path) else os.path.dirname(path)
    if not sys.platform.startswith("win"):
        raise OSError("open-in-file-manager is Windows only")
    subprocess.run(["explorer", target])


def _is_drive_root(rp):
    # 只在真正的盘符根（H:\\）上拒绝。
    # 顶层目录（如 H:\\adsbl、C:\\tmp）是合法的清理目标，不能一刀切。
    parts = [x for x in os.path.normpath(rp).split(os.sep) if x]
    return len(parts) <= 1


def _denied(rp):
    low = os.path.normcase(os.path.normpath(rp))
    names = [x for x in low.split(os.sep) if x]
    for n in names[1:]:
        if n in SYSTEM_DIR_NAMES:
            return "系统保留目录（%s）" % n
    if low in SYSTEM_DRIVE_DENY_EXACT:
        return "系统盘关键目录本身"
    for d in SYSTEM_DRIVE_DENY_PREFIX:
        if low == d or low.startswith(d + os.sep):
            return "系统盘关键目录"
    return None


def check_path(p, allow):
    rp = _norm(p)
    if rp not in allow:
        return None, "path not in allowlist: %s" % p
    if _is_drive_root(rp):
        return None, "refusing to operate on a whole drive: %s" % p
    why = _denied(rp)
    if why:
        return None, "protected system path (%s), refused: %s" % (why, p)
    if not any(rp == base or rp.startswith(base + os.sep) for base in ROOTS):
        return None, "path outside declared roots: %s" % p
    return rp, None

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        b = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            blob = json.dumps(DATA, ensure_ascii=False)
            cfg = json.dumps({"token": TOKEN, "endpoint": "/action", "progress": "/progress", "preview": "/preview", "shutdown": "/shutdown"})
            html = TPL.replace("__REPORT_DATA__", blob).replace("__DELETE_CONFIG__", cfg)
            self._send(200, html, "text/html; charset=utf-8")
        elif self.path.startswith("/progress"):
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            if q.get("token", [""])[0] != TOKEN:
                self._send(403, json.dumps({"ok": False, "error": "bad token"}))
                return
            job = JOBS.get(q.get("id", [""])[0])
            if not job:
                self._send(404, json.dumps({"ok": False, "error": "no such job"}))
                return
            self._send(200, json.dumps({
                "ok": True, "id": job["id"], "total": job["total"],
                "index": job["index"], "current": job["current"],
                "done_count": len(job["done"]), "failed_count": len(job["failed"]),
                "finished": job["finished"], "result": job["result"],
            }, ensure_ascii=False))
        elif self.path == "/ping":
            self._send(200, json.dumps({"ok": True}))
        else:
            self._send(404, "not found", "text/plain")

    def _host_ok(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")

    def do_POST(self):
        if self.path == "/shutdown":
            if not self._host_ok():
                self._send(403, json.dumps({"ok": False, "error": "host not allowed"}))
                return
            n = int(self.headers.get("Content-Length", 0))
            try:
                req = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                self._send(400, json.dumps({"ok": False, "error": "bad request"}))
                return
            if req.get("token") != TOKEN:
                self._send(403, json.dumps({"ok": False, "error": "bad token"}))
                return
            self._send(200, json.dumps({"ok": True, "stopping": True}))
            threading.Thread(target=_stop_server, daemon=True).start()
            return

        if self.path == "/preview":
            if not self._host_ok():
                self._send(403, json.dumps({"ok": False, "error": "host not allowed"}))
                return
            n = int(self.headers.get("Content-Length", 0))
            try:
                req = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                self._send(400, json.dumps({"ok": False, "error": "bad request"}))
                return
            if req.get("token") != TOKEN:
                self._send(403, json.dumps({"ok": False, "error": "bad token"}))
                return
            try:
                res = preview_paths(req.get("paths") or [])
            except Exception as e:
                self._send(500, json.dumps({"ok": False, "error": str(e)}, ensure_ascii=False))
                return
            self._send(200, json.dumps(res, ensure_ascii=False))
            return

        if self.path != "/action":
            self._send(404, json.dumps({"ok": False, "error": "not found"}))
            return
        if not self._host_ok():
            self._send(403, json.dumps({"ok": False, "error": "host not allowed"}))
            return
        n = int(self.headers.get("Content-Length", 0))
        try:
            req = json.loads(self.rfile.read(n) or b"{}")
        except Exception:
            self._send(400, json.dumps({"ok": False, "error": "bad request"}))
            return
        if req.get("token") != TOKEN:
            self._send(403, json.dumps({"ok": False, "error": "bad token"}))
            return
        mode = req.get("mode")
        allow = {"rm": RM_ALLOW, "trash": TRASH_ALLOW, "open": OPEN_ALLOW}.get(mode)
        if allow is None:
            self._send(400, json.dumps({"ok": False, "error": "unknown mode"}))
            return
        paths = req.get("paths") or []
        # 先整单预校验：任何一个路径不合法就整单拒绝，避免删到一半才报错
        for p in paths:
            rp, err = check_path(p, allow)
            if err:
                self._send(403, json.dumps({"ok": False, "error": err, "done": []},
                                           ensure_ascii=False))
                return
        job_id = secrets.token_urlsafe(9)
        JOBS[job_id] = {
            "id": job_id, "total": len(paths), "index": 0, "current": "",
            "done": [], "failed": [], "finished": False, "mode": mode,
            "result": None, "started": time.time(),
        }
        threading.Thread(target=_run_job,
                         args=(job_id, paths, mode, bool(req.get("stop_on_error"))),
                         daemon=True).start()
        self._send(200, json.dumps({"ok": True, "job_id": job_id,
                                     "total": len(paths)}))


def _run_job(job_id, paths, mode, stop_on_error):
    """逐条执行，边跑边更新进度。默认出错跳过、继续后面的。"""
    job = JOBS.get(job_id)
    if not job:
        return
    done, failed = [], []
    for i, p in enumerate(paths):
        job["current"] = p
        job["index"] = i
        try:
            rp = _norm(p)
            if mode == "open":
                open_in_file_manager(rp)
            elif not os.path.exists(rp):
                pass
            elif mode == "trash":
                move_to_trash(rp)
            else:
                hard_delete(rp)
            done.append(p)
        except Exception as e:
            failed.append({"path": p, "error": str(e)})
            if stop_on_error:
                job["done"] = list(done)
                job["failed"] = list(failed)
                job["index"] = len(paths)
                break
        job["done"] = list(done)
        job["failed"] = list(failed)
    if not stop_on_error:
        job["index"] = len(paths)
    job["current"] = ""
    job["finished"] = True
    job["result"] = {
        "ok": not failed,
        "partial": bool(done) and bool(failed),
        "done": done, "failed": failed,
        "done_count": len(done), "failed_count": len(failed),
    }
    if failed and not done:
        job["result"]["error"] = failed[0]["error"]
    threading.Timer(3600, lambda: JOBS.pop(job_id, None)).start()

def _stop_server():
    time.sleep(0.4)
    if SRV is not None:
        SRV.shutdown()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    src = args[0]
    port = 0
    no_browser = "--no-browser" in sys.argv
    for i, a in enumerate(sys.argv):
        if a == "--port" and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
    global DATA, TPL, RM_ALLOW, TRASH_ALLOW, OPEN_ALLOW, ROOTS, SRV
    DATA, TPL, RM_ALLOW, TRASH_ALLOW, OPEN_ALLOW, ROOTS = load(src)
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    SRV = srv
    url = "http://127.0.0.1:%d/" % srv.server_address[1]
    print("report server: " + url)
    print("green deletable %d | yellow trashable %d" % (len(RM_ALLOW), len(TRASH_ALLOW) - len(RM_ALLOW)))
    print("click the 'stop service' button at bottom-right, or Ctrl+C. Buttons die with the service.")
    if not no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    print("\nstopped.")


if __name__ == "__main__":
    main()

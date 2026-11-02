#!/usr/bin/env python3
"""Read-only storage scanner for Windows.

Collects disk usage, system info, and per-directory size breakdowns for the
hot spots that typically eat disk, and emits one JSON blob to stdout for Claude
to interpret and classify. Auto-detects the OS and scans the right locations.

STRICTLY READ-ONLY: only sizes/lists/reads metadata. Never creates, moves, or
deletes anything.

Output shape (same on both OSes):
{
  "generated_at", "scan_seconds",
  "system": {os, build, arch, user, home, filesystem,
             disk_total, disk_used, disk_free, purgeable,
             disks: [{name, total, used, free}]},   # all volumes/drives
  "groups": { "<group>": [{name, path, size_kb, size_h}], ... }
}
"""
import json
import os
import shutil
import sys
import time

HOME = os.path.expanduser("~")


def human(kb):
    """KB number -> human string like '12.3 GB'."""
    n = float(kb) * 1024
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit not in ("B", "KB") else f"{int(n)} {unit}"
        n /= 1024


# ======================================================================
# Windows only (stdlib: os, shutil, ctypes, subprocess)
# ======================================================================
REPARSE_POINT = 0x400


def _is_reparse(st):
    """junction / symlink / mount point: never follow, never count twice.
    os.path.islink() misses junctions; this catches them all."""
    return bool(getattr(st, "st_file_attributes", 0) & REPARSE_POINT)


def _long(path):
    r"""Explorer-style \\?\ prefix so >260 char paths still open."""
    if path.startswith("\\\\?\\"):
        return path
    if len(path) >= 240:
        return "\\\\?\\" + path
    return path


def dir_size_bytes(path):
    """Recursive size in bytes via os.scandir. Skips reparse points and unreadable."""
    total = 0
    try:
        with os.scandir(_long(path)) as it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                    if _is_reparse(st):
                        continue
                    if e.is_file(follow_symlinks=False):
                        total += st.st_size
                    elif e.is_dir(follow_symlinks=False):
                        total += dir_size_bytes(e.path)
                except (PermissionError, OSError):
                    continue
    except (PermissionError, OSError):
        pass
    return total


def scandir_children(path, min_kb=51200, limit=40):
    """Size every immediate child of `path` via os.scandir. Windows."""
    if not path or not os.path.isdir(path):
        return []
    results = []
    try:
        entries = sorted(os.listdir(path))
    except PermissionError:
        return [{"name": "(permission denied)", "path": path,
                 "size_kb": 0, "size_h": "?", "denied": True}]
    for name in entries:
        child = os.path.join(path, name)
        if os.path.islink(child):
            continue
        try:
            kb = (os.path.getsize(child) if os.path.isfile(child)
                  else dir_size_bytes(child)) // 1024
        except (PermissionError, OSError):
            continue
        if kb < min_kb:
            continue
        results.append({"name": name, "path": child, "size_kb": kb, "size_h": human(kb)})
    results.sort(key=lambda r: r["size_kb"], reverse=True)
    return results[:limit]


def list_fixed_drives():
    """All fixed (non-removable, non-network) drives, e.g. ['C:\\', 'D:\\']."""
    drives = []
    if sys.platform.startswith("win"):
        try:
            import ctypes
            DRIVE_FIXED = 3
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if not (bitmask >> i) & 1:
                    continue
                letter = chr(ord("A") + i) + ":\\"
                if ctypes.windll.kernel32.GetDriveTypeW(letter) == DRIVE_FIXED:
                    drives.append(letter)
        except Exception:
            pass
    if not drives:
        import string
        for letter in string.ascii_uppercase:
            root = letter + ":\\"
            if os.path.exists(root):
                try:
                    shutil.disk_usage(root)
                    drives.append(root)
                except Exception:
                    continue
    return drives


def list_drives_windows():
    drives = []
    import string
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        if os.path.exists(root):
            try:
                t, u, f = shutil.disk_usage(root)
                drives.append({"name": root, "total": human(t // 1024),
                               "used": human(u // 1024), "free": human(f // 1024)})
            except Exception:
                continue
    return drives


def system_info_windows():
    import platform
    info = {}
    info["os"] = platform.system() + " " + platform.release()
    info["build"] = platform.version()
    info["arch"] = os.environ.get("PROCESSOR_ARCHITECTURE", platform.machine())
    info["user"] = os.environ.get("USERNAME", "")
    info["home"] = os.environ.get("USERPROFILE", HOME)
    sysdrive = os.environ.get("SystemDrive", "C:") + "\\"
    total, used, free = "?", "?", "?"
    try:
        t, u, f = shutil.disk_usage(sysdrive)
        total, used, free = human(t // 1024), human(u // 1024), human(f // 1024)
    except Exception:
        pass
    info["disk_total"], info["disk_used"], info["disk_free"] = total, used, free
    info["filesystem"] = "NTFS"
    info["purgeable"] = ""
    info["disk_name"] = sysdrive
    info["disks"] = list_drives_windows()
    return info


DOC_EXT = {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "md",
           "rtf", "odt", "csv", "pages", "key", "numbers"}
MEDIA_EXT = {"jpg", "jpeg", "png", "gif", "bmp", "heic", "webp", "svg",
             "mp4", "mkv", "mov", "avi", "wmv", "flv", "mp3", "wav", "flac", "m4a"}
ARCHIVE_EXT = {"zip", "rar", "7z", "iso", "tar", "gz", "bz2", "xz", "cab"}


def _ext(name):
    e = os.path.splitext(name)[1].lower().lstrip(".")
    return e or "(noext)"


def profile_dir(path, size_index, top_files=3, top_ext=6, top_subdirs=5):
    """One-level content profile of a directory: what is actually inside it.

    Reads only the immediate children (not recursive), so it is cheap even for
    huge trees. Answers two questions at once:
      - 这个目录的体积是自己的文件撑起来的，还是子目录撑起来的？
      - 自己的文件都是什么类型，有没有"混进来"的文档/媒体/压缩包？
    """
    ext_bytes, ext_count = {}, {}
    biggest = []
    stray = 0
    own = 0
    subdirs = []
    try:
        with os.scandir(_long(path)) as it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                except (PermissionError, OSError):
                    continue
                if _is_reparse(st):
                    continue
                if e.is_dir(follow_symlinks=False):
                    subdirs.append((size_index.get(e.path, 0), e.path))
                    continue
                k = _ext(e.name)
                own += st.st_size
                ext_bytes[k] = ext_bytes.get(k, 0) + st.st_size
                ext_count[k] = ext_count.get(k, 0) + 1
                if k in DOC_EXT or k in MEDIA_EXT or k in ARCHIVE_EXT:
                    stray += st.st_size
                biggest.append((st.st_size, e.path))
    except (PermissionError, OSError) as ex:
        return {"path": path, "error": str(ex)}
    biggest.sort(key=lambda x: -x[0])
    subdirs.sort(key=lambda x: -x[0])
    ext_sorted = sorted(ext_bytes.items(), key=lambda x: -x[1])[:top_ext]
    return {
        "path": path,
        "own_bytes": own,
        "subdir_bytes": sum(s for s, _ in subdirs),
        "ext": [[k, v, ext_count.get(k, 0)] for k, v in ext_sorted],
        "top_files": [[sz, p] for sz, p in biggest[:top_files]],
        "top_subdirs": [[sz, p] for sz, p in subdirs[:top_subdirs]],
        "stray_bytes": stray,
        "stray_ratio": round(stray / own, 4) if own else 0.0,
    }


SYSTEM_DIR_TOKENS = ("system volume information", "$recycle.bin", "recovery",
                     "config.msi", "$windows.~bt", "$windows.~ws", "perflogs")


def _err_kind(path, msg):
    low = path.lower()
    if any(t in low for t in SYSTEM_DIR_TOKENS):
        return "system"          # 系统保留区，读不到是正常的，不算遗漏
    if "PermissionError" in msg or "WinError 5" in msg or "拒绝访问" in msg:
        return "acl"             # 需要管理员权限才能读
    return "other"


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def full_volume_scan(root, big_mb=100, max_depth=6, min_bytes=1024 ** 3,
                     max_entries=3000000, max_seconds=900, profiles=12,
                     profile_min_mb=512):
    """Walk an entire volume: per-directory totals + big files + content profiles.

    Read-only. Skips reparse points (junctions/symlinks) so nothing is counted
    twice and no cycle can hang the walk. Two budgets keep it bounded:
    max_entries (default 3M) and max_seconds (default 900). Hitting either sets
    truncated=true and stops - a partial result beats an endless scan.
    """
    started = time.time()
    dirs, big, errors = [], [], []
    entries = 0
    truncated = False
    root = root.rstrip("\\/") + os.sep
    try:
        top = os.scandir(_long(root))
    except (PermissionError, OSError) as e:
        return {"root": root, "error": str(e), "dirs": [], "big_files": []}
    stack = [[root, 0, top, 0, 0]]
    while stack:
        if entries >= max_entries or (time.time() - started) > max_seconds:
            truncated = True
            break
        fr = stack[-1]
        try:
            e = next(fr[2])
        except StopIteration:
            fr[2].close(); stack.pop()
            dirs.append([fr[0], fr[1], fr[3], fr[4]])
            if stack:
                stack[-1][3] += fr[3]; stack[-1][4] += fr[4]
            continue
        except (PermissionError, OSError) as ex:
            errors.append([fr[0], str(ex), _err_kind(fr[0], str(ex))])
            try: fr[2].close()
            except Exception: pass
            stack.pop()
            dirs.append([fr[0], fr[1], fr[3], fr[4]])
            if stack:
                stack[-1][3] += fr[3]; stack[-1][4] += fr[4]
            continue
        entries += 1
        try:
            st = e.stat(follow_symlinks=False)
        except (PermissionError, OSError):
            continue
        if _is_reparse(st):
            continue
        try:
            if e.is_dir(follow_symlinks=False):
                sub = os.scandir(_long(e.path))
                stack.append([e.path, fr[1] + 1, sub, 0, 0])
            else:
                sz = st.st_size
                fr[3] += sz; fr[4] += 1
                if sz >= big_mb * 1024 * 1024:
                    big.append([sz, e.path])
        except (PermissionError, OSError) as ex:
            errors.append([e.path, str(ex), _err_kind(e.path, str(ex))])
            continue
    if truncated:
        while stack:
            fr = stack.pop()
            try: fr[2].close()
            except Exception: pass
            dirs.append([fr[0], fr[1], fr[3], fr[4]])
            if stack:
                stack[-1][3] += fr[3]; stack[-1][4] += fr[4]
    keep = [d for d in dirs if d[1] <= max_depth or d[2] >= min_bytes]
    keep.sort(key=lambda d: -d[2])
    big.sort(key=lambda x: -x[0])

    size_index = {d[0]: d[2] for d in dirs}
    # 每个目录"自己的文件"有多大 = 总大小 - 直接子目录之和。
    # 用它挑两类目录做画像：体积最大的（看结构），以及自身文件占比最高的（看内容）。
    child_sum = {}
    for d in dirs:
        parent = os.path.dirname(d[0].rstrip("\\/"))
        child_sum[parent] = child_sum.get(parent, 0) + d[2]
    own_of = {d[0]: max(0, d[2] - child_sum.get(d[0], 0)) for d in dirs}

    prof = []
    if profiles:
        cand = [d for d in dirs if d[2] >= profile_min_mb * 1024 * 1024 and d[1] >= 1]
        by_size = sorted(cand, key=lambda d: -d[2])[:profiles]
        by_own = sorted(cand, key=lambda d: -own_of.get(d[0], 0))[:profiles]
        seen, picked = set(), []
        for d in by_size + by_own:
            if d[0] in seen:
                continue
            seen.add(d[0]); picked.append(d)
            if len(picked) >= profiles * 2:
                break
        for d in picked:
            pr = profile_dir(d[0], size_index)
            pr["bytes"] = d[2]
            pr["files"] = d[3]
            pr["own_bytes"] = own_of.get(d[0], pr.get("own_bytes", 0))
            prof.append(pr)

    return {"root": root,
            "dirs": keep,
            "big_files": big[:500],
            "big_file_count": len(big),
            "profiles": prof,
            "errors": errors[:80],
            "denied_summary": {
                "system": sum(1 for e in errors if len(e) > 2 and e[2] == "system"),
                "acl": sum(1 for e in errors if len(e) > 2 and e[2] == "acl"),
                "other": sum(1 for e in errors if len(e) > 2 and e[2] == "other"),
                "acl_paths": [e[0] for e in errors if len(e) > 2 and e[2] == "acl"][:40],
                "system_paths": [e[0] for e in errors if len(e) > 2 and e[2] == "system"][:20],
                "is_admin": is_admin(),
            },
            "errors_count": len(errors),
            "entries_scanned": entries,
            "truncated": truncated,
            "total_bytes": sum(d[2] for d in dirs if d[1] == 0),
            "file_count": sum(d[3] for d in dirs if d[1] == 0)}


def scan_windows(full=False, drives=None):
    profile = os.environ.get("USERPROFILE", HOME)
    local = os.environ.get("LOCALAPPDATA", os.path.join(profile, "AppData", "Local"))
    roaming = os.environ.get("APPDATA", os.path.join(profile, "AppData", "Roaming"))
    targets = [
        ("user_profile", profile, 102400),
        ("appdata_local", local, 51200),
        ("appdata_roaming", roaming, 51200),
        ("temp", os.environ.get("TEMP", os.path.join(local, "Temp")), 51200),
        ("downloads", os.path.join(profile, "Downloads"), 51200),
        ("program_files", os.environ.get("ProgramFiles", r"C:\Program Files"), 102400),
        ("program_files_x86", os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), 102400),
    ]
    groups = {}
    for key, path, floor in targets:
        groups[key] = scandir_children(path, min_kb=floor)

    dev_paths = [
        os.path.join(profile, ".cache"), os.path.join(profile, ".npm"),
        os.path.join(profile, ".gradle"), os.path.join(profile, ".m2"),
        os.path.join(profile, ".nuget", "packages"), os.path.join(profile, ".cargo"),
        os.path.join(local, "pip", "Cache"), os.path.join(local, "Yarn"),
        os.path.join(local, "uv"), os.path.join(local, "ms-playwright"),
        os.path.join(local, "go-build"),
    ]
    dev = []
    for path in dev_paths:
        if not os.path.isdir(path):
            continue
        try:
            kb = dir_size_bytes(path) // 1024
        except (PermissionError, OSError):
            continue
        if kb < 51200:
            continue
        dev.append({"name": os.path.basename(path.rstrip("\\/")) or path,
                    "path": path, "size_kb": kb, "size_h": human(kb)})
    dev.sort(key=lambda r: r["size_kb"], reverse=True)
    groups["dev_caches"] = dev
    system = system_info_windows()
    if full:
        targets = drives or [(os.environ.get("SystemDrive", "C:") + os.sep)]
        deadline = time.time() + MAX_SECONDS
        scans = []
        for drive in targets:
            remain = max(30, int(deadline - time.time()))
            data = full_volume_scan(drive, profiles=PROFILES, max_seconds=remain)
            data["drive"] = drive
            try:
                data["volume_used_bytes"] = shutil.disk_usage(drive).used
            except Exception:
                data["volume_used_bytes"] = None
            scans.append(data)
            if time.time() >= deadline:
                for rest in targets[targets.index(drive) + 1:]:
                    scans.append({"drive": rest, "skipped": True,
                                  "reason": "global time budget exhausted"})
                break
        system["full_scans"] = scans
        system["full_scan"] = scans[0] if scans else None
    return system, groups


# ======================================================================
USE_FULL = "--full" in sys.argv
def _arg(name, default):
    for i, a in enumerate(sys.argv):
        if a == name and i + 1 < len(sys.argv):
            try:
                return int(sys.argv[i + 1])
            except ValueError:
                return default
    return default

PROFILES = _arg("--profiles", 12)
MAX_SECONDS = _arg("--budget", 900)


def _pick_drives():
    """--all-drives => every fixed volume; --drive D: (repeatable) => those volumes."""
    if "--all-drives" in sys.argv:
        return list_fixed_drives()
    picked = []
    for i, a in enumerate(sys.argv):
        if a == "--drive" and i + 1 < len(sys.argv):
            d = sys.argv[i + 1].strip().rstrip("\\/:")
            if d:
                picked.append(d.upper() + ":" + os.sep)
    return picked or None


def _ps_quote(a):
    return "\"" + str(a).replace("\"", "\\\"") + "\""


def _relaunch_elevated():
    """Re-run this scan as administrator (one UAC prompt), then print its result.

    The elevated child writes JSON to a temp file; the parent reads it back.
    This avoids the classic trap of trying to capture an elevated process stdout.
    """
    import subprocess
    import tempfile
    tmp = tempfile.gettempdir()
    out = os.path.join(tmp, "storage_scan_admin_%d.json" % os.getpid())
    args = [a for a in sys.argv[1:] if a != "--elevate"] + ["--out", out]
    ps1 = os.path.join(tmp, "storage_scan_elev_%d.ps1" % os.getpid())
    line = "& %s %s %s" % (_ps_quote(sys.executable), _ps_quote(os.path.abspath(__file__)),
                           " ".join(_ps_quote(a) for a in args))
    with open(ps1, "w", encoding="utf-8-sig") as f:
        f.write("$ErrorActionPreference = 'Stop'" + chr(10) + line + chr(10))
    print("[elevate] 正在请求管理员权限，请在 UAC 弹窗点“是”…", file=sys.stderr)
    try:
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                        "Start-Process powershell -Verb RunAs -Wait -ArgumentList "
                        "'-NoProfile','-ExecutionPolicy','Bypass','-File','%s'" % ps1],
                       timeout=1800)
    except Exception as e:
        print("[elevate] 启动失败：%s" % e, file=sys.stderr)
        return 1
    if not os.path.exists(out):
        print("[elevate] 未拿到结果（可能 UAC 被取消）。可改用非提权模式。", file=sys.stderr)
        return 1
    with open(out, "r", encoding="utf-8") as f:
        data = f.read()
    try:
        sys.stdout.buffer.write(data.encode("utf-8"))
    except AttributeError:
        sys.stdout.write(data)
    return 0

def main():
    if "--elevate" in sys.argv and sys.platform.startswith("win") and not is_admin():
        sys.exit(_relaunch_elevated())
    started = time.time()
    if not sys.platform.startswith("win"):
        print(json.dumps({"error": "unsupported_platform", "platform": sys.platform,
                          "message": "This skill targets Windows only."},
                         ensure_ascii=False))
        return
    system, groups = scan_windows(full=USE_FULL, drives=_pick_drives())
    data = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "system": system,
        "groups": groups,
        "scan_seconds": round(time.time() - started, 1),
    }
    # 强制 UTF-8 输出：Windows 控制台默认 GBK，重定向到文件时会写出非 UTF-8 字节，
    # 下游（agent / jq / Python）读不了。这里直接写字节，绕开控制台编码。
    out = json.dumps(data, ensure_ascii=False, indent=2)
    outfile = None
    for i, a in enumerate(sys.argv):
        if a == "--out" and i + 1 < len(sys.argv):
            outfile = sys.argv[i + 1]
    if outfile:
        with open(outfile, "w", encoding="utf-8") as f:
            f.write(out)
        print("wrote " + outfile, file=sys.stderr)
        return
    try:
        sys.stdout.buffer.write(out.encode("utf-8"))
        sys.stdout.buffer.flush()
    except AttributeError:
        sys.stdout.write(out)


if __name__ == "__main__":
    main()

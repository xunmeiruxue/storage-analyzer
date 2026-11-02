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


# 扩展名 -> 内容类型。占比超过 50% 才认，否则算混合。
EXT_GROUPS = {
    "video": {"mp4", "mkv", "mov", "avi", "flv", "wmv", "m4v", "ts", "webm", "rmvb"},
    "image": {"jpg", "jpeg", "png", "gif", "bmp", "heic", "webp", "tif", "tiff",
              "raw", "cr2", "nef", "arw"},
    "audio": {"mp3", "wav", "flac", "m4a", "aac", "ogg", "ape"},
    "archive": {"zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab"},
    "disk_image": {"iso", "wim", "esd", "img", "vhd", "vhdx", "vmdk", "qcow2", "ova"},
    "documents": {"doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "txt", "md",
                  "rtf", "odt", "csv", "epub"},
    "code": {"py", "js", "ts", "jsx", "tsx", "java", "cs", "go", "rs", "c", "cpp",
             "h", "hpp", "json", "xml", "yml", "yaml", "html", "css"},
    "app": {"exe", "dll", "sys", "msi", "msix", "appx", "cab"},
    "model": {"gguf", "onnx", "safetensors", "pt", "pth", "ckpt"},
}

# 出现这些名字，说明这个目录很可能是"另一个盘的根目录拷贝"
OS_MARKERS = {"windows", "program files", "program files (x86)", "users",
              "programdata", "perflogs", "recovery", "boot", "bootmgr",
              "pagefile.sys", "hiberfil.sys", "swapfile.sys"}
ROOT_MARKERS = {"$recycle.bin", "system volume information"}
CACHE_NAMES = {"cache", "caches", "gpucache", "code cache", "shadercache", "tmp",
               "temp", "crashpad", "logs", "node_modules", "__pycache__", ".cache",
               "cache2", "thumbnails"}


def _scan_one_level(path, size_index):
    """读一层：自己的文件按扩展名汇总，子目录按 index 取大小。"""
    ext_bytes, ext_count = {}, {}
    biggest, subdirs, names = [], [], []
    own = 0
    try:
        with os.scandir(_long(path)) as it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                except (PermissionError, OSError):
                    continue
                if _is_reparse(st):
                    continue
                names.append(e.name)
                if e.is_dir(follow_symlinks=False):
                    subdirs.append((size_index.get(e.path, 0), e.path))
                    continue
                k = _ext(e.name)
                own += st.st_size
                ext_bytes[k] = ext_bytes.get(k, 0) + st.st_size
                ext_count[k] = ext_count.get(k, 0) + 1
                biggest.append((st.st_size, e.path))
    except (PermissionError, OSError) as ex:
        return None, str(ex)
    biggest.sort(key=lambda x: -x[0])
    subdirs.sort(key=lambda x: -x[0])
    return {
        "own": own,
        "sub": sum(s for s, _ in subdirs),
        "ext_bytes": ext_bytes,
        "ext_count": ext_count,
        "biggest": biggest,
        "subdirs": subdirs,
        "names": names,
    }, None


def _classify(stats):
    """给目录打一个内容类型 + 若干 flags。只是初判，最终由分析者核实。"""
    ext_bytes = stats["ext_bytes"]
    total = sum(ext_bytes.values())
    kind, share = "mixed", 0.0
    if total > 0:
        for k, exts in EXT_GROUPS.items():
            b = sum(v for e, v in ext_bytes.items() if e in exts)
            r = b / total
            if r > share:
                share, kind = r, k
        if share < 0.5:
            kind = "mixed"

    low = {n.lower() for n in stats["names"]}
    flags = []
    if len(low & OS_MARKERS) >= 2:
        flags.append("disk_clone")
    if low & ROOT_MARKERS:
        flags.append("drive_root_copy")
    if "sources" in low or "boot" in low:
        flags.append("os_image_candidate")
    if low & CACHE_NAMES:
        flags.append("cache_dir")
    if kind == "disk_image" and share >= 0.6:
        flags.append("system_image")
    return kind, round(share, 3), flags


HOMOGENEOUS = ("video", "image", "audio", "archive", "disk_image", "app")


def profile_tree(path, size_index, depth, ctx):
    """递归内容画像：一层不够就往下看，直到类型单一 / 太小 / 到深度上限。

    设计取舍：
      - 只看"最大的几个子目录"往下钻（branch 默认 4），不铺开整棵树；
      - 单一类型的目录（比如整层 mp4）到 85% 就停，再钻也是同类；
      - 命中 disk_clone / os_image 的目录**继续往下钻**，因为整盘备份里
        往往还套着缓存目录、镜像文件，浅看会漏掉。
      - 全局 profile 数量有上限（cap），防止 JSON 爆炸。
    """
    stats, err = _scan_one_level(path, size_index)
    if stats is None:
        return {"path": path, "error": err}

    kind, share, flags = _classify(stats)
    own, sub = stats["own"], stats["sub"]
    node = {
        "path": path,
        "depth": depth,
        "bytes": size_index.get(path, own + sub),
        "own_bytes": own,
        "subdir_bytes": sub,
        "kind": kind,
        "kind_share": share,
        "flags": flags,
        "ext": [[k, v, stats["ext_count"].get(k, 0)]
                for k, v in sorted(stats["ext_bytes"].items(), key=lambda x: -x[1])[:6]],
        "top_files": [[sz, p] for sz, p in stats["biggest"][:3]],
        "top_subdirs": [[sz, p] for sz, p in stats["subdirs"][:5]],
        "children": [],
    }
    ctx["count"] += 1

    if depth >= ctx["max_depth"] or ctx["count"] >= ctx["cap"]:
        return node
    if sub < ctx["min_bytes"]:
        return node
    if kind in HOMOGENEOUS and share >= 0.85 and "disk_clone" not in flags:
        return node

    for sz, child in stats["subdirs"][:ctx["branch"]]:
        if ctx["count"] >= ctx["cap"]:
            break
        if sz < ctx["min_bytes"]:
            continue
        node["children"].append(profile_tree(child, size_index, depth + 1, ctx))
    return node


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
                     profile_min_mb=512, drill_depth=3, drill_min_mb=512,
                     drill_branch=4, drill_max=150):
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
        # 去重：如果某个候选已经在另一个候选的子树里，就不再单列，避免同一棵子树重复出现
        picked.sort(key=lambda d: (len(d[0]), d[0]))
        roots = []
        for d in picked:
            if any(d[0].lower() == r.lower() or d[0].lower().startswith(r.lower() + os.sep)
                   for r in roots):
                continue
            roots.append(d[0])
        picked = [d for d in picked if d[0] in roots]

        ctx = {"max_depth": drill_depth,
               "min_bytes": int(drill_min_mb * 1024 * 1024),
               "branch": drill_branch,
               "cap": drill_max,
               "count": 0}
        for d in picked:
            node = profile_tree(d[0], size_index, 0, ctx)
            node["files"] = d[3]
            prof.append(node)

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
            data = full_volume_scan(drive, profiles=PROFILES, max_seconds=remain,
                            drill_depth=DRILL, drill_min_mb=DRILL_MIN,
                            drill_branch=DRILL_BRANCH, drill_max=DRILL_MAX)
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
DRILL = _arg("--drill", 3)              # 内容画像往下钻几层
DRILL_MIN = _arg("--drill-min", 512)      # 小于这个（MB）的分支不钻
DRILL_BRANCH = _arg("--drill-branch", 4)  # 每个节点最多钻几个子目录
DRILL_MAX = _arg("--drill-max", 150)      # 画像总数上限
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
        "schema": {
            "dirs": ["path", "depth", "bytes", "files"],
            "big_files": ["bytes", "path"],
            "profiles": {
                "path": "绝对路径", "depth": "相对选中的顶层目录的层数",
                "bytes": "该目录总大小", "own_bytes": "自己文件占的", "subdir_bytes": "子目录占的",
                "kind": "内容类型（video/image/archive/disk_image/vm/documents/code/app/model/mixed）",
                "kind_share": "主类型的字节占比",
                "flags": ["disk_clone 整盘拷贝", "os_image_candidate 安装镜像", "drive_root_copy 盘根拷贝", "cache_dir 缓存目录", "system_image 镜像文件"],
                "ext": ["ext", "bytes", "count"],
                "top_files": ["bytes", "path"],
                "top_subdirs": ["bytes", "path"],
                "children": "结构同 profiles 元素，递归下钻",
            },
        },
        "scan_scope": {
            "groups": "当前用户目录速览（固定取 USERPROFILE/LOCALAPPDATA 等），与 --drive 无关",
            "full_scans": "盘级扫描结果数组，--drive / --all-drives 生效的位置",
            "full_scan": "full_scans[0] 的别名，兼容旧调用",
        },
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

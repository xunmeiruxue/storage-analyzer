#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect which disk-usage tools are installed. Read-only, never launches them.

    python3 scripts/detect_tools.py            # human summary
    python3 scripts/detect_tools.py --json     # machine readable (used by the agent)

Why: 选扫描工具前必须先确认"这台机器装了什么"，不能假设。
探测顺序：PATH -> 常见安装目录 -> 注册表卸载项 -> 开始菜单快捷方式（仅作线索）。
"""
import glob
import json
import os
import shutil
import sys

TOOLS = {
    "TreeSize": {
        "rank": 1,
        "needs_admin": False,
        "kind": "disk-analyzer",
        "exe_names": ["treesize.exe", "treesize free.exe"],
        "patterns": [
            r"%ProgramFiles%\JAM Software\TreeSize*\TreeSize.exe",
            r"%ProgramFiles(x86)%\JAM Software\TreeSize*\TreeSize.exe",
            r"%LOCALAPPDATA%\Programs\TreeSize*\TreeSize.exe",
            r"%ProgramFiles%\TreeSize*\TreeSize.exe",
            r"%ProgramFiles(x86)%\TreeSize*\TreeSize.exe",
        ],
        "cmd": '"{exe}" /SCAN "{drive}" /CSV "{out}" /EXPAND 6',
        "note": "最快且免提权；/EXPAND n 决定导出深度，默认只出 1 层，必须显式给 6",
    },
    "WizTree": {
        "rank": 2,
        "needs_admin": True,
        "kind": "disk-analyzer",
        "exe_names": ["wiztree.exe", "wiztree64.exe"],
        "patterns": [
            r"%ProgramFiles%\WizTree\WizTree64.exe",
            r"%ProgramFiles(x86)%\WizTree\WizTree64.exe",
            r"%ProgramFiles%\WizTree\WizTree.exe",
            r"%USERPROFILE%\scoop\apps\wiztree\current\WizTree64.exe",
            r"C:\Program Files\WizTree\WizTree64.exe",
        ],
        "cmd": '"{exe}" /path="{drive}" /export="{out}" /exportfolders /admin=0 /noopen',
        "note": "读 MFT 最快，但必须管理员；非管理员会静默产出 0 字节文件",
    },
    "Everything": {
        "rank": 3,
        "needs_admin": False,
        "kind": "file-index",
        "exe_names": ["everything.exe", "es.exe"],
        "patterns": [
            r"%ProgramFiles%\Everything\Everything.exe",
            r"%ProgramFiles(x86)%\Everything\Everything.exe",
            r"%ProgramFiles%\Everything\es.exe",
            r"%USERPROFILE%\scoop\apps\everything\current\es.exe",
        ],
        "cmd": '"{exe}" -export-csv "{out}" -path "{drive}"',
        "note": "只索引文件名、不做目录大小汇总，只适合点查大文件/找路径",
    },
}


def expand(p):
    return os.path.expandvars(os.path.expanduser(p))


def _which(names):
    for n in names:
        w = shutil.which(n)
        if w:
            return os.path.abspath(w)
    return None


def _glob_any(patterns, exe_names):
    for pat in patterns:
        try:
            hits = glob.glob(expand(pat))
        except Exception:
            continue
        for h in hits:
            if os.path.isfile(h) and os.path.basename(h).lower() in exe_names:
                return os.path.abspath(h)
    return None


def _registry_hits(keywords):
    """InstallLocation from Uninstall keys whose DisplayName matches."""
    if not sys.platform.startswith("win"):
        return []
    out = []
    try:
        import winreg
    except Exception:
        return out
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, path in roots:
        try:
            key = winreg.OpenKey(hive, path)
        except Exception:
            continue
        for i in range(0, 1024):
            try:
                sub = winreg.EnumKey(key, i)
            except OSError:
                break
            try:
                sk = winreg.OpenKey(key, sub)
                name = winreg.QueryValueEx(sk, "DisplayName")[0]
            except Exception:
                continue
            low = str(name).lower()
            if any(k.lower() in low for k in keywords):
                try:
                    loc = winreg.QueryValueEx(sk, "InstallLocation")[0]
                except Exception:
                    loc = ""
                out.append({"name": name, "location": loc})
    return out


def _start_menu_hits(keywords):
    if not sys.platform.startswith("win"):
        return []
    dirs = [
        os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs"),
        os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs"),
    ]
    hits = []
    for d in dirs:
        if not d or not os.path.isdir(d):
            continue
        for root, _, files in os.walk(d):
            for f in files:
                if f.lower().endswith(".lnk") and any(k.lower() in f.lower() for k in keywords):
                    hits.append(os.path.join(root, f))
    return hits


def detect():
    result = {"os": sys.platform, "tools": []}
    for name, spec in TOOLS.items():
        found, source = None, None
        w = _which(spec["exe_names"])
        if w:
            found, source = w, "PATH"
        if not found:
            g = _glob_any(spec["patterns"], spec["exe_names"])
            if g:
                found, source = g, "common-path"
        if not found:
            for hit in _registry_hits([name]):
                loc = hit.get("location") or ""
                if loc and os.path.isdir(loc):
                    for f in os.listdir(loc):
                        if f.lower() in spec["exe_names"]:
                            found, source = os.path.join(loc, f), "registry"
                            break
                if found:
                    break
        entry = {
            "name": name,
            "found": bool(found),
            "exe": found,
            "source": source,
            "rank": spec["rank"],
            "needs_admin": spec["needs_admin"],
            "kind": spec["kind"],
            "note": spec["note"],
        }
        if found:
            entry["cmd_template"] = spec["cmd"].format(exe=found, drive="{drive}", out="{out}")
        elif _start_menu_hits([name]):
            entry["shortcut_only"] = True
        result["tools"].append(entry)
    ranked = [t for t in result["tools"] if t["found"]]
    ranked.sort(key=lambda t: t["rank"])
    analyzers = [t for t in ranked if t["kind"] == "disk-analyzer"]
    result["recommended"] = analyzers[0]["name"] if analyzers else None
    result["python_ok"] = sys.version_info >= (3, 8)
    return result


def main():
    r = detect()
    if "--json" in sys.argv:
        out = json.dumps(r, ensure_ascii=False, indent=2)
        try:
            sys.stdout.buffer.write(out.encode("utf-8"))
        except AttributeError:
            sys.stdout.write(out)
        return
    print("OS:", r["os"])
    for t in r["tools"]:
        mark = "OK " if t["found"] else "-- "
        extra = t["exe"] if t["found"] else ("(only a Start Menu shortcut)" if t.get("shortcut_only") else "")
        admin = " [needs admin]" if t["needs_admin"] else ""
        print("%s%-11s %s%s" % (mark, t["name"], extra, admin))
    print("recommended:", r["recommended"] or "none -> fall back to scripts/scan.py")


if __name__ == "__main__":
    main()

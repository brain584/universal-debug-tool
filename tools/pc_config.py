#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""pc_config.py —— ATrace 电脑端工具的共享配置与自动探测。

为什么需要它：原来的脚本把 python / adb / 端口 都当"现成就在 PATH 里"，
换一台电脑就全废。这里统一做三件事：

  1. **自动探测** python / adb 的常见安装位置（PATH、ANDROID_HOME、
     LOCALAPPDATA\Android\Sdk、C:\\platform-tools、常见 Python 安装目录、conda…）；
  2. 探测不到就**问用户要路径**（支持把文件直接拖进窗口，自动去引号），
     并校验文件确实存在、能执行；
  3. 把结果存进脚本旁边的 **pc_config.ini**（key=value，批处理也能读），
     下次直接复用；换了电脑只要探测/输入一次。

配置项：
    adb        adb 可执行文件路径（留空=自动探测）
    port       adb 转发端口，默认 28471
    ide        电脑端 IDE 启动命令，{file} 为占位符（留空=自动探测）
    last_file  上次编辑/执行的脚本路径（便于直接再跑一次）
    python     Python 解释器路径（**由 .bat 写入**，给批处理直接用）
"""

import json
import os
import shutil
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(SCRIPT_DIR, "pc_config.ini")

DEFAULT_PORT = 28471

# ------------------------------------------------------------------ 配置文件

def load_config():
    cfg = {}
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    except Exception as e:
        sys.stderr.write("[pc_config] 读取配置失败: %s\n" % e)
    return cfg


def save_config(cfg):
    """写回配置；只保留已知键，顺序固定，便于人肉查看/手改。

    注意：**文件内容保持纯 ASCII**（注释也用英文）——因为 `atrace_lua.bat`
    也会用 `for /f` 读这个文件，而 cmd.exe 是按系统 ANSI 代码页读的，
    写 UTF-8 中文注释虽然不影响解析，但会让批处理里的回显变成乱码。
    """
    order = ["python", "adb", "port", "ide", "last_file"]
    lines = ["# ATrace PC config (edit by hand is fine; delete this file to re-detect)"]
    for k in order:
        if k in cfg and cfg[k] not in (None, ""):
            lines.append("%s=%s" % (k, cfg[k]))
    for k, v in cfg.items():
        if k not in order and v not in (None, ""):
            lines.append("%s=%s" % (k, v))
    try:
        with open(CONFIG_PATH, "w", encoding="ascii", errors="replace") as f:
            f.write("\n".join(lines) + "\n")
        return True
    except Exception as e:
        sys.stderr.write("[pc_config] 写配置失败: %s\n" % e)
        return False


def set_config(**kw):
    cfg = load_config()
    cfg.update({k: str(v) for k, v in kw.items() if v is not None})
    return save_config(cfg)


# ------------------------------------------------------------------ 路径工具

def _strip_quotes(p):
    if not p:
        return ""
    p = p.strip()
    if len(p) >= 2 and p[0] == '"' and p[-1] == '"':
        p = p[1:-1]
    return p.strip()


def _is_exe(p):
    return bool(p) and os.path.isfile(p)


# ------------------------------------------------------------------ adb 探测

def _adb_candidates():
    cands = []
    # 1) PATH
    for n in ("adb", "adb.exe"):
        w = shutil.which(n)
        if w:
            cands.append(w)
    # 2) 环境变量指向的 SDK
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.environ.get(env)
        if root:
            cands.append(os.path.join(root, "platform-tools", "adb.exe"))
    # 3) 默认安装位置
    local = os.environ.get("LOCALAPPDATA", "")
    user = os.environ.get("USERPROFILE", "")
    if local:
        cands.append(os.path.join(local, "Android", "Sdk", "platform-tools", "adb.exe"))
    if user:
        cands.append(os.path.join(user, "AppData", "Local", "Android", "Sdk",
                                  "platform-tools", "adb.exe"))
    cands += [
        r"C:\platform-tools\adb.exe",
        r"C:\adb\adb.exe",
        r"C:\Android\platform-tools\adb.exe",
        r"D:\Android\Sdk\platform-tools\adb.exe",
        "/usr/bin/adb", "/usr/local/bin/adb",
    ]
    # 4) 常见工具目录下带 platform-tools 的（扫一层盘符根目录，成本很低）
    for drive in ("C:", "D:", "E:", "F:"):
        try:
            if os.path.isdir(drive + "\\"):
                cands.append(drive + r"\platform-tools\adb.exe")
                cands.append(drive + r"\Android\Sdk\platform-tools\adb.exe")
        except Exception:
            pass
    # 去重保序
    seen, out = set(), []
    for c in cands:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def find_adb(user_adb=None, interactive=True):
    """返回可用的 adb 路径；顺序：显式参数 → 配置 → 自动探测 → 询问用户。"""
    if user_adb and _is_exe(_strip_quotes(user_adb)):
        return _strip_quotes(user_adb)

    cfg = load_config()
    if _is_exe(cfg.get("adb", "")):
        return cfg["adb"]

    for c in _adb_candidates():
        if _is_exe(c):
            # 探测到就记住，下次不用再找
            set_config(adb=c)
            return c

    if not interactive:
        return None

    print("[!] 没找到 adb。")
    print("    可以：① 把 adb.exe 用鼠标拖进这个窗口；② 直接粘贴完整路径；③ 回车跳过（不写死了）")
    for _ in range(5):
        try:
            p = _strip_quotes(input("adb 路径> "))
        except (EOFError, KeyboardInterrupt):
            return None
        if not p:
            return None
        if _is_exe(p):
            set_config(adb=p)
            print("[+] 已记住 adb 路径: %s" % p)
            return p
        # 也许给的是目录
        cand = os.path.join(p, "adb.exe")
        if _is_exe(cand):
            set_config(adb=cand)
            print("[+] 已记住 adb 路径: %s" % cand)
            return cand
        print("[!] 这个路径不存在或不是文件，请重试：%s" % p)
    return None


# ------------------------------------------------------------------ python 探测

def _python_candidates():
    cands = []
    for n in ("python", "python3", "python.exe"):
        w = shutil.which(n)
        if w:
            # 排除 Microsoft Store 的占位 stub（运行会弹商店）
            if "WindowsApps" not in w:
                cands.append(w)
    # py 启动器：拿到它背后的真实路径
    try:
        r = subprocess.run(["py", "-3", "-c",
                            "import sys;print(sys.executable)"],
                           capture_output=True, text=True, timeout=15)
        if r.returncode == 0 and r.stdout.strip():
            cands.insert(0, r.stdout.strip())
    except Exception:
        pass
    local = os.environ.get("LOCALAPPDATA", "")
    user = os.environ.get("USERPROFILE", "")
    prog = os.environ.get("ProgramFiles", r"C:\Program Files")
    if local:
        p = os.path.join(local, "Programs", "Python")
        if os.path.isdir(p):
            for d in sorted(os.listdir(p), reverse=True):
                cands.append(os.path.join(p, d, "python.exe"))
    for ver in ("313", "312", "311", "310", "39"):
        cands.append(r"C:\Python%s\python.exe" % ver)
        cands.append(os.path.join(prog, "Python%s" % ver, "python.exe"))
    for conda in ("anaconda3", "miniconda3", "Anaconda3", "Miniconda3"):
        if user:
            cands.append(os.path.join(user, conda, "python.exe"))
    seen, out = set(), []
    for c in cands:
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def find_python(interactive=True):
    cfg = load_config()
    if _is_exe(cfg.get("python", "")):
        return cfg["python"]
    for c in _python_candidates():
        if _is_exe(c):
            return c
    if not interactive:
        return None
    print("[!] 没找到 Python 3。")
    print("    可以：① 把 python.exe 拖进窗口；② 粘贴完整路径；③ 回车跳过")
    for _ in range(5):
        try:
            p = _strip_quotes(input("python 路径> "))
        except (EOFError, KeyboardInterrupt):
            return None
        if not p:
            return None
        if _is_exe(p):
            set_config(python=p)
            return p
        print("[!] 路径不存在，请重试：%s" % p)
    return None


# ------------------------------------------------------------------ 端口

def resolve_port(cli_port=None):
    if cli_port:
        return int(cli_port)
    cfg = load_config()
    try:
        return int(cfg.get("port", DEFAULT_PORT))
    except Exception:
        return DEFAULT_PORT


# ------------------------------------------------------------------ 杂项

def adb_forward(adb, port):
    """adb forward tcp:port tcp:port —— 电脑连手机的必需一步。"""
    if not adb:
        return False, "找不到 adb"
    try:
        r = subprocess.run([adb, "forward", "tcp:%d" % port, "tcp:%d" % port],
                           capture_output=True, text=True, timeout=25)
    except Exception as e:
        return False, str(e)
    if r.returncode != 0:
        return False, (r.stdout or "") + (r.stderr or "")
    return True, ""

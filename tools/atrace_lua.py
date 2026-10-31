#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""atrace_lua.py —— 用电脑的 cmd 编辑/执行手机目标进程里的 Lua 脚本。

=============================== 它解决什么问题 ===============================
ATrace 的脚本页要在手机上开悬浮窗才能编辑。这个脚本让**电脑 cmd 就能改脚本并执行**：

    手机(USB 调试) ──adb forward tcp:<port>──> App 内的 loopback 服务
                                                   │
                                                   └─ App 用自己已注入的 agent 通道执行 Lua

手机上**不需要打开悬浮窗**，App 在后台跑着就行。

=============================== 换电脑也不用改代码 ===========================
python / adb / 端口 / IDE 命令都会：
  ① 自动探测（PATH、ANDROID_HOME、LOCALAPPDATA\\Android\\Sdk、常见 Python 目录…）
  ② 探测不到就**问你要路径**（支持把文件拖进窗口）
  ③ 记住到同目录的 `pc_config.ini`，下次直接用
删掉 `pc_config.ini` 就恢复全新自动探测。

=============================== 两种编辑方式 =================================
1) 电脑装了 IDE：拉起来编辑临时文件，改完回来确认就自动回传并执行。
   启动命令可自定义（`i` 命令），支持 {file} 占位符；留空则自动探测。
2) 没 IDE：直接在 cmd 里逐行输入，单独一行 `.` 结束。

=============================== 用法 ========================================
    python atrace_lua.py                     # 交互模式（推荐先跑这个）
    python atrace_lua.py demo.lua            # 直接推上去并执行（拖拽 .bat 也行）
    python atrace_lua.py demo.lua --edit     # 用 IDE 编辑后再执行
    python atrace_lua.py --port 28471
    python atrace_lua.py --show-config        # 看当前配置/探测结果
    python atrace_lua.py --reset-config       # 清掉配置文件

交互命令（输入 h 再看一遍）：
    e / edit        用 IDE 编辑当前脚本，然后执行
    t / type        在 cmd 里逐行重写脚本，然后执行
    r / run         直接执行手机上的当前草稿
    v / view        查看手机上的当前草稿
    p / push FILE   把本地文件上传成手机草稿
    g / pull FILE   把手机草稿保存到本地文件
    l / logs        重新拉一次 Lua print 日志
    i / ide [CMD]   查看/设置 IDE 启动命令
    cfg             显示配置与自动探测结果
    info            连接与设备信息
    q / quit        退出
"""

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

# Windows 控制台默认代码页常是 936(GBK)，直接输出 UTF-8 中文会乱码。
if sys.platform == "win32":
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pc_config  # noqa: E402  同目录的共享配置/探测模块


# ---------------------------------------------------------------- 协议实现

class BridgeError(Exception):
    pass


class Bridge:
    """与手机 App 的行式协议客户端（命令 + 长度分帧载荷）。"""

    def __init__(self, port, timeout=60.0):
        # 60s：首次执行 Lua / 重新连 agent 后，手机端可能要等引擎就绪
        # （run_lua 内部会 sleep 1.2s 再取日志；重连后偶发更慢），20s 会误报超时。
        self.port = port
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.f = self.sock.makefile("rb")

    def _read_line(self):
        line = self.f.readline()
        if not line:
            raise BridgeError("连接被手机端关闭")
        return line.decode("utf-8", "replace").rstrip("\r\n")

    def _read_exact(self, n):
        data = b""
        while len(data) < n:
            chunk = self.f.read(n - len(data))
            if not chunk:
                raise BridgeError("读取载荷时连接中断")
            data += chunk
        return data

    def _recv(self):
        head = self._read_line()
        if head not in ("OK", "ERR"):
            raise BridgeError("协议错误，期望 OK/ERR，收到: %r" % head)
        length = int(self._read_line())
        payload = self._read_exact(length).decode("utf-8", "replace")
        if head == "ERR":
            raise BridgeError(payload)
        return payload

    def cmd(self, name):
        self.sock.sendall((name + "\n").encode("utf-8"))
        return self._recv()

    def cmd_payload(self, name, text):
        body = text.encode("utf-8")
        self.sock.sendall((name + "\n" + str(len(body)) + "\n").encode("utf-8") + body)
        return self._recv()

    def close(self):
        try:
            self.cmd("QUIT")
        except Exception:
            pass
        try:
            self.f.close()
            self.sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------- IDE 相关

# 自动探测候选。用文件存在性判断，不依赖 PATH。
IDE_CANDIDATES = [
    # (命令模板, 探测用的可执行文件候选列表)
    ('code --wait -n "{file}"', [
        "code", "code.cmd",
        os.path.join(os.environ.get("LOCALAPPDATA", ""),
                     r"Programs\Microsoft VS Code\bin\code.cmd"),
        r"C:\Program Files\Microsoft VS Code\bin\code.cmd",
        r"C:\Program Files (x86)\Microsoft VS Code\bin\code.cmd",
    ]),
    ('notepad++ "{file}"', [
        r"C:\Program Files\Notepad++\notepad++.exe",
        r"C:\Program Files (x86)\Notepad++\notepad++.exe",
        "notepad++",
    ]),
    ('subl -n -w "{file}"', [
        r"C:\Program Files\Sublime Text\sublime_text.exe",
        r"C:\Program Files\Sublime Text 3\sublime_text.exe",
        "subl",
    ]),
    ('notepad "{file}"', ["notepad"]),      # Windows 自带，兜底（会阻塞到关闭）
]


def _exe_ok(x):
    if not x:
        return False
    if os.path.isabs(x):
        return os.path.isfile(x)
    return shutil.which(x) is not None


def detect_ide():
    """返回自动探测到的 IDE 命令（含 {file}），没有则 None。"""
    for cmd, probes in IDE_CANDIDATES:
        for p in probes:
            if _exe_ok(p):
                return cmd
    return None


def resolve_ide_cmd(phone_cmd):
    """优先级：手机端显式配置 → 本机自动探测 → None（走 cmd 行编辑）。"""
    if phone_cmd.strip():
        return phone_cmd.strip()
    return detect_ide()


def build_editor_argv(ide_cmd, file_path):
    if "{file}" in ide_cmd:
        return ide_cmd.replace("{file}", file_path)
    return ide_cmd + " \"" + file_path + "\""


def edit_with_ide(ide_cmd, current_text):
    """用电脑的 IDE 编辑脚本。返回改后的文本（取消返回 None）。

    等待策略（重要）：
      · `code --wait` / `notepad` 这类会阻塞到窗口关闭 → 自动继续，不用按回车；
      · VS Code 不带 --wait、Notepad++ 默认等**会立刻返回**（把文件交给已有窗口），
        此时退化为"请按回车确认"。
    """
    fd, path = tempfile.mkstemp(suffix=".lua", prefix="atrace_")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as f:
        f.write(current_text)

    argv = build_editor_argv(ide_cmd, path)
    print("[*] 拉起编辑器: %s" % argv)
    try:
        proc = subprocess.Popen(argv, shell=True)
    except Exception as e:
        print("[!] 拉起编辑器失败: %s" % e)
        print("[*] 退回 cmd 行编辑。")
        try:
            os.unlink(path)
        except OSError:
            pass
        return None

    # 先给 2 秒判断这个编辑器是"阻塞型"还是"立刻返回型"
    blocking = True
    t0 = time.time()
    while time.time() - t0 < 2.0:
        if proc.poll() is not None:
            blocking = False
            break
        time.sleep(0.1)

    if blocking:
        # 阻塞型（code --wait / notepad）：关掉编辑器就自动继续，不需要按回车
        print("[*] 编辑器已打开。改完**关闭它**就会自动继续…")
        while proc.poll() is None:
            time.sleep(0.3)
    else:
        # 立刻返回型（VS Code 不带 --wait、Notepad++）：让用户回车确认
        print("[*] 这个编辑器会立刻返回（把文件交给已有窗口）。")
        print("[*] 改完后**回到本窗口按回车**，脚本会自动回传并执行。")
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            pass

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return text


def edit_in_cmd(current_text):
    """没有 IDE 时的回退：在 cmd 里逐行写脚本，单独一行 `.` 结束。"""
    print()
    print("---- cmd 行编辑模式 ----")
    print("逐行输入 Lua，单独一行 `.` 结束（:show 查看当前草稿、:clear 清空、:cancel 取消）")
    if current_text.strip():
        print("---- 当前草稿（输入 :clear 可清空）----")
        for i, line in enumerate(current_text.splitlines(), 1):
            print("%4d | %s" % (i, line))
        print("--------------------------------------")
    buf = []
    while True:
        try:
            line = input()
        except (EOFError, KeyboardInterrupt):
            print("\n[!] 已取消")
            return None
        if line == ".":
            break
        if line == ":show":
            for i, l in enumerate(buf, 1):
                print("%4d | %s" % (i, l))
            continue
        if line == ":clear":
            buf = []
            print("[*] 已清空输入缓冲")
            continue
        if line == ":cancel":
            print("[*] 已取消")
            return None
        buf.append(line)
    return "\n".join(buf) + "\n"


# ---------------------------------------------------------------- 主流程

def show_help():
    print("""
命令：
  e / edit        用 IDE 编辑当前脚本，然后执行
  t / type        在 cmd 里逐行重写脚本，然后执行
  r / run         直接执行手机上的当前草稿
  v / view        查看手机上的当前草稿
  p / push FILE   把本地文件上传成手机草稿
  g / pull FILE   把手机草稿保存到本地文件
  l / logs        重新拉一次 Lua print 日志
  i / ide [CMD]   查看/设置 IDE 启动命令（CMD 里用 {file} 占位）
  cfg             显示配置与自动探测结果
  info            连接与设备信息
  q / quit        退出
""")


def print_info(br):
    info = br.cmd("INFO")
    for line in info.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            print("  %-16s %s" % (k, v))
        else:
            print("  " + line)


def print_cfg(adb, port):
    cfg = pc_config.load_config()
    print("  配置文件      %s" % pc_config.CONFIG_PATH)
    print("  python        %s" % (cfg.get("python") or sys.executable))
    print("  adb           %s" % (adb or "(未找到)"))
    print("  port          %d" % port)
    print("  手机端 IDE     %s" % (cfg.get("ide") or "(空=电脑自动探测)"))
    print("  本机探测 IDE   %s" % (detect_ide() or "(无)"))


def connect(port):
    br = Bridge(port)
    pong = br.cmd("PING")
    if pong != "pong":
        raise BridgeError("握手异常: %r" % pong)
    return br


def run_remote(br, text):
    """上传并执行（自动处理占位符与草稿备份）。

    特殊占位符（在发送前替换，省得每次重新注入后手改脚本）：
        {{AGENT}}  → 当前注入 so（memfd）的完整路径，例如 "/memfd:il815h3u (deleted)"
    用法：
        local a = getBase("{{AGENT}}")

    占位符解析不了时**不会**上传（避免把无效文本写进手机草稿）。
    返回执行结果文本；失败时抛 BridgeError。
    """
    ok, final = push_text(br, text)
    if not ok:
        raise BridgeError("占位符无法解析，已取消执行（手机草稿未被改动）")
    return br.cmd_payload("RUN_SCRIPT", final)


def agent_module_path(br):
    """从手机的模块列表里找出注入的 agent（memfd 那条），找不到返回 None。"""
    try:
        mods = br.cmd("LIST_MODULES")
    except Exception:
        return None
    for line in mods.splitlines():
        line = line.strip()
        if "/memfd:" in line:
            # 行格式： "0x1234abcd  /memfd:xxxx (deleted)"
            idx = line.find("/memfd:")
            return line[idx:].strip()
    return None


def expand_placeholders(br, text):
    """展开 {{AGENT}} / {{MODULES}}。

    返回 (新文本, 是否全部解析成功)。
    **重要**：解析失败时调用方必须放弃上传，否则会把带字面量 {{AGENT}} 的
    无效脚本写进手机草稿，覆盖用户正在编辑的内容（2026-10-23 踩过这个坑）。
    """
    ok = True
    if "{{MODULES}}" in text:
        try:
            text = text.replace("{{MODULES}}", br.cmd("LIST_MODULES"))
        except Exception as e:
            print("[!] 取模块列表失败: %s" % e)
            ok = False
    if "{{AGENT}}" in text:
        p = agent_module_path(br)
        if p:
            text = text.replace("{{AGENT}}", p)
            print("[*] {{AGENT}} -> %s" % p)
        else:
            print("[!] 无法解析 {{AGENT}}：当前没有注入的 so（agent 未连接或目标未注入）。")
            ok = False
    return text, ok


BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "script_backups")


def backup_phone_draft(br):
    """覆盖手机草稿前，先把现有草稿备份到电脑，避免误覆盖用户的脚本。

    备份到 tools/script_backups/draft_YYYYmmdd_HHMMSS.lua，只保留最近 20 份。
    """
    try:
        cur = br.cmd("GET_SCRIPT")
    except Exception as e:
        print("[!] 备份草稿失败（读取失败）: %s" % e)
        return None
    if not cur.strip():
        return None
    try:
        os.makedirs(BACKUP_DIR, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        path = os.path.join(BACKUP_DIR, "draft_%s.lua" % stamp)
        with open(path, "w", encoding="utf-8") as f:
            f.write(cur)
        # 只保留最近 20 份
        files = sorted((f for f in os.listdir(BACKUP_DIR) if f.startswith("draft_")),
                       reverse=True)
        for old in files[20:]:
            try:
                os.unlink(os.path.join(BACKUP_DIR, old))
            except OSError:
                pass
        print("[*] 已备份手机原草稿 -> %s" % path)
        return path
    except Exception as e:
        print("[!] 备份草稿失败: %s" % e)
        return None


def push_text(br, text):
    """展开占位符 → 备份原草稿 → 上传。返回 (是否成功, 最终文本)。

    占位符解析失败时**直接放弃**（不覆盖手机草稿）。
    """
    text, ok = expand_placeholders(br, text)
    if not ok:
        print("[!] 脚本里有无法解析的占位符，已取消上传（手机草稿未被改动）。")
        print("    建议：先回手机注入目标并连接 agent，再重试。")
        return False, text
    backup_phone_draft(br)
    br.cmd_payload("PUT_SCRIPT", text)
    return True, text


def ensure_agent(br, auto_connect=True):
    """确保 agent 已连接；未连接时尝试让手机端自动连一次（App 重启后常用）。"""
    try:
        st = br.cmd("AGENT_STATUS")
    except Exception:
        return False
    if st.startswith("connected"):
        return True
    if not auto_connect:
        return False
    print("[*] agent 未连接，尝试让手机端自动连接…")
    try:
        r = br.cmd("CONNECT_AGENT")
        print("[+] %s" % r)
        return True
    except BridgeError as e:
        print("[!] 自动连接失败: %s" % e)
        return False
    except Exception as e:
        print("[!] 自动连接异常: %s" % e)
        return False


def do_file_mode(br, local_file, run=True, edit=False):
    """非交互：把一个本地 .lua 推到手机并（可选）执行。用于拖拽 .bat。"""
    path = os.path.abspath(local_file)
    if not os.path.isfile(path):
        print("[!] 文件不存在: %s" % path)
        return 1
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        text = f.read()
    if edit:
        ide = resolve_ide_cmd(br.cmd("GET_IDE"))
        if ide:
            edited = edit_with_ide(ide, text)
            if edited is not None:
                text = edited
                try:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(text)
                except OSError:
                    pass
        else:
            print("[!] 没探测到 IDE，直接按文件内容执行")
    print("[*] 上传 %s（%d 字节）…" % (path, len(text.encode("utf-8"))))
    try:
        # 顺序很重要：**先确保 agent 已连接**，再展开 {{AGENT}}
        # （LIST_MODULES 需要 agent；没连时展开会拿不到 memfd 名字）
        ensure_agent(br)
        # push_text 内部：展开占位符 → 备份手机原草稿 → 上传。
        # 占位符解析失败时它**不会上传**，所以不会覆盖手机上的草稿。
        ok, text = push_text(br, text)
        if not ok:
            print("[!] 未上传，手机草稿保持不变。")
            return 1
        pc_config.set_config(last_file=path)
        if not run:
            print("[+] 已上传（未执行）。")
            return 0
        print("[*] 执行…")
        out = br.cmd_payload("RUN_SCRIPT", text)
        print("---- 执行结果 ----")
        print(out if out.strip() else "(无输出)")
        print("------------------")
        return 0
    except BridgeError as e:
        print("[!] 手机端返回错误: %s" % e)
        if "SO 通道" in str(e) or "agent" in str(e):
            if ensure_agent(br):
                print("[*] 已重新连接 agent，重试一次…")
                try:
                    ok2, text2 = push_text(br, text)
                    if not ok2:
                        return 1
                    out = br.cmd_payload("RUN_SCRIPT", text2)
                    print("---- 执行结果 ----")
                    print(out if out.strip() else "(无输出)")
                    print("------------------")
                    return 0
                except Exception as e2:
                    print("[!] 仍然失败: %s" % e2)
        return 1


def main():
    ap = argparse.ArgumentParser(description="ATrace 电脑端 Lua 脚本编辑/执行客户端")
    ap.add_argument("file", nargs="?", help="要直接推送并执行的 .lua 文件（也可从 .bat 拖拽）")
    ap.add_argument("--port", type=int, default=None, help="adb 转发端口（默认取配置/28471）")
    ap.add_argument("--adb", default=None, help="adb 路径（默认自动探测）")
    ap.add_argument("--no-forward", action="store_true", help="跳过 adb forward")
    ap.add_argument("--edit", action="store_true", help="配合 file：先用 IDE 编辑再执行")
    ap.add_argument("--no-run", action="store_true", help="配合 file：只推送不执行")
    ap.add_argument("--show-config", action="store_true", help="打印配置与探测结果后退出")
    ap.add_argument("--reset-config", action="store_true", help="删除配置文件后退出")
    args = ap.parse_args()

    if args.reset_config:
        try:
            os.unlink(pc_config.CONFIG_PATH)
            print("[+] 已删除配置: %s" % pc_config.CONFIG_PATH)
        except FileNotFoundError:
            print("[*] 配置文件不存在")
        except Exception as e:
            print("[!] 删除失败: %s" % e)
            return 1
        return 0

    port = pc_config.resolve_port(args.port)
    adb = pc_config.find_adb(args.adb, interactive=not args.file)

    # 把"当前在用的 Python / 端口"写回配置：下次 .bat 启动时不用再猜/再问。
    # （.bat 只能靠 ini 里的 python=/port= 找到解释器与端口，所以这步很关键；
    #   换电脑时 ini 里的路径会失效，pc_config 会自动重新探测。）
    try:
        cur = pc_config.load_config()
        if cur.get("python", "") != sys.executable or cur.get("port", "") != str(port):
            pc_config.set_config(python=sys.executable, port=port)
    except Exception:
        pass

    if args.show_config:
        print_cfg(adb, port)
        return 0

    print("=" * 62)
    print(" ATrace 电脑端脚本模式")
    print("=" * 62)
    print("[*] adb: %s" % (adb or "未找到（若手机已连过、且桥在监听，仍可直连）"))

    # adb forward（没 adb 也允许继续：也许用户已经手动 forward 过）
    if not args.no_forward:
        if adb:
            ok, err = pc_config.adb_forward(adb, port)
            if not ok:
                print("[!] adb forward 失败: %s" % err.strip())
                print("    检查：USB 调试是否开、手机是否授权本电脑（adb devices）、")
                print("          手机 App 是否在跑且选项页勾选了「adb 脚本模式」。")
                if not args.file:
                    return 1
            else:
                print("[+] 已建立 adb forward  tcp:%d -> tcp:%d" % (port, port))
        else:
            print("[!] 没有 adb，跳过 forward（假定你已经手动做过）")

    try:
        br = connect(port)
    except Exception as e:
        print("[!] 连接手机失败: %s" % e)
        print("    手机端检查：App 在跑？选项页勾选了「adb 脚本模式」？")
        print("    端口是否一致？（手机端与电脑端都用 %d）" % port)
        return 1

    try:
        print("[+] 已连接手机端 adb 桥（127.0.0.1:%d）\n" % port)

        # 非交互模式：拖拽/命令行给了一个文件
        if args.file:
            return do_file_mode(br, args.file, run=not args.no_run, edit=args.edit)

        # 交互模式
        print_info(br)
        print()
        script = br.cmd("GET_SCRIPT")
        print("[*] 手机上的当前草稿共 %d 行；输入 h 看命令，e 编辑并执行。" %
              (len(script.splitlines())))
        ide_used = resolve_ide_cmd(br.cmd("GET_IDE"))
        if ide_used:
            print("[*] 编辑方式: IDE（%s）" % ide_used)
        else:
            print("[*] 编辑方式: cmd 行编辑（没探测到 IDE，可用 i 命令指定）")
        print()

        while True:
            try:
                raw = input("atrace> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not raw:
                continue
            parts = raw.split(None, 1)
            c = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            try:
                if c in ("q", "quit", "exit"):
                    break
                elif c in ("h", "help", "?"):
                    show_help()
                elif c == "cfg":
                    print_cfg(adb, port)
                elif c == "info":
                    print_info(br)
                elif c in ("v", "view"):
                    print("---- 手机草稿 ----")
                    print(br.cmd("GET_SCRIPT"))
                    print("------------------")
                elif c in ("l", "logs"):
                    logs = br.cmd("GET_LOGS")
                    print(logs if logs.strip() else "(暂无新日志)")
                elif c in ("i", "ide"):
                    if arg:
                        br.cmd_payload("SET_IDE", arg)
                        pc_config.set_config(ide=arg)
                        print("[+] IDE 命令已保存: %s" % arg)
                    else:
                        cur = br.cmd("GET_IDE")
                        print("手机端 IDE 命令: %s" % (cur if cur.strip() else "(空 = 电脑端自动探测)"))
                        print("本机自动探测结果: %s" % (resolve_ide_cmd(cur) or "无"))
                elif c in ("m", "modules"):
                    mods = br.cmd("LIST_MODULES")
                    agent = agent_module_path(br)
                    print("注入的 so: %s" % (agent or "(未找到 /memfd: 条目)"))
                    if arg == "all":
                        print(mods)
                    else:
                        print("（输入 m all 看全部 %d 个模块）" % len(mods.splitlines()))
                elif c in ("p", "push"):
                    if not arg:
                        print("用法: p <本地文件路径>")
                        continue
                    with open(arg, "r", encoding="utf-8", errors="replace") as f:
                        text = f.read()
                    # 展开占位符 + 备份原草稿 + 上传（解析失败则不上传）
                    ok, text = push_text(br, text)
                    if not ok:
                        continue
                    pc_config.set_config(last_file=os.path.abspath(arg))
                    print("[+] 已上传 %s（%d 字节）" % (arg, len(text.encode("utf-8"))))
                elif c in ("e", "edit"):
                    cur = br.cmd("GET_SCRIPT")
                    cmd_to_use = resolve_ide_cmd(br.cmd("GET_IDE"))
                    if not cmd_to_use:
                        print("[!] 没探测到 IDE，改用 cmd 行编辑（也可先 `i 你的命令` 指定）")
                        text = edit_in_cmd(cur)
                    else:
                        text = edit_with_ide(cmd_to_use, cur)
                    if text is None:
                        continue
                    print("[*] 回传并执行…")
                    out = run_remote(br, text)
                    print("---- 执行结果 ----")
                    print(out if out.strip() else "(无输出)")
                    print("------------------")
                elif c in ("t", "type"):
                    text = edit_in_cmd(br.cmd("GET_SCRIPT"))
                    if text is None:
                        continue
                    print("[*] 回传并执行…")
                    out = run_remote(br, text)
                    print("---- 执行结果 ----")
                    print(out if out.strip() else "(无输出)")
                    print("------------------")
                elif c in ("r", "run"):
                    print("[*] 执行手机上当前草稿…")
                    out = br.cmd("RUN")
                    print("---- 执行结果 ----")
                    print(out if out.strip() else "(无输出)")
                    print("------------------")
                elif c in ("g", "pull"):
                    if not arg:
                        print("用法: g <本地保存路径>")
                        continue
                    text = br.cmd("GET_SCRIPT")
                    with open(arg, "w", encoding="utf-8") as f:
                        f.write(text)
                    print("[+] 已保存到 %s（%d 字节）" % (arg, len(text.encode("utf-8"))))
                else:
                    print("未知命令: %s（输入 h 看帮助）" % c)
            except BridgeError as e:
                print("[!] 手机端返回错误: %s" % e)
            except FileNotFoundError as e:
                print("[!] 文件不存在: %s" % e)
            except Exception as e:
                print("[!] 出错: %s" % e)
    finally:
        br.close()
        print("已断开。")
    return 0


if __name__ == "__main__":
    sys.exit(main())

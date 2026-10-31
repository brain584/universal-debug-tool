#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""atrace_mcp.py —— 电脑端的 MCP（Model Context Protocol）服务，把手机工具暴露给 AI。

=============================== 它做什么 =====================================
用 **stdio** 说 MCP 协议（JSON-RPC 2.0），所以可以直接配到 Claude Desktop、
Cursor、以及任何支持 stdio MCP 的客户端里。工具的实际执行发生在**手机**上：
本进程把 tools/call 转发给手机 App 的 adb 桥（与脚本模式共用一个端口）。

    电脑 MCP 客户端 ──stdio JSON-RPC──> 本脚本 ──adb forward──> 手机 App ──> agent/LuaJIT

=============================== 两种模式 =====================================
  --mode phone  （默认）必须连着手机；工具实时转发到手机执行。
  --mode local  不连手机，只提供本机工具（目前是 local_info），
                用于"没插 USB 时也能先跑起来"；手机工具会明确报不可用。
  --mode auto   先试手机，连不上就退到 local。

用户要求「未连 USB 时依旧可以自由选择手机本地 mcp 或电脑 mcp」：
  · 电脑 mcp  = 本脚本（工具在电脑侧转发/执行）
  · 手机本地  = 需要在手机侧有 MCP 运行时（本轮未实现，见 HANDOFF 的遗留项）

=============================== 配置示例（Claude Desktop）====================
  "mcpServers": {
    "atrace": {
      "command": "python",
      "args": ["D:/path/to/atrace_mcp.py", "--port", "28471"]
    }
  }

=============================== 自测 =========================================
  python atrace_mcp.py --selftest        # 不需要 MCP 客户端，直接跑一遍协议
"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pc_config  # noqa: E402  同目录的共享配置/探测模块

if sys.platform == "win32":
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

PORT_DEFAULT = 28471
PROTOCOL_VERSION = "2024-11-05"

# ---------------------------------------------------------------- 手机桥客户端
# 与 atrace_lua.py 里的 Bridge 相同协议；这里单独实现一份，让 MCP 服务可以独立部署。


class PhoneBridge:
    def __init__(self, port, timeout=20.0):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.f = self.sock.makefile("rb")

    def _line(self):
        l = self.f.readline()
        if not l:
            raise RuntimeError("手机端连接已关闭")
        return l.decode("utf-8", "replace").rstrip("\r\n")

    def _exact(self, n):
        d = b""
        while len(d) < n:
            c = self.f.read(n - len(d))
            if not c:
                raise RuntimeError("读取载荷中断")
            d += c
        return d

    def _recv(self):
        head = self._line()
        if head not in ("OK", "ERR"):
            raise RuntimeError("协议错误: %r" % head)
        n = int(self._line())
        body = self._exact(n).decode("utf-8", "replace")
        if head == "ERR":
            raise RuntimeError(body)
        return body

    def cmd(self, name):
        self.sock.sendall((name + "\n").encode())
        return self._recv()

    def cmd_body(self, name, text):
        b = text.encode()
        self.sock.sendall((name + "\n%d\n" % len(b)).encode() + b)
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


# ---------------------------------------------------------------- 工具清单

LOCAL_TOOLS = [
    {
        "name": "local_info",
        "description": "返回本机（电脑）信息，用于确认 MCP 服务本身在工作",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    }
]


def find_adb(user_adb=None):
    """adb 探测统一交给 pc_config（PATH / ANDROID_HOME / 常见 SDK 目录 / 配置记忆）。

    注意：MCP 服务是被 AI 客户端以**非交互**方式拉起的，不能弹提示问路径，
    所以 interactive=False；探测不到就不做 forward（用户可能已手动 forward 过）。
    上次在 `atrace_lua.py` 里探测到的 adb 也会写进 pc_config.ini，这里直接复用。"""
    return pc_config.find_adb(user_adb, interactive=False)


# ---------------------------------------------------------------- MCP 服务

class McpServer:
    def __init__(self, mode, port, adb):
        self.mode = mode
        self.port = port
        self.adb = adb
        self.bridge = None
        self.tools = []

    # -- 连接手机 --
    def ensure_bridge(self):
        if self.bridge:
            return self.bridge
        if self.mode == "local":
            return None
        if self.adb:
            try:
                subprocess.run([self.adb, "forward", "tcp:%d" % self.port, "tcp:%d" % self.port],
                               capture_output=True, timeout=20)
            except Exception:
                pass
        try:
            self.bridge = PhoneBridge(self.port)
            self.bridge.cmd("PING")
            return self.bridge
        except Exception as e:
            self.bridge = None
            if self.mode == "auto":
                self.log("连不上手机(%s)，退到 local 模式" % e)
                self.mode = "local"
                return None
            raise

    def log(self, msg):
        # MCP 的 stdio 只能走协议报文，日志一律走 stderr
        sys.stderr.write("[atrace-mcp] %s\n" % msg)
        sys.stderr.flush()

    # -- tools/list --
    CACHE_FILE = "mcp_tools_cache.json"

    def _cache_path(self):
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), self.CACHE_FILE)

    def _load_cache(self):
        try:
            with open(self._cache_path(), encoding="utf-8-sig") as f:
                data = json.load(f)
            if isinstance(data, list) and data:
                return data
        except Exception:
            pass
        return None

    def list_tools(self):
        br = None
        try:
            br = self.ensure_bridge()
        except Exception as e:
            self.log("手机不可用: %s" % e)
        if br:
            try:
                self.tools = json.loads(br.cmd("TOOL_LIST"))
                if isinstance(self.tools, list) and self.tools:
                    try:   # 缓存最近一次工具清单，供离线时展示
                        with open(self._cache_path(), "w", encoding="utf-8") as f:
                            json.dump(self.tools, f, ensure_ascii=False, indent=1)
                    except Exception:
                        pass
                    return self.tools
            except Exception as e:
                self.log("TOOL_LIST 失败（App 的「MCP 工具通道」可能没开）: %s" % e)
        cached = self._load_cache()
        if cached:
            self.log("手机不可用，使用离线工具清单缓存（%d 个工具）" % len(cached))
            self.tools = cached
            return self.tools
        self.tools = LOCAL_TOOLS
        return self.tools

    # -- tools/call --
    def call_tool(self, name, args):
        try:
            br = self.ensure_bridge()
        except Exception:
            br = None
        if br:
            try:
                req = json.dumps({"name": name, "args": args or {}}, ensure_ascii=False)
                return br.cmd_body("TOOL_CALL", req)
            except Exception as e:
                return ("ERR: 手机端调用失败: %s\n"
                        "提示：确认 App 选项页已打开「MCP 工具通道」，且 "
                        "adb forward tcp:%d tcp:%d 生效，目标进程已注入并连接 agent。"
                        % (e, self.port, self.port))
        # local 模式：只提供本机工具
        if name == "local_info":
            return "mode=local\npython=%s\nplatform=%s\nphone_tools=unavailable(未连接 USB)" % (
                sys.version.split()[0], sys.platform)
        return ("ERR: 手机未连接，工具 %s 暂不可用。\n"
                "请插上 USB，在 App 选项页打开「MCP 工具通道」，重新执行一次 tools/list。"
                % name)

    # -- JSON-RPC 分发 --
    def handle(self, req):
        method = req.get("method")
        rid = req.get("id")
        params = req.get("params") or {}

        def ok(result):
            return {"jsonrpc": "2.0", "id": rid, "result": result}

        def err(code, message):
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}

        if method == "initialize":
            return ok({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "atrace-mcp", "version": "1.0.0"},
            })
        if method in ("notifications/initialized", "initialized"):
            return None                      # 通知不需要回应
        if method == "tools/list":
            return ok({"tools": self.list_tools()})
        if method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments") or {}
            text = self.call_tool(name, args)
            is_error = text.startswith("ERR")
            return ok({
                "content": [{"type": "text", "text": text}],
                "isError": is_error,
            })
        if method == "ping":
            return ok({})
        return err(-32601, "Method not found: %s" % method)

    # -- 主循环：一行一个 JSON-RPC --
    def serve(self):
        self.log("MCP 服务启动 mode=%s port=%d adb=%s" % (self.mode, self.port, self.adb))
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except Exception as e:
                self.log("解析请求失败: %s" % e)
                continue
            try:
                resp = self.handle(req)
            except Exception as e:
                resp = {"jsonrpc": "2.0", "id": req.get("id"),
                        "error": {"code": -32603, "message": str(e)}}
            if resp is not None:
                sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
        if self.bridge:
            self.bridge.close()


# ---------------------------------------------------------------- 自测

def selftest(port, adb):
    """不接 MCP 客户端，直接把协议跑一遍，方便排障。"""
    srv = McpServer("auto" if port else "local", port or PORT_DEFAULT, adb)
    tests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "agent_status", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "list_processes", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
         "params": {"name": "no_such", "arguments": {}}},
    ]
    ok = 0
    for t in tests:
        r = srv.handle(t)
        print(json.dumps(r, ensure_ascii=False)[:400])
        ok += 1
    print("=" * 50)
    print("自测完成：%d 个请求已处理（看上面每个是否有 result/error）" % ok)
    if srv.bridge:
        srv.bridge.close()
    return 0


def main():
    ap = argparse.ArgumentParser(description="ATrace MCP 服务（stdio）")
    ap.add_argument("--mode", choices=["phone", "local", "auto"], default="auto",
                    help="phone=只连手机；local=只本机；auto=先手机后本机（默认）")
    ap.add_argument("--port", type=int, default=None,
                    help="adb 转发端口（默认取 pc_config.ini 或 %d）" % PORT_DEFAULT)
    ap.add_argument("--adb", default=None)
    ap.add_argument("--selftest", action="store_true", help="自测一遍协议，不进入 MCP 主循环")
    a = ap.parse_args()

    port = pc_config.resolve_port(a.port)
    adb = find_adb(a.adb)
    if a.selftest:
        return selftest(0 if a.mode == "local" else port, adb)
    McpServer(a.mode, port, adb).serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MCP 端到端验证：读目标进程内存 → 改成 1000(D) → 用 Lua 打印结果与注入 so 地址。

用法:
    python _mcp_verify.py --mcp <atrace_mcp.py> --pid <目标pid> --addr 0x70B8D02D70 [--value 1000]

它作为一个标准 MCP 客户端启动 atrace_mcp.py（stdio JSON-RPC），
依次发 initialize / tools/list / tools/call，打印每步的请求与回复。
"""
import argparse
import json
import subprocess
import sys

if sys.platform == "win32":
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


class McpClient:
    def __init__(self, mcp_script, extra_args):
        self.p = subprocess.Popen(
            [sys.executable, mcp_script] + extra_args,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", bufsize=1)
        self.rid = 0

    def call(self, method, params=None):
        self.rid += 1
        req = {"jsonrpc": "2.0", "id": self.rid, "method": method, "params": params or {}}
        self.p.stdin.write(json.dumps(req, ensure_ascii=False) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        if not line:
            err = self.p.stderr.read()
            raise RuntimeError("MCP 服务没有响应；stderr=%s" % err[-800:])
        return json.loads(line)

    def tool(self, name, **args):
        resp = self.call("tools/call", {"name": name, "arguments": args})
        if "error" in resp:
            raise RuntimeError("MCP error: %s" % resp["error"])
        r = resp["result"]
        text = "".join(c.get("text", "") for c in r.get("content", []))
        return r.get("isError", False), text

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=10)
        except Exception:
            self.p.kill()


def show(label, is_err, text, limit=800):
    tag = "ERR" if is_err else "OK "
    body = text if len(text) <= limit else text[:limit] + " …(截断)"
    print("[%s] %s\n      %s\n" % (tag, label, body.replace("\n", "\n      ")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mcp", required=True, help="atrace_mcp.py 路径")
    ap.add_argument("--pid", type=int, required=True, help="目标进程 pid")
    ap.add_argument("--addr", default="0x70B8D02D70", help="目标地址（hex）")
    ap.add_argument("--value", type=int, default=1000, help="要写入的 D(32bit) 值")
    ap.add_argument("--port", default="28471")
    a = ap.parse_args()

    c = McpClient(a.mcp, ["--mode", "phone", "--port", a.port])
    try:
        # 0) 握手
        init = c.call("initialize", {"protocolVersion": "2024-11-05"})
        print("[MCP] initialize ->", json.dumps(init.get("result", {}), ensure_ascii=False)[:200], "\n")

        tl = c.call("tools/list")
        names = [t["name"] for t in tl.get("result", {}).get("tools", [])]
        print("[MCP] tools/list -> %d 个工具: %s\n" % (len(names), ", ".join(names)))

        is_err, txt = c.tool("agent_status")
        show("agent_status", is_err, txt)

        # 1) 读当前值（D = 32bit）
        is_err, txt = c.tool("mem_read", pid=a.pid, addr=a.addr, len=4)
        show("mem_read(%s, 4) 当前值" % a.addr, is_err, txt)
        before_hex = txt.strip() if not is_err else ""
        if before_hex and len(before_hex) == 8:
            le = int.from_bytes(bytes.fromhex(before_hex), "little", signed=False)
            be = int.from_bytes(bytes.fromhex(before_hex), "big", signed=False)
            print("      LE(小端，arm64 实际值) = %d (0x%X) | BE = %d\n" % (le, le, be))

        # 2) 写成 1000（D 类型 = 32bit 小端）
        payload = a.value.to_bytes(4, "little", signed=False).hex()
        print("[*] 写入 %d (0x%X) -> 小端字节 %s" % (a.value, a.value, payload))
        is_err, txt = c.tool("mem_write", pid=a.pid, addr=a.addr, data=payload)
        show("mem_write", is_err, txt)

        # 3) 回读校验
        is_err, txt = c.tool("mem_read", pid=a.pid, addr=a.addr, len=4)
        show("mem_read 回读", is_err, txt)
        if txt.strip() and len(txt.strip()) == 8:
            v = int.from_bytes(bytes.fromhex(txt.strip()), "little")
            print("      回读值 = %d (0x%X)  %s\n" % (v, v, "✅ 与预期一致" if v == a.value else "❌ 不一致"))

        # 4) 用 Lua 打印：读同一地址 + 注入 so 的基址
        lua = (
            'local addr = %s\n'
            'local v = readDword(addr)\n'
            'print(string.format("Lua readDword(0x%%x) = %%d (0x%%x)", addr, v, v))\n'
            'local b = getBase("libagent.so")\n'
            'print(string.format("libagent.so base = 0x%%x", b))\n'
        ) % a.addr
        is_err, txt = c.tool("run_lua", script=lua)
        show("run_lua（打印同一地址的值 + 注入 so 地址）", is_err, txt)
    finally:
        c.close()


if __name__ == "__main__":
    main()

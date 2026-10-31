# ATrace 电脑端工具 —— 使用说明

> 让**电脑通过 USB 调试使用手机上的 ATrace**：
> ① **脚本模式**：在电脑 cmd / IDE 里编写、执行 Lua，手机不用开悬浮窗。
> ② **MCP 工具通道**：电脑的 AI（Claude Desktop / Cursor 等）可以调用手机工具。
>
> 两者共用一条通道：手机 App 监听 `127.0.0.1:28471`，电脑用
> `adb forward tcp:28471 tcp:28471` 连进去（`.bat` 会自动做）。

---

## 文件清单

| 文件 | 作用 |
|---|---|
| `atrace_lua.bat` | **双击入口**：自动找 Python/adb → `adb forward` → 启动脚本客户端 |
| `atrace_lua.py` | 脚本客户端本体（IDE 编辑 / cmd 行编辑 / 推拉文件 / 执行） |
| `atrace_mcp.py` | **电脑端 MCP 服务**（stdio JSON-RPC，31 个工具动态转发到手机） |
| `atrace_mcp_test.bat` | 双击自测 MCP（握手 / 工具清单 / 一次真实工具调用） |
| `mcp_verify.py` | MCP 端到端验证（读→写→回读→Lua 打印） |
| `pc_config.py` | 共享的配置与**自动探测**（python / adb / 端口 / IDE） |
| `pc_config.ini` | 自动生成的配置（可手改；删掉即恢复全新探测） |

> ⚠️ **改 `.bat` 必须纯 ASCII + CRLF。** `cmd.exe` 按系统 ANSI 代码页读批处理并要求 CRLF，
> 写成 UTF-8/LF 会被拆成乱码命令。中文提示一律放 `.py` 里。

---

## 0. 准备（一次性）

**手机**：打开 ATrace → 选项页最下面「电脑连接（USB 调试）」勾上对应开关
（状态显示 `监听中 127.0.0.1:28471`）→ 选目标进程 → 注入 → **连接 agent**（显示已连接）。
**电脑**：有 Python 3 和 adb（`adb devices` 能看到设备）。**不需要 root**。

---

## 1. 脚本模式

### 三种启动方式

| 方式 | 操作 | 效果 |
|---|---|---|
| 双击 | 双击 `atrace_lua.bat` | 进入交互模式 |
| **拖拽** | 把 `.lua` 文件拖到 `atrace_lua.bat` 上 | **直接推到手机并执行**，输出打印完自动退出 |
| 命令行 | `python atrace_lua.py demo.lua` | 同上 |
| 命令行 | `python atrace_lua.py demo.lua --edit` | 先用 IDE 编辑再执行 |

### 交互模式命令

| 命令 | 作用 |
|---|---|
| `e` | 用 IDE 编辑当前脚本 → 关闭编辑器自动执行（VS Code 用 `--wait`，无需回车） |
| `t` | 没有 IDE 时，在 cmd 里逐行写，单独一行 `.` 结束 |
| `r` | 直接执行手机上的当前草稿 |
| `v` | 查看手机草稿 |
| `p <文件>` / `g <文件>` | 上传本地文件 / 下载手机草稿 |
| `m` / `m all` | 看注入的 so（memfd 路径） / 全部模块 |
| `i [命令]` / `ide` | 查看/设置 IDE 启动命令（`{file}` 占位符） |
| `l` | 拉一次 Lua print 日志 |
| `cfg` | 显示配置与自动探测结果 |
| `info` | 连接与设备信息 |
| `q` | 退出 |

**agent 断了会自动重连**：App 重启后不用回手机点，客户端发现未连接会调手机端自动连一次。

### 特殊占位符（推荐用，避免每次重注入后手改）

注入的 agent 是 **memfd** 方式加载，模块名形如 `/memfd:xxxxxxxx (deleted)`，
**每次重新注入都会变**。所以脚本里别写死，用占位符：

```lua
local a = getBase("{{AGENT}}")          -- 电脑端自动替换成当前的 /memfd:xxxx (deleted)
print(string.format("注入 so 基址 = 0x%x", a))

print("{{MODULES}}")                    -- 也可嵌入完整模块列表
```

> 占位符**只在电脑端上传前展开**。手机编辑器里看到的永远是展开后的结果；
> 如果 agent 没连上导致解析不了，客户端会**拒绝上传**（不会把 `{{AGENT}}` 字面量写进手机草稿）。

### 草稿安全（重要）

手机"脚本"页的编辑框 = 手机上的草稿文件 `last.lua`，**电脑端上传会覆盖它**。因此：

- 每次上传前，客户端会先把手机原草稿备份到 **`tools/script_backups/draft_<时间>.lua`**（保留最近 20 份）；
- 占位符解析失败时**不会上传**，草稿保持原样。

被误覆盖后可从这里找回：看 `tools/script_backups/` 下最新的备份，用 `p` 或拖拽推回去。

---

## 2. MCP 工具通道

> 有两种形态，**别搞混**：
> - **电脑端 MCP**：`atrace_mcp.py`，电脑上的 stdio 进程，给电脑客户端（Claude Desktop/Cursor）用。
> - **手机本地 MCP**：跑在 ATrace 里的 HTTP 服务，给**手机上的 AI App** 用（它连不了电脑程序）。

### 2A. 手机本地 MCP（给手机上的 AI App，导入 JSON 即可）

手机 App 打开选项页勾「MCP 工具通道」后，ATrace 会监听两个端口：
- `28471`：adb 桥（给电脑用）
- **`28472`：手机本地 MCP（给手机 App 用，HTTP）**

两种传输都支持，按你的 App 支持哪种选一个导入：

| 传输 | URL | 客户端 type | 导入文件 |
|---|---|---|---|
| Streamable HTTP（新） | `http://127.0.0.1:28472/mcp` | `http` / `streamableHttp` | `mcp_local_http.json` |
| HTTP+SSE（旧） | `http://127.0.0.1:28472/sse` | `sse` | `mcp_local_sse.json` |

导入文件已生成并推到手机：**`/sdcard/ATrace/`** 下（`mcp_local_http.json` / `mcp_local_sse.json` /
`mcp_local_streamable.json`）。在你的 App 里选「导入 MCP 服务器 JSON」指向对应文件即可。
手机面板里也有「复制手机 MCP 导入 JSON」一行，可以直接复制粘贴。

> 前提：ATrace 进程活着且勾了「MCP 工具通道」。工具本身仍受限制——
> `run_lua`/`list_modules` 要 agent 已连接，`mem_read`/`mem_write` 要 root。

### 2B. 电脑端 MCP（给电脑客户端）

### 配到 AI 客户端（Claude Desktop / Cursor）

```json
"mcpServers": {
  "atrace": {
    "command": "python",
    "args": ["D:/project/ARM64-ZeroPtrace-delivery-20261005/universal_debug_tool/tools/atrace_mcp.py"]
  }
}
```
端口从 `pc_config.ini` 读（默认 28471），也可以显式 `--port 28471`。

然后直接用自然语言：
- “列出手机上的进程” → `list_processes`
- “读 pid 16272 的 0x70B8D02D70 四个字节” → `mem_read`
- “把那个地址改成 1000” → `mem_write`
- “在目标里执行 Lua 打印注入 so 的基址” → `run_lua`

### 自己不接客户端时

```bat
atrace_mcp_test.bat                                        :: 双击自测
python atrace_mcp.py --selftest --mode auto                :: 命令行自测
python mcp_verify.py --mcp atrace_mcp.py --pid <pid> --addr 0x... --value 1000
```

`--mode`：`phone`（只连手机）/ `local`（只用本机）/ `auto`（默认，先手机后本机）。

### 15 个工具

**基础（7）**

| 工具 | 参数 | 说明 | 前提 |
|---|---|---|---|
| `run_lua` | `script` | 目标内执行 Lua，返回本次结果+print | agent 已连接 |
| `agent_status` | — | `connected` / `not_connected` | — |
| `inject_pid` | `pid` | 用 ptrace 注入器注入目标，成功后自动连 agent | root |
| `list_processes` | — | 进程表 `pid\|ppid\|name` | root |
| `list_modules` | — | 目标模块表 `地址 路径` | agent 已连接 |
| `mem_read` | `pid`,`addr`,`len` | 读内存 → hex（小端） | root |
| `mem_write` | `pid`,`addr`,`data` | 写内存，hex 偶长 | root |

`mem_read` 返回小端 hex：`e8030000` = 1000（D 类型就是 32 位）。

> **`run_lua` 第一次用请先执行 `api()`**：目标进程里注入了 28 个宿主 API
> （`getBase` / `hookCPU` / `hookfunc` / `read*` / `write*` / `regsOf` / `setReg` …）。
> `api()` 返回每个函数的签名、返回值、说明、示例；`api("hookfunc")` 单查；`help()` 打印可读清单。
> 一条命令自测：把 `tools/lua_api_probe.lua` 的内容当脚本传给 `run_lua`。

**hook 用法（推荐 instrument 模式）**：

```lua
-- 入口回调：原函数照常执行，不破坏原逻辑
local h = hookfunc(getBase("libxxx.so") + 0x1234, function(regs, addr)
    local r = regsOf(regs)          -- {x0..x28, sp, fp, lr}
    setReg(regs, "x0", 0x1000)      -- 改寄存器
end)
print(h:hits())                     -- 命中次数
h:remove()

-- 高级：hookfunc(addr, 可执行地址) 做原生替换，句柄可 h:call_original(...)
```

⚠️ **不要 hook `clock_gettime`/`malloc`/`pthread_mutex_lock` 这类运行时高频函数**：
handler 自身会调用它们，形成递归 hook，实测会让目标 SIGSEGV。要 hook 业务函数。

**硬件断点（8，需要 root）**

| 工具 | 参数 | 说明 |
|---|---|---|
| `bp_status` | — | `running / target_pid / status / last_line` |
| `bp_start` | `pid?` | 启动断点服务；pid 省略时自动用 agent 自报的 pid |
| `bp_stop` | — | 停止并清理 |
| `bp_set` | `addr` 或 `module`+`offset`、`type`(x/r/w/rw)、`len`(1/2/4/8) | 下断点，返回 `OK/ERR` 确认行 |
| `bp_clear` | `addr` | 清单个 |
| `bp_clear_all` | — | 清全部 |
| `bp_hits` | `max?` | 最近命中（`pc\|tid\|addr\|反汇编\|sp\|栈\|寄存器\|次数\|区域\|模块\|类型\|长度`）|
| `bp_wait` | `timeout_sec?`,`max?` | 等命中（下断→等→看寄存器/栈） |

要点：
- `type=x` 执行断点；`r/w/rw` 数据观察点（必须给长度）。
- 命中基于 **perf_event 采样，不会暂停线程**，只上报寄存器/栈快照。
- 每线程 4 个硬件断点槽位；`set` 会遍历目标所有线程，返回 `threads=N failed=M`。
- 例子：`bp_set(module="libc.so", offset="0x8f120", type="x")`（clock_gettime）几乎立刻能命中。
- 常见失败：`bp_start` 报「su 失败？」→ 手机 App 重启后还没请求过 root，先启动一次 Overlay；
  `bp_set` 报「找不到模块」→ agent 链路脏了，重启 App 并重新注入目标。


---

## 3. 换电脑 / 换环境怎么办

**什么都不用改。** 启动时：

1. 先读 `pc_config.ini` 里的 `python=` / `adb=` / `port=`；
2. 路径失效（比如换了电脑）→ **自动重新探测**（PATH、`ANDROID_HOME`、`%LOCALAPPDATA%\Android\Sdk`、
   `C:\platform-tools`、常见 Python 安装目录、conda…）；
3. 还找不到 → **弹提示问你要路径**（可以把 `python.exe` / `adb.exe` 直接拖进窗口）；
4. 找到后写回 `pc_config.ini`，下次直接用。

手动管理：

```bat
python atrace_lua.py --show-config      :: 看当前配置 + 探测结果
python atrace_lua.py --reset-config     :: 删配置，恢复全新探测
```

---

## 4. 常见问题

| 现象 | 检查 |
|---|---|
| 连不上 127.0.0.1:28471 | App 在跑？开关勾了？`adb devices` 正常？ |
| 提示 `SO 通道未连接` | 回手机注入目标并「连接 agent」；客户端也会尝试自动连 |
| `错误: 响应超时` | **目标进程重启过**（pid 变了，旧进程里的 agent 已消失）→ 需要重新注入 |
| `{{AGENT}}` 没被替换 | 同上：agent 没连上时查不到 memfd 名字 |
| `getBase("libagent.so")` 返回 0 | 正常。注入 so 是 memfd，用 `{{AGENT}}` 占位符 |
| 中文乱码 | 用 `.bat` 启动（内部 `chcp 65001`） |
| 输出了上一轮旧日志 | `run_lua` 取的是累计 Lua 日志，历史 print 会一起返回 |
| `.bat` 报一堆"不是内部或外部命令" | 文件被存成 UTF-8/LF 了；必须是 ASCII + CRLF |

## 5. 已知限制

- 桥随 **App 进程**存活；App 被杀后不再监听（未做前台 Service）。
- 端口默认 **28471**（`AdbBridge.PORT`、`pc_config.ini` 的 `port=` 需一致）。
- “手机本地 MCP” 尚未实现。
- Lua 侧没有枚举模块的 API，只有 `getBase(名字)`；所以用 `{{AGENT}}` 占位符绕开。


## 0. 这套 tools 是干什么的

**电脑写脚本/调工具，真正执行发生在手机目标进程里。**

- `atrace_mcp.py`：电脑端 stdio MCP 服务。AI（Claude Desktop / Cursor 等）通过它
  `tools/list` 拿到手机端的 31 个工具，`tools/call` 转发给手机 App 的 adb 桥执行；
- `atrace_lua.bat`：双击/命令行运行即可，在电脑上写/跑 Lua 脚本（同样发到手机执行）；
- `mcp_local_*.json`：手机**本地** MCP（App 内 HTTP 服务，端口 28472）的导入配置，
  给手机上的 AI App 用；
- `mcp_tools_cache.json`：最近一次工具清单缓存。USB 断开时 `tools/list` 仍能列出
  31 个工具（调用会明确提示"手机未连接"），避免 AI 端以为工具消失。

### 前置条件（缺一不可）

1. 手机 App「选项」页打开 **MCP 工具通道**（`127.0.0.1:28471` 监听中）；
2. 电脑执行 `adb forward tcp:28471 tcp:28471`（`.bat` 脚本会自动做）；
3. 已对目标进程**注入并连接 agent**（`agent_status` 显示已连接）；
4. Python 3.8+，`python tools/atrace_mcp.py --selftest` 可先自检。

### 可移植性说明

`mcp_servers.json` / `mcp_servers_typed.json` 使用 `"command": "python"` 和相对路径
`tools/atrace_mcp.py`：需在**仓库根目录**启动，或把参数换成脚本绝对路径。

# MCP 使用说明（手机端 / 电脑端）

ATrace 的 MCP 有两条通道，**工具的实际执行都发生在手机目标进程里**
（注入 agent 后由目标进程内的 LuaJIT / ART / 内存模块执行）：

| 通道 | 端点 | 给谁用 |
| --- | --- | --- |
| 手机本地 MCP | `http://127.0.0.1:28472/mcp`（Streamable HTTP）<br>`http://127.0.0.1:28472/sse`（旧 SSE） | 手机上的 AI App（它们连不了电脑程序） |
| 电脑 stdio 代理 | `tools/atrace_mcp.py` → 经 `adb forward tcp:28471` 转发到 App 的 adb 桥 | 电脑上的 AI 客户端（Claude Desktop / Cursor 等） |

两条通道暴露的是**同一套 31 个工具**，清单由手机端动态提供，升级 App 自动同步。

## 前置条件（缺一不可）

1. 手机 App「选项」页打开 **「MCP 工具通道」**（监听 `127.0.0.1:28471` 与 `28472`）；
2. 电脑端：`adb forward tcp:28471 tcp:28471`（`tools/*.bat` 会自动执行）；
3. 已对目标进程**注入并连接 agent**（`agent_status` 返回已连接）；
4. 工具调用需要 root（注入/断点/内存读写都走 root 通道）。

## 一、手机端怎么用

1. 打开 ATrace → 选项页勾选「MCP 工具通道」，状态显示 `监听中 127.0.0.1:28471`；
2. 手机 AI App 里选择「导入 MCP 服务器 JSON」，指向 `/sdcard/ATrace/` 下的：
   - Streamable HTTP：`mcp_local_http.json`（或 `mcp_local_streamable.json`）
   - 旧 SSE：`mcp_local_sse.json`
   （App 面板里也有「复制手机 MCP 导入 JSON」可直接粘贴）
3. 连接成功后 `tools/list` 应看到 **31 个工具**；若报
   `Server's protocol version is not supported`，请升级到 v1.2.0+（服务端已回显客户端协议版本）。

## 二、电脑端怎么用（stdio MCP 代理）

`tools/atrace_mcp.py` 是一个 stdio JSON-RPC 服务，推荐配置（仓库根目录启动）：

```json
{
  "mcpServers": {
    "atrace": {
      "command": "python",
      "args": ["tools/atrace_mcp.py", "--port", "28471"]
    }
  }
}
```

也可把 `args[0]` 换成脚本绝对路径；`tools/mcp_servers.json`、`tools/mcp_servers_typed.json` 是两份现成配置。

可行性自检（不需要 MCP 客户端）：

```bat
python tools\atrace_mcp.py --selftest                :: 手机在线时
python tools\atrace_mcp.py --mode local --selftest   :: 离线，用缓存清单
```

离线时 `tools/list` 会使用 `tools/mcp_tools_cache.json` 里缓存的上一次工具清单
（仍列出 31 个工具），调用时明确提示「手机未连接」。

## 三、电脑写脚本，手机执行

三种方式，按顺手程度选：

### 1) MCP 工具 `run_lua`（AI 客户端里最常用）

在 AI 客户端里调用 `tools/call`：

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call",
 "params":{"name":"run_lua","arguments":{"script":"print(dump(capabilities(),1))"}}}
```

脚本在目标进程的 LuaJIT 中执行，`print` 输出会随结果返回（也进 `agent_logs`）。

### 2) `tools/atrace_lua.bat`（电脑 cmd 直接写/跑脚本）

**只需要运行这个 .bat**（会自动探测 adb/Python、自动 `adb forward`）：

```bat
tools\atrace_lua.bat                 :: 交互模式：e=IDE 编辑并执行 / t=cmd 逐行写 / r=跑草稿
tools\atrace_lua.bat demo.lua        :: 直接把本地 .lua 推到手机执行（也可把 .lua 拖到 .bat 上）
```

手机不需要开悬浮窗，App 在后台运行即可。

### 3) 手机 App 的「脚本」页

直接在悬浮窗脚本页写完点执行，效果同上。

## 四、31 个工具一览

| 分组 | 工具 |
| --- | --- |
| 环境 / 进程 | `agent_status`、`list_processes`、`list_modules` |
| 注入 | `inject_pid`、`launch_and_inject`、`get_autorun`、`set_autorun` |
| 内存 | `mem_read`、`mem_write`、`mem_page` |
| 搜索 | `search_start`、`search_status`、`search_page`、`search_refine`、`search_reset`、`fuzzy_start`、`fuzzy_filter` |
| 脚本 / Java | `run_lua`、`art_hook`、`art_unhook`、`art_hooks`、`agent_logs` |
| 硬件断点 | `bp_status`、`bp_start`、`bp_stop`、`bp_set`、`bp_clear`、`bp_clear_all`、`bp_hits`、`bp_java_stack`、`bp_wait` |

## 五、常见问题

| 现象 | 处理 |
| --- | --- |
| `Server's protocol version is not supported` | 升级到 v1.2.0+（服务端回显客户端协议版本） |
| `手机未连接，工具 xxx 暂不可用` | 插 USB、开「MCP 工具通道」、`adb forward tcp:28471 tcp:28471` |
| 工具调用都报 agent 未连接 | 先 `inject_pid` 注入并确认 `agent_status` 已连接 |
| 电脑端看不到工具（只有 1 个） | 老版本回退逻辑；v1.2.0+ 会读 `mcp_tools_cache.json` 缓存 |
| 手机 AI App 连不上 28472 | 确认 ATrace 在后台运行、MCP 通道已开、App 未被系统冻结 |

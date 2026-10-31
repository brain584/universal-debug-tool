# ATrace（ARM64 Android 动态调试工具）

原名 Universal Debug Tool。面向 **ARM64 Android** 的本地动态调试工具：运行期调试（函数插桩、
硬件断点、主动调用、内存读写/搜索/修改）不挂起目标进程；注入阶段通过 ptrace 会短暂挂起目标
进程，注入完成后恢复。整个工具打包为一个 Android APK，注入与调试能力依赖设备 root。

当前版本：**1.2.0**（versionCode 1200）。版本改动见 [Releases/RELEASE-1.2.0.md](Releases/RELEASE-1.2.0.md)。

## 命名说明（与 Android 系统工具无关）

本项目的名字 **ATrace** 与 Android 平台自带的 `atrace`（Systrace/Perfetto 使用的系统追踪命令）
**只是重名，两者没有任何代码、功能或依赖关系**。本项目是独立实现的 APK 调试工具，
不封装、不替代、也不依赖系统 atrace；README 中所有「ATrace」均指本仓库的 App。

## ZeroPtrace 注入（实验性）

「零 ptrace 注入」是**实验特性**：通过 data-only GOT 劫持在目标进程内完成加载，不建立 ptrace 关系
（`TracerPid` 不变），用于对抗 ptrace 检测的少数场景。**它仅在极少数软件上可正常注入**，
多数目标会注入失败、进程异常或功能不可用，属于可选实验通道，不建议作为默认用法；
常规场景请使用默认 ptrace 注入（`inject_pid` / `launch_and_inject`，`zero=false`）。

## 功能概览

- **进程管理**：root 下按 PID / 包名枚举进程、按 PID 直接注入、按包名注入（目标未运行可自动拉起）。
- **动态注入**：基于 ptrace 把 agent.so（LuaJIT + Dobby + LSPlant）注入目标进程；注入器负责
  ELF 解析、远程内存分配、dlopen；支持 stealth（memfd / 隐藏 maps / 隐藏 solist / dlclose 隐藏）。
- **加密通信**：GUI 与 agent 通过抽象 Unix socket 通信，ChaCha20 加密；直连失败时通过 root relay 转发。
- **MCP 服务**：App 内置 HTTP MCP 服务（默认 `127.0.0.1:28471`），把注入、内存、断点、Lua、
  模块查询等能力提供给 AI 客户端；工具列表由服务端动态返回，随版本同步。
- **内存查看与修改**
  - 按 GG 风格整页浏览：一页 0x2000（2048 行）连续滚动、右侧滚动条、页首/页尾「地址跳转」行；
  - 每行显示地址、hex、ASCII、DWORD、FLOAT、指令与区域类型（code app / java / cd / ca / A 等）；
  - 长按行：解引用 / 跳转到此地址 / 下断点 / 偏移量计算器 / 指针搜索 / 搜索附近 / 自定义勾选 /
    复制地址 / 复制值；支持指令引用跳转（adrp/adr/b/bl/ldr 字面量）；
  - 类型切换（D/F/E/W/B/Q/A/U）、QQ 指针字面量写入（如 `78fd6604Ch`）、`~A8` 汇编写入；
  - 修改可撤销（Undo），不可读页安全降级显示 0；分配内存页（优先 agent 内 mmap，地址校验）。
- **内存搜索**：精确 / 范围 / 模糊搜索与结果「改善」，内存类型多选筛选；结果可翻页、批量保存。
- **动态调试**
  - LuaJIT（FFI）：`hookfunc` / `hookCPU` / `call` / 数值读写 / ArtHook 反射 / `nativeBacktrace` 等；
    `api()` 可自检可用函数、分组与说明；
  - 硬件断点（root，perf_event）：对目标全部线程下断，命中回传寄存器、PC、堆栈、模块偏移，
    并补充 Java 线程调用链；命中计数以悬浮按钮展示，可一键清除；
  - 反汇编（capstone）与汇编写入（asmjit）。
- **原生悬浮窗 GUI**：Android View 气泡 + 全屏面板（选项 / 搜索 / 保存 / 内存 / 断点 / 脚本），
  支持拖动、深浅色、悬浮窗大小与透明度调节；不依赖 ImGui。

## tools/（电脑端辅助脚本）

`tools/` 是**给电脑侧用的辅助脚本**，不参与 APK 构建，核心用途是：

- **MCP 通道**：`tools/atrace_mcp.py` 是电脑端 stdio MCP 服务，把手机 App 暴露的
  **31 个工具**（注入 / 内存读写搜索 / 硬件断点 / Lua / Java hook / 模块查询等）
  动态转发给 AI 客户端（Claude Desktop、Cursor 等）；工具清单与实现都由手机端提供，
  升级 App 即自动同步，不需要改脚本。
- **电脑写脚本、手机执行**：用 `tools/atrace_lua.py` 或在电脑上让 AI 通过 MCP 调 `run_lua`，
  脚本实际在手机目标进程内的 LuaJIT 中执行（hook、读写内存、主动调用等）。
- **手机本地 MCP**：`tools/mcp_local_http.json` / `mcp_local_sse.json` /
  `mcp_local_streamable.json` 是导入手机 AI App 的配置（App 内 HTTP 服务，端口 28472）。

前置条件：App「选项」页打开「MCP 工具通道」、`adb forward tcp:28471 tcp:28471`、
目标进程已注入并连接 agent。离线时 `tools/list` 会使用 `tools/mcp_tools_cache.json`
缓存的工具清单（调用会提示"手机未连接"）。详见 [tools/README.md](tools/README.md)。

## MCP 使用（手机端 / 电脑端）

工具的实际执行都发生在**手机目标进程内**（注入 agent 后由目标进程的 LuaJIT / ART / 内存模块执行）。

- **手机端**：App 选项页打开「MCP 工具通道」→ 手机 AI App 导入
  `/sdcard/ATrace/mcp_local_http.json`（Streamable HTTP `127.0.0.1:28472/mcp`）
  或 `mcp_local_sse.json`（旧 SSE `127.0.0.1:28472/sse`）→ 连接后可见 31 个工具。
- **电脑端**：`tools/atrace_mcp.py` 是 stdio MCP 代理，AI 客户端（Claude Desktop / Cursor）
  通过它把 `tools/call` 转发到手机 App 的 adb 桥：

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

  前置：`adb forward tcp:28471 tcp:28471` + App「MCP 工具通道」已开 + 目标已注入并连接 agent。
  离线时 `tools/list` 会用 `tools/mcp_tools_cache.json` 缓存列出工具，调用时提示未连接。

**电脑写脚本、手机执行**（三种方式）：

1. AI 客户端里调 `run_lua` 工具（脚本在目标进程 LuaJIT 执行，`print` 随结果返回）；
2. 运行 `tools\atrace_lua.bat`（电脑 cmd 里编辑/运行 .lua，手机无需开悬浮窗；脚本会自动探测 adb/python 并做 forward）；
3. App 悬浮窗「脚本」页直接写。

完整说明与 31 个工具清单见 **[docs/MCP.md](docs/MCP.md)**。

## Lua API 示例

首次使用先执行 `api()` / `help()` 查看全部函数签名与说明。常用示例：

```lua
-- 环境自检
dump(capabilities(), 1)
print(artStatus())

-- 模块 / 符号
local base = module_info("libc.so").base
print(hexOf(symbol("getpid", "libc.so")))

-- 内存读写
local p = readPtrNum(base + 0x650d8)
print(readI32(p))
writeDword(p, 8888)

-- 原生 hook（观察调用；回调里只做数值运算）
local h = hookfunc(base + sym_openat, function(regs, a) _G.n = (_G.n or 0) + 1 end)
print(h:hits()); h:remove()

-- Java hook（拦截检测 / 拿对象）
artHook("com.example.crc_test.MainActivity$detectRunnable$1", "run", function(ctx)
  return true
end)
```

更多分组示例（模块扫描、hook/回溯、ART、Java 对象、主线程、实战模板）见
**[docs/LUA-API.md](docs/LUA-API.md)**。

## 构建

```bash
# 需要 Android Studio（JBR 17）与 NDK；离线构建示例：
$env:JAVA_HOME='<Android Studio>/jbr'
./gradlew assembleDebug --offline
```

产物：`app/build/outputs/apk/debug/ATrace-debug.apk`（arm64-v8a）。

使用注入、断点、socket relay、内存搜索等功能需要 root。

## 项目结构

- 文档：`README.md`、`docs/MCP.md`（两条 MCP 通道与电脑写脚本）、`docs/LUA-API.md`（Lua API 速查与示例）
- Kotlin 原生悬浮窗 UI：`app/src/main/java/com/Alive/Trace/overlay`
  （气泡、面板、各功能页、JNI 桥、MCP 服务）
- `app/src/main/cpp` 分三部分：

| 目录 | 说明 |
| --- | --- |
| `backend` | 后端复用层：内存搜索、断点客户端、socket 客户端、反汇编/汇编写入；由 `overlay_bridge.cpp` 通过 JNI 暴露 |
| `agent` | SO 端：注入目标进程，内置 LuaJIT、Dobby、LSPlant、xDL、socket 服务端与内存工具 |
| `injector` | 注入器：ptrace 注入、ELF 解析、root 服务（密钥、socket relay、`--bp` 硬件断点服务、`--alloc` 远程分配） |

## 技术实现

### Socket 连接

- agent 监听抽象命名空间 Unix socket（`sun_path[0]='\0'`），不落地文件，规避 SELinux 对
  `/data/local/tmp` socket 文件的限制。
- 密钥由注入器（root）预生成到 `/data/local/tmp/universal_debug_tool_key.bin`
  （32B key + 12B nonce），agent 复用。
- 消息格式：4 字节大端长度 + ChaCha20 密文，双向独立 nonce/计数器。
- GUI 优先直连；被 SELinux 拦截时回退 root relay。
- 固定 socket 名存在「连到旧 agent」风险：客户端连接后校验 agent 返回的 pid，不一致则清理旧宿主进程。

### LuaJIT + Dobby + LSPlant

- agent 维护持久 LuaJIT 状态（含 FFI），脚本经加密 socket 以 `lua <script>` 执行。
- `hookfunc` / `removehook`：DobbyHook 封装，返回跳板；`hookCPU`：DobbyInstrument 寄存器级插桩；
  `call`：闭包排队到目标主线程泵（`eglSwapBuffers` / `ALooper_pollOnce`），否则兜底线程执行。
- ArtHook（LSPlant）：Java 方法 hook、反射调用（findClass / getStatic / setStatic / listMethods）。
- 回调内禁止分配 Lua 表（会崩溃）：提供 `nativeBacktraceInto` 等安全变体。

### 内存搜索

- 搜索引擎运行在 App 进程（MemorySearch，MIT）；App 非 root，经 su + dd 管道读写目标内存，
  maps 枚举同样走 su，不占用 agent socket。
- 精确/范围搜索接入多线程引擎；模糊搜索与「改善」为旧实现（后续可迁移）。

### 硬件断点

- 断点服务以 root 运行（`injector --bp <pid> --parent <app pid>`），基于 `perf_event_open`
  硬件断点，由内核编程调试寄存器；不设 sigtrap，目标不停顿。
- 命中通过 `PERF_SAMPLE_REGS_USER` 采集寄存器（含 `PERF_SAMPLE_REGS_INTR` 兜底），回传 PC、
  tid、堆栈、模块偏移；GUI 可点击跳转内存页。
- `--parent` 看门狗：App 进程退出后断点进程自杀，内核自动释放 perf 事件，避免残留。

### 内存页（GG 风格）

- 整页 0x2000 = 2048 行交给 RecyclerView 虚拟化渲染；一页连续滚动，页首跳转 = 上一页最后一个地址，
  页尾 = 下一页起始。
- 读取：优先整页一次 `memRead` + 一次 `memDisasmBlock`（capstone 句柄常驻）；不可读页分块回退；
  可见区优先反汇编、滚动按需补齐；同页刷新走缓存，重开悬浮窗/切页即时显示。
- 区域类型来自 `/proc/<pid>/maps`（匿名映射统一显示 `A`）。

## 已知问题

1. 断点堆栈以 native 帧（PC + LR）为主，JNI 场景的 Java 帧依赖 `bpJavaStack` 补取，结果仅供参考。
2. 部分内核/机型上 `PERF_SAMPLE_REGS_USER` 采样的个别寄存器可能为 0（已加 REGS_INTR 兜底）。
3. Android 10+ 后台窗口写剪贴板可能被拒：可在「选项」页开启「兼容复制」。
4. Android 16 对匿名可执行内存（execmem）有限制，rwx 分配可能随机失败，工具会降级为 rw 并提示。
5. 注入/断点/Lua 等能力仅在作者机型（Android 16，arm64）充分验证，其他机型兼容性不保证。

## 参考库与改动说明

| 库 | 用途 | 改动情况 | 许可证 |
| --- | --- | --- | --- |
| [asmjit](https://github.com/asmjit/asmjit) | AArch64 汇编文本写入 | 未改源码，仅新增封装层；CMake 只编译 core/support/arm 子集 | Zlib |
| [capstone](https://github.com/capstone-engine/capstone) | 反汇编 | 未改源码（句柄常驻复用） | BSD-3-Clause |
| [xDL](https://github.com/hexhacking/xDL) | so 遍历、基址解析 | 未改源码 | MIT |
| [LuaJIT](https://github.com/LuaJIT/LuaJIT) | 脚本引擎 | 未改源码 | MIT |
| [Dobby](https://github.com/jmpews/Dobby) | inline hook | 未改源码，预编译 `libdobby.a`，LuaEngine 薄封装 | Apache-2.0 |
| [LSPlant](https://github.com/LSPosed/LSPlant) | Java 方法 hook | 未改源码，预编译静态库 | LGPL-3.0 |
| [AndroidInject](https://github.com/niqiuqiux/AndroidInject) | ptrace 注入器基础 | 未改源码 | 上游未确认，详见上游仓库 |
| [MemorySearch](https://github.com/Aboy-g/MemorySearch) | 内存读写 / 搜索 | 剔除 Keystone 依赖；新增 su 后端适配器；源码位于 `backend/jni/memsearch` | MIT |

## 开源协议

本项目自身代码以 Apache License 2.0 发布（见 [LICENSE](LICENSE)），集成的第三方库保留其原有许可证。

## 致谢

感谢 asmjit、capstone、xDL、LuaJIT、Dobby、LSPlant、AndroidInject、MemorySearch 等开源项目及其作者。


## 免责声明

1. 本工具仅限合法用途（学习研究、调试自己拥有权限的程序等），禁止用于非法活动，使用者自行承担法律责任。
2. 作者不承诺持续维护；需求请自行 fork 修改编译。
3. 仅在作者机型（Android 16，arm64）验证通过，不保证其他 Android 版本/机型兼容。
4. 本 README 由 AI 协助整理，可能与实际实现存在差异。

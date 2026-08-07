# Universal Debug Tool（通用动态调试工具）

面向 **ARM64 Android** 的本地动态调试工具：在不挂起目标进程的前提下，实现函数插桩、硬件断点、主动调用与实时内存读写、搜索、修改。整个工具被打包成一个 Android APK，注入与调试能力依赖设备 root。

## 功能概览

- **进程管理**：root 下按 PID / 包名枚举进程，支持刷新列表。
- **动态注入**：基于 ptrace 将 agent.so（集成 LuaJIT 与 Dobby）注入目标进程；注入器负责 ELF 解析、远程内存分配、dlopen 等。
- **加密通信**：GUI 与 agent 之间通过本地 Unix socket 通信，负载使用 ChaCha20 加密，双向独立密钥流。
- **内存查看与修改**
  - 解析 `/proc/<pid>/maps` 与 `/proc/<pid>/mem`，按 GG 风格对内存页分类（code app、code system、anonymous、java heap、cpp heap、stack、ashmem 等）。
  - 连续 / 分页两种浏览模式，支持内存类型多选筛选、数值类型切换（dword、float、utf8、utf16、hex 等）。
  - 单条内存修改、偏移跳转、地址保存页、链接库基址跳转。
  - 内存搜索：精确搜索、模糊搜索、改善搜索结果，内存类型可多选。
- **动态调试**
  - LuaJIT 脚本引擎（FFI）：`hookfunc` inline hook、`hookCPU` 寄存器级插桩、`call` 主动调用、内存读写辅助。
  - 硬件断点（root）：对目标进程所有线程下断，命中后回传寄存器、PC 与堆栈，地址可点击跳转内存页。
  - 反汇编（capstone）与汇编写入（asmjit）：内存页内可直接修改指令，例如输入 `~A8 nop`。
- **悬浮窗 GUI**：ImGui 界面，支持收起 / 展开、防录屏、输入法唤起等。

## 构建

- Android Studio 工程，执行 `assembleDebug` 可一次性构建 GUI（imgui）、agent.so、注入器并打包为一个 APK。
- 使用注入、断点、socket relay 等功能需要 root 权限。

## 项目结构

`app/src/main/cpp` 下主要分三部分：

| 目录 | 说明 |
| --- | --- |
| `imgui` | GUI 端：悬浮窗渲染、ImGui 界面、触摸处理、socket 客户端、内存搜索、反汇编、汇编写入；所依赖的开源库（imgui、capstone、asmjit 等）直接放在该目录下 |
| `agent` | SO 端：注入目标进程，内置 LuaJIT、Dobby、xDL、socket 服务端与内存工具 |
| `injector` | 注入器：ptrace 注入、ELF 解析、root 服务（密钥生成、socket relay、断点服务） |

## 技术实现

### Socket 连接方案

- agent 作为 Unix 域 socket 服务端，监听**抽象命名空间**（`sun_path[0] = '\0'`），不落地 socket 文件，从而规避 SELinux 对 `/data/local/tmp` 下 socket 文件的限制。
- 加密密钥由注入器（root）预先生成到 `/data/local/tmp/universal_debug_tool_key.bin`（32 字节 key + 12 字节 nonce），agent 直接复用，避免注入后因权限不足而无法生成。
- 消息格式为 4 字节大端长度 + ChaCha20 密文；两个方向使用独立 nonce 与消息计数器，防止重放与串流。
- GUI 端优先直连 socket；若被 SELinux 拦截，则回退到 root relay：通过 su 启动注入器的 relay 模式，在 stdin/stdout 与 socket 之间转发。

### LuaJIT 交互 Dobby

- agent 维护一个持久 LuaJIT 状态（含 FFI），脚本通过加密 socket 以 `lua <script>` 消息执行，输出回传 GUI 日志框。
- 主要 API：
  - `getBase`：使用 xDL（`xdl_iterate_phdr`）遍历目标进程已加载的 so，返回基址。
  - `hookfunc` / `removehook`：封装 DobbyHook，返回跳板地址与成功标志；脚本通过 FFI 将跳板转成函数指针以调用原函数。
  - `hookCPU`：封装 DobbyInstrument，回调中提供寄存器上下文（lightuserdata）与函数地址。
  - `call`：经 `eglSwapBuffers` hook 把 Lua 闭包投递到目标主线程 / 渲染线程执行，解决跨线程调用问题。
  - `read*` / `write*`：内存读写辅助函数。
- hook 回调与脚本执行共用递归互斥锁，避免回调中再次执行 Lua 造成死锁。

### 断点实现

- 断点服务以 root 运行（注入器 `--bp` 模式），基于 Linux `perf_event_open` 硬件断点（`PERF_TYPE_BREAKPOINT`），由内核直接编程 CPU 调试寄存器。
- 周期性重扫目标进程全部线程并统一挂断点，且不设置 sigtrap 位：目标进程不会停顿、不会被 ptrace、也不会收到 SIGTRAP。
- 命中时通过 `PERF_SAMPLE_REGS_USER` 采集寄存器（跳过 `regs_user_abi` 字段），连同 PC、线程 ID、堆栈链一并回传。
- 与 GUI 通过管道协议通信（stdin：set / clear / clearall / list / ping / quit；stdout：OK / ERR / INFO / HIT）。GUI 断点页展示寄存器网格、PC 汇编与堆栈链，PC / 寄存器 / 堆栈地址均可点击跳转内存页。

## 已知问题

1. 新建子 GUI（如链接库窗口、内存修改窗口）会导致主 UI 闪现，关闭子窗口后主窗口位置可能被重置。
2. 新建子 GUI 后系统触摸事件会被拦截，出现"只有 ImGui 可交互、系统界面触摸失灵"的问题（悬浮窗整体已做不触摸穿透处理，子窗口路径仍有该缺陷）。

## 可优化方向

- 内存搜索耗时较长：当前搜索由 GUI 端组织、经 socket 逐页读取内存；可改为 agent 端直接搜索并返回结果集，或按页批量读取缓存。
- 子窗口渲染与触摸分发：可考虑子窗口独立纹理渲染、统一触摸事件分发路径，从根源上解决闪现与触摸拦截问题。

## 参考库与改动说明

| 库 | 用途 | 改动情况 | 许可证 |
| --- | --- | --- | --- |
| [Qimgui](https://github.com/ohno1007/Qimgui) | Android 端 ImGui 悬浮窗基础 | 修复了触摸穿透；修改了界面布局，UI 重写为调试工具界面 | 上游未明确标注（内部 ANativeWindowCreator.h 标 MIT，另含 AndroidSurfaceImgui-Enhanced（MIT）与 Google NDK Vulkan wrapper（Apache-2.0）），详见上游仓库 |
| [imgui](https://github.com/ocornut/imgui) | GUI 渲染 | 预编译，核心未改动 | MIT |
| [asmjit](https://github.com/asmjit/asmjit) | AArch64 汇编文本写入 | 未改源码，仅新增封装层（Disasm/AsmWrite.h）；CMake 只编译 core/support/arm 子集 | Zlib |
| [capstone](https://github.com/capstone-engine/capstone) | 反汇编 | 未改源码 | BSD-3-Clause |
| [xDL](https://github.com/hexhacking/xDL) | so 遍历、基址解析 | 未改源码 | MIT |
| [LuaJIT](https://github.com/LuaJIT/LuaJIT) | 脚本引擎 | 未改源码 | MIT |
| [Dobby](https://github.com/jmpews/Dobby) | inline hook | 未改源码，使用预编译 `libdobby.a`，经 LuaEngine 薄封装 | Apache-2.0 |
| [AndroidInject](https://github.com/niqiuqiux/AndroidInject) | ptrace 注入器基础 | 未改源码 | 上游未确认，详见上游仓库 |

## 开源协议

本项目自身代码以 Apache License 2.0 发布（见 [LICENSE](LICENSE)），项目内集成的第三方开源库保留其原有许可证，详见上文"参考库与改动说明"。

## 致谢

感谢以下开源项目及其作者：Qimgui、ImGui、asmjit、capstone、xDL、LuaJIT、Dobby、AndroidInject。

特别感谢 Codex（OpenAI）在本项目开发过程中协助编写代码。

## 免责声明

本人不一定会对该项目进行维护，如有需求者，请自行下载源码修改并编译。

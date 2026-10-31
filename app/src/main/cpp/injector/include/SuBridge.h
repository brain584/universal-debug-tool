// ─────────────────────────────────────────────────────────────────────────────
//
//  为什么需要它：本工程原先有 11 处各自拼 "su -c '...'"（native-lib.cpp、
//  BpService.cpp、SocketClient.cpp），全都假设 `su` 在 PATH 里。
//  这个假设在 KernelSU 的设备上不成立 —— KernelSU 的 su 由内核在 execve 上
//  拦截，**不以文件形式出现在普通 App 的挂载命名空间**里，裸 `su` 直接 ENOENT。
//      ATrace 进程 /proc/<pid>/root/system/bin/su  -> No such file or directory
//      App 里 `su -c id`                            -> rc=127
//      而 `/system/bin/sh -c 'su -c id'`             -> uid=0（可用）
//  所以统一走 SuWrap()：用 /system/bin/sh -c 包一层，并补上 KernelSU 的 bin 目录。
//
//  实现体在 native-lib.cpp（同一 .so 内的全局符号）。
// ─────────────────────────────────────────────────────────────────────────────
#pragma once

#include <string>

// 把一条"要在 root 下执行的命令"包成完整、可直接 popen/execl 的 shell 命令行。
//
// `merge_stderr`（默认 true）决定结尾是 `2>&1` 还是 `2>/dev/null`，这一点很关键：
//   * popen 抓输出给人看（suCmd / 注入器日志）→ 需要合并，否则看不到报错；
//   * **走 stdout 的协议流**（BpService 的 `HIT addr=...`、SocketClient 的 relay）
//     → **必须不合并**，否则 stderr 会污染协议。
//
// ⚠️ 它内部用 `/system/bin/sh -c` 包了一层（为了让裸 `su` 在 App 里能被解析）。
// 因此**只能用于 popen**：`popen()` 自己就会起一个 sh。
// 如果调用方自己已经 fork+execl("/system/bin/sh","-c",...)，
// 必须改用下面的 SuSpawnCommand()，否则会套成 sh→sh→su→sh 四层，
std::string SuWrap(const std::string& cmd, bool merge_stderr = true);

// 当前解析出的 su 路径；返回空串表示"依赖 PATH 上的裸 su"
// （注意：KernelSU 场景下这是正常值，不要把空串当成错误）。
const char* SuPath();

// 直接执行并捕获输出（stdout+stderr 合并）。空串 = 执行失败。
std::string SuRun(const std::string& cmd);

// ── 供 fork+pipe 协议调用方（BpService / SocketClient relay）──
//
// 返回的是**给 `execl("/system/bin/sh","-c",...)` 直接用的命令串**，
// 即原始实现的形式：
//     su -c '<cmd>' 2>/dev/null
// **不要再套外层 sh -c**——调用方自己已经起了 sh。
std::string SuSpawnCommand(const std::string& cmd);

// 断点服务启动形态自检：用 App 内真实的 fork+execl 方式，
// 对比"原始 su -c 形式"与"合并 stderr 形式"能否让子进程活过 150ms。
// 返回可直接显示给用户的文本。实现在 native-lib.cpp。
std::string BuildSpawnDiag();

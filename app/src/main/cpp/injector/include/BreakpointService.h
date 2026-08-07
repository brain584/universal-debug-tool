#pragma once

#include <sys/types.h>

// 硬件断点 / 监视点服务。
//
// 以 root 运行（由 imgui 应用通过 `su` 启动），用 Linux
// perf_event_open 硬件断点监视 `targetPid` 的每个线程
//（PERF_TYPE_BREAKPOINT）。内核编程 CPU 调试寄存器，
// 每次命中记录 perf 样本，目标进程永远不会被
// 停止、ptrace 或发信号（我们从不设置 perf "sigtrap" 位）。
//
// 服务通过 stdin/stdout 以纯文本行通信：
//   stdin:  set <hexaddr> <x|r|w|rw> [1|2|4|8]
//           clear <hexaddr>
//           clearall
//           list
//           ping
//           quit
//   stdout: OK <...> / ERR <...> / INFO <...> /
//           HIT addr=0x.. tid=.. pc=0x.. <regs> stack=0x<sp>>0x..>0x..
//     （stack 字段列出起始地址 (sp)，后面跟着
//      sp、sp+8 ... 处的 8 字节数据，用 '>' 分隔）
//
// 返回进程退出码。
int RunBreakpointService(pid_t targetPid);

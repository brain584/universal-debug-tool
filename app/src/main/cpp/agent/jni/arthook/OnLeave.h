// ============================================================================
//  OnLeave.h —— 「函数返回后回调」（on-leave / trace 模式）的 C ABI
//
//  机制（实现见 OnLeave.cpp + OnLeaveStub.S）：
//    DobbyHook(target, stub) 把目标函数入口换成一页运行时生成的 arm64 跳板，
//    跳板先保存调用现场、调 Dobby 的 origin trampoline 跑完原函数，然后调用
//    本头文件声明的 C 桥，最后恢复现场 ret 回调用方。
//
//  桥签名（由 Lua 层实现；**安装任何 hook 之前必须先 set_bridge**）：
//
//    void bridge(uint64_t* regs8, uint64_t* ret_io, int hook_id);
//
//    regs8[0..7]  进入目标函数时的 x0..x7（整数/指针参数，含 this）。
//                 只读快照：改它没有意义（原函数已经执行完了）。
//                 **指针只在 bridge 执行期间有效**（它指向跳板的栈帧），
//                 要留存就自己把值拷走。
//    ret_io[0]    目标函数返回的 x0（整数/指针返回值）。
//                 **可写**：写它 = 改这次调用的返回值（只对 x0 生效）。
//    ret_io[1]    返回的 q0 低 64 位（浮点返回值快照，只读；写它无效）。
//                 同样只在 bridge 执行期间有效。
//    hook_id      install 时传入的 id（0..65535），用于让同一个 bridge 分派多个 hook。
//
//  支持范围 / 限制（不满足的函数不要用 hookAfter）：
//    * 只支持「整数/指针参数 ≤ 8 个、没有栈传参」的函数（ARM64 AAPCS64: x0..x7）；
//    * 不支持 sret：返回值只能是 x0 能装下的（≤16B 且不需要隐藏指针；
//      大于 16B 的结构体按值返回会走 x8，会坏）；
//    * 浮点/向量**参数**不支持（q0..q7 会原样传给原函数，但桥里看不到）；
//      浮点返回值只能读（ret_io[1]），不能改；
//    * 目标函数必须会正常返回（noreturn 函数永远等不到回调）；
//    * 同一 target 同时只能有一个 on-leave hook（重复 install 返回 0 并写 err）；
//    * 目标地址必须在可执行映射里（本模块会检查 /proc/self/maps）。
//
//  ⚠ 调用上下文：bridge 会在**目标进程的任意线程**里被调用，而且此时可能正持有
//  目标自己的锁/在信号处理路径上。桥实现必须短小：只做「把参数/返回值塞进队列」
//  之类的动作，不要阻塞、不要长时间持锁、不要抛异常；重活请排队到主线程/Lua 泵
//  （这部分由 Lead 的 Lua 层负责）。本模块只保证寄存器现场正确，不做调度。
//
//  线程安全：set_bridge / install / uninstall / is_hooked 均由内部 mutex 串行化；
//  bridge 的调用来自由目标线程（不属于本模块的锁保护范围）。
// ============================================================================
#ifndef ATRACE_ONLEAVE_H
#define ATRACE_ONLEAVE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// hook_id 上限：跳板里用一条 `movz w2, #imm16` 传 id。
#define ATRACE_ONLEAVE_MAX_HOOK_ID 65535

typedef void (*atrace_onleave_bridge)(uint64_t* regs8, uint64_t* ret_io, int hook_id);

// 设置全局桥函数（所有后续 install 的跳板都会快照这个指针）。
// 传 NULL 只影响"之后的 install"（已安装的跳板仍用旧指针），install 会拒绝。
// 返回：无。
void atrace_onleave_set_bridge(atrace_onleave_bridge fn);

// 安装 on-leave hook。
//   target  : 目标函数地址（必须是可执行映射；内部会 Untag 无关，直接按原样用）
//   hook_id : 传给 bridge 的 id，范围 0..65535
//   err/cap : 失败时写人类可读原因（UTF-8，总能 NUL 结尾）
// 返回：1 = 成功；0 = 失败（原因在 err）。
int atrace_onleave_install(uintptr_t target, int hook_id, char* err, int cap);

// 卸载 on-leave hook（DobbyDestroy 恢复目标入口 + munmap 跳板页）。
// 返回：1 = 成功卸载；0 = 没装过/取消失败。
// ⚠ 不要在目标线程正在执行该函数时卸载：DobbyDestroy 之后跳板页会被 munmap，
//   若还有线程停在里面会崩（与项目里其他 DobbyDestroy 用法同一风险）。
int atrace_onleave_uninstall(uintptr_t target);

// 查询 target 是否装有 on-leave hook。返回 1/0。
int atrace_onleave_is_hooked(uintptr_t target);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ATRACE_ONLEAVE_H

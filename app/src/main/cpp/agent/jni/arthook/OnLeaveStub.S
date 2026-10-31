// ============================================================================
//  OnLeaveStub.S —— 「函数返回后回调」（on-leave / trace 模式）的 arm64 跳板模板
//  2026-10-30 新增（P1-13 底层；Lua 层 hookAfter 由 Lead 接）
//
//  这不是一段可执行代码，而是**模板**：OnLeave.cpp 在 install 时把
//  [atrace_onleave_template_start, atrace_onleave_template_end) 整段 memcpy 到
//  自己 mmap 的一页 RW 内存里，按符号偏移打好补丁，再 mprotect(PROT_READ|EXEC)，
//  最后 DobbyHook(target, stub, &origin) 把目标函数入口换成这块跳板。
//
//  运行时数据流：
//      caller → target(已被 Dobby 改成跳转) → [本跳板]
//        ├─ 保存 x0..x7 / q0..q7 / x29 / x30（全部按 AAPCS64 传参现场）
//        ├─ ldr x16,[lit_orig_slot] ; blr x16   → Dobby 的 origin trampoline
//        │      （trampoline 跑完被覆盖的 prologue 后跳回 target+prologue）
//        ├─ 保存返回的 x0 / q0 / q1
//        ├─ bridge(regs8=保存的 x0..x7, ret_io=&返回x0, hook_id)
//        ├─ 从 ret_io 重载 x0（**允许桥改返回值**），恢复 x1、q0/q1、x29/x30
//        └─ ret 回 caller
//
//  限制（与 OnLeave.h 的说明一致，不要拿不满足的函数去 hook）：
//    * 只支持「整数/指针参数 ≤ 8 个、无栈传参」的函数（ARM64 AAPCS64 的 x0..x7）；
//    * 没有 sret（>16B 结构体按值返回，隐藏指针走 x8）——返回值只认 x0；
//    * 浮点/向量参数不支持（q0..q7 原样传给原函数，但桥拿不到）；
//      浮点返回值只能读快照、不能改（桥只改 x0）；
//    * 函数必须正常 ret（noreturn 函数桥永远不会被调用）。
//
//  栈帧布局（FRAME_SIZE=256，进入时 sp 16 字节对齐，减 256 后仍对齐）：
//      +000  x0,x1        +016  x2,x3        +032  x4,x5        +048  x6,x7
//      +064  q0,q1        +096  q2,q3        +128  q4,q5        +160  q6,q7
//      +192  q0_ret,q1_ret（返回时的 FP 现场，桥返回后从这里恢复）
//      +224  x29,x30（caller 的 fp/lr）
//      +240  ret_io[0] = 返回的 x0（桥可改）
//      +248  ret_io[1] = 返回的 q0 低 64 位（只读快照，给 Lua 看浮点返回值）
//
//  模板尾部两个字面量槽（C++ 用 (uintptr_t)&sym - (uintptr_t)&start 算偏移）：
//      atrace_onleave_lit_orig_slot : 指向 C++ 侧 uintptr_t 槽的**指针**
//                                     （该槽里放 Dobby 给的 origin trampoline 地址）
//      atrace_onleave_lit_bridge    : bridge 函数指针
//  另外 atrace_onleave_hookid_insn 指向 `movz w2, #imm16` 那条指令，
//  C++ 用 0x52800002 | (hook_id << 5) 覆写它（hook_id 限 0..65535）。
//
//  为什么 orig 用「指针的指针」而不是直接把 origin 写进字面量：
//  DobbyHook 是**先**把 target 入口改成跳到本跳板、**然后**才返回 origin 指针，
//  所以 origin 在跳板已上线之后才知道。若字面量里存 origin 本身，就只能
//  mprotect(RW) 再改一次可执行页（会短暂让跳板不可执行 → 正好被调用的线程崩）。
//  现在字面量存的是「RW 数据槽的地址」，安装后只需一次 8 字节对齐存储即可生效，
//  跳板页全程保持 RX。
//  竞态兜底：origin 还没写进槽之前（窗口 = 一次纳秒级 store），槽里放的是
//  atrace_onleave_safe_zero_ret（mov x0,xzr; ret），此时正好被调用只会返回 0，
//  不会崩目标。
// ============================================================================

    .text

// 帧内偏移（不用表达式，避免 clang 集成汇编器的立即数解析差异）
#define FRAME_SIZE   256
#define SAVED_X0     0
#define SAVED_X1     8
#define SAVED_X23    16
#define SAVED_X45    32
#define SAVED_X67    48
#define SAVED_Q01    64
#define SAVED_Q23    96
#define SAVED_Q45    128
#define SAVED_Q67    160
#define RET_Q0       192
#define SAVED_FP     224
#define RET_IO       240
#define RET_Q0_LOW   248

    .p2align 3
    .globl  atrace_onleave_template_start
    .hidden atrace_onleave_template_start
    .type   atrace_onleave_template_start, %object
atrace_onleave_template_start:

    // BTI 落地桩：ARMv8.5+ 且进程启用 BTI 时，若 Dobby 用 `br` 间接跳到本页，
    // 入口必须有 BTI landing pad；旧核把 `bti` 当 NOP（HINT），无副作用。
    // 注意：它占用模板第 0..3 字节，所有偏移都由 C++ 用符号差值算，不写死。
    bti     c

    // ── 1) 保存传参现场（不碰 x0..x7，随后原样交给原函数）──
    sub     sp, sp, #FRAME_SIZE
    stp     x0, x1, [sp, #SAVED_X0]
    stp     x2, x3, [sp, #SAVED_X23]
    stp     x4, x5, [sp, #SAVED_X45]
    stp     x6, x7, [sp, #SAVED_X67]
    stp     q0, q1, [sp, #SAVED_Q01]
    stp     q2, q3, [sp, #SAVED_Q23]
    stp     q4, q5, [sp, #SAVED_Q45]
    stp     q6, q7, [sp, #SAVED_Q67]
    stp     x29, x30, [sp, #SAVED_FP]

    // ── 2) 调原函数：x16 = *atrace_onleave_lit_orig_slot ──
    ldr     x16, atrace_onleave_lit_orig_slot
    ldr     x16, [x16]
    blr     x16

    // ── 3) 保存返回值（x0 给桥读写；q0/q1 快照，桥返回后恢复）──
    str     x0, [sp, #RET_IO]
    stp     q0, q1, [sp, #RET_Q0]
    str     d0, [sp, #RET_Q0_LOW]

    // ── 4) bridge(saved_regs, ret_io, hook_id) ──
    mov     x0, sp                       // regs8：保存的 x0..x7 连续 8 个 u64
    add     x1, sp, #RET_IO              // ret_io：ret_io[0]=返回 x0（可写）
    .globl  atrace_onleave_hookid_insn
    .hidden atrace_onleave_hookid_insn
    .type   atrace_onleave_hookid_insn, %object
atrace_onleave_hookid_insn:
    movz    w2, #0                       // ← hook_id 占位，C++ 按位覆写这条指令
    ldr     x16, atrace_onleave_lit_bridge
    blr     x16

    // ── 5) 重载返回值 / 恢复现场 / 返回 caller ──
    ldr     x0, [sp, #RET_IO]            // 桥可以改这里 → 改函数返回值
    ldp     q0, q1, [sp, #RET_Q0]        // 浮点返回值原样带回（桥不可改）
    ldr     x1, [sp, #SAVED_X1]          // 按约定恢复 x1（其余 x2..x7 是 caller-saved）
    ldp     x29, x30, [sp, #SAVED_FP]
    add     sp, sp, #FRAME_SIZE
    ret

    // ── 竞态兜底用的"假原函数"：origin 槽还没填时被调用就走这里（返回 0，不崩）──
    .p2align 2
    .globl  atrace_onleave_safe_zero_ret
    .hidden atrace_onleave_safe_zero_ret
    .type   atrace_onleave_safe_zero_ret, %function
atrace_onleave_safe_zero_ret:
    mov     x0, xzr
    ret

    // ── 模板尾部：两个字面量槽（安装时 patch，均 8 字节对齐）──
    .p2align 3
    .globl  atrace_onleave_lit_orig_slot
    .hidden atrace_onleave_lit_orig_slot
    .type   atrace_onleave_lit_orig_slot, %object
atrace_onleave_lit_orig_slot:
    .quad   0                            // ← C++ 填 &orig_slot（orig_slot 在 RW 数据里）
    .globl  atrace_onleave_lit_bridge
    .hidden atrace_onleave_lit_bridge
    .type   atrace_onleave_lit_bridge, %object
atrace_onleave_lit_bridge:
    .quad   0                            // ← C++ 填 bridge 函数指针

    .p2align 3
    .globl  atrace_onleave_template_end
    .hidden atrace_onleave_template_end
    .type   atrace_onleave_template_end, %object
atrace_onleave_template_end:

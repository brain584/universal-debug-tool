// ============================================================================
//
//  设计要点见 OnLeave.h（ABI/限制）与 OnLeaveStub.S（模板/栈帧/竞态兜底）。
//  这里只负责：
//    1) 把模板拷进一页 RW 匿名内存，按符号偏移 patch 两个字面量槽 + hook_id 指令；
//    2) mprotect(PROT_READ|PROT_EXEC) 后 DobbyHook(target, stub, &origin)；
//    3) 把 origin 写进 8B 对齐的数据槽（跳板全程保持 RX，不需要二次 mprotect）；
//    4) uninstall = DobbyDestroy + munmap + free + 从表里删。
//
//  不依赖 Lua：bridge 由调用方（Lua 层）在 install 之前用 set_bridge 注入。
// ============================================================================
#include "OnLeave.h"

#include <android/log.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <map>
#include <mutex>

#include "dobby.h"

#define LOG_TAG "OnLeave"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ── 汇编模板符号（定义在 OnLeaveStub.S；偏移一律用 (uintptr_t)&sym - (uintptr_t)&start 算）──
extern "C" {
extern unsigned char atrace_onleave_template_start[];
extern unsigned char atrace_onleave_template_end[];
extern unsigned char atrace_onleave_lit_orig_slot[];
extern unsigned char atrace_onleave_lit_bridge[];
extern unsigned char atrace_onleave_hookid_insn[];
extern unsigned char atrace_onleave_safe_zero_ret[];
}

namespace {

struct OnLeaveHookInfo {
    void*     stub       = nullptr;   // 跳板页基址（RX）
    size_t    page_size  = 0;
    uintptr_t* orig_slot = nullptr;   // 8B 对齐槽：Dobby 的 origin trampoline 地址
    int       hook_id    = 0;
};

std::mutex                              g_mutex;
std::map<uintptr_t, OnLeaveHookInfo>    g_hooks;
atrace_onleave_bridge                   g_bridge = nullptr;

void SetErr(char* err, int cap, const char* fmt, ...) {
    if (!err || cap <= 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err, (size_t)cap, fmt, ap);
    va_end(ap);
    err[cap - 1] = '\0';
}

// 目标是否在可执行映射里。拿不到 maps 时宽松放行（与 LuaEngine.h 的
// AddrInExecMapping 同一取舍），避免在受限环境里把正常 hook 判死。
bool IsExecutableAddr(uintptr_t addr) {
    if (addr == 0) return false;
    FILE* maps = fopen("/proc/self/maps", "re");
    if (!maps) return true;
    char line[512];
    bool ok = false;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long long start = 0, end = 0;
        char perms[5] = {0};
        if (sscanf(line, "%llx-%llx %4s", &start, &end, perms) != 3) continue;
        if (addr >= start && addr < end) {
            ok = (perms[2] == 'x');
            break;
        }
    }
    fclose(maps);
    return ok;
}

void StoreWord(void* base, uintptr_t sym, uintptr_t start, uint32_t value) {
    memcpy((uint8_t*)base + ((uintptr_t)sym - start), &value, sizeof(value));
}

void StorePtr(void* base, uintptr_t sym, uintptr_t start, uintptr_t value) {
    memcpy((uint8_t*)base + ((uintptr_t)sym - start), &value, sizeof(value));
}

}  // namespace

extern "C" {

void atrace_onleave_set_bridge(atrace_onleave_bridge fn) {
    std::lock_guard<std::mutex> lk(g_mutex);
    g_bridge = fn;
    LOGI("bridge set: %p", (void*)(uintptr_t)fn);
}

int atrace_onleave_install(uintptr_t target, int hook_id, char* err, int cap) {
    if (err && cap > 0) err[0] = '\0';

    if (target == 0) {
        SetErr(err, cap, "目标地址不能为 0");
        return 0;
    }
    if (hook_id < 0 || hook_id > ATRACE_ONLEAVE_MAX_HOOK_ID) {
        SetErr(err, cap, "hook_id 必须在 0..%d 之间（当前 %d）",
               ATRACE_ONLEAVE_MAX_HOOK_ID, hook_id);
        return 0;
    }
    if (!IsExecutableAddr(target)) {
        SetErr(err, cap, "目标 0x%llx 不在可执行映射里（地址是否算错/漏了 getBase？）",
               (unsigned long long)target);
        return 0;
    }

    std::lock_guard<std::mutex> lk(g_mutex);

    if (!g_bridge) {
        SetErr(err, cap, "bridge 未设置：安装前必须先调用 atrace_onleave_set_bridge()");
        return 0;
    }
    auto exist = g_hooks.find(target);
    if (exist != g_hooks.end()) {
        SetErr(err, cap, "目标 0x%llx 已安装 on-leave hook（hook_id=%d），先卸载再装",
               (unsigned long long)target, exist->second.hook_id);
        return 0;
    }

    const uintptr_t tpl_start = (uintptr_t)atrace_onleave_template_start;
    const uintptr_t tpl_end   = (uintptr_t)atrace_onleave_template_end;
    const size_t    tpl_size  = (size_t)(tpl_end - tpl_start);
    const long      ps        = sysconf(_SC_PAGESIZE);
    if (ps <= 0) {
        SetErr(err, cap, "sysconf(_SC_PAGESIZE) 失败：%s", strerror(errno));
        return 0;
    }
    const size_t page_size = (size_t)ps;
    if (tpl_size == 0 || tpl_size > page_size) {
        SetErr(err, cap, "汇编模板尺寸异常（%zu 字节 > 页大小 %zu）", tpl_size, page_size);
        return 0;
    }

    // origin 槽：8 字节对齐的独立 RW 数据（跳板通过字面量里的指针访问它），
    // 这样 DobbyHook 之后写 origin **不需要**把跳板页临时改回可写。
    uintptr_t* orig_slot = (uintptr_t*)calloc(1, sizeof(uintptr_t));
    if (!orig_slot) {
        SetErr(err, cap, "calloc(origin slot) 失败");
        return 0;
    }

    void* stub = mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (stub == MAP_FAILED) {
        const int e = errno;
        free(orig_slot);
        SetErr(err, cap, "mmap(跳板页) 失败：%s", strerror(e));
        return 0;
    }

    // 1) 拷模板 + patch
    memcpy(stub, atrace_onleave_template_start, tpl_size);
    StorePtr(stub, (uintptr_t)atrace_onleave_lit_orig_slot, tpl_start, (uintptr_t)orig_slot);
    StorePtr(stub, (uintptr_t)atrace_onleave_lit_bridge, tpl_start, (uintptr_t)g_bridge);
    // `movz w2, #imm16`：0x52800002 | (imm16 << 5)（hook_id 已校验 ≤ 0xFFFF）
    StoreWord(stub, (uintptr_t)atrace_onleave_hookid_insn, tpl_start,
              0x52800002u | ((uint32_t)hook_id << 5));

    // 2) 竞态占位：DobbyHook 返回前若有线程正好调用 target，跳板会 blr 到这里
    //    （返回 0，不崩目标）。窗口 = DobbyHook 返回后的一次 8B 存储（纳秒级）。
    *orig_slot = (uintptr_t)stub +
                 ((uintptr_t)atrace_onleave_safe_zero_ret - tpl_start);

    // 3) RW → RX（先写后改权限；跳板页全程不再需要写）
    if (mprotect(stub, page_size, PROT_READ | PROT_EXEC) != 0) {
        const int e = errno;
        munmap(stub, page_size);
        free(orig_slot);
        SetErr(err, cap, "mprotect(RX) 跳板页失败：%s", strerror(e));
        return 0;
    }
    // 改完权限再刷 i-cache（写入的指令/字面量已定型；DobbyHook 前必须刷完）。
    __builtin___clear_cache((char*)stub, (char*)stub + tpl_size);

    // 4) 用 Dobby 替换目标入口。失败时必须把刚分配的页/槽全部回收。
    void* origin = nullptr;
    const int rc = DobbyHook((void*)target, stub, &origin);
    if (rc != 0 || origin == nullptr) {
        munmap(stub, page_size);
        free(orig_slot);
        SetErr(err, cap, "DobbyHook 失败（rc=%d, origin=%p）", rc, origin);
        LOGE("DobbyHook(target=0x%llx) failed rc=%d origin=%p",
             (unsigned long long)target, rc, origin);
        return 0;
    }

    // 5) 关窗：8B 对齐存储（ARM64 上是单条 str，不会撕裂/不是复合写）
    *orig_slot = (uintptr_t)origin;

    OnLeaveHookInfo info;
    info.stub      = stub;
    info.page_size = page_size;
    info.orig_slot = orig_slot;
    info.hook_id   = hook_id;
    g_hooks[target] = info;

    LOGI("installed on-leave hook: target=0x%llx hook_id=%d stub=%p orig=%p tpl=%zuB",
         (unsigned long long)target, hook_id, stub, origin, tpl_size);
    return 1;
}

int atrace_onleave_uninstall(uintptr_t target) {
    std::lock_guard<std::mutex> lk(g_mutex);
    auto it = g_hooks.find(target);
    if (it == g_hooks.end()) {
        LOGE("uninstall: target=0x%llx 没有 on-leave hook", (unsigned long long)target);
        return 0;
    }

    // 先恢复目标入口，再回收跳板：顺序反了会有线程停在已 munmap 的页里。
    const int rc = DobbyDestroy((void*)target);
    if (rc != 0) {
        // 取消失败：保留记录与跳板（它还在被目标使用），让调用方重试/放弃。
        LOGE("DobbyDestroy(target=0x%llx) failed rc=%d，保留跳板不释放",
             (unsigned long long)target, rc);
        return 0;
    }

    munmap(it->second.stub, it->second.page_size);
    free(it->second.orig_slot);
    g_hooks.erase(it);
    LOGI("uninstalled on-leave hook: target=0x%llx", (unsigned long long)target);
    return 1;
}

int atrace_onleave_is_hooked(uintptr_t target) {
    std::lock_guard<std::mutex> lk(g_mutex);
    return g_hooks.find(target) != g_hooks.end() ? 1 : 0;
}

}  // extern "C"

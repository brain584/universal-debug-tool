#ifndef UDT_LUA_ENGINE_H
#define UDT_LUA_ENGINE_H

// Agent 侧 Lua 调试引擎。
//
// 把 LuaJIT（启用 FFI）+ Dobby（内联 hook / instrument）封装成
// 位于被注入进程内的持久 Lua 状态。imgui
// 悬浮层通过加密 socket 发送脚本；本引擎执行它们
// 并返回捕获的输出。
//
// 暴露的 Lua API（完整清单运行时可用 api() / help() 自描述）：
//   print(...)                  -> 捕获到命令响应中
//   getBase("libxxx.so")        -> 模块基址（xdl）
//   api([name])                 -> 返回结构化 API 说明表（name/sig/ret/desc/example）
//   help()                      -> 把 API 清单打印到调试日志
//   hookCPU(addr, function)     -> DobbyInstrument；回调 (regs, addr)，
//                                  用 regsOf(regs) 读、setReg(regs,"x0",v) 写。
//                                  原函数照常执行。
//   hookfunc(addr, function)    -> 同上（instrument，推荐写法）
//   hookfunc(addr, replaceAddr) -> DobbyHook 原生替换（高级）；返回 handle 表：
//                                  h.addr / h.orig / h.mode / h:remove() /
//                                  h:hits() / h:call_original(...)
//   removehook(addr)            -> DobbyDestroy 单个 hook
//   remove_all_hook()           -> 销毁所有已安装的 hook
//   call(function)              -> 稍后在进程主 / 渲染线程运行（无渲染循环
//                                  或 Looper 时回退到独立兜底线程）
//   msleep(ms)
//   readByte/readDword/readQword/readFloat/readDouble/readPtr/readBytes/readString
//   writeByte/writeDword/writeQword/writeFloat/writeDouble/writePtr/writeBytes/writeString
//   regsOf(regs) / setReg(regs, name, value)
//
//   · 注册方式改为 luaL_Reg，报错里显示真实函数名（不再是 '?'）；
//   · hook 参数严格校验（地址必须可执行、替换地址不能为 0、多传参数直接报错）；
//   · hookfunc 支持直接传 Lua function（instrument 模式，不会破坏原函数）；
//   · hook 返回值从裸 number 改为 handle 表（旧用法 ffi.cast 后调用会崩）。

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <sys/mman.h>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include <unistd.h>
#include <pthread.h>   // P1-22：nativeBacktrace 的栈范围校验（pthread_getattr_np）
#include <unwind.h>   // P1-22：nativeBacktrace（_Unwind_Backtrace 兜底）

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#include "dobby.h"
#include "xdl.h"
#include <elf.h>
#include <deque>
#include "arthook/ArtHookApi.h"
#include "arthook/OnLeave.h"

namespace LuaEngine {

namespace {

// 自包含的内存辅助函数（对应 agent/jni/memTool/MemModify_tool.h，
// 但使用内部链接，因此该头文件可安全地被多个
// 编译单元包含）。
// Android arm64 的堆/对象指针带 TBI tag（高 8 位，例如 0xb400007733f4cdb0），
// 而 /proc/self/maps 里的地址**不带 tag**。所有"地址→maps 查询 / 实际访存"
inline uintptr_t UntagAddr(uintptr_t a) {
    return a & 0x00FFFFFFFFFFFFFFULL;
}

inline int GetProtFromMaps(uintptr_t addr) {
    addr = UntagAddr(addr);
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return PROT_READ | PROT_WRITE | PROT_EXEC;
    char line[512];
    int prot = 0;
    while (fgets(line, sizeof(line), maps)) {
        uintptr_t start = 0, end = 0;
        char perms[5] = {0};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (addr >= start && addr < end) {
                if (perms[0] == 'r') prot |= PROT_READ;
                if (perms[1] == 'w') prot |= PROT_WRITE;
                if (perms[2] == 'x') prot |= PROT_EXEC;
                break;
            }
        }
    }
    fclose(maps);
    if (prot == 0) prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    return prot;
}

inline bool LuaWriteMemory(uintptr_t addr, const void* data, size_t size) {
    addr = UntagAddr(addr);
    if (addr == 0 || !data || size == 0) return false;
    long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = addr & ~((uintptr_t)page_size - 1);
    uintptr_t page_end = (addr + size + page_size - 1) & ~((uintptr_t)page_size - 1);

    // 逐页处理：跨页写入时各页原权限可能不同（P2-1）。
    struct SavedPage { uintptr_t page; int prot; };
    std::vector<SavedPage> saved;
    saved.reserve((size_t)((page_end - page_start) / (uintptr_t)page_size) + 1);
    bool ok = true;
    for (uintptr_t p = page_start; p < page_end; p += (uintptr_t)page_size) {
        int orig = GetProtFromMaps(p);
        if (mprotect((void*)p, (size_t)page_size, orig | PROT_WRITE) != 0) {
            ok = false;
            break;
        }
        saved.push_back({p, orig});
    }
    if (ok) {
        memcpy((void*)addr, data, size);
#if defined(__arm__) || defined(__aarch64__)
        __builtin___clear_cache((char*)addr, (char*)addr + size);
#endif
    }
    for (const auto& s : saved) mprotect((void*)s.page, (size_t)page_size, s.prot);
    return ok;
}

inline uintptr_t LuaReadPtr(uintptr_t addr) {
    uintptr_t v = 0;
    addr = UntagAddr(addr);
    memcpy(&v, (const void*)addr, sizeof(v));
    return v;
}

} // 匿名命名空间

inline lua_State* L = nullptr;

// LuaJIT 不是线程安全的；对 L 的每次访问都经过此互斥锁。
// 递归锁：Lua 脚本可能调用被 hook 的函数，从而在 lua_pcall
// 进行中时从 Dobby 回调重新进入引擎。
// 用 recursive_timed_mutex：RunScript 需要 try_lock_for(500ms) 区分"引擎忙"与"执行错误"（P1-4）。lock_guard/recursive 语义不变。
inline std::recursive_timed_mutex g_luaMutex;

inline std::mutex g_logMutex;
inline std::vector<std::string> g_logMessages;
// 日志上限：只保留最近 3000 条，避免长挂内存上涨；绝对序号不倒退。
constexpr size_t kMaxLogMessages = 3000;
inline size_t g_logBase = 0;   // 已丢弃的最旧条数（绝对序号偏移）

inline std::map<uintptr_t, int> g_luaCallbacks;  // hookCPU：addr -> registry 引用
inline std::set<uintptr_t> g_hookAddrs;          // hookfunc：已安装的地址集合
inline std::map<uintptr_t, int> g_hookCounts;    // 每个 hook 的命中/回调次数
inline std::map<uintptr_t, uintptr_t> g_hookTrampolines;  // replace 模式的 trampoline

// replace 模式的计数跳板：addr -> {可执行跳板页, 计数器页, 计数地址}
// replace 分支不再直接 DobbyHook(替换地址)，而是先跳到跳板（自增计数）再 br 到替换地址。
struct ReplaceThunkInfo {
    void* code_page = nullptr;
    void* counter_page = nullptr;
    uintptr_t counter_addr = 0;
};
inline std::map<uintptr_t, ReplaceThunkInfo> g_replaceThunks;
// 64 位返回值的提示每脚本只打一次（旧实现每次 readPtr 都打，轮询会把日志刷爆）
inline bool g_u64Warned = false;
// 前向声明（定义在后面，但 removehook / __index 需要先引用）
inline void FreeReplaceThunk(uintptr_t addr);
inline int Lua_JavaFields(lua_State* Ls);

// Dobby/artHook 回调深度：>0 时禁止 ffi.*（LuaJIT 在回调上下文里 ffi 会静默失败/闪退）
inline void SetCallbackDepth(int depth) {
    if (!L) return;
    lua_pushinteger(L, (lua_Integer)depth);
    lua_setglobal(L, "__atrace_cb_depth");
}
inline void PushCallbackDepthEnter() { SetCallbackDepth(1); }
inline void PushCallbackDepthLeave() { SetCallbackDepth(0); }

// LuaJIT 的 VM 是手写汇编，既没有 .eh_frame 也不维护 x29 帧指针，所以从 Lua
// 函数里直接 _Unwind_Backtrace / 走 FP 链都会断在 LuaJIT 边界（只出 1~2 帧）。
// 解决：在**进入 Lua 之前**的 C++ 桥接层（Dobby/artHook/OnLeave/脚本执行）
// 记录当时的 x29；nativeBacktrace 从那个帧往外走，就能跳过 LuaJIT、拿到
// 「目标函数的原生调用链」。thread_local：同一线程的嵌套回调各自压栈。
inline thread_local uintptr_t g_nativeBtBase = 0;
struct NativeBtScope {
    uintptr_t prev;
    NativeBtScope() : prev(g_nativeBtBase) {
        g_nativeBtBase = (uintptr_t)__builtin_frame_address(0);
    }
    ~NativeBtScope() { g_nativeBtBase = prev; }
};

// P1-22：回调里捕获的**目标侧**原生上下文（目标函数的返回地址 + 调用者帧指针）。
// OnLeave 跳板把进入时的 x29/x30 存在自己的栈帧偏移 224/232（regs8 指针即帧基址）；
// hookCPU 的 RegisterContext 直接有 fp/lr。nativeBacktrace 在回调里优先用它们，
// 这样拿到的是「目标函数被谁调用」的真实原生链，而不是 agent/LuaJIT 自己的帧。
inline thread_local uintptr_t g_cb_target_fp = 0;
inline thread_local uintptr_t g_cb_target_lr = 0;

// ---------- 回调安全：目标线程剩余栈检查 ----------
// hookAfter / hookfunc(instrument) / artHook 的回调都在**目标线程**上同步执行 Lua。
// 如果该线程本来就接近栈底（Java 深调用链很常见），Lua/JIT 再压栈会直接把目标打爆
//  "likely due to stack overflow"）。这里在进回调前检查剩余栈，
// 不足就跳过回调并记日志 —— 宁可不回调，也不能崩目标进程。
inline bool CurrentStackRange(uintptr_t* lo, uintptr_t* hi) {
#if defined(__ANDROID__)
    pthread_attr_t attr;
    if (pthread_getattr_np(pthread_self(), &attr) != 0) return false;
    void* base = nullptr;
    size_t size = 0;
    int rc = pthread_attr_getstack(&attr, &base, &size);
    pthread_attr_destroy(&attr);
    if (rc != 0 || !base || size == 0) return false;
    *lo = (uintptr_t)base;
    *hi = (uintptr_t)base + size;
    return true;
#else
    (void)lo; (void)hi;
    return false;
#endif
}

// need：给回调（LuaJIT + 我们的 C 函数）预留的栈空间，默认 64KB。
inline bool CallbackStackOk(size_t need = 64 * 1024) {
    uintptr_t lo = 0, hi = 0;
    if (!CurrentStackRange(&lo, &hi)) return true;   // 拿不到栈范围时放行（保持旧行为）
    uintptr_t sp = (uintptr_t)__builtin_frame_address(0);
    return sp > lo + need;
}

inline std::map<std::string, uintptr_t> g_baseCache;

// 本次 agent 实例 id：仅可观测（区分不同 agent 实例），不改变 socket 设计。
inline uint64_t g_instanceId = 0;

// 引擎启动时间（self_info / status 用）
inline const std::chrono::steady_clock::time_point g_startTime =
    std::chrono::steady_clock::now();

inline uint64_t UptimeMs() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now() - g_startTime).count();
}

// 查地址所在映射的权限（"x" = 可执行）。用于**校验 hook 参数**：
// 目标函数入口，等于把函数体改成跳到 0，一旦调用就段错误。
inline bool AddrInExecMapping(uintptr_t addr) {
    addr = UntagAddr(addr);
    if (addr == 0) return false;
    FILE* maps = fopen("/proc/self/maps", "re");
    if (!maps) return true;  // 拿不到 maps 时不阻塞用户（宽松放行）
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
// 小工具：luaL_error 的格式化**不支持 %llx**（只支持 %d/%s/%p 等），
// 所以地址要先自己 snprintf 成字符串再拼进去。
inline std::string HexStr(uintptr_t v) {
    char b[32];
    snprintf(b, sizeof(b), "0x%llx", (unsigned long long)v);
    return b;
}

// 地址是否落在任意映射里（用于判断指针是否明显非法）。
inline bool AddrIsMapped(uintptr_t addr) {
    if (addr == 0) return false;
    FILE* maps = fopen("/proc/self/maps", "re");
    if (!maps) return true;
    char line[512];
    bool ok = false;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long long start = 0, end = 0;
        if (sscanf(line, "%llx-%llx", &start, &end) != 2) continue;
        if (addr >= start && addr < end) { ok = true; break; }
    }
    fclose(maps);
    return ok;
}

// 主线程（渲染循环）任务队列，由 eglSwapBuffers hook 泵出。
// P1-5：每个任务带 id，执行结果（ok/err）可查询（call_done(id) / call_stats()）。
struct MainCallTask {
    int id = 0;
    int ref = LUA_NOREF;
};
inline std::mutex g_mainCallMutex;
inline std::deque<MainCallTask> g_mainCallRefs;

struct CallResult {
    bool done = false;
    bool ok = false;
    std::string err;
};
inline std::mutex g_callResultMutex;
inline std::map<int, CallResult> g_callResults;
inline std::atomic<int> g_callNextId{1};
inline std::atomic<int> g_callPending{0};
inline std::atomic<int> g_callDoneCount{0};
inline std::string g_callLastErr;   // 受 g_callResultMutex 保护

inline void RecordCallResult(int id, bool ok, const std::string& err) {
    std::lock_guard<std::mutex> lk(g_callResultMutex);
    CallResult& r = g_callResults[id];
    r.done = true;
    r.ok = ok;
    r.err = err;
    if (!ok) g_callLastErr = err;
    // 只保留最近 256 条结果，防止无限增长
    while (g_callResults.size() > 256) g_callResults.erase(g_callResults.begin());
    g_callDoneCount.fetch_add(1);
}

// 首选泵（eglSwapBuffers / ALooper_pollOnce）最近一次动作时间，
// 兜底线程据此判断首选泵是否还活着。
inline std::atomic<uint64_t> g_lastPreferredPumpMs{0};

inline uint64_t NowMs() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

inline void PushLog(const std::string& msg);
inline void ProcessMainThreadTasks();

// ProcessMainThreadTasks 的可选泵：hook eglSwapBuffers（游戏每帧
// 调用一次），在那里运行排队的 "call" 任务。
typedef int (*EglSwapBuffers_t)(void*, void*);
inline EglSwapBuffers_t g_origSwapBuffers = nullptr;
inline void* g_mainPumpHooked = nullptr;  // 当前已安装的主线程泵 hook 地址

inline int SwapBuffersHook(void* dpy, void* surface) {
    int ret = g_origSwapBuffers ? g_origSwapBuffers(dpy, surface) : 0;
    ProcessMainThreadTasks();
    g_lastPreferredPumpMs.store(NowMs());
    return ret;
}

// 备用泵 1：ALooper_pollOnce（libandroid.so）。目标进程没有 GLES 渲染
// 循环，但主线程在 Looper 上轮询消息时会调用它。
typedef int (*ALooper_pollOnce_t)(int timeoutMillis, int* outFd, int* outEvents, void** outData);
inline ALooper_pollOnce_t g_origPollOnce = nullptr;

inline int PollOnceHook(int timeoutMillis, int* outFd, int* outEvents, void** outData) {
    // 先刷新排队的 call 任务，再进入本轮阻塞轮询，
    // 避免 Looper 长时间空闲时任务迟迟不执行。
    ProcessMainThreadTasks();
    g_lastPreferredPumpMs.store(NowMs());
    return g_origPollOnce(timeoutMillis, outFd, outEvents, outData);
}

// 兜底泵：独立线程定期刷新任务队列。无论首选泵（eglSwapBuffers /
// ALooper_pollOnce）是否安装都会启动，保证 call 任务一定能被执行；
// 仅当首选泵超过 300ms 没有动作且队列非空时才接管，避免抢走
// 本应在主线程执行的任务。注意：兜底线程执行的任务不在目标主线程。
inline std::thread g_fallbackPumpThread;
inline std::atomic<bool> g_fallbackPumpRunning{false};
// P0-3：旧实现 detach() 后 join 永远失效，Reset() 里 lua_close 时泵线程可能仍在
// lua_pcall → UAF。改用 stop flag + condition_variable，Stop 时真正 join。
inline std::mutex g_fallbackPumpMutex;
inline std::condition_variable g_fallbackPumpCv;

inline bool HasPendingTasks() {
    std::lock_guard<std::mutex> lk(g_mainCallMutex);
    return !g_mainCallRefs.empty();
}

inline void FallbackPumpLoop() {
    while (true) {
        {
            std::unique_lock<std::mutex> lk(g_fallbackPumpMutex);
            g_fallbackPumpCv.wait_for(lk, std::chrono::milliseconds(20),
                                      [] { return !g_fallbackPumpRunning.load(); });
        }
        if (!g_fallbackPumpRunning.load()) break;
        ProcessMainThreadTasks();
    }
}

inline void StopFallbackPump() {
    g_fallbackPumpRunning.store(false);
    {
        std::lock_guard<std::mutex> lk(g_fallbackPumpMutex);
    }
    g_fallbackPumpCv.notify_all();
    if (g_fallbackPumpThread.joinable()) g_fallbackPumpThread.join();
}

inline void InstallMainThreadHook() {
    g_lastPreferredPumpMs.store(NowMs());

    // 1. 优先：eglSwapBuffers（游戏渲染循环，每帧调用一次）
    void* sym = DobbySymbolResolver("libEGL.so", "eglSwapBuffers");
    if (sym) {
        void* orig = nullptr;
        if (DobbyHook(sym, (void*)SwapBuffersHook, &orig) == 0 && orig) {
            g_origSwapBuffers = (EglSwapBuffers_t)orig;
            g_mainPumpHooked = sym;
        }
    }
    // 2. 其次：ALooper_pollOnce（主线程 Looper 消息循环）
    if (!g_mainPumpHooked) {
        sym = DobbySymbolResolver("libandroid.so", "ALooper_pollOnce");
        if (sym) {
            void* orig = nullptr;
            if (DobbyHook(sym, (void*)PollOnceHook, &orig) == 0 && orig) {
                g_origPollOnce = (ALooper_pollOnce_t)orig;
                g_mainPumpHooked = sym;
            }
        }
    }
    // 3. 兜底线程：始终启动，保证 call 任务不会被卡死
    g_fallbackPumpRunning.store(true);
    // P0-3：不 detach，保留 joinable 以便 Reset()/detach 时真正回收
    if (g_fallbackPumpThread.joinable()) g_fallbackPumpThread.join();
    g_fallbackPumpThread = std::thread(FallbackPumpLoop);

    if (g_mainPumpHooked)
        PushLog("[Lua] 主线程泵已安装，兜底线程就绪");
    else
        PushLog("[Lua] 主线程泵: 兜底线程（非目标主线程）");
}

// ---------- 日志 ----------
inline void PushLog(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_logMessages.push_back(msg);
    if (g_logMessages.size() > kMaxLogMessages) {
        size_t drop = g_logMessages.size() - kMaxLogMessages;
        g_logMessages.erase(g_logMessages.begin(), g_logMessages.begin() + (long)drop);
        g_logBase += drop;
    }
}

inline std::vector<std::string> TakeLogsSince(size_t from) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (from < g_logBase) from = g_logBase;   // 过期水位：从最旧可用开始
    size_t rel = from - g_logBase;
    if (rel >= g_logMessages.size()) return {};
    return std::vector<std::string>(g_logMessages.begin() + (long)rel, g_logMessages.end());
}

// 当前日志绝对序号（GUI 轮询日志水位用）
inline size_t LogCount() {
    std::lock_guard<std::mutex> lock(g_logMutex);
    return g_logBase + g_logMessages.size();
}

// ---------- Dobby instrument 回调 ----------
inline void DobbyHandler(RegisterContext* ctx, const HookEntryInfo* info) {
    if (!L) return;
    std::lock_guard<std::recursive_timed_mutex> lock(g_luaMutex);
    // P1-22：目标线程剩余栈不足时直接跳过回调。必须放在**任何 ctx 构造/日志**之前：
    // 旧位置在 ctx 之后，而 ctx 里的 PushU64Safe 首次打日志会调用 snprintf（需 ~0x150 栈），
    // 在深栈 Java 线程上直接把目标打爆（实测 tombstone: SIGSEGV in __vfprintf）。
    if (!CallbackStackOk()) {
        PushLog("[回调跳过] 目标线程剩余栈不足 64KB（避免栈溢出崩溃）：hookCPU 回调未执行");
        return;
    }
    // P1-22：捕获目标侧 fp/lr（hookCPU 的 RegisterContext 有现成字段）
    g_cb_target_fp = (uintptr_t)ctx->fp;
    g_cb_target_lr = (uintptr_t)ctx->lr;
    uintptr_t func_addr = (uintptr_t)info->function_address;
    auto it = g_luaCallbacks.find(func_addr);
    if (it == g_luaCallbacks.end()) return;
    g_hookCounts[func_addr]++;
    lua_rawgeti(L, LUA_REGISTRYINDEX, it->second);
    lua_pushlightuserdata(L, ctx);
    lua_pushinteger(L, (lua_Integer)func_addr);
    PushCallbackDepthEnter();
    NativeBtScope btScope;   // P1-22：记录桥接层帧指针（nativeBacktrace 从这往外走）
    int rc = lua_pcall(L, 2, 0, 0);
    PushCallbackDepthLeave();
    if (rc != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        PushLog(std::string("[Hook错误] ") + (err ? err : "未知错误"));
        lua_pop(L, 1);
    }
}

// ---------- Lua：print ----------
// 现在：
//   · 有 __tostring 元方法的（例如 api()）调用它，打印可读摘要；
//   · 普通 table 打印 "table: 0x..."；
//   · 其它类型打印类型名。
inline int Lua_Print(lua_State* Ls) {
    int n = lua_gettop(Ls);
    std::string out = "[Lua] ";
    for (int i = 1; i <= n; i++) {
        size_t len = 0;
        const char* s = lua_tolstring(Ls, i, &len);
        if (s) {
            out.append(s, len);
        } else if (lua_istable(Ls, i) || lua_isuserdata(Ls, i)) {
            bool done = false;
            if (luaL_getmetafield(Ls, i, "__tostring")) {   // 压入元方法
                lua_pushvalue(Ls, i);
                if (lua_pcall(Ls, 1, 1, 0) == LUA_OK) {
                    const char* ts = lua_tostring(Ls, -1);
                    if (ts) {
                        out.append(ts);
                        done = true;
                    }
                }
                lua_pop(Ls, 1);   // 弹出结果/错误
            }
            if (!done) {
                char b[64];
                snprintf(b, sizeof(b), "%s: %p",
                         lua_istable(Ls, i) ? "table" : "userdata",
                         lua_topointer(Ls, i));
                out.append(b);
            }
        } else if (lua_isboolean(Ls, i)) {
            out.append(lua_toboolean(Ls, i) ? "true" : "false");
        } else if (lua_isnil(Ls, i)) {
            out.append("nil");
        } else {
            // 其它（function/thread 等）
            char b[64];
            snprintf(b, sizeof(b), "%s: %p", lua_typename(Ls, lua_type(Ls, i)),
                     lua_topointer(Ls, i));
            out.append(b);
        }
        out += " ";
    }
    PushLog(out);
    return 0;
}

// ---------- Lua：getBase（通过 xdl_iterate_phdr）----------
struct BaseQuery {
    std::string name;
    uintptr_t   addr = 0;
};

static int BaseIterCb(struct dl_phdr_info* info, size_t /*size*/, void* data) {
    BaseQuery* q = static_cast<BaseQuery*>(data);
    if (!info->dlpi_name || info->dlpi_name[0] == '\0') return 0;
    if (info->dlpi_phnum <= 0) return 0;
    std::string full = info->dlpi_name;
    std::string base = full;
    size_t slash = full.find_last_of('/');
    if (slash != std::string::npos) base = full.substr(slash + 1);
    if (base == q->name || full == q->name) {
        q->addr = (uintptr_t)info->dlpi_addr;
        return 1;  // 停止遍历
    }
    return 0;
}

inline int Lua_GetBase(lua_State* Ls) {
    const char* name = luaL_checkstring(Ls, 1);
    uintptr_t addr = 0;

    auto it = g_baseCache.find(name);
    if (it != g_baseCache.end()) {
        lua_pushinteger(Ls, (lua_Integer)it->second);
        return 1;
    }

    // 用 xdl 枚举已加载库（与模块
    // 列表相同的机制），使基址与 UI 显示一致。
    // 不解析 /proc/self/maps。
    BaseQuery q{name, 0};
    xdl_iterate_phdr(BaseIterCb, &q, XDL_FULL_PATHNAME);
    addr = q.addr;

    // P2-3：只有查到才缓存（模块尚未加载时查到 0，缓存后永远返回 0）。
    // 仍返回 number（模块基址 < 2^53，不会丢精度）；需要字符串用 hexOf()。
    if (addr != 0) g_baseCache[name] = addr;
    lua_pushinteger(Ls, (lua_Integer)addr);
    return 1;
}

// clearbase([name])：清空模块基址缓存（目标重新加载/卸载模块后调用）。
inline int Lua_ClearBase(lua_State* Ls) {
    if (lua_gettop(Ls) >= 1 && lua_isstring(Ls, 1)) {
        g_baseCache.erase(lua_tostring(Ls, 1));
    } else {
        g_baseCache.clear();
    }
    lua_pushboolean(Ls, true);
    return 1;
}

// ---------- Lua：hookCPU（DobbyInstrument，入口回调，原函数照常执行）----------
inline int Lua_Hook(lua_State* Ls) {
    // 显式检查参数个数：Lua 的 luaL_check* 对"多传参数"是静默忽略的，
    // 这里改成报错，避免用户以为某个参数生效了。
    int nargs = lua_gettop(Ls);
    if (nargs != 2) {
        return luaL_error(Ls,
            "hookCPU(addr, function) 需要 2 个参数，实际给了 %d 个", nargs);
    }
    if (!lua_isnumber(Ls, 1)) {
        return luaL_error(Ls, "hookCPU 第 1 个参数 addr 必须是数字（函数地址）");
    }
    uintptr_t addr = UntagAddr((uintptr_t)luaL_checkinteger(Ls, 1));
    if (addr == 0) {
        return luaL_error(Ls, "hookCPU: addr 不能为 0");
    }
    if (!AddrInExecMapping(addr)) {
        return luaL_error(Ls,
            "hookCPU: %s 不在可执行映射里（是不是漏了 getBase？）",
            HexStr(addr).c_str());
    }
    // P0-2：同地址重复安装显式拒绝（旧实现会覆盖 registry ref 造成泄漏，
    // DobbyInstrument 二次返回 -1 且报错信息不足）。
    if (g_luaCallbacks.count(addr) || g_hookAddrs.count(addr)) {
        const char* mode = g_luaCallbacks.count(addr) ? "instrument" : "replace";
        return luaL_error(Ls,
            "hookCPU: %s 已被 hook（mode=%s）。先 h:remove() 或 removehook(addr) 再装",
            HexStr(addr).c_str(), mode);
    }
    luaL_checktype(Ls, 2, LUA_TFUNCTION);
    int ref = luaL_ref(Ls, LUA_REGISTRYINDEX);
    g_luaCallbacks[addr] = ref;
    int ret = DobbyInstrument((void*)addr, DobbyHandler);
    if (ret != 0) {
        luaL_unref(Ls, LUA_REGISTRYINDEX, ref);
        g_luaCallbacks.erase(addr);
        return luaL_error(Ls,
            "hookCPU: DobbyInstrument 失败(返回值 %d)，目标地址 %s",
            ret, HexStr(addr).c_str());
    }
    g_hookCounts[addr] = 0;
    return 0;
}

// ---------- hook 句柄（table，带方法） ----------
// 被 ffi.cast 后调用直接崩进程。改为返回 table：
//   h.addr            目标地址
//   h.orig            原始函数跳板地址（replace 模式才有，可能为 0）
//   h.mode            "instrument" / "replace"
//   h:remove()        卸载
//   h:hits()          回调次数
//   h:call_original(...)  调用原始函数（replace 模式；仅支持 ≤8 个整数参数）

inline int Lua_HookRemove(lua_State* Ls) {
    // 方法调用 h:remove() 时 arg1 是 table 自身，真正的地址在 upvalue 里。
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, lua_upvalueindex(1));
    int ret = DobbyDestroy((void*)addr);
    if (ret == 0) g_hookAddrs.erase(addr);
    g_hookTrampolines.erase(addr);
    FreeReplaceThunk(addr);
    auto it = g_luaCallbacks.find(addr);
    if (it != g_luaCallbacks.end()) {
        luaL_unref(Ls, LUA_REGISTRYINDEX, it->second);
        g_luaCallbacks.erase(it);
    }
    g_hookCounts.erase(addr);
    lua_pushboolean(Ls, ret == 0);
    return 1;
}

inline int Lua_HookHits(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, lua_upvalueindex(1));
    // instrument：g_hookCounts；replace：计数跳板里的计数器
    auto it = g_hookCounts.find(addr);
    if (it != g_hookCounts.end()) {
        lua_pushinteger(Ls, (lua_Integer)it->second);
        return 1;
    }
    auto th = g_replaceThunks.find(addr);
    if (th != g_replaceThunks.end() && th->second.counter_addr) {
        lua_pushinteger(Ls, (lua_Integer)*(volatile uint32_t*)th->second.counter_addr);
        return 1;
    }
    lua_pushinteger(Ls, 0);
    return 1;
}

inline int Lua_HookCallOriginal(lua_State* Ls) {
    uintptr_t fn = (uintptr_t)luaL_checkinteger(Ls, lua_upvalueindex(1));
    if (fn == 0) {
        return luaL_error(Ls,
            "call_original: 没有可用的原始函数跳板。"
            "hookfunc(addr, function) 是 instrument 模式，原函数会自动执行，不需要它；"
            "只有 hookfunc(addr, 替换地址) 才有跳板。");
    }
    // h:call_original(a, b) 的栈布局是 [self, a, b]；跳过 self 那个 table。
    int base = 0;
    if (lua_istable(Ls, 1)) base = 1;
    int n = lua_gettop(Ls) - base;
    if (n > 8) {
        return luaL_error(Ls, "call_original: 最多支持 8 个整数参数，实际 %d 个", n);
    }
    uint64_t a[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    for (int i = 0; i < n; i++) {
        if (lua_isnoneornil(Ls, base + i + 1)) {
            a[i] = 0;   // P2-15：call_original(nil,nil) 以前报"必须是整数"，按 0 处理
            continue;
        }
        if (!lua_isnumber(Ls, base + i + 1)) {
            return luaL_error(Ls,
                "call_original: 第 %d 个参数必须是整数（浮点参数暂不支持）", i + 1);
        }
        a[i] = (uint64_t)luaL_checkinteger(Ls, base + i + 1);
    }
    typedef uint64_t (*Fn8)(uint64_t, uint64_t, uint64_t, uint64_t,
                            uint64_t, uint64_t, uint64_t, uint64_t);
    uint64_t r = ((Fn8)fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
    lua_pushinteger(Ls, (lua_Integer)r);
    return 1;
}

// 把 hook 信息包装成 table 压栈。
inline void PushHookHandle(lua_State* Ls, uintptr_t addr, uintptr_t orig,
                           const char* mode) {
    lua_newtable(Ls);

    lua_pushstring(Ls, "addr");
    lua_pushinteger(Ls, (lua_Integer)addr);
    lua_settable(Ls, -3);

    lua_pushstring(Ls, "orig");
    lua_pushinteger(Ls, (lua_Integer)orig);
    lua_settable(Ls, -3);

    // 语义别名：h.orig 实际是 Dobby trampoline（不是"原函数入口"），
    // 同时提供 trampoline 字段避免误解。
    lua_pushstring(Ls, "trampoline");
    lua_pushinteger(Ls, (lua_Integer)orig);
    lua_settable(Ls, -3);

    lua_pushstring(Ls, "mode");
    lua_pushstring(Ls, mode);
    lua_settable(Ls, -3);

    // h:remove()
    lua_pushstring(Ls, "remove");
    lua_pushinteger(Ls, (lua_Integer)addr);
    lua_pushcclosure(Ls, Lua_HookRemove, 1);
    lua_settable(Ls, -3);

    // h:hits()
    lua_pushstring(Ls, "hits");
    lua_pushinteger(Ls, (lua_Integer)addr);
    lua_pushcclosure(Ls, Lua_HookHits, 1);
    lua_settable(Ls, -3);

    // h:call_original(...)
    lua_pushstring(Ls, "call_original");
    lua_pushinteger(Ls, (lua_Integer)orig);
    lua_pushcclosure(Ls, Lua_HookCallOriginal, 1);
    lua_settable(Ls, -3);
}

// ---------- Lua：hookfunc ----------
// 两种模式：
//   1) hookfunc(addr, function)     -> DobbyInstrument（**推荐**）：函数入口执行你的
//      Lua，然后原函数照常执行；回调签名 function(regs, addr)。
//      不会破坏原逻辑，不需要手写 shellcode/跳板。
//   2) hookfunc(addr, 替换地址:number) -> DobbyHook（高级）：把目标函数整体替换成
//      给的 native 地址；返回句柄可 :call_original(...) 调原函数。
// 两种都返回 table 句柄（见 PushHookHandle），而不是裸 number。
// 生成 replace 计数跳板（arm64 机器码，~40B）：
//   ldr x9,[pc,#24] ; ldr w10,[x9] ; add w10,w10,#1 ; str w10,[x9]
//   ldr x10,[pc,#16] ; br x10 ; (pad 8B) ; .quad counter ; .quad replace_fn
// 这样 replace 模式也能统计命中数（Dobby 直接替换时无法插桩）。
inline void* MakeReplaceThunk(uintptr_t counter_addr, uintptr_t replace_fn) {
    long ps = sysconf(_SC_PAGESIZE);
    uint8_t* page = (uint8_t*)mmap(nullptr, (size_t)ps, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return nullptr;
    uint32_t* c = (uint32_t*)page;
    c[0] = 0x58000000u | (6u << 5) | 9u;                    // ldr x9, [pc, #24]
    c[1] = 0xB9400000u | (9u << 5) | 10u;                   // ldr w10, [x9]
    c[2] = 0x11000000u | (1u << 10) | (10u << 5) | 10u;     // add w10, w10, #1
    c[3] = 0xB9000000u | (9u << 5) | 10u;                   // str w10, [x9]
    c[4] = 0x58000000u | (4u << 5) | 10u;                   // ldr x10, [pc, #16]
    c[5] = 0xD61F0000u | (10u << 5);                        // br x10
    *(uint64_t*)(page + 24) = (uint64_t)counter_addr;
    *(uint64_t*)(page + 32) = (uint64_t)replace_fn;
    __builtin___clear_cache((char*)page, (char*)page + 40);
    if (mprotect(page, (size_t)ps, PROT_READ | PROT_EXEC) != 0) {
        munmap(page, (size_t)ps);
        return nullptr;
    }
    return page;
}

inline void FreeReplaceThunk(uintptr_t addr) {
    auto it = g_replaceThunks.find(addr);
    if (it == g_replaceThunks.end()) return;
    long ps = sysconf(_SC_PAGESIZE);
    if (it->second.code_page) munmap(it->second.code_page, (size_t)ps);
    if (it->second.counter_page) munmap(it->second.counter_page, (size_t)ps);
    g_replaceThunks.erase(it);
}

inline int Lua_HookReplace(lua_State* Ls) {
    int nargs = lua_gettop(Ls);
    if (nargs != 2) {
        return luaL_error(Ls,
            "hookfunc(addr, function|替换地址) 需要 2 个参数，实际给了 %d 个", nargs);
    }
    if (!lua_isnumber(Ls, 1)) {
        return luaL_error(Ls, "hookfunc 第 1 个参数 addr 必须是数字（目标函数地址）");
    }
    uintptr_t target = UntagAddr((uintptr_t)luaL_checkinteger(Ls, 1));
    if (target == 0) {
        return luaL_error(Ls, "hookfunc: 目标地址 addr 不能为 0");
    }
    if (!AddrInExecMapping(target)) {
        return luaL_error(Ls,
            "hookfunc: 目标 %s 不在可执行映射里（是不是漏了 getBase？）",
            HexStr(target).c_str());
    }

    // P0-2：同地址重复安装显式拒绝
    if (g_luaCallbacks.count(target) || g_hookAddrs.count(target)) {
        const char* mode = g_luaCallbacks.count(target) ? "instrument" : "replace";
        auto it = g_hookCounts.find(target);
        int hits = (it == g_hookCounts.end()) ? 0 : it->second;
        return luaL_error(Ls,
            "hookfunc: %s 已被 hook（mode=%s, hits=%d）。先 h:remove()/removehook(addr) 再装",
            HexStr(target).c_str(), mode, hits);
    }

    // 模式 1：第二参数是 Lua function -> instrument（入口回调，原函数继续）
    if (lua_isfunction(Ls, 2)) {
        int ref = luaL_ref(Ls, LUA_REGISTRYINDEX);
        g_luaCallbacks[target] = ref;
        int ret = DobbyInstrument((void*)target, DobbyHandler);
        if (ret != 0) {
            luaL_unref(Ls, LUA_REGISTRYINDEX, ref);
            g_luaCallbacks.erase(target);
            return luaL_error(Ls,
                "hookfunc: 安装 instrument 失败(返回值 %d)，地址 %s",
                ret, HexStr(target).c_str());
        }
        g_hookCounts[target] = 0;
        PushHookHandle(Ls, target, 0, "instrument");
        return 1;
    }

    // 模式 2：第二参数是 number -> 原生替换（高级用法）
    if (lua_isnumber(Ls, 2)) {
        uintptr_t replace = UntagAddr((uintptr_t)luaL_checkinteger(Ls, 2));
        if (replace == 0) {
            return luaL_error(Ls,
                "hookfunc: 替换地址不能是 0（这会把函数入口改成跳到 0，目标一旦调用就崩）。"
                "如果在入口插逻辑，请传 Lua function："
                "hookfunc(addr, function(regs, addr) ... end)");
        }
        if (!AddrInExecMapping(replace)) {
            return luaL_error(Ls,
                "hookfunc: 替换地址 %s 不在可执行映射里（是否忘了 ffi.cast？）",
                HexStr(replace).c_str());
        }
        // replace 模式也带命中计数：用计数跳板包一层
        long ps = sysconf(_SC_PAGESIZE);
        void* counter_page = mmap(nullptr, (size_t)ps, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (counter_page == MAP_FAILED) {
            return luaL_error(Ls, "hookfunc: 分配计数器失败");
        }
        memset(counter_page, 0, (size_t)ps);
        uintptr_t counter_addr = (uintptr_t)counter_page;
        void* thunk = MakeReplaceThunk(counter_addr, replace);
        if (!thunk) {
            munmap(counter_page, (size_t)ps);
            return luaL_error(Ls, "hookfunc: 生成 replace 计数跳板失败");
        }
        void* trampoline = nullptr;
        int ret = DobbyHook((void*)target, thunk, &trampoline);
        if (ret != 0) {
            munmap(counter_page, (size_t)ps);
            munmap(thunk, (size_t)ps);
            return luaL_error(Ls,
                "hookfunc: DobbyHook 失败(返回值 %d)，目标 %s",
                ret, HexStr(target).c_str());
        }
        g_hookAddrs.insert(target);
        g_hookTrampolines[target] = (uintptr_t)trampoline;
        g_replaceThunks[target] = ReplaceThunkInfo{thunk, counter_page, counter_addr};
        PushHookHandle(Ls, target, (uintptr_t)trampoline, "replace");
        return 1;
    }

    return luaL_error(Ls,
        "hookfunc 第 2 个参数必须是 Lua function 或可执行地址(number)，实际是 %s",
        luaL_typename(Ls, 2));
}

// ---------- Lua：removehook ----------
inline int Lua_HookUnhook(lua_State* Ls) {
    uintptr_t addr = UntagAddr((uintptr_t)luaL_checkinteger(Ls, 1));
    int ret = DobbyDestroy((void*)addr);
    if (ret == 0) g_hookAddrs.erase(addr);
    g_hookTrampolines.erase(addr);
    auto it = g_luaCallbacks.find(addr);
    if (it != g_luaCallbacks.end()) {
        luaL_unref(Ls, LUA_REGISTRYINDEX, it->second);
        g_luaCallbacks.erase(it);
    }
    lua_pushboolean(Ls, ret == 0);
    return 1;
}

// ---------- Lua：remove_all_hook ----------
inline int Lua_RemoveAllHooks(lua_State* Ls) {
    for (uintptr_t addr : g_hookAddrs) DobbyDestroy((void*)addr);
    for (auto& kv : g_replaceThunks) FreeReplaceThunk(kv.first);
    g_hookAddrs.clear();
    g_hookTrampolines.clear();
    for (auto& pair : g_luaCallbacks) {
        DobbyDestroy((void*)pair.first);
        if (L) luaL_unref(L, LUA_REGISTRYINDEX, pair.second);
    }
    g_luaCallbacks.clear();
    lua_pushboolean(Ls, true);
    return 1;
}

// ---------- Lua：call（排队到主 / 渲染线程）----------
inline void ProcessMainThreadTasks() {
    if (!L) return;
    std::lock_guard<std::recursive_timed_mutex> lock(g_luaMutex);

    // P1-6：每帧最多执行 2ms，剩余任务留在队列里（保持顺序），避免卡帧。
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(2);
    for (;;) {
        MainCallTask task;
        {
            std::lock_guard<std::mutex> lk(g_mainCallMutex);
            if (g_mainCallRefs.empty()) break;
            task = g_mainCallRefs.front();
            g_mainCallRefs.pop_front();
        }
        g_callPending.fetch_sub(1);

        lua_rawgeti(L, LUA_REGISTRYINDEX, task.ref);
        bool ok = true;
        std::string err;
        if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
            const char* e = lua_tostring(L, -1);
            err = e ? e : "未知错误";
            ok = false;
            PushLog(std::string("[主线程调用错误] ") + err);
            lua_pop(L, 1);
        }
        luaL_unref(L, LUA_REGISTRYINDEX, task.ref);
        RecordCallResult(task.id, ok, err);

        if (std::chrono::steady_clock::now() >= deadline) break;
    }
}

inline int Lua_CallOnMain(lua_State* Ls) {
    luaL_checktype(Ls, 1, LUA_TFUNCTION);
    lua_pushvalue(Ls, 1);
    int ref = luaL_ref(Ls, LUA_REGISTRYINDEX);
    int id = g_callNextId.fetch_add(1);
    {
        std::lock_guard<std::mutex> lock(g_mainCallMutex);
        g_mainCallRefs.push_back(MainCallTask{id, ref});
    }
    g_callPending.fetch_add(1);
    lua_pushinteger(Ls, (lua_Integer)id);
    return 1;
}

// call_stats() -> { pending, done, last_err }
inline int Lua_CallStats(lua_State* Ls) {
    lua_newtable(Ls);
    auto seti = [&](const char* k, lua_Integer v) {
        lua_pushstring(Ls, k); lua_pushinteger(Ls, v); lua_settable(Ls, -3);
    };
    seti("pending", (lua_Integer)g_callPending.load());
    seti("done", (lua_Integer)g_callDoneCount.load());
    std::string lastErr;
    {
        std::lock_guard<std::mutex> lk(g_callResultMutex);
        lastErr = g_callLastErr;
    }
    lua_pushstring(Ls, "last_err");
    if (lastErr.empty()) lua_pushnil(Ls); else lua_pushstring(Ls, lastErr.c_str());
    lua_settable(Ls, -3);
    return 1;
}

// call_done(id) -> true | false | nil,"pending"|"unknown id"
inline int Lua_CallDone(lua_State* Ls) {
    int id = (int)luaL_checkinteger(Ls, 1);
    CallResult r;
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(g_callResultMutex);
        auto it = g_callResults.find(id);
        if (it != g_callResults.end()) { r = it->second; found = true; }
    }
    if (!found) {
        // 可能还在队列里
        bool queued = false;
        {
            std::lock_guard<std::mutex> lk(g_mainCallMutex);
            for (const auto& t : g_mainCallRefs) {
                if (t.id == id) { queued = true; break; }
            }
        }
        if (queued) {
            lua_pushnil(Ls); lua_pushstring(Ls, "pending");
        } else {
            lua_pushnil(Ls); lua_pushstring(Ls, "unknown id");
        }
        return 2;
    }
    if (r.ok) {
        lua_pushboolean(Ls, true);
        return 1;
    }
    lua_pushboolean(Ls, false);
    lua_pushstring(Ls, r.err.c_str());
    return 2;
}

// call_sync(fn, ...) -> 立即在当前线程执行并返回结果（不排队）。
// 说明：run_lua 本身持有 Lua 锁，真正的"等待异步任务"会死锁；
// 需要"立刻拿到结果"的场景用 call_sync，需要"延后执行"用 call()。
inline int Lua_CallSync(lua_State* Ls) {
    int base = lua_gettop(Ls);
    if (base < 1 || !lua_isfunction(Ls, 1)) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, "call_sync 第一个参数必须是函数");
        return 2;
    }
    lua_pushvalue(Ls, 1);
    for (int i = 2; i <= base; i++) lua_pushvalue(Ls, i);
    int rc = lua_pcall(Ls, base - 1, LUA_MULTRET, 0);
    if (rc != LUA_OK) {
        const char* e = lua_tostring(Ls, -1);
        std::string err = e ? e : "未知错误";
        lua_pop(Ls, 1);
        lua_pushnil(Ls);
        lua_pushstring(Ls, err.c_str());
        return 2;
    }
    return lua_gettop(Ls) - base;
}

// ---------- Lua：msleep ----------
inline int Lua_Msleep(lua_State* Ls) {
    int ms = (int)luaL_checkinteger(Ls, 1);
    if (ms < 0) ms = 0;
    if (ms > 60000) ms = 60000;
    usleep((useconds_t)ms * 1000);
    return 0;
}

// 外部 AI 反馈：为了拿 .dynsym 手写三遍 ELF 解析、盲扫 .so 越界把 agent 干断。
// 这里用 xdl 拿到 phdr 后直接解析内存里的 ELF（不读文件、不依赖 /proc）。
struct ModSeg {
    uintptr_t start;
    uintptr_t end;
    int       prot;
};

struct ModInfo {
    std::string name;
    std::string path;
    uintptr_t   base = 0;
    uintptr_t   size = 0;
    std::vector<ModSeg> segs;
    const struct dl_phdr_info* info = nullptr;
    bool ok = false;
};

struct ModQuery2 {
    const char* want;
    ModInfo*    out;
};

static int ModInfoCb(struct dl_phdr_info* info, size_t /*size*/, void* data) {
    ModQuery2* q = static_cast<ModQuery2*>(data);
    if (!info->dlpi_name || info->dlpi_name[0] == '\0') return 0;
    if (info->dlpi_phnum <= 0) return 0;
    std::string full = info->dlpi_name;
    std::string base = full;
    size_t slash = full.find_last_of('/');
    if (slash != std::string::npos) base = full.substr(slash + 1);
    if (base != q->want && full != q->want) return 0;

    ModInfo& mi = *q->out;
    mi.name = base;
    mi.path = full;
    mi.base = (uintptr_t)info->dlpi_addr;
    mi.info = info;
    uintptr_t maxEnd = mi.base;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const Elf64_Phdr& ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD) continue;
        uintptr_t s = mi.base + (uintptr_t)ph.p_vaddr;
        uintptr_t e = s + (uintptr_t)ph.p_memsz;
        int prot = 0;
        if (ph.p_flags & PF_R) prot |= PROT_READ;
        if (ph.p_flags & PF_W) prot |= PROT_WRITE;
        if (ph.p_flags & PF_X) prot |= PROT_EXEC;
        mi.segs.push_back(ModSeg{s, e, prot});
        if (e > maxEnd) maxEnd = e;
    }
    mi.size = maxEnd - mi.base;
    mi.ok = true;
    return 1;
}

inline bool GetModInfo(const char* name, ModInfo& out) {
    ModQuery2 q{name, &out};
    xdl_iterate_phdr(ModInfoCb, &q, XDL_FULL_PATHNAME);
    return out.ok;
}

struct DynVals {
    uintptr_t symtab = 0;
    uintptr_t strtab = 0;
    uintptr_t hash = 0;
    uintptr_t gnuhash = 0;
    size_t    strsz = 0;
};

inline bool ReadDynVals(const ModInfo& mi, DynVals& d) {
    const Elf64_Phdr* ph = mi.info->dlpi_phdr;
    for (int i = 0; i < mi.info->dlpi_phnum; i++) {
        if (ph[i].p_type != PT_DYNAMIC) continue;
        const auto* dyn = (const Elf64_Dyn*)(mi.base + (uintptr_t)ph[i].p_vaddr);
        size_t n = (size_t)ph[i].p_memsz / sizeof(Elf64_Dyn);
        for (size_t k = 0; k < n; k++) {
            switch (dyn[k].d_tag) {
                case DT_SYMTAB:   d.symtab = mi.base + (uintptr_t)dyn[k].d_un.d_ptr; break;
                case DT_STRTAB:   d.strtab = mi.base + (uintptr_t)dyn[k].d_un.d_ptr; break;
                case DT_HASH:     d.hash = mi.base + (uintptr_t)dyn[k].d_un.d_ptr; break;
                case DT_GNU_HASH: d.gnuhash = mi.base + (uintptr_t)dyn[k].d_un.d_ptr; break;
                case DT_STRSZ:    d.strsz = (size_t)dyn[k].d_un.d_val; break;
                default: break;
            }
        }
        return d.symtab != 0 && d.strtab != 0;
    }
    return false;
}

inline uint32_t GnuHashSymCount(uintptr_t gh) {
    const uint32_t* h = (const uint32_t*)gh;
    uint32_t nbuckets  = h[0];
    uint32_t symoffset = h[1];
    uint32_t bloomSize = h[2];          // bloom 项是 64 位 → 占 2 个 uint32
    if (nbuckets == 0 || nbuckets > (1u << 24)) return 0;
    const uint32_t* buckets = h + 4 + bloomSize * 2;
    const uint32_t* chain = buckets + nbuckets;
    uint32_t last = symoffset;
    for (uint32_t i = 0; i < nbuckets; i++) {
        uint32_t b = buckets[i];
        if (b < symoffset) continue;
        uint32_t idx = b;
        while (!(chain[idx - symoffset] & 1u)) ++idx;
        if (idx + 1 > last) last = idx + 1;
    }
    return last;
}

inline uint32_t SymCount(const DynVals& d) {
    if (d.hash) {
        const uint32_t* h = (const uint32_t*)d.hash;
        return h[1];   // nchain
    }
    if (d.gnuhash) return GnuHashSymCount(d.gnuhash);
    return 0;
}

inline int Lua_ModuleInfo(lua_State* Ls) {
    const char* name = luaL_checkstring(Ls, 1);
    ModInfo mi;
    if (!GetModInfo(name, mi)) {
        lua_pushnil(Ls);
        lua_pushfstring(Ls, "模块未加载: %s", name);
        return 2;
    }
    lua_newtable(Ls);
    lua_pushstring(Ls, "name");  lua_pushstring(Ls, mi.name.c_str());  lua_settable(Ls, -3);
    lua_pushstring(Ls, "path");  lua_pushstring(Ls, mi.path.c_str());  lua_settable(Ls, -3);
    lua_pushstring(Ls, "base");  lua_pushinteger(Ls, (lua_Integer)mi.base); lua_settable(Ls, -3);
    // size 可能超过 2^53？模块大小不会，安全用 number
    lua_pushstring(Ls, "size");  lua_pushinteger(Ls, (lua_Integer)mi.size); lua_settable(Ls, -3);
    lua_pushstring(Ls, "segments");
    lua_newtable(Ls);
    int idx = 1;
    for (const auto& s : mi.segs) {
        lua_newtable(Ls);
        lua_pushstring(Ls, "start"); lua_pushinteger(Ls, (lua_Integer)s.start); lua_settable(Ls, -3);
        lua_pushstring(Ls, "stop");  lua_pushinteger(Ls, (lua_Integer)s.end);   lua_settable(Ls, -3);
        // "end" 是 Lua 保留字，只能写成 s["end"]；同时提供 stop 别名方便使用。
        lua_pushstring(Ls, "end");   lua_pushinteger(Ls, (lua_Integer)s.end);   lua_settable(Ls, -3);
        lua_pushstring(Ls, "prot");  lua_pushinteger(Ls, (lua_Integer)s.prot);  lua_settable(Ls, -3);
        char perms[4] = {
            (s.prot & PROT_READ) ? 'r' : '-',
            (s.prot & PROT_WRITE) ? 'w' : '-',
            (s.prot & PROT_EXEC) ? 'x' : '-', 0
        };
        lua_pushstring(Ls, "name");  lua_pushstring(Ls, perms); lua_settable(Ls, -3);
        lua_pushstring(Ls, "perms"); lua_pushstring(Ls, perms); lua_settable(Ls, -3);
        lua_pushstring(Ls, "label");
        lua_pushstring(Ls, (s.prot & PROT_EXEC) ? "text"
                              : ((s.prot & PROT_WRITE) ? "data" : "rodata"));
        lua_settable(Ls, -3);
        lua_pushstring(Ls, "exec");
        lua_pushboolean(Ls, (s.prot & PROT_EXEC) != 0);
        lua_settable(Ls, -3);
        lua_rawseti(Ls, -2, idx++);
    }
    lua_settable(Ls, -3);
    return 1;
}

inline int Lua_Symbols(lua_State* Ls) {
    const char* name = luaL_checkstring(Ls, 1);
    const char* pat = luaL_optstring(Ls, 2, "");
    ModInfo mi;
    if (!GetModInfo(name, mi)) {
        lua_pushnil(Ls); lua_pushfstring(Ls, "模块未加载: %s", name); return 2;
    }
    DynVals d;
    if (!ReadDynVals(mi, d)) {
        lua_pushnil(Ls); lua_pushstring(Ls, "该模块没有 .dynamic/.dynsym"); return 2;
    }
    uint32_t total = SymCount(d);
    if (total == 0 || total > 1000000u) {
        lua_pushnil(Ls); lua_pushstring(Ls, "无法确定符号表大小（无 DT_HASH/DT_GNU_HASH）"); return 2;
    }
    const Elf64_Sym* syms = (const Elf64_Sym*)d.symtab;
    const char* strtab = (const char*)d.strtab;
    constexpr int kMaxOut = 4000;

    lua_newtable(Ls);          // arr（符号数组，也作为 result 的数组部分）
    int out = 0;
    int matched = 0;
    for (uint32_t i = 1; i < total; i++) {
        const Elf64_Sym& s = syms[i];
        if (s.st_name == 0) continue;
        if (d.strsz && (size_t)s.st_name >= d.strsz) continue;
        const char* nm = strtab + s.st_name;
        if (!nm || !nm[0]) continue;
        if (pat[0] && !strstr(nm, pat)) continue;
        unsigned type = ELF64_ST_TYPE(s.st_info);
        if (type != STT_FUNC && type != STT_OBJECT && type != STT_NOTYPE) continue;
        matched++;
        if (out >= kMaxOut) continue;
        lua_newtable(Ls);
        lua_pushstring(Ls, "name");   lua_pushstring(Ls, nm); lua_settable(Ls, -3);
        lua_pushstring(Ls, "offset"); lua_pushinteger(Ls, (lua_Integer)s.st_value); lua_settable(Ls, -3);
        lua_pushstring(Ls, "addr");
        lua_pushinteger(Ls, (lua_Integer)(mi.base + (uintptr_t)s.st_value));
        lua_settable(Ls, -3);
        lua_pushstring(Ls, "size");   lua_pushinteger(Ls, (lua_Integer)s.st_size); lua_settable(Ls, -3);
        lua_pushstring(Ls, "type");
        lua_pushstring(Ls, type == STT_FUNC ? "func" : (type == STT_OBJECT ? "object" : "notype"));
        lua_settable(Ls, -3);
        lua_rawseti(Ls, -2, ++out);
    }
    // 返回：数组部分 = 符号表（#r == 实际返回条数），另有 symbols/count/truncated 字段
    int arrIdx = lua_gettop(Ls);
    lua_newtable(Ls);          // result
    for (int i = 1; i <= out; i++) {
        lua_rawgeti(Ls, arrIdx, i);
        lua_rawseti(Ls, -2, i);
    }
    lua_pushstring(Ls, "symbols");
    lua_pushvalue(Ls, arrIdx);
    lua_settable(Ls, -3);
    lua_pushstring(Ls, "count"); lua_pushinteger(Ls, (lua_Integer)matched); lua_settable(Ls, -3);
    lua_pushstring(Ls, "truncated"); lua_pushboolean(Ls, matched > out); lua_settable(Ls, -3);
    return 1;
}

inline bool ParseHexBytes(const char* s, std::vector<uint8_t>& out) {
    out.clear();
    if (!s) return false;
    for (const char* p = s; *p; ) {
        while (*p == ' ' || *p == '\t' || *p == '_' || *p == '-') ++p;
        if (!*p) break;
        if (p[0] == '?' && p[1] == '?') { out.push_back(0); p += 2; continue; }
        auto hexv = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = hexv(p[0]);
        int lo = p[1] ? hexv(p[1]) : -1;
        if (hi < 0 || lo < 0) return false;
        out.push_back((uint8_t)((hi << 4) | lo));
        p += 2;
    }
    return !out.empty();
}

inline int Lua_Scan(lua_State* Ls) {
    const char* name = luaL_checkstring(Ls, 1);
    const char* hexstr = luaL_checkstring(Ls, 2);
    const char* maskstr = luaL_optstring(Ls, 3, nullptr);

    std::vector<uint8_t> pat, maskv;
    if (!ParseHexBytes(hexstr, pat)) {
        lua_pushnil(Ls); lua_pushstring(Ls, "hex 模式解析失败（示例：\"90000008\" 或 \"90 00 ?? 08\"）"); return 2;
    }
    if (maskstr && *maskstr) {
        if (!ParseHexBytes(maskstr, maskv) || maskv.size() != pat.size()) {
            lua_pushnil(Ls); lua_pushstring(Ls, "mask 长度必须与模式一致（FF=匹配，00=通配）"); return 2;
        }
    }
    ModInfo mi;
    if (!GetModInfo(name, mi)) {
        lua_pushnil(Ls); lua_pushfstring(Ls, "模块未加载: %s", name); return 2;
    }

    constexpr size_t kMaxHits = 4096;
    lua_newtable(Ls);          // arr：命中的地址数组（也作为 result 的数组部分）
    size_t hits = 0;
    const uint8_t* patp = pat.data();
    const size_t plen = pat.size();

    for (const auto& seg : mi.segs) {
        if (!(seg.prot & PROT_READ)) continue;
        uintptr_t start = seg.start;
        uintptr_t end = seg.end;
        if (end <= start) continue;
        if (end - start > (uintptr_t)(64u * 1024 * 1024)) continue;  // 防呆
        const uint8_t* p = (const uint8_t*)start;
        size_t n = (size_t)(end - start);
        if (n < plen) continue;
        for (size_t i = 0; i + plen <= n; i++) {
            bool ok = true;
            for (size_t k = 0; k < plen; k++) {
                uint8_t mask = maskv.empty() ? 0xFF : maskv[k];
                if ((p[i + k] & mask) != (patp[k] & mask)) { ok = false; break; }
            }
            if (!ok) continue;
            if (hits < kMaxHits) {
                lua_pushinteger(Ls, (lua_Integer)(start + i));
                lua_rawseti(Ls, -2, (int)hits + 1);
            }
            hits++;
        }
    }
    // 让返回值既支持 #r（数组），也支持 r.addrs / r.count（旧写法）
    int arrIdx = lua_gettop(Ls);
    size_t stored = hits < kMaxHits ? hits : kMaxHits;
    lua_newtable(Ls);          // result
    for (size_t i = 1; i <= stored; i++) {
        lua_rawgeti(Ls, arrIdx, (int)i);
        lua_rawseti(Ls, -2, (int)i);
    }
    lua_pushstring(Ls, "addrs");
    lua_pushvalue(Ls, arrIdx);
    lua_settable(Ls, -3);
    lua_pushstring(Ls, "count"); lua_pushinteger(Ls, (lua_Integer)hits); lua_settable(Ls, -3);
    lua_pushstring(Ls, "truncated"); lua_pushboolean(Ls, hits > kMaxHits); lua_settable(Ls, -3);
    return 1;
}

// 外部 AI 实战反馈：`readDword(未映射地址)` 会把 agent 和目标进程一起崩掉；
// `readPtr` 用 lua_pushinteger 返回超过 2^53 的地址时会被 double 截断
// （0xb400007971cde630 变成 ...e800）。这里统一处理：
//   1) 读写前查 /proc/self/maps（缓存 + 未命中懒刷新），非法地址返回 nil,原因；
//   2) 地址参数接受 number / "0x..." 字符串 / lightuserdata / cdata；
//   3) 超过 2^53 的 64 位值返回十六进制字符串（不静默丢精度），并提供
//      readPtrHex / readQwordHex / hexOf / ptrOf / u64 这套精确工具。

struct MemMapEntry {
    uintptr_t start;
    uintptr_t end;
    int       prot;
};

inline std::vector<MemMapEntry>& MapCacheRef() {
    static std::vector<MemMapEntry> v;
    return v;
}

inline std::mutex& MapCacheMutex() {
    static std::mutex m;
    return m;
}

inline void RefreshMapsLocked() {
    std::vector<MemMapEntry>& v = MapCacheRef();
    v.clear();
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        unsigned long long s = 0, e = 0;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &s, &e, perms) != 3) continue;
        int prot = 0;
        if (perms[0] == 'r') prot |= PROT_READ;
        if (perms[1] == 'w') prot |= PROT_WRITE;
        if (perms[2] == 'x') prot |= PROT_EXEC;
        v.push_back({(uintptr_t)s, (uintptr_t)e, prot});
    }
    fclose(f);
}

// 校验 [addr, addr+len) 是否已映射（needWrite=true 时只要求已映射，
// 因为 LuaWriteMemory 会尝试 mprotect；读操作要求可读）。
// 返回 nullptr 表示通过；否则返回静态原因文本（写入 why）。
inline const char* CheckRange(uintptr_t addr, size_t len, bool needWrite,
                              std::string& why) {
    why.clear();
    addr = UntagAddr(addr);   // maps 里的地址不带 TBI tag
    if (addr == 0) { why = "地址为 0"; return why.c_str(); }
    if (len == 0) return nullptr;
    uintptr_t end = addr + len;
    if (end < addr) { why = "范围溢出"; return why.c_str(); }

    std::lock_guard<std::mutex> lk(MapCacheMutex());
    bool refreshed = false;
    for (int attempt = 0; attempt < 2; ++attempt) {
        uintptr_t cur = addr;
        std::string bad;
        bool missing = false;
        while (cur < end) {
            const MemMapEntry* hit = nullptr;
            for (const auto& m : MapCacheRef()) {
                if (cur >= m.start && cur < m.end) { hit = &m; break; }
            }
            if (!hit) {
                if (!refreshed) { missing = true; break; }  // 先刷新再重试
                char buf[96];
                snprintf(buf, sizeof(buf), "未映射地址 0x%llx",
                         (unsigned long long)cur);
                why = buf;
                return why.c_str();
            }
            if (!needWrite && !(hit->prot & PROT_READ)) {
                char buf[112];
                snprintf(buf, sizeof(buf), "地址 0x%llx 不可读（prot=%d）",
                         (unsigned long long)cur, hit->prot);
                why = buf;
                return why.c_str();
            }
            cur = hit->end;
        }
        if (!missing) return nullptr;
        RefreshMapsLocked();   // 可能是新 mmap（例如 alloc 之后），刷新一次
        refreshed = true;
    }
    why = "未映射";
    return why.c_str();
}

// 地址参数解析：number / "0x..." / lightuserdata / cdata 均支持。
inline uintptr_t CheckAddr(lua_State* Ls, int idx) {
    int tt = lua_type(Ls, idx);
    if (tt == LUA_TNUMBER) {
        return (uintptr_t)lua_tointegerx(Ls, idx, nullptr);
    }
    if (tt == LUA_TSTRING) {
        const char* s = lua_tostring(Ls, idx);
        if (!s) return 0;
        const char* p = s;
        while (*p == ' ' || *p == '\t') ++p;
        int base = 10;
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { base = 16; p += 2; }
        else {
            for (const char* q = p; *q; ++q) {
                if ((*q >= 'a' && *q <= 'f') || (*q >= 'A' && *q <= 'F')) { base = 16; break; }
            }
        }
        return (uintptr_t)strtoull(p, nullptr, base);
    }
    if (tt == LUA_TLIGHTUSERDATA) {
        return (uintptr_t)lua_touserdata(Ls, idx);
    }
    // LuaJIT cdata（例如 ffi.cast("uint64_t", ...) / u64("0x...")）
    // 注意：lua_tointegerx 对 cdata 不可靠，这里走 Lua 助手拆 hi/lo（都 <=32 位，精确）。
    if (tt == 10) {
        lua_getglobal(Ls, "__atrace_addr_parts");
        if (lua_isfunction(Ls, -1)) {
            lua_pushvalue(Ls, idx);
            if (lua_pcall(Ls, 1, 2, 0) == LUA_OK) {
                lua_Integer lo = lua_tointegerx(Ls, -2, nullptr);
                lua_Integer hi = lua_tointegerx(Ls, -1, nullptr);
                lua_pop(Ls, 2);
                return (uintptr_t)(((uint64_t)(uint32_t)hi << 32) | (uint32_t)lo);
            }
            lua_pop(Ls, 1);   // 错误对象
        } else {
            lua_pop(Ls, 1);
        }
    }
    return 0;
}

inline std::string HexStr64(uint64_t v) {
    char b[32];
    snprintf(b, sizeof(b), "0x%llx", (unsigned long long)v);
    return b;
}

// 64 位值返回策略：<= 2^53 返回 number（脚本可继续算术），
// 超过则返回 "0x..." 字符串（避免 double 静默截断），并提示用精确 API。
inline bool PushU64Safe(lua_State* Ls, uint64_t v, const char* fn) {
    constexpr uint64_t kMaxExact = 9007199254740992ULL;  // 2^53
    if (v <= kMaxExact) {
        lua_pushinteger(Ls, (lua_Integer)v);
        return true;
    }
    if (!g_u64Warned) {
        g_u64Warned = true;   // 每个脚本只提示一次，避免轮询把日志/通道刷爆
        PushLog(std::string("[Lua] 注意: ") + fn +
                " 返回值超过 2^53，已改为十六进制字符串 " + HexStr64(v) +
                "；请用 readPtrHex/readQwordHex + u64() 继续处理"
                "（本脚本内后续不再重复提示；需要恒 number 用 readPtrNum）");
    }
    lua_pushstring(Ls, HexStr64(v).c_str());
    return false;
}

inline int Lua_ReadByte(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    std::string why;
    if (const char* bad = CheckRange(addr, 1, false, why)) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, bad);
        return 2;
    }
    uint8_t v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    lua_pushinteger(Ls, (lua_Integer)v);
    return 1;
}

inline int Lua_ReadDword(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    std::string why;
    if (const char* bad = CheckRange(addr, 4, false, why)) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, bad);
        return 2;
    }
    uint32_t v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    lua_pushinteger(Ls, (lua_Integer)v);
    return 1;
}

inline int Lua_ReadQword(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    std::string why;
    if (const char* bad = CheckRange(addr, 8, false, why)) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, bad);
        return 2;
    }
    uint64_t v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    PushU64Safe(Ls, v, "readQword");
    return 1;
}

inline int Lua_ReadFloat(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    std::string why;
    if (const char* bad = CheckRange(addr, 4, false, why)) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, bad);
        return 2;
    }
    float v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    lua_pushnumber(Ls, (lua_Number)v);
    return 1;
}

inline int Lua_ReadDouble(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    std::string why;
    if (const char* bad = CheckRange(addr, 8, false, why)) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, bad);
        return 2;
    }
    double v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    lua_pushnumber(Ls, (lua_Number)v);
    return 1;
}

// 类型不固定会让 `string.format`/算术在运行时突然报 "number expected"，轮询里尤其难受。
// 现在统一为**恒 number**：
//   · 读到的指针先剥掉 arm64 TBI 高位 tag（0xb4000079... → 0x0079...），
//     常见堆/对象指针剥完 tag 后都 <= 2^53，因此**不丢精度**；
//   · 极端值（剥完仍 > 2^53）才可能丢精度，每脚本只提示一次（g_u64Warned）；
//   · 需要"带 tag 的原始位串"用 readPtrHex()；需要 cdata 精确值用 u64(readPtrHex())。
inline int Lua_ReadPtr(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    std::string why;
    if (const char* bad = CheckRange(addr, sizeof(uintptr_t), false, why)) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, bad);
        return 2;
    }
    uintptr_t v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    uintptr_t clean = UntagAddr(v);
    constexpr uint64_t kMaxExact = 9007199254740992ULL;  // 2^53
    if ((uint64_t)clean > kMaxExact && !g_u64Warned) {
        g_u64Warned = true;   // 每个脚本只提示一次，避免轮询把日志/通道刷爆
        PushLog(std::string("[Lua] 注意: readPtr 的值（剥 tag 后）超过 2^53，number 可能有精度损失：") +
                HexStr64((uint64_t)clean) +
                "；需要精确位串请用 readPtrHex()/readQwordHex() + u64()（本脚本内不再重复提示）");
    }
    lua_pushnumber(Ls, (lua_Number)clean);
    return 1;
}

// readPtrNum(addr) -> number：与 readPtr 现在**完全一致**（恒 number、剥 tag）。
// 保留它只为兼容旧脚本；新脚本直接用 readPtr 即可。
inline int Lua_ReadPtrNum(lua_State* Ls) {
    return Lua_ReadPtr(Ls);
}

// 精确版本：始终返回 "0x..." 字符串。
inline int Lua_ReadPtrHex(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    std::string why;
    if (const char* bad = CheckRange(addr, sizeof(uintptr_t), false, why)) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, bad);
        return 2;
    }
    uintptr_t v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    lua_pushstring(Ls, HexStr64((uint64_t)v).c_str());
    return 1;
}

inline int Lua_ReadQwordHex(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    std::string why;
    if (const char* bad = CheckRange(addr, 8, false, why)) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, bad);
        return 2;
    }
    uint64_t v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    lua_pushstring(Ls, HexStr64(v).c_str());
    return 1;
}

// untag(x) -> "0x..."：去掉 arm64 TBI 高位 tag（readPtrHex 返回的是带 tag 原始值）。
inline int Lua_Untag(lua_State* Ls) {
    uintptr_t v = UntagAddr(CheckAddr(Ls, 1));
    lua_pushstring(Ls, HexStr64((uint64_t)v).c_str());
    return 1;
}

// ptrOf(x) -> cdata<void*>（"0x..." 转成可解引用指针）
//   · LuaJIT 的 cdata 在 C 侧难以精确转换，Lua 侧用 cdata 整数运算反而精确；
//   · 这三个函数没有 C 实现，但 api() 里仍列出（它们确实是全局 API）。

// self_info() -> { pid, pkg, agent_base, hooks, hookcpu, hookfunc, hits, uptime_ms }
// 外部 AI 反馈：getpid() 在 namespace 里可能查不到，且不知道 agent 自己加载在哪。
inline int Lua_SelfInfo(lua_State* Ls) {
    lua_newtable(Ls);
    auto seti = [&](const char* k, lua_Integer v) {
        lua_pushstring(Ls, k); lua_pushinteger(Ls, v); lua_settable(Ls, -3);
    };
    auto sets = [&](const char* k, const char* v) {
        lua_pushstring(Ls, k); lua_pushstring(Ls, v ? v : ""); lua_settable(Ls, -3);
    };

    seti("pid", (lua_Integer)getpid());

    char cmdline[256] = {0};
    FILE* f = fopen("/proc/self/cmdline", "r");
    if (f) {
        size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);
        fclose(f);
        if (n > 0) cmdline[n] = 0;
    }
    sets("pkg", cmdline);

    Dl_info info;
    uintptr_t base = 0;
    if (dladdr((void*)&Lua_SelfInfo, &info) && info.dli_fbase) {
        base = (uintptr_t)info.dli_fbase;
    }
    sets("agent_base", HexStr64((uint64_t)base).c_str());

    size_t hookcpu = g_luaCallbacks.size();
    size_t hookfunc = g_hookAddrs.size();
    seti("hookcpu", (lua_Integer)hookcpu);
    seti("hookfunc", (lua_Integer)hookfunc);
    seti("hooks", (lua_Integer)(hookcpu + hookfunc));

    uint64_t hits = 0;
    for (const auto& kv : g_hookCounts) hits += (uint64_t)kv.second;
    seti("hits", (lua_Integer)hits);
    seti("uptime_ms", (lua_Integer)UptimeMs());
    sets("instance_id", HexStr(g_instanceId).c_str());
    return 1;
}

// 给 socket 的 status 命令用的文本摘要。
inline std::string StatusSummary() {
    char cmdline[256] = {0};
    FILE* f = fopen("/proc/self/cmdline", "r");
    if (f) {
        size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);
        fclose(f);
        if (n > 0) cmdline[n] = 0;
    }
    Dl_info info;
    uintptr_t base = 0;
    if (dladdr((void*)&StatusSummary, &info) && info.dli_fbase) {
        base = (uintptr_t)info.dli_fbase;
    }
    uint64_t hits = 0;
    for (const auto& kv : g_hookCounts) hits += (uint64_t)kv.second;
    char buf[576];
    snprintf(buf, sizeof(buf),
             "pid=%d pkg=%s base=0x%llx hooks=%zu(cpu=%zu,func=%zu) hits=%llu "
             "uptime_ms=%llu instance=0x%llx",
             (int)getpid(), cmdline, (unsigned long long)base,
             g_luaCallbacks.size() + g_hookAddrs.size(),
             g_luaCallbacks.size(), g_hookAddrs.size(),
             (unsigned long long)hits, (unsigned long long)UptimeMs(),
             (unsigned long long)g_instanceId);
    return buf;
}

// whoami() -> "pid=.. pkg=.. base=0x.. hooks=.. instance=0x.."（多进程时确认"我连的是谁"）
inline int Lua_WhoAmI(lua_State* Ls) {
    lua_pushstring(Ls, StatusSummary().c_str());
    return 1;
}

// hooks() / hook_list() -> 数组 { {addr, mode, hits, trampoline}, ... , count }
// replace 模式下 hits 恒 0（Dobby 替换桩里无法计数）；instrument 才有命中统计。
inline int Lua_Hooks(lua_State* Ls) {
    lua_newtable(Ls);
    int n = 0;
    auto pushOne = [&](uintptr_t addr, const char* mode, uintptr_t tramp, int hits) {
        lua_newtable(Ls);
        lua_pushstring(Ls, "addr");       lua_pushinteger(Ls, (lua_Integer)addr);  lua_settable(Ls, -3);
        lua_pushstring(Ls, "mode");       lua_pushstring(Ls, mode);                lua_settable(Ls, -3);
        lua_pushstring(Ls, "hits");       lua_pushinteger(Ls, (lua_Integer)hits);  lua_settable(Ls, -3);
        lua_pushstring(Ls, "trampoline"); lua_pushinteger(Ls, (lua_Integer)tramp); lua_settable(Ls, -3);
        lua_rawseti(Ls, -2, ++n);
    };
    for (const auto& kv : g_luaCallbacks) {
        auto it = g_hookCounts.find(kv.first);
        pushOne(kv.first, "instrument", 0, it == g_hookCounts.end() ? 0 : it->second);
    }
    for (uintptr_t addr : g_hookAddrs) {
        auto it = g_hookTrampolines.find(addr);
        uintptr_t tramp = (it == g_hookTrampolines.end()) ? 0 : it->second;
        int hits = 0;
        auto th = g_replaceThunks.find(addr);
        if (th != g_replaceThunks.end() && th->second.counter_addr)
            hits = (int)*(volatile uint32_t*)th->second.counter_addr;
        pushOne(addr, "replace", tramp, hits);
    }
    lua_pushstring(Ls, "count"); lua_pushinteger(Ls, (lua_Integer)n); lua_settable(Ls, -3);
    return 1;
}

// readInt32(addr) -> 有符号 32 位（readDword 是无符号）
inline int Lua_ReadInt32(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    std::string why;
    if (const char* bad = CheckRange(addr, 4, false, why)) {
        lua_pushnil(Ls); lua_pushstring(Ls, bad); return 2;
    }
    int32_t v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    lua_pushinteger(Ls, (lua_Integer)v);
    return 1;
}

// readInt64(addr) -> 有符号 64 位（超 2^53 返回 "0x..." 原始位串）
inline int Lua_ReadInt64(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    std::string why;
    if (const char* bad = CheckRange(addr, 8, false, why)) {
        lua_pushnil(Ls); lua_pushstring(Ls, bad); return 2;
    }
    int64_t v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    constexpr int64_t kMaxExact = 9007199254740992LL;
    if (v >= -kMaxExact && v <= kMaxExact) {
        lua_pushinteger(Ls, (lua_Integer)v);
    } else {
        PushLog("[Lua] 注意: readInt64 返回值超过 2^53，已改为十六进制字符串；需要原始位用 readQwordHex");
        lua_pushstring(Ls, HexStr64((uint64_t)v).c_str());
    }
    return 1;
}

inline int Lua_ReadBytes(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    int len = (int)luaL_checkinteger(Ls, 2);
    if (len < 0) len = 0;
    if (len > 65536) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, "长度超过单次上限 65536，请分块读取");
        return 2;
    }
    if (len < 0) len = 0;
    std::string why;
    if (const char* bad = CheckRange(addr, (size_t)len, false, why)) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, bad);
        return 2;
    }
    lua_pushlstring(Ls, (const char*)addr, (size_t)len);
    return 1;
}

inline int Lua_ReadString(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    int max = (int)luaL_optinteger(Ls, 2, 256);
    if (max < 1) max = 1;
    if (max > 65536) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, "maxlen 超过单次上限 65536，请分块读取");
        return 2;
    }
    std::string why;
    if (const char* bad = CheckRange(addr, (size_t)max, false, why)) {
        // 只保证首字节可读时也允许尝试（字符串可能提前遇到 NUL）
        if (CheckRange(addr, 1, false, why)) {
            lua_pushnil(Ls);
            lua_pushstring(Ls, bad);
            return 2;
        }
    }
    std::vector<char> buf((size_t)max + 1, 0);
    for (int i = 0; i < max; i++) {
        char c = 0;
        memcpy(&c, (const void*)(addr + (uintptr_t)i), 1);
        buf[(size_t)i] = c;
        if (c == 0) break;
    }
    lua_pushstring(Ls, buf.data());
    return 1;
}

// 写操作：只校验"已映射"，权限交给 LuaWriteMemory 的 mprotect 流程
// （代码页补丁是合法用法）。返回 true/false,err。
inline int Lua_WriteByte(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    int64_t v = (int64_t)luaL_checkinteger(Ls, 2);
    std::string why;
    const char* bad = CheckRange(addr, 1, true, why);
    uint8_t b = (uint8_t)v;
    bool ok = !bad && LuaWriteMemory(addr, &b, 1);
    lua_pushboolean(Ls, ok);
    if (!ok) { lua_pushstring(Ls, bad ? bad : "写入失败"); return 2; }
    return 1;
}

inline int Lua_WriteDword(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    int64_t v = (int64_t)luaL_checkinteger(Ls, 2);
    std::string why;
    const char* bad = CheckRange(addr, 4, true, why);
    uint32_t w = (uint32_t)v;
    bool ok = !bad && LuaWriteMemory(addr, &w, sizeof(w));
    lua_pushboolean(Ls, ok);
    if (!ok) { lua_pushstring(Ls, bad ? bad : "写入失败"); return 2; }
    return 1;
}

inline int Lua_WriteQword(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    // 值也支持 "0x..." 字符串（64 位精确写入）
    uint64_t q = 0;
    int tt = lua_type(Ls, 2);
    if (tt == LUA_TSTRING) {
        const char* s = lua_tostring(Ls, 2);
        const char* p = s ? s : "0";
        if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
        q = (uint64_t)strtoull(p, nullptr, 16);
    } else if (tt == 10) {
        int isnum = 0;
        lua_Integer iv = lua_tointegerx(Ls, 2, &isnum);
        q = isnum ? (uint64_t)iv : 0;
    } else {
        q = (uint64_t)luaL_checkinteger(Ls, 2);
    }
    std::string why;
    const char* bad = CheckRange(addr, 8, true, why);
    bool ok = !bad && LuaWriteMemory(addr, &q, sizeof(q));
    lua_pushboolean(Ls, ok);
    if (!ok) { lua_pushstring(Ls, bad ? bad : "写入失败"); return 2; }
    return 1;
}

inline int Lua_WriteFloat(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    double v = (double)luaL_checknumber(Ls, 2);
    std::string why;
    const char* bad = CheckRange(addr, 4, true, why);
    float f = (float)v;
    bool ok = !bad && LuaWriteMemory(addr, &f, sizeof(f));
    lua_pushboolean(Ls, ok);
    if (!ok) { lua_pushstring(Ls, bad ? bad : "写入失败"); return 2; }
    return 1;
}

inline int Lua_WriteDouble(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    double v = (double)luaL_checknumber(Ls, 2);
    std::string why;
    const char* bad = CheckRange(addr, 8, true, why);
    bool ok = !bad && LuaWriteMemory(addr, &v, sizeof(v));
    lua_pushboolean(Ls, ok);
    if (!ok) { lua_pushstring(Ls, bad ? bad : "写入失败"); return 2; }
    return 1;
}

inline int Lua_WritePtr(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    uintptr_t p = CheckAddr(Ls, 2);
    std::string why;
    const char* bad = CheckRange(addr, sizeof(uintptr_t), true, why);
    bool ok = !bad && LuaWriteMemory(addr, &p, sizeof(p));
    lua_pushboolean(Ls, ok);
    if (!ok) { lua_pushstring(Ls, bad ? bad : "写入失败"); return 2; }
    return 1;
}

inline int Lua_WriteBytes(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    size_t len = 0;
    const char* data = luaL_checklstring(Ls, 2, &len);
    std::string why;
    const char* bad = CheckRange(addr, len, true, why);
    bool ok = !bad && LuaWriteMemory(addr, data, len);
    lua_pushboolean(Ls, ok);
    if (!ok) { lua_pushstring(Ls, bad ? bad : "写入失败"); return 2; }
    return 1;
}

// writeString(addr, s [, with_nul])
// 需要 NUL 终止时显式传 true。
inline int Lua_WriteString(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    size_t len = 0;
    const char* data = luaL_checklstring(Ls, 2, &len);
    bool withNul = lua_toboolean(Ls, 3) != 0;
    size_t total = len + (withNul ? 1 : 0);
    std::string why;
    const char* bad = CheckRange(addr, total, true, why);
    if (bad) {
        lua_pushboolean(Ls, false);
        lua_pushstring(Ls, bad);
        return 2;
    }
    std::vector<char> buf(total, 0);
    if (len) memcpy(buf.data(), data, len);
    bool ok = LuaWriteMemory(addr, buf.data(), total);
    lua_pushboolean(Ls, ok);
    if (!ok) { lua_pushstring(Ls, "写入失败"); return 2; }
    return 1;
}

// ---------- 全角转半角 ----------
inline void ReplaceAll(std::string& str, const std::string& from, const std::string& to) {
    if (from.empty()) return;
    size_t pos = 0;
    while ((pos = str.find(from, pos)) != std::string::npos) {
        str.replace(pos, from.length(), to);
        pos += to.length();
    }
}

// ---------- RunScript ----------
inline std::string RunScript(const std::string& script) {
    if (!L) return "[Lua] 引擎未初始化";

    // P1-4：锁超时要能区分"引擎忙"，而不是让客户端干等到超时。
    std::unique_lock<std::recursive_timed_mutex> lock(g_luaMutex, std::defer_lock);
    if (!lock.try_lock_for(std::chrono::milliseconds(500))) {
        return "[Lua] 引擎忙（可能卡在 hook 回调/兜底泵），本次未执行";
    }
    g_u64Warned = false;   // 每次脚本执行重置超过 2^53 的提示

    std::string code = script;
    ReplaceAll(code, "\u201C", "\"");  // "
    ReplaceAll(code, "\u201D", "\"");  // "
    ReplaceAll(code, "\u2018", "'");   // '
    ReplaceAll(code, "\u2019", "'");   // '
    ReplaceAll(code, "\uFF08", "(");   // (
    ReplaceAll(code, "\uFF09", ")");   // )
    ReplaceAll(code, "\uFF1B", ";");   // ;
    ReplaceAll(code, "\uFF1A", ":");   // :
    ReplaceAll(code, "\uFF0C", ",");   // ,
    ReplaceAll(code, "\u3002", ".");   // .
    ReplaceAll(code, "\u3000", " ");   // 全角空格
    ReplaceAll(code, "\uFF1D", "=");   // =
    ReplaceAll(code, "\uFF1C", "<");   // <
    ReplaceAll(code, "\uFF1E", ">");   // >
    ReplaceAll(code, "\uFF0B", "+");   // +
    ReplaceAll(code, "\uFF0D", "-");   // -
    ReplaceAll(code, "\uFF0A", "*");   // *
    ReplaceAll(code, "\uFF0F", "/");   // /
    ReplaceAll(code, "\uFF1F", "?");   // ?
    ReplaceAll(code, "\uFF01", "!");   // !
    ReplaceAll(code, "\uFF3B", "[");   // [
    ReplaceAll(code, "\uFF3D", "]");   // ]
    ReplaceAll(code, "\uFF5B", "{");   // {
    ReplaceAll(code, "\uFF5D", "}");   // }

    // P1-22：记录脚本执行的桥接层帧指针，nativeBacktrace 可由此拿到宿主 C 调用链。
    NativeBtScope btScope;
    // P2-4：先按原文执行；失败再尝试全角→半角替换重试（避免替换误伤字符串字面量）。
    int rc = luaL_loadstring(L, script.c_str());
    if (rc == LUA_OK) {
        rc = lua_pcall(L, 0, 0, 0);
    } else {
        lua_pop(L, 1);   // 丢弃原始错误，换规范化版本重试
        rc = luaL_dostring(L, code.c_str());
    }
    std::string err;
    if (rc != LUA_OK) {
        const char* e = lua_tostring(L, -1);
        err = e ? e : "未知错误";
        lua_pop(L, 1);
    }

    // 日志统一由 GUI 轮询 lua_logs 获取（含 call 闭包等异步输出），
    // 这里只返回成功 / 错误标记，避免与轮询结果重复。
    std::string out;
    if (!err.empty()) out = "[Lua 错误] " + err + "\n";
    else if (rc == LUA_OK) out = "[Lua] 执行成功\n";
    return out;
}

// ---------- Lua：regsOf / setReg（hook 回调里的寄存器读写）----------
// RegisterContext 布局（见 dobby.h）：
//   0: dmmpy_0  8: sp  16: dmmpy_1  24: x0..x28(29*8)  256: fp  264: lr
inline int Lua_RegsOf(lua_State* Ls) {
    void* p = lua_touserdata(Ls, 1);
    if (!p) {
        return luaL_error(Ls,
            "regsOf(regs_ptr): 参数必须是 hook 回调收到的第 1 个参数（lightuserdata regs）");
    }
    const uint8_t* base = (const uint8_t*)p;
    lua_newtable(Ls);
    char key[8];
    for (int i = 0; i < 29; i++) {
        uint64_t v = 0;
        memcpy(&v, base + 24 + (size_t)i * 8, 8);
        snprintf(key, sizeof(key), "x%d", i);
        lua_pushstring(Ls, key);
        lua_pushinteger(Ls, (lua_Integer)v);
        lua_settable(Ls, -3);
    }
    uint64_t sp = 0, fp = 0, lr = 0;
    memcpy(&sp, base + 8, 8);
    memcpy(&fp, base + 256, 8);
    memcpy(&lr, base + 264, 8);
    const char* names[] = {"sp", "fp", "lr"};
    uint64_t vals[] = {sp, fp, lr};
    for (int i = 0; i < 3; i++) {
        lua_pushstring(Ls, names[i]);
        lua_pushinteger(Ls, (lua_Integer)vals[i]);
        lua_settable(Ls, -3);
    }
    return 1;
}

inline int Lua_SetReg(lua_State* Ls) {
    void* p = lua_touserdata(Ls, 1);
    const char* name = luaL_checkstring(Ls, 2);
    uint64_t v = (uint64_t)luaL_checkinteger(Ls, 3);
    if (!p) {
        return luaL_error(Ls, "setReg(regs_ptr, name, value): 第 1 个参数必须是 hook 回调的 regs");
    }
    uint8_t* base = (uint8_t*)p;
    if (!strcmp(name, "sp")) { memcpy(base + 8, &v, 8); return 0; }
    if (!strcmp(name, "fp")) { memcpy(base + 256, &v, 8); return 0; }
    if (!strcmp(name, "lr")) { memcpy(base + 264, &v, 8); return 0; }
    if (name[0] == 'x') {
        char* end = nullptr;
        long idx = strtol(name + 1, &end, 10);
        if (end && *end == '\0' && idx >= 0 && idx <= 28) {
            memcpy(base + 24 + (size_t)idx * 8, &v, 8);
            return 0;
        }
    }
    return luaL_error(Ls,
        "setReg: 不认识的寄存器名 '%s'（可用 x0-x28 / sp / fp / lr）", name);
}

// ---------- Lua：api() / help()——自描述 ----------
// api() 返回结构化的函数表（机器可读），help() 往日志里打印人类可读清单。
struct LuaApiDoc {
    const char* name;
    const char* sig;
    const char* ret;
    const char* desc;
    const char* example;
};

inline const std::vector<LuaApiDoc>& ApiDocs() {
    static const std::vector<LuaApiDoc> kDocs = {
        {"print", "print(...)", "nil",
         "输出到调试日志（电脑端脚本模式/手机日志都能看到）",
         "print(string.format(\"base=0x%x\", getBase(\"libxxx.so\")))"},
        {"getBase", "getBase(name: string) -> number", "number",
         "返回已加载模块的基址（number）；name 可写短名或全路径。"
         "模块未加载/名字不对时返回 **0 且不缓存**（旧版会缓存 0）；"
         "可用 clearbase(name) 清缓存后重查",
         "local b = getBase(\"libtutorial.so\")"},
        {"hookCPU", "hookCPU(addr: number, fn: function(regs, addr)) -> nil", "nil",
         "在函数入口插入回调（DobbyInstrument）。回调第 1 个参数是寄存器上下文，"
         "用 regsOf(regs) 读、setReg(regs, \"x0\", v) 写；第 2 个参数是函数地址。"
         "原函数照常执行。**注意：回调运行在目标线程里，只写一行 call(runner)；"
         "ffi.cast/循环/字符串拼接等会分配内存的操作放到 runner 里，否则容易闪退**",
         "hookCPU(addr, function(regs, a) local r = regsOf(regs); print(r.x0) end)"},
        {"hookfunc", "hookfunc(addr, fn: function|replaceAddr) -> handle", "handle",
         "两种模式（返回的都是 handle 表，不是裸指针）："
         "① hookfunc(addr, function(regs, addr)) = instrument（入口回调，原函数照常执行）；"
         "只能观察/改寄存器，**不能改返回值**；"
         "② hookfunc(addr, 原生地址) = replace（整体替换，可以改返回值）。"
         "原生地址**可以直接用 ffi.cast 从 Lua 函数生成，不需要 NDK**："
         "local cb = ffi.cast(\"int(*)(void)\", function() return 1 end)；"
         "**必须把 cb 挂到全局防 GC**（_G.keep = cb），再传 tonumber(ffi.cast(\"uintptr_t\", cb))。"
         "handle 字段：h.addr / h.orig(**Dobby trampoline，不是原函数入口；ffi.cast 后乱调会崩**，"
         "h:remove() / h:hits()（**仅 instrument 计数；replace 恒 0**，因为替换桩里没有计数点） / "
         "h:call_original(...)。h.orig 的同义字段是 h.trampoline",
         "local h = hookfunc(addr, function(regs, a) print(\"hit\") end); print(h:hits())"},
        {"removehook", "removehook(addr: number) -> boolean", "boolean",
         "卸载指定地址的 hook（hookfunc 的 h:remove() 等价）", "removehook(addr)"},
        {"remove_all_hook", "remove_all_hook() -> boolean", "boolean",
         "卸载所有 Lua 层 hook。**不会卸载主线程泵**"
         "（eglSwapBuffers/ALooper hook 是 call() 的机制，仍然工作）", "remove_all_hook()"},
        {"call_stats", "call_stats() -> table", "table",
         "返回 { pending, done, last_err }（call() 投递任务的状态）", "print(call_stats().pending)"},
        {"call_done", "call_done(id) -> true|false,err|nil,reason", "boolean",
         "查询 call() 任务是否完成及结果；未完成返回 nil,\"pending\"，未知 id 返回 nil,\"unknown id\"",
         "local id = call(function() end); print(call_done(id))"},
        {"call_sync", "call_sync(fn, ...) -> ...", "any",
         "**立即在当前线程执行** fn 并返回其结果（不排队）。"
         "需要\"马上拿到结果\"用 call_sync；需要\"延后到主线程\"用 call()",
         "local v = call_sync(function(a) return a * 2 end, 21)"},
        {"call", "call(fn) -> number", "number",
         "把 fn 排队到 **eglSwapBuffers 渲染线程 / ALooper 主线程** 执行；"
         "两者都没有动静（静默 300ms）时由**独立兜底线程**执行——"
         "**兜底线程不是主线程**，不要在里面碰 JNI/UI（会崩）。"
         "异步执行：**返回任务 id**（配合 call_done/call_stats 查询）；错误只写日志；"
         "泵未就绪时任务静默丢失。回调里只写一行 call(runner)，runner 里自己 pcall。"
         "**重要（锁语义）**：run_lua 执行期间全程持有 Lua 锁，泵线程拿不到锁，"
         "所以在**同一个脚本内**用 while/msleep 等 call 的结果永远等不到（会一直 pending）；"
         "结果只能在**下一个脚本**里读。",
         "call(function() pcall(function() print(\"on pump\") end) end)"},
        {"msleep", "msleep(ms: number) -> nil", "nil", "休眠指定毫秒", "msleep(100)"},
        {"readByte", "readByte(addr) -> number", "number", "读 1 字节", ""},
        {"readDword", "readDword(addr) -> number", "number", "读 4 字节（小端 uint32）",
         "print(readDword(0x70B8D02D70))"},
        {"readQword", "readQword(addr) -> number|string", "number|string",
         "读 8 字节。<=2^53 返回 number，超过返回 \"0x...\" 字符串（避免 double 截断）；"
         "精确读取用 readQwordHex", ""},
        {"readFloat", "readFloat(addr) -> number", "number", "读 float", ""},
        {"readDouble", "readDouble(addr) -> number", "number", "读 double", ""},
        {"readPtr", "readPtr(addr) -> number|nil,err", "number",
         "读指针（8 字节）并**始终返回 number**（类型统一，可直接算术/string.format/拼接）。"
         "返回值会先剥掉 arm64 TBI 高位 tag（0xb4xxxx... → 0x0079xxxx...），"
         "常见堆/对象指针剥完 tag 后都 <=2^53 因而不丢精度；极端值每脚本只提示一次。"
         "需要带 tag 的原始位串用 readPtrHex()，需要 cdata 精确值用 u64(readPtrHex())。", ""},
        {"readPtrHex", "readPtrHex(addr) -> string", "string",
         "精确读 8 字节指针，返回 \"0x...\" 字符串（64 位不丢精度）。"
         "注意：**返回的是带 TBI tag 的原始值**（如 0xb400007733f4cdb0）；"
         "readDword/writeDword 等地址入口会自动剥离 tag，无需手动处理",
         "local p = readPtrHex(0xb400007971cde630)"},
        {"readQwordHex", "readQwordHex(addr) -> string", "string",
         "精确读 8 字节整数，返回 \"0x...\" 字符串", ""},
        {"readInt32", "readInt32(addr) -> number", "number",
         "读**有符号** 32 位整数（readDword 是无符号；写 -88880 后 readDword 会得到 4294878416）",
         "print(readInt32(addr))"},
        {"readInt64", "readInt64(addr) -> number|string", "number|string",
         "读**有符号** 64 位整数；超过 2^53 返回 \"0x...\" 原始位串（需要无符号用 readQwordHex）", ""},
        {"readBytes", "readBytes(addr, len) -> string", "string",
         "读一段内存为字符串；len 上限 65536（超过返回 nil,原因，不静默截断）", ""},
        {"readString", "readString(addr, maxlen?) -> string", "string",
         "读 C 字符串；maxlen 上限 65536（超过返回 nil,原因）", ""},
        {"hexOf", "hexOf(x) -> string", "string",
         "把 number / 字符串 / lightuserdata / cdata 统一格式化成 \"0x...\"",
         "print(hexOf(self_info().agent_base))"},
        {"ptrOf", "ptrOf(x) -> cdata<void*>", "cdata",
         "把 \"0x...\" 转成 cdata<void*>，可直接 ffi.cast / 解引用",
         "local p = ptrOf(\"0xb400007971cde630\")"},
        {"untag", "untag(x) -> string", "string",
         "去掉 arm64 TBI 高位 tag，返回 \"0x...\"（readPtrHex 返回的是**带 tag 原始值**；"
         "read/write/hook 等地址入口已自动剥离 tag，一般不需要手动调用）",
         "print(untag(\"0xb400007733f4cdb0\")) --> 0x7733f4cdb0"},
        {"u64", "u64(x: string|number) -> cdata<uint64_t>", "cdata",
         "把 \"0x...\" 转成 64 位精确整数（cdata），超过 2^53 也不丢精度；"
         "可直接用于 ffi.cast(\"void*\", u64(\"0x...\"))",
         "local p = ffi.cast(\"void*\", u64(\"0xb400007971cde630\"))"},
        {"whoami", "whoami() -> string", "string",
         "一行摘要：pid/pkg/base/hooks/instance（多进程并存时确认\"我连的是谁\"）",
         "print(whoami())"},
        {"hooks", "hooks() -> array", "array",
         "列出所有已安装 hook：{addr, mode(\"instrument\"/\"replace\"), hits, trampoline}；"
         "数组部分 = 列表（#h == 数量），另有 count 字段。replace 的 hits 恒 0",
         "for _, h in ipairs(hooks()) do print(hexOf(h.addr), h.mode, h.hits) end"},
        {"hook_list", "hook_list() -> array", "array", "hooks() 的别名", ""},
        {"self_info", "self_info() -> table", "table",
         "返回 { pid, pkg, agent_base, hooks, hookcpu, hookfunc, hits, uptime_ms, instance_id }。"
         "getpid() 在 namespace 里可能查不到进程时用它",
         "local si = self_info(); print(si.pid, si.pkg, si.instance_id)"},
        {"writeByte", "writeByte(addr, v) -> boolean", "boolean",
         "写 1 字节；返回是否成功（未映射/不可写返回 false,原因）", ""},
        {"writeDword", "writeDword(addr, v) -> boolean", "boolean",
         "写 4 字节（小端）；返回是否成功", "local ok = writeDword(addr, 1000)"},
        {"writeQword", "writeQword(addr, v) -> boolean", "boolean",
         "写 8 字节（v 可为 \"0x...\" 字符串）；返回是否成功", ""},
        {"writeFloat", "writeFloat(addr, v) -> boolean", "boolean",
         "写 float；返回是否成功", ""},
        {"writeDouble", "writeDouble(addr, v) -> boolean", "boolean",
         "写 double；返回是否成功", ""},
        {"writePtr", "writePtr(addr, ptr) -> boolean", "boolean",
         "写指针（地址/字符串/cdata 均可）；返回是否成功", ""},
        {"writeBytes", "writeBytes(addr, s) -> boolean", "boolean",
         "写一段字节串；返回是否成功", ""},
        {"writeString", "writeString(addr, s [, with_nul]) -> boolean", "boolean",
         "写字符串；**默认不追加 NUL**（需要 NUL 终止传 true）；返回是否成功", ""},
        {"clearbase", "clearbase([name]) -> boolean", "boolean",
         "清空模块基址缓存（模块重载后 getBase 拿不到新基址时用）", "clearbase()"},
        {"module_info", "module_info(name) -> table", "table",
         "返回 { name, path, base, size, segments=[{name,perms,label,start,stop,prot,exec}] }；"
         "name/perms 形如 \"r-x\"，label = text/data/rodata；"
         "（每段也有 \"end\" 字段，但 end 是 Lua 保留字，要用 s[\"end\"]；建议用 stop）"
         "segments 可直接作为 scan 的安全边界", "local mi = module_info(\"libtutorial.so\"); print(mi.base, mi.size)"},
        {"symbols", "symbols(name, pattern?) -> array", "array",
         "解析 .dynsym，返回**数组**（#r == 实际条数，每条 {name,offset,addr,size,type}）；"
         "另有 count / truncated / symbols 字段（旧写法 r.symbols 仍可用）。"
         "pattern 为名字子串过滤。最多返回 4000 条",
         "for _, s in ipairs(symbols(\"libtutorial.so\", \"Step\").symbols) do print(s.name, hexOf(s.addr)) end"},
        {"scan", "scan(name, hex, mask?) -> array", "array",
         "在模块可读段内做带掩码的**内存字节序**扫描，返回**数组**（#r == 命中数，元素是地址）；"
         "另有 count / addrs / truncated 字段（旧写法 r.addrs 仍可用）。"
         "hex 支持 \"90 00 ?? 08\"，mask 用 FF=匹配 00=通配；"
         "注意按内存原始字节序：小端机上 32 位指令 0x90000008 的字节是 08 00 00 90；"
         "最多 4096 个命中",
         "for _, a in ipairs(scan(\"libtutorial.so\", \"90000008\", \"FFFFFFFF\").addrs) do print(hexOf(a)) end"},
        {"regsOf", "regsOf(regs) -> table", "table",
         "把 hook 回调的寄存器上下文转成表：{x0..x28, sp, fp, lr}。"
         "**没有 pc/pstate**（Dobby 的 RegisterContext 不含）；"
         "要知道函数地址用回调第 2 个参数", ""},
        {"setReg", "setReg(regs, name, value)", "nil",
         "修改回调里的寄存器（name = x0..x28 / sp / fp / lr）", ""},
        {"api", "api([name]) -> table", "table",
         "返回本引擎的 API 说明表（含 sig/ret/desc/example）；传 name 只返回那一项",
         "for _, f in ipairs(api().functions) do print(f.name, f.sig) end"},
        {"help", "help() -> nil", "nil", "把 API 清单打印到调试日志（人类可读）", "help()"},
        {"capabilities", "capabilities() -> table", "table",
         "**能力自检**：一次输出架构/版本/api 数量/进程/ART 状态/各类 hook 可用性/数组与 ffi 限制/断点实现方式，"
         "另附 limitations 数组。比翻文档更快知道它到底会什么。",
         "local c = capabilities(); for k, v in pairs(c) do print(k, v) end"},
        {"artHook", "artHook(class: string, method: string [, signature: string], fn) -> number|nil,err", "number",
         "hook 一个 **Java/ART 方法**（LSPlant，运行期替换，不改 dex）。"
         "回调 fn(ctx) 在调用该方法的 Java 线程上执行；ctx = {id, this=接收者对象或 nil, args={实际参数}, "
         "signature=\"完整方法描述符\"（如 \"(Ljava/lang/String;)V\"）, retType=\"返回类型描述符\"（如 V/I/Ljava/lang/String;）}。"
         "参数按类型自动转换：数字/Bool/String 直接是 Lua 值，其它对象是 userdata（tostring 会调 Java toString）。"
         "**返回非 nil 就作为 Java 返回值**（按方法返回类型自动装箱）；返回 nil 表示透传：自动调用原方法并把结果返回。"
         "signature 可省略（同名唯一时）；重载请传 JNI 描述符，如 \"(Ljava/lang/String;)V\"。"
         "注意：回调里不要做重活（会卡住正在调用该方法的 Java 线程）；同一个 run_lua 执行期间 Lua 锁被占用，回调会被延后。",
         "local id = artHook(\"java.lang.StringBuilder\", \"append\", \"(Ljava/lang/String;)Ljava/lang/StringBuilder;\", function(ctx) print(\"append:\", tostring(ctx.args[1])) end)"},
        {"artUnhook", "artUnhook(id: number) -> boolean[,err]", "boolean",
         "卸载 artHook 装上的 Java hook（LSPlant UnHook）。", "artUnhook(id)"},
        {"artHooks", "artHooks() -> array", "array",
         "列出当前所有 Java hook：{id, class, method, signature, mode}。", "for _, h in ipairs(artHooks()) do print(h.id, h.class, h.method) end"},
        {"artVmState", "artVmState() -> string", "string",
         "ART/JavaVM 诊断：init/vm/vmSource/currentThreadAttached/lastError；artHook 初始化失败时先看它。", "print(artVmState())"},
        {"artStatus", "artStatus() -> string", "string",
         "返回 ART hook 引擎状态（是否已初始化 LSPlant）。", "print(artStatus())"},
        {"javaNew", "javaNew(class: string, signature: string, ...) -> userdata|nil,err", "userdata",
         "构造一个 Java 对象（返回 userdata，可用 :call / :getField / :setField / tostring）。"
         "signature 是构造方法描述符，如 \"()V\" / \"(I)V\" / \"(Ljava/lang/String;)V\"。"
         "对象参数也可直接传别的 userdata / string / number；生命周期由 Lua GC 管理（__gc 释放 global ref）。",
         "local ai = javaNew(\"java.util.concurrent.atomic.AtomicInteger\", \"(I)V\", 42); print(ai:call(\"get\", \"()I\"))"},
        {"readPtrNum", "readPtrNum(addr) -> number|nil,err", "number",
         "**与 readPtr 等价**（保留仅为兼容旧脚本）：恒返回 number、自动剥 TBI tag。", "local p = readPtrNum(addr)"},
        {"readU8", "readU8(addr) -> number", "number", "读 1 字节无符号（0..255）；readByte 的同义。", "print(readU8(addr))"},
        {"readI8", "readI8(addr) -> number", "number", "读 1 字节有符号（-128..127）。", "print(readI8(addr))"},
        {"readU16", "readU16(addr) -> number", "number", "读 2 字节无符号（小端）。", "print(readU16(addr))"},
        {"readI16", "readI16(addr) -> number", "number", "读 2 字节有符号（小端）。", "print(readI16(addr))"},
        {"readU32", "readU32(addr) -> number", "number", "读 4 字节无符号（= readDword）。", "print(readU32(addr))"},
        {"readI32", "readI32(addr) -> number", "number", "读 4 字节有符号（= readInt32）。", "print(readI32(addr))"},
        {"readU64", "readU64(addr) -> number|string", "number|string", "读 8 字节无符号；超 2^53 返回十六进制字符串（= readQword）。", "print(readU64(addr))"},
        {"readI64", "readI64(addr) -> number|string", "number|string", "读 8 字节有符号；超 2^53 返回原始位串（= readInt64）。", "print(readI64(addr))"},
        {"readU64Num", "readU64Num(addr) -> number", "number", "读 8 字节无符号，**恒返回 number**（>2^53 有精度损失，每脚本提示一次）。", "print(readU64Num(addr))"},
        {"readI64Num", "readI64Num(addr) -> number", "number", "读 8 字节有符号，**恒返回 number**（>2^53 有精度损失，每脚本提示一次）。", "print(readI64Num(addr))"},
        {"verify", "verify(addr, hex[, mask]) -> true | false, offset, reason", "boolean",
         "校验一段内存是否仍是期望字节（支持 ?? 通配）。用于确认 writeBytes 补丁在目标重启后是否还有效。",
         "print(verify(addr, \"08000090\"))"},
        {"maps", "maps() -> array", "array",
         "返回 /proc/self/maps 解析结果：{start, stop, size, perms, path, read, write, exec}。",
         "for _, m in ipairs(maps()) do if m.exec and m.path:find(\"libtutorial\") then print(hexOf(m.start)) end end"},
        {"scanRange", "scanRange(start, stop, hex[, mask]) -> array", "array",
         "在**任意可读区间**（堆/匿名段也行）按字节模式扫描；掩码 FF=匹配 00=通配，?? 也可；最多 4096 命中。"
         "返回数组 + addrs/count/truncated。", "for _, a in ipairs(scanRange(m.start, m.stop, \"08000090\")) do print(hexOf(a)) end"},
        {"symbol", "symbol(name[, module]) -> number|nil,err", "number",
         "按名字查符号地址：先 dlsym 全局导出，再遍历已加载模块的 .dynsym；传 module 可限定模块。",
         "print(hexOf(symbol(\"SSL_write\")))"},
        {"dumpToFile", "dumpToFile(addr, len, path) -> true,bytes|nil,err", "boolean",
         "把目标内存 dump 到文件（脱壳/抓包/导出样本）；path 需要目标进程可写。", "dumpToFile(addr, 0x1000, \"/data/local/tmp/dump.bin\")"},
        {"dump", "dump(value[, depth]) -> lines", "number",
         "结构化打印 Lua 值（table 递归、userdata 走 __tostring）到日志，depth 默认 2。", "dump({a=1,b={c=2}})"},
        {"javaFields", "javaFields(obj[, includeSuper]) -> array", "array",
         "列出一个 Java 对象的字段：{name, descriptor, value}；includeSuper=true 沿父类链。",
         "for _, f in ipairs(javaFields(obj, true)) do print(f.name, f.descriptor, f.value) end"},
        {"javaCallStatic", "javaCallStatic(class, method, signature, ...) -> value", "any",
         "调用静态 Java 方法（class 用完整类名；signature 必填）。配合 javaNew/数组 API 解枚举。",
         "print(javaCallStatic(\"java.lang.Class\", \"forName\", \"(Ljava/lang/String;)Ljava/lang/Class;\", \"java.lang.String\"))"},
        {"artHookAll", "artHookAll(class, namePattern, fn) -> table|nil,err", "table",
         "**批量 hook** 类里所有匹配 Lua 模式的方法（含同名重载）："
         "返回 {[i]={id,method,signature}, count=N, errors={…}}，可对每项 artUnhook(id)。"
         "namePattern 用 Lua 模式：精确 \"^append$\"、前缀 \"^get\"、全部 \".*\"；native/abstract 自动跳过。",
         "local r = artHookAll(\"java.util.ArrayList\", \"^add$\", function(ctx) return nil end); print(r.count)"},
        {"javaDump", "javaDump(obj[, maxDepth]) -> string", "string",
         "**对象图 dump**：递归打印字段（含父类、静态字段），带深度/节点预算和环检测；"
         "maxDepth 默认 2、上限 5。比 javaFields 更适合看嵌套对象状态。",
         "print(javaDump(javaNew(\"java.util.ArrayList\", \"()V\")))"},
        {"javaFindClass", "javaFindClass(name) -> userdata|nil,err", "userdata",
         "**用应用 ClassLoader 查类**（Class.forName(name,false,appLoader)），能查到 App 自己的类；"
         "失败给明确错误（不是静默 nil）。内部类用 $ 分隔。拿到 Class 后可配合 javaCallStatic/javaNew。"
         "对比：javaCallStatic(\"java.lang.Class\",\"forName\",...) 只走 boot ClassLoader，查应用类必失败。",
         "local c = javaFindClass(\"com.example.Foo\"); print(tostring(c))"},
        {"javaString", "javaString(s) -> userdata(java.lang.String)", "userdata",
         "把 Lua string 包成 **Java String 对象**（可继续 :call）。"
         "因为 PushJavaValue 会把 String 自动转回 Lua string，所以想对字符串调 Java 方法必须显式包一层。",
         "print(javaString(\"hello\"):call(\"getBytes\", \"()[B\"))"},
        {"javaBox", "javaBox(v[, type]) -> userdata", "userdata",
         "把 Lua number/boolean 包成**包装类对象**（Integer/Long/Double/Boolean…）；type 可显式给 I/J/F/D/Z/B/S/C。"
         "用于 javaCallStatic/反射参数需要对象类型的场景。",
         "print(javaBox(42, \"J\"):call(\"longValue\", \"()J\"))"},
        {"javaValue", "javaValue(v) -> value", "any",
         "把 Java 对象 userdata 还原成 Lua 原生值（String/包装类→string/number；其它→toString 文本）；"
         "非 userdata 原样返回。与 javaString/javaBox 互逆。",
         "print(javaValue(javaBox(7)))"},
        {"javaGetStatic", "javaGetStatic(class, name, signature) -> value|nil,err", "any",
         "**读静态字段**（getField 对 static 字段会失败；本函数据此补上）。signature 必填（如 \"I\" / \"Ljava/lang/String;\"）。",
         "print(javaGetStatic(\"android.os.Build$VERSION\", \"SDK_INT\", \"I\"))"},
        {"javaSetStatic", "javaSetStatic(class, name, signature, value) -> true|nil,err", "boolean",
         "**写静态字段**（signature 必填；value 按 signature 转换）。",
         "print(javaSetStatic(\"com.example.Foo\", \"FLAG\", \"I\", 1))"},
        {"javaStackTrace", "javaStackTrace([maxDepth]) -> array|nil,err", "array",
         "**回溯当前线程的 Java 调用栈**（Thread.currentThread().getStackTrace()）："
         "每条 = {className, method, file, line, native, text}，返回表另附 count / text。"
         "maxDepth 默认 64、上限 256。在 artHook 回调里调用最有意义（看是谁调了被 hook 的方法）；"
         "run_lua 的脚本线程可能不是 Java 线程（栈可能为空）——需要原生栈时用 nativeBacktrace。",
         "local st = javaStackTrace(20); for _, f in ipairs(st) do print(f.className, f.method, f.file, f.line) end"},
        {"javaThreadStack", "javaThreadStack([tid][, maxDepth]) -> array|nil,err", "array",
         "**回溯任意 Java 线程的栈**（Thread.getAllStackTraces()；Android 上 Thread.getId() == Linux tid）。"
         "硬件断点命中行里的 tid 可直接传进来，补出「这条原生断点属于哪个 Java 调用链」。"
         "tid 省略/0 = 当前线程；纯 native 线程（未被 ART Attach）返回 nil,err。"
         "注意：会短暂挂起 ART 线程列表，别在热路径/高频轮询里调。",
         "local st = javaThreadStack(5149, 16); for _, f in ipairs(st) do print(f.className, f.method, f.line) end"},
        {"nativeBacktrace", "nativeBacktrace([maxDepth]) -> array|nil,err", "array",
         "**回溯当前原生（C/C++/汇编）调用栈**，每条 = {addr, module, offset, symbol, src}；"
         "src = fp（帧指针链）/ cb-lr（回调捕获的目标侧返回地址）/ unwind（.eh_frame 兜底）。"
         "**⚠ 只能在普通脚本里调**：它会为每帧建 Lua 表（= 分配），在 hook 回调里调用会崩目标——"
         "回调里请用 nativeBacktraceInto(buf)（不建表），抓到地址后再用 nativeFrame(addr) 符号化。"
         "限制：LuaJIT 汇编帧没有展开信息，普通脚本里通常只有 3 帧左右且都是 agent 自身。",
         "for i, f in ipairs(nativeBacktrace(16)) do print(i, f.module, '+0x' .. string.format('%x', f.offset), f.symbol) end"},
        {"nativeBacktraceInto", "nativeBacktraceInto(buf[, maxDepth]) -> count|nil,err", "number",
         "**回调里唯一推荐的原生栈入口**：只把返回地址写进你预分配的内存（buf[i] = 第 i 帧 uint64），"
         "**不建 Lua 表、不分配**，所以能在 hookAfter/hookCPU 回调里安全用。"
         "buf 至少 maxDepth*8 字节、必须可写（在进回调前用 ffi.new(\"uint64_t[64]\") 分配最稳）。"
         "抓完后在回调外/下个脚本用 nativeFrame(addr) 做符号化。",
         "local buf = ffi.new(\"uint64_t[64]\"); local n = nativeBacktraceInto(buf, 64); for i = 0, n - 1 do local f = nativeFrame(tonumber(buf[i])); print(i, f.module, f.symbol) end"},
        {"nativeFrame", "nativeFrame(addr) -> {addr, module, offset, symbol}|nil,err", "table",
         "把单个地址用 dladdr 解析成 {addr, module, offset, symbol}（普通脚本里调，可以分配）。"
         "配合 nativeBacktraceInto 使用。", "local f = nativeFrame(0x789bd6189c); print(f.module, f.symbol)"},
        {"hookAfter", "hookAfter(addr, fn) -> id|nil,err", "number",
         "**函数返回后**回调（arm64 跳板）：fn(ctx) 里 ctx.args[1..8] 是进入时的 x0..x7（含 this/指针参数），"
         "ctx.ret 是返回的 x0；return 一个 number 可改返回值。限制：≤8 个整数/指针参数、无栈参数、无 sret 大结构、浮点参数不支持。"
         "适合 SSL_read 之后抄 buffer。", "local id = hookAfter(addr, function(c) print(\"ret\", c.ret, \"buf\", c.args[2]) end)"},
        {"removeAfter", "removeAfter(id) -> boolean", "boolean", "卸载 hookAfter。", "removeAfter(id)"},
        {"afterHooks", "afterHooks() -> array", "array", "列出 hookAfter：{id, target}。", "for _, h in ipairs(afterHooks()) do print(h.id, hexOf(h.target)) end"},

    };
    return kDocs;
}

inline void PushApiEntry(lua_State* Ls, const LuaApiDoc& d) {
    lua_newtable(Ls);
    const char* keys[] = {"name", "sig", "ret", "desc", "example"};
    const char* vals[] = {d.name, d.sig, d.ret, d.desc, d.example};
    for (int i = 0; i < 5; i++) {
        lua_pushstring(Ls, keys[i]);
        lua_pushstring(Ls, vals[i] ? vals[i] : "");
        lua_settable(Ls, -3);
    }
}

// 给 api() 返回表用的 __tostring：一行摘要（函数名列表），方便 print(api())。
inline int Lua_ApiToString(lua_State* Ls) {
    const auto& docs = ApiDocs();
    std::string s = "ATrace Lua API (" + std::to_string(docs.size()) + " 个函数): ";
    for (size_t i = 0; i < docs.size(); i++) {
        if (i) s += ", ";
        s += docs[i].name;
    }
    s += "  —— 详情用 help() 或 api(\"函数名\")";
    lua_pushstring(Ls, s.c_str());
    return 1;
}

// 单条 api("name") 返回表的 __tostring：打印 签名 -> 返回值 + 说明。
inline int Lua_ApiEntryToString(lua_State* Ls) {
    if (!lua_istable(Ls, 1)) {
        lua_pushstring(Ls, "api entry");
        return 1;
    }
    auto field = [&](const char* k) -> std::string {
        lua_getfield(Ls, 1, k);
        const char* s = lua_tostring(Ls, -1);
        std::string v = s ? s : "";
        lua_pop(Ls, 1);
        return v;
    };
    std::string name = field("name");
    std::string sig = field("sig");
    std::string ret = field("ret");
    std::string s = name + "  " + sig;
    // sig 里一般已经写了 "-> handle"，避免重复追加
    if (sig.find("->") == std::string::npos) s += " -> " + ret;
    std::string desc = field("desc");
    if (!desc.empty()) s += "  " + desc;
    lua_pushstring(Ls, s.c_str());
    return 1;
}

// 外部 AI 反馈：70 个函数混成一坨，且 :call/:getField 等 userdata 方法根本没出现在 api() 里，
// 只能靠猜（他因此绕去手解 DEX）。这里提供程序化可读的分组清单。
inline const std::vector<std::pair<std::string, std::vector<std::string>>>& ApiGroups() {
    static const std::vector<std::pair<std::string, std::vector<std::string>>> k = {
        {"内存读写", {
            "readByte","readDword","readQword","readFloat","readDouble","readPtr",
            "readPtrHex","readPtrNum","readQwordHex","readInt32","readInt64",
            "readBytes","readString","writeByte","writeDword","writeQword","writeFloat",
            "writeDouble","writePtr","writeBytes","writeString","verify","dumpToFile","dump",
            "untag","hexOf","ptrOf","u64",
            "readU8","readI8","readU16","readI16","readU32","readI32",
            "readU64","readI64","readU64Num","readI64Num"}},
        {"模块/符号/扫描", {
            "getBase","clearbase","module_info","symbols","scan","scanRange","maps","symbol"}},
        {"Hook（native）", {
            "hookCPU","hookfunc","removehook","remove_all_hook","hooks","hook_list",
            "hookAfter","removeAfter","afterHooks"}},
        {"Java/ART", {
            "javaFindClass","javaNew","javaFields","javaCallStatic",
            "artHook","artHookAll","artUnhook","artHooks","artStatus","artVmState",
            "javaString","javaBox","javaValue","javaGetStatic","javaSetStatic",
            "javaFindClass","javaDump"}},
        {"调用栈", {
            "javaStackTrace","javaThreadStack","nativeBacktrace","nativeBacktraceInto","nativeFrame"}},
        {"异步/线程", {"call","call_stats","call_done","call_sync","msleep"}},
        {"诊断/其它", {"api","help","capabilities","whoami","self_info","regsOf","setReg"}},
    };
    return k;
}

inline const std::vector<std::pair<std::string, std::string>>& UserdataMethods() {
    // Java 对象（userdata）上的方法：用冒号调用，例如 obj:call("getName","()Ljava/lang/String;")
    static const std::vector<std::pair<std::string, std::string>> k = {
        {"obj:call(method, signature, ...)", "调用实例方法（signature 必填，JNI 描述符）"},
        {"obj:getField(name, signature)", "读实例字段（signature 必填，如 \"I\" / \"Ljava/lang/String;\"）"},
        {"obj:setField(name, signature, value)", "写实例字段（signature 必填）"},
        {"obj:className()", "返回类名"},
        {"obj:isArray()", "是否 Java 数组"},
        {"obj:len()", "数组长度（非数组返回 0）"},
        {"obj:get(i)", "数组取元素（1 起）"},
        {"obj[i]", "数组下标语法糖（1 起；*不是* Lua 的 # 长度）"},
        {"tostring(obj)", "调用 Java toString()"},
    };
    return k;
}

inline int Lua_Api(lua_State* Ls) {    const auto& docs = ApiDocs();
    if (lua_gettop(Ls) >= 1 && lua_isstring(Ls, 1)) {
        std::string want = lua_tostring(Ls, 1);
        for (const auto& d : docs) {
            if (want == d.name) {
                PushApiEntry(Ls, d);
                // 单条查询也挂 __tostring，print(api("hookfunc")) 直接可读
                lua_newtable(Ls);
                lua_pushstring(Ls, "__tostring");
                lua_pushcfunction(Ls, Lua_ApiEntryToString);
                lua_settable(Ls, -3);
                lua_setmetatable(Ls, -2);
                return 1;
            }
        }
        return luaL_error(Ls, "api: 没有名为 '%s' 的函数（用 api() 看全部）", want.c_str());
    }
    lua_newtable(Ls);
    lua_pushstring(Ls, "engine");
    lua_pushstring(Ls, "ATrace LuaJIT (Dobby)");
    lua_settable(Ls, -3);
    lua_pushstring(Ls, "notes");
    lua_newtable(Ls);
    const char* notes[] = {
        "这是 LuaJIT：ffi / bit / io / os / package 都可用；"
        "ffi.load(\"libxxx.so\") 能直接调用系统库（不需要编译扩展）",
        "hookCPU/hookfunc 的回调运行在目标线程：只读寄存器/读内存；"
        "ffi、循环、字符串拼接都会分配内存，一律用 call(function() ... end) 投递执行",
        "回调拿到的是 regs（x0-x28/sp/fp/lr），**没有 pc**；要知道函数地址用回调第 2 个参数",
        "read*/write* 会先查 /proc/self/maps：非法地址返回 nil,原因（不会崩进程）；"
        "地址参数支持 number / \"0x...\" / lightuserdata / cdata",
        "arm64 堆指针带 TBI tag（高 8 位，如 0xb4...）；read/write/hook 的地址入口"
        "会自动剥离 tag，readPtrHex 返回原始带 tag 值（需要时用 untag()）",
        "Lua 状态在目标进程内**持久**：_G 跨 run_lua 保留；只有重新注入/新 agent 才重置",
        "call() 异步且无回执；可能跑在兜底线程（不是主线程），别在里面碰 JNI/UI",
        "**call() 锁语义**：run_lua 期间全程持锁，泵线程拿不到锁，"
        "所以同一个脚本内等不到 call 的结果；只能在下一个脚本里用 call_done/call_stats 读",
        "msleep() 在脚本/回调里会一直持锁，会拖住泵；不要用它轮询 call 结果",
        "scan()/symbols() 返回的是**数组**（#r 就是命中数），另有 count/addrs(symbols) 字段；"
        "scan 按**内存原始字节序**匹配（小端机上 32 位指令要倒着写）",
        "hooks()/hook_list() 可列出所有 hook（addr/mode/hits/trampoline）；"
        "replace 模式的 hits 恒 0（仅 instrument 计数）",
        "remove_all_hook() 只卸 Lua 层 hook，不会卸 call() 的主线程泵",
        "日志最多保留最近 3000 条（绝对序号不倒退）；API 清单用 api() / help() 查",
        "**回调里 ffi.C.* 也会被硬报错拦住**（LuaJIT 的 ffi.C 成员以前拦不住、调用会直接崩；"
        "已修）。唯一逃生舱是 _G.__atrace_ffi_raw（后果自负）；"
        "回调里要做重活请用 call()/call_sync() 投递",
        "**nativeBacktrace() 会建 Lua 表 = 分配，只能在普通脚本里调**；hook 回调里必须用 "
        "nativeBacktraceInto(预分配 buf)（不建表），再用 nativeFrame(addr) 符号化",
    };
    const int nNotes = (int)(sizeof(notes) / sizeof(notes[0]));
    for (int i = 0; i < nNotes; i++) {
        lua_pushinteger(Ls, i + 1);
        lua_pushstring(Ls, notes[i]);
        lua_settable(Ls, -3);
    }
    lua_settable(Ls, -3);
    lua_pushstring(Ls, "functions");
    lua_newtable(Ls);
    for (size_t i = 0; i < docs.size(); i++) {
        PushApiEntry(Ls, docs[i]);
        lua_rawseti(Ls, -2, (lua_Integer)(i + 1));
    }
    lua_settable(Ls, -3);
    lua_pushstring(Ls, "groups");
    lua_newtable(Ls);
    {
        std::vector<std::string> assigned;
        auto push_group = [&](const char* g, const std::vector<std::string>& names) {
            lua_pushstring(Ls, g);
            lua_newtable(Ls);
            int k = 0;
            for (const auto& nm : names) { lua_pushstring(Ls, nm.c_str()); lua_rawseti(Ls, -2, ++k); }
            lua_settable(Ls, -3);
            assigned.insert(assigned.end(), names.begin(), names.end());
        };
        for (const auto& grp : ApiGroups()) push_group(grp.first.c_str(), grp.second);
        // 没归组的自动进"其它"（新增函数不会漏）
        std::vector<std::string> others;
        for (const auto& d : docs) {
            bool found = false;
            for (const auto& a2 : assigned) if (a2 == d.name) { found = true; break; }
            if (!found) others.push_back(d.name);
        }
        if (!others.empty()) push_group("其它", others);
    }
    lua_settable(Ls, -3);
    lua_pushstring(Ls, "userdata_methods");
    lua_newtable(Ls);
    {
        int k = 0;
        for (const auto& u : UserdataMethods()) {
            lua_newtable(Ls);
            lua_pushstring(Ls, "sig");  lua_pushstring(Ls, u.first.c_str());  lua_settable(Ls, -3);
            lua_pushstring(Ls, "desc"); lua_pushstring(Ls, u.second.c_str()); lua_settable(Ls, -3);
            lua_rawseti(Ls, -2, ++k);
        }
    }
    lua_settable(Ls, -3);
    // 给返回表挂 __tostring：print(api()) 输出一行可读摘要，
    // 而不是空行（旧 print 不认 table）或整张表的转储。
    lua_newtable(Ls);
    lua_pushstring(Ls, "__tostring");
    lua_pushcfunction(Ls, Lua_ApiToString);
    lua_settable(Ls, -3);
    lua_setmetatable(Ls, -2);
    return 1;
}

inline int Lua_Help(lua_State* Ls) {
    const auto& docs = ApiDocs();
    PushLog("===== ATrace Lua API（LuaJIT + Dobby）=====");
    for (const auto& d : docs) {
        // sig 里通常已经写了 "-> ret"，避免出现 "handle -> handle"
        std::string line = std::string("[Lua] ") + d.name + "  " + d.sig;
        if (std::string(d.sig).find("->") == std::string::npos) {
            line += std::string(" -> ") + d.ret;
        }
        line += std::string("  ") + d.desc;
        PushLog(line);
    }
    PushLog("[Lua] ---- 按用途分组（也可读 api().groups）----");
    for (const auto& grp : ApiGroups()) {
        std::string line = "[Lua] " + grp.first + ": ";
        for (size_t i = 0; i < grp.second.size(); ++i) {
            if (i) line += ", ";
            line += grp.second[i];
        }
        PushLog(line);
    }
    PushLog("[Lua] ---- userdata（Java 对象）方法（也可读 api().userdata_methods）----");
    for (const auto& u : UserdataMethods()) {
        PushLog("[Lua] " + u.first + "  —  " + u.second);
    }
    PushLog("[Lua] 提示：api() 返回结构化表；api(\"hookfunc\") 查单个函数");
    return 0;
}


// ---------- ArtHook（Lua 层 Java/ART hook，基于 LSPlant）----------
// 回调里拿到的是目标 Java 线程；这里会把 Java 参数转成 Lua 值，
// 用户回调返回非 nil 就覆盖 Java 返回值，返回 nil 则自动调用原方法（透传）。

struct JavaBoxCache {
    jclass str_cls = nullptr, bool_cls = nullptr, byte_cls = nullptr, short_cls = nullptr;
    jclass int_cls = nullptr, long_cls = nullptr, float_cls = nullptr, double_cls = nullptr;
    jclass char_cls = nullptr, obj_cls = nullptr;
    jmethodID bool_val = nullptr, byte_val = nullptr, short_val = nullptr, int_val = nullptr;
    jmethodID long_val = nullptr, float_val = nullptr, double_val = nullptr, char_val = nullptr;
    jmethodID bool_of = nullptr, byte_of = nullptr, short_of = nullptr, int_of = nullptr;
    jmethodID long_of = nullptr, float_of = nullptr, double_of = nullptr, char_of = nullptr;
    std::mutex mu;
    bool ready = false;
};

inline JavaBoxCache& BoxCache() { static JavaBoxCache c; return c; }

inline void EnsureBoxCache(JNIEnv* env) {
    JavaBoxCache& c = BoxCache();
    if (c.ready) return;
    std::lock_guard<std::mutex> lk(c.mu);
    if (c.ready) return;
    auto gcls = [&](const char* n) -> jclass {
        jclass k = env->FindClass(n);
        return k ? (jclass)env->NewGlobalRef(k) : nullptr;
    };
    c.str_cls = gcls("java/lang/String");
    c.obj_cls = gcls("java/lang/Object");
    c.bool_cls = gcls("java/lang/Boolean");
    c.byte_cls = gcls("java/lang/Byte");
    c.short_cls = gcls("java/lang/Short");
    c.int_cls = gcls("java/lang/Integer");
    c.long_cls = gcls("java/lang/Long");
    c.float_cls = gcls("java/lang/Float");
    c.double_cls = gcls("java/lang/Double");
    c.char_cls = gcls("java/lang/Character");
    auto gm = [&](jclass k, const char* n, const char* s) -> jmethodID {
        return k ? env->GetMethodID(k, n, s) : nullptr;
    };
    auto gs = [&](jclass k, const char* n, const char* s) -> jmethodID {
        return k ? env->GetStaticMethodID(k, n, s) : nullptr;
    };
    c.bool_val = gm(c.bool_cls, "booleanValue", "()Z");
    c.byte_val = gm(c.byte_cls, "byteValue", "()B");
    c.short_val = gm(c.short_cls, "shortValue", "()S");
    c.int_val = gm(c.int_cls, "intValue", "()I");
    c.long_val = gm(c.long_cls, "longValue", "()J");
    c.float_val = gm(c.float_cls, "floatValue", "()F");
    c.double_val = gm(c.double_cls, "doubleValue", "()D");
    c.char_val = gm(c.char_cls, "charValue", "()C");
    c.bool_of = gs(c.bool_cls, "valueOf", "(Z)Ljava/lang/Boolean;");
    c.byte_of = gs(c.byte_cls, "valueOf", "(B)Ljava/lang/Byte;");
    c.short_of = gs(c.short_cls, "valueOf", "(S)Ljava/lang/Short;");
    c.int_of = gs(c.int_cls, "valueOf", "(I)Ljava/lang/Integer;");
    c.long_of = gs(c.long_cls, "valueOf", "(J)Ljava/lang/Long;");
    c.float_of = gs(c.float_cls, "valueOf", "(F)Ljava/lang/Float;");
    c.double_of = gs(c.double_cls, "valueOf", "(D)Ljava/lang/Double;");
    c.char_of = gs(c.char_cls, "valueOf", "(C)Ljava/lang/Character;");
    c.ready = true;
}

inline int Lua_JavaObjGc(lua_State* Ls) {
    void** ud = (void**)lua_touserdata(Ls, 1);
    if (ud && *ud) {
        JNIEnv* env = atrace_arthook_env();
        if (env) env->DeleteGlobalRef((jobject)*ud);
        *ud = nullptr;
    }
    return 0;
}

inline int Lua_JavaObjToString(lua_State* Ls) {
    void** ud = (void**)lua_touserdata(Ls, 1);
    JNIEnv* env = atrace_arthook_env();
    if (!ud || !*ud || !env) { lua_pushstring(Ls, "<java obj>"); return 1; }
    jclass cls = env->GetObjectClass((jobject)*ud);
    jmethodID ts = env->GetMethodID(cls, "toString", "()Ljava/lang/String;");
    if (ts) {
        jstring js = (jstring)env->CallObjectMethod((jobject)*ud, ts);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (js) {
            const char* cs = env->GetStringUTFChars(js, nullptr);
            lua_pushstring(Ls, cs ? cs : "<java obj>");
            if (cs) env->ReleaseStringUTFChars(js, cs);
            env->DeleteLocalRef(js);
            env->DeleteLocalRef(cls);
            return 1;
        }
    }
    env->DeleteLocalRef(cls);
    lua_pushstring(Ls, "<java obj>");
    return 1;
}

inline void PushJavaValue(lua_State* Ls, JNIEnv* env, jobject obj) {
    if (!env || !obj) { lua_pushnil(Ls); return; }
    EnsureBoxCache(env);
    JavaBoxCache& c = BoxCache();
    if (c.str_cls && env->IsInstanceOf(obj, c.str_cls)) {
        const char* s = env->GetStringUTFChars((jstring)obj, nullptr);
        lua_pushstring(Ls, s ? s : "");
        if (s) env->ReleaseStringUTFChars((jstring)obj, s);
        return;
    }
    if (c.bool_cls && env->IsInstanceOf(obj, c.bool_cls)) {
        lua_pushboolean(Ls, env->CallBooleanMethod(obj, c.bool_val)); return;
    }
    if (c.byte_cls && env->IsInstanceOf(obj, c.byte_cls)) {
        lua_pushinteger(Ls, env->CallByteMethod(obj, c.byte_val)); return;
    }
    if (c.short_cls && env->IsInstanceOf(obj, c.short_cls)) {
        lua_pushinteger(Ls, env->CallShortMethod(obj, c.short_val)); return;
    }
    if (c.int_cls && env->IsInstanceOf(obj, c.int_cls)) {
        lua_pushinteger(Ls, env->CallIntMethod(obj, c.int_val)); return;
    }
    if (c.long_cls && env->IsInstanceOf(obj, c.long_cls)) {
        jlong v = env->CallLongMethod(obj, c.long_val);
        // >2^53 用十进制字符串，避免 Lua double 丢精度
        if (v > 9007199254740992LL || v < -9007199254740992LL) {
            char buf[32]; snprintf(buf, sizeof(buf), "%lld", (long long)v);
            lua_pushstring(Ls, buf);
        } else {
            lua_pushinteger(Ls, (lua_Integer)v);
        }
        return;
    }
    if (c.float_cls && env->IsInstanceOf(obj, c.float_cls)) {
        lua_pushnumber(Ls, env->CallFloatMethod(obj, c.float_val)); return;
    }
    if (c.double_cls && env->IsInstanceOf(obj, c.double_cls)) {
        lua_pushnumber(Ls, env->CallDoubleMethod(obj, c.double_val)); return;
    }
    if (c.char_cls && env->IsInstanceOf(obj, c.char_cls)) {
        lua_pushinteger(Ls, env->CallCharMethod(obj, c.char_val)); return;
    }
    // 其它对象：userdata 持 global ref，__gc 释放；tostring 调 Java toString
    void** ud = (void**)lua_newuserdata(Ls, sizeof(void*));
    *ud = env->NewGlobalRef(obj);
    luaL_getmetatable(Ls, "atrace.javaobj");
    if (lua_istable(Ls, -1)) lua_setmetatable(Ls, -2);
    else lua_pop(Ls, 1);
}

// 背景：String / 包装类型会被 PushJavaValue 自动转成 Lua 原生值，
// 于是 "hello":call(...) 会报 "attempt to call method 'call' (a nil value)"。
// 这里提供反向包装：javaString / javaBox；javaValue 把 userdata 还原成 Lua 值。
inline void PushJavaObjectAlways(lua_State* Ls, JNIEnv* env, jobject obj) {
    if (!env || !obj) { lua_pushnil(Ls); return; }
    void** ud = (void**)lua_newuserdata(Ls, sizeof(void*));
    *ud = env->NewGlobalRef(obj);
    luaL_getmetatable(Ls, "atrace.javaobj");
    if (lua_istable(Ls, -1)) lua_setmetatable(Ls, -2);
    else lua_pop(Ls, 1);
}

// javaString(s) -> userdata(java.lang.String)（可继续 :call）
inline int Lua_JavaString(lua_State* Ls) {
    size_t len = 0;
    const char* str = luaL_checklstring(Ls, 1, &len);
    JNIEnv* env = atrace_arthook_env();
    if (!env) { lua_pushnil(Ls); lua_pushstring(Ls, "未连接 JVM"); return 2; }
    jstring js = env->NewStringUTF(str ? str : "");
    if (!js) { env->ExceptionClear(); lua_pushnil(Ls); lua_pushstring(Ls, "NewStringUTF 失败"); return 2; }
    PushJavaObjectAlways(Ls, env, js);
    env->DeleteLocalRef(js);
    return 1;
}

// javaBox(v[, type]) -> userdata(包装对象)：number→Integer（整数）/Double，boolean→Boolean，string→String
// type 可显式指定：I/J/F/D/Z（如 javaBox(3,"J") 得到 Long）
inline int Lua_JavaBox(lua_State* Ls) {
    JNIEnv* env = atrace_arthook_env();
    if (!env) { lua_pushnil(Ls); lua_pushstring(Ls, "未连接 JVM"); return 2; }
    EnsureBoxCache(env);
    JavaBoxCache& c = BoxCache();
    const char* t = luaL_optstring(Ls, 2, nullptr);
    jvalue v{};
    jmethodID of = nullptr;
    jclass cls = nullptr;
    int ty = lua_type(Ls, 1);
    if (t && *t) {
        switch (t[0]) {
        case 'Z': v.z = (jboolean)lua_toboolean(Ls, 1); of = c.bool_of; cls = c.bool_cls; break;
        case 'B': v.b = (jbyte)lua_tointeger(Ls, 1);    of = c.byte_of; cls = c.byte_cls; break;
        case 'S': v.s = (jshort)lua_tointeger(Ls, 1);   of = c.short_of; cls = c.short_cls; break;
        case 'I': v.i = (jint)lua_tointeger(Ls, 1);     of = c.int_of; cls = c.int_cls; break;
        case 'J': v.j = (jlong)lua_tointeger(Ls, 1);    of = c.long_of; cls = c.long_cls; break;
        case 'F': v.f = (jfloat)lua_tonumber(Ls, 1);    of = c.float_of; cls = c.float_cls; break;
        case 'D': v.d = (jdouble)lua_tonumber(Ls, 1);   of = c.double_of; cls = c.double_cls; break;
        case 'C': v.c = (jchar)lua_tointeger(Ls, 1);    of = c.char_of; cls = c.char_cls; break;
        default:
            lua_pushnil(Ls);
            lua_pushfstring(Ls, "javaBox: 不支持的 type 描述符 '%s'（用 I/J/F/D/Z/B/S/C）", t);
            return 2;
        }
    } else if (ty == LUA_TBOOLEAN) {
        v.z = (jboolean)lua_toboolean(Ls, 1); of = c.bool_of; cls = c.bool_cls;
    } else if (ty == LUA_TNUMBER) {
        double d = lua_tonumber(Ls, 1);
        if (d == (double)(long long)d && d >= -2147483648.0 && d <= 2147483647.0) {
            v.i = (jint)d; of = c.int_of; cls = c.int_cls;
        } else {
            v.d = d; of = c.double_of; cls = c.double_cls;
        }
    } else if (ty == LUA_TSTRING) {
        return Lua_JavaString(Ls);
    } else {
        lua_pushnil(Ls);
        lua_pushstring(Ls, "javaBox: 需要 number/boolean/string（或显式 type）");
        return 2;
    }
    if (!of || !cls) { lua_pushnil(Ls); lua_pushstring(Ls, "javaBox: 包装类缓存未就绪"); return 2; }
    jobject o = env->CallStaticObjectMethodA(cls, of, &v);
    if (env->ExceptionCheck() || !o) {
        env->ExceptionClear();
        lua_pushnil(Ls); lua_pushstring(Ls, "javaBox: 构造包装对象失败"); return 2;
    }
    PushJavaObjectAlways(Ls, env, o);
    env->DeleteLocalRef(o);
    return 1;
}

// javaValue(v) -> 把 userdata 还原成 Lua 原生值；非 userdata 原样返回
inline int Lua_JavaValue(lua_State* Ls) {
    void** ud = (void**)lua_touserdata(Ls, 1);
    if (!ud || !*ud) { lua_pushvalue(Ls, 1); return 1; }
    JNIEnv* env = atrace_arthook_env();
    if (!env) { lua_pushnil(Ls); lua_pushstring(Ls, "未连接 JVM"); return 2; }
    PushJavaValue(Ls, env, (jobject)*ud);
    return 1;
}

inline jobject JavaObjectFromLua(JNIEnv* env, const char* desc, int idx) {
    if (!desc || !desc[0]) return nullptr;
    char t = desc[0];
    if (t == 'V') return nullptr;
    if (lua_isnoneornil(L, idx)) return nullptr;
    EnsureBoxCache(env);
    JavaBoxCache& c = BoxCache();
    jvalue v{};
    switch (t) {
    case 'Z': v.z = (jboolean)lua_toboolean(L, idx); return env->CallStaticObjectMethodA(c.bool_cls, c.bool_of, &v);
    case 'B': v.b = (jbyte)lua_tointeger(L, idx); return env->CallStaticObjectMethodA(c.byte_cls, c.byte_of, &v);
    case 'S': v.s = (jshort)lua_tointeger(L, idx); return env->CallStaticObjectMethodA(c.short_cls, c.short_of, &v);
    case 'I': v.i = (jint)lua_tointeger(L, idx); return env->CallStaticObjectMethodA(c.int_cls, c.int_of, &v);
    case 'J': v.j = (jlong)lua_tointeger(L, idx); return env->CallStaticObjectMethodA(c.long_cls, c.long_of, &v);
    case 'F': v.f = (jfloat)lua_tonumber(L, idx); return env->CallStaticObjectMethodA(c.float_cls, c.float_of, &v);
    case 'D': v.d = (jdouble)lua_tonumber(L, idx); return env->CallStaticObjectMethodA(c.double_cls, c.double_of, &v);
    case 'C': v.c = (jchar)lua_tointeger(L, idx); return env->CallStaticObjectMethodA(c.char_cls, c.char_of, &v);
    case 'L': {
        if (lua_isuserdata(L, idx)) {
            void** ud = (void**)lua_touserdata(L, idx);
            return (ud && *ud) ? env->NewLocalRef((jobject)*ud) : nullptr;
        }
        if (lua_isstring(L, idx)) return env->NewStringUTF(lua_tostring(L, idx));
        if (lua_isboolean(L, idx)) { v.z = (jboolean)lua_toboolean(L, idx); return env->CallStaticObjectMethodA(c.bool_cls, c.bool_of, &v); }
        if (lua_isnumber(L, idx)) { v.i = (jint)lua_tointeger(L, idx); return env->CallStaticObjectMethodA(c.int_cls, c.int_of, &v); }
        return nullptr;
    }
    default:
        if (lua_isuserdata(L, idx)) {
            void** ud = (void**)lua_touserdata(L, idx);
            return (ud && *ud) ? env->NewLocalRef((jobject)*ud) : nullptr;
        }
        return nullptr;
    }
}

inline atrace_lua_result ArtHookLuaCall(int hookId, jobjectArray args,
                                        const char* methodDesc, const char* retDesc, int isStatic) {
    atrace_lua_result out{0, nullptr};
    if (!L) return out;
    int ref = atrace_arthook_luaref(hookId);
    if (!ref) return out;
    JNIEnv* env = atrace_arthook_env();
    if (!env) return out;
    std::lock_guard<std::recursive_timed_mutex> lk(g_luaMutex);
    if (!CallbackStackOk()) {
        PushLog("[回调跳过] 目标线程剩余栈不足 64KB（避免栈溢出崩溃）：artHook 回调未执行");
        return out;
    }
    lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
    if (!lua_isfunction(L, -1)) { lua_pop(L, 1); return out; }
    lua_newtable(L);
    lua_pushstring(L, "id"); lua_pushinteger(L, hookId); lua_settable(L, -3);
    int n = (args && !isStatic) ? 0 : (args ? env->GetArrayLength(args) : 0);
    (void)n;
    lua_pushstring(L, "this");
    if (!isStatic && args && env->GetArrayLength(args) > 0) {
        jobject thiz = env->GetObjectArrayElement(args, 0);
        PushJavaValue(L, env, thiz);
        env->DeleteLocalRef(thiz);
    } else {
        lua_pushnil(L);
    }
    lua_settable(L, -3);
    lua_pushstring(L, "args");
    lua_newtable(L);
    int total = args ? env->GetArrayLength(args) : 0;
    int start = isStatic ? 0 : 1;
    for (int i = start; i < total; ++i) {
        jobject a = env->GetObjectArrayElement(args, i);
        PushJavaValue(L, env, a);
        if (a) env->DeleteLocalRef(a);
        lua_rawseti(L, -2, i - start + 1);
    }
    lua_settable(L, -3);
    lua_pushstring(L, "signature");
    lua_pushstring(L, methodDesc ? methodDesc : "");
    lua_settable(L, -3);
    // 现在 signature = 完整方法描述符（如 "(Ljava/lang/String;)V"），
    // 单独再给一个 retType = 返回类型描述符（需要判断"返什么"时用它）。
    lua_pushstring(L, "retType");
    lua_pushstring(L, retDesc ? retDesc : "");
    lua_settable(L, -3);

    PushCallbackDepthEnter();
    NativeBtScope btScope;   // P1-22：记录桥接层帧指针（nativeBacktrace 从这往外走）
    int rc = lua_pcall(L, 1, 1, 0);
    PushCallbackDepthLeave();
    if (rc != LUA_OK) {
        const char* e = lua_tostring(L, -1);
        PushLog(std::string("[ArtHook错误] ") + (e ? e : "未知错误"));
        lua_pop(L, 1);
        return out;
    }
    if (!lua_isnil(L, -1)) {
        out.value = JavaObjectFromLua(env, retDesc, lua_gettop(L));
        out.has_value = 1;
    }
    lua_pop(L, 1);
    return out;
}

inline void ArtHookLogBridge(const char* msg) {
    PushLog(std::string("[ArtHook] ") + (msg ? msg : ""));
}

// artHook(class, method [, signature], fn) -> id | nil, err
inline int Lua_ArtHook(lua_State* Ls) {
    const char* cls = luaL_checkstring(Ls, 1);
    const char* name = luaL_checkstring(Ls, 2);
    const char* sig = "";
    int fnIdx = 3;
    if (lua_isstring(Ls, 3)) { sig = lua_tostring(Ls, 3); fnIdx = 4; }
    if (!lua_isfunction(Ls, fnIdx))
        return luaL_error(Ls, "artHook(class, method[, signature], function) 需要一个回调函数");
    lua_pushvalue(Ls, fnIdx);
    int ref = luaL_ref(Ls, LUA_REGISTRYINDEX);
    char err[320] = {0};
    int id = atrace_arthook_install(cls, name, sig, ref, err, (int)sizeof(err));
    if (id <= 0) {
        luaL_unref(Ls, LUA_REGISTRYINDEX, ref);
        lua_pushnil(Ls);
        lua_pushstring(Ls, err[0] ? err : "artHook 失败");
        return 2;
    }
    lua_pushinteger(Ls, id);
    return 1;
}

//   枚举类里所有匹配 Lua 模式的方法（含重载）并逐个安装 hook。
//   返回 { [i] = {id, method, signature}, count = N, errors = {…} }。
//   namePattern 是 **Lua 模式**：精确名用 "^size$"，全部用 ".*"。native/abstract 自动跳过。
inline int Lua_ArtHookAll(lua_State* Ls) {
    const char* cls = luaL_checkstring(Ls, 1);
    const char* pat = luaL_optstring(Ls, 2, ".*");
    if (!lua_isfunction(Ls, 3))
        return luaL_error(Ls,
            "artHookAll(class, namePattern, function) 需要回调函数；"
            "namePattern 用 Lua 模式，如 \"^append$\" / \".*Size.*\" / \".*\"");
    char buf[16384] = {0};
    char err[384] = {0};
    int n = atrace_arthook_list_methods(cls, buf, (int)sizeof(buf), err, (int)sizeof(err));
    if (n < 0) { lua_pushnil(Ls); lua_pushstring(Ls, err[0] ? err : "artHookAll 枚举失败"); return 2; }

    lua_newtable(Ls);
    std::vector<std::string> errors;
    int installed = 0;
    std::string all(buf);
    size_t pos = 0;
    while (pos < all.size()) {
        size_t e = all.find('\n', pos);
        if (e == std::string::npos) e = all.size();
        std::string line = all.substr(pos, e - pos);
        pos = e + 1;
        if (line.empty()) continue;
        size_t bar = line.find('|');
        if (bar == std::string::npos) continue;
        std::string mname = line.substr(0, bar);
        std::string sig = line.substr(bar + 1);
        // 用 Lua 的 string.find 做模式匹配（保证与 Lua 模式语义一致）
        lua_getglobal(Ls, "string");
        lua_getfield(Ls, -1, "find");
        lua_remove(Ls, -2);
        lua_pushstring(Ls, mname.c_str());
        lua_pushstring(Ls, pat);
        bool matched = false;
        if (lua_pcall(Ls, 2, 2, 0) == 0) {
            matched = !lua_isnil(Ls, -2);
            lua_pop(Ls, 2);
        } else {
            lua_pop(Ls, 1);
            lua_pushnil(Ls); lua_pushstring(Ls, "namePattern 不是合法 Lua 模式"); return 2;
        }
        if (!matched) continue;
        lua_pushvalue(Ls, 3);
        int ref = luaL_ref(Ls, LUA_REGISTRYINDEX);
        char ierr[384] = {0};
        int id = atrace_arthook_install(cls, mname.c_str(), sig.c_str(), ref, ierr, (int)sizeof(ierr));
        if (id <= 0) {
            luaL_unref(Ls, LUA_REGISTRYINDEX, ref);
            errors.push_back(mname + sig + ": " + (ierr[0] ? ierr : "install failed"));
            continue;
        }
        lua_newtable(Ls);
        lua_pushstring(Ls, "id"); lua_pushinteger(Ls, id); lua_settable(Ls, -3);
        lua_pushstring(Ls, "method"); lua_pushstring(Ls, mname.c_str()); lua_settable(Ls, -3);
        lua_pushstring(Ls, "signature"); lua_pushstring(Ls, sig.c_str()); lua_settable(Ls, -3);
        lua_rawseti(Ls, -2, ++installed);
    }
    lua_pushstring(Ls, "count"); lua_pushinteger(Ls, installed); lua_settable(Ls, -3);
    if (!errors.empty()) {
        lua_pushstring(Ls, "errors");
        lua_newtable(Ls);
        for (size_t i = 0; i < errors.size(); ++i) {
            lua_pushstring(Ls, errors[i].c_str());
            lua_rawseti(Ls, -2, (lua_Integer)(i + 1));
        }
        lua_settable(Ls, -3);
    }
    if (installed == 0) {
        lua_pushnil(Ls);
        lua_pushfstring(Ls, "没有匹配 \"%s\" 且可 hook 的方法（native/abstract 已跳过）", pat);
        return 2;
    }
    return 1;
}

inline int Lua_ArtUnhook(lua_State* Ls) {
    int id = (int)luaL_checkinteger(Ls, 1);
    int ref = 0;
    bool ok = atrace_arthook_unhook(id, &ref) != 0;
    if (ref) luaL_unref(Ls, LUA_REGISTRYINDEX, ref);
    lua_pushboolean(Ls, ok);
    if (!ok) lua_pushstring(Ls, "artUnhook: 未找到该 hook id（或 lsplant::UnHook 失败）");
    return ok ? 1 : 2;
}

inline int Lua_ArtHooks(lua_State* Ls) {
    char buf[8192];
    int n = atrace_arthook_list(buf, (int)sizeof(buf));
    lua_newtable(Ls);
    std::string s(buf, n > 0 ? (size_t)(n < (int)sizeof(buf) ? n : (int)sizeof(buf)) : 0);
    size_t pos = 0, idx = 1;
    while (pos < s.size()) {
        size_t e = s.find('\n', pos);
        if (e == std::string::npos) e = s.size();
        std::string line = s.substr(pos, e - pos);
        pos = e + 1;
        if (line.empty()) continue;
        std::vector<std::string> f;
        size_t p = 0;
        while (true) {
            size_t q = line.find('|', p);
            if (q == std::string::npos) { f.push_back(line.substr(p)); break; }
            f.push_back(line.substr(p, q - p));
            p = q + 1;
        }
        if (f.size() < 5) continue;
        lua_newtable(Ls);
        auto set = [&](const char* k, const char* v) {
            lua_pushstring(Ls, k); lua_pushstring(Ls, v ? v : ""); lua_settable(Ls, -3);
        };
        lua_pushstring(Ls, "id"); lua_pushinteger(Ls, (lua_Integer)std::strtol(f[0].c_str(), nullptr, 10)); lua_settable(Ls, -3);
        set("class", f[1].c_str());
        set("method", f[2].c_str());
        set("signature", f[3].c_str());
        set("mode", f[4].c_str());
        if (f.size() >= 7) {
            unsigned long long hits = std::strtoull(f[5].c_str(), nullptr, 10);
            unsigned long long instal = std::strtoull(f[6].c_str(), nullptr, 10);
            lua_pushstring(Ls, "hits"); lua_pushinteger(Ls, (lua_Integer)hits); lua_settable(Ls, -3);
            unsigned long long now = (unsigned long long)std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            lua_pushstring(Ls, "age_ms");
            lua_pushinteger(Ls, (lua_Integer)(now > instal ? now - instal : 0));
            lua_settable(Ls, -3);
        }
        lua_rawseti(Ls, -2, (lua_Integer)idx++);
    }
    return 1;
}

inline int Lua_ArtStatus(lua_State* Ls) {
    std::string s = atrace_arthook_ready() ? "ready（LSPlant 已初始化）" : "not initialized（首次 artHook 时自动初始化）";
    lua_pushstring(Ls, s.c_str());
    return 1;
}

inline void SetJavaVM(JavaVM* vm) { atrace_arthook_set_javavm(vm); }
// ---------- Java 对象 userdata 的方法（:call / :getField / :setField 等）----------
inline void SplitParams(const char* desc, std::vector<std::string>& out) {
    out.clear();
    if (!desc || desc[0] != '(') return;
    const char* p = desc + 1;
    while (*p && *p != ')') {
        const char* st = p;
        while (*p == '[') ++p;
        if (*p == 'L') {
            while (*p && *p != ';') ++p;
            if (*p == ';') ++p;
        } else if (*p) {
            ++p;
        }
        out.emplace_back(st, (size_t)(p - st));
    }
}

inline jobjectArray BuildJavaArgs(JNIEnv* env, const std::vector<std::string>& types,
                                  int firstIdx) {
    jclass obj_cls = env->FindClass("java/lang/Object");
    jobjectArray arr = env->NewObjectArray((jsize)types.size(), obj_cls, nullptr);
    if (!arr) return nullptr;
    for (size_t i = 0; i < types.size(); ++i) {
        jobject v = JavaObjectFromLua(env, types[i].c_str(), firstIdx + (int)i);
        env->SetObjectArrayElement(arr, (jsize)i, v);
        if (v) env->DeleteLocalRef(v);
    }
    return arr;
}

inline jobject SelfObject(lua_State* Ls) {
    void** ud = (void**)lua_touserdata(Ls, 1);
    return (ud && *ud) ? (jobject)*ud : nullptr;
}

inline int Lua_JavaObjCall(lua_State* Ls) {
    jobject self = SelfObject(Ls);
    if (!self) return luaL_error(Ls, "javaobj:call: 无效对象");
    const char* name = luaL_checkstring(Ls, 2);
    if (!lua_isstring(Ls, 3))
        return luaL_error(Ls,
            "obj:call 需要第 3 个参数（JNI 方法签名），例如：\n"
            "  obj:call(\"getName\", \"()Ljava/lang/String;\")\n"
            "  obj:call(\"charAt\", \"(I)C\", 0)\n"
            "提示：签名从类的 javap/反编译里抄，格式 (参数类型)返回类型");
    const char* sig = luaL_checkstring(Ls, 3);
    JNIEnv* env = atrace_arthook_env();
    if (!env) { lua_pushnil(Ls); lua_pushstring(Ls, "未连接 JVM"); return 2; }
    std::vector<std::string> types;
    SplitParams(sig, types);
    jobjectArray args = BuildJavaArgs(env, types, 4);
    char err[256] = {0};
    jobject ret = atrace_java_call(self, name, sig, args, err, (int)sizeof(err));
    if (args) env->DeleteLocalRef(args);
    if (err[0]) { lua_pushnil(Ls); lua_pushstring(Ls, err); return 2; }
    PushJavaValue(Ls, env, ret);
    if (ret) env->DeleteLocalRef(ret);
    return 1;
}

inline int Lua_JavaObjGetField(lua_State* Ls) {
    jobject self = SelfObject(Ls);
    if (!self) return luaL_error(Ls, "javaobj:getField: 无效对象");
    const char* name = luaL_checkstring(Ls, 2);
    if (!lua_isstring(Ls, 3))
        return luaL_error(Ls,
            "obj:getField 需要第 3 个参数（字段类型描述符），例如：\n"
            "  obj:getField(\"mCount\", \"I\")\n"
            "  obj:getField(\"name\", \"Ljava/lang/String;\")\n"
            "提示：javaFields(obj) 会列出每个字段的类型描述符；静态字段用 javaGetStatic(cls,name,sig)");
    const char* sig = luaL_checkstring(Ls, 3);
    JNIEnv* env = atrace_arthook_env();
    if (!env) { lua_pushnil(Ls); lua_pushstring(Ls, "未连接 JVM"); return 2; }
    char err[256] = {0};
    jobject v = atrace_java_get_field(self, name, sig, err, (int)sizeof(err));
    if (err[0]) {
        // javaFields 里能看到但 getField 静默 nil）。
        char cls[256] = {0};
        if (atrace_java_class_name(self, cls, (int)sizeof(cls)) > 0 && cls[0]) {
            char err2[256] = {0};
            jobject sv = atrace_java_get_static_field(cls, name, sig, err2, (int)sizeof(err2));
            if (!err2[0]) {
                PushJavaValue(Ls, env, sv);
                if (sv) env->DeleteLocalRef(sv);
                return 1;
            }
        }
        lua_pushnil(Ls); lua_pushstring(Ls, err); return 2;
    }
    PushJavaValue(Ls, env, v);
    if (v) env->DeleteLocalRef(v);
    return 1;
}

inline int Lua_JavaObjSetField(lua_State* Ls) {
    jobject self = SelfObject(Ls);
    if (!self) return luaL_error(Ls, "javaobj:setField: 无效对象");
    const char* name = luaL_checkstring(Ls, 2);
    if (!lua_isstring(Ls, 3))
        return luaL_error(Ls,
            "obj:setField 需要第 3 个参数（字段类型描述符），例如：\n"
            "  obj:setField(\"mCount\", \"I\", 42)\n"
            "  obj:setField(\"name\", \"Ljava/lang/String;\", \"hi\")\n"
            "提示：javaFields(obj) 会列出字段类型；静态字段用 javaSetStatic(cls,name,sig,value)");
    const char* sig = luaL_checkstring(Ls, 3);
    JNIEnv* env = atrace_arthook_env();
    if (!env) { lua_pushboolean(Ls, 0); lua_pushstring(Ls, "未连接 JVM"); return 2; }
    jobject v = JavaObjectFromLua(env, sig, 4);
    char err[256] = {0};
    int ok = atrace_java_set_field(self, name, sig, v, err, (int)sizeof(err));
    if (!ok) {
        // P0-10：回退写静态字段
        char cls[256] = {0};
        if (atrace_java_class_name(self, cls, (int)sizeof(cls)) > 0 && cls[0]) {
            char err2[256] = {0};
            ok = atrace_java_set_static_field(cls, name, sig, v, err2, (int)sizeof(err2));
            if (!ok && err2[0]) { if (v) env->DeleteLocalRef(v); lua_pushboolean(Ls, 0); lua_pushstring(Ls, err2); return 2; }
        }
    }
    if (v) env->DeleteLocalRef(v);
    lua_pushboolean(Ls, ok);
    if (!ok) { lua_pushstring(Ls, err[0] ? err : "setField failed"); return 2; }
    return 1;
}

inline int Lua_JavaObjClassName(lua_State* Ls) {
    jobject self = SelfObject(Ls);
    if (!self) return luaL_error(Ls, "javaobj:className: 无效对象");
    char buf[256] = {0};
    if (!atrace_java_class_name(self, buf, (int)sizeof(buf))) { lua_pushnil(Ls); return 1; }
    lua_pushstring(Ls, buf);
    return 1;
}

inline int Lua_JavaObjLen(lua_State* Ls) {
    jobject self = SelfObject(Ls);
    if (!self) { lua_pushinteger(Ls, 0); return 1; }
    char desc[64] = {0};
    int n = atrace_java_array_len(self, desc, (int)sizeof(desc));
    if (n < 0) { lua_pushnil(Ls); lua_pushstring(Ls, "不是数组"); return 2; }
    lua_pushinteger(Ls, (lua_Integer)n);
    return 1;
}

inline int Lua_JavaObjGetAt(lua_State* Ls) {
    jobject self = SelfObject(Ls);
    if (!self) return luaL_error(Ls, "javaobj:get: 无效对象");
    int idx = (int)luaL_checkinteger(Ls, 2);
    JNIEnv* env = atrace_arthook_env();
    if (!env) { lua_pushnil(Ls); lua_pushstring(Ls, "未连接 JVM"); return 2; }
    char err[256] = {0};
    jobject v = atrace_java_array_get(self, idx, err, (int)sizeof(err));
    if (err[0]) { lua_pushnil(Ls); lua_pushstring(Ls, err); return 2; }
    PushJavaValue(Ls, env, v);
    if (v) env->DeleteLocalRef(v);
    return 1;
}

inline int Lua_JavaObjIsArray(lua_State* Ls) {
    jobject self = SelfObject(Ls);
    lua_pushboolean(Ls, self && atrace_java_is_array(self));
    return 1;
}

inline int Lua_JavaObjIndex(lua_State* Ls) {
    // 数字 key：数组下标（arr[1]）
    if (lua_type(Ls, 2) == LUA_TNUMBER) {
        jobject self = SelfObject(Ls);
        if (!self) { lua_pushnil(Ls); return 1; }
        JNIEnv* env = atrace_arthook_env();
        if (!env) { lua_pushnil(Ls); return 1; }
        char err[256] = {0};
        jobject v = atrace_java_array_get(self, (int)lua_tointeger(Ls, 2), err, (int)sizeof(err));
        PushJavaValue(Ls, env, v);
        if (v) env->DeleteLocalRef(v);
        return 1;
    }
    const char* key = lua_tostring(Ls, 2);
    if (!key) { lua_pushnil(Ls); return 1; }
    if (!strcmp(key, "call")) lua_pushcfunction(Ls, Lua_JavaObjCall);
    else if (!strcmp(key, "getField")) lua_pushcfunction(Ls, Lua_JavaObjGetField);
    else if (!strcmp(key, "setField")) lua_pushcfunction(Ls, Lua_JavaObjSetField);
    else if (!strcmp(key, "className")) lua_pushcfunction(Ls, Lua_JavaObjClassName);
    else if (!strcmp(key, "len") || !strcmp(key, "length")) lua_pushcfunction(Ls, Lua_JavaObjLen);
    else if (!strcmp(key, "get")) lua_pushcfunction(Ls, Lua_JavaObjGetAt);
    else if (!strcmp(key, "isArray")) lua_pushcfunction(Ls, Lua_JavaObjIsArray);
    else if (!strcmp(key, "fields")) lua_pushcfunction(Ls, Lua_JavaFields);
    else if (!strcmp(key, "toString") || !strcmp(key, "__tostring")) lua_pushcfunction(Ls, Lua_JavaObjToString);
    else lua_pushnil(Ls);
    return 1;
}

// javaNew(class, signature, ...) -> userdata | nil, err
inline int Lua_JavaNew(lua_State* Ls) {
    const char* cls = luaL_checkstring(Ls, 1);
    const char* sig = luaL_checkstring(Ls, 2);
    JNIEnv* env = atrace_arthook_env();
    if (!env) { lua_pushnil(Ls); lua_pushstring(Ls, "未连接 JVM"); return 2; }
    std::vector<std::string> types;
    SplitParams(sig, types);
    jobjectArray args = BuildJavaArgs(env, types, 3);
    char err[256] = {0};
    jobject obj = atrace_java_new(cls, sig, args, err, (int)sizeof(err));
    if (args) env->DeleteLocalRef(args);
    if (err[0] || !obj) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, err[0] ? err : "javaNew failed");
        return 2;
    }
    PushJavaValue(Ls, env, obj);
    env->DeleteLocalRef(obj);
    return 1;
}




// ---------- P1-11：maps() / scanRange()（任意可读区间扫描）----------
struct SelfMap {
    uintptr_t start = 0, end = 0;
    unsigned prot = 0;
    std::string perms;
    std::string path;
};

inline bool ReadSelfMaps(std::vector<SelfMap>& out) {
    out.clear();
    FILE* f = fopen("/proc/self/maps", "re");
    if (!f) return false;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        unsigned long long s = 0, e = 0, off = 0;
        unsigned long long ino = 0;
        char perms[8] = {0}, dev[16] = {0};
        if (sscanf(line, "%llx-%llx %7s %llx %15s %llu", &s, &e, perms, &off, dev, &ino) != 6) continue;
        SelfMap m;
        m.start = (uintptr_t)s;
        m.end = (uintptr_t)e;
        m.perms = perms;
        unsigned p = 0;
        if (perms[0] == 'r') p |= PROT_READ;
        if (perms[1] == 'w') p |= PROT_WRITE;
        if (perms[2] == 'x') p |= PROT_EXEC;
        m.prot = p;
        char* pathp = strchr(line, '/');
        if (pathp) {
            std::string path(pathp);
            while (!path.empty() && (path.back() == '\n' || path.back() == '\r')) path.pop_back();
            m.path = path;
        } else {
            // 匿名段：保留 [anon:...] 之类的标签（没有 '/' 时取第 6 字段）
            char* p2 = line;
            int fields = 0;
            while (*p2 && fields < 5) {
                while (*p2 && *p2 != ' ') ++p2;
                while (*p2 == ' ') ++p2;
                ++fields;
            }
            if (*p2) {
                std::string path(p2);
                while (!path.empty() && (path.back() == '\n' || path.back() == '\r')) path.pop_back();
                m.path = path;
            }
        }
        out.push_back(std::move(m));
    }
    fclose(f);
    return true;
}

// 检查 [start,end) 全部落在可读映射里（逐段推进）
inline bool RangeReadable(const std::vector<SelfMap>& maps, uintptr_t start, uintptr_t end) {
    uintptr_t cur = start;
    for (const auto& m : maps) {
        if (m.end <= cur) continue;
        if (m.start > cur) return false;
        if (!(m.prot & PROT_READ)) return false;
        if (m.end >= end) return true;
        cur = m.end;
    }
    return false;
}

inline int Lua_Maps(lua_State* Ls) {
    std::vector<SelfMap> maps;
    if (!ReadSelfMaps(maps)) {
        lua_pushnil(Ls); lua_pushstring(Ls, "读取 /proc/self/maps 失败"); return 2;
    }
    lua_newtable(Ls);
    int n = 0;
    for (const auto& m : maps) {
        lua_newtable(Ls);
        auto seti = [&](const char* k, lua_Integer v) {
            lua_pushstring(Ls, k); lua_pushinteger(Ls, v); lua_settable(Ls, -3);
        };
        auto sets = [&](const char* k, const char* v) {
            lua_pushstring(Ls, k); lua_pushstring(Ls, v ? v : ""); lua_settable(Ls, -3);
        };
        seti("start", (lua_Integer)m.start);
        seti("stop", (lua_Integer)m.end);
        seti("size", (lua_Integer)(m.end - m.start));
        sets("perms", m.perms.c_str());
        sets("path", m.path.c_str());
        lua_pushstring(Ls, "read");  lua_pushboolean(Ls, (m.prot & PROT_READ) != 0);  lua_settable(Ls, -3);
        lua_pushstring(Ls, "write"); lua_pushboolean(Ls, (m.prot & PROT_WRITE) != 0); lua_settable(Ls, -3);
        lua_pushstring(Ls, "exec");  lua_pushboolean(Ls, (m.prot & PROT_EXEC) != 0);  lua_settable(Ls, -3);
        lua_rawseti(Ls, -2, ++n);
    }
    return 1;
}

// 解析 "90000008"/"90 00 ?? 08" + 可选 mask；?? 视为通配
inline bool ParsePatternMask(const char* hexstr, const char* maskstr,
                             std::vector<uint8_t>& pat, std::vector<uint8_t>& mask) {
    pat.clear();
    mask.clear();
    if (!hexstr) return false;
    auto hexv = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (const char* p = hexstr; *p;) {
        while (*p == ' ' || *p == '\t' || *p == '_' || *p == '-') ++p;
        if (!*p) break;
        if (p[0] == '?' && p[1] == '?') { pat.push_back(0); mask.push_back(0); p += 2; continue; }
        int hi = hexv(p[0]);
        int lo = p[1] ? hexv(p[1]) : -1;
        if (hi < 0 || lo < 0) return false;
        pat.push_back((uint8_t)((hi << 4) | lo));
        mask.push_back(0xFF);
        p += 2;
    }
    if (pat.empty()) return false;
    if (maskstr && *maskstr) {
        std::vector<uint8_t> mv;
        if (!ParseHexBytes(maskstr, mv) || mv.size() != pat.size()) return false;
        for (size_t i = 0; i < mv.size(); ++i) mask[i] = mv[i];
    }
    return true;
}

// 在 hay[0..hlen) 里找第一个满足 pat/mask 的起点（mask 0xFF = 必须匹配，其它按位与）。
// 返回起点下标；未找到返回 SIZE_MAX。
//
// 实测 16MB 要 0.45s（~35MB/s），比纯 Lua string.find 还慢 80 倍。
// 现在先挑一个「全掩码字节」当锚点，用 memchr 一次跳过大量不可能的位置，
// 只对锚点命中的位置做完整校验。
inline size_t FindMaskedPattern(const uint8_t* hay, size_t hlen,
                                const uint8_t* pat, const uint8_t* mask, size_t plen) {
    if (plen == 0 || hlen < plen) return SIZE_MAX;
    const size_t limit = hlen - plen + 1;   // 合法的起点范围
    // 锚点选择：优先挑"全掩码且不是 0x00/0xFF"的字节——堆里 0x00/0xFF 太常见，
    // 用它们当锚点会让 memchr 每次都命中一大片，退化回逐字节。
    size_t anchor = plen;
    for (size_t i = 0; i < plen; ++i) {
        if (mask[i] == 0xFF && pat[i] != 0x00 && pat[i] != 0xFF) { anchor = i; break; }
    }
    if (anchor == plen) {
        for (size_t i = 0; i < plen; ++i) {
            if (mask[i] == 0xFF) { anchor = i; break; }
        }
    }
    if (anchor == plen) return 0;   // 模式全是通配：第一个位置就满足
    const uint8_t want = pat[anchor];
    size_t i = 0;
    while (i < limit) {
        const uint8_t* q = (const uint8_t*)memchr(hay + i + anchor, want, limit - i);
        if (!q) return SIZE_MAX;
        i = (size_t)(q - hay) - anchor;      // 候选起点
        bool ok = true;
        for (size_t k = 0; k < plen; ++k) {
            if ((hay[i + k] & mask[k]) != (pat[k] & mask[k])) { ok = false; break; }
        }
        if (ok) return i;
        ++i;
    }
    return SIZE_MAX;
}

inline int Lua_ScanRange(lua_State* Ls) {
    uintptr_t start = UntagAddr(CheckAddr(Ls, 1));
    uintptr_t end = UntagAddr(CheckAddr(Ls, 2));
    const char* hexstr = luaL_checkstring(Ls, 3);
    const char* maskstr = luaL_optstring(Ls, 4, nullptr);
    std::vector<uint8_t> pat, mask;
    if (!ParsePatternMask(hexstr, maskstr, pat, mask)) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, "hex/mask 解析失败（示例：\"90000008\" 或 \"90 00 ?? 08\"）");
        return 2;
    }
    if (end <= start) { lua_pushnil(Ls); lua_pushstring(Ls, "end 必须大于 start"); return 2; }
    if (end - start > (uintptr_t)(1ull << 32)) {
        lua_pushnil(Ls); lua_pushstring(Ls, "单次扫描区间不能超过 4GB"); return 2;
    }
    std::vector<SelfMap> maps;
    if (!ReadSelfMaps(maps)) { lua_pushnil(Ls); lua_pushstring(Ls, "读取 maps 失败"); return 2; }
    if (!RangeReadable(maps, start, end)) {
        lua_pushnil(Ls); lua_pushstring(Ls, "区间不可读（含未映射/不可读段），用 maps() 查"); return 2;
    }
    constexpr size_t kMaxHits = 4096;
    constexpr size_t kChunk = 1u << 20;   // 1MB
    const size_t plen = pat.size();
    const uint8_t* patp = pat.data();
    const uint8_t* maskp = mask.data();
    lua_newtable(Ls);
    size_t hits = 0;
    uintptr_t pos = start;
    // 直接在映射上扫（省掉每块一次 1MB 拷贝，吞吐接近 memchr 本身）。
    while (pos < end) {
        size_t n = (size_t)((end - pos) > kChunk ? kChunk : (end - pos));
        const uint8_t* base = (const uint8_t*)pos;
        if (n >= plen) {
            size_t off = 0;
            while (off + plen <= n) {
                size_t r = FindMaskedPattern(base + off, n - off, patp, maskp, plen);
                if (r == SIZE_MAX) break;
                size_t hit = off + r;
                if (hits < kMaxHits) {
                    lua_pushinteger(Ls, (lua_Integer)(pos + hit));
                    lua_rawseti(Ls, -2, (int)hits + 1);
                }
                ++hits;
                off = hit + 1;   // 允许重叠命中（与原实现一致）
            }
        }
        if (n < plen) break;
        pos += n - (plen - 1);   // 重叠 pattern-1 字节
        if (n < kChunk) break;
    }
    int arrIdx = lua_gettop(Ls);
    size_t stored = hits < kMaxHits ? hits : kMaxHits;
    lua_newtable(Ls);
    for (size_t i = 1; i <= stored; ++i) {
        lua_rawgeti(Ls, arrIdx, (int)i);
        lua_rawseti(Ls, -2, (int)i);
    }
    lua_pushstring(Ls, "addrs"); lua_pushvalue(Ls, arrIdx); lua_settable(Ls, -3);
    lua_pushstring(Ls, "count"); lua_pushinteger(Ls, (lua_Integer)hits); lua_settable(Ls, -3);
    lua_pushstring(Ls, "truncated"); lua_pushboolean(Ls, hits > kMaxHits); lua_settable(Ls, -3);
    return 1;
}

// ---------- P2-17 symbol(name[, module]) ----------
inline bool FindSymbolExactInModule(const char* module, const char* name, uintptr_t* out) {
    ModInfo mi;
    if (!GetModInfo(module, mi)) return false;
    DynVals d;
    if (!ReadDynVals(mi, d)) return false;
    uint32_t total = SymCount(d);
    if (total == 0 || total > 1000000u) return false;
    const Elf64_Sym* syms = (const Elf64_Sym*)d.symtab;
    const char* strtab = (const char*)d.strtab;
    for (uint32_t i = 1; i < total; ++i) {
        if (syms[i].st_name == 0) continue;
        if (d.strsz && (size_t)syms[i].st_name >= d.strsz) continue;
        const char* nm = strtab + syms[i].st_name;
        if (!nm || strcmp(nm, name) != 0) continue;
        if (syms[i].st_value == 0) continue;
        *out = mi.base + (uintptr_t)syms[i].st_value;
        return true;
    }
    return false;
}

inline int Lua_Symbol(lua_State* Ls) {
    const char* name = luaL_checkstring(Ls, 1);
    const char* module = luaL_optstring(Ls, 2, nullptr);
    if (name[0] == 0) { lua_pushnil(Ls); lua_pushstring(Ls, "symbol 名为空"); return 2; }
    auto looks_like_module = [](const char* s) -> bool {
        if (!s || !*s) return false;
        return strstr(s, ".so") != nullptr || strchr(s, '/') != nullptr;
    };
    // 常见误用：symbol("libc.so", "getpid") 把参数写反了。旧实现会静默返回 nil，
    if (module && *module && looks_like_module(name) && !looks_like_module(module)) {
        lua_pushnil(Ls);
        lua_pushfstring(Ls,
            "参数顺序反了：用法是 symbol(符号名[, 模块名])，例如 symbol(\"getpid\", \"libc.so\")；"
            "你传的是 symbol(\"%s\", \"%s\")", name, module);
        return 2;
    }
    uintptr_t addr = 0;
    if (module && *module) {
        // 先做一次"模块是否加载"检查：旧实现只会报"模块 X 里没有符号 Y"，
        // 分不清是模块没加载、还是符号真的不存在。
        ModInfo mi;
        if (!GetModInfo(module, mi)) {
            lua_pushnil(Ls);
            lua_pushfstring(Ls,
                "模块未加载: %s（用法 symbol(符号名[, 模块名])；模块名可用模块列表里的短名或全路径）",
                module);
            return 2;
        }
        if (!FindSymbolExactInModule(module, name, &addr)) {
            lua_pushnil(Ls);
            lua_pushfstring(Ls, "模块 %s 里没有符号 %s", module, name);
            return 2;
        }
        lua_pushinteger(Ls, (lua_Integer)addr);
        return 1;
    }
    // 先查全局导出（dlsym），再逐个已加载模块查 dynsym
    void* p = dlsym(RTLD_DEFAULT, name);
    if (p) { lua_pushinteger(Ls, (lua_Integer)(uintptr_t)p); return 1; }
    std::vector<SelfMap> maps;
    if (ReadSelfMaps(maps)) {
        std::set<std::string> tried;
        for (const auto& m : maps) {
            if (m.path.empty() || m.path[0] != '/') continue;
            if (m.path.find(".so") == std::string::npos) continue;
            if (!tried.insert(m.path).second) continue;
            if (FindSymbolExactInModule(m.path.c_str(), name, &addr)) {
                lua_pushinteger(Ls, (lua_Integer)addr);
                return 1;
            }
        }
    }
    lua_pushnil(Ls);
    lua_pushfstring(Ls, "找不到符号 %s（可传第二参数指定模块）", name);
    return 2;
}

// ---------- P0-7 verify(addr, hex) ----------
inline int Lua_Verify(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    const char* hexstr = luaL_checkstring(Ls, 2);
    std::vector<uint8_t> pat, mask;
    if (!ParsePatternMask(hexstr, luaL_optstring(Ls, 3, nullptr), pat, mask)) {
        lua_pushnil(Ls); lua_pushstring(Ls, "hex 解析失败"); return 2;
    }
    std::string why;
    if (const char* bad = CheckRange(addr, pat.size(), false, why)) {
        lua_pushnil(Ls); lua_pushstring(Ls, bad); return 2;
    }
    const uint8_t* p = (const uint8_t*)addr;
    for (size_t i = 0; i < pat.size(); ++i) {
        uint8_t mk = mask[i];
        if ((p[i] & mk) != (pat[i] & mk)) {
            lua_pushboolean(Ls, 0);
            lua_pushinteger(Ls, (lua_Integer)i);
            lua_pushfstring(Ls, "第 %d 字节不匹配：期望 %02X，实际 %02X", (int)i, pat[i], p[i]);
            return 3;
        }
    }
    lua_pushboolean(Ls, 1);
    return 1;
}

// ---------- P1-14 dumpToFile(addr, len, path) ----------
inline int Lua_DumpToFile(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    size_t len = (size_t)luaL_checkinteger(Ls, 2);
    const char* path = luaL_checkstring(Ls, 3);
    if (len == 0 || len > (256u << 20)) {
        lua_pushnil(Ls); lua_pushstring(Ls, "len 必须在 1..256MB"); return 2;
    }
    std::string why;
    if (const char* bad = CheckRange(addr, len, false, why)) {
        lua_pushnil(Ls); lua_pushstring(Ls, bad); return 2;
    }
    FILE* f = fopen(path, "wb");
    if (!f) {
        lua_pushnil(Ls);
        lua_pushfstring(Ls, "打不开 %s（目标进程对该路径没有写权限？换 /data/local/tmp 或 App 可写目录）", path);
        return 2;
    }
    size_t n = fwrite((const void*)addr, 1, len, f);
    int err = ferror(f);
    fclose(f);
    if (n != len || err) {
        lua_pushnil(Ls);
        lua_pushfstring(Ls, "写入不完整 %zu/%zu", n, len);
        return 2;
    }
    lua_pushboolean(Ls, 1);
    lua_pushinteger(Ls, (lua_Integer)n);
    return 2;
}

// ---------- P2-20 dump(value[, depth]) ----------
inline void DumpValue(lua_State* Ls, int idx, int depth, int maxDepth,
                      const std::string& indent, const std::string& label, int* lines) {
    if (*lines > 400) return;
    int t = lua_type(Ls, idx);
    if (t == LUA_TTABLE && depth < maxDepth) {
        PushLog(indent + label + "{");
        ++(*lines);
        int absIdx = (idx > 0) ? idx : (lua_gettop(Ls) + idx + 1);
        lua_pushnil(Ls);
        int shown = 0;
        while (lua_next(Ls, absIdx) != 0) {
            std::string key;
            if (lua_type(Ls, -2) == LUA_TSTRING) key = lua_tostring(Ls, -2);
            else key = std::to_string((long long)lua_tointeger(Ls, -2));
            DumpValue(Ls, lua_gettop(Ls), depth + 1, maxDepth,
                      indent + "  ", key + " = ", lines);
            lua_pop(Ls, 1);
            if (++shown >= 64) { PushLog(indent + "  ...(truncated)"); break; }
        }
        PushLog(indent + "}");
        ++(*lines);
        return;
    }
    std::string line = indent + label;
    switch (t) {
    case LUA_TNIL: line += "nil"; break;
    case LUA_TBOOLEAN: line += (lua_toboolean(Ls, idx) ? "true" : "false"); break;
    case LUA_TNUMBER: line += std::to_string((long long)lua_tointeger(Ls, idx)); break;
    case LUA_TSTRING: line += std::string("\"") + lua_tostring(Ls, idx) + "\""; break;
    case LUA_TTABLE: line += "{...}"; break;
    default:
        line += lua_typename(Ls, t);
        if (lua_isuserdata(Ls, idx) || luaL_getmetafield(Ls, idx, "__tostring")) {
            // 注意：luaL_getmetafield 成功时已把函数压栈
            if (lua_isfunction(Ls, -1)) {
                lua_pushvalue(Ls, idx);
                if (lua_pcall(Ls, 1, 1, 0) == LUA_OK) {
                    const char* s = lua_tostring(Ls, -1);
                    if (s) line = indent + label + s;
                }
                lua_pop(Ls, 1);
            } else {
                lua_pop(Ls, 1);
            }
        }
        break;
    }
    PushLog(line);
    ++(*lines);
}

inline int Lua_Dump(lua_State* Ls) {
    int maxDepth = luaL_optinteger(Ls, 2, 2);
    if (maxDepth < 1) maxDepth = 1;
    if (maxDepth > 6) maxDepth = 6;
    int lines = 0;
    DumpValue(Ls, 1, 0, maxDepth, "", "", &lines);
    lua_pushinteger(Ls, lines);
    return 1;
}

// ---------- P1-8 javaFields(obj[, includeSuper]) ----------
inline int Lua_ArtVmState(lua_State* Ls) {
    char buf[1024] = {0};
    int n = atrace_arthook_vm_state(buf, (int)sizeof(buf));
    if (n <= 0) { lua_pushstring(Ls, "（无法读取 VM 状态）"); return 1; }
    lua_pushlstring(Ls, buf, (size_t)(n < (int)sizeof(buf) ? n : (int)sizeof(buf) - 1));
    return 1;
}

inline int Lua_JavaFields(lua_State* Ls) {
    void** ud = (void**)lua_touserdata(Ls, 1);
    if (!ud || !*ud) return luaL_error(Ls, "javaFields: 参数必须是 Java 对象 userdata");
    bool includeSuper = lua_toboolean(Ls, 2) != 0;
    static std::vector<char> buf(256 * 1024);
    std::fill(buf.begin(), buf.end(), 0);
    int n = atrace_java_fields((jobject)*ud, includeSuper ? 1 : 0, buf.data(), (int)buf.size());
    if (n < 0) { lua_pushnil(Ls); lua_pushstring(Ls, "读取字段失败（对象无效或 JNI 异常）"); return 2; }
    (void)n;   // n>=0：out 是 NUL 结尾的 name|desc|value 行（空对象时为空表）
    lua_newtable(Ls);
    int idx = 0;
    std::string all(buf.data());
    size_t pos = 0;
    while (pos < all.size()) {
        size_t e = all.find('\n', pos);
        if (e == std::string::npos) e = all.size();
        std::string line = all.substr(pos, e - pos);
        pos = e + 1;
        if (line.empty()) continue;
        size_t p1 = line.find('|');
        size_t p2 = (p1 == std::string::npos) ? std::string::npos : line.find('|', p1 + 1);
        if (p1 == std::string::npos || p2 == std::string::npos) continue;
        std::string name = line.substr(0, p1);
        std::string desc = line.substr(p1 + 1, p2 - p1 - 1);
        std::string value = line.substr(p2 + 1);
        lua_newtable(Ls);
        lua_pushstring(Ls, "name"); lua_pushstring(Ls, name.c_str()); lua_settable(Ls, -3);
        lua_pushstring(Ls, "descriptor"); lua_pushstring(Ls, desc.c_str()); lua_settable(Ls, -3);
        lua_pushstring(Ls, "value"); lua_pushstring(Ls, value.c_str()); lua_settable(Ls, -3);
        lua_rawseti(Ls, -2, ++idx);
    }
    return 1;
}

// 把 "className|method|file|line|native" 行解析成 Lua 数组；
// javaStackTrace / javaThreadStack 共用同一套字段。
inline int PushJavaStackFrames(lua_State* Ls, const std::string& all) {
    lua_newtable(Ls);
    int idx = 0;
    size_t pos = 0;
    while (pos < all.size()) {
        size_t e = all.find('\n', pos);
        if (e == std::string::npos) e = all.size();
        std::string line = all.substr(pos, e - pos);
        pos = e + 1;
        if (line.empty()) continue;
        std::vector<std::string> f;
        size_t p = 0;
        while (true) {
            size_t q = line.find('|', p);
            if (q == std::string::npos) { f.push_back(line.substr(p)); break; }
            f.push_back(line.substr(p, q - p));
            p = q + 1;
        }
        if (f.size() < 5) continue;
        lua_newtable(Ls);
        lua_pushstring(Ls, "className"); lua_pushstring(Ls, f[0].c_str()); lua_settable(Ls, -3);
        lua_pushstring(Ls, "method");    lua_pushstring(Ls, f[1].c_str()); lua_settable(Ls, -3);
        lua_pushstring(Ls, "file");      lua_pushstring(Ls, f[2].c_str()); lua_settable(Ls, -3);
        lua_pushstring(Ls, "line");
        lua_pushinteger(Ls, (lua_Integer)std::strtol(f[3].c_str(), nullptr, 10));
        lua_settable(Ls, -3);
        lua_pushstring(Ls, "native");    lua_pushboolean(Ls, f[4] == "1"); lua_settable(Ls, -3);
        lua_pushstring(Ls, "text");      lua_pushstring(Ls, line.c_str()); lua_settable(Ls, -3);
        lua_rawseti(Ls, -2, ++idx);
    }
    lua_pushstring(Ls, "count"); lua_pushinteger(Ls, idx); lua_settable(Ls, -3);
    lua_pushstring(Ls, "text");  lua_pushstring(Ls, all.c_str()); lua_settable(Ls, -3);
    return 1;
}

// javaStackTrace([maxDepth]) -> array|nil,err
//   返回**当前线程**的 Java 调用栈（Thread.currentThread().getStackTrace()）。
//   经典用法：在 artHook 回调里打印，看"谁调用了这个被 hook 的方法"。
inline int Lua_JavaStackTrace(lua_State* Ls) {
    int maxDepth = (int)luaL_optinteger(Ls, 1, 64);
    if (maxDepth <= 0) maxDepth = 64;
    if (maxDepth > 256) maxDepth = 256;
    const int cap = 32 * 1024;
    std::vector<char> buf((size_t)cap, 0);
    int n = atrace_java_stack_trace(buf.data(), cap, maxDepth);
    if (n < 0) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, buf[0] ? buf.data()
                                  : "javaStackTrace 失败（JVM 未初始化或当前线程不是 Java 线程）");
        return 2;
    }
    return PushJavaStackFrames(Ls, std::string(buf.data(), (size_t)n));
}

// javaThreadStack([tid][, maxDepth]) -> array|nil,err
//   返回**任意线程**的 Java 栈：Android 上 Thread.getId() == Linux tid，
//   硬件断点命中的 hit 行里就有 tid，用它就能补出「这条原生断点属于哪个 Java 调用链」。
//   tid 省略/0 = 当前线程。纯 native 线程（未被 ART Attach）会返回 nil,err。
inline int Lua_JavaThreadStack(lua_State* Ls) {
    int tid = (int)luaL_optinteger(Ls, 1, 0);
    int maxDepth = (int)luaL_optinteger(Ls, 2, 32);
    if (maxDepth <= 0) maxDepth = 32;
    if (maxDepth > 256) maxDepth = 256;
    const int cap = 32 * 1024;
    std::vector<char> buf((size_t)cap, 0);
    int n = atrace_java_thread_stack(tid, buf.data(), cap, maxDepth);
    if (n < 0) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, buf[0] ? buf.data() : "javaThreadStack 失败");
        return 2;
    }
    return PushJavaStackFrames(Ls, std::string(buf.data(), (size_t)n));
}

//   · 根本原因：表版要为每帧建 Lua table = **在回调里做分配**，而回调上下文本就不该分配；
//   · 现在的约定：`nativeBacktrace()` 只能在普通脚本里调，回调里**硬报错**；
//     回调里请用 `nativeBacktraceInto(buf[, max])` —— 只往预分配缓冲写地址、**不建表**；
//     抓到的地址在回调外/下个脚本再用 `nativeFrame(addr)` 符号化。
//   · 为什么以帧指针链为主：LuaJIT 的 VM 是手写汇编、没有 CFI，_Unwind_Backtrace 会断在
//     LuaJIT 边界；Android arm64 原生 .so 普遍保留 x29 帧指针，链能走得更远。.eh_frame 兜底。
struct NativeBtState {
    uintptr_t* pcs = nullptr;
    int n = 0;
    int max = 0;
};
inline _Unwind_Reason_Code NativeBtCb(struct _Unwind_Context* ctx, void* arg) {
    auto* st = static_cast<NativeBtState*>(arg);
    uintptr_t ip = (uintptr_t)_Unwind_GetIP(ctx);
    if (ip != 0 && st->n < st->max) st->pcs[st->n++] = ip;
    return st->n >= st->max ? _URC_END_OF_STACK : _URC_NO_REASON;
}

// 当前回调深度（0 = 不在任何 hook/artHook 回调里）。用于禁止回调内分配类 API。
inline int CallbackDepthNow() {
    if (!L) return 0;
    lua_getglobal(L, "__atrace_cb_depth");
    int d = (int)lua_tointegerx(L, -1, nullptr);
    lua_pop(L, 1);
    return d;
}

// 收集原生返回地址；**不分配堆内存**（只写调用方给的数组 + 栈上 1KB）。
// src（可空）：0=fp 帧指针链，1=cb-lr（回调里捕获的目标侧返回地址），2=unwind 兜底。
inline int CollectNativePcs(uintptr_t* out, int maxDepth, unsigned char* src) {
    if (!out || maxDepth <= 0) return 0;
    if (maxDepth > 128) maxDepth = 128;
    int n = 0;
    uintptr_t stackLo = 0, stackHi = 0;
    const bool haveRange = CurrentStackRange(&stackLo, &stackHi);
    const bool fromCb = (g_cb_target_fp != 0 || g_cb_target_lr != 0);
    if (fromCb && g_cb_target_lr >= 0x1000 && n < maxDepth) {
        out[n] = g_cb_target_lr;
        if (src) src[n] = 1;
        ++n;
    }
    uintptr_t fp = fromCb ? g_cb_target_fp
                          : (g_nativeBtBase ? g_nativeBtBase
                                            : (uintptr_t)__builtin_frame_address(0));
    uintptr_t last = 0;
    while (n < maxDepth && fp > last && (fp & 7) == 0) {
        if (haveRange && (fp < stackLo || fp + 16 > stackHi)) break;
        uintptr_t next = *(const uintptr_t*)fp;        // 保存的上一层 x29
        uintptr_t ret = *(const uintptr_t*)(fp + 8);   // 返回地址（x30）
        if (ret < 0x1000) break;
        out[n] = ret;
        if (src) src[n] = 0;
        ++n;
        last = fp;
        fp = next;
    }
    if (n < 2) {   // 帧指针链断了：退到 .eh_frame
        uintptr_t u[128];
        NativeBtState st;
        st.pcs = u;
        st.max = maxDepth;
        _Unwind_Backtrace(NativeBtCb, &st);
        for (int i = 0; i < st.n && n < maxDepth; ++i) {
            if (u[i] == 0) continue;
            out[n] = u[i];
            if (src) src[n] = 2;
            ++n;
        }
    }
    return n;
}

// nativeBacktrace([maxDepth]) -> array | nil,err
//   **只能在普通脚本里调用**（要建 Lua 表=分配）。hook 回调里会直接报错，
//   请改用 nativeBacktraceInto(buf)（buf 用 ffi.new 预分配）。
inline int Lua_NativeBacktrace(lua_State* Ls) {
    if (CallbackDepthNow() > 0) {
        return luaL_error(Ls,
            "回调里不能调用 nativeBacktrace（它要建 Lua 表=分配，已知会把目标打崩）：\n"
            "  · 回调里用 nativeBacktraceInto(buf)：buf 在**进回调前**预分配，"
            "例如 local buf = ffi.new(\"uint64_t[64]\")，回调里 nativeBacktraceInto(buf, 64)\n"
            "  · 或者用 call(function() ... end) 投递到主线程再调 nativeBacktrace");
    }
    int maxDepth = (int)luaL_optinteger(Ls, 1, 32);
    if (maxDepth <= 0) maxDepth = 32;
    if (maxDepth > 128) maxDepth = 128;
    uintptr_t pcs[128];
    unsigned char srcs[128];
    int n = CollectNativePcs(pcs, maxDepth, srcs);
    lua_newtable(Ls);
    int idx = 0;
    for (int i = 0; i < n; ++i) {
        uintptr_t pc = pcs[i];
        Dl_info info;
        memset(&info, 0, sizeof(info));
        std::string module, symbol;
        uintptr_t off = 0;
        if (dladdr((void*)pc, &info) != 0) {
            if (info.dli_fname) {
                const char* base = strrchr(info.dli_fname, '/');
                module = base ? (base + 1) : info.dli_fname;
            }
            if (info.dli_fbase) off = pc - (uintptr_t)info.dli_fbase;
            if (info.dli_sname) symbol = info.dli_sname;
        }
        lua_newtable(Ls);
        lua_pushstring(Ls, "addr");   lua_pushinteger(Ls, (lua_Integer)pc); lua_settable(Ls, -3);
        lua_pushstring(Ls, "module"); lua_pushstring(Ls, module.c_str()); lua_settable(Ls, -3);
        lua_pushstring(Ls, "offset"); lua_pushinteger(Ls, (lua_Integer)off); lua_settable(Ls, -3);
        lua_pushstring(Ls, "symbol"); lua_pushstring(Ls, symbol.c_str()); lua_settable(Ls, -3);
        lua_pushstring(Ls, "src");
        lua_pushstring(Ls, srcs[i] == 1 ? "cb-lr" : (srcs[i] == 2 ? "unwind" : "fp"));
        lua_settable(Ls, -3);
        lua_rawseti(Ls, -2, ++idx);
    }
    lua_pushstring(Ls, "count"); lua_pushinteger(Ls, idx); lua_settable(Ls, -3);
    return 1;
}

// nativeBacktraceInto(buf[, maxDepth]) -> count | nil,err
//   buf：可写内存地址（number / "0x..." / lightuserdata / cdata），至少 maxDepth*8 字节。
//   **不建 Lua 表、不分配**，因此可以在 hook 回调里安全调用（这是回调里唯一推荐的原生栈入口）。
//   地址数组布局：buf[i] = 第 i 帧的返回地址（uint64_t）。
inline int Lua_NativeBacktraceInto(lua_State* Ls) {
    uintptr_t buf = UntagAddr(CheckAddr(Ls, 1));
    int maxDepth = (int)luaL_optinteger(Ls, 2, 32);
    if (maxDepth <= 0) maxDepth = 32;
    if (maxDepth > 128) maxDepth = 128;
    std::string why;
    if (const char* bad = CheckRange(buf, (size_t)maxDepth * sizeof(uintptr_t), true, why)) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, bad);
        return 2;
    }
    uintptr_t pcs[128];
    int n = CollectNativePcs(pcs, maxDepth, nullptr);
    if (n > 0) memcpy((void*)buf, pcs, (size_t)n * sizeof(uintptr_t));
    lua_pushinteger(Ls, n);
    return 1;
}

// nativeFrame(addr) -> {addr, module, offset, symbol} | nil,err
//   给 nativeBacktraceInto 抓到的地址做符号化（普通脚本里调，可以分配）。
inline int Lua_NativeFrame(lua_State* Ls) {
    uintptr_t pc = UntagAddr(CheckAddr(Ls, 1));
    if (pc == 0) { lua_pushnil(Ls); lua_pushstring(Ls, "地址为 0"); return 2; }
    Dl_info info;
    memset(&info, 0, sizeof(info));
    std::string module, symbol;
    uintptr_t off = 0;
    if (dladdr((void*)pc, &info) != 0) {
        if (info.dli_fname) {
            const char* base = strrchr(info.dli_fname, '/');
            module = base ? (base + 1) : info.dli_fname;
        }
        if (info.dli_fbase) off = pc - (uintptr_t)info.dli_fbase;
        if (info.dli_sname) symbol = info.dli_sname;
    }
    lua_newtable(Ls);
    lua_pushstring(Ls, "addr");   lua_pushinteger(Ls, (lua_Integer)pc); lua_settable(Ls, -3);
    lua_pushstring(Ls, "module"); lua_pushstring(Ls, module.c_str()); lua_settable(Ls, -3);
    lua_pushstring(Ls, "offset"); lua_pushinteger(Ls, (lua_Integer)off); lua_settable(Ls, -3);
    lua_pushstring(Ls, "symbol"); lua_pushstring(Ls, symbol.c_str()); lua_settable(Ls, -3);
    return 1;
}

// ---------- P1-9 静态方法调用 ----------
inline int Lua_JavaCallStatic(lua_State* Ls) {
    const char* cls = luaL_checkstring(Ls, 1);
    const char* name = luaL_checkstring(Ls, 2);
    const char* sig = luaL_checkstring(Ls, 3);
    JNIEnv* env = atrace_arthook_env();
    if (!env) { lua_pushnil(Ls); lua_pushstring(Ls, "未连接 JVM"); return 2; }
    std::vector<std::string> types;
    SplitParams(sig, types);
    jobjectArray args = BuildJavaArgs(env, types, 4);
    char err[320] = {0};
    jobject ret = atrace_java_call_static(cls, name, sig, args, err, (int)sizeof(err));
    if (args) env->DeleteLocalRef(args);
    if (err[0]) { lua_pushnil(Ls); lua_pushstring(Ls, err); return 2; }
    PushJavaValue(Ls, env, ret);
    if (ret) env->DeleteLocalRef(ret);
    return 1;
}

// javaFindClass(name) -> userdata(java.lang.Class) | nil,err
//   因此能查到 App 自己的类；失败时给出明确错误，而不是像 Class.forName 那样静默 nil。
//   内部类用 $ 分隔（com.foo.Outer$Inner）；拿到 Class 后可配合 javaCallStatic/javaNew 使用。
inline int Lua_JavaFindClass(lua_State* Ls) {
    const char* name = luaL_checkstring(Ls, 1);
    char err[384] = {0};
    jobject cls = atrace_java_find_class(name, err, (int)sizeof(err));
    if (!cls) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, err[0] ? err : "javaFindClass 失败（JVM 未初始化？）");
        return 2;
    }
    JNIEnv* env = atrace_arthook_env();
    PushJavaValue(Ls, env, cls);
    if (env) env->DeleteLocalRef(cls);
    return 1;
}

// ---------- P1-13 hookAfter：函数返回后回调（OnLeave 跳板）----------
struct OnLeaveHookRec {
    int id = 0;
    int lua_ref = 0;
    uintptr_t target = 0;
};
inline std::mutex g_onLeaveMutex;
inline std::map<int, OnLeaveHookRec> g_onLeaveHooks;
inline int g_onLeaveNextId = 1;

inline void OnLeaveBridge(uint64_t* regs8, uint64_t* ret_io, int hook_id) {
    if (!L) return;
    std::lock_guard<std::recursive_timed_mutex> lock(g_luaMutex);
    if (!CallbackStackOk()) {
        PushLog("[回调跳过] 目标线程剩余栈不足 64KB（避免栈溢出崩溃）：hookAfter 回调未执行");
        return;
    }
    // P1-22：regs8 指针其实是跳板栈帧基址；偏移 224/232 是进入目标函数时的 x29/x30
    //（= 调用者的帧指针与返回地址）。
    g_cb_target_fp = ((const uint64_t*)regs8)[28];
    g_cb_target_lr = ((const uint64_t*)regs8)[29];
    int ref = 0;
    uintptr_t target = 0;
    {
        std::lock_guard<std::mutex> lk(g_onLeaveMutex);
        auto it = g_onLeaveHooks.find(hook_id);
        if (it == g_onLeaveHooks.end()) return;
        ref = it->second.lua_ref;
        target = it->second.target;
    }
    if (!ref) return;
    lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
    if (!lua_isfunction(L, -1)) { lua_pop(L, 1); return; }
    lua_newtable(L);
    lua_pushstring(L, "id"); lua_pushinteger(L, (lua_Integer)hook_id); lua_settable(L, -3);
    lua_pushstring(L, "addr"); lua_pushinteger(L, (lua_Integer)target); lua_settable(L, -3);
    lua_pushstring(L, "args");
    lua_newtable(L);
    for (int i = 0; i < 8; ++i) {
        PushU64Safe(L, regs8[i], "hookAfter.args");
        lua_rawseti(L, -2, i + 1);
    }
    lua_settable(L, -3);
    lua_pushstring(L, "ret");
    PushU64Safe(L, ret_io[0], "hookAfter.ret");
    lua_settable(L, -3);
    PushCallbackDepthEnter();
    NativeBtScope btScope;   // P1-22：记录桥接层帧指针（nativeBacktrace 从这往外走）
    int rc = lua_pcall(L, 1, 1, 0);
    PushCallbackDepthLeave();
    if (rc != LUA_OK) {
        const char* e = lua_tostring(L, -1);
        PushLog(std::string("[hookAfter 错误] ") + (e ? e : "未知错误"));
        lua_pop(L, 1);
        return;
    }
    if (lua_isnumber(L, -1)) {
        ret_io[0] = (uint64_t)lua_tointeger(L, -1);   // 允许改返回值（x0）
    }
    lua_pop(L, 1);
}

inline int Lua_HookAfter(lua_State* Ls) {
    if (lua_gettop(Ls) != 2) return luaL_error(Ls, "hookAfter(addr, function) 需要 2 个参数");
    uintptr_t target = UntagAddr((uintptr_t)luaL_checkinteger(Ls, 1));
    if (target == 0) return luaL_error(Ls, "hookAfter: 地址不能为 0");
    if (!AddrInExecMapping(target)) {
        return luaL_error(Ls, "hookAfter: %s 不在可执行映射里", HexStr(target).c_str());
    }
    if (!lua_isfunction(Ls, 2)) return luaL_error(Ls, "hookAfter 第 2 个参数必须是 function");
    lua_pushvalue(Ls, 2);
    int ref = luaL_ref(Ls, LUA_REGISTRYINDEX);
    int id = g_onLeaveNextId++;
    char err[256] = {0};
    if (atrace_onleave_install(target, id, err, (int)sizeof(err)) != 1) {
        luaL_unref(Ls, LUA_REGISTRYINDEX, ref);
        lua_pushnil(Ls);
        lua_pushfstring(Ls, "hookAfter 安装失败: %s", err[0] ? err : "未知错误");
        return 2;
    }
    {
        std::lock_guard<std::mutex> lk(g_onLeaveMutex);
        g_onLeaveHooks[id] = OnLeaveHookRec{id, ref, target};
    }
    lua_pushinteger(Ls, (lua_Integer)id);
    return 1;
}

inline int Lua_RemoveAfter(lua_State* Ls) {
    int id = (int)luaL_checkinteger(Ls, 1);
    OnLeaveHookRec rec;
    {
        std::lock_guard<std::mutex> lk(g_onLeaveMutex);
        auto it = g_onLeaveHooks.find(id);
        if (it == g_onLeaveHooks.end()) { lua_pushboolean(Ls, 0); return 1; }
        rec = it->second;
        g_onLeaveHooks.erase(it);
    }
    int ok = atrace_onleave_uninstall(rec.target);
    if (rec.lua_ref) luaL_unref(Ls, LUA_REGISTRYINDEX, rec.lua_ref);
    lua_pushboolean(Ls, ok == 1);
    return 1;
}

inline int Lua_AfterHooks(lua_State* Ls) {
    lua_newtable(Ls);
    int n = 0;
    std::lock_guard<std::mutex> lk(g_onLeaveMutex);
    for (auto& kv : g_onLeaveHooks) {
        lua_newtable(Ls);
        lua_pushstring(Ls, "id"); lua_pushinteger(Ls, (lua_Integer)kv.second.id); lua_settable(Ls, -3);
        lua_pushstring(Ls, "target"); lua_pushinteger(Ls, (lua_Integer)kv.second.target); lua_settable(Ls, -3);
        lua_rawseti(Ls, -2, ++n);
    }
    return 1;
}

// ---------- 初始化 ----------
    // ---------- P0-10：静态字段读写（Lua 侧） ----------
inline int Lua_JavaGetStatic(lua_State* Ls) {
    const char* cls = luaL_checkstring(Ls, 1);
    const char* name = luaL_checkstring(Ls, 2);
    const char* sig = luaL_optstring(Ls, 3, "");
    if (!sig || !*sig) {
        return luaL_error(Ls,
            "javaGetStatic(class, name, signature) 需要第 3 个参数（字段类型描述符），例如：\n"
            "  javaGetStatic(\"com.example.App\", \"TAG\", \"Ljava/lang/String;\")\n"
            "  javaGetStatic(\"com.example.App\", \"VERSION\", \"I\")\n"
            "提示：javaFields(实例) 能看到静态字段的类型描述符");
    }
    char err[384] = {0};
    jobject v = atrace_java_get_static_field(cls, name, sig, err, (int)sizeof(err));
    if (err[0] || !v) {
        lua_pushnil(Ls);
        lua_pushstring(Ls, err[0] ? err : "静态字段读取失败（值为 null？）");
        return 2;
    }
    JNIEnv* env = atrace_arthook_env();
    PushJavaValue(Ls, env, v);
    if (env) env->DeleteLocalRef(v);
    return 1;
}

inline int Lua_JavaSetStatic(lua_State* Ls) {
    const char* cls = luaL_checkstring(Ls, 1);
    const char* name = luaL_checkstring(Ls, 2);
    const char* sig = luaL_optstring(Ls, 3, "");
    if (!sig || !*sig)
        return luaL_error(Ls,
            "javaSetStatic(class, name, signature, value) 需要第 3 个参数（字段类型描述符），例如：\n"
            "  javaSetStatic(\"com.example.App\", \"TAG\", \"Ljava/lang/String;\", \"x\")\n"
            "  javaSetStatic(\"com.example.App\", \"FLAG\", \"I\", 1)");
    JNIEnv* env = atrace_arthook_env();
    if (!env) { lua_pushboolean(Ls, 0); lua_pushstring(Ls, "未连接 JVM"); return 2; }
    jobject v = JavaObjectFromLua(env, sig, 4);
    char err[384] = {0};
    int ok = atrace_java_set_static_field(cls, name, sig, v, err, (int)sizeof(err));
    if (v) env->DeleteLocalRef(v);
    lua_pushboolean(Ls, ok);
    if (!ok) { lua_pushstring(Ls, err[0] ? err : "静态字段写入失败"); return 2; }
    return 1;
}

inline int Lua_ReadU16(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    std::string why;
    if (const char* bad = CheckRange(addr, 2, false, why)) { lua_pushnil(Ls); lua_pushstring(Ls, bad); return 2; }
    uint16_t v = 0; memcpy(&v, (const void*)addr, 2);
    lua_pushinteger(Ls, (lua_Integer)v); return 1;
}
inline int Lua_ReadI8(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    std::string why;
    if (const char* bad = CheckRange(addr, 1, false, why)) { lua_pushnil(Ls); lua_pushstring(Ls, bad); return 2; }
    int8_t v = 0; memcpy(&v, (const void*)addr, 1);
    lua_pushinteger(Ls, (lua_Integer)v); return 1;
}
inline int Lua_ReadI16(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    std::string why;
    if (const char* bad = CheckRange(addr, 2, false, why)) { lua_pushnil(Ls); lua_pushstring(Ls, bad); return 2; }
    int16_t v = 0; memcpy(&v, (const void*)addr, 2);
    lua_pushinteger(Ls, (lua_Integer)v); return 1;
}
// 恒返回 number 的 64 位读取（>2^53 会有精度损失，每脚本只提示一次）
inline int Lua_ReadU64Num(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    std::string why;
    if (const char* bad = CheckRange(addr, 8, false, why)) { lua_pushnil(Ls); lua_pushstring(Ls, bad); return 2; }
    uint64_t v = 0; memcpy(&v, (const void*)addr, 8);
    if (v > 9007199254740992ULL && !g_u64Warned) {
        g_u64Warned = true;
        PushLog("[Lua] 注意: readU64Num 返回值超过 2^53，可能有精度损失（本脚本内只提示一次；精确值用 readQwordHex）");
    }
    lua_pushnumber(Ls, (lua_Number)v); return 1;
}
inline int Lua_ReadI64Num(lua_State* Ls) {
    uintptr_t addr = UntagAddr(CheckAddr(Ls, 1));
    std::string why;
    if (const char* bad = CheckRange(addr, 8, false, why)) { lua_pushnil(Ls); lua_pushstring(Ls, bad); return 2; }
    int64_t v = 0; memcpy(&v, (const void*)addr, 8);
    if ((v > 9007199254740992LL || v < -9007199254740992LL) && !g_u64Warned) {
        g_u64Warned = true;
        PushLog("[Lua] 注意: readI64Num 返回值超过 2^53，可能有精度损失（本脚本内只提示一次；精确值用 readQwordHex + u64）");
    }
    lua_pushnumber(Ls, (lua_Number)v); return 1;
}

// capabilities() -> table：一次看清"这个 agent 会什么/当前状态"
inline int Lua_Capabilities(lua_State* Ls) {
    lua_newtable(Ls);
    auto sets = [&](const char* k, const char* v) {
        lua_pushstring(Ls, k); lua_pushstring(Ls, v ? v : ""); lua_settable(Ls, -3);
    };
    auto setb = [&](const char* k, bool v) {
        lua_pushstring(Ls, k); lua_pushboolean(Ls, v ? 1 : 0); lua_settable(Ls, -3);
    };
    auto seti = [&](const char* k, lua_Integer v) {
        lua_pushstring(Ls, k); lua_pushinteger(Ls, v); lua_settable(Ls, -3);
    };
    sets("engine", "ATrace LuaJIT (Dobby + LSPlant)");
    sets("lua", "LuaJIT / Lua 5.1 语义（无 1<<n、& 语法；用 bit.* 或 2^n）");
#if defined(__aarch64__)
    sets("arch", "arm64-v8a");
#elif defined(__arm__)
    sets("arch", "armeabi-v7a");
#elif defined(__x86_64__)
    sets("arch", "x86_64");
#else
    sets("arch", "unknown");
#endif
    seti("api_count", (lua_Integer)ApiDocs().size());
    seti("pid", (lua_Integer)getpid());
    {   // 进程名
        char cmd[256] = {0};
        FILE* f = fopen("/proc/self/cmdline", "re");
        if (f) { size_t n = fread(cmd, 1, sizeof(cmd) - 1, f); (void)n; fclose(f); }
        sets("process", cmd[0] ? cmd : "?");
    }
    seti("agent_instance", (lua_Integer)(int64_t)g_instanceId);
    seti("uptime_ms", (lua_Integer)UptimeMs());
    {
        bool artReady = atrace_arthook_ready() != 0;
        setb("art_hook", artReady);
        sets("art_hook_state", artReady
             ? "initialized"
             : "lazy-init（首次 artHook/artUnhook 时初始化，通常可正常安装）");
    }
    {   // JVM 状态一句话
        char buf[384] = {0};
        atrace_arthook_vm_state(buf, (int)sizeof(buf));
        sets("art_vm", buf);
    }
    sets("native_hook", "hookfunc(替换) / hookCPU(instrument) / hookAfter(返回后) —— Dobby");
    setb("native_art_hook", false);           // LSPlant 不支持 native 方法
    setb("array_index", true);                // obj[i]
    setb("array_len_method", true);           // obj:len()
    setb("array_len_operator", true);
    setb("ffi_guard", true);                  // 回调里 ffi.* / ffi.C.* 硬报错
    setb("native_backtrace_callback", true);  // 回调里用 nativeBacktraceInto
    setb("bp_service", true);                 // 硬件断点=App 侧 perf_event 独立服务（不暂停目标）
    sets("bp_note", "硬件断点是采样，不暂停目标；Java 栈是查询时刻的栈，不是命中瞬间");
    sets("inject_path", "传统 ptrace（zero=true 为零 ptrace 实验路径）");
    // 已知限制清单
    lua_pushstring(Ls, "limitations");
    lua_newtable(Ls);
    const char* lim[] = {
        "回调里不能调 nativeBacktrace()（建表=分配，会报错）；用 nativeBacktraceInto(buf)",
        "回调里不能用 ffi.* / ffi.C.*（硬报错）；重活用 call()/call_sync() 投递",
        "artHook 不支持 native/abstract 方法（native 请用 hookfunc/hookAfter）",
        "artHookAll 不支持构造器 <init>（LSPlant 需要反射 Method；构造器只有 Constructor）",
        "Java 数组支持 obj[i] 和 obj:len()，但不支持 Lua 的 #obj",
        "hardware bp 由独立 perf_event 服务实现：不暂停目标、命中栈为查询时刻",
        "autorun 在注入成功+连上 agent 之后执行，不保证早于目标自身检测",
    };
    for (int i = 0; i < (int)(sizeof(lim) / sizeof(lim[0])); ++i) {
        lua_pushstring(Ls, lim[i]);
        lua_rawseti(Ls, -2, i + 1);
    }
    lua_settable(Ls, -3);
    return 1;
}

inline void Init() {
    std::lock_guard<std::recursive_timed_mutex> lock(g_luaMutex);
    if (L) return;

    L = luaL_newstate();
    if (!L) {
        PushLog("[Lua] 初始化失败: luaL_newstate 返回 null");
        return;
    }
    luaL_openlibs(L);

    // 每次 Init 生成新实例 id（仅观测用）
    {
        uint64_t id = 0;
        FILE* ur = fopen("/dev/urandom", "rb");
        if (ur) {
            if (fread(&id, 1, sizeof(id), ur) != sizeof(id)) id = 0;
            fclose(ur);
        }
        if (id == 0) id = ((uint64_t)getpid() << 32) ^ (uint64_t)time(nullptr);
        g_instanceId = id;
    }

// 用 luaL_Reg 统一注册（而不是逐个 lua_pushcfunction+lua_setglobal）：
    // 这样 luaL_checkinteger 等报错里才会显示**真实函数名**，
    // 而不是旧版那样只显示 '?'（外部 AI 反馈过这条）。
    static const luaL_Reg kGlobalFuncs[] = {
        {"print", Lua_Print},
        {"getBase", Lua_GetBase},
        {"clearbase", Lua_ClearBase},
        {"module_info", Lua_ModuleInfo},
        {"symbols", Lua_Symbols},
        {"scan", Lua_Scan},
        {"hookCPU", Lua_Hook},
        {"hookfunc", Lua_HookReplace},
        {"removehook", Lua_HookUnhook},
        {"remove_all_hook", Lua_RemoveAllHooks},
        {"hooks", Lua_Hooks},
        {"hook_list", Lua_Hooks},
        {"whoami", Lua_WhoAmI},
        {"artHook", Lua_ArtHook},
        {"artHookAll", Lua_ArtHookAll},
        {"artUnhook", Lua_ArtUnhook},
        {"artHooks", Lua_ArtHooks},
        {"artStatus", Lua_ArtStatus},
        {"javaNew", Lua_JavaNew},
        {"readPtrNum", Lua_ReadPtrNum},
        {"readU8", Lua_ReadByte},
        {"readU16", Lua_ReadU16},
        {"readI8", Lua_ReadI8},
        {"readI16", Lua_ReadI16},
        {"readU32", Lua_ReadDword},
        {"readI32", Lua_ReadInt32},
        {"readU64", Lua_ReadQword},
        {"readI64", Lua_ReadInt64},
        {"readU64Num", Lua_ReadU64Num},
        {"readI64Num", Lua_ReadI64Num},
        {"verify", Lua_Verify},
        {"maps", Lua_Maps},
        {"scanRange", Lua_ScanRange},
        {"symbol", Lua_Symbol},
        {"dumpToFile", Lua_DumpToFile},
        {"dump", Lua_Dump},
        {"javaFields", Lua_JavaFields},
        {"artVmState", Lua_ArtVmState},
        {"javaCallStatic", Lua_JavaCallStatic},
        {"javaFindClass", Lua_JavaFindClass},
        {"javaString", Lua_JavaString},
        {"javaBox", Lua_JavaBox},
        {"javaValue", Lua_JavaValue},
        {"javaGetStatic", Lua_JavaGetStatic},
        {"javaSetStatic", Lua_JavaSetStatic},
        {"capabilities", Lua_Capabilities},
        {"javaStackTrace", Lua_JavaStackTrace},
        {"javaThreadStack", Lua_JavaThreadStack},
        {"nativeBacktrace", Lua_NativeBacktrace},
        {"nativeBacktraceInto", Lua_NativeBacktraceInto},
        {"nativeFrame", Lua_NativeFrame},
        {"hookAfter", Lua_HookAfter},
        {"removeAfter", Lua_RemoveAfter},
        {"afterHooks", Lua_AfterHooks},
        {"call", Lua_CallOnMain},
        {"call_stats", Lua_CallStats},
        {"call_done", Lua_CallDone},
        {"call_sync", Lua_CallSync},
        {"msleep", Lua_Msleep},
        {"readByte", Lua_ReadByte},
        {"readDword", Lua_ReadDword},
        {"readQword", Lua_ReadQword},
        {"readFloat", Lua_ReadFloat},
        {"readDouble", Lua_ReadDouble},
        {"readPtr", Lua_ReadPtr},
        {"readPtrHex", Lua_ReadPtrHex},
        {"untag", Lua_Untag},
        {"readQwordHex", Lua_ReadQwordHex},
        {"readInt32", Lua_ReadInt32},
        {"readInt64", Lua_ReadInt64},
        {"self_info", Lua_SelfInfo},
        {"readBytes", Lua_ReadBytes},
        {"readString", Lua_ReadString},
        {"writeByte", Lua_WriteByte},
        {"writeDword", Lua_WriteDword},
        {"writeQword", Lua_WriteQword},
        {"writeFloat", Lua_WriteFloat},
        {"writeDouble", Lua_WriteDouble},
        {"writePtr", Lua_WritePtr},
        {"writeBytes", Lua_WriteBytes},
        {"writeString", Lua_WriteString},
        {"regsOf", Lua_RegsOf},
        {"setReg", Lua_SetReg},
        {"api", Lua_Api},
        {"help", Lua_Help},
        {nullptr, nullptr},
    };
    luaL_register(L, "_G", kGlobalFuncs);

    // regs_t 对应 arm64 上 dobby.h 的 RegisterContext，脚本可在
    // hookCPU 回调中检查 x0-x28/sp/fp/lr 与浮点寄存器。
    const char* setup_ffi = R"(
        local ffi = require("ffi")
        ffi.cdef[[
            typedef struct { double d1; double d2; } fpreg_t;
            typedef struct {
                uint64_t dmmpy_0;
                uint64_t sp;
                uint64_t dmmpy_1;
                uint64_t x[29];
                uint64_t fp;
                uint64_t lr;
                fpreg_t q[32];
            } regs_t;
            int system(const char* cmd);
        ]]
    )";
    if (luaL_dostring(L, setup_ffi) != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        PushLog(std::string("[Lua] FFI 初始化失败: ") + (err ? err : "未知错误"));
        lua_pop(L, 1);
    }

    // 64 位地址精确工具：u64("0x...") -> cdata<uint64_t>。
    // LuaJIT 的 number 是 double，超过 2^53 会丢精度；cdata 运算则是精确的。
    const char* setup_u64 = R"LUA(
        local ffi = require("ffi")

        -- "0x..." / number / cdata / lightuserdata -> cdata<uint64_t>（精确）
        function u64(v)
            local tv = type(v)
            if tv == "string" then
                local h = v:gsub("^%s*0[xX]", ""):gsub("%s*$", "")
                if #h > 8 then
                    local hi = tonumber(h:sub(1, #h - 8), 16) or 0
                    local lo = tonumber(h:sub(-8), 16) or 0
                    return ffi.cast("uint64_t", hi) * ffi.cast("uint64_t", 0x100000000LL) +
                           ffi.cast("uint64_t", lo)
                end
                return ffi.cast("uint64_t", tonumber(h, 16) or 0)
            end
            return ffi.cast("uint64_t", v)
        end

        -- 给 C 侧 CheckAddr 用：把 cdata 地址拆成 (lo, hi)，两个都 <= 32 位，精确
        -- x 可能是 uint64_t / 指针 / **数组**（如 ffi.new("uint64_t[64]")）等 cdata；
        -- 数组/指针先退化成 uintptr_t 再转 uint64_t。转换失败返回 0,0（调用方按非法地址处理）。
        function __atrace_addr_parts(x)
            local okc, c = pcall(ffi.cast, "uint64_t", x)
            if not okc then
                okc, c = pcall(function() return ffi.cast("uint64_t", ffi.cast("uintptr_t", x)) end)
            end
            if not okc or c == nil then return 0, 0 end
            local hi = tonumber(c / 0x100000000ULL)
            local lo = tonumber(c - ffi.cast("uint64_t", hi) * ffi.cast("uint64_t", 0x100000000LL))
            return lo, hi
        end

        -- number / "0x..." / cdata / lightuserdata -> "0x..."（64 位不丢精度）
        function hexOf(x)
            local c = ffi.cast("uint64_t", x)
            local hi = tonumber(c / 0x100000000ULL)
            local lo = tonumber(c - ffi.cast("uint64_t", hi) * ffi.cast("uint64_t", 0x100000000LL))
            if hi == 0 then return string.format("0x%x", lo) end
            return string.format("0x%x%08x", hi, lo)
        end

        -- "0x..." -> cdata<void*>，可直接 ffi.cast / 直接解引用
        function ptrOf(x)
            return ffi.cast("void*", u64(x))
        end

        -- P1-11：对象图 dump（递归字段 + 深度/节点预算 + 环检测）。
        -- v2 过滤：跳过 shadow$_* / 全大写常量 / serialVersionUID；
        --   java./jdk./dalvik./javax./android. 内部类型只 toString 不递归（避免刷屏）；
        --   数组打印 [len=N] 预览；maфDepth 默认 1、上限 4。
        function javaDump(obj, maxDepth)
            if type(obj) ~= "userdata" then return tostring(obj) end
            maxDepth = math.min(tonumber(maxDepth) or 1, 4)
            local out, nodes, seen = {}, 0, {}
            local function internalName(n)
                if not n or n == "" then return true end
                return n:match("^java%.") or n:match("^jdk%.") or n:match("^javax%.")
                    or n:match("^dalvik%.") or n:match("^android%.")
            end
            local function classNameOf(o)
                local ok, n = pcall(function() return o:className() end)
                if ok and n then return n end
                return "?"
            end
            local function arrPreview(o)
                local ok, n = pcall(function() return o:len() end)
                if not ok or type(n) ~= "number" then return nil end
                local parts = {}
                for i = 0, math.min(n - 1, 7) do
                    local okv, v = pcall(function() return o:get(i) end)
                    if okv then parts[#parts + 1] = tostring(v) end
                end
                local more = n > 8 and ", …" or ""
                return string.format("[len=%d] %s%s", n, table.concat(parts, ", "), more)
            end
            local function skipField(name, desc)
                if name:sub(1, 8) == "shadow$_" then return true end
                if name == "serialVersionUID" then return true end
                -- 全大写 / 下划线常量（DEFAULT_CAPACITY、MAX_VALUE…）：不是对象状态
                if name:match("^[A-Z][A-Z0-9_]+$") then return true end
                return false
            end
            local function dump(o, depth)
                local tag = tostring(o)
                if seen[tag] then
                    out[#out + 1] = string.rep("  ", depth) .. "(循环引用，跳过)"
                    return
                end
                seen[tag] = true
                out[#out + 1] = string.rep("  ", depth) .. tag .. " {"
                local okf, fs = pcall(javaFields, o, true)
                if not okf or type(fs) ~= "table" then
                    out[#out + 1] = string.rep("  ", depth + 1) .. "(字段读取失败)"
                else
                    for _, f in ipairs(fs) do
                        nodes = nodes + 1
                        if nodes > 120 then
                            out[#out + 1] = string.rep("  ", depth + 1) .. "…(字段过多，已截断)"
                            break
                        end
                        local name = f.name
                        local desc = f.descriptor or "?"
                        if skipField(name, desc) then
                            -- skip
                        else
                            local line = string.rep("  ", depth + 1) .. name .. " : " .. desc .. " = "
                            local leaf = (desc:sub(1, 1) ~= "L" and desc:sub(1, 1) ~= "[")
                            if leaf then
                                out[#out + 1] = line .. tostring(f.value)
                            else
                                local okv, v = pcall(function() return o:getField(name, desc) end)
                                if not okv or v == nil then
                                    out[#out + 1] = line .. tostring(f.value)
                                elseif type(v) ~= "userdata" then
                                    out[#out + 1] = line .. tostring(v)
                                else
                                    local ap = arrPreview(v)
                                    if ap then
                                        out[#out + 1] = line .. ap
                                    elseif depth >= maxDepth or internalName(classNameOf(v)) then
                                        out[#out + 1] = line .. tostring(v) .. " (更深层省略)"
                                    else
                                        out[#out + 1] = line
                                        dump(v, depth + 1)
                                    end
                                end
                            end
                        end
                    end
                end
                out[#out + 1] = string.rep("  ", depth) .. "}"
            end
            dump(obj, 0)
            return table.concat(out, "\n")
        end

        -- P2-16：Lua 5.1 没有位运算语法（1<<20 / & 会语法错误）。
        -- LuaJIT 自带 bit 库 → 导出成全局；再补一个 Lua 5.2 风格的 bit32 兼容层。
        local okbit, bitmod = pcall(require, "bit")
        if okbit and bitmod then
            _G.bit = bitmod
            local function u32(x) return bitmod.band(x, 0xffffffff) % 4294967296 end
            _G.bit32 = {
                band = function(...) return u32(bitmod.band(...)) end,
                bor  = function(...) return u32(bitmod.bor(...)) end,
                bxor = function(...) return u32(bitmod.bxor(...)) end,
                bnot = function(x) return u32(bitmod.bnot(x)) end,
                lshift = function(x, d) return u32(bitmod.lshift(x, d)) end,
                rshift = function(x, d) return u32(bitmod.rshift(x, d)) end,
                arshift = function(x, d) return bitmod.arshift(x, d) end,
                btst = function(x, n) return bitmod.band(bitmod.rshift(x, n), 1) == 1 end,
                extract = function(n, field, width)
                    width = width or 1
                    return u32(bitmod.rshift(n, field)) % (2 ^ width)
                end,
                replace = function(n, v, field, width)
                    width = width or 1
                    local mask = bitmod.lshift(1, width) - 1
                    local cleared = bitmod.band(n, bitmod.bnot(bitmod.lshift(mask, field)))
                    return u32(bitmod.bor(cleared, bitmod.band(bitmod.lshift(v, field), bitmod.lshift(mask, field))))
                end,
            }
        end
    )LUA";
    if (luaL_dostring(L, setup_u64) != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        PushLog(std::string("[Lua] u64 辅助函数初始化失败: ") + (err ? err : "未知错误"));
        lua_pop(L, 1);
    }

    // ArtHook：java 对象 userdata 的元表 + 把 Lua 回调桥接给 ArtHook.cpp
    luaL_newmetatable(L, "atrace.javaobj");
    lua_pushcfunction(L, Lua_JavaObjGc); lua_setfield(L, -2, "__gc");
    // P0-9：尽量支持 #arr（LuaJIT 对 userdata 的 __len 支持不确定，失败时用 arr:len()）
    lua_pushcfunction(L, Lua_JavaObjLen); lua_setfield(L, -2, "__len");
    lua_pushcfunction(L, Lua_JavaObjToString); lua_setfield(L, -2, "__tostring");
    lua_pushcfunction(L, Lua_JavaObjIndex); lua_setfield(L, -2, "__index");
    lua_pop(L, 1);
    atrace_arthook_set_lua_bridge(ArtHookLuaCall, ArtHookLogBridge);

    // P1-13：注册 on-leave 桥（函数返回后回调 Lua）
    atrace_onleave_set_bridge(OnLeaveBridge);
    // P0-1：回调上下文里禁止 ffi.*（LuaJIT 在 Dobby/artHook 回调里调 ffi 会静默失败或闪退）。
    // 于是回调里调 ffi.C.SSL_write 之类会"静默成功/静默失败"，hits 在涨但记录为 0 条。
    // 现在额外在 __index 里拦截 "C"：回调深度 >0 时返回一个"谁调谁报错"的代理。
    {
        const char* guard = R"(
            local ok, real = pcall(require, "ffi")
            if ok and real then
                local names = {"cast","cdef","new","typeof","metatype","gc","sizeof",
                               "offsetof","istype","errno","string","load","copy","fill","abi"}
                local guarded = {}
                for _, n in ipairs(names) do
                    local f = real[n]
                    if type(f) == "function" then
                        guarded[n] = function(...)
                            if _G.__atrace_cb_depth and _G.__atrace_cb_depth > 0 then
                                error("回调内不能调用 ffi." .. n ..
                                      "（会静默失败/闪退）：把这段放进 call(runner) 或 call_sync", 2)
                            end
                            return f(...)
                        end
                    else guarded[n] = f end
                end

                -- ffi.C 的成员调用也要硬报错（这才是旧版真正漏掉的那条静默失败路径）
                local real_C = real.C
                local C_proxy = setmetatable({}, {
                    __index = function(_, k)
                        return function()
                            error("回调内不能调用 ffi.C." .. tostring(k) ..
                                  "（回调上下文里 ffi 会静默失败/闪退）：" ..
                                  "把这段放进 call(runner) 或 call_sync", 2)
                        end
                    end,
                })

                local proxy = setmetatable(guarded, {
                    __index = function(_, k)
                        if k == "C" then
                            if _G.__atrace_cb_depth and _G.__atrace_cb_depth > 0 then
                                return C_proxy
                            end
                            return real_C
                        end
                        return real[k]
                    end,
                })
                package.loaded["ffi"] = proxy
                _G.ffi = proxy
                -- 逃生舱：极少数确实要在回调里用 ffi 的场景（后果自负）
                _G.__atrace_ffi_raw = real
            end
        )";
        if (luaL_dostring(L, guard) != LUA_OK) {
            const char* e = lua_tostring(L, -1);
            PushLog(std::string("[Lua] ffi 回调守卫初始化失败: ") + (e ? e : "未知错误"));
            lua_pop(L, 1);
        }
    }
    SetCallbackDepth(0);

    InstallMainThreadHook();
    PushLog("[Lua] 引擎就绪 (LuaJIT + Dobby)");
}

// ---------- 重置 ----------
inline void Reset() {
    // 停止兜底泵，避免它继续访问即将销毁的 Lua 状态
    StopFallbackPump();
    // 卸载主线程泵 hook，避免 Init 时重复安装
    if (g_mainPumpHooked) {
        DobbyDestroy(g_mainPumpHooked);
        g_mainPumpHooked = nullptr;
        g_origSwapBuffers = nullptr;
        g_origPollOnce = nullptr;
    }
    std::lock_guard<std::recursive_timed_mutex> lock(g_luaMutex);
    for (uintptr_t addr : g_hookAddrs) DobbyDestroy((void*)addr);
    g_hookAddrs.clear();
    for (auto& pair : g_luaCallbacks) {
        DobbyDestroy((void*)pair.first);
        if (L) luaL_unref(L, LUA_REGISTRYINDEX, pair.second);
    }
    g_luaCallbacks.clear();
    g_baseCache.clear();
    if (L) {
        lua_close(L);
        L = nullptr;
    }
    Init();
}

} // 命名空间 LuaEngine

#endif // UDT_LUA_ENGINE_H

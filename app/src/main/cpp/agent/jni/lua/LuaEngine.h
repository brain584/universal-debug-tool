#ifndef UDT_LUA_ENGINE_H
#define UDT_LUA_ENGINE_H

// Agent 侧 Lua 调试引擎。
//
// 把 LuaJIT（启用 FFI）+ Dobby（内联 hook / instrument）封装成
// 位于被注入进程内的持久 Lua 状态。imgui
// 悬浮层通过加密 socket 发送脚本；本引擎执行它们
// 并返回捕获的输出。
//
// 暴露的 Lua API：
//   print(...)                  -> 捕获到命令响应中
//   getBase("libxxx.so")        -> 模块基址（xdl）
//   hookCPU(addr, function)     -> DobbyInstrument；回调接收
//                                  (regs_lightuserdata, function_address)
//   hookfunc(addr, replaceAddr) -> DobbyHook（返回跳板与成功标志）
//   removehook(addr)            -> DobbyDestroy 单个 hook
//   remove_all_hook()           -> 销毁所有已安装的 hook
//   call(function)              -> 稍后在进程主 / 渲染线程运行
//   msleep(ms)
//   readByte/readDword/readQword/readFloat/readDouble/readPtr/readBytes/readString
//   writeByte/writeDword/writeQword/writeFloat/writeDouble/writePtr/writeBytes/writeString

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
#include <vector>
#include <unistd.h>

extern "C" {
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
}

#include "dobby.h"
#include "xdl.h"

namespace LuaEngine {

namespace {

// 自包含的内存辅助函数（对应 agent/jni/memTool/MemModify_tool.h，
// 但使用内部链接，因此该头文件可安全地被多个
// 编译单元包含）。
inline int GetProtFromMaps(uintptr_t addr) {
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
    if (addr == 0 || !data || size == 0) return false;
    long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = addr & ~((uintptr_t)page_size - 1);
    uintptr_t page_end = (addr + size + page_size - 1) & ~((uintptr_t)page_size - 1);
    int orig = GetProtFromMaps(addr);
    int want = orig | PROT_WRITE;
    if (mprotect((void*)page_start, page_end - page_start, want) != 0) return false;
    memcpy((void*)addr, data, size);
#if defined(__arm__) || defined(__aarch64__)
    __builtin___clear_cache((char*)addr, (char*)addr + size);
#endif
    mprotect((void*)page_start, page_end - page_start, orig);
    return true;
}

inline uintptr_t LuaReadPtr(uintptr_t addr) {
    uintptr_t v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    return v;
}

} // 匿名命名空间

inline lua_State* L = nullptr;

// LuaJIT 不是线程安全的；对 L 的每次访问都经过此互斥锁。
// 递归锁：Lua 脚本可能调用被 hook 的函数，从而在 lua_pcall
// 进行中时从 Dobby 回调重新进入引擎。
inline std::recursive_mutex g_luaMutex;

inline std::mutex g_logMutex;
inline std::vector<std::string> g_logMessages;

inline std::map<uintptr_t, int> g_luaCallbacks;  // hookCPU：addr -> registry 引用
inline std::set<uintptr_t> g_hookAddrs;          // hookfunc：已安装的地址集合
inline std::map<std::string, uintptr_t> g_baseCache;

// 主线程（渲染循环）任务队列，由 eglSwapBuffers hook 泵出。
inline std::mutex g_mainCallMutex;
inline std::vector<int> g_mainCallRefs;

inline void PushLog(const std::string& msg);
inline void ProcessMainThreadTasks();

// ProcessMainThreadTasks 的可选泵：hook eglSwapBuffers（游戏每帧
// 调用一次），在那里运行排队的 "call" 任务。
typedef int (*EglSwapBuffers_t)(void*, void*);
inline EglSwapBuffers_t g_origSwapBuffers = nullptr;

inline int SwapBuffersHook(void* dpy, void* surface) {
    int ret = g_origSwapBuffers ? g_origSwapBuffers(dpy, surface) : 0;
    ProcessMainThreadTasks();
    return ret;
}

inline void InstallMainThreadHook() {
    void* sym = DobbySymbolResolver("libEGL.so", "eglSwapBuffers");
    if (!sym) return;
    void* orig = nullptr;
    if (DobbyHook(sym, (void*)SwapBuffersHook, &orig) == 0 && orig) {
        g_origSwapBuffers = (EglSwapBuffers_t)orig;
        PushLog("[Lua] 已挂载 eglSwapBuffers 主线程泵");
    }
}

// ---------- 日志 ----------
inline void PushLog(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_logMessages.push_back(msg);
}

inline std::vector<std::string> TakeLogsSince(size_t from) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (from >= g_logMessages.size()) return {};
    return std::vector<std::string>(g_logMessages.begin() + from, g_logMessages.end());
}

// ---------- Dobby instrument 回调 ----------
inline void DobbyHandler(RegisterContext* ctx, const HookEntryInfo* info) {
    if (!L) return;
    std::lock_guard<std::recursive_mutex> lock(g_luaMutex);
    uintptr_t func_addr = (uintptr_t)info->function_address;
    auto it = g_luaCallbacks.find(func_addr);
    if (it == g_luaCallbacks.end()) return;
    lua_rawgeti(L, LUA_REGISTRYINDEX, it->second);
    lua_pushlightuserdata(L, ctx);
    lua_pushinteger(L, (lua_Integer)func_addr);
    if (lua_pcall(L, 2, 0, 0) != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        PushLog(std::string("[Hook错误] ") + (err ? err : "未知错误"));
        lua_pop(L, 1);
    }
}

// ---------- Lua：print ----------
inline int Lua_Print(lua_State* Ls) {
    int n = lua_gettop(Ls);
    std::string out = "[Lua] ";
    for (int i = 1; i <= n; i++) {
        size_t len = 0;
        const char* s = lua_tolstring(Ls, i, &len);
        if (s) out.append(s, len);
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

    g_baseCache[name] = addr;
    lua_pushinteger(Ls, (lua_Integer)addr);
    return 1;
}

// ---------- Lua：hookCPU（DobbyInstrument）----------
inline int Lua_Hook(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    if (addr == 0) return 0;
    luaL_checktype(Ls, 2, LUA_TFUNCTION);
    int ref = luaL_ref(Ls, LUA_REGISTRYINDEX);
    g_luaCallbacks[addr] = ref;
    int ret = DobbyInstrument((void*)addr, DobbyHandler);
    if (ret != 0) {
        luaL_unref(Ls, LUA_REGISTRYINDEX, ref);
        g_luaCallbacks.erase(addr);
        lua_pushstring(Ls, "hookCPU failed, DobbyInstrument returned nonzero");
        return lua_error(Ls);
    }
    return 0;
}

// ---------- Lua：hookfunc（DobbyHook 替换）----------
inline int Lua_HookReplace(lua_State* Ls) {
    uintptr_t target = (uintptr_t)luaL_checkinteger(Ls, 1);
    uintptr_t replace = (uintptr_t)luaL_checkinteger(Ls, 2);
    void* trampoline = nullptr;
    int ret = DobbyHook((void*)target, (void*)replace, &trampoline);
    if (ret == 0) g_hookAddrs.insert(target);
    lua_pushinteger(Ls, (lua_Integer)(uintptr_t)trampoline);
    lua_pushboolean(Ls, ret == 0);
    return 2;
}

// ---------- Lua：removehook ----------
inline int Lua_HookUnhook(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    int ret = DobbyDestroy((void*)addr);
    if (ret == 0) g_hookAddrs.erase(addr);
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
    g_hookAddrs.clear();
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
    std::lock_guard<std::recursive_mutex> lock(g_luaMutex);
    std::vector<int> tasks;
    {
        std::lock_guard<std::mutex> lk(g_mainCallMutex);
        tasks.swap(g_mainCallRefs);
    }
    for (int ref : tasks) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
        if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
            const char* err = lua_tostring(L, -1);
            PushLog(std::string("[主线程调用错误] ") + (err ? err : "未知错误"));
            lua_pop(L, 1);
        }
        luaL_unref(L, LUA_REGISTRYINDEX, ref);
    }
}

inline int Lua_CallOnMain(lua_State* Ls) {
    luaL_checktype(Ls, 1, LUA_TFUNCTION);
    lua_pushvalue(Ls, 1);
    int ref = luaL_ref(Ls, LUA_REGISTRYINDEX);
    {
        std::lock_guard<std::mutex> lock(g_mainCallMutex);
        g_mainCallRefs.push_back(ref);
    }
    return 0;
}

// ---------- Lua：msleep ----------
inline int Lua_Msleep(lua_State* Ls) {
    int ms = (int)luaL_checkinteger(Ls, 1);
    if (ms < 0) ms = 0;
    if (ms > 60000) ms = 60000;
    usleep((useconds_t)ms * 1000);
    return 0;
}

// ---------- Lua：内存辅助函数 ----------
inline int Lua_ReadByte(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    uint8_t v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    lua_pushinteger(Ls, (lua_Integer)v);
    return 1;
}

inline int Lua_ReadDword(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    uint32_t v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    lua_pushinteger(Ls, (lua_Integer)v);
    return 1;
}

inline int Lua_ReadQword(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    uint64_t v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    lua_pushinteger(Ls, (lua_Integer)v);
    return 1;
}

inline int Lua_ReadFloat(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    float v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    lua_pushnumber(Ls, (lua_Number)v);
    return 1;
}

inline int Lua_ReadDouble(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    double v = 0;
    memcpy(&v, (const void*)addr, sizeof(v));
    lua_pushnumber(Ls, (lua_Number)v);
    return 1;
}

inline int Lua_ReadPtr(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    uintptr_t v = LuaReadPtr(addr);
    lua_pushinteger(Ls, (lua_Integer)v);
    return 1;
}

inline int Lua_ReadBytes(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    int len = (int)luaL_checkinteger(Ls, 2);
    if (len < 0) len = 0;
    if (len > 65536) len = 65536;
    lua_pushlstring(Ls, (const char*)addr, (size_t)len);
    return 1;
}

inline int Lua_ReadString(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    int max = (int)luaL_optinteger(Ls, 2, 256);
    if (max < 1) max = 1;
    if (max > 65536) max = 65536;
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

inline int Lua_WriteByte(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    int64_t v = (int64_t)luaL_checkinteger(Ls, 2);
    uint8_t b = (uint8_t)v;
    lua_pushboolean(Ls, LuaWriteMemory(addr, &b, 1));
    return 1;
}

inline int Lua_WriteDword(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    int64_t v = (int64_t)luaL_checkinteger(Ls, 2);
    uint32_t w = (uint32_t)v;
    lua_pushboolean(Ls, LuaWriteMemory(addr, &w, sizeof(w)));
    return 1;
}

inline int Lua_WriteQword(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    int64_t v = (int64_t)luaL_checkinteger(Ls, 2);
    uint64_t q = (uint64_t)v;
    lua_pushboolean(Ls, LuaWriteMemory(addr, &q, sizeof(q)));
    return 1;
}

inline int Lua_WriteFloat(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    double v = (double)luaL_checknumber(Ls, 2);
    float f = (float)v;
    lua_pushboolean(Ls, LuaWriteMemory(addr, &f, sizeof(f)));
    return 1;
}

inline int Lua_WriteDouble(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    double v = (double)luaL_checknumber(Ls, 2);
    lua_pushboolean(Ls, LuaWriteMemory(addr, &v, sizeof(v)));
    return 1;
}

inline int Lua_WritePtr(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    int64_t v = (int64_t)luaL_checkinteger(Ls, 2);
    uintptr_t p = (uintptr_t)v;
    lua_pushboolean(Ls, LuaWriteMemory(addr, &p, sizeof(p)));
    return 1;
}

inline int Lua_WriteBytes(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    size_t len = 0;
    const char* data = luaL_checklstring(Ls, 2, &len);
    lua_pushboolean(Ls, LuaWriteMemory(addr, data, len));
    return 1;
}

inline int Lua_WriteString(lua_State* Ls) {
    uintptr_t addr = (uintptr_t)luaL_checkinteger(Ls, 1);
    size_t len = 0;
    const char* data = luaL_checklstring(Ls, 2, &len);
    std::vector<char> buf(len + 1, 0);
    memcpy(buf.data(), data, len);
    lua_pushboolean(Ls, LuaWriteMemory(addr, buf.data(), len + 1));
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

    std::lock_guard<std::recursive_mutex> lock(g_luaMutex);
    size_t log_from = 0;
    {
        std::lock_guard<std::mutex> lk(g_logMutex);
        log_from = g_logMessages.size();
    }

    std::string code = script;
    ReplaceAll(code, u8"\u201C", "\"");  // "
    ReplaceAll(code, u8"\u201D", "\"");  // "
    ReplaceAll(code, u8"\u2018", "'");   // '
    ReplaceAll(code, u8"\u2019", "'");   // '
    ReplaceAll(code, u8"\uFF08", "(");   // (
    ReplaceAll(code, u8"\uFF09", ")");   // )
    ReplaceAll(code, u8"\uFF1B", ";");   // ;
    ReplaceAll(code, u8"\uFF1A", ":");   // :
    ReplaceAll(code, u8"\uFF0C", ",");   // ,
    ReplaceAll(code, u8"\u3002", ".");   // .
    ReplaceAll(code, u8"\u3000", " ");   // 全角空格
    ReplaceAll(code, u8"\uFF1D", "=");   // =
    ReplaceAll(code, u8"\uFF1C", "<");   // <
    ReplaceAll(code, u8"\uFF1E", ">");   // >
    ReplaceAll(code, u8"\uFF0B", "+");   // +
    ReplaceAll(code, u8"\uFF0D", "-");   // -
    ReplaceAll(code, u8"\uFF0A", "*");   // *
    ReplaceAll(code, u8"\uFF0F", "/");   // /
    ReplaceAll(code, u8"\uFF1F", "?");   // ?
    ReplaceAll(code, u8"\uFF01", "!");   // !
    ReplaceAll(code, u8"\uFF3B", "[");   // [
    ReplaceAll(code, u8"\uFF3D", "]");   // ]
    ReplaceAll(code, u8"\uFF5B", "{");   // {
    ReplaceAll(code, u8"\uFF5D", "}");   // }

    int rc = luaL_dostring(L, code.c_str());
    std::string err;
    if (rc != LUA_OK) {
        const char* e = lua_tostring(L, -1);
        err = e ? e : "未知错误";
        lua_pop(L, 1);
    }

    std::vector<std::string> logs = TakeLogsSince(log_from);
    std::string out;
    for (const auto& s : logs) out += s + "\n";
    if (!err.empty()) out += "[Lua 错误] " + err + "\n";
    if (rc == LUA_OK && logs.empty()) out += "[Lua] 执行成功\n";
    return out;
}

// ---------- 初始化 ----------
inline void Init() {
    std::lock_guard<std::recursive_mutex> lock(g_luaMutex);
    if (L) return;

    L = luaL_newstate();
    if (!L) {
        PushLog("[Lua] 初始化失败: luaL_newstate 返回 null");
        return;
    }
    luaL_openlibs(L);

    lua_pushcfunction(L, Lua_Print);          lua_setglobal(L, "print");
    lua_pushcfunction(L, Lua_GetBase);        lua_setglobal(L, "getBase");
    lua_pushcfunction(L, Lua_Hook);           lua_setglobal(L, "hookCPU");
    lua_pushcfunction(L, Lua_HookReplace);    lua_setglobal(L, "hookfunc");
    lua_pushcfunction(L, Lua_HookUnhook);     lua_setglobal(L, "removehook");
    lua_pushcfunction(L, Lua_RemoveAllHooks); lua_setglobal(L, "remove_all_hook");
    lua_pushcfunction(L, Lua_CallOnMain);     lua_setglobal(L, "call");
    lua_pushcfunction(L, Lua_Msleep);         lua_setglobal(L, "msleep");

    lua_pushcfunction(L, Lua_ReadByte);   lua_setglobal(L, "readByte");
    lua_pushcfunction(L, Lua_ReadDword);  lua_setglobal(L, "readDword");
    lua_pushcfunction(L, Lua_ReadQword);  lua_setglobal(L, "readQword");
    lua_pushcfunction(L, Lua_ReadFloat);  lua_setglobal(L, "readFloat");
    lua_pushcfunction(L, Lua_ReadDouble); lua_setglobal(L, "readDouble");
    lua_pushcfunction(L, Lua_ReadPtr);    lua_setglobal(L, "readPtr");
    lua_pushcfunction(L, Lua_ReadBytes);  lua_setglobal(L, "readBytes");
    lua_pushcfunction(L, Lua_ReadString); lua_setglobal(L, "readString");
    lua_pushcfunction(L, Lua_WriteByte);  lua_setglobal(L, "writeByte");
    lua_pushcfunction(L, Lua_WriteDword); lua_setglobal(L, "writeDword");
    lua_pushcfunction(L, Lua_WriteQword); lua_setglobal(L, "writeQword");
    lua_pushcfunction(L, Lua_WriteFloat); lua_setglobal(L, "writeFloat");
    lua_pushcfunction(L, Lua_WriteDouble);lua_setglobal(L, "writeDouble");
    lua_pushcfunction(L, Lua_WritePtr);   lua_setglobal(L, "writePtr");
    lua_pushcfunction(L, Lua_WriteBytes); lua_setglobal(L, "writeBytes");
    lua_pushcfunction(L, Lua_WriteString);lua_setglobal(L, "writeString");

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

    InstallMainThreadHook();
    PushLog("[Lua] 引擎就绪 (LuaJIT + Dobby)");
}

// ---------- 重置 ----------
inline void Reset() {
    std::lock_guard<std::recursive_mutex> lock(g_luaMutex);
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

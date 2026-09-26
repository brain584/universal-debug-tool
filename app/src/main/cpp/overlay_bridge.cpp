// 原生悬浮窗（Android View 版）的 JNI 桥接层。
// 复用 native-lib.cpp 的 su 读写/注入器与 memsearch 搜索引擎，
// 与 ImGui 界面（main_ui.cpp）完全独立，互不共享状态。

#include <jni.h>
#include <android/log.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "MemSu.hpp"
#include "Search.hpp"
// 注意：MemToolTypes.h 的 RANGE_* 宏会破坏 ProcMap.hpp 的枚举，
// 必须在 memsearch 头之后包含（历史已知坑）。
#include "MemToolTypes.h"

// native-lib.cpp 提供的全局函数（非 static）。
extern std::string RunSuCommand(const std::string& cmd);
extern std::string RunInjector(const std::string& pkg);
extern std::string RunInjectorPid(int pid);
extern std::string RunInjectorArgs(const std::string& args);
extern std::string ReadRemoteMaps(int pid);

// SO 通道：ImGui 侧同一加密 socket 客户端实现（悬浮窗脚本页复用）。
#include "socket/socket.h"
static SocketClient g_ov_socket;
extern bool ReadRemoteBytes(int pid, uintptr_t addr, void* buf, size_t n);
extern bool ReadRemoteChunk(int pid, uintptr_t addr, void* buf, size_t n);
extern bool ReadRemotePages(int pid, const std::vector<uintptr_t>& pages,
                            std::vector<uint8_t>& out);
extern bool WriteRemoteDword(int pid, uintptr_t addr, uint32_t value);

#define OLOG(...) __android_log_print(ANDROID_LOG_INFO, "ATraceBridge", __VA_ARGS__)

namespace {

struct Hit {
    uintptr_t addr = 0;
    uint64_t raw = 0;
};

std::mutex g_mux;
std::vector<Hit> g_hits;
std::string g_status = "就绪";
std::atomic<bool> g_running{false};
int g_pid = 0;
int g_type = TYPE_DWORD;

constexpr size_t kMaxExact = 200000;
constexpr size_t kMaxFuzzy = 1000000;
constexpr size_t kChunk = 256 * 1024;

// 搜索值解析（支持 100 / 0x64 / 10~20），与 ImGui 侧语义一致。
bool ParseNum(const std::string& s, bool isFloat, int64_t& iv, double& dv) {
    const char* p = s.c_str();
    while (*p && isspace((unsigned char)*p)) p++;
    if (!*p) return false;
    if (isFloat) {
        char* e = nullptr;
        dv = strtod(p, &e);
        return e && !*e;
    }
    bool hex = p[0] == '0' && (p[1] == 'x' || p[1] == 'X');
    char* e = nullptr;
    iv = strtoll(p, &e, hex ? 16 : 10);
    return e && !*e;
}

bool ParseTarget(const std::string& str, int type, int64_t& iv, double& dv,
                 bool& isRange, int64_t& imin, int64_t& imax,
                 double& dmin, double& dmax) {
    if (str.empty()) return false;
    bool isFloat = (type == TYPE_FLOAT || type == TYPE_DOUBLE);
    size_t tilde = str.find('~');
    if (tilde != std::string::npos) {
        isRange = true;
        auto trim = [](std::string s) {
            size_t b = s.find_first_not_of(" \t");
            if (b == std::string::npos) return std::string();
            return s.substr(b, s.find_last_not_of(" \t") - b + 1);
        };
        return ParseNum(trim(str.substr(0, tilde)), isFloat, imin, dmin) &&
               ParseNum(trim(str.substr(tilde + 1)), isFloat, imax, dmax);
    }
    isRange = false;
    return ParseNum(str, isFloat, iv, dv);
}

void SetStatus(const std::string& s) {
    std::lock_guard<std::mutex> lk(g_mux);
    g_status = s;
}

// 按类型掩码过滤区域 id；掩码 0 = 全部。
uint32_t AreasToMask(const std::vector<int>& areas) {
    uint32_t mask = 0;
    for (int a : areas) {
        if (a == RANGE_ALL) return 0;
        mask |= (a == RANGE_OTHER) ? (1u << 31) : (uint32_t)a;
    }
    return mask;
}

// 批量读取命中地址的当前值（一次 su 取回涉及的全部页面）。
bool ReadHitValues(int pid, const std::vector<Hit>& hits, int type,
                   std::vector<uint8_t>& values) {
    int stride = MemTypeSize(type);
    std::vector<uintptr_t> pv;
    pv.reserve(hits.size() * 2);
    for (const auto& h : hits) {
        uintptr_t pg = h.addr & ~(uintptr_t)4095;
        pv.push_back(pg);
        if (((h.addr & 4095) + (uintptr_t)stride) > 4096)
            pv.push_back(pg + 4096);
    }
    std::sort(pv.begin(), pv.end());
    pv.erase(std::unique(pv.begin(), pv.end()), pv.end());
    if (pv.empty()) return false;
    if (!ReadRemotePages(pid, pv, values)) return false;
    // 重新排布为与 hits 对齐的值数组。
    std::vector<uint8_t> packed(hits.size() * (size_t)stride);
    for (size_t i = 0; i < hits.size(); ++i) {
        uintptr_t pg = hits[i].addr & ~(uintptr_t)4095;
        size_t pi = (size_t)(std::lower_bound(pv.begin(), pv.end(), pg) -
                             pv.begin());
        size_t off = (size_t)(hits[i].addr & 4095);
        uint8_t* dst = packed.data() + i * (size_t)stride;
        if (off + (size_t)stride <= 4096) {
            memcpy(dst, values.data() + pi * 4096 + off, (size_t)stride);
        } else {
            size_t first = 4096 - off;
            memcpy(dst, values.data() + pi * 4096 + off, first);
            memcpy(dst + first, values.data() + (pi + 1) * 4096,
                   (size_t)stride - first);
        }
    }
    values.swap(packed);
    return true;
}

jstring ToJString(JNIEnv* env, const std::string& s) {
    return env->NewStringUTF(s.c_str());
}

} // namespace

extern "C" {

// ── 进程 / 注入 / 系统 ─────────────────────────────────────────────

// su 扫描 /proc：仅用 shell 内建命令（与 ImGui 侧 ScanRooted 同一
// 脚本，mksh 兼容——不能用 bash 的 read -d），输出 "pid|uid|cmdline" 行。
JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_scanProcesses(JNIEnv* env, jobject) {
    std::string script =
        "for d in /proc/[0-9]*; do pid=${d##*/}; "
        "read -r cmd < \"$d/cmdline\" 2>/dev/null; uid=; "
        "while IFS= read -r line; do case \"$line\" in "
        "Uid:*) set -- $line; uid=$2; break;; esac; "
        "done < \"$d/status\" 2>/dev/null; "
        "[ -n \"$cmd\" ] && echo \"$pid|$uid|$cmd\"; done";
    return ToJString(env, RunSuCommand(script));
}

JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_injectPkg(JNIEnv* env, jobject,
                                                    jstring pkg) {
    const char* p = pkg ? env->GetStringUTFChars(pkg, nullptr) : "";
    std::string out = RunInjector(p ? p : "");
    if (p) env->ReleaseStringUTFChars(pkg, p);
    return ToJString(env, out);
}

JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_injectPid(JNIEnv* env, jobject,
                                                    jint pid) {
    return ToJString(env, RunInjectorPid(pid));
}

JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_killProcess(JNIEnv* env, jobject,
                                                      jint pid) {
    return ToJString(env, RunSuCommand("kill -9 " + std::to_string(pid)));
}

// 目标进程是否仍存活。使用 kill(pid, 0)：普通应用对其他 uid 的进程
// 会得到 EPERM（表示进程存在），仅 ESRCH 表示已退出；无需 su。
JNIEXPORT jboolean JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_procAlive(JNIEnv*, jobject,
                                                    jint pid) {
    if (pid <= 0) return JNI_FALSE;
    if (kill((pid_t)pid, 0) == 0) return JNI_TRUE;
    return errno == EPERM ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_suCmd(JNIEnv* env, jobject,
                                                jstring cmd) {
    const char* c = cmd ? env->GetStringUTFChars(cmd, nullptr) : "";
    std::string out = RunSuCommand(c ? c : "");
    if (c) env->ReleaseStringUTFChars(cmd, c);
    return ToJString(env, out);
}

// ── SO 通道（agent 加密 socket，与 ImGui 侧同一实现）──────────────

JNIEXPORT void JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_socketSetTarget(JNIEnv* env,
                                                          jobject,
                                                          jstring pkg) {
    const char* p = pkg ? env->GetStringUTFChars(pkg, nullptr) : "";
    g_ov_socket.SetTargetPackage(p ? p : "");
    if (p) env->ReleaseStringUTFChars(pkg, p);
}

JNIEXPORT void JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_socketConnect(JNIEnv*, jobject) {
    g_ov_socket.ConnectAsync();
}

JNIEXPORT void JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_socketDisconnect(JNIEnv*, jobject) {
    g_ov_socket.Disconnect();
}

JNIEXPORT jboolean JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_socketIsConnected(JNIEnv*, jobject) {
    return g_ov_socket.IsConnected() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_socketStatus(JNIEnv* env, jobject) {
    return ToJString(env, g_ov_socket.StatusText());
}

// 执行 Lua 脚本并返回响应（超时 20s）。
JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_socketSendLua(JNIEnv* env, jobject,
                                                        jstring script) {
    const char* s = script ? env->GetStringUTFChars(script, nullptr) : "";
    std::string out = g_ov_socket.SendCommand(
        std::string("lua ") + (s ? s : ""), 20000);
    if (s) env->ReleaseStringUTFChars(script, s);
    return ToJString(env, out);
}

// 远程分配内存页：注入器 --alloc 模式，返回 "0x<地址>" 或错误文本。
JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_allocRemote(JNIEnv* env, jobject,
                                                      jint pid, jlong size,
                                                      jstring prot) {
    const char* p = prot ? env->GetStringUTFChars(prot, nullptr) : "rw";
    std::string args = "-i " + std::to_string(pid) + " --alloc " +
                       std::to_string((unsigned long long)size) +
                       " --prot " + (p ? p : "rw");
    if (p) env->ReleaseStringUTFChars(prot, p);
    std::string out = RunInjectorArgs(args);
    // 提取 "ALLOC 0x..." 的地址部分。
    size_t pos = out.find("ALLOC 0x");
    if (pos != std::string::npos) {
        std::string addr = out.substr(pos + 6);
        while (!addr.empty() && (addr.back() == '\n' || addr.back() == '\r'))
            addr.pop_back();
        return ToJString(env, addr);
    }
    return ToJString(env, "ERR:" + out);
}

// ── 内存读写 ────────────────────────────────────────────────────────

JNIEXPORT jboolean JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_memWrite(JNIEnv* env, jobject,
                                                   jint pid, jlong addr,
                                                   jbyteArray data) {
    jsize len = env->GetArrayLength(data);
    if (len <= 0) return JNI_TRUE;
    std::vector<uint8_t> buf((size_t)len);
    env->GetByteArrayRegion(data, 0, len,
                            reinterpret_cast<jbyte*>(buf.data()));
    uintptr_t a = (uintptr_t)addr;
    size_t off = 0;
    // 4 字节对齐整字写入。
    while (len - off >= 4) {
        uint32_t w = 0;
        memcpy(&w, buf.data() + off, 4);
        if (!WriteRemoteDword(pid, a + off, w)) return JNI_FALSE;
        off += 4;
    }
    // 尾部字节：读改写所在 dword。
    if (off < (size_t)len) {
        size_t rem = (size_t)len - off;
        uint32_t w = 0;
        ReadRemoteBytes(pid, a + off, &w, 4);
        memcpy(&w, buf.data() + off, rem);
        if (!WriteRemoteDword(pid, a + off, w)) return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT jbyteArray JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_memRead(JNIEnv* env, jobject,
                                                  jint pid, jlong addr,
                                                  jint len) {
    if (len <= 0) return nullptr;
    std::vector<uint8_t> buf((size_t)len, 0);
    if (!ReadRemoteBytes(pid, (uintptr_t)addr, buf.data(), (size_t)len))
        return nullptr;
    jbyteArray arr = env->NewByteArray(len);
    env->SetByteArrayRegion(arr, 0, len,
                            reinterpret_cast<const jbyte*>(buf.data()));
    return arr;
}

// 目标进程 maps 中第一块可读区域起点，供内存页默认定位。
JNIEXPORT jlong JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_memFirstAddress(JNIEnv*, jobject,
                                                          jint pid) {
    std::string maps = ReadRemoteMaps(pid);
    if (maps.empty()) return 0;
    size_t pos = 0;
    while (pos < maps.size()) {
        size_t e = maps.find('\n', pos);
        if (e == std::string::npos) e = maps.size();
        std::string line = maps.substr(pos, e - pos);
        pos = e + 1;
        if (line.size() < 20) continue;
        unsigned long long a = 0, b = 0;
        if (sscanf(line.c_str(), "%llx-%llx", &a, &b) != 2 || b <= a)
            continue;
        // 权限段形如 "r-xp"，仅取可读区域。
        if (line.find(" r") == std::string::npos) continue;
        return (jlong)a;
    }
    return 0;
}

// ── 搜索状态 ────────────────────────────────────────────────────────

JNIEXPORT jint JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_searchCount(JNIEnv*, jobject) {
    std::lock_guard<std::mutex> lk(g_mux);
    return (jint)g_hits.size();
}

JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_searchStatus(JNIEnv* env, jobject) {
    std::lock_guard<std::mutex> lk(g_mux);
    return ToJString(env, g_status);
}

JNIEXPORT jboolean JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_searchRunning(JNIEnv*, jobject) {
    return g_running ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_searchReset(JNIEnv*, jobject) {
    std::lock_guard<std::mutex> lk(g_mux);
    g_hits.clear();
    g_status = "就绪";
}

// 取一页结果："addr|rawhex" 行，同时刷新为当前内存值。
JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_searchPage(JNIEnv* env, jobject,
                                                     jint offset, jint count) {
    std::vector<Hit> slice;
    int type;
    int pid;
    {
        std::lock_guard<std::mutex> lk(g_mux);
        if (offset < 0 || (size_t)offset >= g_hits.size()) return ToJString(env, "");
        size_t end = std::min(g_hits.size(), (size_t)(offset + count));
        slice.assign(g_hits.begin() + offset, g_hits.begin() + end);
        type = g_type;
        pid = g_pid;
    }
    if (slice.empty()) return ToJString(env, "");
    std::vector<uint8_t> vals;
    if (ReadHitValues(pid, slice, type, vals)) {
        std::lock_guard<std::mutex> lk(g_mux);
        int stride = MemTypeSize(type);
        for (size_t i = 0; i < slice.size(); ++i) {
            uint64_t v = 0;
            memcpy(&v, vals.data() + i * (size_t)stride,
                   (size_t)stride);
            slice[i].raw = v;
        }
        // 回写当前值到全局结果（供后续过滤使用最新值）。
        size_t base = (size_t)offset;
        for (size_t i = 0; i < slice.size() && base + i < g_hits.size(); ++i)
            g_hits[base + i].raw = slice[i].raw;
    }
    std::string out;
    char line[64];
    for (const auto& h : slice) {
        snprintf(line, sizeof(line), "%llx|%016llx",
                 (unsigned long long)h.addr, (unsigned long long)h.raw);
        out += line;
        out += '\n';
    }
    return ToJString(env, out);
}

// ── 精确搜索 ────────────────────────────────────────────────────────

JNIEXPORT void JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_searchStart(
    JNIEnv* env, jobject, jint pid, jint type, jstring value,
    jintArray areas) {
    if (g_running.exchange(true)) return;
    const char* vs = value ? env->GetStringUTFChars(value, nullptr) : "";
    std::string valueStr = vs ? vs : "";
    if (vs) env->ReleaseStringUTFChars(value, vs);

    jsize na = areas ? env->GetArrayLength(areas) : 0;
    std::vector<int> areaV(na);
    if (areas)
        env->GetIntArrayRegion(areas, 0, na, reinterpret_cast<jint*>(areaV.data()));

    g_pid = pid;
    g_type = type;
    SetStatus("搜索中...");
    std::thread([pid, type, valueStr, areaV] {
        auto t0 = std::chrono::steady_clock::now();
        std::vector<Hit> hits;
        hits.reserve(8192);

        int64_t iv = 0, imin = 0, imax = 0;
        double dv = 0, dmin = 0, dmax = 0;
        bool isRange = false;
        if (!ParseTarget(valueStr, type, iv, dv, isRange, imin, imax,
                         dmin, dmax)) {
            SetStatus("搜索值格式错误 (支持 100 / 0x64 / 10~20)");
            g_running.store(false);
            return;
        }
        bool isFloat = (type == TYPE_FLOAT || type == TYPE_DOUBLE);
        try {
            MemSu mem(pid);
            SearchEngine engine(mem);
            SearchParams params;
            params.memTypeMask = AreasToMask(areaV);
            params.maxResults = kMaxExact;
            params.align = true;
            params.parallel = true;
            params.numThreads = 4;
            bool capped = false;
            auto collect = [&](uintptr_t addr, uint64_t raw) {
                if (hits.size() >= kMaxExact) { capped = true; return; }
                hits.push_back({addr, raw});
            };
            auto runSearch = [&](auto* tag) {
                using T = std::decay_t<decltype(*tag)>;
                if (isRange) {
                    long double lo = isFloat ? (long double)dmin
                                             : (long double)imin;
                    long double hi = isFloat ? (long double)dmax
                                             : (long double)imax;
                    if (lo < (long double)std::numeric_limits<T>::lowest() ||
                        hi > (long double)std::numeric_limits<T>::max())
                        return;
                    auto rs = engine.searchRange<T>(params, (T)lo, (T)hi);
                    for (const auto& r : rs.results()) {
                        if (capped) break;
                        uint64_t raw = 0;
                        memcpy(&raw, &r.value, sizeof(T));
                        collect(r.address, raw);
                    }
                } else {
                    long double v = isFloat ? (long double)dv : (long double)iv;
                    auto rs = engine.search<T>(params, (T)v);
                    for (const auto& r : rs.results()) {
                        if (capped) break;
                        uint64_t raw = 0;
                        memcpy(&raw, &r.value, sizeof(T));
                        collect(r.address, raw);
                    }
                }
            };
            switch (type) {
            case TYPE_BYTE:   runSearch((int8_t*)nullptr);  break;
            case TYPE_WORD:   runSearch((int16_t*)nullptr); break;
            case TYPE_DWORD:  runSearch((int32_t*)nullptr); break;
            case TYPE_QWORD:  runSearch((int64_t*)nullptr); break;
            case TYPE_FLOAT:  runSearch((float*)nullptr);   break;
            case TYPE_DOUBLE: runSearch((double*)nullptr);  break;
            }
            double sec = std::chrono::duration<double>(
                             std::chrono::steady_clock::now() - t0).count();
            char msg[160];
            snprintf(msg, sizeof(msg),
                     "精确搜索完成: %zu 个结果%s (耗时 %.1fs)",
                     hits.size(), capped ? " (已达上限)" : "", sec);
            std::lock_guard<std::mutex> lk(g_mux);
            g_hits = std::move(hits);
            g_status = msg;
        } catch (const std::exception& ex) {
            SetStatus(std::string("搜索异常: ") + ex.what());
        }
        g_running.store(false);
    }).detach();
}

// ── 模糊搜索 ────────────────────────────────────────────────────────

JNIEXPORT void JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_fuzzyStart(JNIEnv* env, jobject,
                                                     jint pid, jint type,
                                                     jintArray areas) {
    if (g_running.exchange(true)) return;
    jsize na = areas ? env->GetArrayLength(areas) : 0;
    std::vector<int> areaV(na);
    if (areas)
        env->GetIntArrayRegion(areas, 0, na, reinterpret_cast<jint*>(areaV.data()));
    g_pid = pid;
    g_type = type;
    SetStatus("模糊搜索初始化中...");
    std::thread([pid, type, areaV] {
        auto t0 = std::chrono::steady_clock::now();
        std::vector<Hit> hits;
        hits.reserve(100000);
        std::string maps = ReadRemoteMaps(pid);
        if (maps.empty()) {
            SetStatus("maps 读取为空 (需要 root？目标已退出？)");
            g_running.store(false);
            return;
        }
        int stride = MemTypeSize(type);
        std::vector<uint8_t> buf(kChunk);
        bool capped = false;
        size_t pos = 0;
        while (pos < maps.size()) {
            size_t e = maps.find('\n', pos);
            if (e == std::string::npos) e = maps.size();
            std::string line = maps.substr(pos, e - pos);
            pos = e + 1;
            if (line.size() < 20) continue;
            unsigned long long a = 0, b = 0;
            if (sscanf(line.c_str(), "%llx-%llx", &a, &b) != 2 || b <= a)
                continue;
            bool ok = false;
            for (int aid : areaV)
                if (BCMAPSFLAG(line.c_str(), aid)) { ok = true; break; }
            if (!ok) continue;
            uintptr_t start = (a + 4095) & ~(uintptr_t)4095;
            uintptr_t end = b & ~(uintptr_t)4095;
            for (uintptr_t addr = start; addr < end && !capped;
                 addr += kChunk) {
                size_t want = (size_t)std::min<uintptr_t>(kChunk, end - addr);
                if (!ReadRemoteChunk(pid, addr, buf.data(), want)) continue;
                for (size_t i = 0; i + (size_t)stride <= want;
                     i += (size_t)stride) {
                    uint64_t v = 0;
                    memcpy(&v, buf.data() + i, (size_t)stride);
                    hits.push_back({addr + i, v});
                    if (hits.size() >= kMaxFuzzy) { capped = true; break; }
                }
            }
        }
        double sec = std::chrono::duration<double>(
                         std::chrono::steady_clock::now() - t0).count();
        char msg[160];
        snprintf(msg, sizeof(msg), "模糊搜索初始化完成: %zu 个地址%s (耗时 %.1fs)",
                 hits.size(), capped ? " (已达上限)" : "", sec);
        std::lock_guard<std::mutex> lk(g_mux);
        g_hits = std::move(hits);
        g_status = msg;
        g_running.store(false);
    }).detach();
}

// op: 0=未变化 1=已变化 2=变大 3=变小
JNIEXPORT void JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_fuzzyFilter(JNIEnv*, jobject,
                                                      jint op) {
    if (g_running.exchange(true)) return;
    SetStatus("过滤中...");
    std::thread([op] {
        auto t0 = std::chrono::steady_clock::now();
        std::vector<Hit> hits;
        int pid;
        int type;
        {
            std::lock_guard<std::mutex> lk(g_mux);
            hits = g_hits;
            pid = g_pid;
            type = g_type;
        }
        if (hits.empty()) {
            SetStatus("请先初始化模糊搜索");
            g_running.store(false);
            return;
        }
        std::vector<uint8_t> vals;
        if (!ReadHitValues(pid, hits, type, vals)) {
            SetStatus("读取当前值失败 (目标已退出？)");
            g_running.store(false);
            return;
        }
        int stride = MemTypeSize(type);
        bool isFloat = (type == TYPE_FLOAT || type == TYPE_DOUBLE);
        std::vector<Hit> kept;
        kept.reserve(hits.size() / 2);
        for (size_t i = 0; i < hits.size(); ++i) {
            uint64_t cur = 0;
            memcpy(&cur, vals.data() + i * (size_t)stride, (size_t)stride);
            uint64_t old = hits[i].raw;
            bool keep = false;
            if (isFloat) {
                float cf, of;
                memcpy(&cf, &cur, 4);
                memcpy(&of, &old, 4);
                keep = op == 0 ? cf == of
                     : op == 1 ? cf != of
                     : op == 2 ? cf > of
                               : cf < of;
            } else {
                switch (stride) {
                case 1: { int8_t c = (int8_t)cur, o = (int8_t)old;
                          keep = op == 0 ? c == o : op == 1 ? c != o
                               : op == 2 ? c > o : c < o; break; }
                case 2: { int16_t c = (int16_t)cur, o = (int16_t)old;
                          keep = op == 0 ? c == o : op == 1 ? c != o
                               : op == 2 ? c > o : c < o; break; }
                case 4: { int32_t c = (int32_t)cur, o = (int32_t)old;
                          keep = op == 0 ? c == o : op == 1 ? c != o
                               : op == 2 ? c > o : c < o; break; }
                default:{ int64_t c = (int64_t)cur, o = (int64_t)old;
                          keep = op == 0 ? c == o : op == 1 ? c != o
                               : op == 2 ? c > o : c < o; break; }
                }
            }
            if (keep) {
                hits[i].raw = cur;  // 保存最新值，供下一轮比较
                kept.push_back(hits[i]);
            }
        }
        double sec = std::chrono::duration<double>(
                         std::chrono::steady_clock::now() - t0).count();
        char msg[160];
        snprintf(msg, sizeof(msg), "过滤完成: %zu / %zu (耗时 %.1fs)",
                 kept.size(), hits.size(), sec);
        std::lock_guard<std::mutex> lk(g_mux);
        g_hits = std::move(kept);
        g_status = msg;
        g_running.store(false);
    }).detach();
}

// 精确改善：在现有结果中保留当前值等于搜索值的地址。
JNIEXPORT void JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_searchRefine(JNIEnv* env, jobject,
                                                       jint type,
                                                       jstring value) {
    if (g_running.exchange(true)) return;
    const char* vs = value ? env->GetStringUTFChars(value, nullptr) : "";
    std::string valueStr = vs ? vs : "";
    if (vs) env->ReleaseStringUTFChars(value, vs);
    SetStatus("改善中...");
    std::thread([type, valueStr] {
        auto t0 = std::chrono::steady_clock::now();
        std::vector<Hit> hits;
        int pid;
        {
            std::lock_guard<std::mutex> lk(g_mux);
            hits = g_hits;
            pid = g_pid;
        }
        if (hits.empty()) {
            SetStatus("没有可改善的结果");
            g_running.store(false);
            return;
        }
        int64_t iv = 0, imin = 0, imax = 0;
        double dv = 0, dmin = 0, dmax = 0;
        bool isRange = false;
        if (!ParseTarget(valueStr, type, iv, dv, isRange, imin, imax,
                         dmin, dmax) || isRange) {
            SetStatus("改善值格式错误");
            g_running.store(false);
            return;
        }
        std::vector<uint8_t> vals;
        if (!ReadHitValues(pid, hits, type, vals)) {
            SetStatus("读取当前值失败");
            g_running.store(false);
            return;
        }
        int stride = MemTypeSize(type);
        bool isFloat = (type == TYPE_FLOAT || type == TYPE_DOUBLE);
        std::vector<Hit> kept;
        for (size_t i = 0; i < hits.size(); ++i) {
            uint64_t cur = 0;
            memcpy(&cur, vals.data() + i * (size_t)stride, (size_t)stride);
            bool eq = false;
            if (isFloat) {
                double cf;
                memcpy(&cf, &cur, 8);
                eq = cf == dv;
            } else {
                eq = (int64_t)cur == iv;
            }
            if (eq) {
                hits[i].raw = cur;
                kept.push_back(hits[i]);
            }
        }
        double sec = std::chrono::duration<double>(
                         std::chrono::steady_clock::now() - t0).count();
        char msg[160];
        snprintf(msg, sizeof(msg), "改善完成: %zu / %zu (耗时 %.1fs)",
                 kept.size(), hits.size(), sec);
        std::lock_guard<std::mutex> lk(g_mux);
        g_hits = std::move(kept);
        g_status = msg;
        g_running.store(false);
    }).detach();
}

} // extern "C"

// ── 内存页行渲染复用（与 ImGui 侧 MemLoadCont 相同逻辑）──────────
#include "Disasm.h"
#include "AsmWrite.h"
#include "bp/BpService.h"
extern BpService g_bp;

namespace {

struct MemRegionSimple {
    uintptr_t   start = 0;
    uintptr_t   end = 0;
    std::string type;
    std::string path;   // maps 行末尾的路径/模块名（可能为空）
};

// 把 ClassifyMemType 的长名映射为 ImGui/主流工具使用的短代号。
std::string ShortMemType(const std::string& t) {
    if (t == "cpp heap")   return "Ch";
    if (t == "cpp alloc")  return "Ca";
    if (t == "bss")        return "Cb";
    if (t == "anonymous")  return "A";
    if (t == "stack")      return "S";
    if (t == "ashmem")     return "As";
    if (t == "video")      return "V";
    if (t == "bad")        return "B";
    if (t == "code system")return "Xs";
    if (t == "java")       return "J";
    if (t == "cpp data")   return "Cd";
    if (t == "code app")   return "Xa";
    return "O";
}

// 取 maps 路径的模块基名（去掉目录与末尾空格）。
std::string ModuleBaseName(const std::string& path) {
    size_t b = path.find_last_of('/');
    std::string name = (b == std::string::npos) ? path : path.substr(b + 1);
    while (!name.empty() && (name.back() == ' ' || name.back() == '\r'))
        name.pop_back();
    return name;
}

// 解码某行地址处的第一条 ARM64 指令；带 LDR(literal) 的 PC 相对改写，
// 与 ImGui 侧 DisasmFirstLine 完全一致。
std::string DisasmFirstLineArm64(const uint8_t* bytes, size_t n) {
    std::vector<udt_disasm::Insn> insns;
    if (!udt_disasm::Disassemble(udt_disasm::Arch::Arm64, bytes, n, 0, 1,
                                 insns) || insns.empty())
        return "";
    std::string s = insns[0].mnemonic;
    if (!insns[0].op_str.empty()) s += " " + insns[0].op_str;
    if (insns[0].size >= 4) {
        uint32_t w = (uint32_t)insns[0].bytes[0] |
                     ((uint32_t)insns[0].bytes[1] << 8) |
                     ((uint32_t)insns[0].bytes[2] << 16) |
                     ((uint32_t)insns[0].bytes[3] << 24);
        uint32_t fam = w & 0x3F000000u;
        if (fam == 0x18000000u || fam == 0x1C000000u) {
            int64_t imm19 = (int64_t)(w >> 5) & 0x7FFFF;
            if (imm19 & 0x40000) imm19 -= 0x80000;
            int64_t off = imm19 * 4;
            size_t comma = insns[0].op_str.find(',');
            if (comma != std::string::npos) {
                std::string first = insns[0].op_str.substr(0, comma);
                size_t b = first.find_first_not_of(" \t");
                if (b != std::string::npos) {
                    first = first.substr(
                        b, first.find_last_not_of(" \t") - b + 1);
                    char buf[48];
                    if (off < 0)
                        snprintf(buf, sizeof(buf), "[pc, #-0x%llx]",
                                 (unsigned long long)(-off));
                    else
                        snprintf(buf, sizeof(buf), "[pc, #0x%llx]",
                                 (unsigned long long)off);
                    s = insns[0].mnemonic + " " + first + ", " + buf;
                }
            }
        }
    }
    return s;
}

std::vector<MemRegionSimple> ParseMemRegions(int pid) {
    std::vector<MemRegionSimple> out;
    std::string maps = ReadRemoteMaps(pid);
    size_t pos = 0;
    while (pos < maps.size()) {
        size_t e = maps.find('\n', pos);
        if (e == std::string::npos) e = maps.size();
        std::string line = maps.substr(pos, e - pos);
        pos = e + 1;
        if (line.size() < 20) continue;
        unsigned long long a = 0, b = 0, off = 0, ino = 0;
        char perms[8] = {0};
        char dev[32] = {0};
        char path[512] = {0};
        int n = sscanf(line.c_str(),
                       "%llx-%llx %7s %llx %31s %llu %511[^\n]",
                       &a, &b, perms, &off, dev, &ino, path);
        if (n < 6) continue;
        MemRegionSimple r;
        r.start = (uintptr_t)a;
        r.end = (uintptr_t)b;
        r.type = ClassifyMemType(perms, n >= 7 ? path : "");
        r.path = n >= 7 ? path : "";
        out.push_back(std::move(r));
    }
    return out;
}

// 带 TTL 的 maps 缓存：断点命中解析 PC 所属区域/模块时避免每次
// 都 fork su 读取 maps。
std::vector<MemRegionSimple> CachedMemRegions(int pid) {
    static std::mutex    mtx;
    static int           cached_pid = 0;
    static int64_t       cached_at  = 0;
    static std::vector<MemRegionSimple> cached;
    std::lock_guard<std::mutex> lk(mtx);
    int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    if (pid != cached_pid || now - cached_at > 3000 || cached.empty()) {
        cached = ParseMemRegions(pid);
        cached_pid = pid;
        cached_at = now;
    }
    return cached;
}

} // namespace

extern "C" {

// ── 硬件断点服务（复用 ImGui 侧 g_bp 单例，两端共享状态）──────────
JNIEXPORT void JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_bpStart(JNIEnv*, jobject, jint pid) {
    try {
        g_bp.Start(pid);
    } catch (const std::exception& ex) {
        OLOG("bpStart exception: %s", ex.what());
        g_bp.ReportError(std::string("错误: 启动异常 ") + ex.what());
    }
}

JNIEXPORT void JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_bpStop(JNIEnv*, jobject) {
    try {
        g_bp.Stop();
    } catch (const std::exception& ex) {
        OLOG("bpStop exception: %s", ex.what());
    }
}

JNIEXPORT jboolean JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_bpIsRunning(JNIEnv*, jobject) {
    try {
        return g_bp.IsRunning() ? JNI_TRUE : JNI_FALSE;
    } catch (...) {
        return JNI_FALSE;
    }
}

JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_bpStatus(JNIEnv* env, jobject) {
    try {
        return ToJString(env, g_bp.Status());
    } catch (...) {
        return ToJString(env, "状态读取异常");
    }
}

JNIEXPORT void JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_bpSet(JNIEnv* env, jobject, jlong addr,
                                                jstring type, jint len) {
    try {
        const char* t = type ? env->GetStringUTFChars(type, nullptr) : "x";
        char line[96];
        snprintf(line, sizeof(line), "set %llx %s %d",
                 (unsigned long long)addr, t ? t : "x", len);
        if (t) env->ReleaseStringUTFChars(type, t);
        g_bp.Send(line);
    } catch (const std::exception& ex) {
        OLOG("bpSet exception: %s", ex.what());
    }
}

JNIEXPORT void JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_bpClear(JNIEnv*, jobject, jlong addr) {
    char line[64];
    snprintf(line, sizeof(line), "clear %llx", (unsigned long long)addr);
    g_bp.Send(line);
}

JNIEXPORT void JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_bpClearHits(JNIEnv*, jobject) {
    g_bp.ClearHits();
}

// 最近命中："PC|TID|ADDR|反汇编" 行。
JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_bpHits(JNIEnv* env, jobject,
                                                 jint maxN) {
    try {
        auto hits = g_bp.Hits();
        int tpid = g_bp.TargetPid();
        std::vector<MemRegionSimple> regions;
        if (tpid > 0) regions = CachedMemRegions(tpid);
        std::string out;
        int n = 0;
        for (auto it = hits.rbegin(); it != hits.rend() && n < maxN; ++it, ++n) {
            std::string stack;
            for (size_t k = 0; k < it->stack.size(); ++k) {
                if (k) stack += '>';
                char sb[24];
                snprintf(sb, sizeof(sb), "0x%llx",
                         (unsigned long long)it->stack[k]);
                stack += sb;
            }
            std::string regs;
            for (size_t k = 0; k < it->regs.size(); ++k) {
                if (k) regs += ',';
                char rb[48];
                snprintf(rb, sizeof(rb), "%s=0x%llx",
                         it->regs[k].name.c_str(),
                         (unsigned long long)it->regs[k].value);
                regs += rb;
            }
            // 解析 PC 所属内存区域与模块（供 UI 显示 "Xa libxxx.so"）。
            std::string region, module;
            for (const auto& r : regions) {
                if (it->pc >= r.start && it->pc < r.end) {
                    region = ShortMemType(r.type);
                    module = ModuleBaseName(r.path);
                    break;
                }
            }
            char line[4096];
            snprintf(line, sizeof(line),
                     "%llx|%d|%llx|%s|%llx|%s|%s|%d|%s|%s|%d|%d",
                     (unsigned long long)it->pc, it->tid,
                     (unsigned long long)it->addr,
                     it->disasm.c_str(),
                     (unsigned long long)it->sp,
                     stack.c_str(), regs.c_str(),
                     it->counter, region.c_str(), module.c_str(),
                     it->bp_type, it->bp_len);
            out += line;
            out += '\n';
        }
        return ToJString(env, out);
    } catch (const std::exception& ex) {
        OLOG("bpHits exception: %s", ex.what());
        return ToJString(env, "");
    }
}

// agent 的 lua 日志（分配等脚本通过 print 回传结果）。
JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_socketLuaLogs(JNIEnv* env, jobject) {
    return ToJString(env, g_ov_socket.SendCommand("lua_logs 0", 2000));
}

// 目标进程内 mmap（agent 侧 alloc 命令），返回 "ALLOC 0x..." 或错误。
JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_socketAlloc(JNIEnv* env, jobject,
                                                      jlong size,
                                                      jstring prot) {
    const char* p = prot ? env->GetStringUTFChars(prot, nullptr) : "rw";
    int bits = 0;
    for (const char* c = p ? p : ""; *c; ++c) {
        if (*c == 'r') bits |= 1;
        else if (*c == 'w') bits |= 2;
        else if (*c == 'x') bits |= 4;
    }
    if (p) env->ReleaseStringUTFChars(prot, p);
    if (bits == 0) bits = 3;
    std::string cmd = "alloc " + std::to_string((unsigned long long)size) +
                      " " + std::to_string(bits);
    return ToJString(env, g_ov_socket.SendCommand(cmd, 10000));
}

// 目标进程已加载库列表（agent 侧 modules 命令）。
JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_socketModules(JNIEnv* env, jobject) {
    return ToJString(env, g_ov_socket.SendCommand("modules", 5000));
}

// ── 反汇编 / 汇编写入（capstone + asmjit，复用 ImGui 侧封装）──────

// bytes → "助记符 操作数"（单条，失败返回空）。
JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_memDisasm(JNIEnv* env, jobject,
                                                    jbyteArray bytes) {
    jsize n = env->GetArrayLength(bytes);
    if (n < 4) return ToJString(env, "");
    std::vector<uint8_t> buf((size_t)n);
    env->GetByteArrayRegion(bytes, 0, n,
                            reinterpret_cast<jbyte*>(buf.data()));
    return ToJString(env, DisasmFirstLineArm64(buf.data(), buf.size()));
}

// 内存页整页读取（复用 ImGui MemLoadCont 的逐行逻辑）：
// 每行输出 "addr|ok|hex8|disasm|type"。
JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_memPage(JNIEnv* env, jobject,
                                                  jint pid, jlong base,
                                                  jint rows) {
    if (rows <= 0 || rows > 64) return ToJString(env, "");
    auto regions = ParseMemRegions(pid);
    std::string out;
    for (int i = 0; i < rows; ++i) {
        uintptr_t a = (uintptr_t)base + (uintptr_t)i * 4;
        uint8_t b[16] = {0};
        bool ok = ReadRemoteBytes(pid, a, b, sizeof(b));
        if (!ok) {
            // 行尾跨到不可读页时退化为只读 4 字节（值 + 单条指令仍可显示）。
            ok = ReadRemoteBytes(pid, a, b, 4);
        }
        std::string disasm = ok ? DisasmFirstLineArm64(b, sizeof(b)) : "";
        std::string type = "other";
        for (const auto& r : regions) {
            if (a >= r.start && a < r.end) { type = r.type; break; }
        }
        char line[1024];
        snprintf(line, sizeof(line), "%llx|%d|%08X|%s|%s\n",
                 (unsigned long long)a, ok ? 1 : 0,
                 ok ? (unsigned int)(b[0] | (b[1] << 8) |
                         (b[2] << 16) | ((uint32_t)b[3] << 24)) : 0u,
                 disasm.c_str(), type.c_str());
        out += line;
    }
    return ToJString(env, out);
}

// 文本汇编 → 写入目标地址（~A8 语法，与 ImGui 侧一致）。
JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_asmWrite(JNIEnv* env, jobject,
                                                   jint pid, jlong addr,
                                                   jstring text) {
    const char* t = text ? env->GetStringUTFChars(text, nullptr) : "";
    std::string asmText = t ? t : "";
    if (t) env->ReleaseStringUTFChars(text, t);
    std::vector<uint8_t> bytes;
    std::string err;
    if (!udt_asm::Assemble(asmText.c_str(), bytes, err))
        return ToJString(env, "错误: " + err);
    for (size_t i = 0; i < bytes.size(); i += 4) {
        uint32_t w = 0;
        size_t n = bytes.size() - i;
        if (n >= 4) memcpy(&w, bytes.data() + i, 4);
        else {
            for (size_t k = 0; k < n; ++k)
                w |= (uint32_t)bytes[i + k] << (8 * k);
        }
        if (!WriteRemoteDword(pid, addr + i, w))
            return ToJString(env, "错误: 写入失败 (目标不可写?)");
    }
    char msg[64];
    snprintf(msg, sizeof(msg), "OK %zu 字节", bytes.size());
    return ToJString(env, msg);
}

} // extern "C"

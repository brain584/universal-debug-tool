//
// JNI 桥 —— ATrace 后端。
//
// 只保留与 root 相关的后端能力：su 命令、注入器调用、远程内存读写。
// 原生悬浮窗（overlay_bridge.cpp）复用这些函数。
// 旧的 ImGui 渲染界面（SurfaceView + AImGui）已移除。
//
#include <jni.h>
#include <android/log.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#define TAG "ATraceJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ── 注入信息（由 Java 设置）──
static std::mutex  g_inject_mutex;
static std::string g_injector_path;
static std::string g_agent_path;
static std::string g_config_dir;   // App 私有 files 目录（配置文件存放处）

// 配置文件路径（App 私有 files 目录，免 root）。
std::string GetConfigFilePath() {
    return g_config_dir.empty()
               ? ""
               : g_config_dir + "/universal_debug_tool.conf";
}

// 返回解压后的注入器路径（断点服务使用）。
std::string GetInjectorPath() {
    std::lock_guard<std::mutex> lk(g_inject_mutex);
    return g_injector_path;
}

// ── 注入（ptrace）──
// 在 `su` 下为指定参数运行独立注入器可执行文件并返回捕获的输出。
// 必须在后台线程调用：`su` + ptrace 注入可能耗时。
std::string RunInjectorArgs(const std::string& args) {
    std::string inj, agent;
    {
        std::lock_guard<std::mutex> lk(g_inject_mutex);
        inj = g_injector_path;
        agent = g_agent_path;
    }
    if (inj.empty() || agent.empty())
        return "错误: injector/agent 路径未设置";

    // 被注入的 agent 以目标应用的 uid 运行，必须能
    // 在 /data/local/tmp 下创建密钥文件和 unix socket。
    // 先用 root 开放目录权限；对已允许的设备无害。
    {
        FILE* prep = popen("su -c 'chmod 777 /data/local/tmp' 2>&1 </dev/null", "r");
        if (prep) pclose(prep);
    }

    std::string cmd = "su -c '" + inj + " " + args + " -l " + agent + "' 2>&1";
    FILE* f = popen(cmd.c_str(), "r");
    if (!f) return "错误: 无法启动 su";

    std::string out;
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        out.append(buf, n);
    int rc = pclose(f);

    // 如果注入器没有任何输出（例如在打日志前崩溃），
    // 显示退出码，避免 UI 静默无提示。
    if (out.empty() && rc != 0) {
        out = "injector 无输出，退出码 " + std::to_string(rc);
    }

    if (out.size() > 2048)
        out = out.substr(out.size() - 2048);
    return out;
}

std::string RunInjector(const std::string& pkg) {
    return RunInjectorArgs("-p " + pkg);
}

// 按 PID 注入：用于 native ELF 等非应用进程——没有包名可解析，
// 注入器把 agent 复制到 /data/local/tmp 供目标读取。
std::string RunInjectorPid(int pid) {
    return RunInjectorArgs("-i " + std::to_string(pid));
}

// ── Root 内存辅助函数 ──
// 在 `su` 下运行命令并返回捕获的输出。cmd 不能包含单引号。
std::string RunSuCommand(const std::string& cmd) {
    std::string full = "su -c '" + cmd + "' 2>&1 </dev/null";
    FILE* f = popen(full.c_str(), "r");
    if (!f) return "";
    std::string out;
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        out.append(buf, n);
    pclose(f);
    return out;
}

std::string ReadRemoteMaps(int pid) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "cat /proc/%d/maps", pid);
    return RunSuCommand(cmd);
}

bool ReadRemoteDword(int pid, uintptr_t addr, uint32_t& out) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "dd if=/proc/%d/mem bs=1 skip=%llu count=4 2>/dev/null | xxd -p -c 8",
        pid, (unsigned long long)addr);
    std::string hex = RunSuCommand(cmd);
    // xxd -p 按文件顺序打印字节，例如 "78563412\n"
    if (hex.size() < 8) return false;
    uint32_t v = 0;
    for (int i = 0; i < 8; ++i) {
        char c = hex[i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return false;
        v = (v << 4) | (uint32_t)d;
    }
    out = v;
    return true;
}

bool ReadRemoteBytes(int pid, uintptr_t addr, void* buf, size_t n) {
    if (n == 0) return true;
    // /proc/<pid>/mem 用 bs=1 + 大 skip 会按字节读并丢弃，慢到不可用
    // （对高位地址尤其明显）。与 MemSu（搜索后端，已验证可用）一致：
    // 按页 dd bs=4096 读取，再裁出目标区间。
    uintptr_t page = addr & ~(uintptr_t)4095;
    size_t off = (size_t)(addr - page);
    size_t bytes = (off + n + 4095) & ~(size_t)4095;
    if (bytes == 0) return false;
    std::vector<uint8_t> tmp(bytes);
    char cmd[320];
    snprintf(cmd, sizeof(cmd),
        "dd if=/proc/%d/mem bs=4096 skip=%llu count=%zu 2>/dev/null | xxd -p",
        pid, (unsigned long long)(page / 4096), bytes / 4096);
    std::string hex = RunSuCommand(cmd);
    unsigned char* out = tmp.data();
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    size_t got = 0;
    int hi = -1;
    for (size_t i = 0; i < hex.size() && got < bytes; ++i) {
        int d = nib(hex[i]);
        if (d < 0) continue;  // 跳过换行 / 空白
        if (hi < 0) {
            hi = d;
        } else {
            out[got++] = (unsigned char)((hi << 4) | d);
            hi = -1;
        }
    }
    if (got != bytes) return false;
    memcpy(buf, tmp.data() + off, n);
    return true;
}

// 内存搜索用的快速页对齐批量读取。addr 必须 4096 对齐，
// n 是 4096 的倍数；用块大小 dd 读取，完整扫描
// 比每字节一次 bs=1 调用快几个数量级。
bool ReadRemoteChunk(int pid, uintptr_t addr, void* buf, size_t n) {
    size_t pages = n / 4096;
    if (pages == 0 || (addr & 4095) != 0) return false;
    char cmd[320];
    snprintf(cmd, sizeof(cmd),
        "dd if=/proc/%d/mem bs=4096 skip=%llu count=%zu 2>/dev/null | xxd -p",
        pid, (unsigned long long)(addr / 4096), pages);
    std::string hex = RunSuCommand(cmd);
    unsigned char* out = static_cast<unsigned char*>(buf);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    size_t got = 0;
    int hi = -1;
    for (size_t i = 0; i < hex.size() && got < n; ++i) {
        int d = nib(hex[i]);
        if (d < 0) continue;
        if (hi < 0) {
            hi = d;
        } else {
            out[got++] = (unsigned char)((hi << 4) | d);
            hi = -1;
        }
    }
    return got > 0;
}

// 搜索改善用的批量页读取器：通过一次 su 调用
//（内部批量）读取远程进程的指定 4KB 页，而不是
// 每个 8MB 块一次 su + dd + xxd 往返。每页恰好输出 4096
// 字节（页面读取失败时输出 0），因此输出可以确定性地切分。
// 仅当整批数据丢失时才返回 false。
bool ReadRemotePages(int pid, const std::vector<uintptr_t>& pages,
                     std::vector<uint8_t>& out) {
    out.clear();
    if (pages.empty()) return true;

    constexpr size_t kBatch = 400;
    const size_t total = pages.size();
    out.resize(total * 4096);

    for (size_t base = 0; base < total; base += kBatch) {
        const size_t cnt = std::min(kBatch, total - base);
        std::string cmd = "for o in";
        for (size_t i = 0; i < cnt; ++i) {
            char num[24];
            snprintf(num, sizeof(num), " %llu",
                     (unsigned long long)(pages[base + i] / 4096));
            cmd += num;
        }
        char pbuf[16];
        snprintf(pbuf, sizeof(pbuf), "%d", pid);
        cmd += "; do dd if=/proc/";
        cmd += pbuf;
        cmd += "/mem bs=4096 skip=$o count=1 2>/dev/null || "
               "dd if=/dev/zero bs=4096 count=1 2>/dev/null; done";

        std::string raw = RunSuCommand(cmd);
        const size_t need = cnt * 4096;
        if (raw.size() < need) return false;
        memcpy(out.data() + base * 4096, raw.data(), need);
    }
    return true;
}

bool WriteRemoteDword(int pid, uintptr_t addr, uint32_t value) {
    unsigned char b0 = (unsigned char)(value & 0xff);
    unsigned char b1 = (unsigned char)((value >> 8) & 0xff);
    unsigned char b2 = (unsigned char)((value >> 16) & 0xff);
    unsigned char b3 = (unsigned char)((value >> 24) & 0xff);
    char cmd[320];
    snprintf(cmd, sizeof(cmd),
        "printf \"\\x%02x\\x%02x\\x%02x\\x%02x\" | dd of=/proc/%d/mem bs=1 seek=%llu conv=notrunc 2>&1",
        b0, b1, b2, b3, pid, (unsigned long long)addr);
    std::string out = RunSuCommand(cmd);
    // dd 成功时打印 "N+0 records in"。
    return out.find("records in") != std::string::npos;
}

extern "C" {

// 注入路径（从 assets 解压的注入器可执行文件 + APK 中
// 打包的 agent .so）。
JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeSetInjectorInfo(
    JNIEnv* env, jobject, jstring injectorPath, jstring agentPath) {
    const char* ip = injectorPath ? env->GetStringUTFChars(injectorPath, nullptr) : nullptr;
    const char* ap = agentPath ? env->GetStringUTFChars(agentPath, nullptr) : nullptr;
    {
        std::lock_guard<std::mutex> lk(g_inject_mutex);
        g_injector_path = ip ? ip : "";
        g_agent_path = ap ? ap : "";
    }
    if (ip) env->ReleaseStringUTFChars(injectorPath, ip);
    if (ap) env->ReleaseStringUTFChars(agentPath, ap);
}

// 配置文件目录（App 私有 files 目录，由 Java 传入）。
JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeSetConfigDir(
    JNIEnv* env, jobject, jstring dir) {
    const char* d = dir ? env->GetStringUTFChars(dir, nullptr) : nullptr;
    g_config_dir = d ? d : "";
    if (d) env->ReleaseStringUTFChars(dir, d);
}

} // extern "C"

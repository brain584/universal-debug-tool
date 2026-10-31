// Agent 侧命令通道：ChaCha20 加密的 Unix 域 socket 服务端。
//
// imgui 悬浮层连接该服务端并交换分帧加密
// 文本消息。支持两个方向：
//   - 客户端 -> 服务端：命令（"ping"、"hello" 等），返回响应
//   - 服务端 -> 客户端：主动事件，以 "EVENT " 开头
//
// 每条消息的线上格式：4 字节大端负载长度 +
// ChaCha20 加密负载。密钥材料（32 字节密钥 + 12 字节 nonce）
// **只存在于内存**：由注入器通过远程内存写入本进程，再调用
// AgentStartWithAuth() 传入；不再读写任何公共路径的密钥文件。
// 客户端->服务端与服务端->客户端使用两个不同 nonce（
// nonce[0] 中的方向位），每侧各自维护方向消息
// 计数器，确保同一个 key+nonce+counter 组合不会被重复使用。
//
//   · 认证材料 = 内存中的 key/nonce + 允许的客户端 uid；
//   · accept 后用 SO_PEERCRED 校验对端：只接受 root（relay）或 GUI uid；
//   · 不再把命令明文写 logcat。

#include "socket.h"
#include "lua/LuaEngine.h"
#include "xdl.h"

#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <string>
#include <vector>

#define TAG "AgentSocket"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

namespace {

constexpr char kSocketPath[] = "/data/local/tmp/universal_debug_tool.sock";
// 旧版本在 /data/local/tmp 里放 0666 的密钥文件；现在只做清理，不再使用。
constexpr char kLegacyKeyPath[] = "/data/local/tmp/universal_debug_tool_key.bin";
constexpr size_t kKeyLen     = 32;
constexpr size_t kNonceLen   = 12;

// 与 GUI 侧 backend/jni/src/socket/ChannelKey.h::Blob 逐字节一致。
struct AgentAuthBlob {
    uint32_t magic;
    uint32_t version;
    uint8_t  key[kKeyLen];
    uint8_t  nonce[kNonceLen];
    uint32_t client_uid;
};
constexpr uint32_t kAuthMagic   = 0x43525441u;   // 'ATRC'
constexpr uint32_t kAuthVersion = 1;
constexpr size_t kMaxMsg     = 1024 * 1024;  // 1 MiB 负载上限

// 抽象 socket 名称。刻意使用固定名称：目标可能是
// zygote USAP 进程，其 /proc/self/cmdline 是 "usap64" 而不是
// 包名，因此从进程推导名称会与应用侧不一致。
// 工具同时只与一个目标通信，固定名称没有问题。
// 抽象 socket 不创建文件系统对象，因此 SELinux 对
// /data/local/tmp 的 sock_file 限制（曾拒绝我们的 bind）不适用。
// 说明：同一进程重复注入时新 agent 会 bind 失败（客户端会继续连旧 agent）；
// ServerThread 里给了可执行处置：`adb shell am force-stop <包名>` 后重新注入。
std::string GetSocketName() {
    return "udt_debug_chan";
}

std::atomic<bool> g_running{false};
std::atomic<bool> g_auth_ready{false};
uint32_t          g_client_uid = 0;   // 允许直连的 GUI uid（0 = 未指定）
std::atomic<int>  g_listen_fd{-1};
std::atomic<int>  g_client_fd{-1};
uint8_t           g_key[kKeyLen];
uint8_t           g_nonce[kNonceLen];

// ── ChaCha20（两端核心一致）──────────────────────────────
inline uint32_t Rotl(uint32_t v, int n) {
    return (v << n) | (v >> (32 - n));
}

void ChaCha20Block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = in[i];

    for (int i = 0; i < 10; ++i) {
        x[0] += x[4];  x[12] = Rotl(x[12] ^ x[0], 16);
        x[8] += x[12]; x[4]  = Rotl(x[4]  ^ x[8], 12);
        x[0] += x[4];  x[12] = Rotl(x[12] ^ x[0], 8);
        x[8] += x[12]; x[4]  = Rotl(x[4]  ^ x[8], 7);

        x[1] += x[5];  x[13] = Rotl(x[13] ^ x[1], 16);
        x[9] += x[13]; x[5]  = Rotl(x[5]  ^ x[9], 12);
        x[1] += x[5];  x[13] = Rotl(x[13] ^ x[1], 8);
        x[9] += x[13]; x[5]  = Rotl(x[5]  ^ x[9], 7);

        x[2] += x[6];  x[14] = Rotl(x[14] ^ x[2], 16);
        x[10] += x[14]; x[6] = Rotl(x[6] ^ x[10], 12);
        x[2] += x[6];  x[14] = Rotl(x[14] ^ x[2], 8);
        x[10] += x[14]; x[6] = Rotl(x[6] ^ x[10], 7);

        x[3] += x[7];  x[15] = Rotl(x[15] ^ x[3], 16);
        x[11] += x[15]; x[7] = Rotl(x[7] ^ x[11], 12);
        x[3] += x[7];  x[15] = Rotl(x[15] ^ x[3], 8);
        x[11] += x[15]; x[7] = Rotl(x[7] ^ x[11], 7);

        x[0] += x[5];  x[15] = Rotl(x[15] ^ x[0], 16);
        x[10] += x[15]; x[5] = Rotl(x[5] ^ x[10], 12);
        x[0] += x[5];  x[15] = Rotl(x[15] ^ x[0], 8);
        x[10] += x[15]; x[5] = Rotl(x[5] ^ x[10], 7);

        x[1] += x[6];  x[12] = Rotl(x[12] ^ x[1], 16);
        x[11] += x[12]; x[6] = Rotl(x[6] ^ x[11], 12);
        x[1] += x[6];  x[12] = Rotl(x[12] ^ x[1], 8);
        x[11] += x[12]; x[6] = Rotl(x[6] ^ x[11], 7);

        x[2] += x[7];  x[13] = Rotl(x[13] ^ x[2], 16);
        x[8] += x[13]; x[7]  = Rotl(x[7] ^ x[8], 12);
        x[2] += x[7];  x[13] = Rotl(x[13] ^ x[2], 8);
        x[8] += x[13]; x[7]  = Rotl(x[7] ^ x[8], 7);

        x[3] += x[4];  x[14] = Rotl(x[14] ^ x[3], 16);
        x[9] += x[14]; x[4]  = Rotl(x[4] ^ x[9], 12);
        x[3] += x[4];  x[14] = Rotl(x[14] ^ x[3], 8);
        x[9] += x[14]; x[4]  = Rotl(x[4] ^ x[9], 7);
    }

    for (int i = 0; i < 16; ++i) out[i] = x[i] + in[i];
}

std::vector<uint8_t> ChaCha20Crypt(const uint8_t* input, size_t length,
                                   const uint8_t key[32],
                                   const uint8_t nonce[12],
                                   uint32_t counter) {
    std::vector<uint8_t> output(length);
    uint32_t state[16];
    const uint8_t constant[] = "expand 32-byte k";
    memcpy(&state[0], constant, 16);
    memcpy(&state[4], key, 32);
    state[12] = counter;
    memcpy(&state[13], nonce, 12);

    size_t pos = 0;
    while (pos < length) {
        uint32_t block[16];
        uint8_t key_stream[64];
        ChaCha20Block(block, state);
        memcpy(key_stream, block, 64);
        size_t block_size = (length - pos < 64) ? (length - pos) : 64;
        for (size_t i = 0; i < block_size; ++i)
            output[pos + i] = input[pos + i] ^ key_stream[i];
        pos += block_size;
        ++state[12];
        if (state[12] == 0) ++state[13];
    }
    return output;
}

// 客户端->服务端与服务端->客户端使用不同 nonce，
// 两个方向绝不共享密钥流。
void DirectionNonce(const uint8_t base[12], bool server_to_client,
                    uint8_t out[12]) {
    memcpy(out, base, 12);
    if (server_to_client) out[0] |= 0x80;
    else out[0] &= 0x7F;
}

// ── 分帧 I/O ───────────────────────────────────────────
bool SendExact(int fd, const uint8_t* data, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = send(fd, data + off, n - off, MSG_NOSIGNAL);
        if (w <= 0) return false;
        off += (size_t)w;
    }
    return true;
}

bool RecvExact(int fd, uint8_t* data, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, data + off, n - off, 0);
        if (r <= 0) return false;
        off += (size_t)r;
    }
    return true;
}

bool SendMessage(int fd, const uint8_t* plain, size_t len,
                 const uint8_t key[32], const uint8_t nonce[12],
                 uint32_t& counter) {
    if (len > kMaxMsg) return false;
    uint8_t hdr[4] = {
        (uint8_t)(len >> 24), (uint8_t)(len >> 16),
        (uint8_t)(len >> 8),  (uint8_t)len
    };
    std::vector<uint8_t> enc = ChaCha20Crypt(plain, len, key, nonce, counter);
    ++counter;
    return SendExact(fd, hdr, 4) && SendExact(fd, enc.data(), enc.size());
}

bool RecvMessage(int fd, std::string& out, const uint8_t key[32],
                 const uint8_t nonce[12], uint32_t& counter) {
    uint8_t hdr[4];
    if (!RecvExact(fd, hdr, 4)) return false;
    uint32_t len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                   ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
    if (len == 0 || len > kMaxMsg) return false;
    std::vector<uint8_t> enc(len);
    if (!RecvExact(fd, enc.data(), len)) return false;
    std::vector<uint8_t> dec = ChaCha20Crypt(enc.data(), len, key, nonce, counter);
    ++counter;
    out.assign(reinterpret_cast<const char*>(dec.data()), dec.size());
    return true;
}

// ── 认证材料（内存，来自注入器）───────────────────────
bool ApplyAuthBlob(const AgentAuthBlob& blob) {
    if (blob.magic != kAuthMagic || blob.version != kAuthVersion) {
        LOGE("bad auth blob magic/version (0x%x/%u)",
             blob.magic, (unsigned)blob.version);
        return false;
    }
    memcpy(g_key, blob.key, kKeyLen);
    memcpy(g_nonce, blob.nonce, kNonceLen);
    g_client_uid = blob.client_uid;
    g_auth_ready.store(true);
    LOGI("auth ready (client_uid=%u)", (unsigned)g_client_uid);
    return true;
}

// 对端身份校验：只接受 root（relay）或 GUI uid。
bool PeerAllowed(int fd) {
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
        LOGE("SO_PEERCRED failed: %s", strerror(errno));
        return false;
    }
    bool ok = (cred.uid == 0) || (g_client_uid != 0 && cred.uid == g_client_uid);
    if (!ok) {
        LOGE("reject peer uid=%u pid=%d (allowed: root or %u)",
             (unsigned)cred.uid, (int)cred.pid, (unsigned)g_client_uid);
    }
    return ok;
}

// ── 命令分发 ───────────────────────────────────────────
// xdl_iterate_phdr 回调：为当前（被注入）进程中
// 加载的每个库收集 "0x<基址> <完整路径>" 行。
static int ModuleIterCb(struct dl_phdr_info* info,
                        size_t /*size*/, void* data) {
    std::string* out = static_cast<std::string*>(data);
    if (!info->dlpi_name || info->dlpi_name[0] == '\0') return 0;
    if (info->dlpi_phnum <= 0) return 0;
    char line[1024];
    snprintf(line, sizeof(line), "0x%llx %s",
             (unsigned long long)info->dlpi_addr, info->dlpi_name);
    out->append(line);
    out->append("\n");
    return 0;
}

std::string AgentHandleCommand(const std::string& cmd) {
    if (cmd == "ping") {
        return "pong";
    }
    if (cmd == "hello") {
        char buf[96];
        snprintf(buf, sizeof(buf), "hello from agent pid=%d", getpid());
        return buf;
    }
    if (cmd == "info") {
        char buf[160];
        snprintf(buf, sizeof(buf), "agent pid=%d socket=@%s",
                 getpid(), GetSocketName().c_str());
        return buf;
    }
    if (cmd == "status") {
        // 给 MCP/电脑端返回足够的信息，避免"连的是谁"说不清（外部 AI 反馈）。
        return LuaEngine::StatusSummary();
    }
    if (cmd == "lua_reset") {
        LuaEngine::Reset();
        return "lua engine reset ok";
    }
    if (cmd == "lua_count") {
        return std::to_string(LuaEngine::LogCount());
    }
    if (cmd.rfind("alloc ", 0) == 0) {
        // "alloc <size> <prot>"：在 agent 所在的目标进程内 mmap，
        // 地址直接作为响应传回，不经过 Lua/FFI。
        unsigned long long size = 0;
        int prot = PROT_READ | PROT_WRITE;
        int n = sscanf(cmd.c_str(), "alloc %llu %d", &size, &prot);
        if (n < 1 || size == 0)
            return "ERR alloc usage: alloc <size> <prot>";
        void* p = mmap(nullptr, (size_t)size, prot,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED)
            return "ERR mmap failed errno=" + std::to_string(errno);
        char buf[64];
        snprintf(buf, sizeof(buf), "ALLOC 0x%llx",
                 (unsigned long long)(uintptr_t)p);
        return buf;
    }
    if (cmd.rfind("lua_logs ", 0) == 0) {
        // 返回格式：第一行为当前日志总数（新水位），
        // 其余行为 from 之后新增的日志。
        size_t from = 0;
        try { from = (size_t)std::stoull(cmd.substr(9)); } catch (...) { from = 0; }
        std::vector<std::string> logs = LuaEngine::TakeLogsSince(from);
        std::string out = std::to_string(LuaEngine::LogCount()) + "\n";
        for (const auto& s : logs) out += s + "\n";
        return out;
    }
    if (cmd.rfind("lua ", 0) == 0) {
        return LuaEngine::RunScript(cmd.substr(4));
    }
    if (cmd.rfind("java_stack ", 0) == 0) {
        // P1-21：按 tid 取任意 Java 线程的栈（硬件断点命中后，App 用它把
        // 「原生断点」补上 Java 调用链）。载荷：java_stack <tid> [maxDepth]
        int tid = 0, maxd = 32;
        sscanf(cmd.c_str() + 11, "%d %d", &tid, &maxd);
        if (maxd <= 0 || maxd > 128) maxd = 32;
        std::vector<char> jbuf(64 * 1024, 0);
        int n = atrace_java_thread_stack(tid, jbuf.data(), (int)jbuf.size(), maxd);
        if (n < 0) return std::string("ERR ") + jbuf.data();
        return std::string(jbuf.data(), (size_t)n);
    }
    if (cmd == "modules") {
        std::string out;
        xdl_iterate_phdr(ModuleIterCb, &out, XDL_FULL_PATHNAME);
        if (out.empty()) return "no modules";
        return out;
    }
    return "unknown command: " + cmd;
}

// ── 每连接处理器 ───────────────────────────────────────
void HandleClient(int fd) {
    // 安全检查放在最前面：未通过校验的连接不发送任何数据。
    if (!PeerAllowed(fd)) {
        close(fd);
        return;
    }

    uint8_t nonce_c2s[12], nonce_s2c[12];
    DirectionNonce(g_nonce, false, nonce_c2s);
    DirectionNonce(g_nonce, true,  nonce_s2c);
    uint32_t recv_counter = 0, send_counter = 0;

    // 立即推送事件（服务端 -> 客户端方向）。
    {
        char ev[96];
        snprintf(ev, sizeof(ev), "EVENT agent:connected pid=%d", getpid());
        SendMessage(fd, reinterpret_cast<const uint8_t*>(ev), strlen(ev),
                    g_key, nonce_s2c, send_counter);
    }

    while (g_running.load()) {
        std::string cmd;
        if (!RecvMessage(fd, cmd, g_key, nonce_c2s, recv_counter)) break;
        // 不打印命令内容：Lua 脚本属于敏感信息，旧的 LOGI("recv cmd: %s")
        // 会把明文脚本写进 logcat。
        LOGI("recv cmd len=%zu", cmd.size());

        std::string resp = AgentHandleCommand(cmd);
        if (!SendMessage(fd, reinterpret_cast<const uint8_t*>(resp.data()),
                         resp.size(), g_key, nonce_s2c, send_counter))
            break;
    }
    close(fd);
    LOGI("client disconnected");
}

void* ClientThread(void* arg) {
    int fd = (int)(intptr_t)arg;
    int old = g_client_fd.exchange(fd);
    if (old >= 0 && old != fd) {
        shutdown(old, SHUT_RDWR);   // 解除上一个客户端 recv 的阻塞
    }
    HandleClient(fd);
    int cur = g_client_fd.load();
    if (cur == fd) g_client_fd.store(-1);
    return nullptr;
}

// 从 /proc/self/cmdline 取进程名（应用进程通常就是包名；USAP 等可能是
// "usap64"）。只用于把 bind 失败时的「怎么恢复」写成可直接执行的形式。
std::string GetSelfProcessName() {
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return "";
    char buf[256] = {0};
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return "";
    buf[n] = '\0';
    // cmdline 是 NUL 分隔的 argv[0] 起：std::string(buf) 天然只取到第一个 NUL。
    return std::string(buf);
}

void* ServerThread(void*) {
    if (!g_auth_ready.load()) {
        // 没有认证材料就绝不监听：避免出现"无密钥也能连"的通道。
        LOGE("refuse to listen: no auth material (injector must call AgentStartWithAuth)");
        g_running = false;
        return nullptr;
    }
    // 清理旧版本遗留的公共密钥文件（0666），避免历史信息残留。
    unlink(kLegacyKeyPath);

    std::string sockName = GetSocketName();
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOGE("socket() failed: %s", strerror(errno));
        g_running = false;
        return nullptr;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';   // 抽象 socket：不创建文件
    strncpy(&addr.sun_path[1], sockName.c_str(), sizeof(addr.sun_path) - 2);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        // P2-21：旧提示只说"请重启目标进程"，不可执行。这里给出明确指令，
        // 并说明这是已知设计限制（固定 socket 名 + agent 没有 __detach__）。
        const int bindErrno = errno;
        std::string selfName = GetSelfProcessName();
        if (selfName.empty()) selfName = "<包名，用 adb shell ps 查>";
        LOGE("bind(@%s) 失败: %s —— 同一进程里已有旧 agent 占用该固定 socket 名，"
             "新 agent 无法接管（固定名 + 无 detach 的已知限制；客户端此时连到的是"
             "旧 agent，状态可能是旧的）。"
             "处置：重启目标进程后再注入，例如：adb shell am force-stop %s，"
             "然后重新启动目标应用并再次注入。",
             sockName.c_str(), strerror(bindErrno), selfName.c_str());
        close(fd);
        g_running = false;
        return nullptr;
    }

    if (listen(fd, 5) < 0) {
        LOGE("listen() failed: %s", strerror(errno));
        close(fd);
        g_running = false;
        return nullptr;
    }

    g_listen_fd.store(fd);
    LOGI("socket server listening: @%s", sockName.c_str());

    while (g_running.load()) {
        int c = accept(fd, nullptr, nullptr);
        if (c < 0) {
            if (errno != EINTR) usleep(100000);
            continue;
        }
        // 身份校验必须在**抢占旧客户端之前**完成：
        // 否则任何未授权进程只要 connect 一次，就能把 GUI 的连接踢掉（DoS）。
        if (!PeerAllowed(c)) {
            close(c);
            continue;
        }
        LOGI("client connected fd=%d", c);
        pthread_t t;
        if (pthread_create(&t, nullptr, ClientThread,
                           reinterpret_cast<void*>((intptr_t)c)) != 0) {
            close(c);
            continue;
        }
        pthread_detach(t);
    }

    if (g_listen_fd.load() == fd) { close(fd); g_listen_fd.store(-1); }
    return nullptr;
}

} // 匿名命名空间

extern "C" {

// 兼容旧名称：没有认证材料时拒绝启动（返回 -1）。
int AgentSocketStart() {
    if (!g_auth_ready.load()) {
        LOGE("AgentSocketStart without auth material; refusing");
        return -1;
    }
    if (g_running.exchange(true)) return 0;
    pthread_t t;
    if (pthread_create(&t, nullptr, ServerThread, nullptr) != 0) {
        g_running = false;
        LOGE("failed to start server thread");
        return -1;
    }
    pthread_detach(t);
    return 0;
}

// 注入器在 dlopen 之后调用：blob 是目标进程内存里的 AgentAuthBlob（56 字节）。
// 返回 0 = 成功启动 / 已在运行；非 0 = 失败。
int AgentStartWithAuth(const void* blob) {
    if (!blob) return -1;
    if (!ApplyAuthBlob(*static_cast<const AgentAuthBlob*>(blob))) return -2;
    return AgentSocketStart();
}

void AgentSocketStop() {
    g_running = false;
    // 注意：抽象 socket 的**名字只在 close() 时释放**，只 shutdown 不够，
    int lfd = g_listen_fd.exchange(-1);
    if (lfd >= 0) {
        shutdown(lfd, SHUT_RDWR);
        close(lfd);
    }
    int c = g_client_fd.exchange(-1);
    if (c >= 0) {
        shutdown(c, SHUT_RDWR);
        close(c);
    }
    unlink(kSocketPath);
}

} // extern "C"

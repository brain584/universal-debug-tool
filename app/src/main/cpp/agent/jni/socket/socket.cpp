// Agent 侧命令通道：ChaCha20 加密的 Unix 域 socket 服务端。
//
// imgui 悬浮层连接该服务端并交换分帧加密
// 文本消息。支持两个方向：
//   - 客户端 -> 服务端：命令（"ping"、"hello" 等），返回响应
//   - 服务端 -> 客户端：主动事件，以 "EVENT " 开头
//
// 每条消息的线上格式：4 字节大端负载长度 +
// ChaCha20 加密负载。密钥材料（32 字节密钥 + 12 字节 nonce）
// 在启动时生成并写入 /data/local/tmp，供应用侧
// 加载。客户端->服务端与服务端->客户端使用两个不同 nonce（
// nonce[0] 中的方向位），每侧各自维护方向消息
// 计数器，确保同一个 key+nonce+counter 组合不会被重复使用。

#include "socket.h"
#include "lua/LuaEngine.h"
#include "xdl.h"

#include <android/log.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
constexpr char kKeyPath[]    = "/data/local/tmp/universal_debug_tool_key.bin";
constexpr size_t kKeyLen     = 32;
constexpr size_t kNonceLen   = 12;
constexpr size_t kMaxMsg     = 1024 * 1024;  // 1 MiB 负载上限

// 抽象 socket 名称。刻意使用固定名称：目标可能是
// zygote USAP 进程，其 /proc/self/cmdline 是 "usap64" 而不是
// 包名，因此从进程推导名称会与应用侧不一致。
// 工具同时只与一个目标通信，固定名称没有问题。
// 抽象 socket 不创建文件系统对象，因此 SELinux 对
// /data/local/tmp 的 sock_file 限制（曾拒绝我们的 bind）不适用。
std::string GetSocketName() {
    return "udt_debug_chan";
}

std::atomic<bool> g_running{false};
int               g_listen_fd = -1;
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

// ── 密钥文件 ───────────────────────────────────────────
bool GenerateKeyFile() {
    // 如果已有预先创建的密钥文件则复用：注入器（以 root
    // 运行）在注入前会写入一份，因此即使本进程
    // 创建文件被 SELinux 限制，通道仍能工作。
    FILE* existing = fopen(kKeyPath, "rb");
    if (existing) {
        size_t ek = fread(g_key, 1, kKeyLen, existing);
        size_t en = fread(g_nonce, 1, kNonceLen, existing);
        fclose(existing);
        if (ek == kKeyLen && en == kNonceLen) {
            LOGI("using existing key file: %s", kKeyPath);
            return true;
        }
    }

    FILE* urand = fopen("/dev/urandom", "rb");
    if (!urand) {
        LOGE("cannot open /dev/urandom: %s", strerror(errno));
        return false;
    }
    size_t k = fread(g_key, 1, kKeyLen, urand);
    size_t n = fread(g_nonce, 1, kNonceLen, urand);
    fclose(urand);
    if (k != kKeyLen || n != kNonceLen) {
        LOGE("short read from /dev/urandom: key=%zu nonce=%zu", k, n);
        return false;
    }

    FILE* f = fopen(kKeyPath, "wb");
    if (!f) {
        LOGE("cannot write key file %s: %s", kKeyPath, strerror(errno));
        return false;
    }
    fwrite(g_key, 1, kKeyLen, f);
    fwrite(g_nonce, 1, kNonceLen, f);
    fclose(f);
    if (chmod(kKeyPath, 0666) != 0) {   // imgui 悬浮层（其他应用 uid）必须能读取它
        LOGE("chmod key file %s failed: %s", kKeyPath, strerror(errno));
    }
    LOGI("key file written: %s", kKeyPath);
    return true;
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
    if (cmd == "lua_reset") {
        LuaEngine::Reset();
        return "lua engine reset ok";
    }
    if (cmd.rfind("lua ", 0) == 0) {
        return LuaEngine::RunScript(cmd.substr(4));
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
        LOGI("recv cmd: %s", cmd.c_str());

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

void* ServerThread(void*) {
    if (!GenerateKeyFile()) {
        LOGE("failed to generate key file");
        g_running = false;
        return nullptr;
    }

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
        LOGE("bind(@%s) failed: %s", sockName.c_str(), strerror(errno));
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

    g_listen_fd = fd;
    LOGI("socket server listening: @%s", sockName.c_str());

    while (g_running.load()) {
        int c = accept(fd, nullptr, nullptr);
        if (c < 0) {
            if (errno != EINTR) usleep(100000);
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

    close(fd);
    g_listen_fd = -1;
    return nullptr;
}

} // 匿名命名空间

extern "C" {

int AgentSocketStart() {
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

void AgentSocketStop() {
    g_running = false;
    if (g_listen_fd >= 0) shutdown(g_listen_fd, SHUT_RDWR);
    int c = g_client_fd.load();
    if (c >= 0) shutdown(c, SHUT_RDWR);
    unlink(kSocketPath);
}

} // extern "C"

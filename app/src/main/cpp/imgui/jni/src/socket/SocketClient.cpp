// ImGui 侧加密通道客户端。
//
// 与 agent 的服务端实现对应：相同的分帧、相同的 ChaCha20
// 核心、相同的密钥文件、相同的方向 nonce。参见 agent_socket.cpp。

#include "socket/socket.h"

#include <android/log.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#include <chrono>
#include <vector>

#define TAG "SocketClient"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

namespace {

constexpr char kSocketPath[] = "/data/local/tmp/universal_debug_tool.sock";
constexpr char kKeyPath[]    = "/data/local/tmp/universal_debug_tool_key.bin";
constexpr size_t kKeyLen     = 32;
constexpr size_t kNonceLen   = 12;
constexpr size_t kMaxMsg     = 1024 * 1024;  // 1 MiB 负载上限
constexpr int    kConnectAttempts = 30;      // 约 15 秒重试（每次 500ms）
constexpr int    kConnectDelayMs  = 500;

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
        ssize_t w = write(fd, data + off, n - off);
        if (w <= 0) return false;
        off += (size_t)w;
    }
    return true;
}

bool RecvExact(int fd, uint8_t* data, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, data + off, n - off);
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

} // 匿名命名空间

SocketClient g_socket;

SocketClient::SocketClient() {
    memset(m_key, 0, sizeof(m_key));
    memset(m_nonce, 0, sizeof(m_nonce));
    signal(SIGPIPE, SIG_IGN);  // 向已关闭管道 write() 不能杀死进程
    SetStatus("未连接");
}

SocketClient::~SocketClient() {
    Disconnect();
}

namespace {
// 通过 `su -c cat` 读取 44 字节的密钥 + nonce，绕过
// 可能阻止应用直接读取的 DAC/SELinux 限制。
bool ReadKeyViaRoot(uint8_t* key, uint8_t* nonce, const char* path) {
    char cmd[320];
    snprintf(cmd, sizeof(cmd), "su -c 'cat %s' 2>/dev/null", path);
    FILE* p = popen(cmd, "r");
    if (!p) return false;
    size_t k = fread(key, 1, 32, p);
    size_t n = fread(nonce, 1, 12, p);
    pclose(p);
    return k == 32 && n == 12;
}
} // 匿名命名空间

bool SocketClient::LoadKeyFile() {
    FILE* f = fopen(kKeyPath, "rb");
    if (!f) {  // 直接读取失败
        // Root 回退：应用有 su 权限，通过 shell 读取
        // 即使在 SELinux/DAC 阻止直接打开时也能工作。
        if (ReadKeyViaRoot(m_key, m_nonce, kKeyPath)) return true;
        char buf[192];
        snprintf(buf, sizeof(buf), "无法读取密钥文件 %s: %s",
                 kKeyPath, strerror(errno));
        SetError(buf);
        LOGE("%s", buf);
        return false;
    }
    size_t k = fread(m_key, 1, kKeyLen, f);
    size_t n = fread(m_nonce, 1, kNonceLen, f);
    fclose(f);
    if (k != kKeyLen || n != kNonceLen) {
        char buf[192];
        snprintf(buf, sizeof(buf), "密钥文件 %s 内容不完整 (%zu/%zu 字节)",
                 kKeyPath, k, kKeyLen);
        SetError(buf);
        LOGE("%s", buf);
        return false;
    }
    return true;
}

int SocketClient::SpawnRelay(int& read_fd, int& write_fd) {
    // 注入器可执行文件（通过 su 以 root 运行）连接到 agent socket，
    // 并在 socket 与 stdin/stdout 之间转发字节。尝试常见应用路径。
    static const char* kRelayPaths[] = {
        "/data/user/0/com.example.unversaldebugtool/files/injector",
        "/data/data/com.example.unversaldebugtool/files/injector",
        nullptr,
    };
    for (int i = 0; kRelayPaths[i]; ++i) {
        if (access(kRelayPaths[i], X_OK) != 0) continue;
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "su -c '%s --relay %s' 2>/dev/null",
                 kRelayPaths[i], SocketName().c_str());

        int to_child[2], from_child[2];
        if (pipe(to_child) != 0 || pipe(from_child) != 0) return -1;

        pid_t pid = fork();
        if (pid < 0) {
            close(to_child[0]); close(to_child[1]);
            close(from_child[0]); close(from_child[1]);
            return -1;
        }
        if (pid == 0) {
            dup2(to_child[0], STDIN_FILENO);
            dup2(from_child[1], STDOUT_FILENO);
            close(to_child[0]); close(to_child[1]);
            close(from_child[0]); close(from_child[1]);
            execl("/system/bin/sh", "sh", "-c", cmd, (char*)nullptr);
            _exit(127);
        }
        close(to_child[0]);
        close(from_child[1]);
        write_fd = to_child[1];
        read_fd = from_child[0];
        return (int)pid;
    }
    return -1;
}

int SocketClient::ConnectOnce() {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        char buf[192];
        snprintf(buf, sizeof(buf), "创建套接字失败: %s", strerror(errno));
        SetError(buf);
        LOGE("%s", buf);
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    // 抽象 socket（不创建文件，因此不适用 SELinux sock_file 限制）；
    // 名称由目标包名推导。
    std::string sockName = SocketName();
    addr.sun_path[0] = '\0';
    strncpy(&addr.sun_path[1], sockName.c_str(), sizeof(addr.sun_path) - 2);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        char buf[192];
        snprintf(buf, sizeof(buf), "无法连接 %s: %s",
                 kSocketPath, strerror(errno));
        SetError(buf);
        LOGE("%s", buf);
        close(fd);

        // 直接连接失败（SELinux 可能阻止应用的跨进程连接）；
        // 回退到 root 中继（通过 su 运行注入器）。
        int rfd = -1, wfd = -1;
        int rpid = SpawnRelay(rfd, wfd);
        if (rpid < 0) {
            char ebuf[192];
            snprintf(ebuf, sizeof(ebuf), "无法连接 %s: %s (root relay 启动失败)",
                     kSocketPath, strerror(errno));
            SetError(ebuf);
            LOGE("%s", ebuf);
            return -1;
        }
        {
            std::lock_guard<std::mutex> lk(m_io_mutex);
            m_relay_read = rfd;
            m_relay_write = wfd;
            m_relay_pid = rpid;
        }
        // 给中继一点连接时间。如果它立即退出，说明
        // agent socket 未就绪（目标未注入 / 进程已重启）；
        // 报告这一原因，而不是笼统的 "connection closed"。
        usleep(300 * 1000);
        int wstatus = 0;
        pid_t wres = waitpid(rpid, &wstatus, WNOHANG);
        if (wres == rpid) {
            close(rfd);
            close(wfd);
            {
                std::lock_guard<std::mutex> lk(m_io_mutex);
                m_relay_read = -1;
                m_relay_write = -1;
                m_relay_pid = -1;
            }
            SetError("agent 未响应 (Connection refused)：请确认已注入且目标进程存活");
            return -1;
        }
        return rfd;
    }
    return fd;
}

void SocketClient::ConnectLoop() {
    SetError("");
    m_connecting.store(true);
    SetStatus("连接中...");

    int fd = -1;
    for (int i = 0; i < kConnectAttempts && m_running.load(); ++i) {
        if (LoadKeyFile()) {
            fd = ConnectOnce();
            if (fd >= 0) break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(kConnectDelayMs));
    }

    if (fd < 0) {
        std::string err = LastError();
        SetStatus(err.empty() ? "未连接" : "未连接: " + err);
        m_connecting.store(false);
        LOGI("connect failed after %d attempts", kConnectAttempts);
        return;
    }

    {
        std::lock_guard<std::mutex> lk(m_io_mutex);
        m_fd = fd;
        m_send_counter = 0;
    }
    m_connected.store(true);
    SetError("");
    SetStatus("已连接");

    // 即发即忘的握手；事件与 hello 响应由下面的 RecvLoop
    // 消费，同时把状态更新为 "已连接(pid=..)"。
    {
        std::lock_guard<std::mutex> lk(m_io_mutex);
        uint8_t n[12];
        DirectionNonce(m_nonce, false, n);
        int sfd = (m_relay_write >= 0) ? m_relay_write : m_fd;
        SendMessage(sfd, reinterpret_cast<const uint8_t*>("hello"), 5,
                    m_key, n, m_send_counter);
    }

    RecvLoop(fd);   // 阻塞直到连接断开或调用 Disconnect()

    {
        std::lock_guard<std::mutex> lk(m_io_mutex);
        if (m_fd == fd) {
            close(fd);
            m_fd = -1;
        }
        if (m_relay_pid > 0) kill(m_relay_pid, SIGTERM);
        m_relay_pid = -1;
        if (m_relay_write >= 0) close(m_relay_write);
        m_relay_write = -1;
        m_relay_read = -1;
    }
    m_connected.store(false);
    m_agent_pid.store(-1);
    SetStatus("未连接");
    m_connecting.store(false);

    // 唤醒仍在等待响应的 SendCommand()。
    {
        std::lock_guard<std::mutex> lk(m_resp_mutex);
        m_resp_text = "错误: 连接已断开";
        m_resp_ready = true;
    }
    m_resp_cv.notify_all();
    LOGI("connection closed");
}

void SocketClient::RecvLoop(int fd) {
    uint32_t recv_counter = 0;
    uint8_t nonce_s2c[12];
    DirectionNonce(m_nonce, true, nonce_s2c);

    while (m_running.load()) {
        std::string msg;
        if (!RecvMessage(fd, msg, m_key, nonce_s2c, recv_counter)) break;

        if (msg.rfind("EVENT ", 0) == 0) {
            std::string ev = msg.substr(6);
            LOGI("event: %s", ev.c_str());
            {
                std::lock_guard<std::mutex> lk(m_info_mutex);
                m_last_event = ev;
            }
            size_t p = ev.find("pid=");
            if (p != std::string::npos) {
                int pid = atoi(ev.c_str() + p + 4);
                m_agent_pid.store(pid);
                char st[64];
                snprintf(st, sizeof(st), "已连接(pid=%d)", pid);
                SetStatus(st);
            }
        } else {
            LOGI("response: %s", msg.c_str());
            {
                std::lock_guard<std::mutex> lk(m_info_mutex);
                m_last_response = msg;
            }
            std::lock_guard<std::mutex> lk(m_resp_mutex);
            m_resp_text = msg;
            m_resp_ready = true;
            m_resp_cv.notify_one();
        }
    }
}

void SocketClient::ConnectAsync() {
    if (m_connected.load() || m_connecting.load()) return;
    if (m_thread.joinable()) m_thread.join();   // 回收上一个工作线程
    m_running.store(true);
    m_thread = std::thread(&SocketClient::ConnectLoop, this);
}

void SocketClient::Disconnect() {
    m_running.store(false);
    {
        std::lock_guard<std::mutex> lk(m_io_mutex);
        // 对于中继连接，关闭写管道会使中继的 stdin 到达 EOF，
        // 从而退出并解除 RecvLoop 的阻塞。
        if (m_relay_pid > 0) kill(m_relay_pid, SIGTERM);
        m_relay_pid = -1;
        if (m_relay_write >= 0) close(m_relay_write);
        m_relay_write = -1;
        m_relay_read = -1;
        if (m_fd >= 0) shutdown(m_fd, SHUT_RDWR);  // 解除 RecvLoop 阻塞
    }
    if (m_thread.joinable()) m_thread.join();
}

void SocketClient::SetTargetPackage(const std::string& pkg) {
    std::lock_guard<std::mutex> lk(m_io_mutex);
    m_target_pkg = pkg;
}

std::string SocketClient::SocketName() const {
    // 固定名称，与 agent 的抽象 socket 一致。目标进程
    // 可能是 cmdline 不是包名的 zygote USAP，因此
    // 名称不能依赖 cmdline。
    return "udt_debug_chan";
}

std::string SocketClient::SendCommand(const std::string& cmd, int timeoutMs) {
    {
        std::lock_guard<std::mutex> lk(m_resp_mutex);
        m_resp_ready = false;
        m_resp_text.clear();
    }
    {
        std::lock_guard<std::mutex> lk(m_io_mutex);
        if (m_fd < 0) return "错误: 未连接";
        uint8_t n[12];
        DirectionNonce(m_nonce, false, n);
        int sfd = (m_relay_write >= 0) ? m_relay_write : m_fd;
        if (!SendMessage(sfd, reinterpret_cast<const uint8_t*>(cmd.data()),
                         cmd.size(), m_key, n, m_send_counter))
            return "错误: 发送失败";
    }

    std::unique_lock<std::mutex> lk(m_resp_mutex);
    if (!m_resp_cv.wait_for(lk, std::chrono::milliseconds(timeoutMs),
                            [this] { return m_resp_ready; })) {
        return "错误: 响应超时";
    }
    return m_resp_text;
}

bool SocketClient::IsConnected() const { return m_connected.load(); }
bool SocketClient::IsConnecting() const { return m_connecting.load(); }
int  SocketClient::AgentPid() const { return m_agent_pid.load(); }

void SocketClient::SetStatus(const std::string& s) {
    std::lock_guard<std::mutex> lk(m_status_mutex);
    m_status = s;
}

void SocketClient::SetError(const std::string& e) {
    std::lock_guard<std::mutex> lk(m_info_mutex);
    m_last_error = e;
}

std::string SocketClient::StatusText() const {
    std::lock_guard<std::mutex> lk(m_status_mutex);
    return m_status;
}

std::string SocketClient::LastError() const {
    std::lock_guard<std::mutex> lk(m_info_mutex);
    return m_last_error;
}

std::string SocketClient::LastEvent() const {
    std::lock_guard<std::mutex> lk(m_info_mutex);
    return m_last_event;
}

std::string SocketClient::LastResponse() const {
    std::lock_guard<std::mutex> lk(m_info_mutex);
    return m_last_response;
}

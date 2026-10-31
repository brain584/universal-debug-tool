#ifndef UDT_CHANNEL_KEY_H
#define UDT_CHANNEL_KEY_H

// 通道密钥（key 32B + nonce 12B）的生成与持久化。
//
// 旧实现把密钥写进 `/data/local/tmp/universal_debug_tool_key.bin` 并 `chmod 0666`：
//   · 任何能读该路径的进程都能拿到密钥，再连上 agent 的抽象 socket（名字固定）
//     即可发 `lua <脚本>` → **在目标进程里执行任意代码**；
//   · agent 侧也没有任何对端身份校验。
// 现在：
//   1. 密钥文件只放在 **本 App 私有目录**（`<filesDir>/channel_key.bin`，0600，
//      受 Android 沙箱保护，其他 App 读不到）；
//   2. 注入器（root）只**读取**它并把密钥通过远程内存写进目标进程，agent 只在内存里持有；
//   3. agent 用 SO_PEERCRED 只放行 root（relay）与 GUI 的 uid。
//
// 因此本文件只是"GUI 侧的密钥存取"，不再是跨进程共享的明文通道。
//
// 注意：这是纯头文件实现（inline 变量），本工程里 native-lib.cpp / SocketClient.cpp /
// 注入命令拼装都在同一个 libunversaldebugtool.so 内，故共享同一份实例。

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace ChannelKey {

// agent 与 GUI 之间的认证材料。与 injector + agent 里的结构**逐字节一致**。
struct Blob {
    uint32_t magic;        // kMagic
    uint32_t version;      // kVersion
    uint8_t  key[32];      // ChaCha20 key
    uint8_t  nonce[12];    // 基础 nonce（双向各派生一个方向位）
    uint32_t client_uid;   // 允许直接连接的 GUI uid（relay 的 root 另算）
};
static_assert(sizeof(Blob) == 56, "ChannelKey::Blob 布局必须与 agent/injector 一致");

inline constexpr uint32_t kMagic = 0x43525441u;   // 'ATRC'（小端）
inline constexpr uint32_t kVersion = 1;

inline constexpr size_t kKeyLen = 32;
inline constexpr size_t kNonceLen = 12;
inline constexpr size_t kMaterialLen = kKeyLen + kNonceLen;   // 44

// 配置目录由 native-lib 在 nativeSetConfigDir 时注入。
inline std::string& DirRef() {
    static std::string dir;
    return dir;
}

inline void SetConfigDir(const std::string& dir) { DirRef() = dir; }

inline std::string Path() {
    const std::string& d = DirRef();
    if (d.empty()) return std::string();
    return d + "/channel_key.bin";
}

namespace detail {

inline bool ReadAll(int fd, void* buf, size_t len) {
    uint8_t* p = static_cast<uint8_t*>(buf);
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, p + off, len - off);
        if (r <= 0) return false;
        off += static_cast<size_t>(r);
    }
    return true;
}

inline bool FillRandom(void* buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = ReadAll(fd, buf, len);
    close(fd);
    return ok;
}

} // namespace detail

/**
 * 读取已有密钥；不存在/损坏则生成一份并写入 App 私有目录（0600）。
 *
 * @return true 表示 key/nonce 已就绪。失败时（例如目录不可写）会退化为
 *         **仅内存密钥**（不落盘）并返回 true —— 此时注入时注入器读不到文件，
 *         通道会不可用，但不会静默降级到不安全的共享文件。
 */
inline bool Ensure(uint8_t key[kKeyLen], uint8_t nonce[kNonceLen]) {
    static std::mutex mu;
    std::lock_guard<std::mutex> lk(mu);

    const std::string path = Path();
    if (!path.empty()) {
        int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            uint8_t buf[kMaterialLen];
            bool ok = detail::ReadAll(fd, buf, sizeof(buf));
            close(fd);
            if (ok) {
                // 顺手把权限收紧到 0600（兼容旧版本残留文件）
                chmod(path.c_str(), S_IRUSR | S_IWUSR);
                memcpy(key, buf, kKeyLen);
                memcpy(nonce, buf + kKeyLen, kNonceLen);
                return true;
            }
        }
    }

    uint8_t buf[kMaterialLen];
    if (!detail::FillRandom(buf, sizeof(buf))) {
        return false;
    }

    if (!path.empty()) {
        int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                      S_IRUSR | S_IWUSR);
        if (fd >= 0) {
            ssize_t w = write(fd, buf, sizeof(buf));
            close(fd);
            chmod(path.c_str(), S_IRUSR | S_IWUSR);
            if (w != static_cast<ssize_t>(sizeof(buf))) {
                // 写失败：继续用内存里的这一份（本次注入仍可工作）
                unlink(path.c_str());
            }
        }
    }
    memcpy(key, buf, kKeyLen);
    memcpy(nonce, buf + kKeyLen, kNonceLen);
    return true;
}

} // namespace ChannelKey

#endif // UDT_CHANNEL_KEY_H

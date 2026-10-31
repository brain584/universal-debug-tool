// Agent 载荷——由注入器注入到目标进程中。
//
//   · 构造函数只初始化 Lua 引擎；
//   · socket 的密钥/对端 uid 由注入器通过远程内存写入，然后调用导出的
//     AgentStartWithAuth(blob) 才真正开始监听（见 socket/socket.cpp）。
// 这样即使库被其他方式 dlopen，也不会出现"无密钥监听"的通道。
//
// 注入器以 reserved = 1337 调用 JNI_OnLoad（仅作为识别标记）。
//
// data-only 注入只做到"让目标自己 dlopen 我们的 so"，**没有远程调用函数的
// 能力**，所以 ptrace 路径那句 AgentStartWithAuth() 永远不会发生 —— 这就是
// 之前"注入显示成功、agent_status 却是未连接"的根因。
// 现在由 root 侧（injector/src/zeroptrace_injector.cpp 的 zpt_handoff_*）在
// 触发 dlopen **之前**写好交接文件，本构造函数在 Lua 初始化之后消费它们：
//
//   /data/local/tmp/zpt_auth.bin   56B AgentAuthBlob，0600，chown 目标进程 uid
//   /data/local/tmp/zpt_auth.ready 空文件（预创建，同上权限），成功启动后写 "1"
//
// 流程：读 56B → **立刻把文件清零**（密钥不留在磁盘上）→ 校验 magic/version
//      → AgentStartWithAuth(blob) → 返回 0 才写就绪标记。
// 文件不存在 = 常规 ptrace 注入路径：保持原语义，只 Init Lua、不监听
// （认证材料随后由注入器经远程内存送进来）。
// 安全边界：密钥只在"root 写文件 → agent 读走并清零"这个窗口内以 0600 落盘；
// zpt 侧无论成败都会再清零 + unlink。前提是本机 SELinux Permissive ——
// Enforcing 下目标进程读不到 root 在 /data/local/tmp 创建的文件，这条链会失败，
// 由 zpt 如实报【失败】，不会误报成功。
#include <jni.h>
#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "socket/socket.h"
#include "lua/LuaEngine.h"

#define LOG_TAG "Agent"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

constexpr int INJECTOR_SECRET_KEY = 1337;

// ── 零 ptrace 交接文件（路径/格式必须与 injector/src/zeroptrace_injector.cpp 一致）──
constexpr const char* kZptAuthPath  = "/data/local/tmp/zpt_auth.bin";
constexpr const char* kZptReadyPath = "/data/local/tmp/zpt_auth.ready";

constexpr uint32_t kAuthMagic   = 0x43525441u;   // 'ATRC'
constexpr uint32_t kAuthVersion = 1;
constexpr size_t   kKeyLen      = 32;
constexpr size_t   kNonceLen    = 12;

// 与 backend/jni/src/socket/ChannelKey.h::Blob、socket/socket.cpp 的
// AgentAuthBlob **逐字节一致**（56 字节）。这里只是交接文件的本地解码副本：
// 真正的校验与使用仍在 socket.cpp 的 ApplyAuthBlob()/AgentStartWithAuth() 里。
struct AgentAuthBlobLocal {
    uint32_t magic;
    uint32_t version;
    uint8_t  key[kKeyLen];
    uint8_t  nonce[kNonceLen];
    uint32_t client_uid;
};
static_assert(sizeof(AgentAuthBlobLocal) == 56, "AgentAuthBlob 必须是 56 字节");

// 读满 len 字节（EINTR/短读重试）。返回实际读到的字节数。
static ssize_t ReadFull(int fd, void* dst, size_t len) {
    uint8_t* p = static_cast<uint8_t*>(dst);
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, p + off, len - off);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        off += static_cast<size_t>(r);
    }
    return static_cast<ssize_t>(off);
}

// 写满 len 字节。写失败只影响"就绪标记"，调用方会据此报失败。
static bool WriteFull(int fd, const void* src, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(src);
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        off += static_cast<size_t>(w);
    }
    return true;
}

// 消费零 ptrace 交接文件。文件不存在时**什么都不做**（常规 ptrace 注入语义不变）。
static void TryStartAgentFromHandoff() {
    int fd = open(kZptAuthPath, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        if (errno != ENOENT) {
            LOGE("handoff: open %s failed: %d (%s)", kZptAuthPath, errno, strerror(errno));
        }
        return;   // 常规注入：认证材料由注入器稍后经远程内存传入
    }

    AgentAuthBlobLocal blob;
    memset(&blob, 0, sizeof(blob));
    ssize_t got = ReadFull(fd, &blob, sizeof(blob));

    // 读后立刻清零文件：无论内容是否有效，密钥都不该在磁盘上继续留存。
    uint8_t zeros[sizeof(AgentAuthBlobLocal)] = {0};
    if (pwrite(fd, zeros, sizeof(zeros), 0) != static_cast<ssize_t>(sizeof(zeros))) {
        LOGE("handoff: zero %s failed: %d (%s)", kZptAuthPath, errno, strerror(errno));
    }
    close(fd);

    if (got != static_cast<ssize_t>(sizeof(blob))) {
        LOGE("handoff: short read %zd/%zu bytes", got, sizeof(blob));
        memset(&blob, 0, sizeof(blob));
        return;
    }
    if (blob.magic != kAuthMagic || blob.version != kAuthVersion) {
        // 过期/损坏（典型：上一次 zpt 被 2s 超时清掉后残留的空文件）
        LOGE("handoff: bad blob magic/version (0x%x/%u)", blob.magic,
             static_cast<unsigned>(blob.version));
        memset(&blob, 0, sizeof(blob));
        return;
    }

    int rc = AgentStartWithAuth(&blob);   // 只有真的开始监听才返回 0
    memset(&blob, 0, sizeof(blob));
    if (rc != 0) {
        LOGE("handoff: AgentStartWithAuth rc=%d (socket NOT listening)", rc);
        return;
    }

    // 就绪标记：文件由 root 预创建并 chown 目标 uid，所以这里只需要**文件**
    // 写权限，不需要 /data/local/tmp 的目录写权限（该目录对 app uid 是 0771）。
    int rf = open(kZptReadyPath, O_WRONLY | O_CLOEXEC | O_TRUNC);
    if (rf < 0) {
        LOGE("handoff: open ready marker %s failed: %d (%s)", kZptReadyPath, errno,
             strerror(errno));
        return;
    }
    bool wrote = WriteFull(rf, "1", 1);
    close(rf);
    if (wrote) {
        LOGI("handoff: agent started from handoff file; ready marker written");
    } else {
        LOGE("handoff: write ready marker failed: %d (%s)", errno, strerror(errno));
    }
}

__attribute__((constructor))
static void OnAgentLoad() {
    LOGI("Agent loaded into pid=%d (constructor)", getpid());
    // 先初始化 Lua 引擎：socket 线程一旦开始 accept，命令就可能立刻进来。
    LuaEngine::Init();
    LOGI("Agent Lua engine init done");
    // 零 ptrace 路径：如果 root 已经放了认证交接文件，就在这里自己启动监听。
    // 常规 ptrace 路径没有该文件 → 直接返回，仍由注入器调用 AgentStartWithAuth。
    TryStartAgentFromHandoff();
}

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("Agent JNI_OnLoad vm=%p reserved=%p", vm, reserved);
    LuaEngine::SetJavaVM(vm);
    if (reserved == reinterpret_cast<void*>(INJECTOR_SECRET_KEY)) {
        LOGI("Agent: injected by universal_debug_tool");
    }
    // 注意：这里**不**启动 socket。socket 只可能由两条路启动：
    //   1) ptrace 注入器在 dlopen 之后调用 AgentStartWithAuth(keyBlob)；
    //   2) 上面的构造函数消费零 ptrace 交接文件。
    return JNI_VERSION_1_6;
}

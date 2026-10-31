#include <thread>
#include <elf.h>
#include <dirent.h>
#include <atomic>
// ============================================================================
//  zeroptrace_injector —— 零 ptrace 热注入 PoC（ARM64 / Android）
// ============================================================================
//
//  这是什么
//  --------
//  dlinject（https://github.com/DavidBuchanan314/dlinject）思路在 aarch64 上的
//  最小可验证实现，**全程不建立 ptrace 关系**：
//
//    1. 读 /proc/<tid>/syscall 拿到正在阻塞的 syscall 的 SP/PC（不是 PTRACE_GETREGS）
//    2. 不改寄存器，而是用 /proc/<pid>/mem 把「该线程恢复执行时的第一条指令」
//       覆盖成一条 `b`，跳到我们 mmap 出来的 payload
//    3. 线程从 syscall 返回时直接执行 payload；payload 做完事 `b` 回原 PC+4
//    4. 立刻把原 4 字节写回
//
//  为什么能写只读可执行页
//  ----------------------
//  /proc/<pid>/mem 的写入在内核走 access_remote_vm → follow_page + FOLL_FORCE，
//  绕过页写保护位（private file mapping 会 COW 出私有页，权限位继承 X）。
//  所以 **不需要 rwx 段**——Android 16 上 rwx 段为 0，但覆盖式注入照样成立。
//
//  执行器无关（本文件的关键设计）
//  ------------------------------
//  核心劫持逻辑与「是谁在写」无关，只差一个 fd：
//      * 外部注入（本工具，需 root）：open("/proc/<target_pid>/mem", O_RDWR)
//      * 自注入  （无 root 可跑）    ：open("/proc/self/mem", O_RDWR)
//  两种模式跑的是**同一套** plan_payload / install_hook / restore_hook 代码。
//  本机（2510DRK44C）无普通 root，但装的是 KernelSU 分支，su 不在 PATH 上，
//  实际调用方式由用户侧确认（见 HANDOFF 里的 ROOT 一节）。
//
//  用法
//  ----
//    zeroptrace_injector <target_pid> <target_tid> <mailbox_addr> [--keep]
//        mailbox_addr: 目标进程内一个 8 字节可写地址（例如 &ammo）。
//                      payload 会把 magic 写进去，作为「代码真的执行了」的证据。
//    zeroptrace_injector --self <mailbox_addr>
//        自注入自检：自己起一个 nanosleep 线程，把它的恢复地址覆盖掉，看 magic 是否落地。
//        这条路径**不需要任何权限**，用来在无 root 设备上验证整条劫持链。
//
//  安全边界（务必知道）
//  -------------------
//  * 只碰一个线程；被选中线程必须在可重启的 syscall 里（nanosleep/futex/epoll_wait…）。
//    若线程阻塞在**不可重启**的 syscall（read/write/recv），payload 的 `b` 回去后
//    该 syscall 不会重做，调用者会看到「返回 0 但没做事」——这是本方案的真实限制。
//  * 覆盖的那 4 字节是全局的：如果同一进程里有**别的线程**也在执行同一地址，
//    它们会一起跳进 payload。nanosleep 只在被选中的那个线程里调用，所以本 PoC 安全；
//    真实目标要按「该地址只被一个线程执行」来选。
//
//  本文件是自用研究代码，无法保证稳健性以及是否能够正常使用，在本人的测试靶场是正常的
// ============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <android/log.h>
#include <atomic>
#include <setjmp.h>
#include <sys/signal.h>

#define ZPT_TRACE_FILE "/data/local/tmp/zpt_trace.txt"
#define LOG_TAG "ZPTInject"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// 关键步骤同时写文件：logcat 环形缓冲会被目标 App 的刷屏挤掉（实测过），
// 导致注入器前半段日志全丢，只能看到尾部 —— 排障时非常致命。
static void tlog(const char* fmt, ...) {
    FILE* f = fopen(ZPT_TRACE_FILE, "ae");
    if (!f) return;
    va_list ap; va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fclose(f);
}
#define TLOG(...) do { LOGI(__VA_ARGS__); tlog(__VA_ARGS__); } while (0)

// ═════════════════════════════════════════════════════════════════════════════
// ═════════════════════════════════════════════════════════════════════════════
//
//  为什么需要它：ptrace 注入器可以在目标里**远程调用** AgentStartWithAuth(blob)；
//  data-only 路径没有这个能力，只能让目标自己 dlopen 我们的 so。而 agent 的
//  构造函数（agent/jni/main.cpp）刻意不在加载时监听 —— 没有认证材料就不 listen
//  （socket.cpp 的 AgentSocketStart 在 g_auth_ready=false 时直接拒绝）。
//  所以这里用**文件**当"函数调用"的替身：
//    1) root（本进程）从 App 私有目录读 44B（32 key + 12 nonce），拼成 56B
//       AgentAuthBlob，写到 /data/local/tmp/zpt_auth.bin；
//    2) chown 给**目标进程 uid**、chmod 0600 —— 只有目标 uid 和 root 能读；
//    3) 再预创建一个空的就绪标记 zpt_auth.ready（同样 chown 目标 uid 0600）。
//       agent 只需要**文件写权限**（app uid 对 /data/local/tmp 没有写权限，
//       但预创建的文件是它的，可以写），所以这里不需要 0777 该目录；
//    4) 触发 dlopen → agent 构造函数读 blob → 立刻清零文件 →
//       AgentStartWithAuth → 成功才把 "1" 写进就绪文件；
//    5) 本进程轮询就绪文件（最多 2s），**只有看到 "1" 才允许打印【成功】**。
//  安全边界：密钥只在"写文件 → agent 读走并清零"这个窗口内以 0600 落盘；
//  本进程收尾时无论成败都会再清零 + unlink。前提是本机 SELinux Permissive；
//  Enforcing 下目标读不到 root 在 /data/local/tmp 创建的文件，这条链会失败，
//  并如实打印【失败】（不会退回"只看 so 是否加载"的旧误报口径）。
// ═════════════════════════════════════════════════════════════════════════════
#define ZPT_AUTH_BIN   "/data/local/tmp/zpt_auth.bin"
#define ZPT_AUTH_READY "/data/local/tmp/zpt_auth.ready"
#define ZPT_AUTH_MAGIC   0x43525441u   // 'ATRC'，与 ChannelKey.h / socket.cpp 一致
#define ZPT_AUTH_VERSION 1u
#define ZPT_KEY_LEN      32
#define ZPT_NONCE_LEN    12

// 与 backend/jni/src/socket/ChannelKey.h::Blob、agent/socket.cpp 的 AgentAuthBlob
// 逐字节一致（56 字节）。
struct ZptAuthBlob {
    uint32_t magic;
    uint32_t version;
    uint8_t  key[ZPT_KEY_LEN];
    uint8_t  nonce[ZPT_NONCE_LEN];
    uint32_t client_uid;
};
static_assert(sizeof(ZptAuthBlob) == 56, "AgentAuthBlob 必须是 56 字节");

// 目标进程的 uid（/proc/<pid>/status 的 Uid 行，real uid）。
static bool zpt_target_uid(pid_t tpid, uid_t* out) {
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/status", (int)tpid);
    FILE* f = fopen(p, "re");
    if (!f) return false;
    char line[256];
    bool ok = false;
    while (fgets(line, sizeof(line), f)) {
        unsigned int u = 0;
        if (sscanf(line, "Uid:\t%u", &u) == 1) { *out = (uid_t)u; ok = true; break; }
    }
    fclose(f);
    return ok;
}

// 精确读 len 字节（EINTR/短读重试）。
static bool zpt_read_exact(const char* path, void* dst, size_t len) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    uint8_t* p = (uint8_t*)dst;
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, p + off, len - off);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) break;
        off += (size_t)r;
    }
    close(fd);
    return off == len;
}

// 创建 root 文件 → chown 目标 uid → chmod 0600（data 为 NULL/len 0 时只建空文件）。
static bool zpt_create_owned(const char* path, uid_t uid, const void* data, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        TLOG("交接文件创建失败 %s errno=%d (%s)", path, errno, strerror(errno));
        return false;
    }
    bool ok = true;
    if (fchown(fd, uid, uid) != 0) {
        TLOG("交接文件 chown 失败 %s -> uid=%u errno=%d (%s)",
             path, (unsigned)uid, errno, strerror(errno));
        ok = false;
    }
    if (ok && fchmod(fd, 0600) != 0) {
        TLOG("交接文件 chmod 0600 失败 %s errno=%d", path, errno);
        ok = false;
    }
    if (ok && len > 0) {
        size_t off = 0;
        const uint8_t* p = (const uint8_t*)data;
        while (off < len) {
            ssize_t w = write(fd, p + off, len - off);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) { ok = false; break; }
            off += (size_t)w;
        }
    }
    close(fd);
    if (!ok) { unlink(path); }
    return ok;
}

// 写交接文件。失败时 err 里放人话原因（用于最终【失败】文案）。
static bool zpt_handoff_write(pid_t tpid, const char* key_file, uint32_t client_uid,
                              char* err, size_t cap) {
    if (!key_file || !key_file[0]) {
        snprintf(err, cap, "未提供 --key-file（没有认证材料，agent 不会监听）");
        return false;
    }
    uid_t uid = 0;
    if (!zpt_target_uid(tpid, &uid)) {
        snprintf(err, cap, "读不到目标 uid（/proc/%d/status）", (int)tpid);
        return false;
    }

    uint8_t material[ZPT_KEY_LEN + ZPT_NONCE_LEN];
    if (!zpt_read_exact(key_file, material, sizeof(material))) {
        snprintf(err, cap, "读不到 44B 密钥文件 %s", key_file);
        return false;
    }
    ZptAuthBlob blob;
    memset(&blob, 0, sizeof(blob));
    blob.magic      = ZPT_AUTH_MAGIC;
    blob.version    = ZPT_AUTH_VERSION;
    memcpy(blob.key, material, ZPT_KEY_LEN);
    memcpy(blob.nonce, material + ZPT_KEY_LEN, ZPT_NONCE_LEN);
    blob.client_uid = client_uid;
    memset(material, 0, sizeof(material));

    // 先删旧文件：上一次失败/崩溃留下的过期材料绝不能被 agent 误用。
    unlink(ZPT_AUTH_READY);
    unlink(ZPT_AUTH_BIN);

    bool ok = zpt_create_owned(ZPT_AUTH_BIN, uid, &blob, sizeof(blob));
    memset(&blob, 0, sizeof(blob));
    if (!ok) {
        snprintf(err, cap, "写 auth 交接文件失败（%s）", ZPT_AUTH_BIN);
        return false;
    }
    if (!zpt_create_owned(ZPT_AUTH_READY, uid, nullptr, 0)) {
        unlink(ZPT_AUTH_BIN);
        snprintf(err, cap, "创建就绪标记失败（%s）", ZPT_AUTH_READY);
        return false;
    }
    TLOG("auth 交接文件已就绪: %s（56B, uid=%u, 0600，仅窗口期内有效）",
         ZPT_AUTH_BIN, (unsigned)uid);
    return true;
}

// 轮询就绪标记，只有内容为 "1" 才算 agent 真的开始监听。
static bool zpt_handoff_wait_ready(int timeout_ms, int interval_ms) {
    for (int waited = 0; waited <= timeout_ms; waited += interval_ms) {
        char b = 0;
        int fd = open(ZPT_AUTH_READY, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            ssize_t r = read(fd, &b, 1);
            close(fd);
            if (r == 1 && b == '1') return true;
        }
        usleep((useconds_t)interval_ms * 1000);
    }
    return false;
}

// 收尾：把 auth 文件再清零一次（agent 可能根本没被触发，没机会清），然后删掉两个文件。
static void zpt_handoff_cleanup() {
    int fd = open(ZPT_AUTH_BIN, O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        uint8_t z[sizeof(ZptAuthBlob)] = {0};
        ssize_t w = write(fd, z, sizeof(z));
        (void)w;
        close(fd);
    }
    unlink(ZPT_AUTH_BIN);
    unlink(ZPT_AUTH_READY);
}

#define ZPT_BUILD_TAG "guard-v3"
#define MAGIC 0x5A50544Du
// payload 入口标记（和 MAGIC 不同）：用来区分「根本没进去」和「进去后崩了」
#define MARK  0x5A505441u   // 'ZPTM' —— payload 写进 mailbox 的哨兵值

// payload 里用到的 MMAP 参数：留出 64KB 当 dlopen 期间的临时栈（检查点 B 会用）
#define PAYLOAD_SIZE   65536u
#define STACK_OFFSET   32768u
#define SCRATCH_OFFSET 4096u

// payload 数据区/代码区分界。**守卫绝不能落在代码实际用到的字节上**——
// 第一版守卫放在 base+24，而代码从 base+16 开始，结果 payload 执行时 stlxr
// 把自己的指令写成了 MAGIC，真挂钩时在 payload+0x18 执行到全零 -> SIGILL。
//
// 布局（已用反汇编核对）：
//     +0    MAGIC             (8)
//     +8    mailbox_addr      (8)
//     +16   x1 基址重建表保留  (8)
//     +24   保留              (8)
//     +32   保留              (8)
//     +40   保留              (8)
//     +48   保留              (8)
//     +56   保留              (8)
//     +64   代码起点 CODE_OFF（当前生成 60 字节，即到 +124）
//     +128  GUARD_OFF 守卫 —— 明确放在代码最大长度之后
//
// 代码最后一条是 `b`（单向出口，不会 fall through），所以守卫放在代码之后
// 既不会被指令流扫到，也不会被 CAS 写坏指令。
#define CODE_OFF    64
#define GUARD_OFF   128
static_assert(CODE_OFF >= 64, "数据区至少要 64 字节");
static_assert(GUARD_OFF >= CODE_OFF + 64, "守卫必须留出足够距离，避开代码实际长度");

// ─────────────────────────────────────────────────────────────────────────────
//  AArch64 指令编码器
// ─────────────────────────────────────────────────────────────────────────────

// 无条件直接跳转 `b`：imm26 是相对当前指令的**字**偏移，范围 ±128MB
static bool encode_b(uint64_t from, uint64_t to, uint32_t* out) {
    int64_t delta = (int64_t)to - (int64_t)from;
    if ((delta & 3) != 0) return false;
    int64_t words = delta / 4;
    if (words < -(1 << 25) || words > ((1 << 25) - 1)) return false;   // 超出 ±128MB
    *out = 0x14000000u | (uint32_t)(words & 0x03FFFFFF);
    return true;
}

// 下面几只编码器都按「Rd = 寄存器号」直接拼，取值仅在编译期常量上用。
// **每个常量都用 clang 汇编核对过**（方法见 ZEROPTRACE_NOTES.md 第五节）。
static uint32_t enc_movz_x(int rd, uint16_t imm16) {
    return 0xD2800000u | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}
static uint32_t enc_movk_x(int rd, uint16_t imm16, int shift) {
    return 0xF2800000u | ((uint32_t)(shift / 16) << 21) | ((uint32_t)imm16 << 5) | (uint32_t)rd;
}
// LDR/STR (64-bit, unsigned immediate)：0xF9400000/0xF9000000 | imm12(缩放 8)<<10 | Rn<<5 | Rt
//
// 【教训】这两个字段极容易搞混：imm12 在 bit[21:10]、Rn 在 bit[9:5]、Rt 在 bit[4:0]。
// 第一版手写 ldr 常量时把 Rd 编进了 imm 位域（0xF9400822 反汇编是 ldr x2,[x1,#0x10]），
// payload 于是从错误地址读 mailbox、一执行就崩。
// **手写机器码一律用反汇编器核对，不要靠位运算心算。**
static uint32_t enc_ldr_x_imm(int rt, int rn, unsigned off) {
    return 0xF9400000u | ((uint32_t)(off / 8) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
static uint32_t enc_str_x_imm(int rt, int rn, unsigned off) {
    return 0xF9000000u | ((uint32_t)(off / 8) << 10) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// CBZ/CBNZ (64-bit)：0xB4000000/0xB5000000 | imm19<<5 | Rt
static uint32_t enc_cbz_x(int rt, int words, bool nonzero) {
    return (nonzero ? 0xB5000000u : 0xB4000000u) |
           ((uint32_t)(words & 0x7FFFF) << 5) | (uint32_t)rt;
}
// CMP xN, xzr  = SUBS xzr, xN, xzr
static uint32_t enc_cmp_xzr(int rn) { return 0xEB1F001Fu | ((uint32_t)rn << 16); }
// B.cond：0x54000000 | imm19<<5 | cond
#define COND_NE 1
static uint32_t enc_bcond(int words, int cond) {
    return 0x54000000u | ((uint32_t)(words & 0x7FFFF) << 5) | (uint32_t)cond;
}
// 单寄存器 load/store exclusive（LL/SC）。任何 armv8-A 都能跑，不依赖 LSE。
// 实测 clang 汇编：ldaxr x3,[x1]=0xC85FFC23, stlxr w4,x2,[x1]=0xC804FC22
static uint32_t enc_ldaxr_x(int rt, int rn) {
    return 0xC85FFC00u | ((uint32_t)rn << 5) | (uint32_t)rt;
}
static uint32_t enc_stlxr_x(int rs, int rt, int rn) {
    return 0xC804FC00u | ((uint32_t)rs << 16) | ((uint32_t)rn << 5) | (uint32_t)rt;
}
// ADD (immediate, 64-bit, sh=0)：0x91000000 | imm12<<10 | Rn<<5 | Rd
// BR xN：间接跳转（目标来自寄存器/数据，不需要 i-cache 维护）
static uint32_t enc_br(int rn) { return 0xD61F0000u | ((uint32_t)rn << 5); }
static uint32_t enc_add_x_imm(int rd, int rn, unsigned imm) {
    return 0x91000000u | ((uint32_t)(imm & 0xFFF) << 10) | ((uint32_t)rn << 5) | (uint32_t)rd;
}
// 把 64 位常量装进寄存器（movz + 1~3 条 movk），最多 4 条
static int load_imm64(uint32_t* out, int rd, uint64_t v) {
    int n = 0;
    out[n++] = enc_movz_x(rd, (uint16_t)(v & 0xFFFF));
    for (int sh = 16; sh <= 48; sh += 16) {
        uint16_t part = (uint16_t)((v >> sh) & 0xFFFF);
        if (part) out[n++] = enc_movk_x(rd, part, sh);
    }
    return n;
}

// ─────────────────────────────────────────────────────────────────────────────
//  /proc/<tid>/syscall 读取
// ─────────────────────────────────────────────────────────────────────────────
//
//  arm64 完整格式：`syscallno arg0..arg5 sp pc`（9 个字段），末两个是 SP/PC
//  —— 这正是 dlinject 省掉 PTRACE_GETREGS 的地方。
//
//  ⚠ 实测（2510DRK44C / 内核 6.6.77 / Android 16）：**线程不在 syscall 中时，
//  这个文件返回的是 3 个字段**：`-1 <sp> <pc>`（sysno 为 -1，没有 arg0..arg5）。
//  root 读目标进程时实测就是这个形态，33 个线程全是一行 `-1 0x.. 0x..`。
//  所以解析必须**同时**接受两种长度，否则会把「其实在跑用户代码」误判成错误，
//  也会把真正的 syscall 状态漏掉。
//
//  用 open(O_NONBLOCK)+pread 而不是 fopen/fscanf：
//  O_NONBLOCK 下线程不在 syscall 时不必阻塞等待，可以直接轮询。
struct SyscallInfo {
    long sysno = -1;
    uint64_t args[6] = {0};
    uint64_t sp = 0;
    uint64_t pc = 0;
    int  fields = 0;         // 实际解析到的字段数（9 = 完整, 3 = 仅 sp/pc, 0 = 失败）
    bool valid = false;      // sp/pc 是否可用（只要 pc 可用就算 true）
    bool in_syscall = false; // 是否拿到非负 syscallno（9 字段形态）
    int  err = 0;
};

// 背景：8 个候选 GOT 槽全部改写成功，目标却一次 dlopen 都没发生。
// 文档里的推断是"改的槽不是该线程真正在用的槽"。要证实或证伪，只需要两个事实：
//   * 每个候选槽属于哪个 .so
//   * 线程在 nanosleep 里的返回地址（pc）落在哪个 .so
// 两者若是同一个库，说明改写点选对了、问题在别处；若不是，就是选错了库。
// 两个函数都只读 /proc/<pid>/maps，不碰目标内存，也不依赖后面才声明的函数。
// 前置声明：read_syscall 定义在本文件后面（第 228 行附近）。
static SyscallInfo read_syscall(pid_t tid);

static bool maps_lookup_name(pid_t tpid, uint64_t addr, char* out, size_t cap) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)tpid);
    FILE* f = fopen(path, "re");
    if (!f) { snprintf(out, cap, "<打不开 maps>"); return false; }
    char line[1024];
    bool hit = false;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long a = 0, b = 0;
        char perm[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &a, &b, perm) != 3) continue;
        if (addr < a || addr >= b) continue;
        const char* slash = strchr(line, '/');
        if (slash) {
            const char* nl = strchr(slash, '\n');
            size_t n = nl ? (size_t)(nl - slash) : strlen(slash);
            if (n >= cap) n = cap - 1;
            memcpy(out, slash, n);
            out[n] = 0;
        } else {
            snprintf(out, cap, "<anon %s>", perm);
        }
        hit = true;
        break;
    }
    fclose(f);
    if (!hit) snprintf(out, cap, "<未映射>");
    return hit;
}

// 线程在 syscall 里的返回地址落在哪个库 —— 即"它真正在用的调用点"。
static void log_pc_owner(pid_t tpid, pid_t tid) {
    SyscallInfo si = read_syscall(tid);
    if (!si.valid) { TLOG("  pc 属主: <读不到 syscall>"); return; }
    char nm[512] = {0};
    maps_lookup_name(tpid, si.pc, nm, sizeof(nm));
    // 注意：pc 是 syscall 的**返回地址**，它必然落在 libc 内部的 nanosleep 包装里，
    TLOG("  syscall 返回地址落在: 0x%llx -> %s（这是 libc 内部，不代表调用者）",
         (unsigned long long)si.pc, nm);
}

// 在 /proc/<pid>/maps 里找「文件偏移 == want_off（且可选：路径含 want_file）」的映射，
// 返回 [start,end)。用于定位 APK 内某个 so 的加载范围 ——
// extractNativeLibs=false 时 maps 里没有 so 文件名，只能按 APK 内数据偏移匹配。
static bool find_map_by_file_off(pid_t tpid, const char* want_file, uint64_t want_off,
                                 uint64_t* out_start, uint64_t* out_end) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)tpid);
    FILE* f = fopen(path, "re");
    if (!f) return false;
    char line[1024];
    bool hit = false;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long a = 0, b = 0, off = 0;
        char perm[8] = {0};
        if (sscanf(line, "%llx-%llx %7s %llx", &a, &b, perm, &off) != 4) continue;
        if (off != want_off) continue;
        if (want_file && *want_file && !strstr(line, want_file)) continue;
        if (out_start) *out_start = (uint64_t)a;
        if (out_end) *out_end = (uint64_t)b;
        hit = true;
        break;
    }
    fclose(f);
    return hit;
}

// tid: 目标线程。注意这个读面**不需要** mem fd——/proc/<tid>/syscall 是独立文件，
// 这正说明「拿 PC/SP」和「写内存」是两条互不依赖的免 ptrace 通路。
static SyscallInfo read_syscall(pid_t tid) {
    SyscallInfo si;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/syscall", (int)tid);
    int fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) { si.err = errno; return si; }
    char buf[256];
    ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
    int e = errno;
    close(fd);
    if (n <= 0) { si.err = n < 0 ? e : -1; return si; }
    buf[n] = '\0';

    unsigned long long sysno = 0, a[6] = {0}, sp = 0, pc = 0;
    // 先按完整的 9 字段试
    int got = sscanf(buf, "%llu %llx %llx %llx %llx %llx %llx %llx %llx",
                     &sysno, &a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &sp, &pc);
    if (got == 9) {
        si.sysno = (long)sysno;
        for (int i = 0; i < 6; ++i) si.args[i] = a[i];
        si.sp = sp; si.pc = pc;
        si.fields = 9;
        si.valid = true;
        si.in_syscall = (si.sysno >= 0);
        return si;
    }
    // 再按 3 字段（sysno sp pc）试 —— 这个内核在线程不处于 syscall 时就是这个形态
    sysno = 0; sp = 0; pc = 0;
    got = sscanf(buf, "%llu %llx %llx", &sysno, &sp, &pc);
    if (got == 3) {
        si.sysno = (long)sysno;
        si.sp = sp; si.pc = pc;
        si.fields = 3;
        si.valid = (pc != 0);              // pc 可用就能挂钩
        si.in_syscall = false;             // -1：不在 syscall 中
        return si;
    }
    si.err = -2;
    return si;
}

// ─────────────────────────────────────────────────────────────────────────────
//  覆盖式内存读写（全部经 /proc/<pid>/mem —— 这就是免 ptrace 的写面）
// ─────────────────────────────────────────────────────────────────────────────
static bool pwrite_mem(int fd, uint64_t addr, const void* src, size_t len) {
    ssize_t n = pwrite(fd, src, len, (off_t)addr);
    return n == (ssize_t)len;
}
static bool pread_mem(int fd, uint64_t addr, void* dst, size_t len) {
    ssize_t n = pread(fd, dst, len, (off_t)addr);
    return n == (ssize_t)len;
}

// ─────────────────────────────────────────────────────────────────────────────
//  payload 构造（检查点 A：无害载荷）
// ─────────────────────────────────────────────────────────────────────────────
//
//  这里**故意不碰 SP / 不切栈**：检查点 A 只验证「劫持链通不通」，
//  payload 只用 x1/x2 两个 scratch 寄存器（调用者保存寄存器，syscall 返回后
//  本来也不保值），做完直接 b 回 PC+4，寄存器现场保持原样。
//
//  检查点 B（dlopen）才会用到下面留的栈空间：payload 会先
//  mov sp, <payload+STACK_OFFSET> 再调用 dlopen —— 与 dlinject 一致。
//
//  payload 布局：
//      +0   magic（8 字节，仅作人类可读标记）
//      +8   mailbox_addr（8 字节，调用方填）
//      +16  code...
//      +24  guard（8 字节，调用方清零）—— 一次性守卫，原子 CAS
//
//  ⚠ 一次性守卫是**必须的**，不是优化：
//  「PC 处的返回地址」是**全进程共享**的指令位置（bionic syscall() 的返回点）。
//  同一个地址可能有多个线程在跑，覆盖之后**所有**从那儿返回的线程都会跳进 payload。
//  实测（并行探针 Q5）：一次 200ms 挂钩共触发 13 次，其中只有 6 次是被选中的那个线程，
//  另外 7 次是别的线程踩到的。检查点 A 的 payload 无害（重复执行只是重复写同一常数），
//  但检查点 B 的 dlopen 一旦被并发重入就是灾难——所以从 A 开始就把守卫放进 payload，
//  而不是等 B 再补。
//
//  守卫逻辑（LL/SC，armv8-A 通用）：
//      x4 = guard 地址            (= x1 + 24)
//      ldaxr x5, [x4]             // 原值
//      cmp   x5, xzr
//      b.ne  skip                 // 守卫非 0 -> 已经有人做过了，直接跳过
//      stlxr w6, x3, [x4]         // 写 MAGIC 占坑
//      cbnz  w6, retry
//  只有拿到占坑权的那个线程才会执行真正的 store。
static void build_payload_full(uint8_t* dst, uint64_t logical_base, uint64_t mailbox_addr,
                            uint64_t sp, uint64_t pc, uint64_t resume_at,
                            uint64_t fixup_addr, uint32_t fixup_word, size_t* code_len,
                            uint64_t* jmp_back_target);

static void build_payload_full(uint8_t* dst, uint64_t logical_base, uint64_t mailbox_addr,
                            uint64_t sp, uint64_t pc, uint64_t resume_at,
                            uint64_t fixup_addr, uint32_t fixup_word,
                            size_t* code_len, uint64_t* jmp_back_target);
static void build_payload_a(uint8_t* dst, uint64_t logical_base, uint64_t mailbox_addr,
                            uint64_t sp, uint64_t pc, uint64_t resume_at, size_t* code_len,
                            uint64_t* jmp_back_target) {
    build_payload_full(dst, logical_base, mailbox_addr, sp, pc, resume_at, 0, 0, code_len, jmp_back_target);
}

// fixup_addr/fixup_word：非 0 时，payload 收尾先把这个字写回 fixup_addr，再跳 resume_at。
// 这样「被我们覆盖掉的那条指令」会被**重新执行**而不是跳过 ——
// 跳过指令 = 寄存器/状态全错 = 目标直接崩（实测踩过）。
static void build_payload_full(uint8_t* dst, uint64_t logical_base, uint64_t mailbox_addr,
                            uint64_t sp, uint64_t pc, uint64_t resume_at,
                            uint64_t fixup_addr, uint32_t fixup_word,
                            size_t* code_len, uint64_t* jmp_back_target) {
    // dst = 数据/代码写进哪块本地缓冲；logical_base = 它**将来执行时**的地址。
    // 自注入时两者相同；跨进程时 logical_base 是目标洞里那个地址，
    // 否则 x1（payload 基址）和回跳 b 的偏移都会算错。
    uint8_t* base = dst;
    (void)sp;   // 检查点 A 不切栈；SP 留给检查点 B（dlopen 需要临时栈）
    uint32_t* insn = (uint32_t*)(base + CODE_OFF);

    // 先写数据区。payload 的执行必须发生在**安装 hook 之后**，
    // 所以这里的写顺序是安全的（hook 之前线程不会进 payload）。
    // 【布局纪律】guard 必须放在**代码区之外**。
    // 代码从 base+16 开始；如果 guard 放 base+24，它正好是代码的第 0~2 条指令，
    // payload 执行时 stlxr 会把指令本身写成 MAGIC —— 实测就是这里 SIGILL 的。
    // 所以数据区固定为 base+0..31（magic / mailbox / 保留 / guard），代码从 base+32 起。
    *(uint64_t*)(base + 0)  = MAGIC;
    *(uint64_t*)(base + 8)  = mailbox_addr;
    *(uint64_t*)(base + GUARD_OFF) = 0;              // 守卫清零（在代码区之后）

    int n = 0;
    n += load_imm64(insn + n, 1, logical_base);         // x1 = payload 基址（执行地址）

    // 入口标记：一进 payload 就先写一个和最终值不同的标记。
    // 失败时据此一刀切开两种可能：
    //   mailbox == MARK -> 进去执行了，但在完成前崩了（问题在 payload 内部）
    //   mailbox == 0    -> 根本没进去（问题在 b 覆盖 / 取指 / 线程没走那条路）
    // 上一轮只能看出没写成，这两种可能分不开，只能靠猜。
    {
        insn[n++] = enc_ldr_x_imm(2, 1, 8);                        // ldr x2,[x1,#8] = mailbox
        insn[n++] = enc_movz_x(5, (uint16_t)(MARK & 0xFFFF));      // x5 = MARK
        insn[n++] = enc_movk_x(5, (uint16_t)((MARK >> 16) & 0xFFFF), 16);
        insn[n++] = enc_str_x_imm(5, 2, 0);                        // *mailbox = MARK
    }
    insn[n++] = enc_movz_x(3, (uint16_t)(MAGIC & 0xFFFF));                    // x3 = MAGIC
    insn[n++] = enc_movk_x(3, (uint16_t)((MAGIC >> 16) & 0xFFFF), 16);
    insn[n++] = enc_add_x_imm(4, 1, GUARD_OFF);  // add x4, x1, #GUARD_OFF (x4 = &guard)

    // ── 一次性守卫：CAS(guard, 0 -> MAGIC)，只有赢家继续 ──
    const int cas_retry = n;
    insn[n++] = enc_ldaxr_x(5, 4);            // ldaxr x5, [x4]
    insn[n++] = enc_cmp_xzr(5);               // cmp   x5, xzr
    const int bne_skip = n;
    insn[n++] = enc_bcond(0, COND_NE);        // b.ne  skip   （目标回填）
    insn[n++] = enc_stlxr_x(6, 3, 4);         // stlxr w6, x3, [x4]
    insn[n++] = enc_cbz_x(6, cas_retry - n, true);   // cbnz w6, retry（回到 ldaxr）

    // ── 只有占坑成功的线程走到这里 ──
    // 顺序很重要：先把守卫放开，再写 mailbox。
    // 为什么守卫要**自复位**：payload 结尾是 `b pc+4`，而 `pc` 由 /proc/<tid>/syscall
    // 给出，理论上可能正好落在「上一次 payload 的落点」上，导致同一个线程二次进入。
    // 如果不自复位，第二次进入会被守卫挡住、走 b.ne 跳过 store 后冲出 payload 末尾
    // ——实测就是这样 SIGILL 的。自复位让「重入」退化成「再执行一次」，没有副作用：
    // 反正这个 payload 的语义就是幂等地写一个常数。
    insn[n++] = enc_str_x_imm(31, 4, 0);      // str xzr, [x4]  —— 放开守卫
    insn[n++] = enc_ldr_x_imm(2, 1, 8);       // ldr x2, [x1, #8]  x2 = mailbox
    insn[n++] = enc_str_x_imm(3, 2, 0);       // *x2 = MAGIC —— 任意代码真的执行了的铁证

    // ── fixup：把被覆盖掉的那条指令写回去，让目标线程**重新执行**它 ──
    if (fixup_addr != 0) {
        n += load_imm64(insn + n, 6, fixup_addr);           // x6 = fixup 地址
        n += load_imm64(insn + n, 7, (uint64_t)fixup_word); // x7 = 原指令字
        insn[n++] = 0xB90000C7u;                            // str w7, [x6]
        insn[n++] = 0xD5033FDFu;                            // isb（指令已改，等取指同步）
    }

    // ── 公共出口（b.ne 与正常路径在此汇合）──
    insn[bne_skip] = enc_bcond(n - bne_skip, COND_NE);
    if (!encode_b(logical_base + CODE_OFF + (size_t)n * 4, resume_at, &insn[n])) {
        LOGE("payload: 收尾跳转超出 ±128MB (logical_base=0x%llx resume_at=0x%llx pc=0x%llx)",
             (unsigned long long)logical_base, (unsigned long long)resume_at, (unsigned long long)pc);
        *code_len = 0;
        return;
    }
    n++;

    *jmp_back_target = resume_at;
    *code_len = (size_t)n * 4;
    __builtin___clear_cache((char*)base, (char*)base + CODE_OFF + *code_len);
}

// ═════════════════════════════════════════════════════════════════════════════
//  跨进程专用的 phase-1：借目标线程在**它自己**的地址空间里 mmap 一块 RWX
// ═════════════════════════════════════════════════════════════════════════════
//
//  为什么跨进程必须多这一步（自注入不需要）：
//    mmap_near() 建的是**注入器自己**地址空间里的页。跨进程时目标进程里没有这块页，
//    而 /proc/<pid>/mem **只能写已映射的地址，不能在目标里新建映射**。
//    所以必须借目标线程执行一次 mmap(RWX)，把返回地址回传给注入器，
//    注入器再把真正的 payload 写进去、第二次挂钩跳过去。
//
//  为什么桩放在目标线程自己的栈上：
//    * 栈一定已映射、可写 —— 而 /proc/pid/mem 写不了未映射页
//    * 我们只动 sp-512 以下，而 arm64 栈向下增长，那块空间是「已映射但不会被用」的
//    * 不能改 SP：栈上可能有该线程正在用的数据（信号帧、变长数组、alloca）
//
//  桩要做的事：
//    1. 把会被 mmap 破坏的寄存器全部存到栈帧（x0~x18）
//    2. 自己用 svc #0 调 mmap（不依赖任何符号解析）
//    3. 把返回的地址写进 mailbox（注入器据此知道 payload 该放哪）
//    4. 原样恢复寄存器，b 回 PC+4
//
//  寄存器现场必须**逐字节还原**：我们是在别人线程的 syscall 返回点上动手，
//  只要有一个寄存器不对，目标线程的行为就会漂。这也是桩必须保存 x0~x18 的原因。

// STP/LDP (64-bit, signed offset)：0xA9000000/0xA9400000 | imm7(缩放8)<<15 | Rt2<<10 | Rn<<5 | Rt
static uint32_t enc_stp_x(int rt, int rt2, int rn, int off) {
    return 0xA9000000u | ((uint32_t)((off / 8) & 0x7F) << 15) | ((uint32_t)rt2 << 10) |
           ((uint32_t)rn << 5) | (uint32_t)rt;
}
static uint32_t enc_ldp_x(int rt, int rt2, int rn, int off) {
    return 0xA9400000u | ((uint32_t)((off / 8) & 0x7F) << 15) | ((uint32_t)rt2 << 10) |
           ((uint32_t)rn << 5) | (uint32_t)rt;
}
// add x9, sp, #0  =  mov x9, sp
static const uint32_t kAddX9Sp0 = 0x910003E9u;

#define FRAME_SIZE  512     // 帧大小：x0..x18 + x30 = 20 个 8 字节槽 = 160 字节，留足余量

// 【重要】x9 全程当帧指针，造桩时**不能**再用 load_imm64 往 x9 里装地址
// （load_imm64 会产生中间 movz/movk，把 x9 冲掉）。
// 所以 x9 只用「add x9, sp, #0」得到调用者 SP，帧内偏移一律用立即数。
// mailbox 地址改用 x1 装，且必须放在「保存完 x1」之后。
static size_t build_payload_phase1(uint8_t* buf, uint64_t exec_base, uint64_t pc, uint64_t mailbox_addr) {
    // exec_base = 这段桩**将来执行时所在的地址**。自注入时等于 buf；
    // 跨进程时是「目标地址空间里的洞地址」——回跳 b 的偏移必须按它算，
    // 否则 b 编出来的偏移是注入器本地的，目标执行时会飞掉。
    uint32_t* insn = (uint32_t*)buf;
    int n = 0;

    // 0) x9 = 调用者 SP（此时 x9 还是原值，先别管——它不在需要保存的列表里因为
    //    它本来就是 scratch；但为了绝对安全，也保存它）
    insn[n++] = kAddX9Sp0;                                        // mov x9, sp

    // 1) 保存 x0..x17（STP 成对），再保存 x18/x19？不需要 x19。
    //    只需保存「mmap 会破坏的调用者保存寄存器」+ x9 自己：
    //    x0~x18 全是调用者保存/临时，x30 是返回地址。
    for (int i = 0; i < 18; i += 2)
        insn[n++] = enc_stp_x(i, i + 1, 9, i * 8);                // STP x0,x1,[x9]; ... x16,x17
    insn[n++] = enc_stp_x(18, 30, 9, 144);                        // STP x18,x30,[x9,#144]
    insn[n++] = enc_str_x_imm(9, 9, 160);                         // STR x9,[x9,#160] 存原 x9

    // 2) mmap 参数：x0=0 x1=0x10000 x2=7(RWX) x3=0x22 x4=-1 x5=0 x8=222
    insn[n++] = enc_movz_x(0, 0);
    insn[n++] = enc_movz_x(1, 0x0000); insn[n++] = enc_movk_x(1, 0x0001, 16);   // 0x10000
    insn[n++] = enc_movz_x(2, 7);                                  // PROT_READ|WRITE|EXEC
    insn[n++] = enc_movz_x(3, 0x22);                               // MAP_PRIVATE|MAP_ANONYMOUS
    insn[n++] = 0x92800004u;                                       // movn x4,#0 -> x4 = -1
    insn[n++] = enc_movz_x(5, 0);
    insn[n++] = enc_movz_x(8, 222);                                // __NR_mmap
    insn[n++] = 0xD4000001u;                                       // svc #0

    // 3) *mailbox = x0（mmap 返回地址）。x1 现在可以随便用（已存过）
    n += load_imm64(insn + n, 1, mailbox_addr);
    insn[n++] = enc_str_x_imm(0, 1, 0);

    // 4) 还原 x0..x18 + x30（注意 x9 最后还原，因为前面一直当帧指针用）
    for (int i = 0; i < 18; i += 2)
        insn[n++] = enc_ldp_x(i, i + 1, 9, i * 8);
    insn[n++] = enc_ldp_x(18, 30, 9, 144);
    insn[n++] = enc_ldr_x_imm(9, 9, 160);                         // 还原 x9

    // 5) b 回 PC+4
    if (!encode_b(exec_base + (size_t)n * 4, pc + 4, &insn[n])) {
        LOGE("phase1: 回跳 PC+4 超出 ±128MB (exec_base=0x%llx pc=0x%llx)",
             (unsigned long long)exec_base, (unsigned long long)pc);
        return 0;
    }
    n++;

    __builtin___clear_cache((char*)buf, (char*)buf + (size_t)n * 4);
    return (size_t)n * 4;
}


//
//  `b` 只有 ±128MB。payload 必须落在 pc 附近，否则一跳不过去。
//
//  ── 关键实测结论（2510DRK44C / Android 16 / aarch64）──
//  必须**一步 mmap 就带 PROT_EXEC**：
//      mmap(RWX)                    -> 执行 ✅ (maps: rwxp)
//      mmap(RW) 然后 mprotect(RX)   -> mprotect 返回 0、maps 显示 r-xp，
//                                      但一执行就 SIGSEGV (SEGV_ACCERR)
//      mmap(RW) 然后 mprotect(RWX)  -> 同上，假成功
//  即 mprotect 在这个内核上是**假成功**：权限位改了，执行仍然失败。
//
//  这也解释了探针里看到的「rwx 段 = 0」：不是内核不允许 rwx 页，
//  而是系统里没有组件用「一步 mmap RWX」这条路造过。
//  覆盖式注入本身不需要 rwx（写的是已有 r-x 页），
//  但 payload 二段需要一个落脚点，这个落脚点必须是 mmap(RWX)。
// 查 /proc/self/maps，确认这块页真的可执行
static bool page_is_executable(void* p) {
    FILE* f = fopen("/proc/self/maps", "re");
    if (!f) return false;
    char line[512];
    bool ok = false;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long a = 0, b = 0;
        char perm[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &a, &b, perm) != 3) continue;
        if ((unsigned long long)p >= a && (unsigned long long)p < b) {
            ok = (perm[2] == 'x');
            break;
        }
    }
    fclose(f);
    return ok;
}

static void* mmap_near(uint64_t pc, size_t size, uint64_t* out_dist) {
    const int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    const uint64_t lo = (pc > (1ull << 27)) ? (pc - (1ull << 27)) : 0x100000ull;
    const uint64_t hi = pc + (1ull << 27);

    // 收集 [lo,hi) 内的已占区间（注入器自己的地址空间）
    struct R { uint64_t s, e; };
    static R rs[512];
    int nr = 0;
    FILE* f = fopen("/proc/self/maps", "re");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f) && nr < 512) {
            unsigned long long a = 0, b = 0;
            if (sscanf(line, "%llx-%llx", &a, &b) != 2) continue;
            if (b <= lo || a >= hi) continue;
            rs[nr].s = a; rs[nr].e = b; ++nr;
        }
        fclose(f);
    }
    // maps 本来就是升序，保险起见还是排一下
    for (int i = 1; i < nr; ++i)
        for (int j = i; j > 0 && rs[j].s < rs[j - 1].s; --j) {
            R t = rs[j]; rs[j] = rs[j - 1]; rs[j - 1] = t;
        }

    // 在空洞里挑位置，优先贴近 pc（让 `b` 的偏移最小）
    uint64_t cur = lo;
    for (int i = 0; i <= nr; ++i) {
        uint64_t next = (i < nr) ? rs[i].s : hi;
        if (next > cur && (next - cur) >= size + 0x10000) {
            uint64_t base = (pc > cur) ? pc : cur;
            base = (base + 0xFFFFull) & ~0xFFFFull;
            if (base + size > next) base = (next - size) & ~0xFFFFull;
            if (base >= cur && base + size <= next) {
                void* p = mmap((void*)base, size, prot,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
                if (p != MAP_FAILED && page_is_executable(p)) {
                    int64_t d = (int64_t)((uint64_t)p - pc);
                    if (out_dist) *out_dist = (uint64_t)(d < 0 ? -d : d);
                    LOGI("mmap_near: 空洞 [0x%llx,0x%llx) 取 0x%llx（距 pc %.1fMB）",
                         (unsigned long long)cur, (unsigned long long)next,
                         (unsigned long long)p, (double)(d < 0 ? -d : d) / 1048576.0);
                    return p;
                }
                if (p != MAP_FAILED) munmap(p, size);
            }
        }
        if (i < nr && rs[i].e > cur) cur = rs[i].e;
    }
    LOGE("mmap_near: ±128MB 内（已占区间 %d 个）找不到能放 %zu 字节的空洞", nr, size);
    return MAP_FAILED;
}

// ─────────────────────────────────────────────────────────────────────────────
//  劫持核心：与执行器无关
// ─────────────────────────────────────────────────────────────────────────────
//
//  mem_fd 由调用方给：跨进程用 /proc/<target>/mem，自注入用 /proc/self/mem。
struct HookHandle {
    uint64_t       pc = 0;
    uint32_t       orig = 0;
    bool           installed = false;
    void*          payload = nullptr;
    size_t         payload_size = 0;
};

// ─────────────────────────────────────────────────────────────────────────────
//  【踩过的坑，别再试】「直接在注入器线程里调用一次 payload」这种自证**不能做**
// ─────────────────────────────────────────────────────────────────────────────
//
//  最初我加过一个 verify_payload_once()：在注入器线程里把 payload 当函数调用一次，
//  看 mailbox 有没有被写，以此证明「代码本身是对的」。
//
//  它的两个致命问题（实测踩到）：
//   1. payload 结尾是 `b pc+4`，而 pc 是**目标线程**的返回地址。在注入器线程里
//      调用它，等于让注入器线程带着自己的寄存器去执行目标线程的返回点，
//      后果是**把 payload 自己的前两条指令覆盖成 0**（内存被动过），
//      真挂钩时目标线程于是在 payload+0x18 处执行到全零 -> SIGILL。
//   2. 即便如此，它**仍然报「代码正确」** —— 因为 mailbox 在 payload 被破坏**之前**
//      就已经写好了。也就是说这个自证既会搞坏现场、又会给出假阳性，
//      比没有还危险。
//
//  正确做法：
//   * 要验证 payload 编码 -> 用 --dump-payload 把机器码 dump 出来，交给
//     clang/objdump 反汇编核对（本仓库已脚本化）。
//   * 要验证「执行路径通不通」-> 直接跑 --self（真实挂钩 + 真实线程 + 真实恢复）。
//   * 不要试图用一个「假调用」替代真实验证。

// 返回 0 成功；负数为错误码（见日志）
static int install_hook_a(int mem_fd, const SyscallInfo& si, uint64_t mailbox_addr,
                          HookHandle* hh, size_t* code_len) {
    // 1) 备份「线程恢复执行时的第一条指令」
    if (!pread_mem(mem_fd, si.pc, &hh->orig, 4)) {
        LOGE("备份 pc=0x%llx 处 4 字节失败 (errno=%d)", (unsigned long long)si.pc, errno);
        return -1;
    }
    LOGI("原指令 @0x%llx = 0x%08x", (unsigned long long)si.pc, hh->orig);

    // 2) 在 pc 附近找 payload 落脚点（`b` 的 ±128MB 限制）
    uint64_t dist = 0;
    void* base = mmap_near(si.pc, PAYLOAD_SIZE, &dist);
    if (base == MAP_FAILED) {
        LOGE("在 pc=0x%llx 附近 ±128MB 内找不到可用 mmap 位置", (unsigned long long)si.pc);
        return -2;
    }
    LOGI("payload @%p（距 pc %.1f MB, 页可执行=%d）", base,
         (double)dist / 1048576.0, page_is_executable(base) ? 1 : 0);
    hh->payload = base;
    hh->payload_size = PAYLOAD_SIZE;

    // 3) 造 payload
    uint64_t back = 0;
    build_payload_a((uint8_t*)base, (uint64_t)base, mailbox_addr, si.sp, si.pc, si.pc + 4, code_len, &back);
    if (*code_len == 0) return -3;

    // 3.5) 回读校验：确认 payload 真的落在内存里（pwrite/直接写都可能静默失败）
    {
        uint8_t check[64];
        memset(check, 0, sizeof(check));
        if (!pread_mem(mem_fd, (uint64_t)base + CODE_OFF, check, *code_len)) {
            LOGE("回读 payload 失败 (errno=%d)", errno);
            return -6;
        }
        if (memcmp(check, (uint8_t*)base + CODE_OFF, *code_len) != 0) {
            LOGE("payload 回读不一致（写入未生效）");
            return -6;
        }
        LOGI("payload 首指令 = 0x%08x (期望 0x%08x)", *(uint32_t*)check, *(uint32_t*)((uint8_t*)base + CODE_OFF));
    }

    // 4) 把 pc 处 4 字节换成 `b payload`
    uint32_t br = 0;
    if (!encode_b(si.pc, (uint64_t)base + CODE_OFF, &br)) {
        LOGE("b 编码失败：0x%llx -> 0x%llx", (unsigned long long)si.pc,
             (unsigned long long)((uint64_t)base + CODE_OFF));
        return -4;
    }
    if (!pwrite_mem(mem_fd, si.pc, &br, 4)) {
        LOGE("覆盖 pc=0x%llx 失败 (errno=%d)", (unsigned long long)si.pc, errno);
        return -5;
    }
    hh->pc = si.pc;
    hh->installed = true;
    LOGI("hook: *0x%llx = 0x%08x -> payload+CODE_OFF (guard=%llx)",
         (unsigned long long)si.pc, br,
         (unsigned long long)*(volatile uint64_t*)((uint8_t*)base + GUARD_OFF));
    return 0;
}


// 在被选中线程的 syscall 里挑一个「可重启」的：这类 syscall 被我们的
// 覆盖改变返回值后语义仍然安全，且返回后 x0 的值调用者一般不关心。
//
// 注意 arm64 的 syscall 表里**没有** epoll_wait / poll：
// bionic 把 epoll_wait 实现成 epoll_pwait(sigmask=NULL)，poll 走 ppoll。
// 只能按真实存在的 __NR_* 列举，别凭直觉写。
static const char* syscall_name(long n) {
    switch (n) {
        case __NR_nanosleep:       return "nanosleep";
        case __NR_clock_nanosleep: return "clock_nanosleep";
        case __NR_epoll_pwait:     return "epoll_pwait";
        case __NR_futex:           return "futex";
        case __NR_ppoll:           return "ppoll";
        case __NR_pselect6:        return "pselect6";
        default:                   return "?";
    }
}
static bool is_safe_syscall(long n) {
    return n == __NR_nanosleep || n == __NR_clock_nanosleep ||
           n == __NR_epoll_pwait ||
           n == __NR_futex || n == __NR_ppoll || n == __NR_pselect6;
}

// ─────────────────────────────────────────────────────────────────────────────
//  挂钩/摘钩的公共动作（自注入与跨进程共用）
// ─────────────────────────────────────────────────────────────────────────────

// 把 pc 处 4 字节换成 `b target`，并备份原指令
static bool hook_write(int mem_fd, uint64_t pc, uint64_t target, HookHandle* hh) {
    uint32_t orig = 0;
    if (!pread_mem(mem_fd, pc, &orig, 4)) {
        LOGE("备份 *0x%llx 失败 (errno=%d)", (unsigned long long)pc, errno);
        return false;
    }
    uint32_t br = 0;
    if (!encode_b(pc, target, &br)) {
        LOGE("b 编码失败：0x%llx -> 0x%llx（超出 ±128MB）",
             (unsigned long long)pc, (unsigned long long)target);
        return false;
    }
    if (!pwrite_mem(mem_fd, pc, &br, 4)) {
        LOGE("覆盖 *0x%llx 失败 (errno=%d)", (unsigned long long)pc, errno);
        return false;
    }
    hh->pc = pc;
    hh->orig = orig;
    hh->installed = true;
    LOGI("hook: *0x%llx 0x%08x -> 0x%08x (原 0x%08x)",
         (unsigned long long)pc, br, (unsigned)target, orig);
    return true;
}

static bool restore_hook(int mem_fd, HookHandle* hh) {
    if (!hh->installed) return true;
    bool ok = pwrite_mem(mem_fd, hh->pc, &hh->orig, 4);
    uint32_t check = 0;
    bool verified = pread_mem(mem_fd, hh->pc, &check, 4) && check == hh->orig;
    LOGI("恢复 *0x%llx = 0x%08x : write=%d verify=%d",
         (unsigned long long)hh->pc, hh->orig, ok ? 1 : 0, verified ? 1 : 0);
    hh->installed = false;
    return ok && verified;
}

// 轮询等某线程进入可重启 syscall；把它记到 si
//
// 【本内核实测】线程不在 syscall 中时 /proc/<tid>/syscall 给 3 字段 `-1 sp pc`；
// 只有真处于 syscall 时才是 9 字段带 syscallno。所以这里必须等到 in_syscall，
// 否则会拿到一个「线程正在跑用户代码」的 pc 去挂钩 —— 那个 pc 随时会变，不安全。
static bool wait_for_safe_syscall(pid_t ttid, SyscallInfo* si, int tries, const char* who) {
    int n9 = 0, n3 = 0, nbad = 0;
    for (int i = 0; i < tries; ++i) {
        *si = read_syscall(ttid);
        if (si->fields == 9) ++n9;
        else if (si->fields == 3) ++n3;
        else ++nbad;

        if (si->valid && si->in_syscall && is_safe_syscall(si->sysno)) {
            LOGI("[%s] 命中 syscall: no=%ld(%s) fields=%d sp=0x%llx pc=0x%llx (轮询中 9字段=%d 3字段=%d 失败=%d)",
                 who, si->sysno, syscall_name(si->sysno), si->fields,
                 (unsigned long long)si->sp, (unsigned long long)si->pc, n9, n3, nbad);
            return true;
        }
        if (i > 0 && i % 1000 == 0) {
            LOGI("[%s] 等待中… 最近: fields=%d sysno=%ld err=%d | 9字段=%d 3字段=%d 失败=%d",
                 who, si->fields, si->sysno, si->err, n9, n3, nbad);
        }
        usleep(1000);
    }
    LOGE("[%s] 超时未等到可重启 syscall（9字段=%d 3字段=%d 失败=%d）最后 fields=%d sysno=%ld err=%d",
         who, n9, n3, nbad, si->fields, si->sysno, si->err);
    return false;
}

// 按「APK 内偏移」找某个 .so 的加载基址。
//
// 【为什么不能用 so 文件名】实测：App 的 native 库不是从 lib/arm64/*.so 映射的，
// 而是**直接映射 base.apk**（Android 的 extractNativeLibs=false）：
//    6ccbe34000-6ccbe35000 r-xp 004e0000 ... /data/app/~~.../base.apk
// maps 里根本没有 "libanticheat_detector.so" 这个名字，按名字 strstr 必然找不到。
//
// 【正确做法】未压缩的 .so 在 APK 内有固定数据偏移 data_off（宿主上用 zipfile 算出），
// 链接器把它映射为 file_offset = data_off + p_offset，而第一个 PT_LOAD 的 p_offset=0，
// 且 p_vaddr=0 -> **该映射的起始地址就是 .so 的加载基址**。
// 已用本机算出的偏移与设备 maps 交叉验证过（game_core=0x4e0000、crc_checker=0x4dc000 均对上）。
static uint64_t find_so_base_by_apkoff(pid_t tpid, uint64_t apk_off) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)tpid);
    FILE* f = fopen(path, "re");
    if (!f) { LOGW("find_so_base_by_apkoff: 打不开 maps (errno=%d)", errno); return 0; }
    char line[512];
    uint64_t best = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long a = 0, b = 0, off = 0;
        char perm[8] = {0};
        if (sscanf(line, "%llx-%llx %7s %llx", &a, &b, perm, &off) != 4) continue;
        if (off != apk_off) continue;
        if (best == 0 || (uint64_t)a < best) best = a;
    }
    fclose(f);
    if (best) TLOG("find_so_base_by_apkoff: apk_off=0x%llx -> 基址 0x%llx",
                   (unsigned long long)apk_off, (unsigned long long)best);
    else LOGW("maps 里没有 apk_off=0x%llx 的映射", (unsigned long long)apk_off);
    return best;
}

// ─────────────────────────────────────────────────────────────────────────────
//  跨进程模式：需要 root
// ─────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────
//  在目标的 r-x 段里、pc 附近找一块**已映射且可执行**的落点来放 payload
// ─────────────────────────────────────────────────────────────────────────────
//
//  注意：这里**不判断"是不是空洞"**（上一次这么干把目标搞崩了 —— r-x 段里的
//  零字节可能是字面量池/跳转表，随时会被执行）。这里只保证一件事：
//  这块内存在目标里是**已映射且可执行**的，而且离 pc 足够近（同页优先）。
//  真正的安全来自 fixup：payload 收尾会把 pc 处原指令写回并跳回 pc，
//  于是**第一条**返回的线程跑完就把 pc 复原了，后面的线程根本不会再进来，
//  窗口自动关闭。
static uint64_t find_exec_slot(pid_t tpid, uint64_t pc, size_t need) {
    // ── 落点选择：找一块**从未被执行过**的可执行页 ──
    //
    // 【为什么必须这样】跨进程写代码，内核只给「执行写入的那个 CPU」刷 i-cache。
    // 如果目标页曾被任何线程执行过，执行核的 i-cache 里可能仍是旧字节，
    // 结果就是取到陈旧数据当指令跑 -> SIGILL/ILL_ILLOPC（实测踩过：
    // 写进 libSurfaceFlingerProp.so 的 has_HDR_display 后，靶位线程跳过去直接 SIGILL）。
    // 而目标里没有 rwx、也没有匿名可执行段（4705 行 maps 实测），
    // 所以唯一出路是：在**已加载但从未被执行过**的页里找落点。
    //
    // 【怎么找】内核自己给了信号：读 /proc/<pid>/smaps，
    //   * 可执行映射上 `Rss: 0 kB`  -> 这些页从未被 fault in -> **从未被执行**
    //   * 退一步用 `Referenced: 0`   -> 该窗口内没被访问（配合 clear_refs 更准）
    // 377 个已加载库里绝大多数（vendor HAL / vulkan 驱动 / cronet…）都是 Rss=0 的冷库。
    // 这个方法**不依赖目标配合**，换到真实目标上同样成立。
    const uint64_t limit = (uint64_t)120 * 1024 * 1024;
    const uint64_t lo = (pc > limit) ? (pc - limit) : 0x1000ull;
    const uint64_t hi = pc + limit;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/smaps", (int)tpid);
    FILE* f = fopen(path, "re");
    if (!f) { LOGW("find_exec_slot: 打不开 smaps (errno=%d)，退回 maps", errno); return 0; }

    static const char* hot[] = {
        "libc.so", "linker", "libc++", "libm.so", "libart", "libandroid_runtime",
        "boot.oat", "libnativehelper", "libutils.so", "libbase.so",
        "libhwui.so", "libgui.so", "libui.so", "libskia", "libEGL", "libGLESv2",
        "libGLESv3", "libvulkan", "libbinder", "libinput.so", "libft2", "libpng",
        "libjpeg", "libjnigraphics", "libandroid.so", "libz.so", "liblog.so",
        "libcutils", "libhardware", "libsync", "librenderengine", "libhwui",
        "libsqlite", "libjavacore", "libopenjdk", "libexpat", "libicu",
        "libSurfaceFlingerProp", nullptr};

    char line[1024];
    uint64_t cold_best = 0, cold_len = 0;   // Rss==0 的（首选）
    uint64_t any_best = 0, any_len = 0;     // 退路：够用且最小的
    char cold_name[256]; cold_name[0] = 0;
    char any_name[256];  any_name[0] = 0;
    bool in_exec_seg = false;
    uint64_t seg_s = 0, seg_e = 0;
    uint64_t seg_rss = 0;

    while (fgets(line, sizeof(line), f)) {
        unsigned long long a = 0, b = 0;
        char perm[8] = {0};
        // 映射头行形如 "76b2c000-76b30000 r-xp 00000000 fe:03 1234 /path/lib.so"
        if (sscanf(line, "%llx-%llx %7s", &a, &b, perm) == 3) {
            in_exec_seg = (perm[2] == 'x');
            seg_s = a; seg_e = b; seg_rss = 0;
            continue;
        }
        if (!in_exec_seg) continue;
        if (sscanf(line, "Rss: %llu kB", &seg_rss) == 1) {
            uint64_t len = seg_e - seg_s;
            if (len >= need + 0x1000 && len >= 0x8000 &&
                seg_s < hi && seg_e > lo && seg_s >= lo) {
                // 找段名（在 smaps 里得回看，这里简化为不判名字，
                // 但 Rss==0 本身就是最强信号；仍排除明显热库由上层调用者控制）
                uint64_t q = (seg_s + 0x2000) & ~0xFull;
                if (q + need > seg_e) q = (seg_e - need - 0x100) & ~0xFull;
                if (seg_rss == 0) {
                    if (cold_best == 0 || len < cold_len) {
                        cold_best = q; cold_len = len;
                        snprintf(cold_name, sizeof(cold_name), "seg 0x%llx", (unsigned long long)seg_s);
                    }
                } else {
                    if (any_best == 0 || len < any_len) { any_best = q; any_len = len; }
                }
            }
            in_exec_seg = false;
        }
    }
    fclose(f);

    (void)hot; (void)any_name;
    if (cold_best) {
        TLOG("find_exec_slot: 选冷页 0x%llx（段 0x%llx 长%lluKB, Rss=0 从未执行）",
             (unsigned long long)cold_best, (unsigned long long)(cold_best & ~0xFFFull),
             (unsigned long long)(cold_len / 1024));
        return cold_best;
    }
    if (any_best) {
        LOGW("find_exec_slot: 没有 Rss=0 的冷段，退而选 0x%llx（长%lluKB）—— 有 i-cache 风险",
             (unsigned long long)any_best, (unsigned long long)(any_len / 1024));
        return any_best;
    }
    LOGW("find_exec_slot: ±120MB 内没有合适的可执行段");
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
//  在**目标**地址空间里找一块可执行的落点（dlinject 的“代码洞”思路）
// ─────────────────────────────────────────────────────────────────────────────
//
//  为什么必须这样找：跨进程时桩必须同时满足两条
//    1. 在**目标**地址空间内（注入器自己的 mmap 目标里根本没有）
//    2. 距目标的 pc 在 `b` 的 ±128MB 以内（实测目标栈离 pc ~10GB，够不着）
//  而目标里**没有可写可执行页**（4685 行 maps 实测：可达范围内 rwx 段 = 0，
//  “可写且可执行”的段 = 0）。所以唯一保得住 X 权限的写面是：
//  往目标已有的 r-x 页写 —— /proc/pid/mem 会让它 COW 出私有页，X 权限保留。
//
//  于是策略：在 pc ±limit 范围内扫目标的 r-xp 段，找一段连续的
//  0x00 或 0xD503201F(nop) 填充（代码洞），把桩放进去。
//  这类填充在 so 里很常见（函数间对齐、段尾 padding），且不会被正常执行到。
static uint64_t find_exec_cave(pid_t tpid, uint64_t pc, size_t need, uint64_t limit) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)tpid);
    FILE* fmaps = fopen(path, "re");
    if (!fmaps) { LOGW("find_exec_cave: 打不开 %s (errno=%d)", path, errno); return 0; }

    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/mem", (int)tpid);
    int mem = open(mpath, O_RDONLY);
    if (mem < 0) { LOGW("find_exec_cave: 打不开 %s (errno=%d)", mpath, errno); fclose(fmaps); return 0; }

    const uint64_t lo = (pc > limit) ? (pc - limit) : 0x1000ull;
    const uint64_t hi = pc + limit;

    char line[512];
    uint64_t best = 0;
    int nseg = 0;
    while (fgets(line, sizeof(line), fmaps)) {
        unsigned long long a = 0, b = 0;
        char perm[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &a, &b, perm) != 3) continue;
        if (perm[2] != 'x') continue;                 // 只要可执行段
        if (b <= lo || a >= hi) continue;             // 只扫可达范围
        ++nseg;

        // 段内、可达范围与段范围的交集
        uint64_t s = (a > lo) ? a : lo;
        uint64_t e = (b < hi) ? b : hi;
        if (e <= s) continue;

        // 逐 4KB 页读，找连续零/nop 填充
        static uint8_t page[4096];
        int run = 0;
        uint64_t run_start = 0;
        for (uint64_t p = (s & ~0xFFFull); p < e; p += 4096) {
            ssize_t got = pread(mem, page, sizeof(page), (off_t)p);
            if (got != (ssize_t)sizeof(page)) continue;
            for (int i = 0; i < 4096; i += 4) {
                uint32_t w = 0;
                memcpy(&w, page + i, 4);
                bool filler = (w == 0x00000000u) || (w == 0xD503201Fu);   // 零 或 nop
                if (filler) {
                    if (run == 0) run_start = p + (uint64_t)i;
                    ++run;
                } else {
                    if ((size_t)run * 4 >= need + 64 && run_start >= lo && run_start + (uint64_t)run * 4 <= hi) {
                        // 取洞末尾附近（避免踩到洞入口可能被用到的对齐指令）
                        uint64_t cand = (run_start + (uint64_t)run * 4 - need) & ~0x3Full;
                        if (cand >= run_start) {
                            LOGI("find_exec_cave: 洞 0x%llx 长 %d 字节 (段 0x%llx-0x%llx %s)",
                                 (unsigned long long)run_start, run * 4,
                                 (unsigned long long)a, (unsigned long long)b, perm);
                            best = cand;
                            goto done;
                        }
                    }
                    run = 0;
                }
            }
        }
        if ((size_t)run * 4 >= need + 64) {
            uint64_t cand = (run_start + (uint64_t)run * 4 - need) & ~0x3Full;
            if (cand >= run_start && run_start >= lo) {
                LOGI("find_exec_cave: 洞 0x%llx 长 %d 字节 (段尾)", (unsigned long long)run_start, run * 4);
                best = cand;
                break;
            }
        }
    }
done:
    close(mem);
    fclose(fmaps);
    if (!best) LOGW("find_exec_cave: 扫了 %d 个可执行段，±%lluMB 内没找到 >=%zu 字节的填充洞",
                    nseg, (unsigned long long)(limit / 1048576), need);
    return best;
}

// 在目标进程里找一块「匿名可写、且离已知数据有安全距离」的内存，用来放桩。
// 思路：扫 /proc/<pid>/maps 挑 rw-p 且无路径名（匿名）的映射，取其中段位置。
// 只是兜底手段——首选还是目标线程自己的栈。
// 备用手段（当前 run_remote 走代码洞，不再用它；保留给「目标有可写可执行页」的机型）
static int run_remote(pid_t tpid, pid_t ttid, uint64_t mailbox, bool keep) {
    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/mem", (int)tpid);
    int mem_fd = open(mpath, O_RDWR);
    if (mem_fd < 0) {
        LOGE("打开 %s 失败: errno=%d (%s)", mpath, errno, strerror(errno));
        LOGE("  —— 无 root 时这是预期的：内核 __ptrace_may_access 要求 root 或同 uid");
        return 1;
    }
    TLOG("%s 打开成功（无 ptrace 关系）", mpath);

    // 确认真的有 I/O 权限（procfs 的 mem 打开成功不代表能读写）
    uint64_t probe = 0;
    if (!pread_mem(mem_fd, mailbox, &probe, sizeof(probe))) {
        LOGE("读目标 mailbox 0x%llx 失败: errno=%d", (unsigned long long)mailbox, errno);
        close(mem_fd);
        return 1;
    }
    TLOG("目标 mailbox 原值 = 0x%llx", (unsigned long long)probe);

    // ── phase 1：借目标线程在**目标地址空间**里 mmap 一块 RWX ──
    SyscallInfo si;
    if (!wait_for_safe_syscall(ttid, &si, 4000, "P1")) {
        LOGE("P1 放弃：tid=%d 未进入可重启 syscall (sysno=%ld err=%d)",
             (int)ttid, si.sysno, si.err);
        close(mem_fd);
        return 2;
    }
    TLOG("P1 命中 tid=%d syscall=%ld(%s) sp=0x%llx pc=0x%llx",
         (int)ttid, si.sysno, syscall_name(si.sysno),
         (unsigned long long)si.sp, (unsigned long long)si.pc);

    // ══════════════════════════════════════════════════════════════════════
    //  最终形态：pc 处只改 **4 字节**（一条 `b`），payload 放同页落点，
    //  收尾用 fixup 把 pc 原指令写回并跳回 pc —— 让被覆盖的指令**重新执行**
    // ══════════════════════════════════════════════════════════════════════
    //
    //  为什么不能像上一版那样「覆盖 144 字节再跳到 pc+144」：
    //  那 36 条被跳过的 libc 指令是必须执行的（寄存器检查、错误处理…），
    //  跳过它们 = 状态全错 = 目标直接 SIGSEGV。实测目标每次都 DEAD。
    //
    //  现在的语义是干净的：
    //    pc 处 4 字节 -> `b Q`（Q = 同页/同段内的落点，±128MB 内）
    //    Q 处 payload：干活 -> 把 pc 处的原指令字写回 -> isb -> `b pc`
    //    于是目标线程**原地重演**了那条被我们临时改掉的指令，之后自然继续。
    //  额外好处：第一个返回的线程跑完就把 pc 复原了，**窗口自动关闭**，
    //  后面的线程不会再进 payload（这一点对「返回点被多线程共享」尤其关键）。
    uint8_t pbuf[1024];
    size_t code_len = 0;
    uint64_t back = 0;

    // pc 处的原 4 字节（fixup 要写回的就是它）
    uint32_t orig_word = 0;
    if (!pread_mem(mem_fd, si.pc, &orig_word, 4)) {
        LOGE("读 pc=0x%llx 处原指令失败 (errno=%d)", (unsigned long long)si.pc, errno);
        close(mem_fd);
        return 3;
    }
    TLOG("pc 处原指令 = 0x%08x", orig_word);

    // 先拿长度：**必须带上 fixup 参数**，否则量出来的是不带 fixup 的版本（更短），
    // 而真正写下去的是带 fixup 的版本 -> 会误判"payload 超长"（上一版就栽在这）。
    // 占位 base/resume 相同 -> 收尾偏移 0，一定编得出。
    memset(pbuf, 0, sizeof(pbuf));
    build_payload_full(pbuf, si.pc, mailbox, si.sp, si.pc, si.pc, si.pc, orig_word, &code_len, &back);
    if (code_len == 0) { LOGE("payload 构造失败"); close(mem_fd); return 3; }
    size_t total = CODE_OFF + code_len;
    if (total < (size_t)GUARD_OFF + 8) total = (size_t)GUARD_OFF + 8;
    TLOG("payload code_len=%zu，落点需要 %zu 字节", code_len, total);

    // 找落点：只要「目标里已映射且可执行、离 pc 近」，不猜空洞
    uint64_t Q = find_exec_slot(tpid, si.pc, total);
    if (Q == 0) { LOGE("没找到可执行落点"); close(mem_fd); return 3; }

    // 备份落点原内容（收尾还原）
    uint8_t q_orig[1024];
    bool q_saved = pread_mem(mem_fd, Q, q_orig, total);
    if (!q_saved) LOGW("落点原内容备份失败，收尾将无法还原");

    // 按真实地址重编：x1 = Q，收尾 fixup 写回 pc 处原指令，然后跳回 pc
    memset(pbuf, 0, sizeof(pbuf));
    build_payload_full(pbuf, Q, mailbox, si.sp, si.pc, si.pc, si.pc, orig_word, &code_len, &back);
    if (code_len == 0) { LOGE("payload 按落点重编失败"); close(mem_fd); return 3; }
    if (CODE_OFF + code_len > total) { LOGE("payload 超长"); close(mem_fd); return 3; }

    if (!pwrite_mem(mem_fd, Q, pbuf, total)) {
        LOGE("把 payload 写进落点 0x%llx 失败 (errno=%d)", (unsigned long long)Q, errno);
        close(mem_fd);
        return 3;
    }
    {
        uint8_t chk[1024];
        if (!pread_mem(mem_fd, Q, chk, total) || memcmp(chk, pbuf, total) != 0) {
            LOGE("落点写入后回读不一致");
            close(mem_fd);
            return 3;
        }
        TLOG("payload 已写入落点 0x%llx（%zu 字节，回读一致）", (unsigned long long)Q, total);
    }

    // 关键的 4 字节：pc -> `b Q`
    uint32_t br = 0;
    if (!encode_b(si.pc, Q + CODE_OFF, &br)) {
        LOGE("pc -> 落点 的 b 编码失败（超出 ±128MB）");
        close(mem_fd);
        return 3;
    }
    if (!pwrite_mem(mem_fd, si.pc, &br, 4)) {
        LOGE("覆盖 pc=0x%llx 失败 (errno=%d)", (unsigned long long)si.pc, errno);
        close(mem_fd);
        return 3;
    }
    TLOG("pc 处已改为 0x%08x -> 落点+%d（原 0x%08x）", br, CODE_OFF, orig_word);

    {
        uint64_t zero = 0;
        pwrite_mem(mem_fd, mailbox, &zero, sizeof(zero));
    }

    // 等目标线程从 syscall 返回、执行 payload
    bool hit = false;
    for (int i = 0; i < 1500; ++i) {
        uint64_t v = 0;
        if (pread_mem(mem_fd, mailbox, &v, sizeof(v)) && v == (uint64_t)MAGIC) { hit = true; break; }
        usleep(1000);
    }
    TLOG("=== 跨进程结果: payload %s (期望 mailbox=0x%llx) ===",
         hit ? "【成功】在目标进程里执行了" : "【失败】", (unsigned long long)MAGIC);

    // 收尾：pc 正常已由 payload 自己复原；这里兜底再写一次，并还原落点
    {
        uint32_t cur = 0;
        bool rd_ok = pread_mem(mem_fd, si.pc, &cur, 4);
        if (!rd_ok) {
            // 【诊断坑，别再犯】读失败曾被打印成「已由 payload 自行复原」。
            // 读不到只能说明**目标已经死了**，不能当成复原成功 —— 这会让人误判方向。
            LOGE("读 pc 失败(0x%llx) -> 目标进程很可能已经死了，不能据此认为已复原",
                 (unsigned long long)si.pc);
        } else if (cur != orig_word) {
            LOGW("pc 处仍是 0x%08x（期望 0x%08x），payload 未复原，注入器兜底写回",
                 cur, orig_word);
            pwrite_mem(mem_fd, si.pc, &orig_word, 4);
        } else {
            TLOG("pc 处已复原为 0x%08x（读回确认）", orig_word);
        }
    }
    if (q_saved) {
        if (pwrite_mem(mem_fd, Q, q_orig, total)) LOGI("落点原内容已还原");
        else LOGW("落点原内容还原失败 (errno=%d)", errno);
    }
    (void)keep;
    (void)back;

    uint64_t after = 0;
    pread_mem(mem_fd, mailbox, &after, sizeof(after));
    uint32_t cur = 0;
    bool pc_ok = pread_mem(mem_fd, si.pc, &cur, 4);
    TLOG("收尾: mailbox=0x%llx  *pc=0x%08x (原 0x%08x, 读回=%d)",
         (unsigned long long)after, cur, orig_word, pc_ok ? 1 : 0);
    close(mem_fd);
    return hit ? 0 : 7;
}

// 按文件名找 .so / linker 的基址。
// 注意：APK 内置库（extractNativeLibs=false）在 maps 里**没有** so 文件名，
// 只有 base.apk，那种要用 find_so_base_by_apkoff；
// 但 linker64 是独立文件，maps 里有路径，按名字找即可。
static uint64_t find_so_base_by_name(pid_t tpid, const char* name) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)tpid);
    FILE* f = fopen(path, "re");
    if (!f) return 0;
    char line[512];
    uint64_t best = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, name)) continue;
        unsigned long long a = 0, b = 0;
        char perm[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &a, &b, perm) != 3) continue;
        if (best == 0 || (uint64_t)a < best) best = a;
    }
    fclose(f);
    if (best) TLOG("find_so_base_by_name: %s -> 0x%llx", name, (unsigned long long)best);
    else LOGW("maps 里找不到 %s", name);
    return best;
}

// 统计某路径在目标 maps 里出现的**映射条数**。
//
// 【为什么必须数条数】bionic 加载 .so 的第一步是 open()+mmap 整个文件读 ELF 头做校验，
// 然后立刻 munmap；第二步才映射各段。所以：
//   条数 == 1  -> 只是「头探测」那一瞬间的映射，**并不代表加载成功**
//   条数 >= 2  -> r--p / r-xp / rw-p 等段真的被映射了，才算加载
// 我用"出现过就成功"的布尔判断，连续三次报出假阳性 —— 这是那个 bug 的修复。
static int count_maps_entries(pid_t tpid, const char* needle) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)tpid);
    FILE* f = fopen(path, "re");
    if (!f) return -1;
    char line[1024];
    int n = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, needle)) ++n;
    }
    fclose(f);
    return n;
}

// 目标 maps 里有没有出现某个子串（用于确认 dlopen 真的把它映射进来了）
static bool target_maps_contains(pid_t tpid, const char* needle) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)tpid);
    FILE* f = fopen(path, "re");
    if (!f) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, needle)) { found = true; break; }
    }
    fclose(f);
    return found;
}

// 在目标某个 .so 的**可写段**里扫描，找到值为 want 的那个 8 字节槽（即 GOT 项）。
//
// 为什么不用硬编码 GOT 偏移：实测被这个坑过两次 —— 只要目标 so 重编一次，
// GOT 整体就会移位（0x73210 -> 0x73220），而流程**没有任何报错**，
// 只是"永远等不到调用"。改成按「槽里应当出现的函数地址」反查，才稳。
static uint64_t find_got_slot_for_ptr(pid_t tpid, int mem_fd, uint64_t so_base,
                                      uint64_t want) {
    // 在目标 so 的**可写映射**里找「值等于 want」的 8 字节槽，也就是它的 GOT 项。
    //
    // 【踩过的坑】一开始我按「maps 里 offset == so 在 APK 内的偏移」来筛选段，
    // 结果一个段都没匹配到 —— 因为**同一个 so 的各个段 p_offset 不同**，
    // maps 里的 file offset 自然也不同（实测扫到 0 个可写段）。
    // 改成**按地址范围**筛：so 的各段在地址上是连续的，
    // 取 [so_base, so_base+2MB) 内所有可写映射即可，与 offset 无关。
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)tpid);
    FILE* f = fopen(path, "re");
    if (!f) { LOGW("find_got_slot_for_ptr: 打不开 maps (errno=%d)", errno); return 0; }

    const uint64_t hi = so_base + 0x200000;      // 2MB 窗口：apk 内置 so 足够
    char line[512];
    uint64_t hit = 0;
    int nseg = 0, npage = 0;
    while (fgets(line, sizeof(line), f) && hit == 0) {
        unsigned long long a = 0, b = 0;
        char perm[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &a, &b, perm) != 3) continue;
        // 【注意】不能只扫可写段！GOT 在 RELRO 里，重定位完成后是**只读**的
        // （之前 tombstone 的 SEGV_ACCERR 就是这个原因）。只筛 'w' 会正好把 GOT 段跳过，
        // 实测扫到 5 个别的可写段、却找不到目标函数。这里改成扫所有**可读**段。
        if (perm[0] != 'r') continue;
        if (a < so_base || a >= hi) continue;         // 只要落在该 so 的地址窗口内
        ++nseg;
        // 逐 4KB 读，避免一次要一大片连续内存
        for (uint64_t p = a; p + 8 <= b; p += 4096) {
            uint8_t buf[4096];
            ssize_t got = pread(mem_fd, buf, sizeof(buf), (off_t)p);
            if (got <= 0) continue;                   // 未映射/不可读，跳过
            ++npage;
            size_t lim = (size_t)got;
            for (size_t i = 0; i + 8 <= lim; i += 8) {
                uint64_t v = 0;
                memcpy(&v, buf + i, 8);
                if (v == want) { hit = p + i; break; }
            }
            if (hit) break;
        }
    }
    fclose(f);
    TLOG("find_got_slot_for_ptr: 窗口 [0x%llx,0x%llx) 内可写段 %d 个 / 读到 %d 页；%s 0x%llx",
         (unsigned long long)so_base, (unsigned long long)hi, nseg, npage,
         hit ? "找到槽" : "未找到目标函数", (unsigned long long)want);
    if (hit) TLOG("  => GOT 槽 = 0x%llx", (unsigned long long)hit);
    return hit;
}


// ═════════════════════════════════════════════════════════════════════════════
//  GOT 劫持模式（跨进程，纯数据写 —— 不依赖 i-cache）
// ═════════════════════════════════════════════════════════════════════════════
//
//  为什么换这条路：
//  上一版覆盖 pc 处的**指令**，跨进程写成功了（回读一致）但**从不生效** ——
//  原因是内核只为执行写入的那个 CPU 刷 i-cache，目标线程在另一个核上，
//  它的 i-cache 里仍是旧指令。这是「写指令」的固有边界，不是参数问题。
//
//  GOT 项是**数据**：间接跳转的目标来自数据，d-cache 天然一致，
//  写入立刻对目标可见。所以把某个函数的 GOT 槽改成 payload 地址，
//  该函数下一次被调用就会跳进 payload —— 全程不需要 i-cache 维护。
//
//  payload 很小（~56 字节，不需要数据区）：
//      *mailbox = MAGIC          // 证明执行了
//      [got_slot] = real_func    // 自恢复（一次性 detour）
//      br real_func              // 尾跳转，保留 x0/x1/lr，语义不变
//
//  参数：soname = 含该 GOT 项的 so 基名；got_off = 该 so 内 GOT 槽偏移（ELF 里算好）。
static int run_got(pid_t tpid, uint64_t so_apk_off, uint64_t got_off, uint64_t mailbox) {
    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/mem", (int)tpid);
    int mem_fd = open(mpath, O_RDWR);
    if (mem_fd < 0) { LOGE("打开 %s 失败 errno=%d", mpath, errno); return 1; }
    TLOG("GOT 模式: mem 打开成功");

    uint64_t base = find_so_base_by_apkoff(tpid, so_apk_off);
    if (base == 0) { LOGE("找不到 apk_off=0x%llx 对应 so 的基址",
                          (unsigned long long)so_apk_off); close(mem_fd); return 2; }
    uint64_t got = base + got_off;
    TLOG("GOT 槽 = 0x%llx（so 基址 0x%llx + GOT 偏移 0x%llx）",
         (unsigned long long)got, (unsigned long long)base, (unsigned long long)got_off);

    uint64_t real_fn = 0;
    if (!pread_mem(mem_fd, got, &real_fn, 8)) {
        LOGE("读 GOT 槽 0x%llx 失败 errno=%d", (unsigned long long)got, errno);
        close(mem_fd);
        return 2;
    }
    TLOG("GOT 原值 = 0x%llx（应指向 libc 内的真实函数）", (unsigned long long)real_fn);
    if (real_fn < 0x1000 || real_fn == (uint64_t)-1) {
        LOGE("GOT 原值不像有效函数地址，放弃");
        close(mem_fd);
        return 2;
    }

    // 造 payload
    uint8_t pbuf[256];
    memset(pbuf, 0, sizeof(pbuf));
    uint32_t* insn = (uint32_t*)pbuf;
    int n = 0;
    // 【必须】先把 x0/x1 存栈。它们是**调用者传给被 hook 函数的参数**
    // （nanosleep 的 x0=timespec 指针、x1=rmtp 输出指针）。
    // 踩过的坑：payload 为拿寄存器把 x0/x1 改成 mailbox/MAGIC 就直接尾跳到真函数，
    // 结果 libc 的 nanosleep 把 x1 当 rmtp，出错返回时往 0x5A50544D 写剩余时间
    // -> SIGSEGV -> App 闪退。
    insn[n++] = 0xA9BF07E0u;                               // stp x0, x1, [sp, #-16]!
    n += load_imm64(insn + n, 0, mailbox);                 // x0 = mailbox
    n += load_imm64(insn + n, 1, (uint64_t)MAGIC);         // x1 = MAGIC
    insn[n++] = enc_str_x_imm(1, 0, 0);                    // *mailbox = MAGIC
    n += load_imm64(insn + n, 3, real_fn);                 // x3 = 真函数
    insn[n++] = 0xA8C107E0u;                               // ldp x0, x1, [sp], #16  还原参数
    insn[n++] = enc_br(3);                                 // br x3（尾跳转，语义不变）
    // 【别再让 payload 自己写回 GOT】
    // 实测（tombstone 30）：GOT 槽在只读的 .data.rel.ro 里（Android 链接
    // -z relro + BIND_NOW，重定位后置只读），payload 里的 `str 真函数,[GOT]`
    // 直接 SEGV_ACCERR 崩掉。注入器能写它是因为 /proc/pid/mem 走 FOLL_FORCE
    // （COW 私有副本），但**目标自己写同一地址不行**。
    // 所以自恢复交给注入器做（见 run_got 收尾）。
    (void)got;
    size_t plen = (size_t)n * 4;
    TLOG("GOT payload: %d 条指令 = %zu 字节", n, plen);

    // 落点：仍放在冷门 so 的 r-x 页（目标没有可写可执行页，这是硬约束）
    uint64_t Q = find_exec_slot(tpid, real_fn, plen);
    if (Q == 0) { LOGE("找不到可执行落点"); close(mem_fd); return 3; }

    uint8_t q_orig[256];
    bool q_saved = pread_mem(mem_fd, Q, q_orig, plen);
    if (!pwrite_mem(mem_fd, Q, pbuf, plen)) {
        LOGE("payload 写入落点 0x%llx 失败 errno=%d", (unsigned long long)Q, errno);
        close(mem_fd);
        return 3;
    }
    uint8_t chk[256];
    if (!pread_mem(mem_fd, Q, chk, plen) || memcmp(chk, pbuf, plen) != 0) {
        LOGE("落点回读不一致");
        close(mem_fd);
        return 3;
    }
    TLOG("payload 已写入落点 0x%llx（%zu 字节，回读一致）", (unsigned long long)Q, plen);

    // 关键：纯数据写 —— 把 GOT 槽改成 payload 地址
    if (!pwrite_mem(mem_fd, got, &Q, 8)) {
        LOGE("写 GOT 槽 0x%llx 失败 errno=%d", (unsigned long long)got, errno);
        close(mem_fd);
        return 3;
    }
    TLOG("GOT 槽已改为 0x%llx（等待目标调用该函数…）", (unsigned long long)Q);

    {
        uint64_t zero = 0;
        pwrite_mem(mem_fd, mailbox, &zero, sizeof(zero));
    }

    bool hit = false;
    for (int i = 0; i < 3000; ++i) {
        uint64_t v = 0;
        if (pread_mem(mem_fd, mailbox, &v, sizeof(v)) && v == (uint64_t)MAGIC) { hit = true; break; }
        usleep(1000);
    }
    TLOG("=== GOT 劫持结果: payload %s (mailbox 期望 0x%llx) ===",
         hit ? "【成功】被调用了" : "【失败】未被调用", (unsigned long long)MAGIC);

    // 收尾：兜底还原 GOT 槽；断言目标是否还活着
    {
        uint64_t cur = 0;
        bool rd = pread_mem(mem_fd, got, &cur, 8);
        if (!rd) LOGE("读 GOT 槽失败 -> 目标可能已死");
        else if (cur != real_fn) {
            TLOG("GOT 槽仍为 0x%llx（payload 不再自恢复），注入器写回 0x%llx",
                 (unsigned long long)cur, (unsigned long long)real_fn);
            pwrite_mem(mem_fd, got, &real_fn, 8);
        } else {
            TLOG("GOT 槽已自恢复为 0x%llx（读回确认）", (unsigned long long)real_fn);
        }
    }
    if (q_saved) {
        if (pwrite_mem(mem_fd, Q, q_orig, plen)) TLOG("落点原内容已还原");
        else LOGW("落点原内容还原失败 errno=%d", errno);
    }
    close(mem_fd);
    return hit ? 0 : 7;
}

// ═════════════════════════════════════════════════════════════════════════════
//  检查点 ③：GOT 劫持 + dlopen —— 真正把一个 so 载入目标（全程零 ptrace）
// ═════════════════════════════════════════════════════════════════════════════
//
//  符号解析（Android 的关键点，已用设备文件核实）：
//    * libc.so 里的 dlopen/dlsym 只是**转发桩**（dynsym 里是 UND），真正的实现
//      在 **linker64**：`__loader_dlopen` 偏移 0x88124
//      （设备文件 /apex/com.android.runtime/bin/linker64，宿主 readelf 得到）
//    * `__loader_dlopen(filename, flags, caller_addr)` 有**三个**参数，第三个
//      caller_addr 决定用哪个 namespace 解析。必须传**目标自己 so 里的地址**
//      （这里用它的加载基址），否则会按 payload 所在那个冷门 so 的 namespace 算，
//      可能不允许加载目标路径。
//    * RTLD_NOW = 2
//
//  payload 布局：代码在偏移 0，路径字符串在 DL_PATH_OFF。
//  代码长度上限约 140 字节 < 512，所以 DL_PATH_OFF 固定 512 是安全的。
#define DL_PATH_OFF 512

static int run_dlopen(pid_t tpid, uint64_t so_apk_off, uint64_t libc_sym_off,
                      uint64_t linker_dlopen_off, uint64_t mailbox, const char* so_path) {
    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/mem", (int)tpid);
    int mem_fd = open(mpath, O_RDWR);
    if (mem_fd < 0) { LOGE("打开 %s 失败 errno=%d", mpath, errno); return 1; }
    TLOG("=== dlopen 模式: 目标 so = %s ===", so_path);

    uint64_t so_base = find_so_base_by_apkoff(tpid, so_apk_off);
    if (so_base == 0) { LOGE("找不到 apk_off=0x%llx 的 so 基址", (unsigned long long)so_apk_off); close(mem_fd); return 2; }

    // ---- 自动定位 GOT 槽：不再硬编码 ----
    // 要 hook 的函数（nanosleep）在 libc 里的地址 = libc 基址 + 该符号偏移。
    // 然后在目标 so 的可写段里找「值恰好等于这个地址」的 8 字节槽 —— 那就是它的 GOT 项。
    // 这样 so 重编导致 GOT 移位时不会静默失效，而是要么找到、要么明确报错。
    uint64_t libc_base = find_so_base_by_name(tpid, "libc.so");
    if (libc_base == 0) { LOGE("找不到 libc.so 基址"); close(mem_fd); return 2; }
    uint64_t want = libc_base + libc_sym_off;
    TLOG("libc 基址=0x%llx + 符号偏移 0x%llx = 目标函数 0x%llx",
         (unsigned long long)libc_base, (unsigned long long)libc_sym_off, (unsigned long long)want);

    uint64_t got = find_got_slot_for_ptr(tpid, mem_fd, so_base, want);
    if (got == 0) {
        LOGE("在 apk_off=0x%llx 的 so 里找不到指向 0x%llx 的 GOT 槽（符号偏移或 so 选错了）",
             (unsigned long long)so_apk_off, (unsigned long long)want);
        close(mem_fd);
        return 2;
    }
    uint64_t real_fn = want;
    TLOG("so 基址=0x%llx  GOT 槽=0x%llx（由值反查得到）  被 hook 函数=0x%llx",
         (unsigned long long)so_base, (unsigned long long)got, (unsigned long long)real_fn);

    uint64_t linker_base = find_so_base_by_name(tpid, "linker64");
    if (linker_base == 0) { LOGE("找不到 linker64 基址"); close(mem_fd); return 2; }
    uint64_t dlopen_addr = linker_base + linker_dlopen_off;
    TLOG("linker64 基址=0x%llx  __loader_dlopen=0x%llx", (unsigned long long)linker_base,
         (unsigned long long)dlopen_addr);

    const size_t path_len = strlen(so_path) + 1;
    const size_t need = (size_t)DL_PATH_OFF + path_len;
    uint64_t Q = find_exec_slot(tpid, dlopen_addr, need);
    if (Q == 0) { LOGE("找不到可执行落点（需要 %zu 字节）", need); close(mem_fd); return 3; }

    uint8_t pbuf[1024];
    memset(pbuf, 0, sizeof(pbuf));
    uint32_t* insn = (uint32_t*)pbuf;
    int n = 0;
    insn[n++] = 0xA9BE07E0u;                       // stp x0, x1, [sp, #-32]!
    insn[n++] = 0xF9000BFEu;                       // str x30, [sp, #16]
    n += load_imm64(insn + n, 0, mailbox);         // x0 = mailbox
    n += load_imm64(insn + n, 1, (uint64_t)MAGIC); // x1 = MAGIC
    insn[n++] = enc_str_x_imm(1, 0, 0);            // *mailbox = MAGIC  (证明执行了)
    n += load_imm64(insn + n, 0, Q + DL_PATH_OFF); // x0 = 路径字符串
    insn[n++] = 0xD2800041u;                       // movz x1, #2  (RTLD_NOW)
    n += load_imm64(insn + n, 2, so_base);         // x2 = caller_addr（目标自己的 so）
    n += load_imm64(insn + n, 8, dlopen_addr);     // x8 = __loader_dlopen
    insn[n++] = 0xD63F0100u;                       // blr x8
    insn[n++] = 0xF9400BFEu;                       // ldr x30, [sp, #16]
    insn[n++] = 0xA8C207E0u;                       // ldp x0, x1, [sp], #32
    n += load_imm64(insn + n, 9, real_fn);         // x9 = 被劫持的真函数
    insn[n++] = enc_br(9);                         // br x9（尾跳转，语义不变）
    size_t code_len = (size_t)n * 4;
    if (code_len >= DL_PATH_OFF) { LOGE("payload 代码 %zu 字节超过 PATH_OFF", code_len); close(mem_fd); return 3; }
    memcpy(pbuf + DL_PATH_OFF, so_path, path_len);
    TLOG("payload: 代码 %zu 字节 + 路径 %zu 字节 = %zu，落点 0x%llx",
         code_len, path_len, need, (unsigned long long)Q);

    uint8_t q_orig[1024];
    bool q_saved = pread_mem(mem_fd, Q, q_orig, need);
    if (!pwrite_mem(mem_fd, Q, pbuf, need)) { LOGE("写落点失败 errno=%d", errno); close(mem_fd); return 3; }
    uint8_t chk[1024];
    if (!pread_mem(mem_fd, Q, chk, need) || memcmp(chk, pbuf, need) != 0) {
        LOGE("落点回读不一致"); close(mem_fd); return 3;
    }
    TLOG("payload 已写入落点并回读一致");

    // ---- 关键：纯数据写，改 GOT 槽 ----
    if (!pwrite_mem(mem_fd, got, &Q, 8)) { LOGE("写 GOT 失败 errno=%d", errno); close(mem_fd); return 3; }
    TLOG("GOT 槽已指向 payload，等待目标调用被劫持函数…");

    { uint64_t zero = 0; pwrite_mem(mem_fd, mailbox, &zero, sizeof(zero)); }

    bool ran = false;
    for (int i = 0; i < 5000; ++i) {
        uint64_t v = 0;
        if (pread_mem(mem_fd, mailbox, &v, sizeof(v)) && v == (uint64_t)MAGIC) { ran = true; break; }
        usleep(1000);
    }
    TLOG("payload %s", ran ? "【已执行】" : "【未执行】");

    // ---- 铁证：目标 maps 里出现我们的 so 路径 ----
    bool loaded = false;
    if (ran) {
        const char* base = strrchr(so_path, '/');
        base = base ? base + 1 : so_path;
        for (int i = 0; i < 2000; ++i) {
            if (target_maps_contains(tpid, base)) { loaded = true; break; }
            usleep(1000);
        }
    }
    TLOG("=== dlopen 结果: %s ===", loaded ? "【成功】目标里已映射我们的 so"
                                          : (ran ? "【失败】payload 跑了但 so 未出现在 maps"
                                                 : "【失败】payload 未被执行"));

    // ---- 收尾：还原 GOT 与落点 ----
        { uint64_t cur = 0;
      if (pread_mem(mem_fd, got, &cur, 8) && cur != real_fn) {
          TLOG("GOT 槽 0x%llx -> 写回 0x%llx", (unsigned long long)cur, (unsigned long long)real_fn);
          pwrite_mem(mem_fd, got, &real_fn, 8);
      } }
    if (q_saved && pwrite_mem(mem_fd, Q, q_orig, need)) TLOG("落点原内容已还原");
    close(mem_fd);
    return loaded ? 0 : 7;
}

// 前向声明（定义在下面，run_dataonly 会用到）
static uint64_t elf_lookup_dynsym(const char* path, const char* want, uint64_t* out_size);

// ═════════════════════════════════════════════════════════════════════════════
//  运行时解析 ELF 动态符号（去掉 ROM 相关的硬编码偏移）
// ═════════════════════════════════════════════════════════════════════════════
//  之前 nanosleep(@libc)=0xd8ac0、dlopen(@libdl)=0x401c 都是我拿宿主 readelf
//  从设备文件上算出来再写死进代码的 —— 换 ROM / 系统版本就会失效，而且失效方式
//  是**静默的**。这里真正运行时解析：读设备的 libc.so / libdl.so，查它的 .dynsym。
static uint64_t elf_lookup_dynsym(const char* path, const char* want, uint64_t* out_size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) { LOGW("打不开 %s errno=%d", path, errno); return 0; }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return 0; }
    size_t sz = (size_t)st.st_size;
    uint8_t* buf = (uint8_t*)malloc(sz);
    if (!buf) { close(fd); return 0; }
    ssize_t got = pread(fd, buf, sz, 0);
    close(fd);
    if (got != (ssize_t)sz) { free(buf); return 0; }

    uint64_t result = 0;
    const Elf64_Ehdr* eh = (const Elf64_Ehdr*)buf;
    if (memcmp(eh->e_ident, ELFMAG, 4) == 0 && eh->e_shoff && eh->e_shnum) {
        const Elf64_Shdr* sh = (const Elf64_Shdr*)(buf + eh->e_shoff);
        for (int i = 0; i < eh->e_shnum && !result; ++i) {
            if (sh[i].sh_type != SHT_DYNSYM) continue;
            if (sh[i].sh_offset + sh[i].sh_size > sz) continue;
            if (sh[i].sh_link >= (uint32_t)eh->e_shnum) continue;
            const Elf64_Sym* sym = (const Elf64_Sym*)(buf + sh[i].sh_offset);
            size_t n = (size_t)(sh[i].sh_size / sizeof(Elf64_Sym));
            const char* strtab = (const char*)(buf + sh[sh[i].sh_link].sh_offset);
            for (size_t k = 0; k < n; ++k) {
                if (sym[k].st_name == 0) continue;
                const char* nm = strtab + sym[k].st_name;
                size_t len = 0;
                while (nm[len] && nm[len] != '@') ++len;   // 去掉 @@VERSION 后缀
                if (len != strlen(want) || memcmp(nm, want, len) != 0) continue;
                if (sym[k].st_value == 0) continue;
                result = sym[k].st_value;
                if (out_size) *out_size = sym[k].st_size;
                break;
            }
        }
    }
    free(buf);
    if (result) TLOG("解析 %s: %s = 0x%llx", path, want, (unsigned long long)result);
    else LOGW("在 %s 里找不到符号 %s", path, want);
    return result;
}

// 在目标**所有文件映射的、可读且非可执行**区域里找值为 want 的 8 字节槽（GOT 项）。
// 这样就彻底不需要"某个 so 的 APK 内偏移" —— 与目标是什么 App 完全无关。
// GOT 一定落在非可执行区（RELRO 的 r-- 或 .data 的 rw-），且必然在文件映射里。
// 候选 GOT 槽收集器。
//
// 【上一版为什么失败】我按 maps 顺序扫，只设了 64MB 总配额 —— 而 maps 是按地址排序的，
// 目标进程有 377 个已加载库，前面几百个库的段就把配额吃光，**根本没扫到我们要的那个 so**
// （实测输出：扫了 65536 KB，命中 0 个）。而且只取"第一个命中"在多库环境下也不可靠。
//
// 这一版：
//   * **先扫小段**：GOT/RELRO/.data 都是小段（通常几十 KB），大段（MB 级的 .text/数据）放后面
//   * **优先 r-- 段**：BIND_NOW 下 PLT 的 GOT 在 .data.rel.ro，是只读的
//   * **收集多个候选**（最多 8 个），调用方可以逐个尝试
static int find_got_slots_anywhere(pid_t tpid, int mem_fd, uint64_t want,
                                   uint64_t* out, int max_out) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)tpid);
    int n = 0;
    uint64_t scanned_total = 0;
    // 三轮：先小只读段（RELRO/GOT 最可能在这），再小可写段，最后放宽
    struct Pass { uint64_t maxlen; int want_r; int want_w; } passes[3] = {
        {1ull << 20, 1, 0},        // <=1MB 且 r--（RELRO/GOT）
        {1ull << 20, 0, 1},        // <=1MB 且 rw-（.data）
        {8ull << 20, 0, 0},        // <=8MB 任意可读非可执行
    };
    for (int pi = 0; pi < 3 && n < max_out; ++pi) {
        FILE* f = fopen(path, "re");
        if (!f) return n;
        char line[1024];
        while (fgets(line, sizeof(line), f) && n < max_out) {
            unsigned long long a = 0, b = 0;
            char perm[8] = {0};
            if (sscanf(line, "%llx-%llx %7s", &a, &b, perm) != 3) continue;
            if (perm[0] != 'r' || perm[2] == 'x') continue;   // 可读、非可执行
            if (!strchr(line, '/')) continue;                 // 文件映射（GOT 一定在库里）
            uint64_t len = b - a;
            if (len == 0 || len > passes[pi].maxlen) continue;
            if (passes[pi].want_r && perm[1] != '-') continue;
            if (passes[pi].want_w && perm[1] != 'w') continue;

            for (uint64_t p = a; p + 8 <= b && n < max_out; p += 4096) {
                uint8_t buf[4096];
                ssize_t got = pread(mem_fd, buf, sizeof(buf), (off_t)p);
                if (got <= 0) continue;
                scanned_total += (uint64_t)got;
                for (size_t i = 0; i + 8 <= (size_t)got; i += 8) {
                    uint64_t v = 0;
                    memcpy(&v, buf + i, 8);
                    if (v == want) {
                        uint64_t slot = p + i;
                        bool dup = false;
                        for (int k = 0; k < n; ++k) if (out[k] == slot) { dup = true; break; }
                        if (!dup) {
                            out[n++] = slot;
                            // 8 个槽分属 8 个库时，只有命中该线程真正在用的那个库才可能生效。
                            char owner[512] = {0};
                            maps_lookup_name(tpid, slot, owner, sizeof(owner));
                            TLOG("  候选 GOT 槽 #%d = 0x%llx（段 0x%llx 权限 %s）库=%s",
                                 n, (unsigned long long)slot, (unsigned long long)a, perm,
                                 owner);
                        }
                    }
                }
            }
        }
        fclose(f);
    }
    TLOG("find_got_slots_anywhere: 扫了 %llu KB，共 %d 个候选槽",
         (unsigned long long)(scanned_total / 1024), n);
    return n;
}


// 自动挑 hook 线程：找一个**正在 nanosleep(ts, NULL)** 的线程。
// 选它的理由：x0 = 栈上 timespec（可写、且目标每轮自己重写 -> 覆写可自愈），
//            x1 = NULL -> 正好是 dlopen 的 flags=0。
// 这是"arg1==0 且 arg0 可写"这一类调用点里最安全的一个。
// 单次扫描：找正在 want_sysno 且 arg1==0 的线程。
static pid_t scan_once_for_hook(pid_t tpid, long want_sysno, uint64_t* out_arg0) {
    char tpath[64];
    snprintf(tpath, sizeof(tpath), "/proc/%d/task", (int)tpid);
    DIR* d = opendir(tpath);
    if (!d) return 0;
    struct dirent* e;
    pid_t found = 0;
    while ((e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        pid_t tid = (pid_t)atoi(e->d_name);
        SyscallInfo si = read_syscall(tid);
        if (!si.valid || si.fields < 9) continue;
        if (si.sysno != want_sysno) continue;
        if (si.args[1] != 0) continue;                 // arg1 必须为 0（当 dlopen 的 flags）
        uint64_t a0 = si.args[0];
        if (a0 < 0x1000 || a0 > 0x0000800000000000ull) continue;
        if (out_arg0) *out_arg0 = a0;
        found = tid;
        break;
    }
    closedir(d);
    return found;
}

// 把 /proc/<tid>/syscall 的**原始行**写进 trace。
// 排障必需：目标是判定 si.args[0] 到底是不是它声称的那个缓冲。
static void log_raw_syscall(pid_t tid) {
    char p[64];
    snprintf(p, sizeof(p), "/proc/%d/syscall", (int)tid);
    FILE* f = fopen(p, "re");
    if (!f) { TLOG("  raw syscall: <打不开 %s>", p); return; }
    char line[256] = {0};
    if (fgets(line, sizeof(line), f)) {
        char* nl = strchr(line, '\n');
        if (nl) *nl = 0;
        TLOG("  raw /proc/%d/syscall: %s", (int)tid, line);
        LOGI("ZPTDIAG raw_syscall tid=%d: %s", (int)tid, line);   // logcat，便于外部读取
    }
    fclose(f);
}

// hook 点：线程 + 它正在用的可写缓冲 + 该缓冲对应的 libc 符号
struct HookSite {
    pid_t       tid;
    uint64_t    buf;             // 会被改写成 so 路径的那块缓冲
    const char* sym;             // 在 libc 里要解析的符号名（决定劫持哪些 GOT 项）
    bool        self_healing;    // true = 目标自己会重写该缓冲（nanosleep 的 timespec）
};

// 地址是否落在**可写**映射里，且 [addr, addr+len) 不越出该映射
static bool addr_writable(pid_t tpid, uint64_t addr, size_t len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)tpid);
    FILE* f = fopen(path, "re");
    if (!f) return false;
    char line[1024];
    bool ok = false;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long a = 0, b = 0;
        char perm[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &a, &b, perm) != 3) continue;
        if (addr >= a && (addr + len) <= b) { ok = (perm[1] == 'w'); break; }
        if (a > addr) break;
    }
    fclose(f);
    return ok;
}

// 某地址是否落在**可执行**映射（r-x）里。用来识别"这里存的是返回地址/函数指针"。
static bool addr_in_exec_mapping(pid_t tpid, uint64_t addr) {
    if (addr < 0x1000 || addr > 0x0000800000000000ull) return false;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)tpid);
    FILE* f = fopen(path, "re");
    if (!f) return false;
    char line[1024];
    bool hit = false;
    while (fgets(line, sizeof(line), f)) {
        unsigned long long a = 0, b = 0;
        char perm[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &a, &b, perm) != 3) continue;
        if (addr >= a && addr < b) { hit = (perm[2] == 'x'); break; }
        if (a > addr) break;
    }
    fclose(f);
    return hit;
}

// ═════════════════════════════════════════════════════════════════════════════
//  写入前的硬安全闸 —— 必须放在"改目标内存"之前
// ═════════════════════════════════════════════════════════════════════════════
//  【为什么必须有】实测 com.tencent.KiHan（Unity IL2CPP）被打崩两次：
//      signal 7 (SIGBUS), code 1 (BUS_ADRALN), fault addr 0x706d742f6c6163
//                                                              └─ ASCII "cal/tmp/"
//      x29 = "/data/lo"   lr = "cal/tmp/"   x25 = "zptp"
//    也就是说：目标执行了函数尾声（ldp x29,x30,[sp],#16 之类），把我们写进去的
//    ASCII 路径当成"保存的 x29/x30"弹了出来，ret 于是跳进字符串 → 崩。
//    根因是 /proc/<tid>/syscall 的 arg0 被当成可写缓冲，实际却落在栈帧保存
//    返回地址的位置 —— 一写就毁掉控制流。
//
//  【这道闸做什么】改写之前逐 8 字节扫描将要不覆盖的区域：
//    * 必须整块落在**可写**映射内（栈上的 timespec/路径缓冲满足；只读段不满足）
//    * 区域内**不得**出现"指向可执行映射的指针" —— 那正是返回地址/函数指针的特征
//  任一不满足就**放弃改写**，目标保持原样（失败但安全）。
static bool buffer_is_safe_to_clobber(pid_t tpid, int mem_fd, uint64_t addr, size_t len) {
    if (len == 0 || len > 64) { LOGW("安全闸: 长度异常 %zu", len); return false; }

    // ① 整块必须是可写映射
    if (!addr_writable(tpid, addr, len)) {
        LOGW("安全闸: [0x%llx, +%zu) 不在可写映射内 -> 放弃（未修改目标）",
             (unsigned long long)addr, len);
        return false;
    }

    // ② 区域里不能有指向可执行段的指针（返回地址/函数指针的特征）
    uint8_t orig[64];
    if (!pread_mem(mem_fd, addr, orig, len)) {
        LOGW("安全闸: 读不到目标内存 0x%llx -> 放弃", (unsigned long long)addr);
        return false;
    }
    int ptrs = 0;
    uint64_t first_ptr = 0;
    for (size_t i = 0; i + 8 <= len; i += 8) {
        uint64_t v = 0;
        memcpy(&v, orig + i, 8);
        if (addr_in_exec_mapping(tpid, v)) {
            ++ptrs;
            if (!first_ptr) first_ptr = v;
        }
    }
    if (ptrs > 0) {
        LOGW("安全闸: [0x%llx, +%zu) 内有 %d 个指向代码段的指针（首个 0x%llx）"
             " -> 这是栈帧控制数据，拒绝覆盖（未修改目标）",
             (unsigned long long)addr, len, ptrs, (unsigned long long)first_ptr);
        return false;
    }

    TLOG("安全闸通过: [0x%llx, +%zu) 可写且不含代码指针", (unsigned long long)addr, len);
    return true;
}

// 自动挑 hook 点。两条路线，按安全性排序：
//
//   路线 1  nanosleep(ts, NULL)
//           x0 = 栈上 timespec（可写）、x1 = NULL -> 正好是 dlopen 的 flags=0
//           而且目标每轮**自己重写**它 -> 我们写进去的路径会被它覆盖，
//           所以要持续重写抢那瞬间；好处是**目标天然自愈，风险最低**。
//
//   路线 2  open(path, O_RDONLY)
//           纯 Java App 根本不用 libc 的 nanosleep（ART 的 Thread.sleep 走 futex），
//           但**任何 App 都要开文件**，而 open 的 x1 = flags 恰好是 O_RDONLY = 0，
//           满足同样的条件。底层系统调用是 openat(AT_FDCWD, path, flags, ...)：
//             系统调用 arg0 == AT_FDCWD(-100)  -> 说明调用者是 open() 而不是 openat()
//             系统调用 arg1  = path  <- 对应 libc 的 x0（我们要改写的缓冲）
//             系统调用 arg2  = flags <- 对应 libc 的 x1（必须是 0）
//           注意 openat() 自身不能用：它的 x0 是 dirfd（整数），当路径指针会崩。
//           path 必须是**可写**缓冲（字符串常量在 .rodata 上，写不了）。
static bool pick_hook_site(pid_t tpid, HookSite* out, size_t need, bool allow_open) {
    const int kRounds = 120;                       // 每轮 25ms，约 3 秒
    // 逐级过滤计数：UI 只能看到 trace 文件，所以这些数字必须写进 TLOG，
    // 否则失败时我们只能看到"没扫到"，无法判断是卡在哪一层过滤上。
    long n_nano = 0, n_nano_ok = 0;
    long n_open = 0, n_open_cwd = 0, n_open_ro = 0, n_open_wr = 0;

    // allow_open=false 时**只跑路线1(nanosleep)**：
    // 路线2(open) 会让目标的 open(O_RDONLY) 变成 dlopen -> 文件打开真的失败
    // -> 目标读到空 fd/FILE* 会**闪退**。而 nanosleep 最坏只是睡眠提前返回，无害。
    // 两者破坏性不对等，所以 open 路线必须显式开启。
    for (int phase = 0; phase < (allow_open ? 2 : 1); ++phase) {
        for (int r = 0; r < kRounds; ++r) {
            char dpath[64];
            snprintf(dpath, sizeof(dpath), "/proc/%d/task", (int)tpid);
            DIR* d = opendir(dpath);
            if (!d) return false;
            struct dirent* e;
            bool found = false;
            while ((e = readdir(d))) {
                if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
                pid_t tid = (pid_t)atoi(e->d_name);
                SyscallInfo si = read_syscall(tid);
                if (!si.valid || si.fields < 9) continue;

                if (phase == 0) {
                    if (si.sysno != __NR_nanosleep) continue;
                    ++n_nano;
                    if (si.args[1] != 0) continue;              // rmtp 非 NULL
                    ++n_nano_ok;
                    uint64_t b = si.args[0];
                    if (b < 0x1000 || b > 0x0000800000000000ull) continue;
                    // 必须落在可写映射内 —— 否则说明这个 arg0 根本不是栈上的 timespec
                    if (!addr_writable(tpid, b, need)) continue;
                    out->tid = tid; out->buf = b;
                    out->sym = "nanosleep"; out->self_healing = true;
                    TLOG("选中 hook 点: tid=%d 正在 nanosleep，缓冲=0x%llx（自愈型，第 %d 轮）",
                         (int)tid, (unsigned long long)b, r + 1);
                    found = true;
                    break;
                } else {
                    if (si.sysno != __NR_openat) continue;
                    ++n_open;
                    if (si.args[0] != (uint64_t)(int64_t)-100) continue;   // 非 AT_FDCWD
                    ++n_open_cwd;
                    if (si.args[2] != 0) continue;                          // flags 非 O_RDONLY
                    ++n_open_ro;
                    uint64_t b = si.args[1];
                    if (b < 0x1000 || b > 0x0000800000000000ull) continue;
                    if (!addr_writable(tpid, b, need)) continue;            // 路径不可写
                    ++n_open_wr;
                    out->tid = tid; out->buf = b;
                    out->sym = "open"; out->self_healing = false;
                    TLOG("选中 hook 点: tid=%d 正在 open(O_RDONLY)，路径缓冲=0x%llx 可写（第 %d 轮）",
                         (int)tid, (unsigned long long)b, r + 1);
                    found = true;
                    break;
                }
            }
            closedir(d);
            if (found) return true;
            usleep(25000);
        }
        if (phase == 0) {
            TLOG("路线1(nanosleep) 3 秒统计: 见到 nanosleep 线程 %ld 个，其中 rmtp==NULL %ld 个",
                 n_nano, n_nano_ok);
            TLOG("改试路线2(open O_RDONLY)…");
        }
    }
    TLOG("路线2(open) 3 秒统计: openat %ld 个 -> AT_FDCWD %ld -> flags==0(O_RDONLY) %ld -> 路径可写 %ld",
         n_open, n_open_cwd, n_open_ro, n_open_wr);
    TLOG("两条路线都没扫到可用 hook 点 —— 该目标暂不支持（请把上面这行发我）");
    return false;
}

static int run_dataonly(pid_t tpid, pid_t ttid, uint64_t so_apk_off, uint64_t libc_sym_off,
                        const char* short_path, bool allow_open,
                        const char* key_file, uint32_t client_uid) {
    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/mem", (int)tpid);
    int mem_fd = open(mpath, O_RDWR);
    if (mem_fd < 0) { LOGE("打开 %s 失败 errno=%d", mpath, errno); return 1; }
    TLOG("=== data-only 模式: 路径 = %s ===", short_path);
    // 上一次失败/崩溃可能留下交接文件：先清干净，避免 agent 读到过期密钥。
    zpt_handoff_cleanup();
    TLOG("认证材料: %s", (key_file && key_file[0]) ? "已提供 --key-file（走文件交接启动 agent）"
                                                 : "未提供 --key-file（agent 无法监听）");

    // 【写多少字节 —— 这里是 KiHan 崩溃的根因】
    // 之前是 `(strlen + 1 + 7) & ~7`，即**按 8 字节对齐并补零**：
    //   "/data/local/tmp/zptp" (20) -> 对齐成 24 字节
    // 而 nanosleep 的 timespec **只有 16 字节** —— 多写的 8 字节正好压到栈帧里
    // 保存的 x29/x30。函数返回时 `ldp x29,x30,[sp],#16` 把我们的 ASCII 弹进
    // lr/pc，`ret` 跳进字符串 -> 崩。塔机现场（三次同签名）：
    //   signal 7 (SIGBUS)   lr = ASCII "cal/tmp/"   pc = ASCII "cal/tmp/\0"
    //   lr 恰好是路径的第 8~15 字节 —— 与该机制完全吻合。
    // 现在：长度 = strlen + 1，**不做任何对齐补零**（11 字节就只写 11 字节）。
    const size_t wlen = strlen(short_path) + 1;
    if (wlen > 63) {
        LOGE("路径太长（%zu 字节），拒绝执行", wlen);
        close(mem_fd);
        return 2;
    }

    // ── ① 先挑 hook 点（决定用哪个符号、改哪块缓冲）──
    HookSite site;
    site.tid = 0; site.buf = 0; site.sym = nullptr; site.self_healing = false;
    if (ttid != 0) {
        site.tid = ttid; site.sym = "nanosleep"; site.self_healing = true;
        SyscallInfo si = read_syscall(ttid);
        if (!si.valid || si.sysno != __NR_nanosleep) {
            LOGE("指定线程 tid=%d 不在 nanosleep（sysno=%ld）", (int)ttid, si.sysno);
            close(mem_fd);
            return 2;
        }
        site.buf = si.args[0];
    } else {
        if (!pick_hook_site(tpid, &site, wlen, allow_open)) { close(mem_fd); return 2; }
    }
    TLOG("hook 点: tid=%d 缓冲=0x%llx 符号=%s %s", (int)site.tid,
         (unsigned long long)site.buf, site.sym,
         site.self_healing ? "（目标自愈型）" : "（需我们还原）");

    // ── 缓冲容量硬校验 ──
    // nanosleep 的缓冲就是 timespec，**只有 16 字节**。路径（含 NUL）超过它就一定越界，
    // 会压到栈帧保存的寄存器上 —— 宁可拒绝，也绝不越界写。
    if (site.self_healing && wlen > 16) {
        LOGE("安全闸: nanosleep 的 timespec 只有 16 字节，当前路径 %zu 字节会越界 —— 拒绝（未修改目标）", wlen);
        TLOG("=== data-only 结果: 【放弃】路径超过了 16 字节的 timespec，拒绝越界写入 ===");
        close(mem_fd);
        return 8;
    }
    TLOG("写入长度 = %zu 字节（%s）", wlen,
         site.self_healing ? "timespec 16 字节之内，不会碰到保存的寄存器" : "按实际路径长度");

    // ── 【硬闸】self_healing 路线：那 16 字节**必须是一个合法 timespec** ──
    //
    // 为什么这是硬性不变量：线程此刻正卡在 nanosleep 系统调用里，
    // 内核读的就是它 x0 指向的 timespec —— 那块内存**必然**是 {tv_sec, tv_nsec}
    // 且 tv_nsec < 1e9。若不成立，说明 si.args[0] 根本不是它声称的缓冲。
    //
    // 实测（com.tencent.KiHan 三次崩溃）：
    //   x29 = ASCII "/data/lo" / "/data/zp"（我们路径的前 8 字节）
    //   lr  = ASCII "cal/tmp/" / "tp"
    //   => 那个地址实际是**栈帧里保存 x29/x30 的位置**，
    //      我们一写就把返回地址换成路径 ASCII，ret 跳进字符串里崩掉。
    // 有了这道闸，这种地址会在写入前被识别并拒绝（目标保持原样）。
    if (site.self_healing) {
        uint8_t ts[16];
        if (!pread_mem(mem_fd, site.buf, ts, sizeof(ts))) {
            LOGE("安全闸: 读不到 0x%llx 处的 16 字节 —— 拒绝", (unsigned long long)site.buf);
            TLOG("=== data-only 结果: 【放弃】读不到目标缓冲 ===");
            close(mem_fd);
            return 8;
        }
        uint64_t sec = 0, nsec = 0;
        memcpy(&sec, ts, 8);
        memcpy(&nsec, ts + 8, 8);
        TLOG("缓冲原内容: sec=%llu nsec=%llu", (unsigned long long)sec, (unsigned long long)nsec);

        // 【位置硬校验】nanosleep 的 timespec 一定在**当前线程栈帧里**，
        // 与 /proc/<tid>/syscall 给出的 sp 相距不会太远。
        // 实测 com.tencent.KiHan 连续 4 次崩溃（tombstone_04，19:28）：
        //   x29 = ASCII "/data/zp"、lr/pc 低字节 "tp"
        //   => 写进去的地址其实是**栈帧保存 x29/x30 的位置**，一写就把返回地址
        //      换成了路径 ASCII，ret 跳进字符串 -> SIGSEGV (SEGV_ACCERR)。
        // 光看"像不像 timespec"会被栈上碰巧像 timespec 的字节骗过，所以再加这条距离校验。
        SyscallInfo si2 = read_syscall(site.tid);
        uint64_t sp = si2.valid ? si2.sp : 0;
        int64_t dist = (int64_t)((site.buf > sp) ? (site.buf - sp) : (sp - site.buf));
        TLOG("缓冲=0x%llx sp=0x%llx 距离=%lld", (unsigned long long)site.buf,
             (unsigned long long)sp, (long long)dist);
        LOGI("ZPTDIAG tid=%d buf=0x%llx sp=0x%llx dist=%lld sec=%llu nsec=%llu",
             (int)site.tid, (unsigned long long)site.buf, (unsigned long long)sp,
             (long long)dist, (unsigned long long)sec, (unsigned long long)nsec);
        log_raw_syscall(site.tid);

        if (si2.valid && dist > 8192) {
            LOGE("安全闸: 缓冲 0x%llx 距离线程 sp 有 %lld 字节，不是当前帧里的 timespec"
                 " —— 拒绝（未修改目标）", (unsigned long long)site.buf, (long long)dist);
            TLOG("=== data-only 结果: 【放弃】地址离 sp 太远，拒绝写入 ===");
            close(mem_fd);
            return 8;
        }
        // 【最危险的一类：贴着 sp 写】实测 com.tencent.KiHan（tombstone_04, 19:28）：
        //   arg0 == sp（距离 0），write 之后该线程 x29/x30 变成我们路径的 ASCII，
        //   pc 跳到 0x6d50007074（"[anon:stack_and_tls:31611]" 里）——
        //   "Cause: trying to execute non-executable memory"，直接 SIGSEGV。
        // 结论：栈帧最底部那 16~32 字节**不能碰** —— 那里常常同时是保存 x29/x30 的位置，
        // 而我们无法从外部可靠区分"timespec"与"保存的寄存器"（19:28 那次三道闸全放行了）。
        // 靶场的 timespec 在 sp+0x38（距离 56），一直安全；这条阈值把它放行、把 KiHan 挡住。
        if (si2.valid && dist < 32) {
            LOGE("安全闸: 缓冲 0x%llx 距 sp 只有 %lld 字节（贴着栈帧底部），"
                 "此处置可能是保存的 x29/x30，拒绝写入（未修改目标）",
                 (unsigned long long)site.buf, (long long)dist);
            TLOG("=== data-only 结果: 【放弃】写入点贴着 sp，拒绝（安全优先） ===");
            close(mem_fd);
            return 8;
        }

        const bool looks_like_timespec = (nsec < 1000000000ull) && (sec < 86400ull);
        if (!looks_like_timespec) {
            LOGE("安全闸: 0x%llx 处不像 timespec（sec=%llu nsec=%llu），"
                 "说明它不是 nanosleep 的参数缓冲 —— 拒绝（未修改目标）",
                 (unsigned long long)site.buf, (unsigned long long)sec, (unsigned long long)nsec);
            TLOG("=== data-only 结果: 【放弃】缓冲不是合法 timespec，拒绝写入 ===");
            close(mem_fd);
            return 8;
        }
        TLOG("安全闸通过: 缓冲确实是合法 timespec（sec=%llu nsec=%llu）",
             (unsigned long long)sec, (unsigned long long)nsec);
        // 定位诊断：这个线程在 nanosleep 里的返回地址落在哪个库
        log_pc_owner(tpid, site.tid);
    }

    // ── ② 运行时解析该符号在 libc 里的偏移（不依赖 ROM 硬编码）──
    if (libc_sym_off == 0) {
        libc_sym_off = elf_lookup_dynsym("/apex/com.android.runtime/lib64/bionic/libc.so",
                                         site.sym, nullptr);
        if (libc_sym_off == 0) { LOGE("运行时解析 libc 的 %s 失败", site.sym); close(mem_fd); return 2; }
    }
    uint64_t libc_base = find_so_base_by_name(tpid, "libc.so");
    if (libc_base == 0) { LOGE("找不到 libc"); close(mem_fd); return 2; }
    uint64_t want = libc_base + libc_sym_off;

    // ── ③ 候选 GOT 槽 ──
    uint64_t cand[32];
    int ncand = 0;
    if (so_apk_off == 0) {
        ncand = find_got_slots_anywhere(tpid, mem_fd, want, cand, 32);
    } else {
        uint64_t so_base = find_so_base_by_apkoff(tpid, so_apk_off);
        if (so_base == 0) { LOGE("找不到 so 基址"); close(mem_fd); return 2; }
        uint64_t g = find_got_slot_for_ptr(tpid, mem_fd, so_base, want);
        if (g) cand[ncand++] = g;
    }
    if (ncand == 0) { LOGE("找不到 GOT 槽（没有库导入该符号）"); close(mem_fd); return 2; }

    //
    // 【上一版错在哪】
    // 之前用「syscall 的 pc 反查调用者库」来排序，pc 落在 libc.so，
    // 于是把 **libc 自己的 nanosleep GOT 槽排到了第一位**。这是两重错误：
    //   1) pc 是 syscall 的返回地址，必然在 libc 内部的 nanosleep 包装里，
    //      它**不能**代表"谁调用了 nanosleep"；
    //   2) 改 libc 自己的 GOT，会让 **libc 内部（含 bionic 装载器）的 nanosleep
    //      调用也变成 dlopen** —— 装载器在 dlopen 期间自锁/递归，
    //      表现就是"调用了但什么都没发生"，与实测现象一致。
    //
    // 【正确判据】靶位心跳线程在 libanticheat_detector.so 里，它对 nanosleep 的调用
    // 只可能走**该库自己的 PLT/GOT 槽**。已用 ELF 解析证实：该库 .rela.plt 里
    // nanosleep 的 r_offset = **0x73220**（与交接文档记录一致）。所以：
    //   * 用 APK 内偏移（默认 0x414000）定位该库在 maps 里的加载范围；
    //   * 只保留落在该范围内的候选槽；
    //   * 打出"槽相对库基址的偏移"，与 ELF 算出的 0x73220 对照（强证据）。
    // 范围内一个都没有时，退回全库逐个尝试，并明确告警。
    {
        const uint64_t kTargetSoApkOff = (so_apk_off != 0) ? so_apk_off : 0x414000ull;
        uint64_t tso_start = 0, tso_end = 0;
        bool have_target =
            find_map_by_file_off(tpid, nullptr, kTargetSoApkOff, &tso_start, &tso_end);
        if (have_target) {
            char target_path[512] = {0};
            maps_lookup_name(tpid, tso_start, target_path, sizeof(target_path));
            uint64_t filtered[32];
            int nf = 0;
            for (int i = 0; i < ncand; ++i)
                if (cand[i] >= tso_start && cand[i] < tso_end) filtered[nf++] = cand[i];
            TLOG("目标库: %s  映射 0x%llx-0x%llx（按 APK 内偏移 0x%llx 定位）",
                 target_path, (unsigned long long)tso_start, (unsigned long long)tso_end,
                 (unsigned long long)kTargetSoApkOff);
            if (nf > 0) {
                for (int i = 0; i < nf; ++i)
                    TLOG("  目标库内的槽 #%d = 0x%llx（相对库基址 +0x%llx）",
                         i + 1, (unsigned long long)filtered[i],
                         (unsigned long long)(filtered[i] - tso_start));
                TLOG("  期望偏移（ELF .rela.plt 算出）= 0x73220；不一致=选错段");
                for (int i = 0; i < nf; ++i) cand[i] = filtered[i];
                ncand = nf;
            } else {
                TLOG("!! 目标库范围内没有候选槽 —— 可能该库不经 GOT 调 nanosleep，"
                     "或 APK 内偏移猜错（当前 0x%llx）。退回全库尝试（有风险）",
                     (unsigned long long)kTargetSoApkOff);
            }
        } else {
            TLOG("!! 未找到 APK 内偏移 0x%llx 对应的映射 —— 无法限定目标库，退回全库尝试",
                 (unsigned long long)kTargetSoApkOff);
        }
    }

    // ── ④ dlopen 地址（libdl 里的转发桩，它自己用 mov x2,x30 取 caller_addr）──
    uint64_t libdl_base = find_so_base_by_name(tpid, "libdl.so");
    if (libdl_base == 0) { LOGE("找不到 libdl.so 基址"); close(mem_fd); return 2; }
    uint64_t DLOPEN_OFF = 0x401c;
    {
        uint64_t v = elf_lookup_dynsym("/apex/com.android.runtime/lib64/bionic/libdl.so",
                                       "dlopen", nullptr);
        if (v) DLOPEN_OFF = v;
    }
    uint64_t dlopen_addr = libdl_base + DLOPEN_OFF;
    TLOG("被 hook 函数=0x%llx  候选 GOT 槽 %d 个  dlopen=0x%llx",
         (unsigned long long)want, ncand, (unsigned long long)dlopen_addr);

    uint64_t buf = site.buf;
    TLOG("缓冲 = 0x%llx（将写入 %zu 字节路径）", (unsigned long long)buf, wlen);
    uint8_t buf_orig[64];
    bool buf_saved = pread_mem(mem_fd, buf, buf_orig, wlen);

    // ── ⑤ 写路径 ──
    // 自愈型（nanosleep 的 timespec）必须**持续重写**：目标每次调用前都会重写它。
    // open 型的缓冲目标不会重写，写一次即可 —— 持续重写反而会一直弄坏它的路径。
    char writebuf[64];
    memset(writebuf, 0, sizeof(writebuf));
    snprintf(writebuf, sizeof(writebuf), "%s", short_path);
    // ── 硬安全闸：不通过就**不写**，宁可注入失败也不能把目标搞崩 ──
    if (!buffer_is_safe_to_clobber(tpid, mem_fd, buf, wlen)) {
        LOGE("安全闸拦截：缓冲 0x%llx 不适合覆盖，已放弃（目标未被修改）",
             (unsigned long long)buf);
        TLOG("=== data-only 结果: 【放弃】安全闸拦截，未修改目标 ===");
        close(mem_fd);
        return 8;                       // 8 = 安全闸拒绝（与其它失败码区分）
    }
    if (!pwrite_mem(mem_fd, buf, writebuf, wlen)) {
        LOGE("写路径到 0x%llx 失败 errno=%d", (unsigned long long)buf, errno);
        TLOG("=== zpt 最终结果: 【失败】写不进目标路径缓冲（errno=%d），未触发 dlopen ===", errno);
        close(mem_fd);
        return 3;
    }
    std::atomic<bool> keep_writing{false};
    std::thread writer;
    if (site.self_healing) {
        keep_writing.store(true);
        writer = std::thread([&] {
            while (keep_writing.load()) {
                pwrite_mem(mem_fd, buf, writebuf, wlen);
                usleep(50);
            }
        });
    }

    // ── ⑤.5 认证材料交接（必须在触发 dlopen 之前写好）──
    // agent 的构造函数在 dlopen 期间执行、且只读一次交接文件，所以时间点要卡在
    // 这里（紧贴 GOT 劫持之前，把密钥落盘窗口压到最短）。
    // 写不成功就**不触发 dlopen**（否则就是重演"加载成功但连不上"的旧误报）。
    char hoff_err[192] = {0};
    if (!zpt_handoff_write(tpid, key_file, client_uid, hoff_err, sizeof(hoff_err))) {
        LOGE("认证交接失败：%s", hoff_err);
        TLOG("=== zpt 最终结果: 【失败】认证交接失败：%s ===", hoff_err);
        zpt_handoff_cleanup();
        // ⑤ 已经改过目标路径缓冲，这里尽力还原；不触发 dlopen。
        if (buf_saved && pwrite_mem(mem_fd, buf, buf_orig, wlen))
            TLOG("已还原目标路径缓冲（未触发 dlopen）");
        close(mem_fd);
        return 9;                       // 9 = 交接失败（未触发 dlopen）
    }

    // ── ⑥ 纯数据攻击：**逐个**候选槽尝试，每个只占用 400ms，立刻还原 ──
    //
    // 【为什么不再"全部槽一起劫持 + 等 8 秒"】那样一旦不成功，目标在长达 8 秒里
    // 所有经过这些槽的调用都会被打到 dlopen：
    //   nanosleep 路线 -> 它的睡眠全变成 dlopen
    //   open 路线      -> **它的文件打开全部失败**（返回 NULL）
    //   => 目标读到空 fd/FILE* 直接**闪退**（实测 com.tencent.KiHan / com.max.xiaoheihe）
    // 改成逐个尝试：单个槽最多被占用 400ms，破坏面小一个数量级；
    // 命中即停（dlopen 成功通常 <100ms 就会看到多段映射）。
    const char* base = strrchr(short_path, '/');
    base = base ? base + 1 : short_path;
    bool loaded = false;
    int peak = 0, tried = 0;
    for (int ci = 0; ci < ncand && !loaded; ++ci) {
        uint64_t old = 0;
        if (!pread_mem(mem_fd, cand[ci], &old, 8)) continue;
        // 【诊断】旧值不匹配时原来是静默 continue —— 文档第七节缺陷 1：
        // trace 里只看到"共尝试 N 个"，看不出为什么只试了 1 个。
        if (old != want) {
            TLOG("候选槽 #%d = 0x%llx：旧值 0x%llx != 期望 0x%llx —— 跳过（该槽不是原值）",
                 ci + 1, (unsigned long long)cand[ci],
                 (unsigned long long)old, (unsigned long long)want);
            continue;
        }
        if (!pwrite_mem(mem_fd, cand[ci], &dlopen_addr, 8)) {
            TLOG("候选槽 #%d = 0x%llx：写入 dlopen 地址失败 errno=%d",
                 ci + 1, (unsigned long long)cand[ci], errno);
            continue;
        }
        ++tried;
        // 光有 pwrite 返回成功不够 —— 必须回读一致才能证明目标会读到新值。
        uint64_t rb = 0;
        bool hijack_ok = pread_mem(mem_fd, cand[ci], &rb, 8) && rb == dlopen_addr;
        TLOG("候选槽 #%d 已改写 -> dlopen=0x%llx，回读=0x%llx（%s）",
             ci + 1, (unsigned long long)dlopen_addr, (unsigned long long)rb,
             hijack_ok ? "改写生效" : "!! 回读不一致");
        int p = 0, calls = 0;
        // 窗口 400ms（原 1500ms）：被 hook 的调用点周期是 200ms（nanosleep 200ms），
        // 400ms 足以覆盖 ≥1 次调用；候选槽放大到 32 之后必须缩短窗口，
        for (int i = 0; i < 400; ++i) {
            int c = count_maps_entries(tpid, base);
            if (c > p) p = c;
            if (c > 0) ++calls;                          // 采样到"有映射"的次数
            if (c >= 2) { loaded = true; break; }        // >=2 条映射 = 真加载
            usleep(1000);
        }
        if (p > peak) peak = p;
        uint64_t cur = 0;                                // 不管成败都立刻还原这个槽
        bool changed = pread_mem(mem_fd, cand[ci], &cur, 8) && cur != want;
        if (changed) pwrite_mem(mem_fd, cand[ci], &want, 8);
        TLOG("候选槽 #%d = 0x%llx：400ms 窗口内峰值映射条数=%d（采到映射的次数=%d，"
             "期间槽值%s）%s",
             ci + 1, (unsigned long long)cand[ci], p, calls,
             changed ? "仍为我们的值" : "已被改回", loaded ? "  ← 命中" : "");
        if (!loaded) usleep(20000);
    }
    TLOG("共尝试 %d 个候选槽（每个 400ms），%s 的峰值映射条数 = %d（1=仅 ELF 头探测, >=2=真加载）",
         tried, base, peak);

    keep_writing.store(false);
    if (writer.joinable()) writer.join();

    // 但 data-only 只负责"让目标 dlopen"，不会调用 AgentStartWithAuth，
    // 于是 App 显示注入成功、agent_status 却是"未连接"。
    // 现在：so 加载成功只是"中间结果"，必须等到 agent 自己写出就绪标记，
    // 才能打印唯一的【成功】；否则一律【失败】+ 原因。
    TLOG("=== data-only 中间结果: so %s目标 maps ===",
         loaded ? "已出现在" : "未出现在");
    // 就绪标记是"agent 真的执行了构造函数并开始监听"的直接证据，比 maps 计数更硬：
    // 所以**无论** maps 计数如何都等它（maps 计数只是诊断信息，可能因映射合并少算）。
    TLOG("等待 agent 就绪标记 %s（最多 2000ms，间隔 50ms）…", ZPT_AUTH_READY);
    const bool agent_ready = zpt_handoff_wait_ready(2000, 50);
    TLOG("agent 就绪标记: %s", agent_ready ? "已看到（socket 已监听）"
                                           : "未看到（2s 超时）");

    // ── ⑦ 收尾：兜底把所有候选槽还原（正常情况下上面已逐个还原过）──
    int restored = 0;
    for (int ci = 0; ci < ncand; ++ci) {
        uint64_t cur = 0;
        if (!pread_mem(mem_fd, cand[ci], &cur, 8)) continue;
        if (cur == want) continue;
        if (pwrite_mem(mem_fd, cand[ci], &want, 8)) ++restored;
    }
    TLOG("已还原 %d 个 GOT 槽", restored);
    if (buf_saved && pwrite_mem(mem_fd, buf, buf_orig, wlen))
        TLOG("被覆盖的 %zu 字节缓冲已还原", wlen);

    // ── ⑧ 最终结论：**只有 agent 真的监听**才算成功 ──
    // ok 只看就绪标记：它意味着目标确实 dlopen 了我们的 so、agent 构造函数执行、
    // AgentStartWithAuth 成功、监听线程已起。maps 计数仅作诊断（可能因映射合并少算）。
    const bool ok = agent_ready;
    if (ok) {
        TLOG("=== zpt 最终结果: 【成功】agent socket 已启动（data-only，全程无 ptrace） ===");
    } else if (!loaded) {
        TLOG("=== zpt 最终结果: 【失败】dlopen 未被触发：so 未出现在目标 maps"
             "（目标可能没有可用的 nanosleep 调用点，或候选 GOT 槽全不匹配） ===");
    } else {
        TLOG("=== zpt 最终结果: 【失败】agent 未启动：so 已加载，但未见就绪标记。可能原因："
             "① AgentStartWithAuth 失败（auth 交接文件没被目标读到 / magic/version 不符 / "
             "SELinux 非 Permissive）；② agent 是旧版本（没有交接逻辑）；③ 目标此前已注入过 "
             "agent —— dlopen 同一路径不会重跑构造函数，请重启目标进程后再注入。"
             "（本次 GOT 槽与路径缓冲均已还原） ===");
    }
    // 收尾：auth 文件再清零 + 删除两个交接文件（成功时 agent 已自己清过一次）。
    zpt_handoff_cleanup();
    close(mem_fd);
    return ok ? 0 : 7;
}

// ── stub 自检（run_verify_stub）用的两个全局 ──
// 它们在源码被误删的那一段里（连同 run_self 一起），这里按用途补回：
//   g_stub_test_calls  —— landing 的 C 函数每次被调用就自增，用来证明桩回跳成功
//   g_stub_test_mailbox—— payload 的收尾会把返回值写进来，用来校验寄存器是否被正确恢复
static volatile int      g_stub_test_calls = 0;
static volatile uint64_t g_stub_test_mailbox = 0;

static void stub_test_landing(void) {
    // 桩的「pc+4」会落在这里：一个空函数，什么也不做
    g_stub_test_calls++;
}

static int run_verify_stub() {
    void* page = mmap(NULL, 65536, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) { LOGE("verify-stub: mmap RWX 失败 errno=%d", errno); return 1; }
    uint8_t* base = (uint8_t*)page;

    // 布局（全部在同一页内，避免 `b` 的 ±128MB 限制）：
    //   page+8     : `b` -> landing（桩的 pc+4 落点；桩自己放在 page+16，永远执行不到这）
    //   page+3024  : landing —— 保存 lr、调用 C 函数记账、返回
    //
    // 【坑】桩的回跳目标是 pc+4。这里必须让 pc+4 正好落在 ret_slot 上，
    // 所以 pc = ret_slot-4。头一次我把 landing 放在 pc+12，桩跳到了没写过的
    // 全零内存上 → SIGILL/未定义指令。这类偏移错误只能靠"对齐打印+真机跑"抓。
    uint8_t*  buf = base + CODE_OFF;
    uint64_t  ret_slot = (uint64_t)base + 8;
    uint64_t  landing  = (uint64_t)base + 3024;
    size_t    len = build_payload_phase1(buf, (uint64_t)buf, ret_slot - 4, (uint64_t)&g_stub_test_mailbox);
    if (len == 0) { munmap(page, 65536); return 1; }

    uint32_t jb = 0;
    if (!encode_b(ret_slot, landing, &jb)) {
        LOGE("verify-stub: ret_slot -> landing 的 b 编码失败");
        munmap(page, 65536);
        return 1;
    }
    memcpy((void*)ret_slot, &jb, 4);

    // landing: stp x29,x30,[sp,#-16]! ; blr x16 ; ldp x29,x30,[sp],#16 ; ret
    uint32_t* land = (uint32_t*)landing;
    int ln = 0;
    land[ln++] = 0xA9BF7BFDu;                        // stp x29, x30, [sp, #-16]!
    {
        uint32_t tmp[8];
        int k = load_imm64(tmp, 16, (uint64_t)&stub_test_landing);
        for (int i = 0; i < k; ++i) land[ln++] = tmp[i];
    }
    land[ln++] = 0xD63F0200u;                        // blr x16
    land[ln++] = 0xA8C17BFDu;                        // ldp x29, x30, [sp], #16
    land[ln++] = 0xD65F03C0u;                        // ret

    LOGI("verify-stub: 桩 %zu 字节 @%p, ret_slot=0x%llx landing=0x%llx",
         len, buf, (unsigned long long)ret_slot, (unsigned long long)landing);
    __builtin___clear_cache((char*)page, (char*)page + 65536);

    void (*fn)(void) = (void (*)(void))buf;
    fn();
    LOGI("verify-stub: 调用返回，landing 次数=%d mailbox=0x%llx",
         g_stub_test_calls, (unsigned long long)g_stub_test_mailbox);
    munmap(page, 65536);

    bool ok = (g_stub_test_calls == 1) && g_stub_test_mailbox != 0 &&
              g_stub_test_mailbox != (uint64_t)-1;
    LOGI("=== phase-1 桩自证: %s ===", ok ? "【成功】桩能 mmap 并正确回跳" : "【失败】");
    return ok ? 0 : 4;
}

// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char** argv) {
    LOGI("=== zeroptrace_injector（零 ptrace 热注入 PoC）build=%s ===", ZPT_BUILD_TAG);
    if (argc >= 2 && strcmp(argv[1], "--self") == 0) {
        LOGE("--self 模式已在源码修复中移除（产品路径走 --auto，不需要它）");
        return 1;
    }
    //   --key-file <44B 密钥文件>   --client-uid <GUI uid>
    // 由 App 侧（native-lib.cpp RunZeroPtraceInject）传入，与常规注入共用同一份
    // <filesDir>/channel_key.bin。在任意位置扫描，不影响原有位置参数。
    const char* key_file = nullptr;
    uint32_t    client_uid = 0;
    for (int i = 1; i + 1 < argc; ++i) {
        if (strcmp(argv[i], "--key-file") == 0) {
            key_file = argv[++i];
        } else if (strcmp(argv[i], "--client-uid") == 0) {
            client_uid = (uint32_t)strtoul(argv[++i], nullptr, 10);
        }
    }
    if (argc >= 4 && strcmp(argv[1], "--resolve") == 0) {
        // 自检：运行时解析某个 ELF 里的符号偏移
        uint64_t sz = 0;
        uint64_t v = elf_lookup_dynsym(argv[2], argv[3], &sz);
        printf("%s @ %s = 0x%llx (size=%llu)\n", argv[3], argv[2],
               (unsigned long long)v, (unsigned long long)sz);
        return v ? 0 : 1;
    }
    if (argc >= 4 && strcmp(argv[1], "--auto") == 0) {
        // 一键模式：偏移全部运行时解析、GOT 槽自动定位、hook 点自动挑选
        //   --auto <pid> <agent.so 路径> [open] [--key-file <p> --client-uid <u>]
        // 默认**只用 nanosleep 路线**（安全：睡眠提前返回无害）。
        // 只有第 4 个位置参数显式写 "open" 才启用 open 路线 —— 那会让目标的
        // open(O_RDONLY) 暂时变成 dlopen、**文件打开真的失败，可能闪退**。
        // 注意：--key-file/--client-uid 必须放在位置参数之后（这样 argv[4] 判定不受影响）。
        const bool allow_open = (argc >= 5 && strcmp(argv[4], "open") == 0);
        return run_dataonly((pid_t)atoi(argv[2]), 0, 0, 0, argv[3], allow_open,
                            key_file, client_uid);
    }
    if (argc >= 7 && strcmp(argv[1], "--dataonly") == 0) {
        // --dataonly <pid> <tid> <so的APK偏移> <被hook函数在libc里的偏移> <短路径>
        return run_dataonly((pid_t)atoi(argv[2]), (pid_t)atoi(argv[3]),
                            strtoull(argv[4], nullptr, 0), strtoull(argv[5], nullptr, 0),
                            argv[6], false, key_file, client_uid);
    }
    if (argc >= 8 && strcmp(argv[1], "--dlopen") == 0) {
        // --dlopen <pid> <so的APK偏移> <被hook函数在libc里的偏移> <linker里__loader_dlopen偏移> <mailbox> <so路径>
        return run_dlopen((pid_t)atoi(argv[2]), strtoull(argv[3], nullptr, 0),
                          strtoull(argv[4], nullptr, 0), strtoull(argv[5], nullptr, 0),
                          strtoull(argv[6], nullptr, 0), argv[7]);
    }
    if (argc >= 5 && strcmp(argv[1], "--got") == 0) {
        // --got <pid> <so在APK内的数据偏移> <GOT偏移> <mailbox>
        return run_got((pid_t)atoi(argv[2]), strtoull(argv[3], nullptr, 0),
                       strtoull(argv[4], nullptr, 0), strtoull(argv[5], nullptr, 0));
    }
    if (argc >= 2 && strcmp(argv[1], "--verify-stub") == 0) {
        return run_verify_stub();
    }
    if (argc >= 3 && strcmp(argv[1], "--dump-payload") == 0) {
        // 宿主机上核对机器码用：把固定输入的 payload 字节写到文件
        static uint8_t pool[65536];
        uint8_t* buf = pool + 16;
        uint64_t mailbox = strtoull(argv[2], nullptr, 0);
        // pc 紧贴 payload 自己，否则回跳会超出 ±128MB（这里是「编码器核对」用途，
        // 真实注入时 pc 由 /proc/tid/syscall 给出，一定在附近）
        uint64_t pc      = (uint64_t)buf + 4;
        const char* out  = (argc >= 5) ? argv[4] : "/data/local/tmp/payload.bin";
        size_t code_len = 0;
        uint64_t back = 0;
        build_payload_a(buf, (uint64_t)buf, mailbox, 0, pc, pc + 4, &code_len, &back);
        if (code_len == 0) { LOGE("dump-payload: 构造失败"); return 1; }
        // 关键：dump **完整 payload**（数据区 + 守卫 + 代码），而不仅代码。
        // 只 dump 代码会看不出「守卫有没有落进代码里」这个曾经踩死过的坑。
        const size_t total = CODE_OFF + code_len;
        FILE* f = fopen(out, "wb");
        if (!f) { LOGE("dump-payload: 打开 %s 失败 errno=%d", out, errno); return 1; }
        fwrite(buf, 1, total, f);
        fclose(f);
        LOGI("dump-payload: CODE_OFF=%d code_len=%zu total=%zu -> %s (mailbox=0x%llx pc=0x%llx)",
             CODE_OFF, code_len, total, out, (unsigned long long)mailbox, (unsigned long long)pc);
        {   // 数据区自检：magic 在 +0、mailbox 在 +8、守卫（+GUARD_OFF）必须为 0
            uint64_t magic = 0, mb = 0, guard = 0;
            memcpy(&magic, buf + 0, 8);
            memcpy(&mb, buf + 8, 8);
            memcpy(&guard, buf + GUARD_OFF, 8);
            LOGI("dump-payload 数据区: magic=0x%llx mailbox=0x%llx guard(+%d)=0x%llx %s",
                 (unsigned long long)magic, (unsigned long long)mb, GUARD_OFF,
                 (unsigned long long)guard, guard == 0 ? "OK" : "!! 守卫非 0");
        }
        return 0;
    }
    if (argc >= 3 && strcmp(argv[1], "--dump-stub") == 0) {
        // 把 phase-1 桩的机器码写到文件，交给 llvm-objdump 反汇编核对
        void* blk = mmap(NULL, 65536, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (blk == MAP_FAILED) { LOGE("dump-stub: mmap 失败 errno=%d", errno); return 1; }
        uint8_t* buf = (uint8_t*)blk + 16;
        size_t n = build_payload_phase1(buf, (uint64_t)buf, (uint64_t)buf - 4, strtoull(argv[2], nullptr, 0));
        if (n == 0) { LOGE("dump-stub: 构造失败"); return 1; }
        const char* out = (argc >= 4) ? argv[3] : "/data/local/tmp/stub.bin";
        FILE* f = fopen(out, "wb");
        if (!f) { LOGE("dump-stub: 打开 %s 失败 errno=%d", out, errno); return 1; }
        fwrite(buf, 1, n, f);
        fclose(f);
        LOGI("dump-stub: %zu 字节已写出到 %s (base=%p)", n, out, buf);
        for (size_t i = 0; i < n; i += 4) {
            uint32_t w = 0;
            memcpy(&w, buf + i, 4);
            LOGI("DUMP +%03zu  0x%08x", i, w);
        }
        return 0;
    }
    if (argc >= 4) {
        pid_t tpid = (pid_t)atoi(argv[1]);
        pid_t ttid = (pid_t)atoi(argv[2]);
        uint64_t mailbox = strtoull(argv[3], nullptr, 0);
        bool keep = (argc >= 5 && strcmp(argv[4], "--keep") == 0);
        return run_remote(tpid, ttid, mailbox, keep);
    }
    fprintf(stderr,
            "用法:\n"
            "  %s --auto <pid> <agent.so 短路径> [open] --key-file <44B> --client-uid <uid>\n"
            "         # 产品路径：data-only 注入，必须带认证交接参数（否则 agent 不会监听）\n"
            "  %s --dataonly <pid> <tid> <so_apk_off> <libc_off> <短路径>"
            " --key-file <44B> --client-uid <uid>\n"
            "  %s <target_pid> <target_tid> <mailbox_addr> [--keep]   # 旧跨进程挂钩实验，需 root\n"
            "  %s --dlopen/--got/--resolve/--verify-stub/--dump-payload/--dump-stub   # 实验/自检\n",
            argv[0], argv[0], argv[0], argv[0]);
    return 64;
}

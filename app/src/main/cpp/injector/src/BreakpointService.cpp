// 硬件断点 / 监视点服务。
//
// Linux perf_event_open 硬件
// 断点接口（PERF_TYPE_BREAKPOINT）的独立实现。内核编程 CPU
// 调试寄存器，每次命中记录 perf 样本，目标
// 进程永远不会被停止或 ptrace，除非设置了
// perf_event_attr 的 "sigtrap" 位（Linux >= 5.13）才会收到 SIGTRAP——我们从不
// 设置它。目标的新线程通过周期性重扫捕获。
//
// 这是从零编写的 C++ 实现；只使用有文档的
// perf_event_open ABI，不含任何 GPL 代码。

#include "BreakpointService.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <sstream>
#include <string>
#include <vector>

namespace {

// ---------------------------------------------------------------------------
// perf_event_open ABI 常量（公开的 uapi 事实，保留在本地
// 使本文件不依赖 NDK 内核头文件）。
// ---------------------------------------------------------------------------

#ifndef __NR_perf_event_open
#if defined(__aarch64__)
#define __NR_perf_event_open 241
#elif defined(__x86_64__)
#define __NR_perf_event_open 298
#endif
#endif

enum {
    kPerfTypeBreakpoint = 5,
    kHwBreakpointR      = 1,
    kHwBreakpointW      = 2,
    kHwBreakpointRW     = 3,
    kHwBreakpointX      = 4,
};

enum {
    kPerfSampleTid      = 1U << 1,
    kPerfSampleRegsUser = 1U << 12,
};

enum {
    kPerfRecordSample = 9,
    kPerfRecordLost   = 2,
};

constexpr uint64_t kPerfFlagFdCloexec = 1ULL << 3;

// perf_event_attr 的标志位域（位位置来自 man 手册）。
constexpr uint64_t kAttrExcludeKernel = 1ULL << 5;

// 我们只需要到 sample_regs_user 的字段，因此声明所有
// Android 内核都认识的大小（4.1+，到 __reserved_3 共 120 字节）。
// 避免在结构体早于 sig_data/config3（5.13+）的内核上出现 E2BIG。
constexpr uint32_t kPerfAttrSizeCompat = 120;

#if defined(__aarch64__)
// perf 寄存器编号：x0..x30、sp、pc -> 位 0..32。
constexpr uint64_t kSampleRegsMask = (1ULL << 33) - 1;
constexpr int      kPcRegIndex     = 32;
constexpr int      kSpRegIndex     = 31;
constexpr int      kFpRegIndex     = 29;  // x29 = 帧指针
constexpr int      kLrRegIndex     = 30;  // x30 = 链接寄存器
#elif defined(__x86_64__)
// perf 寄存器编号：ax..cx8、r8..r15、ip、flags -> 位 0..18。
constexpr uint64_t kSampleRegsMask = (1ULL << 19) - 1;
constexpr int      kPcRegIndex     = 8;
constexpr int      kSpRegIndex     = 7;
constexpr int      kFpRegIndex     = -1;
constexpr int      kLrRegIndex     = -1;
#else
constexpr uint64_t kSampleRegsMask = 0;
constexpr int      kPcRegIndex     = -1;
constexpr int      kSpRegIndex     = -1;
constexpr int      kFpRegIndex     = -1;
constexpr int      kLrRegIndex     = -1;
#endif

// struct perf_event_attr（到 sig_data 共 128 字节）。
struct PerfEventAttr {
    uint32_t type;
    uint32_t size;
    uint64_t config;
    union {
        uint64_t sample_period;
        uint64_t sample_freq;
    };
    uint64_t sample_type;
    uint64_t read_format;
    uint64_t flags;
    union {
        uint32_t wakeup_events;
        uint32_t wakeup_watermark;
    };
    uint32_t bp_type;
    union {
        uint64_t bp_addr;
        uint64_t config1;
    };
    union {
        uint64_t bp_len;
        uint64_t config2;
    };
    uint64_t branch_sample_type;
    uint64_t sample_regs_user;
    uint32_t sample_stack_user;
    int32_t  clockid;
    uint64_t sample_regs_intr;
    uint32_t aux_watermark;
    uint16_t sample_max_stack;
    uint16_t __reserved_2;
    uint32_t aux_sample_size;
    uint32_t __reserved_3;
    uint64_t sig_data;
};
static_assert(sizeof(PerfEventAttr) == 128, "perf_event_attr size");

// struct perf_event_mmap_page（环形缓冲区的控制页）。
struct PerfMmapPage {
    uint32_t version;
    uint32_t compat_version;
    uint32_t lock;
    uint32_t index;
    int64_t  offset;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t capabilities;
    uint16_t pmc_width;
    uint16_t time_shift;
    uint32_t time_mult;
    uint64_t time_offset;
    uint64_t time_zero;
    uint32_t size;
    uint32_t __reserved_1;
    uint64_t time_cycles;
    uint64_t time_mask;
    uint8_t  __reserved[116 * 8];
    uint64_t data_head;
    uint64_t data_tail;
    uint64_t data_offset;
    uint64_t data_size;
    uint64_t aux_head;
    uint64_t aux_tail;
    uint64_t aux_offset;
    uint64_t aux_size;
};

struct PerfRecordHeader {
    uint32_t type;
    uint16_t misc;
    uint16_t size;
};

// ---------------------------------------------------------------------------
// 服务状态
// ---------------------------------------------------------------------------

struct ActiveBp {
    uint64_t addr;
    int      type;
    int      len;
};

struct BpEvent {
    int       tid       = 0;
    int       fd        = -1;
    void*     map       = nullptr;
    size_t    map_len   = 0;
    uint64_t  data_off  = 0;
    uint64_t  data_size = 0;
    uint64_t  addr      = 0;
    int       type      = 0;
    int       len       = 0;
};

pid_t                 g_target = 0;
bool                  g_quit   = false;
std::vector<ActiveBp> g_active;
std::vector<BpEvent>  g_events;

const int kRegCount = [] {
    uint64_t v = kSampleRegsMask;
    int c = 0;
    while (v) { v &= v - 1; ++c; }
    return c;
}();

// ---------------------------------------------------------------------------
// 小工具函数
// ---------------------------------------------------------------------------

static const char* TypeName(int type) {
    switch (type) {
        case kHwBreakpointR:  return "r";
        case kHwBreakpointW:  return "w";
        case kHwBreakpointRW: return "rw";
        default:              return "x";
    }
}

static bool ParseHex(const std::string& s, uint64_t& out) {
    const char* p = s.c_str();
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    if (*p == '\0') return false;
    uint64_t v = 0;
    for (; *p; ++p) {
        int d;
        if (*p >= '0' && *p <= '9')      d = *p - '0';
        else if (*p >= 'a' && *p <= 'f') d = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') d = *p - 'A' + 10;
        else return false;
        v = (v << 4) | (uint64_t)d;
    }
    out = v;
    return true;
}

static int ParseType(const std::string& s) {
    if (s == "x")  return kHwBreakpointX;
    if (s == "r")  return kHwBreakpointR;
    if (s == "w")  return kHwBreakpointW;
    if (s == "rw") return kHwBreakpointRW;
    return -1;
}

static int ParseLen(const std::string& s) {
    int v = atoi(s.c_str());
    switch (v) {
        case 1: case 2: case 4: case 8: return v;
        default: return -1;
    }
}

static std::vector<std::string> SplitWords(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream ss(s);
    std::string w;
    while (ss >> w) out.push_back(w);
    return out;
}

static bool ProcessExists(pid_t pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    return access(path, F_OK) == 0;
}

static std::vector<pid_t> ListThreads(pid_t pid) {
    std::vector<pid_t> tids;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR* d = opendir(path);
    if (!d) return tids;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] == '.') continue;
        char* end = nullptr;
        long t = strtol(e->d_name, &end, 10);
        if (end && *end == '\0' && t > 0) tids.push_back((pid_t)t);
    }
    closedir(d);
    return tids;
}

static long PerfEventOpenSyscall(PerfEventAttr* attr, pid_t pid, int cpu,
                                 int group_fd, uint64_t flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

// ---------------------------------------------------------------------------
// 每线程 perf 事件管理
// ---------------------------------------------------------------------------

static int OpenBpEvent(pid_t tid, const ActiveBp& bp, BpEvent& out) {
    PerfEventAttr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type             = kPerfTypeBreakpoint;
    attr.size             = kPerfAttrSizeCompat;
    attr.sample_period    = 1;
    attr.sample_type      = kPerfSampleTid | kPerfSampleRegsUser;
    attr.flags            = kAttrExcludeKernel;   // 仅用户空间命中
    attr.wakeup_events    = 1;
    attr.bp_type          = (uint32_t)bp.type;
    attr.bp_addr          = bp.addr;
    attr.bp_len           = (uint64_t)bp.len;
    attr.sample_regs_user = kSampleRegsMask;

    long fd = PerfEventOpenSyscall(&attr, tid, -1, -1, kPerfFlagFdCloexec);
    if (fd < 0) return -1;

    long page_size = sysconf(_SC_PAGESIZE);
    // 1 个控制页 + 16 个数据页（2 的幂），热点断点
    // 不会在轮询间隔内溢出环形缓冲区。
    size_t map_len = (size_t)page_size * 17;
    void* m = mmap(nullptr, map_len, PROT_READ | PROT_WRITE, MAP_SHARED,
                   (int)fd, 0);
    if (m == MAP_FAILED) {
        close((int)fd);
        return -1;
    }

    PerfMmapPage* page = (PerfMmapPage*)m;
    if (page->data_offset != 0 && page->data_size != 0) {
        out.data_off  = page->data_offset;
        out.data_size = page->data_size;
    } else {
        out.data_off  = (uint64_t)page_size;
        out.data_size = map_len - (size_t)page_size;
    }
    if (out.data_size == 0) {
        munmap(m, map_len);
        close((int)fd);
        errno = EINVAL;
        return -1;
    }

    out.tid      = tid;
    out.fd       = (int)fd;
    out.map      = m;
    out.map_len  = map_len;
    out.addr     = bp.addr;
    out.type     = bp.type;
    out.len      = bp.len;
    return 0;
}

static void CloseEvent(BpEvent& ev) {
    if (ev.fd >= 0) close(ev.fd);
    if (ev.map) munmap(ev.map, ev.map_len);
    ev = BpEvent();
}

static int ClearBreakpoint(uint64_t addr) {
    int closed = 0;
    for (auto it = g_events.begin(); it != g_events.end();) {
        if (it->addr == addr) {
            CloseEvent(*it);
            it = g_events.erase(it);
            ++closed;
        } else {
            ++it;
        }
    }
    g_active.erase(std::remove_if(g_active.begin(), g_active.end(),
                                  [addr](const ActiveBp& b) {
                                      return b.addr == addr;
                                  }),
                   g_active.end());
    return closed;
}

static bool SetBreakpoint(uint64_t addr, int type, int len, std::string& err) {
    if (type == kHwBreakpointX) len = (int)sizeof(long);
    ClearBreakpoint(addr);

    ActiveBp bp{addr, type, len};
    std::vector<pid_t> tids = ListThreads(g_target);
    int ok = 0, fail = 0;
    for (pid_t t : tids) {
        BpEvent ev;
        if (OpenBpEvent(t, bp, ev) == 0) {
            g_events.push_back(ev);
            ++ok;
        } else {
            ++fail;
        }
    }
    if (ok == 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "set 0x%llx %s: perf_event_open failed: %s",
                 (unsigned long long)addr, TypeName(type), strerror(errno));
        err = buf;
        return false;
    }
    g_active.push_back(bp);
    printf("OK set 0x%llx %s len=%d threads=%d failed=%d\n",
           (unsigned long long)addr, TypeName(type), len, ok, fail);
    fflush(stdout);
    return true;
}

// ---------------------------------------------------------------------------
// 环形缓冲区解析
// ---------------------------------------------------------------------------

static void RingRead(const uint8_t* base, uint64_t size, uint64_t off,
                     void* dst, size_t n) {
    uint64_t idx = off % size;
    size_t first = (size_t)(size - idx);
    if (first > n) first = n;
    memcpy(dst, base + idx, first);
    if (first < n) memcpy((uint8_t*)dst + first, base, n - first);
}

static const char* RegName(int i) {
#if defined(__aarch64__)
    if (i == 29) return "fp";   // x29 = 帧指针
    if (i == 30) return "lr";   // x30 = 链接寄存器
    if (i >= 0 && i <= 30) {
        static char b[8];
        snprintf(b, sizeof(b), "x%d", i);
        return b;
    }
    if (i == 31) return "sp";
    if (i == 32) return "pc";
#elif defined(__x86_64__)
    static const char* kNames[] = {
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp", "ip", "flags",
        "cx8", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    };
    if (i >= 0 && i < (int)(sizeof(kNames) / sizeof(kNames[0])))
        return kNames[i];
#endif
    return "?";
}

// 与主流调试工具一致：只输出 PC 与 LR（调用方返回地址）两条。
// 注意断点命中在函数入口时 prologue 尚未执行，x29 仍是调用方
// 的帧指针，沿帧指针链展开会得到错误的上层地址，因此这里
// 不展开整条链，直接用 x30 寄存器作为调用方返回地址。
static void ReadStack(uint64_t sp, uint64_t fp, uint64_t lr, uint64_t pc,
                      std::vector<uint64_t>& out) {
    (void)sp;  // sp 仅用于 GUI 展示堆栈起始地址
    out.push_back(pc);  // 第一帧：断点处的 PC
    if (lr >= 0x1000) {  // 第二帧：调用方返回地址
        out.push_back(lr);
        return;
    }
    // LR 无效时的兜底：从当前帧保存区读一次返回地址
    if (fp < 0x1000 || (fp & 7) != 0) return;
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)g_target);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    uint64_t saved_lr = 0;
    if (pread(fd, &saved_lr, sizeof(saved_lr), (off_t)(fp + 8)) ==
            (ssize_t)sizeof(saved_lr) && saved_lr >= 0x1000)
        out.push_back(saved_lr);
    close(fd);
}

static void EmitHit(const BpEvent& ev, uint32_t tid,
                    const std::vector<uint64_t>& regs) {
    uint64_t pc = (kPcRegIndex >= 0 && kPcRegIndex < (int)regs.size())
                      ? regs[kPcRegIndex] : 0;
    uint64_t sp = (kSpRegIndex >= 0 && kSpRegIndex < (int)regs.size())
                      ? regs[kSpRegIndex] : 0;
    uint64_t fp = (kFpRegIndex >= 0 && kFpRegIndex < (int)regs.size())
                      ? regs[kFpRegIndex] : 0;
    uint64_t lr = (kLrRegIndex >= 0 && kLrRegIndex < (int)regs.size())
                      ? regs[kLrRegIndex] : 0;
    std::vector<uint64_t> stack;
    ReadStack(sp, fp, lr, pc, stack);

    // 堆栈字段格式：stack=0x<sp>>0x[sp]>0x[sp+8]>...（imgui 侧
    // 把 '>' 分隔符渲染为 '→'，每个条目都可点击）。
    char line[2048];
    int pos = snprintf(line, sizeof(line), "HIT addr=0x%llx tid=%u pc=0x%llx",
                       (unsigned long long)ev.addr, tid,
                       (unsigned long long)pc);
    for (int i = 0; i < (int)regs.size() &&
                    pos < (int)sizeof(line) - 96; ++i) {
        pos += snprintf(line + pos, sizeof(line) - (size_t)pos,
                        " %s=0x%llx", RegName(i),
                        (unsigned long long)regs[i]);
    }
    pos += snprintf(line + pos, sizeof(line) - (size_t)pos,
                    " stack=0x%llx", (unsigned long long)sp);
    for (size_t i = 0; i < stack.size() &&
                     pos < (int)sizeof(line) - 32; ++i) {
        pos += snprintf(line + pos, sizeof(line) - (size_t)pos,
                        ">0x%llx", (unsigned long long)stack[i]);
    }
    printf("%s\n", line);
    fflush(stdout);
}

static void DrainEvent(BpEvent& ev) {
    PerfMmapPage* page = (PerfMmapPage*)ev.map;
    uint64_t head = __atomic_load_n(&page->data_head, __ATOMIC_ACQUIRE);
    uint64_t tail = __atomic_load_n(&page->data_tail, __ATOMIC_RELAXED);
    if (tail > head) tail = 0;   // 内核重置了环形缓冲区
    const uint8_t* base = (const uint8_t*)page + ev.data_off;

    while (tail + sizeof(PerfRecordHeader) <= head) {
        PerfRecordHeader hdr;
        RingRead(base, ev.data_size, tail, &hdr, sizeof(hdr));
        if (hdr.size < sizeof(PerfRecordHeader)) break;
        if (tail + hdr.size > head) break;

        if (hdr.type == kPerfRecordSample) {
            // PERF_SAMPLE_REGS_USER 记录布局：
            //   header(8) + pid(4) + tid(4) + regs_user_abi(8) + regs(N*8)
            // 必须跳过 abi 字（PERF_SAMPLE_REGS_ABI_64 == 2），
            // 否则寄存器数组会整体错位
            //（第一个"寄存器"会读到 abi 值）。
            size_t need = 8 + 8 + 8 + (size_t)kRegCount * 8;
            if (hdr.size >= need) {
                uint32_t pid = 0, tid = 0;
                RingRead(base, ev.data_size, tail + 8, &pid, 4);
                RingRead(base, ev.data_size, tail + 12, &tid, 4);
                std::vector<uint64_t> regs((size_t)kRegCount);
                RingRead(base, ev.data_size, tail + 24, regs.data(),
                         regs.size() * 8);
                EmitHit(ev, tid, regs);
            }
        }
        // PERF_RECORD_LOST 等其他记录类型会被跳过。
        tail += hdr.size;
    }
    __atomic_store_n(&page->data_tail, tail, __ATOMIC_RELEASE);
}

// ---------------------------------------------------------------------------
// 线程重扫 + 命令处理
// ---------------------------------------------------------------------------

static void RescanThreads() {
    std::vector<pid_t> tids = ListThreads(g_target);

    // 丢弃线程已不存在的命中事件。
    for (auto it = g_events.begin(); it != g_events.end();) {
        bool alive = std::find(tids.begin(), tids.end(), it->tid) != tids.end();
        if (!alive) {
            CloseEvent(*it);
            it = g_events.erase(it);
        } else {
            ++it;
        }
    }

    // 把活动断点附加到上次扫描后出现
    //（或之前打开失败）的线程。
    for (pid_t t : tids) {
        for (const ActiveBp& bp : g_active) {
            bool has = std::any_of(g_events.begin(), g_events.end(),
                                   [t, &bp](const BpEvent& e) {
                                       return e.tid == t && e.addr == bp.addr;
                                   });
            if (has) continue;
            BpEvent ev;
            if (OpenBpEvent(t, bp, ev) == 0) g_events.push_back(ev);
        }
    }
}

static bool HandleStdin() {
    char line[512];
    if (!fgets(line, sizeof(line), stdin)) return false;   // EOF
    std::vector<std::string> w = SplitWords(line);
    if (w.empty()) return true;
    const std::string& cmd = w[0];

    if (cmd == "ping") {
        printf("OK ping\n");
        fflush(stdout);
        return true;
    }
    if (cmd == "quit" || cmd == "stop") {
        g_quit = true;
        printf("OK bye\n");
        fflush(stdout);
        return true;
    }
    if (cmd == "clearall") {
        int closed = 0;
        for (const ActiveBp& bp : g_active)
            closed += ClearBreakpoint(bp.addr);
        printf("OK clearall removed=%d\n", closed);
        fflush(stdout);
        return true;
    }
    if (cmd == "list") {
        printf("OK list count=%zu\n", g_active.size());
        for (const ActiveBp& bp : g_active)
            printf("bp 0x%llx %s len=%d\n",
                   (unsigned long long)bp.addr, TypeName(bp.type), bp.len);
        fflush(stdout);
        return true;
    }
    if (cmd == "set") {
        if (w.size() < 3) {
            printf("ERR usage: set <hexaddr> <x|r|w|rw> [1|2|4|8]\n");
            fflush(stdout);
            return true;
        }
        uint64_t addr = 0;
        if (!ParseHex(w[1], addr)) {
            printf("ERR bad address: %s\n", w[1].c_str());
            fflush(stdout);
            return true;
        }
        int type = ParseType(w[2]);
        if (type < 0) {
            printf("ERR bad type: %s\n", w[2].c_str());
            fflush(stdout);
            return true;
        }
        int len = 8;
        if (type != kHwBreakpointX) {
            if (w.size() < 4 || (len = ParseLen(w[3])) < 0) {
                printf("ERR len (1/2/4/8) required for %s\n", w[2].c_str());
                fflush(stdout);
                return true;
            }
        }
        std::string err;
        if (!SetBreakpoint(addr, type, len, err))
            printf("ERR %s\n", err.c_str());
        fflush(stdout);
        return true;
    }
    if (cmd == "clear") {
        if (w.size() < 2) {
            printf("ERR usage: clear <hexaddr>\n");
            fflush(stdout);
            return true;
        }
        uint64_t addr = 0;
        if (!ParseHex(w[1], addr)) {
            printf("ERR bad address: %s\n", w[1].c_str());
            fflush(stdout);
            return true;
        }
        int closed = ClearBreakpoint(addr);
        printf("OK clear 0x%llx removed=%d\n",
               (unsigned long long)addr, closed);
        fflush(stdout);
        return true;
    }

    printf("ERR unknown command: %s\n", cmd.c_str());
    fflush(stdout);
    return true;
}

} // 匿名命名空间

// ---------------------------------------------------------------------------
// 入口点
// ---------------------------------------------------------------------------

int RunBreakpointService(pid_t targetPid) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    if (geteuid() != 0) {
        printf("ERR not running as root (euid=%d)\n", (int)geteuid());
        fflush(stdout);
        return 1;
    }
    if (!ProcessExists(targetPid)) {
        printf("ERR target pid %d not found\n", (int)targetPid);
        fflush(stdout);
        return 1;
    }

    g_target = targetPid;
    printf("INFO breakpoint service started pid=%d arch=%s\n",
           (int)targetPid,
#if defined(__aarch64__)
           "arm64"
#elif defined(__x86_64__)
           "x86_64"
#else
           "unknown"
#endif
    );
    fflush(stdout);

    time_t last_scan = 0;
    while (!g_quit) {
        if (!ProcessExists(g_target)) {
            printf("ERR target process %d exited\n", (int)g_target);
            fflush(stdout);
            break;
        }

        time_t now = time(nullptr);
        if (now - last_scan >= 2) {
            RescanThreads();
            last_scan = now;
        }

        std::vector<pollfd> pfds;
        pfds.reserve(g_events.size() + 1);
        pfds.push_back({STDIN_FILENO, POLLIN, 0});
        for (const BpEvent& ev : g_events)
            pfds.push_back({ev.fd, POLLIN, 0});

        int rc = poll(pfds.data(), (nfds_t)pfds.size(), 500);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (rc == 0) continue;

        // 先排空命中事件（不修改状态），再处理 stdin（可能
        // 修改 g_events；下一轮循环会重建 pfds）。
        std::vector<size_t> dead;
        for (size_t i = 1; i < pfds.size(); ++i) {
            size_t idx = i - 1;
            if (idx >= g_events.size()) break;
            if (pfds[i].revents & POLLIN)
                DrainEvent(g_events[idx]);
            if (pfds[i].revents & (POLLHUP | POLLERR))
                dead.push_back(idx);
        }
        for (auto it = dead.rbegin(); it != dead.rend(); ++it) {
            if (*it < g_events.size()) {
                CloseEvent(g_events[*it]);
                g_events.erase(g_events.begin() + (ptrdiff_t)*it);
            }
        }

        if (pfds[0].revents & POLLIN) {
            if (!HandleStdin()) break;
        } else if (pfds[0].revents & (POLLHUP | POLLERR)) {
            break;   // imgui 侧关闭了管道
        }
    }

    for (BpEvent& ev : g_events) CloseEvent(ev);
    g_events.clear();
    g_active.clear();
    return 0;
}

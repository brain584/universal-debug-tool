#include "ui/main_ui.h"
#include "ui/ui.h"
#include "imgui.h"

#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cctype>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <array>
#include <chrono>
#include <string>
#include <cstdlib>
#include <thread>
#include <mutex>
#include <atomic>
#include <utility>

#include "socket/socket.h"
#include "bp/BpService.h"
#include "Disasm.h"
#include "AsmWrite.h"
#include "MemSu.hpp"
#include "Search.hpp"
#include "MemToolTypes.h"

#include <limits>
#include <cerrno>
#include <csignal>

// 由 native-lib.cpp 提供：在 `su` 下运行独立注入器并
// 返回捕获的输出。
extern std::string RunInjector(const std::string& pkg);
extern std::string RunInjectorPid(int pid);
// 由 native-lib.cpp 提供：内存查看器使用的 root 内存辅助函数。
extern std::string RunSuCommand(const std::string& cmd);
extern std::string GetConfigFilePath();
extern std::string ReadRemoteMaps(int pid);
extern bool ReadRemoteDword(int pid, uintptr_t addr, uint32_t& out);
extern bool WriteRemoteDword(int pid, uintptr_t addr, uint32_t value);
extern bool ReadRemoteBytes(int pid, uintptr_t addr, void* buf, size_t n);
extern bool ReadRemoteChunk(int pid, uintptr_t addr, void* buf, size_t n);
extern bool ReadRemotePages(int pid, const std::vector<uintptr_t>& pages,
                            std::vector<uint8_t>& out);
extern bool CopyToClipboard(const std::string& text);

namespace aimgui {

// 目标进程存活监控（实现位于文件末尾，进程选择处需要调用）。
static void BindTargetAlive(int pid);
// 内存类型配置持久化（实现位于文件末尾，页面勾选变化处调用）。
static void SaveMemTypeConfig();

// ─── 侧边栏条目 ─────────────────────────────────────────────────────────
const PageItem kPages[] = {
    { Page::SelectProcess, u8"选择" },
    { Page::Search,        u8"搜索" },
    { Page::Memory,        u8"内存" },
    { Page::Breakpoint,    u8"断点" },
    { Page::Save,          u8"保存" },
    { Page::Script,        u8"脚本" },
    { Page::Settings,      u8"设置" },
};
const int kPagesCount = (int)(sizeof(kPages) / sizeof(kPages[0]));

namespace {

// ─── 进程列表辅助 ────────────────────────────────────────────────────────
struct ProcEntry {
    int         pid;
    std::string package;    // 包名或进程名
};

static std::vector<ProcEntry> g_proc_list;
static std::atomic<bool>      g_proc_list_loaded{false};
static std::atomic<bool>      g_root_available{false};
static std::atomic<bool>      g_scan_started{false};
static std::mutex             g_proc_mutex;

// 注入状态（渲染线程读取，工作线程写入）。
static std::mutex  g_inject_status_mutex;
static std::string g_inject_status;
static bool        g_injecting = false;

// ── 内存查看器状态 ──
struct MemRegion {
    uintptr_t   start = 0;
    uintptr_t   end = 0;
    std::string perms;
    std::string path;
    std::string type;
};

static std::atomic<int>   g_mem_pid{0};
static std::atomic<bool>  g_mem_loading{false};
static std::atomic<bool>  g_mem_loaded{false};
static std::mutex         g_mem_mutex;
static std::vector<MemRegion> g_mem_regions;
static std::string        g_mem_parse_status;   // 由 g_mem_mutex 保护
static int                g_mem_page = 0;
static constexpr int      kMemPageSize = 8;
static uint8_t            g_mem_page_bytes[kMemPageSize][16] = {{0}};
static bool               g_mem_page_ok[kMemPageSize] = {false};
static std::atomic<bool>  g_mem_values_loading{false};
// 分页模式最近一次加载的地址列表（写入后自动刷新复用）。
static std::vector<uintptr_t> g_mem_last_page_addrs;

// 数值显示类型 + HEX 开关
enum { kValDword = 0, kValFloat, kValUtf8, kValUtf16 };
static int  g_mem_value_type = kValDword;
static bool g_mem_hex_enabled = false;
static bool g_mem_filter_dirty = false;

// 类型筛选（GG 风格）
static const char* kMemTypes[] = {
    "code app", "code system", "java heap", "cpp heap", "cpp alloc",
    "cpp data", "cpp", "bss", "anonymous", "stack", "ashmem",
    "video", "java", "other"
};
static const int kMemTypeCount = (int)(sizeof(kMemTypes) / sizeof(kMemTypes[0]));
static bool g_mem_type_show[kMemTypeCount];

// 内存类型索引 -> 搜索用 RANGE_* 标志。内存页与搜索页共享
// g_mem_type_show 这份勾选状态；搜索时按此表换算成引擎掩码。
static const uint32_t kMemTypeFlags[kMemTypeCount] = {
    RANGE_CODE_APP,  RANGE_CODE_SYSTEM, RANGE_JAVA_HEAP, RANGE_C_HEAP,
    RANGE_C_ALLOC,   RANGE_C_DATA,
    RANGE_C_HEAP | RANGE_C_ALLOC | RANGE_C_DATA | RANGE_C_BSS,  // "cpp"（兜底）
    RANGE_C_BSS,     RANGE_ANONYMOUS,   RANGE_STACK,    RANGE_ASHMEM,
    RANGE_VIDEO,     RANGE_JAVA,        (uint32_t)RANGE_OTHER
};

// 连续模式（4 字节步进，与区域列表相同的行格式）
static bool              g_mem_cont_mode = false;
static uintptr_t         g_mem_cont_base = 0;
static std::atomic<bool> g_mem_cont_loading{false};
static std::mutex        g_mem_cont_mutex;
static uintptr_t         g_mem_cont_addrs[kMemPageSize];
static uint32_t          g_mem_cont_vals[kMemPageSize];
static int               g_mem_cont_type[kMemPageSize];
static bool              g_mem_cont_ok[kMemPageSize];
static bool              g_mem_cont_show[kMemPageSize];
static int               g_mem_cont_count = 0;
static char              g_mem_cont_base_buf[32] = "0";

// 内存编辑状态
static uintptr_t         g_edit_addr = 0;
static uintptr_t         g_edit_base = 0;      // 被点击的地址
static int64_t           g_edit_offset = 0;    // 叠加在基址上的偏移
static char              g_edit_offset_buf[32] = "0";
static bool              g_edit_open = false;
static char              g_edit_value[32] = "0";
static std::atomic<bool> g_edit_writing{false};
static std::mutex        g_edit_mutex;
static std::string       g_edit_result;

// 链接库跳转（连续模式下跳到已加载库基址）
static bool                                   g_lib_open = false;
static std::atomic<bool>                      g_lib_fetching{false};
static std::mutex                             g_lib_mutex;
static std::vector<std::pair<uintptr_t, std::string>> g_lib_list;

// 每行反汇编（capstone 在应用内本地解码，不走 socket）
static int              g_disasm_arch = 0;      // 0 = ARM64, 1 = ARM
static std::string      g_mem_page_disasm[kMemPageSize];  // 区域模式的行
static std::string      g_mem_cont_disasm[kMemPageSize];  // 连续模式的行

// Saved addresses (the "保存" page)
struct SavedRow {
    uintptr_t   addr = 0;
    bool        bp = false;          // 硬件断点已启用
    int         bp_type = 0;         // 0=x 1=r 2=w 3=rw
    int         bp_len  = 2;         // {1,2,4,8} 的下标（默认 4）
    bool        ok = false;
    uint8_t     bytes[16] = {0};
    std::string hex;
    std::string disasm;
    int         type = kMemTypeCount - 1;
};
static std::vector<SavedRow> g_saved_rows;
static std::mutex            g_saved_mutex;
static std::atomic<bool>     g_saved_loading{false};
static std::atomic<bool>     g_saved_dirty{true};

// ── 搜索页面 ──
enum SearchMode { kSearchExact = 0, kSearchFuzzy };
struct SearchHit {
    uintptr_t addr = 0;
    uint64_t  val = 0;   // 最近一次按类型大小的原始值（用于显示 + 模糊搜索）
};
static int               g_search_type = TYPE_DWORD;
static int               g_search_mode = kSearchExact;
static char              g_search_value[64] = "0";
static std::vector<SearchHit> g_search_hits;
static std::mutex        g_search_mutex;
static std::atomic<bool> g_search_running{false};
static std::string       g_search_status;      // 由 g_search_mutex 保护
static int               g_search_page = 0;    // 由 g_search_mutex 保护
static uint64_t          g_search_hits_version = 0;  // 由互斥锁保护
static constexpr int     kSearchPageSize = 8;
static constexpr size_t  kSearchMaxExact = 5000;
static constexpr size_t  kSearchMaxFuzzy = 1000000;
static constexpr size_t  kSearchChunk = 8u << 20;   // 每次 su 读取 8 MB

// 搜索结果的分页显示缓存（数值来自 SearchHit）。
static uint8_t  g_search_page_bytes[kSearchPageSize][16] = {{0}};
static bool     g_search_page_ok[kSearchPageSize] = {false};
static std::string g_search_page_disasm[kSearchPageSize];
static int      g_search_page_type[kSearchPageSize];
static std::atomic<bool> g_search_page_loading{false};
static int      g_search_loaded_page = -1;
static uint64_t g_search_loaded_version = 0;

// 页面切换请求，由 ui.cpp 的侧边栏 / 框架消费。
static std::atomic<int> g_requested_page{-1};

// GG 风格的内存类型分类。规则逐字取自
// AlguiMemTool 的 BCMAPSFLAG，判定与该库 / GG 一致。
static std::string ClassifyRegion(const std::string& path, const std::string& perms) {
    return ClassifyMemType(perms, path);
}

static void MemLoadForPid(int pid) {
    if (g_mem_loading.exchange(true)) return;
    std::thread([pid] {
        std::string text = ReadRemoteMaps(pid);
        std::vector<MemRegion> regions;
        std::istringstream iss(text);
        std::string line;
        if (text.empty()) {
            std::lock_guard<std::mutex> lk(g_mem_mutex);
            g_mem_parse_status = "maps 读取为空 (需要 root？目标已退出？)";
            g_mem_loaded.store(true);
            g_mem_loading.store(false);
            return;
        }
        while (std::getline(iss, line)) {
            if (line.size() < 20) continue;
            unsigned long long a = 0, b = 0, off = 0, ino = 0;
            char perms[8] = {0};
            char dev[32] = {0};
            char path[512] = {0};
            int n = sscanf(line.c_str(), "%llx-%llx %7s %llx %31s %llu %511[^\n]",
                           &a, &b, perms, &off, dev, &ino, path);
            if (n < 6) continue;
            MemRegion r;
            r.start = (uintptr_t)a;
            r.end = (uintptr_t)b;
            r.perms = perms;
            r.path = (n >= 7) ? path : "";
            r.type = ClassifyRegion(r.path, r.perms);
            regions.push_back(r);
        }
        {
            std::lock_guard<std::mutex> lk(g_mem_mutex);
            g_mem_regions.swap(regions);
            g_mem_page = 0;
            g_mem_loaded.store(true);
            g_mem_filter_dirty = true;  // 切换后数值需要重新加载
            char status[128];
            snprintf(status, sizeof(status), "已解析 %zu 段", regions.size());
            g_mem_parse_status = status;
        }
        g_mem_loading.store(false);
    }).detach();
}

static void MemClearValues() {
    for (int i = 0; i < kMemPageSize; ++i) {
        g_mem_page_ok[i] = false;
        g_mem_page_disasm[i].clear();
    }
}

static std::string DisasmFirstLine(int arch, const uint8_t* bytes, size_t n);

static void MemLoadValuesForAddrs(int pid, const std::vector<uintptr_t>& addrs) {
    g_mem_last_page_addrs = addrs;  // 供写入后自动刷新复用
    if (g_mem_values_loading.exchange(true)) return;
    int arch = g_disasm_arch;
    std::thread([pid, addrs, arch] {
        struct Item {
            uintptr_t addr;
            uint8_t   bytes[16];
            bool      ok;
            std::string disasm;
        };
        std::vector<Item> items;
        for (auto addr : addrs) {
            Item it;
            it.addr = addr;
            it.ok = ReadRemoteBytes(pid, addr, it.bytes, sizeof(it.bytes));
            if (it.ok) it.disasm = DisasmFirstLine(arch, it.bytes, sizeof(it.bytes));
            items.push_back(it);
        }
        {
            std::lock_guard<std::mutex> lk(g_mem_mutex);
            for (int i = 0; i < kMemPageSize; ++i) {
                g_mem_page_ok[i] = false;
                g_mem_page_disasm[i].clear();
                if (i < (int)items.size() && items[i].ok) {
                    memcpy(g_mem_page_bytes[i], items[i].bytes, 16);
                    g_mem_page_ok[i] = true;
                    g_mem_page_disasm[i] = items[i].disasm;
                }
            }
        }
        g_mem_values_loading.store(false);
    }).detach();
}

static void FormatValue(char* out, size_t outsz, int type, const uint8_t* b, int len) {
    switch (type) {
    case kValDword: {
        uint32_t v = 0;
        if (len >= 4) memcpy(&v, b, 4);
        if (g_mem_hex_enabled)
            snprintf(out, outsz, "0x%08X", v);
        else
            snprintf(out, outsz, "%u", v);
        break;
    }
    case kValFloat: {
        float f = 0.0f;
        if (len >= 4) memcpy(&f, b, 4);
        snprintf(out, outsz, "%.4f", f);
        break;
    }
    case kValUtf8: {
        std::string s;
        for (int i = 0; i < len && b[i] != 0; ++i) {
            unsigned char c = b[i];
            s += (c >= 0x20 && c < 0x7f) ? (char)c : '?';
        }
        snprintf(out, outsz, "\"%s\"", s.c_str());
        break;
    }
    case kValUtf16: {
        std::string s;
        for (int i = 0; i + 1 < len; i += 2) {
            uint16_t w = (uint16_t)(b[i] | (b[i + 1] << 8));
            if (w == 0) break;
            s += (w >= 0x20 && w < 0x7f) ? (char)w : '?';
        }
        snprintf(out, outsz, "\"%s\"", s.c_str());
        break;
    }
    default:
        snprintf(out, outsz, "?");
    }
}

// 解码某行地址处的第一条指令。当字节
// 无法解码为指令（或该行不可读）时返回空字符串。
static std::string DisasmFirstLine(int arch, const uint8_t* bytes, size_t n) {
    std::vector<udt_disasm::Insn> insns;
    udt_disasm::Arch a = arch == 1 ? udt_disasm::Arch::Arm
                                   : udt_disasm::Arch::Arm64;
    if (!udt_disasm::Disassemble(a, bytes, n, 0, 1, insns) || insns.empty())
        return "";
    std::string s = insns[0].mnemonic;
    if (!insns[0].op_str.empty()) s += " " + insns[0].op_str;
    // capstone 把 LDR(literal) 家族（编码位 bits[29:24]=011x00）显示为
    // 绝对地址，基址为 0 时就是偏移（如 ldr x0, 0xc）。改写为标准
    // PC 相对格式 ldr x0, [pc, #0xc]，与 ~A8 汇编写入支持的写法一致。
    if (a == udt_disasm::Arch::Arm64 && insns[0].size >= 4) {
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
                if (b == std::string::npos) return s;
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
    return s;
}

// ── Root 辅助函数 ──
// 应用进程本身没有提权；即使授予 root，
// 其他进程的 /proc 对它也是隐藏的（hidepid/SELinux）。因此扫描必须
// 在 root shell（"su"）中执行，转储结果在这里解析。
static bool HasRoot() {
    FILE* f = popen("su -c id 2>/dev/null", "r");
    if (!f) return false;
    char buf[128] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    pclose(f);
    return n > 0 && strstr(buf, "uid=0") != nullptr;
}

static void ScanRooted(std::vector<ProcEntry>& out) {
    // 只使用 shell 内建命令（read/case/set）：不为每个进程调用 cat/grep，
    // 因此完整扫描 /proc 可在 1 秒内完成，而不是约 10 秒。
    // 输出行格式："pid|uid|cmdline"
    static const char* kScan =
        "su -c 'for d in /proc/[0-9]*; do pid=${d##*/}; "
        "read -r cmd < \"$d/cmdline\" 2>/dev/null; uid=; "
        "while IFS= read -r line; do case \"$line\" in "
        "Uid:*) set -- $line; uid=$2; break;; esac; "
        "done < \"$d/status\" 2>/dev/null; "
        "[ -n \"$cmd\" ] && echo \"$pid|$uid|$cmd\"; done' </dev/null";

    FILE* f = popen(kScan, "r");
    if (!f) return;

    std::string data;
    char tmp[4096];
    size_t n;
    while ((n = fread(tmp, 1, sizeof(tmp), f)) > 0)
        data.append(tmp, n);
    pclose(f);

    out.clear();

    size_t pos = 0;
    while (pos < data.size()) {
        size_t eol = data.find('\n', pos);
        if (eol == std::string::npos) eol = data.size();
        std::string line = data.substr(pos, eol - pos);
        pos = eol + 1;
        if (line.empty()) continue;

        // "pid|uid|cmdline"
        size_t p1 = line.find('|');
        if (p1 == std::string::npos) continue;
        size_t p2 = line.find('|', p1 + 1);
        if (p2 == std::string::npos) continue;

        int pid = atoi(line.c_str());
        int uid = atoi(line.c_str() + p1 + 1);
        std::string arg0 = line.substr(p2 + 1);

        if (pid <= 0 || arg0.empty() || arg0[0] == '\0') continue;  // 内核线程
        if (arg0[0] == '[') continue;
        if (uid < 10000) continue;   // 仅应用 UID

        const char* name = arg0.c_str();
        const char* slash = strrchr(name, '/');
        if (slash) name = slash + 1;

        ProcEntry e;
        e.pid     = pid;
        e.package = name;
        out.push_back(e);
    }
}

// 快速回退：直接从应用进程扫描 /proc（受限内核上只能看到
// 自身进程，但无需 root 也能工作）。
static void ScanDirect(std::vector<ProcEntry>& out) {
    out.clear();
    DIR* dir = opendir("/proc");
    if (!dir) return;

    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_type != DT_DIR) continue;
        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;

        // ── 1. 读取 cmdline 获取进程名 ──────────────────────
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        FILE* f = fopen(path, "r");
        if (!f) continue;
        char cmdline[256] = {};
        size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);
        fclose(f);
        if (n == 0) continue;  // 内核线程（cmdline 为空）直接跳过

        cmdline[n] = '\0';
        char* name = cmdline;
        // 去除路径前缀，取最后的可执行文件名
        char* slash = strrchr(name, '/');
        if (slash) name = slash + 1;

        // ── 2. 排除内核线程（名字被方括号包裹） ──────────────
        if (name[0] == '[') continue;

        // ── 3. 读取 status 文件获取 UID ─────────────────────
        snprintf(path, sizeof(path), "/proc/%d/status", pid);
        std::ifstream status_file(path);
        if (!status_file.is_open()) continue;

        int uid = -1;
        std::string line;
        while (std::getline(status_file, line)) {
            if (line.compare(0, 5, "Uid:\t") == 0) {
                // 格式: "Uid:\t1000\t1000\t1000\t1000"
                std::istringstream iss(line.substr(5));
                iss >> uid;  // 取第一个值（real UID）
                break;
            }
        }
        status_file.close();

        // ── 4. 只保留普通应用 UID（10000 ~ 19999） ─────────
        // AID_APP = 10000，AID_USER = 100000
        if (uid < 10000 || uid > 19999) continue;

        // ── 5. 关键系统进程黑名单（双重保险） ──────────────
        static const char* blocked_names[] = {
            "init", "zygote", "zygote64", "zygote32",
            "system_server", "servicemanager", "surfaceflinger",
            "logd", "lmkd", "vold", "installd", "netd",
            "healthd", "ueventd", "watchdogd", "audioserver",
            "mediaserver", "drmserver", "keystore", "gatekeeperd",
            nullptr
        };
        bool blocked = false;
        for (int i = 0; blocked_names[i]; ++i) {
            if (strcmp(name, blocked_names[i]) == 0) {
                blocked = true;
                break;
            }
        }
        if (blocked) continue;

        // ── 通过全部检查，加入列表 ─────────────────────────
        ProcEntry e;
        e.pid     = pid;
        e.package = name;
        out.push_back(e);
    }
    closedir(dir);
}

void RefreshProcessList(bool force = false) {
    // 在后台线程启动扫描：HasRoot() 和 root 扫描都会启动 su，
    // 绝不能在渲染线程上执行（否则会
    // 阻塞首帧 / 整个悬浮层）。
    if (force) {
        g_proc_list_loaded.store(false);
        g_scan_started.store(false);
    }
    if (g_proc_list_loaded.load() || g_scan_started.exchange(true)) return;
    std::thread([] {
        bool root = HasRoot();
        g_root_available.store(root);
        std::vector<ProcEntry> result;
        if (root) {
            ScanRooted(result);
        } else {
            ScanDirect(result);
        }
        std::lock_guard<std::mutex> lk(g_proc_mutex);
        g_proc_list.swap(result);
        g_proc_list_loaded.store(true);
    }).detach();
}

// ─── 帧率预设 ───────────────────────────────────────────────────────────
constexpr int kFpsPresets[] = { 0, 30, 60, 90, 120, 144 };
constexpr const char* kFpsLabels =
    u8"垂直同步\0" "30\0" "60\0" "90\0" "120\0" "144\0";

int FpsToIndex(int fps) {
    for (int i = 0; i < IM_ARRAYSIZE(kFpsPresets); ++i)
        if (kFpsPresets[i] == fps) return i;
    return 0;
}

// ─── 带数值显示的滑块（保留原功能，设置页仍使用） ───────────────────────
bool SliderFloatGrabValue(const char* label, float* v, float v_min, float v_max,
                          const char* fmt = "%.3f") {
    ImGui::PushStyleColor(ImGuiCol_SliderGrab,       IM_COL32(0,0,0,0));
    ImGui::PushStyleColor(ImGuiCol_SliderGrabActive, IM_COL32(0,0,0,0));
    bool changed = ImGui::SliderFloat(label, v, v_min, v_max, "");
    ImGui::PopStyleColor(2);

    const ImVec2 totalMin = ImGui::GetItemRectMin();
    const ImVec2 totalMax = ImGui::GetItemRectMax();

    const char* hash = std::strstr(label, "##");
    const char* visible_end = hash ? hash : label + std::strlen(label);
    const ImVec2 label_size = ImGui::CalcTextSize(label, visible_end);
    const float  inner      = ImGui::GetStyle().ItemInnerSpacing.x;
    const float  bar_w      = (totalMax.x - totalMin.x) -
                              (label_size.x > 0.0f ? label_size.x + inner : 0.0f);
    const ImVec2 barMin = totalMin;
    const ImVec2 barMax(totalMin.x + bar_w, totalMax.y);

    char buf[32];
    std::snprintf(buf, sizeof(buf), fmt, *v);
    const ImVec2 ts = ImGui::CalcTextSize(buf);

    const float pad_x  = 18.0f;
    const float min_w  = ImGui::GetStyle().GrabMinSize;
    const float grab_w = (ts.x + pad_x > min_w) ? ts.x + pad_x : min_w;
    const float grab_h = ts.y + 10.0f;

    float t = (v_max != v_min) ? (*v - v_min) / (v_max - v_min) : 0.0f;
    if (t < 0.0f) t = 0.0f; else if (t > 1.0f) t = 1.0f;
    const float xL = barMin.x + grab_w * 0.5f;
    const float xR = barMax.x - grab_w * 0.5f;
    const float cx = xL + t * (xR - xL);
    const float cy = (barMin.y + barMax.y) * 0.5f;
    const ImVec2 gMin(cx - grab_w * 0.5f, cy - grab_h * 0.5f);
    const ImVec2 gMax(cx + grab_w * 0.5f, cy + grab_h * 0.5f);

    const ImU32 col = ImGui::GetColorU32(ImGuiCol_SliderGrab);
    ImDrawList* dl  = ImGui::GetWindowDrawList();
    dl->AddRectFilled(gMin, gMax, col, grab_h * 0.5f);
    dl->AddText(ImVec2(cx - ts.x * 0.5f, cy - ts.y * 0.5f), IM_COL32_WHITE, buf);

    return changed;
}

// ─── 页面内容 ───────────────────────────────────────────────────────────

// --- 选择进程页面 --------------------------------------------------------
// 把注入器原始输出压缩成一行状态：
// 成功 -> "注入成功 基址=0x.."，失败 -> "注入失败: <error>"。
static std::string SummarizeInjectResult(const std::string& out) {
    if (out.find("=== Injection successful ===") != std::string::npos) {
        size_t p = out.find("Base:");
        if (p != std::string::npos) {
            p += 6;   // 跳过 "Base: "
            while (p < out.size() && isspace((unsigned char)out[p])) ++p;
            size_t e = p;
            while (e < out.size() && !isspace((unsigned char)out[e])) ++e;
            if (e > p)
                return "注入成功 基址=" + out.substr(p, e - p);
        }
        return "注入成功";
    }
    size_t p = out.find("Error:");
    if (p != std::string::npos) {
        p += 6;
        while (p < out.size() && isspace((unsigned char)out[p])) ++p;
        size_t e = p;
        while (e < out.size() && out[e] != '\n' && e - p < 160) ++e;
        if (e > p) return "注入失败: " + out.substr(p, e - p);
    }
    return "注入失败";
}

void DrawSelectProcess(UiState* state) {
    // 首次加载进程列表
    if (!g_proc_list_loaded.load()) {
        RefreshProcessList();
    }

    if (!g_proc_list_loaded.load()) {
        ImGui::TextDisabled(u8"正在扫描进程...");
    } else if (!g_root_available.load()) {
        ImGui::TextDisabled(u8"未获取 root 权限：只能看到本应用进程，授权后自动列出全部应用");
    }

    ImGui::TextDisabled(u8"仅显示普通应用进程（系统进程已自动隐藏）");
    ImGui::SeparatorText(u8"目标进程");

    // 搜索框
    static char search_buf[128] = "";
    ImGui::InputTextWithHint("##proc_search", u8"搜索 PID 或包名...", search_buf, IM_ARRAYSIZE(search_buf));

    // 获取过滤后的列表
    std::vector<const ProcEntry*> filtered;
    {
        std::lock_guard<std::mutex> lk(g_proc_mutex);
        if (search_buf[0] != '\0') {
            for (const auto& p : g_proc_list) {
                char pid_str[16];
                snprintf(pid_str, sizeof(pid_str), "%d", p.pid);
                if (strstr(pid_str, search_buf) || strstr(p.package.c_str(), search_buf))
                    filtered.push_back(&p);
            }
        } else {
            for (const auto& p : g_proc_list)
                filtered.push_back(&p);
        }
    }

    // 下拉选择框
    static int  selected_idx = -1;
    static ProcEntry current_selection;
    if (ImGui::Button(u8"刷新")) {
        RefreshProcessList(true);
        selected_idx = -1;
        current_selection = ProcEntry();
    }
    ImGui::BeginChild("##proc_list", ImVec2(0, 200),
                      ImGuiChildFlags_Borders,
                      ImGuiWindowFlags_HorizontalScrollbar);
    for (int i = 0; i < (int)filtered.size(); i++) {
        const ProcEntry& p = *filtered[i];
        char label[256];
        snprintf(label, sizeof(label), "%s(%d)", p.package.c_str(), p.pid);
        if (ImGui::Selectable(label, selected_idx == i)) {
            selected_idx = i;
            current_selection = p;
            g_mem_pid.store(p.pid);
            g_mem_loaded.store(false);
            g_mem_loading.store(false);
            BindTargetAlive(p.pid);
        }
    }
    ImGui::EndChild();

    ImGui::Spacing();
    bool has_selection = selected_idx >= 0;
    ImGui::BeginDisabled(!has_selection);
    if (ImGui::Button(u8"注入", ImVec2(120, 0))) {
        // 在后台线程执行 ptrace 注入（绝不在渲染线程），
        // 状态显示在下方。
        {
            std::lock_guard<std::mutex> lk(g_inject_status_mutex);
            if (!g_injecting) {
                g_injecting = true;
                g_inject_status = "正在注入...";
                std::string pkg = current_selection.package;
                std::thread([pkg] {
                    std::string out = RunInjector(pkg);
                    std::lock_guard<std::mutex> lk2(g_inject_status_mutex);
                    g_inject_status = out;
                    g_injecting = false;
                }).detach();
            }
        }
        // TODO：执行注入逻辑
    }
    ImGui::EndDisabled();

    // 注入状态
    {
        std::lock_guard<std::mutex> lk(g_inject_status_mutex);
        if (!g_inject_status.empty()) {
            ImGui::TextWrapped("%s", SummarizeInjectResult(g_inject_status).c_str());
        }
    }
    if (has_selection) {
        ImGui::SameLine();
        ImGui::Text(u8"已选择: %s(%d)", current_selection.package.c_str(), current_selection.pid);
    }

    // ── 按 PID 注入：native ELF / 被列表过滤掉的进程 ──
    // 普通可执行文件（如 /data/local/tmp 下运行的程序）没有包名，
    // 且不在上面的应用进程列表里，只能直接给 PID。
    ImGui::SeparatorText(u8"按 PID 注入（native ELF）");
    static int manual_pid = 0;
    ImGui::SetNextItemWidth(160);
    ImGui::InputInt("##manual_pid", &manual_pid);
    ImGui::SameLine();
    if (ImGui::Button(u8"注入该 PID", ImVec2(120, 0))) {
        if (manual_pid > 0) {
            // 立即绑定为内存/断点页的目标进程，
            // 注入本身在后台线程执行（绝不阻塞渲染线程）。
            g_mem_pid.store(manual_pid);
            g_mem_loaded.store(false);
            g_mem_loading.store(false);
            BindTargetAlive(manual_pid);
            {
                std::lock_guard<std::mutex> lk(g_inject_status_mutex);
                if (!g_injecting) {
                    g_injecting = true;
                    g_inject_status = "正在注入...";
                    int pid = manual_pid;
                    std::thread([pid] {
                        std::string out = RunInjectorPid(pid);
                        std::lock_guard<std::mutex> lk2(g_inject_status_mutex);
                        g_inject_status = out;
                        g_injecting = false;
                    }).detach();
                }
            }
        }
    }

    // ── SO 加密通道 ──────────────────────────────────────────────
    ImGui::SeparatorText(u8"SO 通道");
    {
        const bool connected  = g_socket.IsConnected();
        const bool connecting = g_socket.IsConnecting();
        const ImVec4 col = connected
                               ? ImVec4(0.32f, 0.90f, 0.45f, 1.0f)
                               : (connecting
                                      ? ImVec4(0.95f, 0.72f, 0.20f, 1.0f)
                                      : ImVec4(0.85f, 0.35f, 0.35f, 1.0f));
        const char* st = connected ? u8"已连接" : (connecting ? u8"连接中" : u8"未连接");
        ImGui::TextColored(col, u8"● %s", st);

        if (connected) {
            if (ImGui::Button(u8"断开", ImVec2(90, 0)))
                g_socket.Disconnect();
        } else {
            ImGui::BeginDisabled(connecting);
            if (ImGui::Button(u8"连接", ImVec2(90, 0))) {
                g_socket.SetTargetPackage(current_selection.package);
                g_socket.ConnectAsync();
            }
            ImGui::EndDisabled();
        }
    }
}

// --- 内存页面 (暂时空着) -------------------------------------------------
static int TypeIndexOf(const std::string& type) {
    for (int k = 0; k < kMemTypeCount; ++k)
        if (type == kMemTypes[k]) return k;
    return kMemTypeCount - 1;  // "other"
}

// 二分查找：包含 addr 的区域下标（不存在返回 -1）。
static int FindRegionTypeIdx(const std::vector<MemRegion>& regions, uintptr_t addr) {
    int lo = 0, hi = (int)regions.size() - 1, ans = -1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (regions[mid].start <= addr) { ans = mid; lo = mid + 1; }
        else hi = mid - 1;
    }
    if (ans < 0 || addr >= regions[ans].end) return -1;
    return TypeIndexOf(regions[ans].type);
}

static void MemLoadCont(int pid) {
    if (g_mem_cont_loading.exchange(true)) return;
    int arch = g_disasm_arch;
    std::thread([pid, arch] {
        std::vector<MemRegion> regions;
        {
            std::lock_guard<std::mutex> lk(g_mem_mutex);
            regions = g_mem_regions;
        }
        std::sort(regions.begin(), regions.end(),
                  [](const MemRegion& a, const MemRegion& b) { return a.start < b.start; });

        bool show[kMemTypeCount];
        bool anyType = false;
        for (int i = 0; i < kMemTypeCount; ++i) {
            show[i] = g_mem_type_show[i];
            if (show[i]) anyType = true;
        }

        uintptr_t base = g_mem_cont_base;
        uintptr_t addrs[kMemPageSize] = {0};
        uint32_t  vals[kMemPageSize] = {0};
        int       type[kMemPageSize];
        bool      ok[kMemPageSize] = {false};
        bool      shown[kMemPageSize] = {false};
        std::string disasm[kMemPageSize];
        int       count = 0;
        for (int i = 0; i < kMemPageSize; ++i) {
            uintptr_t addr = base + (uintptr_t)i * 4;
            addrs[i] = addr;
            int ti = FindRegionTypeIdx(regions, addr);
            // 区域快照可能已过期（例如用户在此之后 mmap 了
            // 新页面）。把未知地址归类为 "other"，
            // 这样这些行仍会显示（并遵循 other 类型筛选），
            // 而不是悄悄隐藏内存。
            if (ti < 0) ti = kMemTypeCount - 1;
            type[i] = ti;
            shown[i] = !anyType || show[ti];
            uint8_t b[16];
            ok[i] = ReadRemoteBytes(pid, addr, b, sizeof(b));
            if (ok[i]) {
                memcpy(&vals[i], b, 4);
                disasm[i] = DisasmFirstLine(arch, b, sizeof(b));
            }
            if (shown[i]) count++;
        }
        {
            std::lock_guard<std::mutex> lk(g_mem_cont_mutex);
            for (int i = 0; i < kMemPageSize; ++i) {
                g_mem_cont_addrs[i] = addrs[i];
                g_mem_cont_vals[i] = vals[i];
                g_mem_cont_type[i] = type[i];
                g_mem_cont_ok[i] = ok[i];
                g_mem_cont_show[i] = shown[i];
                g_mem_cont_disasm[i] = disasm[i];
            }
            g_mem_cont_count = count;
        }
        g_mem_cont_loading.store(false);
    }).detach();
}

// 编辑窗口写入成功后自动刷新当前显示页（连续/分页）的数值与反汇编。
static void MemRefreshAfterWrite(int pid) {
    if (g_mem_cont_mode) {
        MemLoadCont(pid);
    } else if (!g_mem_last_page_addrs.empty()) {
        MemLoadValuesForAddrs(pid, g_mem_last_page_addrs);
    }
}

static void DrawMemContinuous(int pid) {
    ImGui::InputText(u8"地址", g_mem_cont_base_buf, sizeof(g_mem_cont_base_buf));
    ImGui::SameLine();
    if (ImGui::Button(u8"跳转")) {
        g_mem_cont_base = (uintptr_t)strtoull(g_mem_cont_base_buf, nullptr, 16) & ~(uintptr_t)3;
        snprintf(g_mem_cont_base_buf, sizeof(g_mem_cont_base_buf), "%llx",
                 (unsigned long long)g_mem_cont_base);
        MemLoadCont(pid);
    }

    if (ImGui::Button(u8"上一页")) {
        g_mem_cont_base = (g_mem_cont_base > kMemPageSize * 4)
                              ? g_mem_cont_base - kMemPageSize * 4 : 0;
        snprintf(g_mem_cont_base_buf, sizeof(g_mem_cont_base_buf), "%llx",
                 (unsigned long long)g_mem_cont_base);
        MemLoadCont(pid);
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"下一页")) {
        g_mem_cont_base += kMemPageSize * 4;
        snprintf(g_mem_cont_base_buf, sizeof(g_mem_cont_base_buf), "%llx",
                 (unsigned long long)g_mem_cont_base);
        MemLoadCont(pid);
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"刷新数值")) MemLoadCont(pid);
    ImGui::SameLine();
    ImGui::Text("0x%llx", (unsigned long long)g_mem_cont_base);

    uintptr_t addrs[kMemPageSize];
    uint32_t  vals[kMemPageSize];
    int       type[kMemPageSize];
    bool      ok[kMemPageSize];
    bool      shown[kMemPageSize];
    std::string disasm[kMemPageSize];
    int       count = 0;
    {
        std::lock_guard<std::mutex> lk(g_mem_cont_mutex);
        for (int i = 0; i < kMemPageSize; ++i) {
            addrs[i] = g_mem_cont_addrs[i];
            vals[i] = g_mem_cont_vals[i];
            type[i] = g_mem_cont_type[i];
            ok[i] = g_mem_cont_ok[i];
            shown[i] = g_mem_cont_show[i];
            disasm[i] = g_mem_cont_disasm[i];
            if (shown[i]) count++;
        }
    }

    ImGui::Text(u8"共 %d/%d 条 (已筛选)", count, kMemPageSize);

    for (int i = 0; i < kMemPageSize; ++i) {
        if (!shown[i]) continue;

        char label[64];
        snprintf(label, sizeof(label), "0x%llx", (unsigned long long)addrs[i]);
        if (ImGui::Button(label, ImVec2(150, 0))) {
            g_edit_base = addrs[i];
            g_edit_addr = addrs[i];
            g_edit_offset = 0;
            snprintf(g_edit_offset_buf, sizeof(g_edit_offset_buf), "0");
            if (ok[i])
                snprintf(g_edit_value, sizeof(g_edit_value), "%u", vals[i]);
            else
                snprintf(g_edit_value, sizeof(g_edit_value), "0");
            {
                std::lock_guard<std::mutex> lk(g_edit_mutex);
                g_edit_result.clear();
            }
            g_edit_open = true;
        }

        ImGui::SameLine();
        char valbuf[64];
        if (ok[i]) {
            uint8_t b[4];
            memcpy(b, &vals[i], 4);
            FormatValue(valbuf, sizeof(valbuf), g_mem_value_type, b, 4);
        } else {
            snprintf(valbuf, sizeof(valbuf), "......");
        }
        ImGui::Text("%s", valbuf);

        // 第 2 行：反汇编指令 + 内存类型。
        char typebuf[32];
        if (type[i] >= 0 && type[i] < kMemTypeCount)
            snprintf(typebuf, sizeof(typebuf), "%s", kMemTypes[type[i]]);
        else
            snprintf(typebuf, sizeof(typebuf), "bad");
        if (disasm[i].empty())
            ImGui::Text("%s", typebuf);
        else
            ImGui::Text("%s  %s", disasm[i].c_str(), typebuf);
    }
}

static void DrawMemEditWindow(int pid) {
    if (!g_edit_open) return;

    ImGui::SetNextWindowSize(ImVec2(430, 210), ImGuiCond_Once);
    if (!ImGui::Begin(u8"内存修改", &g_edit_open,
                      ImGuiWindowFlags_HorizontalScrollbar)) {
        ImGui::End();
        return;
    }
    ImGui::PushTextWrapPos(0.0f);

    ImGui::Text(u8"地址: 0x%llx", (unsigned long long)g_edit_addr);
    if (g_edit_offset != 0)
        ImGui::TextDisabled(u8"基础 0x%llx + 偏移 0x%llx",
                            (unsigned long long)g_edit_base,
                            (unsigned long long)g_edit_offset);

    ImGui::SetNextItemWidth(150.0f);
    ImGui::InputText(u8"偏移", g_edit_offset_buf, sizeof(g_edit_offset_buf));
    ImGui::SameLine();
    if (ImGui::Button(u8"应用偏移")) {
        bool isHex = (strncmp(g_edit_offset_buf, "0x", 2) == 0) ||
                     (strncmp(g_edit_offset_buf, "0X", 2) == 0);
        g_edit_offset =
            (int64_t)strtoll(g_edit_offset_buf, nullptr, isHex ? 16 : 10);
        g_edit_addr = (uintptr_t)((int64_t)g_edit_base + g_edit_offset);
        // 内存页（连续模式）跳转到偏移后的地址。
        g_mem_cont_mode = true;
        g_mem_cont_base = g_edit_addr & ~(uintptr_t)3;
        snprintf(g_mem_cont_base_buf, sizeof(g_mem_cont_base_buf), "%llx",
                 (unsigned long long)g_mem_cont_base);
        MemLoadCont(pid);
        RequestPage(Page::Memory);
        uint32_t v = 0;
        if (ReadRemoteDword(pid, g_edit_addr, v)) {
            snprintf(g_edit_value, sizeof(g_edit_value), "%u", v);
            std::lock_guard<std::mutex> lk(g_edit_mutex);
            g_edit_result = u8"已跳转到偏移地址";
        } else {
            snprintf(g_edit_value, sizeof(g_edit_value), "0");
            std::lock_guard<std::mutex> lk(g_edit_mutex);
            g_edit_result = u8"偏移地址不可读";
        }
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"关闭")) g_edit_open = false;

    ImGui::InputText(u8"值 (HEX, DWORD)", g_edit_value, sizeof(g_edit_value));

    if (ImGui::Button(u8"读取")) {
        uint32_t v = 0;
        if (ReadRemoteDword(pid, g_edit_addr, v)) {
            snprintf(g_edit_value, sizeof(g_edit_value), "%u", v);
            std::lock_guard<std::mutex> lk(g_edit_mutex);
            g_edit_result = "读取成功";
        } else {
            std::lock_guard<std::mutex> lk(g_edit_mutex);
            g_edit_result = "读取失败 (地址不可读?)";
        }
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"写入") && !g_edit_writing.load()) {
        uintptr_t addr = g_edit_addr;
        g_edit_writing.store(true);
        if (strncmp(g_edit_value, "~A8", 3) == 0) {
            // ~A8 <asm>：用 AsmJit 汇编并写入机器码。
            std::string asmText = g_edit_value + 3;
            {
                std::lock_guard<std::mutex> lk(g_edit_mutex);
                g_edit_result = u8"汇编写入中...";
            }
            std::thread([pid, addr, asmText] {
                std::vector<uint8_t> bytes;
                std::string err;
                bool okA = udt_asm::Assemble(asmText.c_str(), bytes, err);
                if (!okA) {
                    std::lock_guard<std::mutex> lk(g_edit_mutex);
                    g_edit_result = u8"汇编失败: " + err;
                    g_edit_writing.store(false);
                    return;
                }
                bool ok = false;
                for (size_t i = 0; i < bytes.size(); i += 4) {
                    uint32_t w = 0;
                    size_t n = bytes.size() - i;
                    if (n >= 4) {
                        memcpy(&w, &bytes[i], 4);
                    } else {
                        for (size_t k = 0; k < n; ++k)
                            w |= (uint32_t)bytes[i + k] << (8 * k);
                    }
                    if (WriteRemoteDword(pid, addr + i, w)) ok = true;
                    else { ok = false; break; }
                }
                {
                    std::lock_guard<std::mutex> lk(g_edit_mutex);
                    char msg[64];
                    snprintf(msg, sizeof(msg),
                             ok ? u8"汇编写入成功 (%zu 字节)"
                                : u8"写入失败 (目标不可写?)",
                             bytes.size());
                    g_edit_result = msg;
                }
                if (ok) {
                    // 写入成功：自动刷新内存页数值并回读当前值。
                    MemRefreshAfterWrite(pid);
                    uint32_t nv = 0;
                    if (ReadRemoteDword(pid, addr, nv))
                        snprintf(g_edit_value, sizeof(g_edit_value),
                                 "%u", nv);
                }
                g_edit_writing.store(false);
            }).detach();
        } else {
            bool isHex = (strncmp(g_edit_value, "0x", 2) == 0) ||
                         (strncmp(g_edit_value, "0X", 2) == 0);
            uint32_t v =
                (uint32_t)strtoull(g_edit_value, nullptr, isHex ? 16 : 10);
            {
                std::lock_guard<std::mutex> lk(g_edit_mutex);
                g_edit_result = "写入中...";
            }
            std::thread([pid, addr, v] {
                bool ok = WriteRemoteDword(pid, addr, v);
                {
                    std::lock_guard<std::mutex> lk(g_edit_mutex);
                    g_edit_result = ok ? "写入成功" : "写入失败 (目标不可写?)";
                }
                if (ok) {
                    // 写入成功：自动刷新内存页数值。
                    MemRefreshAfterWrite(pid);
                }
                g_edit_writing.store(false);
            }).detach();
        }
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"复制地址")) {
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)g_edit_addr);
        bool ok = CopyToClipboard(buf);
        std::lock_guard<std::mutex> lk(g_edit_mutex);
        g_edit_result = ok ? "已复制地址" : "复制失败";
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"保存地址")) {
        {
            std::lock_guard<std::mutex> lk(g_saved_mutex);
            bool exists = false;
            for (const auto& s : g_saved_rows)
                if (s.addr == g_edit_addr) { exists = true; break; }
            if (!exists) {
                SavedRow r;
                r.addr = g_edit_addr;
                g_saved_rows.push_back(r);
            }
        }
        g_saved_dirty.store(true);
        std::lock_guard<std::mutex> lk(g_edit_mutex);
        g_edit_result = u8"已保存地址";
    }

    {
        std::lock_guard<std::mutex> lk(g_edit_mutex);
        if (!g_edit_result.empty())
            ImGui::TextWrapped("%s", g_edit_result.c_str());
    }
    ImGui::PopTextWrapPos();
    ImGui::End();
}

static void DrawMemLibWindow(int pid) {
    if (!g_lib_open) return;

    static char filter[64] = "";
    ImGui::SetNextWindowSize(ImVec2(480, 560), ImGuiCond_Once);
    if (!ImGui::Begin(u8"链接库", &g_lib_open,
                      ImGuiWindowFlags_HorizontalScrollbar)) {
        ImGui::End();
        return;
    }
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextDisabled(u8"点击链接库跳转到其基址（连续模式）");
    ImGui::InputText(u8"筛选", filter, sizeof(filter));
    ImGui::Separator();
    if (ImGui::BeginChild("##lib_list", ImVec2(-1, -1),
                          ImGuiChildFlags_Borders,
                          ImGuiWindowFlags_HorizontalScrollbar)) {
        std::vector<std::pair<uintptr_t, std::string>> libs;
        {
            std::lock_guard<std::mutex> lk(g_lib_mutex);
            libs = g_lib_list;
        }
        if (libs.empty()) {
            if (g_lib_fetching.load())
                ImGui::TextDisabled(u8"加载中...");
            else
                ImGui::TextDisabled(u8"未获取到链接库（请确认已连接 SO 通道）");
        } else {
            std::string f = filter;
            int shown = 0;
            int total = (int)libs.size();
            for (const auto& kv : libs) {
                std::string name = kv.second;
                size_t slash = name.find_last_of('/');
                if (slash != std::string::npos) name = name.substr(slash + 1);
                if (!f.empty()) {
                    std::string lname = name;
                    std::string lf = f;
                    for (auto& ch : lname) ch = (char)tolower((unsigned char)ch);
                    for (auto& ch : lf) ch = (char)tolower((unsigned char)ch);
                    if (lname.find(lf) == std::string::npos) continue;
                }
                shown++;
                char label[512];
                snprintf(label, sizeof(label), "0x%llx  %s",
                         (unsigned long long)kv.first, name.c_str());
                if (ImGui::Button(label, ImVec2(-1, 0))) {
                    g_mem_cont_mode = true;
                    g_mem_cont_base = kv.first & ~(uintptr_t)3;
                    snprintf(g_mem_cont_base_buf, sizeof(g_mem_cont_base_buf), "%llx",
                             (unsigned long long)g_mem_cont_base);
                    g_lib_open = false;
                    MemLoadCont(pid);
                }
            }
            ImGui::TextDisabled(u8"%d/%d", shown, total);
        }
    }
    ImGui::EndChild();
    ImGui::PopTextWrapPos();
    ImGui::End();
}

void DrawMemory() {
    int pid = g_mem_pid.load();
    if (pid <= 0) {
        ImGui::SeparatorText(u8"内存操作");
        ImGui::TextDisabled(u8"请先在「选择」页选定目标进程");
        return;
    }

    if (!g_mem_loaded.load()) {
        MemLoadForPid(pid);
        ImGui::SeparatorText(u8"内存操作");
        ImGui::TextDisabled(u8"正在解析目标进程内存映射 (PID %d)...", pid);
        return;
    }

    ImGui::SeparatorText(u8"内存操作");
    ImGui::Text(u8"目标 PID: %d", pid);

    // 类型筛选 + 数值类型
    {
        bool anyFilterChanged = false;
        if (ImGui::CollapsingHeader(u8"类型筛选（未勾选 = 全部）",
                                    ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::Columns(3, "memtypecols", false);
            for (int i = 0; i < kMemTypeCount; ++i) {
                if (ImGui::Checkbox(kMemTypes[i], &g_mem_type_show[i])) anyFilterChanged = true;
                ImGui::NextColumn();
            }
            ImGui::Columns(1);
            if (ImGui::Button(u8"全选")) {
                for (int i = 0; i < kMemTypeCount; ++i) g_mem_type_show[i] = true;
                anyFilterChanged = true;
            }
            ImGui::SameLine();
            if (ImGui::Button(u8"全不选")) {
                for (int i = 0; i < kMemTypeCount; ++i) g_mem_type_show[i] = false;
                anyFilterChanged = true;
            }
        }
        if (anyFilterChanged) {
            g_mem_filter_dirty = true;
            g_mem_page = 0;
            if (g_mem_cont_mode) MemLoadCont(pid);
            SaveMemTypeConfig();
        }

        ImGui::SeparatorText(u8"数值类型");
        ImGui::Checkbox(u8"显示 HEX", &g_mem_hex_enabled);
        ImGui::SameLine();
        const char* valTypes = "DWORD\0FLOAT\0UTF8\0UTF16\0";
        ImGui::Combo(u8"显示为", &g_mem_value_type, valTypes, 4);
        ImGui::SameLine();
        if (ImGui::Combo(u8"反汇编架构", &g_disasm_arch, u8"ARM64\0ARM\0")) {
            g_mem_filter_dirty = true;
            if (g_mem_cont_mode) MemLoadCont(pid);
        }
        ImGui::Spacing();
    }

    // 连续模式开关（两种模式下都可用）
    if (ImGui::Checkbox(u8"连续模式", &g_mem_cont_mode)) {
        if (g_mem_cont_mode) {
            std::vector<MemRegion> regions;
            {
                std::lock_guard<std::mutex> lk(g_mem_mutex);
                regions = g_mem_regions;
            }
            if (!regions.empty() && g_mem_cont_base == 0)
                g_mem_cont_base = regions[0].start;
            snprintf(g_mem_cont_base_buf, sizeof(g_mem_cont_base_buf), "%llx",
                     (unsigned long long)g_mem_cont_base);
            MemLoadCont(pid);
        }
    }
    ImGui::SameLine();
    if (g_socket.IsConnected()) {
        if (ImGui::Button(u8"跳转链接库")) {
            if (!g_lib_fetching.load()) {
                g_lib_open = true;
                g_lib_fetching.store(true);
                std::thread([] {
                    std::string resp = g_socket.SendCommand("modules", 5000);
                    std::vector<std::pair<uintptr_t, std::string>> libs;
                    std::stringstream ss(resp);
                    std::string line;
                    while (std::getline(ss, line)) {
                        unsigned long long base = 0;
                        char name[512] = {0};
                        if (sscanf(line.c_str(), "%llx %511[^\n]", &base, name) == 2 && base != 0)
                            libs.emplace_back((uintptr_t)base, std::string(name));
                    }
                    {
                        std::lock_guard<std::mutex> lk(g_lib_mutex);
                        g_lib_list = std::move(libs);
                    }
                    g_lib_fetching.store(false);
                }).detach();
            }
        }
    } else {
        ImGui::TextDisabled(u8"跳转链接库（需连接）");
    }
    DrawMemLibWindow(pid);
    if (g_mem_cont_mode) {
        DrawMemContinuous(pid);
        DrawMemEditWindow(pid);
        return;
    }
    ImGui::Spacing();

    // 快照区域列表（几百条，开销小），让渲染线程
    // 不会阻塞在加载器的 su 调用上，绘制时也没有锁
    // 竞争。
    std::vector<MemRegion> regions;
    {
        std::lock_guard<std::mutex> lk(g_mem_mutex);
        regions = g_mem_regions;
    }
    std::string page_disasm[kMemPageSize];
    {
        std::lock_guard<std::mutex> lk(g_mem_mutex);
        for (int i = 0; i < kMemPageSize; ++i)
            page_disasm[i] = g_mem_page_disasm[i];
    }
    if (regions.empty()) {
        ImGui::TextDisabled(u8"未解析到内存映射");
        return;
    }

    bool anyType = false;
    for (int k = 0; k < kMemTypeCount; ++k)
        if (g_mem_type_show[k]) { anyType = true; break; }

    std::vector<int> filtered;
    for (int i = 0; i < (int)regions.size(); ++i) {
        int ti = kMemTypeCount - 1;
        for (int k = 0; k < kMemTypeCount; ++k) {
            if (regions[i].type == kMemTypes[k]) { ti = k; break; }
        }
        if (!anyType || g_mem_type_show[ti]) filtered.push_back(i);
    }
    if (filtered.empty()) {
        ImGui::TextDisabled(u8"当前筛选下没有内存段");
        return;
    }

    int totalPages = (int)((filtered.size() + kMemPageSize - 1) / kMemPageSize);
    if (g_mem_page < 0) g_mem_page = 0;
    if (g_mem_page >= totalPages) g_mem_page = totalPages - 1;

    auto pageAddrsOf = [&](int page) {
        std::vector<uintptr_t> addrs;
        int s = page * kMemPageSize;
        for (int i = s; i < s + kMemPageSize && i < (int)filtered.size(); ++i)
            addrs.push_back(regions[filtered[i]].start);
        return addrs;
    };

    if (g_mem_filter_dirty) {
        g_mem_filter_dirty = false;
        MemClearValues();
        MemLoadValuesForAddrs(pid, pageAddrsOf(g_mem_page));
    }

    ImGui::Text(u8"第 %d/%d 页  共 %zu 段", g_mem_page + 1, totalPages, filtered.size());

    if (ImGui::Button(u8"上一页") && g_mem_page > 0) {
        g_mem_page--;
        MemClearValues();
        MemLoadValuesForAddrs(pid, pageAddrsOf(g_mem_page));
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"下一页") && g_mem_page + 1 < totalPages) {
        g_mem_page++;
        MemClearValues();
        MemLoadValuesForAddrs(pid, pageAddrsOf(g_mem_page));
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"刷新")) {
        g_mem_loaded.store(false);
        g_mem_loading.store(false);
        MemLoadForPid(pid);
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"刷新数值")) {
        MemClearValues();
        MemLoadValuesForAddrs(pid, pageAddrsOf(g_mem_page));
    }

    ImGui::Spacing();

    int start = g_mem_page * kMemPageSize;
    int count = std::min(kMemPageSize, (int)filtered.size() - start);
    for (int i = 0; i < count; ++i) {
        const MemRegion& r = regions[filtered[start + i]];

        char label[64];
        snprintf(label, sizeof(label), "0x%llx", (unsigned long long)r.start);
        if (ImGui::Button(label, ImVec2(150, 0))) {
            g_edit_base = r.start;
            g_edit_addr = r.start;
            g_edit_offset = 0;
            snprintf(g_edit_offset_buf, sizeof(g_edit_offset_buf), "0");
            if (g_mem_page_ok[i]) {
                uint32_t v = 0;
                memcpy(&v, g_mem_page_bytes[i], 4);
                snprintf(g_edit_value, sizeof(g_edit_value), "%u", v);
            } else {
                snprintf(g_edit_value, sizeof(g_edit_value), "0");
            }
            {
                std::lock_guard<std::mutex> lk(g_edit_mutex);
                g_edit_result.clear();
            }
            g_edit_open = true;
        }

        ImGui::SameLine();
        char valbuf[64];
        if (g_mem_page_ok[i])
            FormatValue(valbuf, sizeof(valbuf), g_mem_value_type,
                        g_mem_page_bytes[i], 16);
        else
            snprintf(valbuf, sizeof(valbuf), "......");
        ImGui::Text("%s", valbuf);

        // 第 2 行：反汇编指令 + 内存类型（+ 权限）。
        if (page_disasm[i].empty())
            ImGui::Text("%s  %s", r.type.c_str(), r.perms.c_str());
        else
            ImGui::Text("%s  %s  %s", page_disasm[i].c_str(),
                        r.type.c_str(), r.perms.c_str());
    }

    DrawMemEditWindow(pid);
}

// --- 脚本页面 -------------------------------------------------------------
namespace {
std::mutex g_script_log_mutex;
std::string g_script_log;
std::atomic<size_t> g_script_log_from{SIZE_MAX};  // 已显示的日志水位（SIZE_MAX=未知）
}

void DrawScript() {
    static char script_code[16384] = "";

    // 左右分栏
    ImGui::Columns(2, "script_cols", true);

    // 左：脚本编辑
    ImGui::SeparatorText(u8"脚本编辑器");
    ImGui::InputTextMultiline("##script_editor", script_code, IM_ARRAYSIZE(script_code),
                              ImVec2(-1, ImGui::GetContentRegionAvail().y - 60),
                              ImGuiInputTextFlags_AllowTabInput);
    if (ImGui::Button(u8"执行")) {
        std::string script(script_code);
        std::thread([script] {
            std::string result = g_socket.SendCommand("lua " + script, 20000);
            {
                std::lock_guard<std::mutex> lk(g_script_log_mutex);
                g_script_log += "> " + script + "\n" + result + "\n";
                if (g_script_log.size() > 60000)
                    g_script_log.erase(0, g_script_log.size() - 60000);
            }
            // 同步刷新日志水位，避免轮询重复显示本次同步日志
            std::string cnt = g_socket.SendCommand("lua_count", 2000);
            size_t n = SIZE_MAX;
            try { n = (size_t)std::stoull(cnt); } catch (...) {}
            if (n != SIZE_MAX) g_script_log_from.store(n);
        }).detach();
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"清空")) {
        script_code[0] = '\0';
        std::lock_guard<std::mutex> lk(g_script_log_mutex);
        g_script_log.clear();
    }
    ImGui::SameLine();
    ImGui::TextDisabled(u8"需先连接 agent");

    ImGui::NextColumn();

    // 轮询异步日志（call 闭包、hook 回调等产生），每 300ms 一次
    {
        static std::chrono::steady_clock::time_point g_last_log_poll{};
        auto now_tp = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now_tp - g_last_log_poll).count() >= 300) {
            g_last_log_poll = now_tp;
            if (g_socket.IsConnected()) {
                if (g_script_log_from.load() == SIZE_MAX) {
                    std::string cnt = g_socket.SendCommand("lua_count", 1500);
                    size_t n = SIZE_MAX;
                    try { n = (size_t)std::stoull(cnt); } catch (...) {}
                    if (n != SIZE_MAX) g_script_log_from.store(n);
                } else {
                    std::string resp = g_socket.SendCommand(
                        "lua_logs " + std::to_string(g_script_log_from.load()), 1500);
                    if (resp.rfind("错误:", 0) != 0 && !resp.empty()) {
                        size_t nl = resp.find('\n');
                        if (nl != std::string::npos) {
                            size_t n = SIZE_MAX;
                            try { n = (size_t)std::stoull(resp.substr(0, nl)); } catch (...) {}
                            if (n != SIZE_MAX) {
                                std::lock_guard<std::mutex> lk(g_script_log_mutex);
                                g_script_log += resp.substr(nl + 1);
                                if (g_script_log.size() > 60000)
                                    g_script_log.erase(0, g_script_log.size() - 60000);
                                g_script_log_from.store(n);
                            }
                        }
                    }
                }
            }
        }
    }

    // 右：日志输出
    ImGui::SeparatorText(u8"日志");
    std::string log_snapshot;
    {
        std::lock_guard<std::mutex> lk(g_script_log_mutex);
        log_snapshot = g_script_log;
    }
    ImGui::BeginChild("##log_view", ImVec2(-1, -1),
                      ImGuiChildFlags_Borders,
                      ImGuiWindowFlags_HorizontalScrollbar);
    // 长行（如 Lua 报错信息）会撑宽内容宽度，
    // 通过横向滚动条查看，而不是被裁剪。
    ImGui::TextUnformatted(log_snapshot.c_str());
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
    ImGui::Columns(1);
}

// --- 设置页面 -------------------------------------------------------------
void DrawSettings(UiState* state) {
    // 帧率限制
    ImGui::SeparatorText(u8"帧率");
    int fps_idx = FpsToIndex(state->target_fps);
    if (ImGui::Combo(u8"目标帧率", &fps_idx, kFpsLabels)) {
        state->target_fps = kFpsPresets[fps_idx];
    }
    ImGui::Text(u8"当前帧率: %.1f FPS", ImGui::GetIO().Framerate);

    ImGui::Spacing();
    ImGui::SeparatorText(u8"显示");

    // 辉光强度
    ImGui::Spacing();
    SliderFloatGrabValue(u8"辉光强度", &state->bloom_intensity, 0.0f, 2.5f, "%.2f");
    ImGui::TextWrapped(u8"0 关闭后处理，默认 0.75。亮元素按 luma > 0.6 参与辉光。");

    // 主题切换
    ImGui::Spacing();
    ImGui::SeparatorText(u8"主题");
    static int theme = 0;
    if (ImGui::Combo(u8"##theme", &theme, u8"深色\0浅色\0经典\0")) {
        switch (theme) {
            case 0: ImGui::StyleColorsDark();    break;
            case 1: ImGui::StyleColorsLight();   break;
            case 2: ImGui::StyleColorsClassic(); break;
        }
    }
}

// --- 保存页面 -------------------------------------------------------------
static void SaveLoadValues(int pid) {
    if (g_saved_loading.exchange(true)) return;
    std::thread([pid] {
        std::vector<uintptr_t> addrs;
        {
            std::lock_guard<std::mutex> lk(g_saved_mutex);
            for (const auto& r : g_saved_rows) addrs.push_back(r.addr);
        }

        std::vector<MemRegion> regions;
        {
            std::lock_guard<std::mutex> lk(g_mem_mutex);
            regions = g_mem_regions;
        }
        std::sort(regions.begin(), regions.end(),
                  [](const MemRegion& a, const MemRegion& b) {
                      return a.start < b.start;
                  });
        int arch = g_disasm_arch;

        std::vector<bool> ok(addrs.size(), false);
        std::vector<std::array<uint8_t, 16>> vals(addrs.size());
        std::vector<std::string> hexs(addrs.size());
        std::vector<std::string> disasm(addrs.size());
        std::vector<int> types(addrs.size(), kMemTypeCount - 1);
        for (size_t i = 0; i < addrs.size(); ++i) {
            ok[i] = ReadRemoteBytes(pid, addrs[i], vals[i].data(), vals[i].size());
            if (ok[i]) {
                hexs[i] = udt_disasm::BytesToHex(vals[i].data(), vals[i].size());
                disasm[i] = DisasmFirstLine(arch, vals[i].data(), vals[i].size());
                int ti = FindRegionTypeIdx(regions, addrs[i]);
                if (ti >= 0) types[i] = ti;
            }
        }

        {
            std::lock_guard<std::mutex> lk(g_saved_mutex);
            for (size_t i = 0; i < addrs.size(); ++i) {
                for (auto& r : g_saved_rows) {
                    if (r.addr == addrs[i]) {
                        r.ok = ok[i];
                        memcpy(r.bytes, vals[i].data(), 16);
                        r.hex = hexs[i];
                        r.disasm = disasm[i];
                        r.type = types[i];
                        break;
                    }
                }
            }
        }
        g_saved_loading.store(false);
    }).detach();
}

// ---- 断点类型/长度映射（与 root 断点服务协议一致） ----
static const char* kBpTypeItems = u8"执行(x)\0读取(r)\0写入(w)\0读写(rw)\0";
static const char* kBpLenItems  = "1\0" "2\0" "4\0" "8\0";
static const int   kBpLens[]    = {1, 2, 4, 8};

static const char* BpTypeLetter(int idx) {
    switch (idx) {
        case 1: return "r";
        case 2: return "w";
        case 3: return "rw";
        default: return "x";
    }
}

static int BpLenValue(int idx) {
    if (idx >= 0 && idx < 4) return kBpLens[idx];
    return 8;
}

// 一个可点击的堆栈 / 地址项。with_arrow == true 时在其前面绘制 "→"。
// 第一项（with_arrow == false）是起始地址，
// 标记为 "sp=0x..."。链条按单行绘制；当它超出
// 面板宽度时，内容子窗口的横向滚动条会出现，
// 而不是裁剪。点击自动跳转内存页（无需再按"跳转"）
// 。
static void DrawStackAddress(int pid, uint64_t val, bool with_arrow) {
    char lbl[40];
    if (with_arrow)
        snprintf(lbl, sizeof(lbl), "0x%llx", (unsigned long long)val);
    else
        snprintf(lbl, sizeof(lbl), "sp=0x%llx", (unsigned long long)val);
    if (with_arrow) {
        ImGui::SameLine();
        ImGui::TextUnformatted(u8"→");
        ImGui::SameLine();
    }
    if (ImGui::Button(lbl)) {
        g_mem_cont_mode = true;
        g_mem_cont_base = val & ~(uintptr_t)3;
        snprintf(g_mem_cont_base_buf, sizeof(g_mem_cont_base_buf), "%llx",
                 (unsigned long long)g_mem_cont_base);
        MemLoadCont(pid);
        RequestPage(Page::Memory);
    }
}

// --- 断点页面：断点服务 + 命中结果（寄存器网格） ----
static void DrawBreakpoint() {
    int pid = g_mem_pid.load();
    if (pid <= 0) {
        ImGui::SeparatorText(u8"断点");
        ImGui::TextDisabled(u8"请先在「选择」页选定目标进程");
        return;
    }

    // 断点服务
    ImGui::SeparatorText(u8"断点服务");
    {
        const bool bp_running = g_bp.IsRunning();
        const ImVec4 bp_col = bp_running
                                  ? ImVec4(0.32f, 0.90f, 0.45f, 1.0f)
                                  : ImVec4(0.85f, 0.35f, 0.35f, 1.0f);
        ImGui::TextColored(bp_col, u8"● %s", g_bp.Status().c_str());
        if (!bp_running) {
            if (ImGui::Button(u8"启动断点服务", ImVec2(130, 0))) {
                g_bp.Start(pid);
                // 重新同步保存页里已勾选的断点
                std::vector<SavedRow> sync_rows;
                {
                    std::lock_guard<std::mutex> lk(g_saved_mutex);
                    sync_rows = g_saved_rows;
                }
                for (const SavedRow& s : sync_rows) {
                    if (!s.bp) continue;
                    char c[96];
                    snprintf(c, sizeof(c), "set 0x%llx %s %d",
                             (unsigned long long)s.addr,
                             BpTypeLetter(s.bp_type), BpLenValue(s.bp_len));
                    g_bp.Send(c);
                }
            }
        } else {
            if (ImGui::Button(u8"停止断点服务", ImVec2(130, 0))) g_bp.Stop();
        }
        ImGui::SameLine();
        ImGui::TextDisabled(u8"目标 PID %d", pid);
        std::string bp_last = g_bp.LastLine();
        if (!bp_last.empty())
            ImGui::TextWrapped("%s", bp_last.c_str());
    }

    // 命中结果
    ImGui::SeparatorText(u8"命中结果");
    if (ImGui::Button(u8"清空结果")) g_bp.ClearHits();
    ImGui::SameLine();
    ImGui::TextDisabled(u8"共 %d 条，点击寄存器跳转内存", (int)g_bp.Hits().size());
    std::vector<BpHit> hits = g_bp.Hits();
    if (hits.empty()) {
        ImGui::TextDisabled(u8"暂无命中");
    } else {
        for (auto it = hits.rbegin(); it != hits.rend(); ++it) {
            const BpHit& h = *it;

            char addr_label[32];
            snprintf(addr_label, sizeof(addr_label), "0x%llx",
                     (unsigned long long)h.addr);
            float tw = ImGui::CalcTextSize(addr_label).x;
            ImGui::SetCursorPosX(
                (ImGui::GetContentRegionAvail().x - tw) * 0.5f);
            ImGui::Text("%s", addr_label);

            // PC 寄存器（可点击跳转）+ 该地址的汇编指令。
            char pc_label[40];
            snprintf(pc_label, sizeof(pc_label), "pc=0x%llx",
                     (unsigned long long)h.pc);
            float pw = ImGui::CalcTextSize(pc_label).x + ImGui::GetStyle().FramePadding.x * 2.0f;
            ImGui::SetCursorPosX(
                (ImGui::GetContentRegionAvail().x - pw) * 0.5f);
            if (ImGui::Button(pc_label)) {
                g_mem_cont_mode = true;
                g_mem_cont_base = (uintptr_t)h.pc & ~(uintptr_t)3;
                snprintf(g_mem_cont_base_buf, sizeof(g_mem_cont_base_buf),
                         "%llx", (unsigned long long)g_mem_cont_base);
                MemLoadCont(pid);
                RequestPage(Page::Memory);
            }
            if (!h.disasm.empty())
                ImGui::Text("指令: %s", h.disasm.c_str());

            char meta[96];
            snprintf(meta, sizeof(meta), "tid=%d", h.tid);
            ImGui::TextDisabled("%s", meta);

            // 寄存器网格：每行 3 个（自然流布局，滚动不会错位）。
            // 不用旧版 Columns()，因为 Columns(1) 之后的光标位置依赖内部
            // 实现，显式定位又会在滚动时错位导致多个结果重叠。
            for (size_t ri = 0; ri < h.regs.size(); ++ri) {
                const BpHitReg& r = h.regs[ri];
                char lbl[48];
                snprintf(lbl, sizeof(lbl), "%s 0x%llx",
                         r.name.c_str(), (unsigned long long)r.value);
                if (ri % 3 != 0) ImGui::SameLine();
                if (ImGui::Button(lbl)) {
                    g_mem_cont_mode = true;
                    g_mem_cont_base = (uintptr_t)r.value & ~(uintptr_t)3;
                    snprintf(g_mem_cont_base_buf, sizeof(g_mem_cont_base_buf),
                             "%llx", (unsigned long long)g_mem_cont_base);
                    MemLoadCont(pid);
                    RequestPage(Page::Memory);
                }
            }
            ImGui::NewLine();
            ImGui::Separator();   // ———— 分隔寄存器网格与堆栈链条
            // 堆栈链条：初始地址→地址1→地址2→...（每个地址可点击跳转）
            if (h.sp != 0 || !h.stack.empty()) {
                DrawStackAddress(pid, h.sp, false);
                for (size_t si = 0; si < h.stack.size(); ++si)
                    DrawStackAddress(pid, h.stack[si], true);
                ImGui::NewLine();
            }
        }
    }

    DrawMemEditWindow(pid);
}

static void DrawSave() {
    int pid = g_mem_pid.load();
    if (pid <= 0) {
        ImGui::SeparatorText(u8"保存的地址");
        ImGui::TextDisabled(u8"请先在「选择」页选定目标进程");
        return;
    }
    if (!g_mem_loaded.load()) {
        MemLoadForPid(pid);
        ImGui::SeparatorText(u8"保存的地址");
        ImGui::TextDisabled(u8"正在解析目标进程内存映射 (PID %d)...", pid);
        return;
    }

    // 仅在加载真正开始时消费脏标志，否则
    // 加载过程中请求的重新加载会丢失。
    if (g_saved_dirty.load() && !g_saved_loading.load()) {
        g_saved_dirty.store(false);
        SaveLoadValues(pid);
    }

    ImGui::SeparatorText(u8"保存的地址");
    ImGui::TextDisabled(u8"在内存页的「内存修改」窗口点「保存地址」可收藏当前地址");

    ImGui::Checkbox(u8"显示 HEX", &g_mem_hex_enabled);
    ImGui::SameLine();
    const char* valTypes = "DWORD\0FLOAT\0UTF8\0UTF16\0";
    ImGui::Combo(u8"数值类型", &g_mem_value_type, valTypes, 4);
    ImGui::SameLine();
    if (ImGui::Combo(u8"反汇编架构", &g_disasm_arch, u8"ARM64\0ARM\0"))
        g_saved_dirty.store(true);

    std::vector<SavedRow> rows;
    {
        std::lock_guard<std::mutex> lk(g_saved_mutex);
        rows = g_saved_rows;
    }
    if (rows.empty()) {
        ImGui::TextDisabled(u8"暂无保存的地址");
        return;
    }

    if (ImGui::Button(u8"刷新数值")) SaveLoadValues(pid);
    ImGui::SameLine();
    if (ImGui::Button(u8"清空")) {
        {
            std::lock_guard<std::mutex> lk(g_saved_mutex);
            if (g_bp.IsRunning()) {
                for (const auto& s : g_saved_rows) {
                    if (!s.bp) continue;
                    char c[64];
                    snprintf(c, sizeof(c), "clear 0x%llx",
                             (unsigned long long)s.addr);
                    g_bp.Send(c);
                }
            }
            g_saved_rows.clear();
        }
        g_saved_dirty.store(true);
    }
    ImGui::SameLine();
    ImGui::TextDisabled(u8"共 %d 条", (int)rows.size());

    for (size_t i = 0; i < rows.size(); ++i) {
        const SavedRow& r = rows[i];

        char label[64];
        snprintf(label, sizeof(label), "0x%llx", (unsigned long long)r.addr);
        if (ImGui::Button(label, ImVec2(150, 0))) {
            // 复用完整的内存编辑窗口（读 / 写 / 汇编 / 偏移 / ...）。
            g_edit_base = r.addr;
            g_edit_addr = r.addr;
            g_edit_offset = 0;
            snprintf(g_edit_offset_buf, sizeof(g_edit_offset_buf), "0");
            if (r.ok) {
                uint32_t v = 0;
                memcpy(&v, r.bytes, 4);
                snprintf(g_edit_value, sizeof(g_edit_value), "%u", v);
            } else {
                snprintf(g_edit_value, sizeof(g_edit_value), "0");
            }
            {
                std::lock_guard<std::mutex> lk(g_edit_mutex);
                g_edit_result.clear();
            }
            g_edit_open = true;
        }

        ImGui::SameLine();
        char valbuf[64];
        if (r.ok) {
            FormatValue(valbuf, sizeof(valbuf), g_mem_value_type,
                        r.bytes, 16);
        } else {
            snprintf(valbuf, sizeof(valbuf), "......");
        }
        ImGui::Text("%s", valbuf);

        // 第 2 行：原始十六进制字节。
        if (r.ok && !r.hex.empty())
            ImGui::TextDisabled("%s", r.hex.c_str());

        // 第 3 行：反汇编 + 内存类型。
        if (r.disasm.empty())
            ImGui::Text("%s", kMemTypes[r.type]);
        else
            ImGui::Text("%s  %s", r.disasm.c_str(), kMemTypes[r.type]);

        // 第 4 行：断点类型 / 长度 / 勾选 + 跳转 + 删除。
        char tpid[32];
        snprintf(tpid, sizeof(tpid), u8"类型##t%zu", i);
        int bt = r.bp_type;
        ImGui::SetNextItemWidth(84);
        if (ImGui::Combo(tpid, &bt, kBpTypeItems, 4)) {
            std::lock_guard<std::mutex> lk(g_saved_mutex);
            for (auto& s : g_saved_rows)
                if (s.addr == r.addr) { s.bp_type = bt; break; }
        }
        ImGui::SameLine();
        char lpid[32];
        snprintf(lpid, sizeof(lpid), u8"长度##l%zu", i);
        int bl = r.bp_len;
        ImGui::SetNextItemWidth(58);
        if (ImGui::Combo(lpid, &bl, kBpLenItems, 4)) {
            std::lock_guard<std::mutex> lk(g_saved_mutex);
            for (auto& s : g_saved_rows)
                if (s.addr == r.addr) { s.bp_len = bl; break; }
        }
        ImGui::SameLine();
        char bpid[32];
        snprintf(bpid, sizeof(bpid), u8"断点##bp%zu", i);
        bool bp = r.bp;
        if (ImGui::Checkbox(bpid, &bp)) {
            {
                std::lock_guard<std::mutex> lk(g_saved_mutex);
                for (auto& s : g_saved_rows)
                    if (s.addr == r.addr) { s.bp = bp; break; }
            }
            if (g_bp.IsRunning()) {
                char c[96];
                if (bp) {
                    snprintf(c, sizeof(c), "set 0x%llx %s %d",
                             (unsigned long long)r.addr,
                             BpTypeLetter(r.bp_type), BpLenValue(r.bp_len));
                } else {
                    snprintf(c, sizeof(c), "clear 0x%llx",
                             (unsigned long long)r.addr);
                }
                g_bp.Send(c);
            }
        }
        ImGui::SameLine();
        char jid[32];
        snprintf(jid, sizeof(jid), u8"跳转##j%zu", i);
        if (ImGui::Button(jid)) {
            g_mem_cont_mode = true;
            g_mem_cont_base = r.addr & ~(uintptr_t)3;
            snprintf(g_mem_cont_base_buf, sizeof(g_mem_cont_base_buf), "%llx",
                     (unsigned long long)g_mem_cont_base);
            MemLoadCont(pid);
            RequestPage(Page::Memory);
        }
        ImGui::SameLine();
        char did[32];
        snprintf(did, sizeof(did), u8"删除##d%zu", i);
        if (ImGui::Button(did)) {
            {
                std::lock_guard<std::mutex> lk(g_saved_mutex);
                g_saved_rows.erase(
                    std::remove_if(g_saved_rows.begin(), g_saved_rows.end(),
                                   [addr = r.addr](const SavedRow& s) {
                                       return s.addr == addr;
                                   }),
                    g_saved_rows.end());
            }
            g_saved_dirty.store(true);
        }
    }

    if (g_saved_loading.load())
        ImGui::TextDisabled(u8"加载中...");
    DrawMemEditWindow(pid);
}

// --- 搜索页面 -------------------------------------------------------------
static std::string TrimSpaces(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

static bool ParseSearchNum(const char* s, bool isFloat, int64_t& iout,
                           double& dout) {
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) return false;
    if (isFloat) {
        char* e = nullptr;
        dout = strtod(s, &e);
        if (!e || *e) return false;
        return true;
    }
    bool hex = (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'));
    char* e = nullptr;
    iout = strtoll(s, &e, hex ? 16 : 10);
    if (!e || *e) return false;
    return true;
}

static bool ParseSearchTarget(const char* s, int type, int64_t& iv,
                              double& dv, bool& isRange, int64_t& imin,
                              int64_t& imax, double& dmin, double& dmax) {
    std::string str = TrimSpaces(s ? s : "");
    if (str.empty()) return false;
    bool isFloat = (type == TYPE_FLOAT || type == TYPE_DOUBLE);
    size_t tilde = str.find(R_SEPARATE);
    if (tilde != std::string::npos) {
        isRange = true;
        std::string a = TrimSpaces(str.substr(0, tilde));
        std::string b = TrimSpaces(str.substr(tilde + 1));
        int64_t ia = 0, ib = 0;
        double da = 0, db = 0;
        if (!ParseSearchNum(a.c_str(), isFloat, ia, da) ||
            !ParseSearchNum(b.c_str(), isFloat, ib, db))
            return false;
        imin = ia; imax = ib; dmin = da; dmax = db;
        return true;
    }
    isRange = false;
    return ParseSearchNum(str.c_str(), isFloat, iv, dv);
}

static void ExtractSearchVal(const uint8_t* p, int type, int64_t& ival,
                             double& dval) {
    switch (type) {
    case TYPE_BYTE:   { int8_t  v; memcpy(&v, p, 1); ival = v; break; }
    case TYPE_WORD:   { int16_t v; memcpy(&v, p, 2); ival = v; break; }
    case TYPE_DWORD:  { int32_t v; memcpy(&v, p, 4); ival = v; break; }
    case TYPE_QWORD:  { int64_t v; memcpy(&v, p, 8); ival = v; break; }
    case TYPE_FLOAT:  { float   v; memcpy(&v, p, 4); dval = v; break; }
    case TYPE_DOUBLE: { double  v; memcpy(&v, p, 8); dval = v; break; }
    default: break;
    }
}

static void ReadSearchRaw(const uint8_t* p, int type, uint64_t& out) {
    int n = MemTypeSize(type);
    uint64_t v = 0;
    memcpy(&v, p, (size_t)n);
    out = v;
}

struct SearchMapRegion {
    uintptr_t   start = 0;
    uintptr_t   end = 0;
    std::string line;
};

static bool LoadSearchRegions(int pid, std::vector<SearchMapRegion>& out,
                              std::string& err) {
    std::string text = ReadRemoteMaps(pid);
    if (text.empty()) {
        err = "maps 读取为空 (需要 root？目标已退出？)";
        return false;
    }
    std::istringstream iss(text);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.size() < 20) continue;
        unsigned long long a = 0, b = 0;
        if (sscanf(line.c_str(), "%llx-%llx", &a, &b) != 2 || b <= a) continue;
        SearchMapRegion r;
        r.start = (uintptr_t)a;
        r.end = (uintptr_t)b;
        r.line = line;
        out.push_back(r);
    }
    return !out.empty();
}

static void SearchExactRun(int pid, std::vector<int> areas, int type,
                           std::string valueStr) {
    if (g_search_running.exchange(true)) return;
    std::thread([pid, areas, type, valueStr] {
        auto t0 = std::chrono::steady_clock::now();
        std::vector<SearchHit> hits;
        hits.reserve(8192);

        int64_t iv = 0, imin = 0, imax = 0;
        double dv = 0, dmin = 0, dmax = 0;
        bool isRange = false;
        if (!ParseSearchTarget(valueStr.c_str(), type, iv, dv, isRange,
                               imin, imax, dmin, dmax)) {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            g_search_status = u8"搜索值格式错误 (支持 100 / 0x64 / 10~20)";
            g_search_running.store(false);
            return;
        }

        bool isFloat = (type == TYPE_FLOAT || type == TYPE_DOUBLE);
        // 使用 MemorySearch 引擎（imgui 侧，su 后端）扫描
        MemSu mem(pid);
        SearchEngine engine(mem);
        SearchParams params;
        params.memTypeMask = 0;  // 0 = 全部区域
        for (int a : areas) {
            if (a == RANGE_ALL) { params.memTypeMask = 0; break; }
            params.memTypeMask |= (a == RANGE_OTHER) ? ((uint32_t)1u << 31)
                                                     : (uint32_t)a;
        }
        params.maxResults = kSearchMaxExact;
        params.align = true;
        params.parallel = true;
        params.numThreads = 4;  // 限制并发 su 管道数量，避免过载
        bool capped = false;

        auto collect = [&](uintptr_t addr, uint64_t raw) {
            if (hits.size() >= kSearchMaxExact) { capped = true; return; }
            SearchHit h;
            h.addr = addr;
            h.val = raw;
            hits.push_back(h);
        };
        auto runSearch = [&](auto* tag) {
            using T = std::decay_t<decltype(*tag)>;
            if (isRange) {
                long double lo = isFloat ? (long double)dmin
                                         : (long double)imin;
                long double hi = isFloat ? (long double)dmax
                                         : (long double)imax;
                // 范围超出类型宽度则无结果（与旧的按类型截断语义一致）
                if (lo < (long double)std::numeric_limits<T>::lowest() ||
                    hi > (long double)std::numeric_limits<T>::max())
                    return;
                auto rs = engine.searchRange<T>(params, (T)lo, (T)hi);
                for (const auto& r : rs.results()) {
                    if (capped) break;
                    uint64_t raw = 0;
                    memcpy(&raw, &r.value, sizeof(T) <= 8 ? sizeof(T) : 8);
                    collect(r.address, raw);
                }
            } else {
                long double v = isFloat ? (long double)dv
                                        : (long double)iv;
                auto rs = engine.search<T>(params, (T)v);
                for (const auto& r : rs.results()) {
                    if (capped) break;
                    uint64_t raw = 0;
                    memcpy(&raw, &r.value, sizeof(T) <= 8 ? sizeof(T) : 8);
                    collect(r.address, raw);
                }
            }
        };

        try {
            switch (type) {
            case TYPE_BYTE:   runSearch((int8_t*)nullptr);  break;
            case TYPE_WORD:   runSearch((int16_t*)nullptr); break;
            case TYPE_DWORD:  runSearch((int32_t*)nullptr); break;
            case TYPE_QWORD:  runSearch((int64_t*)nullptr); break;
            case TYPE_FLOAT:  runSearch((float*)nullptr);   break;
            case TYPE_DOUBLE: runSearch((double*)nullptr);  break;
            default:
                std::lock_guard<std::mutex> lk(g_search_mutex);
                g_search_status = u8"不支持的数值类型";
                g_search_running.store(false);
                return;
            }
        } catch (const std::exception& ex) {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            g_search_status = std::string("搜索异常: ") + ex.what();
            g_search_running.store(false);
            return;
        }

        double sec = std::chrono::duration<double>(
                         std::chrono::steady_clock::now() - t0)
                         .count();
        char msg[160];
        snprintf(msg, sizeof(msg), u8"精确搜索完成: %zu 个结果%s (耗时 %.1fs)",
                 hits.size(), capped ? u8" (已达上限)" : "", sec);
        {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            g_search_hits = std::move(hits);
            g_search_page = 0;
            g_search_hits_version++;
            g_search_status = msg;
        }
        g_search_running.store(false);
    }).detach();
}

static void SearchFuzzyInit(int pid, std::vector<int> areas, int type) {
    if (g_search_running.exchange(true)) return;
    std::thread([pid, areas, type] {
        auto t0 = std::chrono::steady_clock::now();
        std::vector<SearchHit> hits;
        hits.reserve(100000);

        std::vector<SearchMapRegion> regions;
        std::string err;
        if (!LoadSearchRegions(pid, regions, err)) {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            g_search_status = err;
            g_search_running.store(false);
            return;
        }

        const int stride = MemTypeSize(type);
        std::vector<uint8_t> buf(kSearchChunk);
        bool capped = false;
        for (const auto& reg : regions) {
            bool areaOk = false;
            for (int aid : areas)
                if (BCMAPSFLAG(reg.line.c_str(), aid)) { areaOk = true; break; }
            if (!areaOk) continue;
            uintptr_t start = (reg.start + 4095) & ~(uintptr_t)4095;
            uintptr_t end = reg.end & ~(uintptr_t)4095;
            for (uintptr_t addr = start; addr < end && !capped;
                 addr += kSearchChunk) {
                size_t want =
                    (size_t)std::min<uintptr_t>(kSearchChunk, end - addr);
                if (!ReadRemoteChunk(pid, addr, buf.data(), want)) continue;
                for (size_t i = 0; i + (size_t)stride <= want;
                     i += (size_t)stride) {
                    SearchHit h;
                    h.addr = addr + i;
                    ReadSearchRaw(buf.data() + i, type, h.val);
                    hits.push_back(h);
                    if (hits.size() >= kSearchMaxFuzzy) {
                        capped = true;
                        break;
                    }
                }
            }
        }

        double sec = std::chrono::duration<double>(
                         std::chrono::steady_clock::now() - t0)
                         .count();
        char msg[160];
        snprintf(msg, sizeof(msg),
                 u8"模糊搜索初始化完成: %zu 个地址%s (耗时 %.1fs)",
                 hits.size(), capped ? u8" (已达上限)" : "", sec);
        {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            g_search_hits = std::move(hits);
            g_search_page = 0;
            g_search_hits_version++;
            g_search_status = msg;
        }
        g_search_running.store(false);
    }).detach();
}

// 重新读取每个命中的当前数值（按类型大小），
// 只通过一次 su 调用获取包含命中的页面。读取
// 完全失败时返回 false。`values` 按相同顺序为每个命中保存一个值。
static bool ReadHitsCurrentValues(int pid, int type,
                                  const std::vector<SearchHit>& hits,
                                  std::vector<uint8_t>& values) {
    const int stride = MemTypeSize(type);
    std::vector<uintptr_t> pv;
    pv.reserve(hits.size() * 2);
    for (const auto& h : hits) {
        uintptr_t pg = h.addr & ~(uintptr_t)4095;
        pv.push_back(pg);
        if (((h.addr & 4095) + (uintptr_t)stride) > 4096)
            pv.push_back(pg + 4096);   // 数值跨入下一页
    }
    std::sort(pv.begin(), pv.end());
    pv.erase(std::unique(pv.begin(), pv.end()), pv.end());

    std::vector<uint8_t> pageData;
    if (!ReadRemotePages(pid, pv, pageData)) return false;

    values.resize(hits.size() * (size_t)stride);
    for (size_t i = 0; i < hits.size(); ++i) {
        const SearchHit& h = hits[i];
        uintptr_t pg = h.addr & ~(uintptr_t)4095;
        size_t pi = (size_t)(std::lower_bound(pv.begin(), pv.end(), pg) -
                             pv.begin());
        size_t off = (size_t)(h.addr & 4095);
        uint8_t* dst = values.data() + i * (size_t)stride;
        if (off + (size_t)stride <= 4096) {
            memcpy(dst, pageData.data() + pi * 4096 + off, (size_t)stride);
        } else {
            size_t first = 4096 - off;
            memcpy(dst, pageData.data() + pi * 4096 + off, first);
            memcpy(dst + first, pageData.data() + (pi + 1) * 4096,
                   (size_t)stride - first);
        }
    }
    return true;
}

// op: 0=未变化 1=已变化 2=变大 3=变小
static void SearchFuzzyFilter(int pid, int type, int op) {
    if (g_search_running.exchange(true)) return;
    std::thread([pid, type, op] {
        auto t0 = std::chrono::steady_clock::now();
        std::vector<SearchHit> hits;
        {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            hits = g_search_hits;
        }
        if (hits.empty()) {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            g_search_status = u8"请先初始化模糊搜索";
            g_search_running.store(false);
            return;
        }

        const int stride = MemTypeSize(type);
        const bool isFloat = (type == TYPE_FLOAT || type == TYPE_DOUBLE);
        std::vector<uint8_t> vals;
        if (!ReadHitsCurrentValues(pid, type, hits, vals)) {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            g_search_status = u8"读取失败 (目标已退出或未授权)";
            g_search_running.store(false);
            return;
        }

        std::vector<SearchHit> kept;
        kept.reserve(hits.size());
        for (size_t i = 0; i < hits.size(); ++i) {
            const SearchHit& h = hits[i];
            int64_t ival = 0, oiv = 0;
            double dval = 0, odv = 0;
            ExtractSearchVal(vals.data() + i * (size_t)stride, type, ival, dval);
            ExtractSearchVal((const uint8_t*)&h.val, type, oiv, odv);
            bool keep = false;
            if (isFloat) {
                switch (op) {
                case 0: keep = (dval == odv); break;
                case 1: keep = (dval != odv); break;
                case 2: keep = (dval > odv);  break;
                case 3: keep = (dval < odv);  break;
                default: break;
                }
            } else {
                switch (op) {
                case 0: keep = (ival == oiv); break;
                case 1: keep = (ival != oiv); break;
                case 2: keep = (ival > oiv);  break;
                case 3: keep = (ival < oiv);  break;
                default: break;
                }
            }
            if (keep) {
                SearchHit nh = h;
                ReadSearchRaw(vals.data() + i * (size_t)stride, type, nh.val);
                kept.push_back(nh);
            }
        }

        double sec = std::chrono::duration<double>(
                         std::chrono::steady_clock::now() - t0)
                         .count();
        static const char* kOpName[] = {
            u8"未变化", u8"已变化", u8"变大", u8"变小"};
        char msg[160];
        snprintf(msg, sizeof(msg), u8"模糊过滤(%s): %zu 个结果 (耗时 %.1fs)",
                 kOpName[op], kept.size(), sec);
        {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            g_search_hits = std::move(kept);
            g_search_page = 0;
            g_search_hits_version++;
            g_search_status = msg;
        }
        g_search_running.store(false);
    }).detach();
}

// 改善：在当前结果内按新值（或范围）再次精确筛选。
static void SearchRefineExact(int pid, int type, const std::string& value) {
    if (g_search_running.exchange(true)) return;
    std::thread([pid, type, value] {
        auto t0 = std::chrono::steady_clock::now();
        std::vector<SearchHit> hits;
        {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            hits = g_search_hits;
        }
        if (hits.empty()) {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            g_search_status = u8"请先搜索";
            g_search_running.store(false);
            return;
        }

        // 第一步：刷新这批地址的当前数值。
        {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            g_search_status =
                u8"正在刷新 " + std::to_string(hits.size()) + u8" 个地址...";
        }

        int64_t iv = 0;
        double  dv = 0;
        bool    isRange = false;
        int64_t imin = 0, imax = 0;
        double  dmin = 0, dmax = 0;
        if (!ParseSearchTarget(value.c_str(), type, iv, dv, isRange,
                               imin, imax, dmin, dmax)) {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            g_search_status = u8"数值格式错误";
            g_search_running.store(false);
            return;
        }

        const bool isFloat = (type == TYPE_FLOAT || type == TYPE_DOUBLE);
        const int stride = MemTypeSize(type);
        std::vector<uint8_t> vals;
        if (!ReadHitsCurrentValues(pid, type, hits, vals)) {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            g_search_status = u8"读取失败 (目标已退出或未授权)";
            g_search_running.store(false);
            return;
        }

        // 第二步：只保留数值匹配的新地址。
        std::vector<SearchHit> kept;
        kept.reserve(hits.size());
        for (size_t i = 0; i < hits.size(); ++i) {
            const SearchHit& h = hits[i];
            int64_t ival = 0;
            double  dval = 0;
            ExtractSearchVal(vals.data() + i * (size_t)stride, type, ival, dval);
            bool match = isFloat
                ? (isRange ? (dval >= dmin && dval <= dmax) : dval == dv)
                : (isRange ? (ival >= imin && ival <= imax) : ival == iv);
            if (match) {
                SearchHit nh = h;
                ReadSearchRaw(vals.data() + i * (size_t)stride, type, nh.val);
                kept.push_back(nh);
            }
        }

        double sec = std::chrono::duration<double>(
                         std::chrono::steady_clock::now() - t0)
                         .count();
        char msg[160];
        snprintf(msg, sizeof(msg), u8"改善完成: %zu 个结果 (耗时 %.1fs)",
                 kept.size(), sec);
        {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            g_search_hits = std::move(kept);
            g_search_page = 0;
            g_search_hits_version++;
            g_search_status = msg;
        }
        g_search_running.store(false);
    }).detach();
}

static void SearchFormatValue(char* out, size_t outsz, int type,
                              uint64_t raw) {
    switch (type) {
    case TYPE_BYTE: {
        uint8_t v = (uint8_t)raw;
        if (g_mem_hex_enabled) snprintf(out, outsz, "0x%02X", v);
        else snprintf(out, outsz, "%u", (unsigned)v);
        break;
    }
    case TYPE_WORD: {
        uint16_t v = (uint16_t)raw;
        if (g_mem_hex_enabled) snprintf(out, outsz, "0x%04X", v);
        else snprintf(out, outsz, "%u", (unsigned)v);
        break;
    }
    case TYPE_DWORD: {
        uint32_t v = (uint32_t)raw;
        if (g_mem_hex_enabled) snprintf(out, outsz, "0x%08X", v);
        else snprintf(out, outsz, "%u", v);
        break;
    }
    case TYPE_QWORD: {
        if (g_mem_hex_enabled)
            snprintf(out, outsz, "0x%llX", (unsigned long long)raw);
        else
            snprintf(out, outsz, "%llu", (unsigned long long)raw);
        break;
    }
    case TYPE_FLOAT: {
        float f;
        memcpy(&f, &raw, 4);
        snprintf(out, outsz, "%.4f", f);
        break;
    }
    case TYPE_DOUBLE: {
        double d;
        memcpy(&d, &raw, 8);
        snprintf(out, outsz, "%.4f", d);
        break;
    }
    default:
        snprintf(out, outsz, "?");
        break;
    }
}

static void SearchValueToEdit(int type, uint64_t raw, char* out, size_t n) {
    switch (type) {
    case TYPE_BYTE:   snprintf(out, n, "%u", (unsigned)(uint8_t)raw); break;
    case TYPE_WORD:   snprintf(out, n, "%u", (unsigned)(uint16_t)raw); break;
    case TYPE_DWORD:  snprintf(out, n, "%u", (unsigned)(uint32_t)raw); break;
    case TYPE_QWORD:  snprintf(out, n, "%llu", (unsigned long long)raw); break;
    case TYPE_FLOAT:  { float f; memcpy(&f, &raw, 4); snprintf(out, n, "%.4f", f); break; }
    case TYPE_DOUBLE: { double d; memcpy(&d, &raw, 8); snprintf(out, n, "%.4f", d); break; }
    default:          snprintf(out, n, "0"); break;
    }
}

static void SearchLoadPage(int pid, int page, uint64_t version,
                           const std::vector<uintptr_t>& addrs) {
    if (g_search_page_loading.exchange(true)) return;
    std::thread([pid, page, version, addrs] {
        std::vector<MemRegion> regions;
        {
            std::lock_guard<std::mutex> lk(g_mem_mutex);
            regions = g_mem_regions;
        }
        std::sort(regions.begin(), regions.end(),
                  [](const MemRegion& a, const MemRegion& b) {
                      return a.start < b.start;
                  });
        int arch = g_disasm_arch;
        uint8_t bytes[kSearchPageSize][16] = {{0}};
        bool ok[kSearchPageSize] = {false};
        std::string disasm[kSearchPageSize];
        int type[kSearchPageSize];
        for (int i = 0; i < kSearchPageSize; ++i) type[i] = kMemTypeCount - 1;
        for (size_t i = 0; i < addrs.size() && i < kSearchPageSize; ++i) {
            ok[i] = ReadRemoteBytes(pid, addrs[i], bytes[i], 16);
            if (ok[i]) {
                disasm[i] = DisasmFirstLine(arch, bytes[i], 16);
                int ti = FindRegionTypeIdx(regions, addrs[i]);
                if (ti >= 0) type[i] = ti;
            }
        }
        {
            std::lock_guard<std::mutex> lk(g_search_mutex);
            for (int i = 0; i < kSearchPageSize; ++i) {
                g_search_page_ok[i] =
                    (size_t)i < addrs.size() && ok[i];
                g_search_page_type[i] = type[i];
                g_search_page_disasm[i] = disasm[i];
                if ((size_t)i < addrs.size())
                    memcpy(g_search_page_bytes[i], bytes[i], 16);
            }
            g_search_loaded_page = page;
            g_search_loaded_version = version;
        }
        g_search_page_loading.store(false);
    }).detach();
}

static void DrawSearch() {
    int pid = g_mem_pid.load();
    if (pid <= 0) {
        ImGui::SeparatorText(u8"内存搜索");
        ImGui::TextDisabled(u8"请先在「选择」页选定目标进程");
        return;
    }
    if (!g_mem_loaded.load()) {
        MemLoadForPid(pid);
        ImGui::SeparatorText(u8"内存搜索");
        ImGui::TextDisabled(u8"正在解析目标进程内存映射 (PID %d)...", pid);
        return;
    }

    ImGui::SeparatorText(u8"内存搜索");
    ImGui::TextDisabled(u8"范围格式: 10~20");

    // 内存类型：多选（与内存页共享勾选状态，未勾选 = 全部）
    if (ImGui::CollapsingHeader(u8"内存类型（多选，未勾选 = 全部）",
                                ImGuiTreeNodeFlags_DefaultOpen)) {
        bool anyChanged = false;
        ImGui::Columns(3, "searchareacols", false);
        for (int i = 0; i < kMemTypeCount; ++i) {
            if (ImGui::Checkbox(kMemTypes[i], &g_mem_type_show[i]))
                anyChanged = true;
            ImGui::NextColumn();
        }
        ImGui::Columns(1);
        if (ImGui::Button(u8"全选")) {
            for (int i = 0; i < kMemTypeCount; ++i) g_mem_type_show[i] = true;
            anyChanged = true;
        }
        ImGui::SameLine();
        if (ImGui::Button(u8"全不选")) {
            for (int i = 0; i < kMemTypeCount; ++i) g_mem_type_show[i] = false;
            anyChanged = true;
        }
        if (anyChanged) SaveMemTypeConfig();
    }

    static const int kTypeIds[] = {
        TYPE_BYTE, TYPE_WORD, TYPE_DWORD, TYPE_QWORD, TYPE_FLOAT, TYPE_DOUBLE};
    static const int kTypeCount =
        (int)(sizeof(kTypeIds) / sizeof(kTypeIds[0]));
    static const char* kTypeNames[] = {
        "BYTE [B]", "WORD [W]", "DWORD [D]", "QWORD [Q]",
        "FLOAT [F]", "DOUBLE [E]"
    };
    int typeIdx = 0;
    for (int i = 0; i < kTypeCount; ++i)
        if (g_search_type == kTypeIds[i]) { typeIdx = i; break; }
    if (ImGui::Combo(u8"数值类型", &typeIdx, kTypeNames, kTypeCount))
        g_search_type = kTypeIds[typeIdx];

    if (ImGui::Combo(u8"搜索方式", &g_search_mode,
                     u8"精确搜索\0模糊搜索\0"))
        g_search_page = 0;

    bool busy = g_search_running.load();
    if (g_search_mode == kSearchExact) {
        ImGui::SetNextItemWidth(240.0f);
        ImGui::InputText(u8"搜索值", g_search_value, sizeof(g_search_value));
        ImGui::SameLine();
        if (ImGui::Button(u8"搜索") && !busy) {
            std::vector<int> sel;
            for (int i = 0; i < kMemTypeCount; ++i)
                if (g_mem_type_show[i]) sel.push_back((int)kMemTypeFlags[i]);
            if (sel.empty())  // 未勾选 = 全部内存类型
                for (int i = 0; i < kMemTypeCount; ++i)
                    sel.push_back((int)kMemTypeFlags[i]);
            SearchExactRun(pid, sel, g_search_type, g_search_value);
        }
        ImGui::SameLine();
        if (ImGui::Button(u8"改善") && !busy)
            SearchRefineExact(pid, g_search_type, g_search_value);
    } else {
        if (ImGui::Button(u8"初始化模糊搜索") && !busy) {
            std::vector<int> sel;
            for (int i = 0; i < kMemTypeCount; ++i)
                if (g_mem_type_show[i]) sel.push_back((int)kMemTypeFlags[i]);
            if (sel.empty())  // 未勾选 = 全部内存类型
                for (int i = 0; i < kMemTypeCount; ++i)
                    sel.push_back((int)kMemTypeFlags[i]);
            SearchFuzzyInit(pid, sel, g_search_type);
        }
        ImGui::SameLine();
        if (ImGui::Button(u8"未变化") && !busy)
            SearchFuzzyFilter(pid, g_search_type, 0);
        ImGui::SameLine();
        if (ImGui::Button(u8"已变化") && !busy)
            SearchFuzzyFilter(pid, g_search_type, 1);
        ImGui::SameLine();
        if (ImGui::Button(u8"变大") && !busy)
            SearchFuzzyFilter(pid, g_search_type, 2);
        ImGui::SameLine();
        if (ImGui::Button(u8"变小") && !busy)
            SearchFuzzyFilter(pid, g_search_type, 3);
    }
    ImGui::SameLine();
    if (ImGui::Button(u8"清除结果") && !busy) {
        std::lock_guard<std::mutex> lk(g_search_mutex);
        g_search_hits.clear();
        g_search_status.clear();
        g_search_page = 0;
        g_search_hits_version++;
        g_search_loaded_page = -1;
        g_search_loaded_version = 0;
    }

    std::string status;
    size_t count = 0;
    int page = 0;
    uint64_t version = 0;
    {
        std::lock_guard<std::mutex> lk(g_search_mutex);
        status = g_search_status;
        count = g_search_hits.size();
        page = g_search_page;
        version = g_search_hits_version;
    }
    if (busy)
        ImGui::TextColored(ImVec4(0.95f, 0.72f, 0.20f, 1.0f), u8"搜索中...");
    ImGui::TextDisabled("%s", status.empty() ? u8"尚未搜索" : status.c_str());

    if (count == 0) {
        DrawMemEditWindow(pid);
        return;
    }

    int totalPages = (int)((count + kSearchPageSize - 1) / kSearchPageSize);
    {
        std::lock_guard<std::mutex> lk(g_search_mutex);
        if (g_search_page < 0) g_search_page = 0;
        if (g_search_page >= totalPages) g_search_page = totalPages - 1;
    }

    if (ImGui::Button(u8"上一页") && g_search_page > 0) g_search_page--;
    ImGui::SameLine();
    if (ImGui::Button(u8"下一页") && g_search_page + 1 < totalPages)
        g_search_page++;
    ImGui::SameLine();
    if (ImGui::Button(u8"刷新数值"))
        g_search_loaded_version = 0;  // 强制页面重新加载
    ImGui::SameLine();
    ImGui::Text(u8"第 %d/%d 页  共 %zu 条", g_search_page + 1, totalPages,
                count);

    // 按需加载可见页的数值字节 / 反汇编。
    std::vector<SearchHit> hits;
    {
        std::lock_guard<std::mutex> lk(g_search_mutex);
        hits = g_search_hits;
        page = g_search_page;
        version = g_search_hits_version;
    }
    if (!g_search_page_loading.load() &&
        (g_search_loaded_page != page ||
         g_search_loaded_version != version)) {
        std::vector<uintptr_t> addrs;
        int start = page * kSearchPageSize;
        for (int i = start; i < start + kSearchPageSize &&
                            (size_t)i < hits.size(); ++i)
            addrs.push_back(hits[i].addr);
        SearchLoadPage(pid, page, version, addrs);
    }

    // 在锁内快照分页显示缓存。
    bool page_ok[kSearchPageSize];
    int  page_type[kSearchPageSize];
    std::string page_disasm[kSearchPageSize];
    {
        std::lock_guard<std::mutex> lk(g_search_mutex);
        for (int i = 0; i < kSearchPageSize; ++i) {
            page_ok[i] = g_search_page_ok[i];
            page_type[i] = g_search_page_type[i];
            page_disasm[i] = g_search_page_disasm[i];
        }
    }

    for (int i = 0; i < kSearchPageSize; ++i) {
        size_t idx = (size_t)page * kSearchPageSize + (size_t)i;
        if (idx >= hits.size()) break;
        const SearchHit& h = hits[idx];

        char label[64];
        snprintf(label, sizeof(label), "0x%llx", (unsigned long long)h.addr);
        if (ImGui::Button(label, ImVec2(150, 0))) {
            g_edit_base = h.addr;
            g_edit_addr = h.addr;
            g_edit_offset = 0;
            snprintf(g_edit_offset_buf, sizeof(g_edit_offset_buf), "0");
            SearchValueToEdit(g_search_type, h.val, g_edit_value,
                              sizeof(g_edit_value));
            {
                std::lock_guard<std::mutex> lk(g_edit_mutex);
                g_edit_result.clear();
            }
            g_edit_open = true;
        }
        ImGui::SameLine();
        char valbuf[64];
        SearchFormatValue(valbuf, sizeof(valbuf), g_search_type, h.val);
        ImGui::Text("%s", valbuf);

        // 第 2 行：反汇编 + 内存类型（按页加载）。
        if (page_ok[i]) {
            if (page_disasm[i].empty())
                ImGui::Text("%s", kMemTypes[page_type[i]]);
            else
                ImGui::Text("%s  %s", page_disasm[i].c_str(),
                            kMemTypes[page_type[i]]);
        } else {
            ImGui::TextDisabled(u8"加载中...");
        }
    }

    DrawMemEditWindow(pid);
}

} // 匿名命名空间

void RequestPage(Page page) {
    g_requested_page.store((int)page);
}

int ConsumeRequestedPage() {
    return g_requested_page.exchange(-1);
}

void DrawPage(UiState* state, Page page) {
    switch (page) {
        case Page::SelectProcess: DrawSelectProcess(state); break;
        case Page::Search:        DrawSearch();             break;
        case Page::Memory:
            if (state->mem_lib_close_request) {
                g_lib_open = false;
                g_edit_open = false;
                state->mem_lib_close_request = false;
            }
            DrawMemory();
            break;
        case Page::Breakpoint:   DrawBreakpoint();         break;
        case Page::Save:          DrawSave();               break;
        case Page::Script:        DrawScript();             break;
        case Page::Settings:      DrawSettings(state);      break;
    }

    // 任何打开的子窗口（链接库列表、内存编辑等）都会扩展
    // 悬浮层，使其能在屏幕任意位置拖动。新增带
    // 独立开关标志的子窗口时，在这里补充。
    SetOverlayExpanded((page == Page::Search || page == Page::Memory ||
                        page == Page::Breakpoint || page == Page::Save) &&
                       (g_lib_open || g_edit_open));
}

// ── 目标进程存活监控 ─────────────────────────────────────────────
// 目标进程销毁后自动清空断点结果、保存地址、搜索结果等状态。
// GUI 进程非 root：pidfd / 直接读 /proc/<pid>/stat 对其它 App 都会
// 被 SELinux 拒绝，因此存在性检查用 kill(pid, 0)（ESRCH = 不存在，
// EPERM = 存在但无权限）；starttime 防 PID 复用则通过 su 读取并低频复核。
static int      g_alive_pid = 0;
static uint64_t g_alive_starttime = 0;   // /proc/<pid>/stat 第 22 字段（su 读取）
static int      g_alive_check_count = 0; // 每 5 次检查做一次 su 复核
static std::chrono::steady_clock::time_point g_alive_last_check{};

// 从 stat 文本解析进程状态（第 3 字段）与 starttime（第 22 字段）。
// comm 可能含空格 / 括号，先做括号配对跳过。
static bool ParseStatText(const std::string& text, uint64_t& starttime,
                          bool& zombie) {
    starttime = 0;
    zombie = false;
    size_t lp = text.find('(');
    if (lp == std::string::npos) return false;
    size_t depth = 0;
    size_t rp = std::string::npos;
    for (size_t i = lp; i < text.size(); ++i) {
        if (text[i] == '(') depth++;
        else if (text[i] == ')') {
            depth--;
            if (depth == 0) { rp = i; break; }
        }
    }
    if (rp == std::string::npos) return false;

    std::istringstream iss(text.substr(rp + 1));
    std::string state;
    if (!(iss >> state) || state.empty()) return false;
    zombie = (state[0] == 'Z');
    std::string tok;
    for (int i = 0; i < 18; ++i)  // 跳过第 4..21 字段
        if (!(iss >> tok)) return false;
    unsigned long long st = 0;
    if (!(iss >> st)) return false;
    starttime = (uint64_t)st;
    return true;
}

// 绑定目标：通过 su 记录 starttime 快照。
static void BindTargetAlive(int pid) {
    g_alive_pid = pid;
    g_alive_starttime = 0;
    g_alive_check_count = 0;
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "cat /proc/%d/stat", pid);
    std::string txt = RunSuCommand(cmd);
    uint64_t st = 0;
    bool z = false;
    if (!txt.empty() && ParseStatText(txt, st, z)) g_alive_starttime = st;
    g_alive_last_check = std::chrono::steady_clock::now();
}

static bool TargetProcessAlive() {
    if (g_alive_pid <= 0) return true;
    // 存在性检查：非 root 也能用 kill(pid, 0) 区分不存在（ESRCH）
    // 与存在但无权限（EPERM）。
    if (kill(g_alive_pid, 0) != 0 && errno == ESRCH) return false;
    // 周期性（每 5 次检查）通过 su 复核 starttime，防 PID 复用
    if (++g_alive_check_count >= 5) {
        g_alive_check_count = 0;
        if (g_alive_starttime != 0) {
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "cat /proc/%d/stat", g_alive_pid);
            std::string txt = RunSuCommand(cmd);
            uint64_t st = 0;
            bool z = false;
            if (txt.empty() || !ParseStatText(txt, st, z)) {
                // su 读取失败（瞬时故障）保守按存活处理，交给 kill 判定
                return true;
            }
            if (z || st != g_alive_starttime) return false;  // 僵尸 / PID 复用
        }
    }
    return true;
}

// 目标进程销毁：清空与目标相关的全部状态。
static void ResetTargetState() {
    g_bp.Stop();
    g_bp.ClearHits();
    {
        std::lock_guard<std::mutex> lk(g_saved_mutex);
        g_saved_rows.clear();
    }
    g_saved_dirty.store(true);
    {
        std::lock_guard<std::mutex> lk(g_search_mutex);
        g_search_hits.clear();
        g_search_page = 0;
        g_search_status = u8"目标进程已退出，相关状态已自动重置";
        g_search_hits_version++;
    }
    {
        std::lock_guard<std::mutex> lk(g_mem_mutex);
        g_mem_regions.clear();
    }
    g_mem_loaded.store(false);
    g_mem_loading.store(false);
    g_mem_page = 0;
    g_mem_cont_count = 0;
    {
        std::lock_guard<std::mutex> lk(g_lib_mutex);
        g_lib_list.clear();
    }
    g_lib_fetching.store(false);
    g_mem_pid.store(0);
    g_alive_pid = 0;
    g_alive_starttime = 0;
    g_alive_check_count = 0;
}

void CheckTargetAlive() {
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::milliseconds>(
            now - g_alive_last_check).count() < 1000)
        return;
    g_alive_last_check = now;
    if (g_alive_pid <= 0) return;
    if (!TargetProcessAlive()) ResetTargetState();
}

// ── 内存类型配置持久化 ────────────────────────────────────────────
// 把内存页 / 搜索页共享的内存类型勾选状态保存到 App 私有 files 目录，
// 启动时恢复。格式：mem_types=0101...（14 个 '0'/'1'）。
static void SaveMemTypeConfig() {
    std::string path = GetConfigFilePath();
    if (path.empty()) return;
    std::string line = "mem_types=";
    for (int i = 0; i < kMemTypeCount; ++i)
        line += g_mem_type_show[i] ? '1' : '0';
    line += "\n";
    std::ofstream ofs(path, std::ios::trunc);
    if (ofs) ofs << line;
}

static void LoadMemTypeConfig() {
    std::string path = GetConfigFilePath();
    if (path.empty()) return;
    std::ifstream ifs(path);
    std::string line;
    while (std::getline(ifs, line)) {
        if (line.rfind("mem_types=", 0) != 0) continue;
        const char* v = line.c_str() + 10;
        for (int i = 0; i < kMemTypeCount && v[i]; ++i)
            g_mem_type_show[i] = (v[i] == '1');
        break;
    }
}

void LoadMemTypeConfigOnce() {
    static bool loaded = false;
    if (!loaded) {
        loaded = true;
        LoadMemTypeConfig();
    }
}

} // 命名空间 aimgui

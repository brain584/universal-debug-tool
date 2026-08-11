#pragma once
#ifndef PROCMAP_HPP
#define PROCMAP_HPP

#include <cstdint>
#include <string>
namespace MemType
{
    constexpr uint32_t RANGE_ALL        = 0;            // 所有内存区域 (all)
    constexpr uint32_t RANGE_C_HEAP     = 1 << 0;       // C++ 堆内存 (ch)
    constexpr uint32_t RANGE_JAVA_HEAP  = 1 << 1;       // Java 虚拟机堆内存 (jh)
    constexpr uint32_t RANGE_C_ALLOC    = 1 << 2;       // C++ 分配器内存 (ca)
    constexpr uint32_t RANGE_C_DATA     = 1 << 3;       // C++ 数据段 (cd)
    constexpr uint32_t RANGE_C_BSS      = 1 << 4;       // C++ BSS 段 (cb)
    constexpr uint32_t RANGE_ANONYMOUS  = 1 << 5;       // 匿名内存区域 (a)
    constexpr uint32_t RANGE_STACK      = 1 << 6;       // 栈内存区域 (s)
    constexpr uint32_t RANGE_CODE_APP   = 1 << 14;      // 应用程序代码段 (xa)
    constexpr uint32_t RANGE_CODE_SYSTEM= 1 << 15;      // 系统代码段 (xs)
    constexpr uint32_t RANGE_JAVA       = 1 << 16;      // Java 虚拟机内存 (j)
    constexpr uint32_t RANGE_B_BAD      = 1 << 17;      // 坏内存区域 (b)
    constexpr uint32_t RANGE_ASHMEM     = 1 << 19;      // Android 共享内存 (as)
    constexpr uint32_t RANGE_VIDEO      = 1 << 20;      // 视频内存区域 (v)
    constexpr uint32_t RANGE_FILE_DATA  = 1 << 21;      // 文件映射数据 (fd)
    constexpr uint32_t RANGE_OTHER      = 1 << 31;      // 其他/未知 (o)
    constexpr uint32_t RANGE_NULL_PAGE  = 99999;        // 空页或无效内存 (null)

    // 常用组合
    constexpr uint32_t RANGE_RW         = RANGE_C_HEAP | RANGE_C_ALLOC | RANGE_C_DATA |
                                          RANGE_C_BSS | RANGE_ANONYMOUS | RANGE_STACK |
                                          RANGE_JAVA_HEAP | RANGE_FILE_DATA;
    constexpr uint32_t RANGE_RX         = RANGE_CODE_APP | RANGE_CODE_SYSTEM;
}
class ProcMap
{
public:
    uintptr_t startAddress;
    uintptr_t endAddress;
    size_t length;
    int protection;
    bool readable, writeable, executable, is_private, is_shared, is_ro, is_rw, is_rx;
    unsigned long long offset;
    std::string dev;
    unsigned long inode;
    std::string pathname;

    inline uint32_t getMemType() const
    {
        // 不可读的区域 → 标记为 OTHER (实际搜索时会被过滤)
        if (!readable)
        {
            return MemType::RANGE_OTHER;
        }

        // ── 1. 匿名区域 ──────────────────────────────
        if (pathname.empty())
        {
            if (writeable && !executable && is_private)
                return MemType::RANGE_ANONYMOUS;
            if (executable && is_private)
                return MemType::RANGE_CODE_APP;  // JIT 代码
            return MemType::RANGE_OTHER;
        }

        // ── 2. 特殊命名映射 ──────────────────────────
        if (pathname == "[heap]")
            return MemType::RANGE_C_HEAP;
        if (pathname.find("[stack") == 0)
            return MemType::RANGE_STACK;
        if (pathname == "[anon:.bss]")
            return MemType::RANGE_C_BSS;
        if (pathname.find("[anon:libc_malloc]") == 0 ||
            pathname.find("[anon:scudo") == 0)
            return MemType::RANGE_C_ALLOC;
        if (pathname == "[vdso]" || pathname == "[vsyscall]" || pathname == "[vvar]")
            return MemType::RANGE_CODE_SYSTEM;

        // ── 3. 坏内存 (GPU/字体) ─────────────────────
        if (pathname.find("kgsl-3d0") != std::string::npos ||
            pathname.find(".ttf") != std::string::npos)
            return MemType::RANGE_B_BAD;

        // ── 4. 视频内存 ──────────────────────────────
        if (pathname.find("/dev/mali") != std::string::npos ||
            pathname.find("/dev/ion") != std::string::npos)
            return MemType::RANGE_VIDEO;

        // ── 5. Ashmem ────────────────────────────────
        if (pathname.find("/dev/ashmem") != std::string::npos)
        {
            if (executable) return MemType::RANGE_CODE_APP;
            return MemType::RANGE_ASHMEM;
        }

        // ── 6. Dalvik/Java ───────────────────────────
        bool is_dalvik = (pathname.find("dalvik-") != std::string::npos);
        bool is_dex_jar_apk = (pathname.find(".dex") != std::string::npos ||
                               pathname.find(".jar") != std::string::npos ||
                               pathname.find(".apk") != std::string::npos);
        if (is_dalvik || is_dex_jar_apk)
        {
            if (readable && writeable && !executable)
                return MemType::RANGE_JAVA_HEAP;
            if (executable)
                return MemType::RANGE_CODE_APP;
            return MemType::RANGE_JAVA;
        }

        // ── 7. 路径前缀判断 (文件映射) ────────────────
        bool is_system_path = (pathname.find("/system/") == 0 ||
                               pathname.find("/vendor/") == 0 ||
                               pathname.find("/apex/") == 0 ||
                               pathname.find("/product/") == 0 ||
                               pathname.find("/memfd") == 0);
        bool is_file_path = (pathname[0] == '/');

        // 可执行 → 代码段
        if (executable)
        {
            if (is_system_path)
                return MemType::RANGE_CODE_SYSTEM;
            return MemType::RANGE_CODE_APP;
        }

        // 可读写文件映射 → C_DATA (私有) 或 FILE_DATA
        if (readable && writeable && is_private && is_file_path)
            return MemType::RANGE_C_DATA;

        // 只读/共享文件映射 → FILE_DATA (如 .so 数据段, 资源文件等)
        if (readable && is_file_path)
            return MemType::RANGE_FILE_DATA;

        // ── 8. 兜底 ──────────────────────────────────
        return MemType::RANGE_OTHER;
    }

    ProcMap() : startAddress(0), endAddress(0), length(0), protection(0),
                readable(false), writeable(false), executable(false),
                is_private(false), is_shared(false),
                is_ro(false), is_rw(false), is_rx(false),
                offset(0), inode(0) {}

    inline bool isValid() const { return (startAddress && endAddress && length); }
    inline bool isUnknown() const { return pathname.empty(); }
    inline bool contains(uintptr_t address) const { return address >= startAddress && address < endAddress; }
    inline std::string toString() const
    {
        char sharing = is_private ? 'p' : (is_shared ? 's' : '-');
        // 计算所需缓冲区大小（动态分配，避免截断）
        int needed = snprintf(nullptr, 0,
                              "%lx-%lx %c%c%c%c %llx %s %lu %s",
                              startAddress, endAddress,
                              readable ? 'r' : '-',
                              writeable ? 'w' : '-',
                              executable ? 'x' : '-',
                              sharing,
                              offset, dev.c_str(), inode, pathname.c_str());
        if (needed < 0)
            return std::string();
        std::string result(needed + 1, '\0');
        snprintf(&result[0], result.size(),
                 "%lx-%lx %c%c%c%c %llx %s %lu %s",
                 startAddress, endAddress,
                 readable ? 'r' : '-',
                 writeable ? 'w' : '-',
                 executable ? 'x' : '-',
                 sharing,
                 offset, dev.c_str(), inode, pathname.c_str());
        result.pop_back(); // 去除末尾多出的 '\0'
        return result;
    }
};

#endif
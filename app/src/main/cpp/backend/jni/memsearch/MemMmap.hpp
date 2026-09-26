#ifndef MEMMAP_HPP
#define MEMMAP_HPP

#include "Membase.hpp"
#include "ProcIO.hpp"
#include <vector>
#include <cstdint>

// ============================================================
// MemMmap — 零拷贝内存读写 (mmap /proc/pid/mem)
// ============================================================
class MemMmap : public MemBase {
public:
    struct Config {
        size_t maxMappedMB;
        uint32_t mapTypeMask;
        bool preferMmap;
        Config() : maxMappedMB(2048), mapTypeMask(0), preferMmap(true) {}
    };

    explicit MemMmap(int pid, const Config& cfg = Config());
    MemMmap(const char* processName, const Config& cfg = Config());
    ~MemMmap() override;

    MemMmap(const MemMmap&) = delete;
    MemMmap& operator=(const MemMmap&) = delete;

    // ── MemBase 接口 ──────────────────────────────
    bool read(uintptr_t address, void* buffer, size_t size) override;
    bool write(uintptr_t address, const void* buffer, size_t size) override;

    // ── 映射管理 ──────────────────────────────────
    void mapRegions(uint32_t memTypeMask = 0);
    void unmapRegions();

    // ── 零拷贝指针 ────────────────────────────────
    void* getPtr(uintptr_t address) const;

    // ── 统计 ──────────────────────────────────────
    size_t mappedSize() const;
    size_t regionCount() const;
    const Config& config() const { return m_cfg; }

private:
    struct MappedRegion {
        uintptr_t start;
        size_t size;
        uint8_t* ptr;
        bool isMmap;
        bool contains(uintptr_t addr) const {
            return addr >= start && addr < start + size;
        }
    };

    Config m_cfg;
    ProcIO m_io;
    std::vector<MappedRegion> m_regions;
    size_t m_totalMapped = 0;

    bool mapOneRegion(uintptr_t start, size_t len, MappedRegion& out);
    // 二分查找 (O(log n)), regions 按 start 升序
    MappedRegion* findRegion(uintptr_t address);
    const MappedRegion* findRegion(uintptr_t address) const;
    void sortRegions();

    // last-hit 缓存 (重复访问同一区域时跳过二分)
    mutable MappedRegion* m_lastHit = nullptr;
};

#endif

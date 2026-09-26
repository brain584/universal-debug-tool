#include "MemMmap.hpp"
#include "Process.hpp"
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>

MemMmap::MemMmap(int pid, const Config& cfg) : m_cfg(cfg) {
    set_pid(pid);
    m_io.open(pid);
}

MemMmap::MemMmap(const char* processName, const Config& cfg) : m_cfg(cfg) {
    set_pid(Process::get_pid_by_name(processName));
    m_io.open(pid);
}

MemMmap::~MemMmap() {
    unmapRegions();
    // ProcIO 自动 close
}

// ============================================================
// 区域查找 — 二分搜索 O(log n) + last-hit 缓存
// ============================================================

void MemMmap::sortRegions() {
    std::sort(m_regions.begin(), m_regions.end(),
              [](const MappedRegion& a, const MappedRegion& b) {
                  return a.start < b.start;
              });
    m_lastHit = nullptr;
}

MemMmap::MappedRegion* MemMmap::findRegion(uintptr_t address) {
    // last-hit 缓存: 连续访问同一区域时 O(1)
    if (m_lastHit && m_lastHit->contains(address))
        return m_lastHit;

    if (m_regions.empty()) return nullptr;

    // 二分搜索: 找 start <= address 的最大区域
    auto it = std::upper_bound(m_regions.begin(), m_regions.end(), address,
        [](uintptr_t addr, const MappedRegion& r) { return addr < r.start; });

    if (it != m_regions.begin()) {
        --it;
        if (it->contains(address)) {
            m_lastHit = &(*it);
            return m_lastHit;
        }
    }
    return nullptr;
}

const MemMmap::MappedRegion* MemMmap::findRegion(uintptr_t address) const {
    if (m_regions.empty()) return nullptr;

    auto it = std::upper_bound(m_regions.begin(), m_regions.end(), address,
        [](uintptr_t addr, const MappedRegion& r) { return addr < r.start; });

    if (it != m_regions.begin()) {
        --it;
        if (it->contains(address))
            return &(*it);
    }
    return nullptr;
}

// ============================================================
// 映射
// ============================================================

bool MemMmap::mapOneRegion(uintptr_t start, size_t len, MappedRegion& out) {
    out.start = start; out.size = len; out.ptr = nullptr; out.isMmap = false;

    int fd = m_io.fd();
    if (fd < 0 || len == 0) return false;

    if (m_cfg.preferMmap) {
        void* p = mmap(nullptr, len, PROT_READ | PROT_WRITE,
                       MAP_SHARED, fd, static_cast<off64_t>(start));
        if (p != MAP_FAILED) {
            out.ptr = static_cast<uint8_t*>(p);
            out.isMmap = true;
            m_totalMapped += len;
            return true;
        }
    }

    uint8_t* buf = static_cast<uint8_t*>(malloc(len));
    if (!buf) return false;
    ssize_t rd = pread64(fd, buf, len, static_cast<off64_t>(start));
    if (rd > 0) {
        out.ptr = buf; out.size = static_cast<size_t>(rd);
        out.isMmap = false; m_totalMapped += rd;
        return true;
    }
    free(buf);
    return false;
}

void MemMmap::mapRegions(uint32_t memTypeMask) {
    unmapRegions();
    if (!m_io.isOpen()) return;

    m_cfg.mapTypeMask = memTypeMask;
    auto maps = Process::get_process_maps(pid);
    size_t maxBytes = m_cfg.maxMappedMB * 1024ULL * 1024ULL;

    std::sort(maps.begin(), maps.end(),
              [](const ProcMap& a, const ProcMap& b) { return a.length > b.length; });

    for (const auto& map : maps) {
        if (!map.isValid() || !map.readable) continue;
        uint32_t t = static_cast<uint32_t>(map.getMemType());
        if (memTypeMask != 0 && (t & memTypeMask) == 0) continue;
        if (m_totalMapped + map.length > maxBytes) continue;

        MappedRegion mr;
        if (mapOneRegion(map.startAddress, map.length, mr))
            m_regions.push_back(mr);
        if (m_totalMapped >= maxBytes) break;
    }
    sortRegions();  // 按地址排序 → 二分查找
}

void MemMmap::unmapRegions() {
    for (auto& r : m_regions) {
        if (r.ptr) {
            if (r.isMmap) munmap(r.ptr, r.size);
            else free(r.ptr);
        }
    }
    m_regions.clear();
    m_totalMapped = 0;
}

void* MemMmap::getPtr(uintptr_t address) const {
    auto* r = findRegion(address);
    return (r && r->isMmap) ? (r->ptr + (address - r->start)) : nullptr;
}

// ============================================================
// read / write
// ============================================================

bool MemMmap::read(uintptr_t address, void* buffer, size_t size) {
    auto* r = findRegion(address);
    // 只有 MAP_SHARED 映射才能反映目标进程的实时变化
    // malloc+pread 是一次性拷贝, 必须走 fallback 读最新值
    if (r && r->isMmap && address + size <= r->start + r->size) {
        memcpy(buffer, r->ptr + (address - r->start), size);
        return true;
    }
    return m_io.read(address, buffer, size);  // pvm → pread
}

bool MemMmap::write(uintptr_t address, const void* buffer, size_t size) {
    if (m_io.pwrite(address, buffer, size)) {
        auto* r = findRegion(address);
        // 只同步 mmap 映射 (malloc 拷贝不需要同步)
        if (r && r->isMmap && address + size <= r->start + r->size)
            memcpy(r->ptr + (address - r->start), buffer, size);
        return true;
    }
    return ProcIO::pvmWrite(pid, address, buffer, size);
}

// ============================================================
// 统计
// ============================================================

size_t MemMmap::mappedSize() const { return m_totalMapped; }
size_t MemMmap::regionCount() const { return m_regions.size(); }

#include "FuzzySearch.hpp"
#include <cstdio>

// ============================================================
// SnapshotStore — 非模板方法
// ============================================================

void SnapshotStore::captureRegion(uintptr_t start, uintptr_t end, const uint8_t* data) {
    RegionSnap rs;
    rs.start = start;
    rs.end = end;
    rs.data.assign(data, data + (end - start));
    m_regions.push_back(std::move(rs));
}

size_t SnapshotStore::valueCount() const { return m_count; }
size_t SnapshotStore::regionCount() const { return m_regions.size(); }

size_t SnapshotStore::memoryUsed() const {
    size_t m = m_values.capacity();
    for (const auto& r : m_regions) m += r.data.capacity();
    return m;
}

void SnapshotStore::clear() {
    m_values.clear();
    m_regions.clear();
    m_count = 0;
    m_typeSize = 0;
}

// ============================================================
// FuzzySearch — 非模板方法
// ============================================================

void FuzzySearch::reset() {
    m_resultsI32.clear(); m_resultsI64.clear();
    m_resultsF32.clear(); m_resultsF64.clear();
    m_snapshot.clear();
    m_phase = Phase::IDLE;
    m_dtypeSize = 0;
}

size_t FuzzySearch::size() const { return getCount(); }
size_t FuzzySearch::memoryUsed() const { return getMemory(); }

size_t FuzzySearch::getCount() const {
    return m_resultsI32.size() + m_resultsI64.size() +
           m_resultsF32.size() + m_resultsF64.size();
}

size_t FuzzySearch::getMemory() const {
    return m_resultsI32.memoryUsed() + m_resultsI64.memoryUsed() +
           m_resultsF32.memoryUsed() + m_resultsF64.memoryUsed() +
           m_snapshot.memoryUsed();
}

size_t FuzzySearch::estimateResults(const std::vector<ProcMap>& maps,
                                     const SearchParams& params, size_t typeSize) {
    size_t total = 0;
    for (const auto& m : maps) {
        if (!m.isValid() || !m.readable) continue;
        uint32_t t = static_cast<uint32_t>(m.getMemType());
        if (params.memTypeMask != 0 && (t & params.memTypeMask) == 0) continue;
        total += m.length / typeSize;
    }
    return total;
}

void FuzzySearch::captureRegions(const std::vector<ProcMap>& maps,
                                  const SearchParams& params) {
    const size_t CHUNK = m_cfg.chunkSize;
    std::vector<uint8_t> buf(CHUNK);
    size_t totalSnapped = 0;

    for (const auto& m : maps) {
        if (!m.isValid() || !m.readable) continue;
        uint32_t t = static_cast<uint32_t>(m.getMemType());
        if (params.memTypeMask != 0 && (t & params.memTypeMask) == 0) continue;

        if (totalSnapped + m.length > m_cfg.maxRegionSnap) {
            if (m_cfg.verbose)
                printf("[FuzzySearch] 区域快照达到上限, 已捕获 %.1f GB\n",
                       totalSnapped / (1024.0*1024.0*1024.0));
            break;
        }

        std::vector<uint8_t> regionData;
        regionData.reserve(m.length);
        uintptr_t cur = m.startAddress;
        uintptr_t end = m.endAddress;
        while (cur < end) {
            size_t toRead = std::min(CHUNK, static_cast<size_t>(end - cur));
            if (!m_mem.read(cur, buf.data(), toRead)) {
                regionData.resize(regionData.size() + toRead, 0);
                cur += toRead;
                continue;
            }
            regionData.insert(regionData.end(), buf.data(), buf.data() + toRead);
            cur += toRead;
        }
        m_snapshot.captureRegion(m.startAddress, m.endAddress, regionData.data());
        totalSnapped += m.length;
    }
}

std::string FuzzySearch::fmtSize(size_t bytes) {
    const char* u[] = {"B","KB","MB","GB"};
    int i = 0; double s = bytes;
    while (s >= 1024 && i < 3) { s /= 1024; i++; }
    char buf[64]; snprintf(buf, sizeof(buf), "%.2f %s", s, u[i]);
    return buf;
}

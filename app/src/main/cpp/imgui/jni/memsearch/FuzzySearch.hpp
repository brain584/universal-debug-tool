#ifndef FUZZYSEARCH_HPP
#define FUZZYSEARCH_HPP

#include "Mem.hpp"
#include "Search.hpp"
#include <cstring>
#include <functional>
#include <atomic>
#include <thread>

// ============================================================
// BulkResults<T> — 紧凑大容量结果存储 (支持 1亿+ 条目)
//
// 内存布局 (int32, 100M条):
//   addresses: 100M × 8B = 800 MB
//   values:    100M × 4B = 400 MB
//   合计: 1.2 GB — 可预分配, 无 realloc
// ============================================================
template <typename T>
class BulkResults {
public:
    BulkResults() : m_count(0) {}

    void reserve(size_t capacity) {
        m_addrs.reserve(capacity);
        m_vals.resize(capacity * sizeof(T));
        m_capacity = capacity;
    }

    void append(uintptr_t addr, const T& value) {
        if (m_count >= m_capacity) return;
        m_addrs.push_back(addr);
        memcpy(&m_vals[m_count * sizeof(T)], &value, sizeof(T));
        m_count++;
    }

    size_t appendFromBuffer(uintptr_t baseAddr, const uint8_t* buf, size_t bufSize,
                            size_t typeSize, size_t step, size_t maxCount) {
        size_t limit = (bufSize >= typeSize) ? (bufSize - typeSize + 1) : 0;
        size_t added = 0;
        for (size_t off = 0; off < limit && m_count < maxCount; off += step) {
            T val;
            memcpy(&val, buf + off, typeSize);
            append(baseAddr + off, val);
            added++;
        }
        return added;
    }

    uintptr_t addr(size_t i) const { return m_addrs[i]; }
    T value(size_t i) const {
        T v;
        memcpy(&v, &m_vals[i * sizeof(T)], sizeof(T));
        return v;
    }
    void setValue(size_t i, const T& v) {
        memcpy(&m_vals[i * sizeof(T)], (const void*)&v, sizeof(T));
    }
    const T* valuePtr(size_t i) const {
        return reinterpret_cast<const T*>(&m_vals[i * sizeof(T)]);
    }
    T* valuePtr(size_t i) {
        return reinterpret_cast<T*>(&m_vals[i * sizeof(T)]);
    }

    size_t size() const { return m_count; }
    size_t capacity() const { return m_capacity; }
    bool empty() const { return m_count == 0; }
    size_t memoryUsed() const {
        return m_addrs.capacity() * sizeof(uintptr_t) + m_vals.capacity();
    }
    void clear() { m_addrs.clear(); m_vals.clear(); m_count = 0; m_capacity = 0; }

    const std::vector<uintptr_t>& addresses() const { return m_addrs; }
    const std::vector<uint8_t>& rawValues() const { return m_vals; }

private:
    std::vector<uintptr_t> m_addrs;
    std::vector<uint8_t>    m_vals;
    size_t m_count = 0;
    size_t m_capacity = 0;
};

// ============================================================
// SnapshotStore — 快照存储
// ============================================================
class SnapshotStore {
public:
    // 从 BulkResults 创建个体快照
    template <typename T>
    void capture(const BulkResults<T>& results) {
        size_t n = results.size();
        size_t vsz = sizeof(T);
        m_typeSize = vsz;
        m_values.resize(n * vsz);
        memcpy(m_values.data(), results.rawValues().data(), n * vsz);
        m_count = n;
    }

    // 区域级快照: 存整个内存区域
    void captureRegion(uintptr_t start, uintptr_t end, const uint8_t* data);

    // 比较: 返回 true 如果地址处的值与快照满足条件
    template <typename T>
    bool compare(size_t idx, const T& current, CompareOp op) const {
        if (idx >= m_count) return false;
        T old;
        memcpy(&old, &m_values[idx * sizeof(T)], sizeof(T));
        switch (op) {
            case CompareOp::INCREASED: return current > old;
            case CompareOp::DECREASED: return current < old;
            case CompareOp::CHANGED:   return current != old;
            case CompareOp::UNCHANGED: return current == old;
            default: return false;
        }
    }

    // 区域级精炼: 重扫区域 vs 快照, 输出匹配地址
    template <typename T>
    void refineRegions(MemBase& mem, BulkResults<T>& out,
                       CompareOp op, size_t maxResults,
                       SearchEngine::ProgressCallback progressCb = nullptr) {
        size_t typeSz = sizeof(T);
        const size_t CHUNK = 32 * 1024 * 1024;
        std::vector<uint8_t> buf(CHUNK + typeSz - 1);

        out.clear();
        size_t estTotal = 0;
        for (const auto& reg : m_regions)
            estTotal += (reg.end - reg.start) / typeSz;
        out.reserve(std::min(estTotal, maxResults));

        for (const auto& reg : m_regions) {
            uintptr_t cur = reg.start;
            uintptr_t end = reg.end;
            uintptr_t rem = cur % typeSz;
            if (rem != 0) cur += (typeSz - rem);

            size_t snapOff = 0;
            while (cur + typeSz <= end && out.size() < maxResults) {
                size_t toRead = std::min(CHUNK + typeSz - 1,
                                         static_cast<size_t>(end - cur));
                size_t snapToRead = std::min(toRead, reg.data.size() - snapOff);
                if (!mem.read(cur, buf.data(), toRead)) {
                    cur += 4096; snapOff += 4096;
                    continue;
                }

                size_t limit = std::min(toRead, snapToRead) - typeSz + 1;
                for (size_t off = 0; off < limit && out.size() < maxResults; off += typeSz) {
                    T curVal, oldVal;
                    memcpy(&curVal, buf.data() + off, typeSz);
                    memcpy(&oldVal, reg.data.data() + snapOff + off, typeSz);

                    bool keep = false;
                    switch (op) {
                        case CompareOp::INCREASED: keep = curVal > oldVal; break;
                        case CompareOp::DECREASED: keep = curVal < oldVal; break;
                        case CompareOp::CHANGED:   keep = curVal != oldVal; break;
                        case CompareOp::UNCHANGED: keep = curVal == oldVal; break;
                        default: break;
                    }
                    if (keep) out.append(cur + off, curVal);
                }
                cur += CHUNK;
                snapOff += CHUNK;
            }
        }
    }

    size_t valueCount() const;
    size_t regionCount() const;
    size_t memoryUsed() const;
    void clear();

private:
    struct RegionSnap {
        uintptr_t start, end;
        std::vector<uint8_t> data;
    };
    std::vector<uint8_t> m_values;
    std::vector<RegionSnap> m_regions;
    size_t m_count = 0;
    size_t m_typeSize = 0;
};

// ============================================================
// FuzzySearch — 模糊搜索工作流引擎
// ============================================================
class FuzzySearch {
public:
    struct Config {
        size_t chunkSize = 32 * 1024 * 1024;
        size_t maxIndividual = 200000000;
        size_t maxRegionSnap = 4ULL * 1024 * 1024 * 1024;
        bool verbose = true;
    };

    explicit FuzzySearch(MemBase& mem) : m_mem(mem), m_search(mem) {}

    // ── Phase 1: 搜索 ─────────────────────────
    // 未知值搜索 (收集全部地址 + 自动快照)
    template <typename T>
    void searchUnknown(const SearchParams& params, size_t maxResults = 0,
                       SearchEngine::ProgressCallback progressCb = nullptr);

    // 精确值搜索 (利用 SearchEngine 优化路径 + 自动快照)
    template <typename T>
    void searchValue(const SearchParams& params, T value,
                     SearchEngine::ProgressCallback progressCb = nullptr);

    // ── Phase 2: 精炼 ─────────────────────────
    template <typename T>
    size_t refine(CompareOp op, size_t maxResults = 0,
                  SearchEngine::ProgressCallback progressCb = nullptr);

    // ── 精确值 / 比较过滤 ─────────────────────
    template <typename T>
    size_t filterExact(T value);

    template <typename T>
    size_t filterCompare(CompareOp op, T ref);

    // ── 访问 ──────────────────────────────────
    enum class Phase { IDLE, UNKNOWN, REGION_SNAPSHOT, INDIVIDUAL };
    Phase phase() const { return m_phase; }
    size_t size() const;
    size_t memoryUsed() const;
    size_t dtypeSize() const { return m_dtypeSize; }

    template <typename T> uintptr_t addrAt(size_t i) const;
    template <typename T> T valueAt(size_t i) const;
    template <typename T> void setValueAt(size_t i, const T& v);
    template <typename T> const BulkResults<T>& results() const;
    template <typename T> BulkResults<T>& results();

    template <typename T> void takeSnapshot() { m_snapshot.capture(results<T>()); }
    void clearSnapshot() { m_snapshot.clear(); }

    template <typename T>
    bool writeBack() {
        bool ok = true;
        auto& r = results<T>();
        for (size_t i = 0; i < r.size(); i++) {
            T v = r.value(i);
            if (!m_mem.Write(r.addr(i), v)) ok = false;
        }
        return ok;
    }

    size_t getCount() const;
    size_t getMemory() const;
    void reset();

    struct Stats {
        size_t phase1Results = 0;
        size_t phase2Results = 0;
        size_t totalScanned = 0;
        double elapsedMs = 0;
    };
    const Stats& stats() const { return m_stats; }

    Config m_cfg;

private:
    MemBase& m_mem;
    SearchEngine m_search;
    Phase m_phase = Phase::IDLE;
    size_t m_dtypeSize = 0;
    Stats m_stats;

    BulkResults<int32_t> m_resultsI32;
    BulkResults<int64_t> m_resultsI64;
    BulkResults<float>   m_resultsF32;
    BulkResults<double>  m_resultsF64;
    SnapshotStore m_snapshot;

    static size_t estimateResults(const std::vector<ProcMap>& maps,
                                   const SearchParams& params, size_t typeSize);
    void captureRegions(const std::vector<ProcMap>& maps, const SearchParams& params);

    template <typename T>
    void scanAllRegions(const std::vector<ProcMap>& maps, const SearchParams& params,
                        BulkResults<T>& out, size_t maxCount,
                        SearchEngine::ProgressCallback progressCb);

    template <typename T>
    size_t refineFromRegions(CompareOp op, size_t maxResults,
                              SearchEngine::ProgressCallback progressCb);

    template <typename T>
    size_t refineIndividual(CompareOp op, size_t maxResults);

    template <typename T, typename Pred>
    size_t filterIndividual(Pred pred);

    static std::string fmtSize(size_t bytes);
};

// ============================================================
// 模板实现 (必须在头文件中)
// ============================================================

// ── searchUnknown ───────────────────────────────────────
template <typename T>
inline void FuzzySearch::searchUnknown(const SearchParams& params, size_t maxResults,
                                        SearchEngine::ProgressCallback progressCb) {
    static_assert(std::is_same_v<T, int32_t> || std::is_same_v<T, int64_t> ||
                  std::is_same_v<T, float>   || std::is_same_v<T, double>,
                  "FuzzySearch supports: int32_t, int64_t, float, double");
    m_dtypeSize = sizeof(T);
    m_phase = Phase::UNKNOWN;

    auto maps = Process::get_process_maps(m_mem.get_pid());
    if (params.residentOnly)
        maps = filterResidentMaps(m_mem.get_pid(), maps);
    size_t estTotal = estimateResults(maps, params, sizeof(T));

    if (m_cfg.verbose) {
        printf("[FuzzySearch] 预估结果: %s (%zu 条)\n",
               fmtSize(estTotal * (sizeof(uintptr_t) + sizeof(T))).c_str(), estTotal);
    }

    if (estTotal > m_cfg.maxIndividual) {
        if (m_cfg.verbose)
            printf("[FuzzySearch] 切换到区域快照模式 (%.1f GB 原始数据)\n",
                   estTotal * sizeof(T) / (1024.0*1024.0*1024.0));
        captureRegions(maps, params);
        m_phase = Phase::REGION_SNAPSHOT;
        m_stats.phase1Results = estTotal;
        return;
    }

    size_t cap = maxResults > 0 ? std::min(estTotal, maxResults) : estTotal;
    m_resultsI32.clear(); m_resultsI64.clear();
    m_resultsF32.clear(); m_resultsF64.clear();

    if constexpr (std::is_same_v<T, int32_t>) {
        m_resultsI32.reserve(cap);
        scanAllRegions<T>(maps, params, m_resultsI32, cap, progressCb);
        m_snapshot.capture(m_resultsI32);
    } else if constexpr (std::is_same_v<T, int64_t>) {
        m_resultsI64.reserve(cap);
        scanAllRegions<T>(maps, params, m_resultsI64, cap, progressCb);
        m_snapshot.capture(m_resultsI64);
    } else if constexpr (std::is_same_v<T, float>) {
        m_resultsF32.reserve(cap);
        scanAllRegions<T>(maps, params, m_resultsF32, cap, progressCb);
        m_snapshot.capture(m_resultsF32);
    } else if constexpr (std::is_same_v<T, double>) {
        m_resultsF64.reserve(cap);
        scanAllRegions<T>(maps, params, m_resultsF64, cap, progressCb);
        m_snapshot.capture(m_resultsF64);
    }

    m_dtypeSize = sizeof(T);
    m_phase = Phase::INDIVIDUAL;
    m_stats.phase1Results = size();
}

// ── searchValue ─────────────────────────────────────────
template <typename T>
inline void FuzzySearch::searchValue(const SearchParams& params, T value,
                                      SearchEngine::ProgressCallback progressCb) {
    static_assert(std::is_same_v<T, int32_t> || std::is_same_v<T, int64_t> ||
                  std::is_same_v<T, float>   || std::is_same_v<T, double>,
                  "FuzzySearch supports: int32_t, int64_t, float, double");
    m_dtypeSize = sizeof(T);

    // 使用 SearchEngine 的优化路径 (BMH + 并行扫描)
    auto resultSet = m_search.search<T>(params, value, progressCb);
    size_t n = resultSet.size();

    // 转换为 BulkResults 格式
    m_resultsI32.clear(); m_resultsI64.clear();
    m_resultsF32.clear(); m_resultsF64.clear();

    if constexpr (std::is_same_v<T, int32_t>) {
        m_resultsI32.reserve(n);
        for (size_t i = 0; i < n; i++)
            m_resultsI32.append(resultSet[i].address, resultSet[i].value);
        m_snapshot.capture(m_resultsI32);
    } else if constexpr (std::is_same_v<T, int64_t>) {
        m_resultsI64.reserve(n);
        for (size_t i = 0; i < n; i++)
            m_resultsI64.append(resultSet[i].address, resultSet[i].value);
        m_snapshot.capture(m_resultsI64);
    } else if constexpr (std::is_same_v<T, float>) {
        m_resultsF32.reserve(n);
        for (size_t i = 0; i < n; i++)
            m_resultsF32.append(resultSet[i].address, resultSet[i].value);
        m_snapshot.capture(m_resultsF32);
    } else if constexpr (std::is_same_v<T, double>) {
        m_resultsF64.reserve(n);
        for (size_t i = 0; i < n; i++)
            m_resultsF64.append(resultSet[i].address, resultSet[i].value);
        m_snapshot.capture(m_resultsF64);
    }

    m_phase = Phase::INDIVIDUAL;
    m_stats.phase1Results = n;
}

// ── refine ──────────────────────────────────────────────
template <typename T>
inline size_t FuzzySearch::refine(CompareOp op, size_t maxResults,
                                   SearchEngine::ProgressCallback progressCb) {
    if (m_phase == Phase::REGION_SNAPSHOT)
        return refineFromRegions<T>(op, maxResults, progressCb);
    if (m_phase == Phase::INDIVIDUAL)
        return refineIndividual<T>(op, maxResults);
    return 0;
}

// ── filterExact ─────────────────────────────────────────
template <typename T>
inline size_t FuzzySearch::filterExact(T value) {
    return filterIndividual<T>([value](T cur) { return cur == value; });
}

// ── filterCompare ───────────────────────────────────────
template <typename T>
inline size_t FuzzySearch::filterCompare(CompareOp op, T ref) {
    return filterIndividual<T>([op, ref](T cur) {
        switch (op) {
            case CompareOp::GT:  return cur > ref;
            case CompareOp::GTE: return cur >= ref;
            case CompareOp::LT:  return cur < ref;
            case CompareOp::LTE: return cur <= ref;
            case CompareOp::NEQ: return cur != ref;
            default: return false;
        }
    });
}

// ── scanAllRegions ──────────────────────────────────────
template <typename T>
inline void FuzzySearch::scanAllRegions(
    const std::vector<ProcMap>& maps, const SearchParams& params,
    BulkResults<T>& out, size_t maxCount,
    SearchEngine::ProgressCallback progressCb) {
    (void)progressCb;
    const size_t typeSz = sizeof(T);
    const size_t step = typeSz;
    const size_t CHUNK = m_cfg.chunkSize;
    std::vector<uint8_t> buf(CHUNK + typeSz - 1);

    size_t totalBytes = 0;
    for (const auto& m : maps) {
        if (!m.isValid() || !m.readable) continue;
        uint32_t t = static_cast<uint32_t>(m.getMemType());
        if (params.memTypeMask != 0 && (t & params.memTypeMask) == 0) continue;

        uintptr_t cur = m.startAddress;
        uintptr_t end = m.endAddress;
        uintptr_t rem = cur % typeSz;
        if (rem != 0) cur += (typeSz - rem);

        while (cur + typeSz <= end && out.size() < maxCount) {
            size_t toRead = std::min(CHUNK + typeSz - 1,
                                     static_cast<size_t>(end - cur));
            if (!m_mem.read(cur, buf.data(), toRead)) {
                cur += 4096; continue;
            }
            totalBytes += toRead;
            out.appendFromBuffer(cur, buf.data(), toRead, typeSz, step, maxCount);
            cur += CHUNK;
        }
        if (out.size() >= maxCount) break;
    }
    m_stats.totalScanned = totalBytes;
}

// ── refineFromRegions ───────────────────────────────────
template <typename T>
inline size_t FuzzySearch::refineFromRegions(
    CompareOp op, size_t maxResults,
    SearchEngine::ProgressCallback progressCb) {
    if (maxResults == 0) maxResults = m_cfg.maxIndividual;

    size_t n = 0;
    if constexpr (std::is_same_v<T, int32_t>) {
        m_resultsI32.clear();
        m_snapshot.refineRegions<T>(m_mem, m_resultsI32, op, maxResults, progressCb);
        n = m_resultsI32.size();
        m_snapshot.clear();         // 清除区域快照
        m_snapshot.capture(m_resultsI32);  // 重建个体快照
    } else if constexpr (std::is_same_v<T, int64_t>) {
        m_resultsI64.clear();
        m_snapshot.refineRegions<T>(m_mem, m_resultsI64, op, maxResults, progressCb);
        n = m_resultsI64.size();
        m_snapshot.clear();
        m_snapshot.capture(m_resultsI64);
    } else if constexpr (std::is_same_v<T, float>) {
        m_resultsF32.clear();
        m_snapshot.refineRegions<T>(m_mem, m_resultsF32, op, maxResults, progressCb);
        n = m_resultsF32.size();
        m_snapshot.clear();
        m_snapshot.capture(m_resultsF32);
    } else if constexpr (std::is_same_v<T, double>) {
        m_resultsF64.clear();
        m_snapshot.refineRegions<T>(m_mem, m_resultsF64, op, maxResults, progressCb);
        n = m_resultsF64.size();
        m_snapshot.clear();
        m_snapshot.capture(m_resultsF64);
    }
    m_phase = Phase::INDIVIDUAL;
    m_stats.phase2Results = n;
    return n;
}

// ── refineIndividual (并行版) ──────────────────────────
template <typename T>
inline size_t FuzzySearch::refineIndividual(CompareOp op, size_t maxResults) {
    size_t total = size();
    if (total == 0) return 0;

    if (maxResults == 0) maxResults = total;
    size_t cap = std::min(total, maxResults);

    unsigned int numThreads = std::thread::hardware_concurrency();
    if (numThreads == 0) numThreads = 4;
    if (total < 1000) numThreads = 1; // 小数据集不开线程

    // 线程局部结果
    struct TL { BulkResults<T> res; size_t readOk=0, readFail=0, matched=0; };
    std::vector<TL> threadData(numThreads);
    size_t perThread = cap / numThreads + 1;
    for (auto& td : threadData) td.res.reserve(perThread + 256);

    auto worker = [&](int tid) {
        auto& tl = threadData[tid];
        size_t start = tid * (total / numThreads);
        size_t end = (tid + 1 == numThreads) ? total : (tid + 1) * (total / numThreads);

        for (size_t i = start; i < end; i++) {
            if (tl.res.size() >= perThread) break;
            uintptr_t addr = addrAt<T>(i);
            T cur{};
            if (!m_mem.read(addr, &cur, sizeof(T))) { tl.readFail++; continue; }
            tl.readOk++;
            if (m_snapshot.compare<T>(i, cur, op)) {
                tl.matched++;
                tl.res.append(addr, cur);
            }
        }
    };

    std::vector<std::thread> pool;
    pool.reserve(numThreads);
    for (unsigned int i = 0; i < numThreads; ++i)
        pool.emplace_back(worker, i);
    for (auto& t : pool) t.join();

    // 合并
    BulkResults<T> filtered;
    filtered.reserve(cap);
    size_t readOk=0, readFail=0, matched=0;
    for (auto& td : threadData) {
        readOk += td.readOk; readFail += td.readFail; matched += td.matched;
        for (size_t i = 0; i < td.res.size() && filtered.size() < maxResults; i++)
            filtered.append(td.res.addr(i), td.res.value(i));
    }

    if (m_cfg.verbose)
        printf("[refine] %zu/%zu read, %zu matched, %zu failed, %u threads\n",
               readOk, total, matched, readFail, numThreads);

    size_t result = filtered.size();
    if constexpr (std::is_same_v<T, int32_t>) {
        m_resultsI32 = std::move(filtered);
        m_snapshot.capture(m_resultsI32);
    } else if constexpr (std::is_same_v<T, int64_t>) {
        m_resultsI64 = std::move(filtered);
        m_snapshot.capture(m_resultsI64);
    } else if constexpr (std::is_same_v<T, float>) {
        m_resultsF32 = std::move(filtered);
        m_snapshot.capture(m_resultsF32);
    } else if constexpr (std::is_same_v<T, double>) {
        m_resultsF64 = std::move(filtered);
        m_snapshot.capture(m_resultsF64);
    }
    return result;
}

// ── filterIndividual ────────────────────────────────────
template <typename T, typename Pred>
inline size_t FuzzySearch::filterIndividual(Pred pred) {
    if (size() == 0) return 0;

    BulkResults<T> filtered;
    filtered.reserve(size());
    for (size_t i = 0; i < size(); i++) {
        uintptr_t addr = addrAt<T>(i);
        T cur{};
        if (!m_mem.read(addr, &cur, sizeof(T))) continue;  // 读实时值
        if (pred(cur)) filtered.append(addr, cur);
    }

    size_t result = filtered.size();
    if constexpr (std::is_same_v<T, int32_t>) {
        m_resultsI32 = std::move(filtered);
        m_snapshot.capture(m_resultsI32);
    } else if constexpr (std::is_same_v<T, int64_t>) {
        m_resultsI64 = std::move(filtered);
        m_snapshot.capture(m_resultsI64);
    } else if constexpr (std::is_same_v<T, float>) {
        m_resultsF32 = std::move(filtered);
        m_snapshot.capture(m_resultsF32);
    } else if constexpr (std::is_same_v<T, double>) {
        m_resultsF64 = std::move(filtered);
        m_snapshot.capture(m_resultsF64);
    }
    return result;
}

// ── 模板特化 ────────────────────────────────────────────
template<> inline uintptr_t FuzzySearch::addrAt<int32_t>(size_t i) const { return m_resultsI32.addr(i); }
template<> inline uintptr_t FuzzySearch::addrAt<int64_t>(size_t i) const { return m_resultsI64.addr(i); }
template<> inline uintptr_t FuzzySearch::addrAt<float>(size_t i)   const { return m_resultsF32.addr(i); }
template<> inline uintptr_t FuzzySearch::addrAt<double>(size_t i)  const { return m_resultsF64.addr(i); }

template<> inline int32_t FuzzySearch::valueAt<int32_t>(size_t i) const { return m_resultsI32.value(i); }
template<> inline int64_t FuzzySearch::valueAt<int64_t>(size_t i) const { return m_resultsI64.value(i); }
template<> inline float   FuzzySearch::valueAt<float>(size_t i)   const { return m_resultsF32.value(i); }
template<> inline double  FuzzySearch::valueAt<double>(size_t i)  const { return m_resultsF64.value(i); }

template<> inline void FuzzySearch::setValueAt<int32_t>(size_t i, const int32_t& v) { m_resultsI32.setValue(i, v); }
template<> inline void FuzzySearch::setValueAt<int64_t>(size_t i, const int64_t& v) { m_resultsI64.setValue(i, v); }
template<> inline void FuzzySearch::setValueAt<float>(size_t i, const float& v)     { m_resultsF32.setValue(i, v); }
template<> inline void FuzzySearch::setValueAt<double>(size_t i, const double& v)   { m_resultsF64.setValue(i, v); }

template<> inline const BulkResults<int32_t>& FuzzySearch::results<int32_t>() const { return m_resultsI32; }
template<> inline const BulkResults<int64_t>& FuzzySearch::results<int64_t>() const { return m_resultsI64; }
template<> inline const BulkResults<float>&   FuzzySearch::results<float>()   const { return m_resultsF32; }
template<> inline const BulkResults<double>&  FuzzySearch::results<double>()  const { return m_resultsF64; }

template<> inline BulkResults<int32_t>& FuzzySearch::results<int32_t>() { return m_resultsI32; }
template<> inline BulkResults<int64_t>& FuzzySearch::results<int64_t>() { return m_resultsI64; }
template<> inline BulkResults<float>&   FuzzySearch::results<float>()   { return m_resultsF32; }
template<> inline BulkResults<double>&  FuzzySearch::results<double>()  { return m_resultsF64; }

#endif // FUZZYSEARCH_HPP

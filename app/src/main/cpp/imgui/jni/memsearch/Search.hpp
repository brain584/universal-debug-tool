#ifndef SEARCH_HPP
#define SEARCH_HPP

#include "Membase.hpp"
#include "Process.hpp"
#include "FastSearch.hpp"
#include <functional>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <unordered_set>
#include <unordered_map>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <limits>
#include <stdexcept>
#include <cstdio>

// Linux/Android 下才需要 pagemap 接口 (用于反检测: 跳过 非驻留 页)
#ifdef __linux__
#include <unistd.h>
#include <fcntl.h>
#endif

// ============================================================
// MemorySearch — 企业级内存搜索库
// ============================================================

// ── 比较运算符 ──────────────────────────────────────────
enum class CompareOp : uint8_t {
    EQ        = 0,  // == value
    NEQ       = 1,  // != value
    GT        = 2,  // >  value
    GTE       = 3,  // >= value
    LT        = 4,  // <  value
    LTE       = 5,  // <= value
    RANGE     = 6,  // min <= x <= max
    CHANGED   = 7,  // != previousSnapshot[addr]
    UNCHANGED = 8,  // == previousSnapshot[addr]
    INCREASED = 9,  // >  previousSnapshot[addr]
    DECREASED = 10, // <  previousSnapshot[addr]
};

// ── 搜索参数 ────────────────────────────────────────────
struct SearchParams {
    uintptr_t startAddress = 0;
    uintptr_t endAddress = UINTPTR_MAX;
    uint32_t memTypeMask = MemType::RANGE_RW;   // 默认搜索可读写区域
    bool parallel = true;
    unsigned int numThreads = 0;
    size_t chunkSize = 0;                        // 0=auto(32MB)

    // 结果控制
    size_t maxResults = 0;                       // 0=无限制 (注意:超大结果集会OOM)
    bool align = true;                           // 按类型大小对齐 (仅精确值搜索)

    // 反检测: 仅扫描常驻内存(RAM)页, 跳过已换出到 非驻留内存 的页。
    // 开启后扫描前会依据 /proc/pid/pagemap 的 PRESENT 位过滤区域,
    // 避免跨进程读取触发目标进程补页被反外挂检测。需 root 权限。
    bool residentOnly = false;

    // 快照 (用于 CHANGED/UNCHANGED/INCREASED/DECREASED)
    const std::unordered_map<uintptr_t, std::vector<uint8_t>>* snapshot = nullptr;

    size_t effectiveChunkSize() const {
        if (chunkSize > 0) return chunkSize;
        return 32 * 1024 * 1024;
    }
};

// ── 搜索结果 ────────────────────────────────────────────
template <typename T>
struct SearchResult {
    uintptr_t address;
    T value;

    SearchResult() : address(0), value{} {}
    SearchResult(uintptr_t addr, T val) : address(addr), value(val) {}
};

// ── 性能统计 ────────────────────────────────────────────
struct SearchStats {
    double   elapsedMs   = 0;
    size_t   totalBytes  = 0;
    size_t   bytesRead   = 0;
    size_t   resultCount = 0;
    double   throughputMBs = 0;
    unsigned int numThreads  = 0;

    void print() const {
        printf("[Stats] %.2f ms | %.2f GB scanned | %zu results | %.1f MB/s | %u threads\n",
               elapsedMs, totalBytes / (1024.0*1024.0*1024.0),
               resultCount, throughputMBs, numThreads);
    }
};

// ── 内存区域 ────────────────────────────────────────────
struct MemoryRange {
    uintptr_t start;
    uintptr_t end;
};

// ── 搜索异常 ────────────────────────────────────────────
class SearchException : public std::runtime_error {
public:
    explicit SearchException(const std::string& msg) : std::runtime_error(msg) {}
};

class ResultLimitExceeded : public SearchException {
public:
    size_t limit;
    explicit ResultLimitExceeded(size_t lim)
        : SearchException("Result limit exceeded: " + std::to_string(lim)), limit(lim) {}
};

// ============================================================
// ResultSet<T> — 结果容器 (支持链式操作、分页、惰性读取)
// ============================================================
template <typename T>
class ResultSet {
public:
    using Result = SearchResult<T>;
    using FilterFunc = std::function<bool(const Result&)>;
    using ModifyFunc = std::function<void(Result&)>;
    using Iterator = typename std::vector<Result>::iterator;
    using ConstIterator = typename std::vector<Result>::const_iterator;

    // ── 构造 ──────────────────────────────────────────
    ResultSet(MemBase& mem, std::vector<Result> results)
        : m_mem(mem), m_results(std::move(results)) {}

    ResultSet(MemBase& mem) : m_mem(mem) {}

    // 移动
    ResultSet(ResultSet&& other) noexcept
        : m_mem(other.m_mem), m_results(std::move(other.m_results)),
          m_truncated(other.m_truncated), m_totalAvailable(other.m_totalAvailable) {}

    ResultSet& operator=(ResultSet&& other) noexcept {
        if (this != &other) {
            m_results = std::move(other.m_results);
            m_truncated = other.m_truncated;
            m_totalAvailable = other.m_totalAvailable;
        }
        return *this;
    }

    ResultSet(const ResultSet&) = delete;
    ResultSet& operator=(const ResultSet&) = delete;

    // ── 迭代器 ────────────────────────────────────────
    Iterator begin() { return m_results.begin(); }
    Iterator end()   { return m_results.end(); }
    ConstIterator begin() const { return m_results.begin(); }
    ConstIterator end()   const { return m_results.end(); }

    // ── 访问 ──────────────────────────────────────────
    const std::vector<Result>& results() const { return m_results; }
    size_t size() const { return m_results.size(); }
    bool empty() const { return m_results.empty(); }
    bool isTruncated() const { return m_truncated; }
    size_t totalAvailable() const { return m_totalAvailable; }

    Result& operator[](size_t i) { return m_results[i]; }
    const Result& operator[](size_t i) const { return m_results[i]; }

    // ── 分页 ──────────────────────────────────────────
    ResultSet page(size_t offset, size_t count) const {
        size_t start = std::min(offset, m_results.size());
        size_t end   = std::min(start + count, m_results.size());
        std::vector<Result> pg(m_results.begin() + start, m_results.begin() + end);
        ResultSet rs(m_mem, std::move(pg));
        rs.m_truncated = m_truncated;
        rs.m_totalAvailable = m_totalAvailable;
        return rs;
    }

    // ── 链式过滤 ──────────────────────────────────────
    ResultSet filter(FilterFunc pred) const {
        std::vector<Result> filtered;
        filtered.reserve(m_results.size());
        for (const auto& r : m_results)
            if (pred(r)) filtered.push_back(r);
        return ResultSet(m_mem, std::move(filtered));
    }

    ResultSet& filterSelf(FilterFunc pred) {
        auto it = std::remove_if(m_results.begin(), m_results.end(),
                                 [&](const Result& r) { return !pred(r); });
        m_results.erase(it, m_results.end());
        return *this;
    }

    // ── 偏移过滤 (基于 address+offset 处的值) ──────────
    template <typename U>
    ResultSet filterOffset(int32_t offset, CompareOp op, U value) const {
        std::vector<Result> filtered;
        filtered.reserve(m_results.size());
        for (const auto& r : m_results) {
            U val = m_mem.Read<U>(r.address + offset);
            if (compareValue(val, value, op))
                filtered.push_back(r);
        }
        return ResultSet(m_mem, std::move(filtered));
    }

    // ── 修改 ──────────────────────────────────────────
    ResultSet& modify(ModifyFunc func) {
        for (auto& r : m_results) func(r);
        return *this;
    }

    // ── 刷新(从进程重读) ───────────────────────────────
    ResultSet& refresh() {
        for (auto& r : m_results)
            m_mem.read(r.address, &r.value, sizeof(T));
        return *this;
    }

    // ── 创建快照 (用于 CHANGED 等比较) ──────────────────
    std::unordered_map<uintptr_t, std::vector<uint8_t>> snapshot() const {
        std::unordered_map<uintptr_t, std::vector<uint8_t>> snap;
        for (const auto& r : m_results) {
            std::vector<uint8_t> data(sizeof(T));
            memcpy(data.data(), &r.value, sizeof(T));
            snap[r.address] = std::move(data);
        }
        return snap;
    }

    // ── 写回 ──────────────────────────────────────────
    bool writeBack() const {
        bool ok = true;
        for (const auto& r : m_results)
            if (!m_mem.Write(r.address, r.value)) ok = false;
        return ok;
    }

    bool writeAll(const T& newValue) const {
        bool ok = true;
        for (const auto& r : m_results)
            if (!m_mem.Write(r.address, newValue)) ok = false;
        return ok;
    }

    bool writeOffset(size_t offset, const T& newValue) const {
        bool ok = true;
        for (const auto& r : m_results)
            if (!m_mem.Write(r.address + offset, newValue)) ok = false;
        return ok;
    }

    // ── 集合操作 ──────────────────────────────────────
    ResultSet intersect(const ResultSet& other) const {
        std::unordered_set<uintptr_t> addrs;
        for (const auto& r : other.m_results) addrs.insert(r.address);
        std::vector<Result> inter;
        for (const auto& r : m_results)
            if (addrs.count(r.address)) inter.push_back(r);
        return ResultSet(m_mem, std::move(inter));
    }

    ResultSet unite(const ResultSet& other) const {
        std::unordered_map<uintptr_t, Result> map;
        for (const auto& r : m_results) map[r.address] = r;
        for (const auto& r : other.m_results)
            if (!map.count(r.address)) map[r.address] = r;
        std::vector<Result> united;
        united.reserve(map.size());
        for (auto& p : map) united.push_back(p.second);
        return ResultSet(m_mem, std::move(united));
    }

    std::vector<uintptr_t> addresses() const {
        std::vector<uintptr_t> addrs;
        addrs.reserve(m_results.size());
        for (const auto& r : m_results) addrs.push_back(r.address);
        return addrs;
    }

    void clear() { m_results.clear(); m_truncated = false; }

    // ── 打印 (调试) ──────────────────────────────────
    void print(size_t n = 10) const {
        size_t show = std::min(n, m_results.size());
        printf("  [ResultSet] %zu results%s\n", m_results.size(),
               m_truncated ? " (TRUNCATED)" : "");
        for (size_t i = 0; i < show; i++) {
            printf("    [%zu] 0x%llx = ", i, (unsigned long long)m_results[i].address);
            printValue(m_results[i].value);
            printf("\n");
        }
        if (m_results.size() > show)
            printf("    ... (%zu more)\n", m_results.size() - show);
    }

private:
    MemBase& m_mem;
    std::vector<Result> m_results;
    bool m_truncated = false;
    size_t m_totalAvailable = 0;

    // 允许 SearchEngine 访问私有成员
    template<typename> friend class SearchEngineImpl;

    template<typename U>
    static bool compareValue(const U& a, const U& b, CompareOp op) {
        switch (op) {
            case CompareOp::EQ:  return a == b;
            case CompareOp::NEQ: return a != b;
            case CompareOp::GT:  return a > b;
            case CompareOp::GTE: return a >= b;
            case CompareOp::LT:  return a < b;
            case CompareOp::LTE: return a <= b;
            default: return false;
        }
    }

    template<typename U>
    static void printValue(const U& v) {
        if constexpr (std::is_same_v<U, float>)
            printf("%.6f", v);
        else if constexpr (std::is_same_v<U, double>)
            printf("%.12f", v);
        else if constexpr (std::is_same_v<U, int64_t> || std::is_same_v<U, uint64_t>)
            printf("%lld", (long long)v);
        else if constexpr (std::is_same_v<U, uint8_t> || std::is_same_v<U, int8_t>)
            printf("%d", (int)v);
        else
            printf("%d", (int)v);
    }
};

// ============================================================
// SearchEngine — 主搜索接口
// ============================================================
class SearchEngine {
public:
    using ProgressCallback = std::function<bool(double progress)>;

    explicit SearchEngine(MemBase& mem) : m_mem(mem) {}
    SearchEngine() = delete;

    // ── 精确值搜索 ────────────────────────────────────
    template <typename T>
    ResultSet<T> search(const SearchParams& params, T value,
                        ProgressCallback progressCb = nullptr);

    // ── 模糊搜索 ──────────────────────────────────────
    template <typename T>
    ResultSet<T> searchCompare(const SearchParams& params, T reference, CompareOp op,
                                ProgressCallback progressCb = nullptr);

    // ── 范围搜索 ──────────────────────────────────────
    template <typename T>
    ResultSet<T> searchRange(const SearchParams& params, T min, T max,
                              ProgressCallback progressCb = nullptr);

    // ── 便捷重载 ──────────────────────────────────────
    template <typename T>
    ResultSet<T> search(T value) {
        SearchParams params;
        return search<T>(params, value);
    }

    template <typename T>
    ResultSet<T> searchFuzzy(T value, CompareOp op) {
        SearchParams params;
        return searchCompare<T>(params, value, op);
    }

    // ── 字符串搜索 ────────────────────────────────────
    std::vector<uintptr_t> searchString(const SearchParams& params,
                                         const std::string& str,
                                         bool includeNull = true,
                                         bool caseSensitive = true);
    std::vector<uintptr_t> searchString(const std::string& str) {
        SearchParams params;
        return searchString(params, str);
    }

    std::vector<uintptr_t> searchStringUTF16(const SearchParams& params,
                                              const std::u16string& str,
                                              bool includeNull = true,
                                              bool caseSensitive = true);

    // ── 特征码扫描 ────────────────────────────────────
    std::vector<uintptr_t> searchPattern(const SearchParams& params,
                                          const std::vector<uint8_t>& pattern,
                                          const std::vector<uint8_t>& mask = {});
    std::vector<uintptr_t> searchPattern(const std::string& hexPattern) {
        SearchParams params;
        return scanPatternString(params, hexPattern);
    }
    std::vector<uintptr_t> scanPatternString(const SearchParams& params,
                                              const std::string& hexPattern);

    // ── 异步扫描 (可提前终止) ──────────────────────────
    void searchPatternAsync(const SearchParams& params,
                            const std::string& hexPattern,
                            std::function<bool(uintptr_t)> callback);

    // ── 性能统计 ──────────────────────────────────────
    const SearchStats& lastStats() const { return m_stats; }

private:
    MemBase& m_mem;
    mutable SearchStats m_stats;

    // 获取可用内存区域
    std::vector<MemoryRange> getSearchableRanges(const SearchParams& params) const;

    // 并行扫描框架 (内部使用)
    // CheckFunc: void(uintptr_t base, const uint8_t* buffer, size_t bufSize,
    //                 std::vector<uintptr_t>& out, std::vector<uint8_t>& valueBuf)
    template <typename CheckFunc>
    void parallelScan(const SearchParams& params, CheckFunc&& checker,
                      std::vector<std::vector<uintptr_t>>& threadResults,
                      ProgressCallback progressCb = nullptr) const;

    // 统计
    void updateStats(std::chrono::high_resolution_clock::time_point t0,
                     std::chrono::high_resolution_clock::time_point t1,
                     size_t bytesRead, size_t totalBytes, size_t resultCount,
                     unsigned int numThreads) const;

    // 模式解析
    static bool parseHexPattern(const std::string& s,
                                std::vector<uint8_t>& pattern,
                                std::vector<uint8_t>& mask);
};

// ============================================================
// ============================================================
// 类型别名
// ============================================================
using Search = SearchEngine;
using Compare = CompareOp;

// ============================================================
// 模板实现
// ============================================================

// ============================================================
// 反检测: 常驻内存过滤
// ============================================================
// 依据 /proc/pid/pagemap 第 63 位(PRESENT)判断页面是否在 RAM,
// 仅保留常驻内存页组成的连续子区间, 跳过已换出到 非驻留页。
// 这样跨进程扫描(process_vm_readv)不会触发目标进程补页,
// 从而避免被反外挂检测。需要 root 权限才能读取 pagemap。
inline std::vector<MemoryRange> filterResidentRanges(int pid, std::vector<MemoryRange> ranges) {
#ifdef __linux__
    long pagesize = sysconf(_SC_PAGESIZE);
    if (pagesize <= 0) pagesize = 4096;
    size_t ps = (size_t)pagesize;

    std::string pmpath = "/proc/" + std::to_string(pid) + "/pagemap";
    int pmfd = open(pmpath.c_str(), O_RDONLY);
    if (pmfd < 0) {
        fprintf(stderr, "[!] 无法打开 %s (需 root 权限), 跳过常驻过滤\n", pmpath.c_str());
        return ranges;
    }

    const uint64_t PRESENT = 1ULL << 63;
    const size_t MAX_RUN = 1024u * 1024u; // 单次连续段上限 1MB, 便于上层按块读取
    std::vector<uint64_t> entries;
    std::vector<MemoryRange> out;

    for (const auto &r : ranges) {
        uintptr_t pstart = (r.start / ps) * ps;            // 下取整到页
        uintptr_t pend = ((r.end + ps - 1) / ps) * ps;     // 上取整到页
        if (pend <= pstart) continue;
        size_t npages = (pend - pstart) / ps;
        entries.resize(npages);

        off_t eoff = (off_t)(pstart / ps) * (off_t)sizeof(uint64_t);
        size_t total = npages * sizeof(uint64_t);
        size_t done = 0;
        while (done < total) {
            ssize_t n = pread(pmfd, (char *)entries.data() + done, total - done, eoff + (off_t)done);
            if (n <= 0) break;
            done += (size_t)n;
        }
        size_t valid = done / sizeof(uint64_t);

        size_t i = 0;
        while (i < valid) {
            if (!(entries[i] & PRESENT)) { ++i; continue; }
            size_t run = 1;
            while (i + run < valid && (run * ps) <= MAX_RUN && (entries[i + run] & PRESENT))
                ++run;
            uintptr_t s = pstart + i * ps;
            uintptr_t e = pstart + (i + run) * ps;
            if (e > r.end) e = r.end;
            if (s < r.start) s = r.start;
            if (s < e) out.push_back({s, e});
            i += run;
        }
    }

    close(pmfd);
    return out;
#else
    (void)pid;
    return ranges;
#endif
}

// 对 ProcMap 列表做同样的常驻过滤 (用于 FuzzySearch 快照流程)
inline std::vector<ProcMap> filterResidentMaps(int pid, const std::vector<ProcMap> &maps) {
#ifdef __linux__
    std::vector<ProcMap> out;
    out.reserve(maps.size());
    for (const auto &m : maps) {
        if (!m.isValid() || !m.readable) { out.push_back(m); continue; }
        auto subs = filterResidentRanges(pid, {{m.startAddress, m.endAddress}});
        for (const auto &sub : subs) {
            ProcMap nm = m;
            nm.startAddress = sub.start;
            nm.endAddress = sub.end;
            nm.length = sub.end - sub.start;
            out.push_back(nm);
        }
    }
    return out;
#else
    (void)pid;
    return maps;
#endif
}

// ── 共享: 构建可搜索区域列表 ────────────────────────
inline std::vector<MemoryRange> buildSearchRanges(MemBase& mem, const SearchParams& params) {
    auto maps = Process::get_process_maps(mem.get_pid());
    std::vector<MemoryRange> ranges;
    for (const auto& map : maps) {
        if (!map.isValid() || !map.readable) continue;
        uint32_t t = static_cast<uint32_t>(map.getMemType());
        if (params.memTypeMask != 0 && (t & params.memTypeMask) == 0) continue;
        uintptr_t s = std::max(static_cast<uintptr_t>(map.startAddress), params.startAddress);
        uintptr_t e = std::min(static_cast<uintptr_t>(map.endAddress),   params.endAddress);
        if (s < e) ranges.push_back({s, e});
    }
    if (params.residentOnly)
        ranges = filterResidentRanges(mem.get_pid(), std::move(ranges));
    std::sort(ranges.begin(), ranges.end(),
              [](const MemoryRange& a, const MemoryRange& b) {
                  return (a.end - a.start) > (b.end - b.start); });
    return ranges;
}

// ── 获取可搜索区域 ───────────────────────────────────
inline std::vector<MemoryRange> SearchEngine::getSearchableRanges(
    const SearchParams& params) const
{
    return buildSearchRanges(m_mem, params);
}

// ── 统计更新 ─────────────────────────────────────────
inline void SearchEngine::updateStats(
    std::chrono::high_resolution_clock::time_point t0,
    std::chrono::high_resolution_clock::time_point t1,
    size_t bytesRead, size_t totalBytes, size_t resultCount,
    unsigned int numThreads) const
{
    double elapsedMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    m_stats.elapsedMs    = elapsedMs;
    m_stats.totalBytes   = totalBytes;
    m_stats.bytesRead    = bytesRead;
    m_stats.resultCount  = resultCount;
    m_stats.throughputMBs = (elapsedMs > 0)
        ? (bytesRead / (1024.0 * 1024.0)) / (elapsedMs / 1000.0) : 0;
    m_stats.numThreads   = numThreads;
}

// ── 并行扫描框架 ─────────────────────────────────────
template <typename CheckFunc>
inline void SearchEngine::parallelScan(
    const SearchParams& params,
    CheckFunc&& checker,
    std::vector<std::vector<uintptr_t>>& threadResults,
    ProgressCallback progressCb) const
{
    auto ranges = getSearchableRanges(params);
    if (ranges.empty()) return;

    const size_t CHUNK_SIZE = params.effectiveChunkSize();

    // 计算总字节数
    size_t totalBytes = 0;
    for (const auto& r : ranges) totalBytes += (r.end - r.start);

    // 线程数
    unsigned int numThreads = params.numThreads;
    if (numThreads == 0) {
        numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0) numThreads = 4;
    }
    numThreads = std::min(numThreads, static_cast<unsigned int>(ranges.size()));

    threadResults.resize(numThreads);
    for (auto& v : threadResults) v.reserve(65536);

    std::atomic<size_t> nextIdx{0};
    std::atomic<size_t> totalBytesRead{0};
    std::atomic<bool> cancelled{false};

    auto worker = [&](int tid) {
        std::vector<uint8_t> buffer(CHUNK_SIZE);
        auto& localResults = threadResults[tid];

        while (!cancelled.load()) {
            size_t idx = nextIdx.fetch_add(1);
            if (idx >= ranges.size()) break;

            const auto& range = ranges[idx];
            uintptr_t cur = range.start;
            uintptr_t end = range.end;

            while (cur < end && !cancelled.load()) {
                size_t toRead = std::min(CHUNK_SIZE, static_cast<size_t>(end - cur));
                if (!m_mem.read(cur, buffer.data(), toRead)) {
                    cur += 4096;
                    continue;
                }
                totalBytesRead.fetch_add(toRead, std::memory_order_relaxed);
                checker(cur, buffer.data(), toRead, localResults);
                cur += toRead;
            }
        }
    };

    auto t0 = std::chrono::high_resolution_clock::now();

    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    for (unsigned int i = 0; i < numThreads; ++i)
        threads.emplace_back(worker, i);

    // 进度回调 (轮询)
    if (progressCb) {
        while (true) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            size_t done = nextIdx.load();
            double progress = std::min(1.0, static_cast<double>(done) / ranges.size());
            if (!progressCb(progress)) {
                cancelled.store(true);
                break;
            }
            if (done >= ranges.size()) break;
        }
    }

    for (auto& t : threads) t.join();

    auto t1 = std::chrono::high_resolution_clock::now();

    // 合并统计
    size_t totalRes = 0;
    for (const auto& v : threadResults) totalRes += v.size();
    updateStats(t0, t1, totalBytesRead.load(), totalBytes, totalRes, numThreads);
}

// ── 共享: 并行值搜索框架 ──────────────────────────────
// ChunkFunc: void(uintptr_t base, const uint8_t* buf, size_t bufSize,
//                 std::vector<SearchResult<T>>& out, std::atomic<size_t>& total)
template <typename T, typename ChunkFunc>
static void parallelValueScan(const SearchParams& params, MemBase& mem,
                               ChunkFunc&& processChunk,
                               std::vector<SearchResult<T>>& results,
                               const SearchEngine::ProgressCallback& progressCb,
                               SearchStats& stats) {
    using Result = SearchResult<T>;
    const size_t typeSize = sizeof(T);
    auto ranges = buildSearchRanges(mem, params);
    if (ranges.empty()) { stats.elapsedMs = 0; return; }

    const size_t CHUNK_SIZE = params.effectiveChunkSize();
    size_t totalBytes = 0;
    for (const auto& r : ranges) totalBytes += (r.end - r.start);

    unsigned int numThreads = params.numThreads;
    if (numThreads == 0) {
        numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0) numThreads = 4;
    }
    numThreads = std::min(numThreads, static_cast<unsigned int>(ranges.size()));

    struct TL { std::vector<Result> results; };
    std::vector<TL> threadData(numThreads);
    for (auto& td : threadData) td.results.reserve(65536);

    std::atomic<size_t> nextIdx{0}, totalBytesRead{0}, totalResults{0};
    std::atomic<bool> cancelled{false};
    const size_t maxResults = params.maxResults;

    auto worker = [&](int tid) {
        std::vector<uint8_t> buffer(CHUNK_SIZE + typeSize - 1);
        auto& out = threadData[tid].results;
        while (!cancelled.load()) {
            if (maxResults > 0 && totalResults.load() >= maxResults) break;
            size_t idx = nextIdx.fetch_add(1);
            if (idx >= ranges.size()) break;
            const auto& range = ranges[idx];
            uintptr_t cur = range.start, end = range.end;
            if (params.align) { uintptr_t rem = cur % typeSize; if (rem) cur += typeSize - rem; }
            while (cur < end && !cancelled.load()) {
                if (maxResults > 0 && totalResults.load() >= maxResults) break;
                size_t toRead = std::min(CHUNK_SIZE + typeSize - 1, static_cast<size_t>(end - cur));
                if (!mem.read(cur, buffer.data(), toRead)) { cur += 4096; continue; }
                totalBytesRead.fetch_add(toRead, std::memory_order_relaxed);
                processChunk(cur, buffer.data(), toRead, out, totalResults);
                cur += std::min(CHUNK_SIZE, static_cast<size_t>(end - cur));
            }
        }
    };

    auto t0 = std::chrono::high_resolution_clock::now();
    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    for (unsigned int i = 0; i < numThreads; ++i) threads.emplace_back(worker, i);

    std::thread progressThread;
    if (progressCb) {
        progressThread = std::thread([&]() {
            while (!cancelled.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                size_t done = nextIdx.load();
                if (done >= ranges.size()) break;
                if (!progressCb(std::min(1.0, (double)done / ranges.size())))
                { cancelled.store(true); break; }
            }
        });
    }
    for (auto& t : threads) t.join();
    cancelled.store(true);
    if (progressThread.joinable()) progressThread.join();
    auto t1 = std::chrono::high_resolution_clock::now();

    // 合并
    size_t total = 0;
    for (const auto& td : threadData) total += td.results.size();
    results.reserve(std::min(total, maxResults > 0 ? maxResults : total));
    for (auto& td : threadData)
        for (auto& r : td.results)
            if (maxResults == 0 || results.size() < maxResults)
                results.push_back(std::move(r));

    double elapsedMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    stats.elapsedMs = elapsedMs; stats.totalBytes = totalBytes;
    stats.bytesRead = totalBytesRead.load(); stats.resultCount = results.size();
    stats.throughputMBs = (elapsedMs > 0) ? (stats.bytesRead / (1024.0*1024.0)) / (elapsedMs/1000.0) : 0;
    stats.numThreads = numThreads;
}

// ── 精确值搜索 (BMH) ──────────────────────────────────
template <typename T>
static void searchEqFast(const SearchParams& params, MemBase& mem,
                          T value, std::vector<SearchResult<T>>& results,
                          const SearchEngine::ProgressCallback& progressCb,
                          SearchStats& stats) {
    std::vector<uint8_t> pattern(sizeof(T));
    memcpy(pattern.data(), &value, sizeof(T));
    FastSearch::OptimizedPatternSearch os;
    os.init(pattern.data(), sizeof(T));
    const size_t MAX_M = 131072;
    parallelValueScan<T>(params, mem, [&](uintptr_t base, const uint8_t* buf, size_t sz,
                           std::vector<SearchResult<T>>& out, std::atomic<size_t>& tres) {
        thread_local std::vector<uintptr_t> mb;
        if (mb.size() < MAX_M) mb.resize(MAX_M);
        size_t n = os.search(buf, sz, mb.data(), MAX_M);
        for (size_t k = 0; k < n; k++) {
            uintptr_t addr = base + mb[k];
            if (params.align && (addr % sizeof(T) != 0)) continue;
            T v; memcpy(&v, buf + mb[k], sizeof(T));
            out.push_back({addr, v});
        }
        tres.fetch_add(n, std::memory_order_relaxed);
    }, results, progressCb, stats);
}

// ── 逐值比较搜索 (NEQ/GT/LT/RANGE) ────────────────────
template <typename T, typename JudgeFunc>
static void searchGeneric(const SearchParams& params, MemBase& mem,
                           JudgeFunc&& judge,
                           std::vector<SearchResult<T>>& results,
                           const SearchEngine::ProgressCallback& progressCb,
                           SearchStats& stats) {
    const size_t ts = sizeof(T), step = params.align ? ts : 1;
    parallelValueScan<T>(params, mem, [&](uintptr_t base, const uint8_t* buf, size_t sz,
                           std::vector<SearchResult<T>>& out, std::atomic<size_t>& tres) {
        size_t limit = sz - ts + 1;
        for (size_t off = 0; off < limit; off += step) {
            T v; memcpy(&v, buf + off, ts);
            if (judge(v)) { out.push_back({base + off, v}); tres.fetch_add(1, std::memory_order_relaxed); }
        }
    }, results, progressCb, stats);
}

// ── 精确值搜索 ───────────────────────────────────────
template <typename T>
inline ResultSet<T> SearchEngine::search(const SearchParams& params, T value,
                                          ProgressCallback progressCb)
{
    std::vector<SearchResult<T>> results;
    searchEqFast(params, m_mem, value, results, progressCb, m_stats);
    return ResultSet<T>(m_mem, std::move(results));
}

// ── 模糊搜索 ─────────────────────────────────────────
template <typename T>
inline ResultSet<T> SearchEngine::searchCompare(const SearchParams& params,
                                                  T reference, CompareOp op,
                                                  ProgressCallback progressCb)
{
    using Result = SearchResult<T>;
    std::vector<Result> results;

    switch (op) {
    case CompareOp::EQ:
        return search(params, reference, progressCb);

    case CompareOp::NEQ:
        searchGeneric<T>(params, m_mem,
            [reference](T v) { return v != reference; },
            results, progressCb, m_stats);
        break;

    case CompareOp::GT:
        searchGeneric<T>(params, m_mem,
            [reference](T v) { return v > reference; },
            results, progressCb, m_stats);
        break;

    case CompareOp::GTE:
        searchGeneric<T>(params, m_mem,
            [reference](T v) { return v >= reference; },
            results, progressCb, m_stats);
        break;

    case CompareOp::LT:
        searchGeneric<T>(params, m_mem,
            [reference](T v) { return v < reference; },
            results, progressCb, m_stats);
        break;

    case CompareOp::LTE:
        searchGeneric<T>(params, m_mem,
            [reference](T v) { return v <= reference; },
            results, progressCb, m_stats);
        break;

    case CompareOp::RANGE:
        throw SearchException("Use searchRange() for range queries");
        break;

    case CompareOp::CHANGED:
    case CompareOp::UNCHANGED:
    case CompareOp::INCREASED:
    case CompareOp::DECREASED:
        throw SearchException(
            "Snapshot-based operators (CHANGED/UNCHANGED/INCREASED/DECREASED) "
            "require per-address comparison. Use FuzzySearch class for this workflow, "
            "or use searchCompare with snapshot parameter.");
        break;
    }

    return ResultSet<T>(m_mem, std::move(results));
}

// ── 范围搜索 ─────────────────────────────────────────
template <typename T>
inline ResultSet<T> SearchEngine::searchRange(const SearchParams& params,
                                                T min, T max,
                                                ProgressCallback progressCb)
{
    static_assert(std::is_arithmetic_v<T>, "searchRange requires arithmetic type");
    using Result = SearchResult<T>;
    std::vector<Result> results;
    searchGeneric<T>(params, m_mem,
        [min, max](T v) { return v >= min && v <= max; },
        results, progressCb, m_stats);
    return ResultSet<T>(m_mem, std::move(results));
}

#endif // SEARCH_HPP

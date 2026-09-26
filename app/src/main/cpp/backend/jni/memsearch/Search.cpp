#include "Search.hpp"
#include <cstring>
#include <algorithm>
#include <cctype>
#include <chrono>

// ── 辅助: 合并 parallelScan 结果 ─────────────────────
static std::vector<uintptr_t> mergeThreadResults(std::vector<std::vector<uintptr_t>>& tr) {
    size_t total = 0;
    for (auto& v : tr) total += v.size();
    std::vector<uintptr_t> r;
    r.reserve(total);
    for (auto& v : tr) r.insert(r.end(), v.begin(), v.end());
    return r;
}

// ============================================================
// 十六进制模式字符串解析
// ============================================================
bool SearchEngine::parseHexPattern(const std::string& patternStr,
                                    std::vector<uint8_t>& pattern,
                                    std::vector<uint8_t>& mask) {
    pattern.clear();
    mask.clear();
    std::string hex;
    for (char ch : patternStr) {
        if (ch == ' ') {
            if (!hex.empty()) {
                if (hex == "?" || hex == "??") {
                    pattern.push_back(0x00);
                    mask.push_back(0x00);
                } else {
                    if (hex.size() != 2) return false;
                    int val = 0;
                    if (sscanf(hex.c_str(), "%02x", &val) != 1) return false;
                    pattern.push_back(static_cast<uint8_t>(val));
                    mask.push_back(0xFF);
                }
                hex.clear();
            }
        } else {
            hex.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
        }
    }
    if (!hex.empty()) {
        if (hex == "?" || hex == "??") {
            pattern.push_back(0x00);
            mask.push_back(0x00);
        } else {
            if (hex.size() != 2) return false;
            int val = 0;
            if (sscanf(hex.c_str(), "%02x", &val) != 1) return false;
            pattern.push_back(static_cast<uint8_t>(val));
            mask.push_back(0xFF);
        }
    }
    return !pattern.empty();
}

// ============================================================
// 字符串解析 → 模式搜索
// ============================================================
std::vector<uintptr_t> SearchEngine::scanPatternString(const SearchParams& params,
                                                        const std::string& hexPattern) {
    std::vector<uint8_t> pattern, mask;
    if (!parseHexPattern(hexPattern, pattern, mask))
        return {};
    return searchPattern(params, pattern, mask);
}

// ============================================================
// 模式搜索 (BMH + parallelScan)
// ============================================================
std::vector<uintptr_t> SearchEngine::searchPattern(
    const SearchParams& params,
    const std::vector<uint8_t>& pattern,
    const std::vector<uint8_t>& mask)
{
    if (pattern.empty()) return {};

    std::vector<uint8_t> effectiveMask = mask;
    if (effectiveMask.empty())
        effectiveMask.resize(pattern.size(), 0xFF);
    if (effectiveMask.size() != pattern.size())
        throw std::invalid_argument("Mask size must equal pattern size");

    bool hasWildcard = false;
    for (uint8_t m : effectiveMask)
        if (m == 0) { hasWildcard = true; break; }

    FastSearch::OptimizedPatternSearch optSearch;
    if (hasWildcard)
        optSearch.init(pattern.data(), effectiveMask.data(), pattern.size());
    else
        optSearch.init(pattern.data(), pattern.size());

    const size_t MAX_PER_CHUNK = 131072;
    const size_t maxR = params.maxResults;

    std::vector<std::vector<uintptr_t>> threadResults;
    auto checker = [&](uintptr_t base, const uint8_t* buffer, size_t bufSize,
                       std::vector<uintptr_t>& out) {
        thread_local std::vector<uintptr_t> tlsMatchBuf;
        if (tlsMatchBuf.size() < MAX_PER_CHUNK)
            tlsMatchBuf.resize(MAX_PER_CHUNK);
        if (maxR > 0 && out.size() >= maxR) return;
        size_t found = optSearch.search(buffer, bufSize, tlsMatchBuf.data(), MAX_PER_CHUNK);
        for (size_t k = 0; k < found; k++) {
            if (maxR > 0 && out.size() >= maxR) break;
            out.push_back(base + tlsMatchBuf[k]);
        }
    };

    parallelScan(params, checker, threadResults);
    auto results = mergeThreadResults(threadResults);
    if (maxR > 0 && results.size() > maxR) results.resize(maxR);
    return results;
}

// ============================================================
// 异步模式扫描
// ============================================================
void SearchEngine::searchPatternAsync(const SearchParams& params,
                                       const std::string& hexPattern,
                                       std::function<bool(uintptr_t)> callback)
{
    std::vector<uint8_t> pattern, mask;
    if (!parseHexPattern(hexPattern, pattern, mask))
        return;

    if (mask.empty()) mask.resize(pattern.size(), 0xFF);

    bool hasWildcard = false;
    for (uint8_t m : mask) {
        if (m == 0) { hasWildcard = true; break; }
    }

    FastSearch::OptimizedPatternSearch optSearch;
    if (hasWildcard)
        optSearch.init(pattern.data(), mask.data(), pattern.size());
    else
        optSearch.init(pattern.data(), pattern.size());

    const size_t MAX_PER_CHUNK = 131072;
    auto ranges = getSearchableRanges(params);
    if (ranges.empty()) return;

    const size_t CHUNK_SIZE = params.effectiveChunkSize();

    unsigned int numThreads = params.numThreads;
    if (numThreads == 0) {
        numThreads = std::thread::hardware_concurrency();
        if (numThreads == 0) numThreads = 4;
    }
    numThreads = std::min(numThreads, static_cast<unsigned int>(ranges.size()));

    std::atomic<size_t> nextIdx{0};
    std::atomic<bool> stopFlag{false};

    auto worker = [&](int) {
        std::vector<uint8_t> buffer(CHUNK_SIZE + pattern.size() - 1);
        thread_local std::vector<uintptr_t> tlsMatchBuf;
        if (tlsMatchBuf.size() < MAX_PER_CHUNK)
            tlsMatchBuf.resize(MAX_PER_CHUNK);

        while (!stopFlag.load()) {
            size_t idx = nextIdx.fetch_add(1);
            if (idx >= ranges.size()) break;

            const auto& range = ranges[idx];
            uintptr_t cur = range.start;
            uintptr_t end = range.end;

            while (cur < end && !stopFlag.load()) {
                size_t toRead = std::min(CHUNK_SIZE + pattern.size() - 1,
                                         static_cast<size_t>(end - cur));
                if (!m_mem.read(cur, buffer.data(), toRead)) {
                    cur += 4096;
                    continue;
                }

                size_t found = optSearch.search(buffer.data(), toRead,
                                                tlsMatchBuf.data(), MAX_PER_CHUNK);
                for (size_t k = 0; k < found; k++) {
                    if (stopFlag.load()) return;
                    if (!callback(cur + tlsMatchBuf[k])) {
                        stopFlag.store(true);
                        return;
                    }
                }
                cur += std::min(CHUNK_SIZE, static_cast<size_t>(end - cur));
            }
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    for (unsigned int i = 0; i < numThreads; ++i)
        threads.emplace_back(worker, i);
    for (auto& t : threads) t.join();
}

// ============================================================
// UTF-8 字符串搜索
// ============================================================
std::vector<uintptr_t> SearchEngine::searchString(const SearchParams& params,
                                                    const std::string& str,
                                                    bool includeNull,
                                                    bool caseSensitive)
{
    if (str.empty()) return {};

    // 构建模式
    std::vector<uint8_t> pattern;
    for (char c : str)
        pattern.push_back(caseSensitive
            ? static_cast<uint8_t>(c)
            : static_cast<uint8_t>(std::tolower(static_cast<unsigned char>(c))));
    if (includeNull) pattern.push_back(0);

    if (caseSensitive) {
        std::vector<uint8_t> mask(pattern.size(), 0xFF);
        return searchPattern(params, pattern, mask);
    }

    // 大小写不敏感 — parallelScan + 逐字节 tolower
    const size_t patLen2 = pattern.size();
    std::vector<std::vector<uintptr_t>> threadResults;
    auto checker2 = [&](uintptr_t base, const uint8_t* buffer, size_t bufSize,
                         std::vector<uintptr_t>& out) {
        for (size_t i = 0; i + patLen2 <= bufSize; i++) {
            bool match = true;
            for (size_t j = 0; j < patLen2; j++) {
                if ((unsigned char)std::tolower(buffer[i + j]) != pattern[j])
                { match = false; break; }
            }
            if (match) out.push_back(base + i);
        }
    };
    parallelScan(params, checker2, threadResults);
    return mergeThreadResults(threadResults);
}

// ============================================================
// UTF-16 字符串搜索
// ============================================================
std::vector<uintptr_t> SearchEngine::searchStringUTF16(const SearchParams& params,
                                                        const std::u16string& str,
                                                        bool includeNull,
                                                        bool caseSensitive)
{
    if (str.empty()) return {};

    // 构建小端序模式
    std::vector<uint8_t> pattern;
    for (char16_t ch : str) {
        char16_t out = ch;
        if (!caseSensitive && ch < 128)
            out = static_cast<char16_t>(std::tolower(static_cast<int>(ch)));
        pattern.push_back(static_cast<uint8_t>(out & 0xFF));
        pattern.push_back(static_cast<uint8_t>((out >> 8) & 0xFF));
    }
    if (includeNull) { pattern.push_back(0); pattern.push_back(0); }

    if (caseSensitive) {
        std::vector<uint8_t> mask(pattern.size(), 0xFF);
        return searchPattern(params, pattern, mask);
    }

    // 大小写不敏感 — 逐 uint16 重建 + ASCII tolower
    const size_t patLen3 = pattern.size();
    std::vector<std::vector<uintptr_t>> threadResults3;
    auto checker3 = [&](uintptr_t base, const uint8_t* buffer, size_t bufSize,
                         std::vector<uintptr_t>& out) {
        for (size_t i = 0; i + patLen3 <= bufSize; i += 2) {
            bool match = true;
            for (size_t j = 0; j < patLen3; j += 2) {
                uint16_t val = (uint16_t)(buffer[i+j] | (buffer[i+j+1] << 8));
                uint16_t exp = (uint16_t)(pattern[j] | (pattern[j+1] << 8));
                if (val < 128) val = (uint16_t)std::tolower((int)val);
                if (val != exp) { match = false; break; }
            }
            if (match) out.push_back(base + i);
        }
    };
    parallelScan(params, checker3, threadResults3);
    return mergeThreadResults(threadResults3);
}

#ifndef FASTSEARCH_HPP
#define FASTSEARCH_HPP

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <algorithm>
#include <vector>

// ============================================================
// Boyer-Moore-Horspool 算法实现
// 特点：O(n) 最坏情况, O(n/m) 最佳情况, 极简预处理
// 非常适合在大量内存中搜索少量模式
// ============================================================

namespace FastSearch {

// ----------------------------------------------------------
// BMH 坏字符跳表 (256 字节)
// ----------------------------------------------------------
struct BMHContext {
    size_t skip[256];
    const uint8_t* pattern;
    size_t patLen;

    BMHContext() : pattern(nullptr), patLen(0) {
        memset(skip, 0, sizeof(skip));
    }
};

// 构建 BMH 跳表 — 无掩码版本
inline void bmh_init(BMHContext& ctx, const uint8_t* pattern, size_t patLen) {
    ctx.pattern = pattern;
    ctx.patLen = patLen;
    // 初始化为模式长度 (未出现在模式中的字符跳过整个模式)
    for (int i = 0; i < 256; i++) {
        ctx.skip[i] = patLen;
    }
    // 设置模式中出现的字符的跳距
    for (size_t i = 0; i < patLen - 1; i++) {
        ctx.skip[pattern[i]] = patLen - 1 - i;
    }
}

// 构建 BMH 跳表 — 带掩码版本 (通配符字节不影响跳表)
inline void bmh_init_masked(BMHContext& ctx, const uint8_t* pattern,
                             const uint8_t* mask, size_t patLen) {
    ctx.pattern = pattern;
    ctx.patLen = patLen;
    for (int i = 0; i < 256; i++) {
        ctx.skip[i] = patLen;
    }
    for (size_t i = 0; i < patLen - 1; i++) {
        if (mask[i]) {  // 只有非通配符字节参与跳表
            ctx.skip[pattern[i]] = patLen - 1 - i;
        }
    }
}

// ----------------------------------------------------------
// BMH 搜索 — 无掩码精确匹配, 返回所有匹配位置
// out: 输出 buffer, maxOut: 最大输出数
// 返回: 实际匹配数
// ----------------------------------------------------------
inline size_t bmh_search(const BMHContext& ctx,
                          const uint8_t* buffer, size_t bufSize,
                          uintptr_t* out, size_t maxOut) {
    if (ctx.patLen == 0 || bufSize < ctx.patLen) return 0;

    const uint8_t* pat = ctx.pattern;
    const size_t m = ctx.patLen;
    const size_t* skip = ctx.skip;
    size_t count = 0;

    size_t i = 0;
    while (i + m <= bufSize && count < maxOut) {
        // 从右向左比较
        size_t j = m - 1;
        while (j != (size_t)-1 && buffer[i + j] == pat[j]) {
            j--;
        }
        if (j == (size_t)-1) {
            // 完全匹配
            out[count++] = i;
            i++;  // 步进1，继续搜索下一个
        } else {
            // 根据坏字符规则跳过
            i += skip[buffer[i + m - 1]];
        }
    }
    return count;
}

// ----------------------------------------------------------
// BMH 搜索 — 带掩码 (通配符支持)
// mask[j] == 0 表示该字节是通配符，不参与比较
// ----------------------------------------------------------
inline size_t bmh_search_masked(const BMHContext& ctx,
                                 const uint8_t* buffer, size_t bufSize,
                                 const uint8_t* mask,
                                 uintptr_t* out, size_t maxOut) {
    if (ctx.patLen == 0 || bufSize < ctx.patLen) return 0;

    const uint8_t* pat = ctx.pattern;
    const size_t m = ctx.patLen;
    const size_t* skip = ctx.skip;
    size_t count = 0;

    // 找到最右边的非通配符字节用于跳表查询
    ptrdiff_t lastNonWild = -1;
    for (size_t k = m; k > 0; k--) {
        if (mask[k - 1]) {
            lastNonWild = static_cast<ptrdiff_t>(k - 1);
            break;
        }
    }
    if (lastNonWild < 0) {
        // 全部是通配符 — 每个位置都匹配
        size_t limit = bufSize - m + 1;
        size_t n = std::min(limit, maxOut);
        for (size_t p = 0; p < n; p++) {
            out[p] = p;
        }
        return n;
    }

    size_t i = 0;
    while (i + m <= bufSize && count < maxOut) {
        // 先检查最右非通配符字节
        size_t lastIdx = static_cast<size_t>(lastNonWild);
        if (buffer[i + lastIdx] != pat[lastIdx]) {
            // 不匹配 — 跳
            i += skip[buffer[i + m - 1]];
            continue;
        }
        // 检查其他字节
        bool match = true;
        for (size_t j = 0; j < m; j++) {
            if (mask[j] && buffer[i + j] != pat[j]) {
                match = false;
                break;
            }
        }
        if (match) {
            out[count++] = i;
            i++;
        } else {
            i += skip[buffer[i + m - 1]];
        }
    }
    return count;
}

// ----------------------------------------------------------
// 组合优化搜索器 — 自动选择最佳算法
// 短模式 (<=3): 使用朴素搜索 (BMH 开销太大)
// 长模式 (>3):  使用 BMH
// ----------------------------------------------------------
class OptimizedPatternSearch {
public:
    OptimizedPatternSearch() : m_patLen(0), m_useBMH(false) {}

    // 初始化搜索器 (无掩码)
    void init(const uint8_t* pattern, size_t patLen) {
        m_patLen = patLen;
        m_useBMH = (patLen > 3);
        m_hasMask = false;
        if (m_useBMH) {
            bmh_init(m_bmh, pattern, patLen);
        } else {
            memcpy(m_pattern, pattern, patLen);
        }
    }

    // 初始化搜索器 (带掩码)
    void init(const uint8_t* pattern, const uint8_t* mask, size_t patLen) {
        m_patLen = patLen;

        // 检查是否有任何通配符
        bool hasWildcard = false;
        for (size_t i = 0; i < patLen; i++) {
            if (mask[i] == 0) { hasWildcard = true; break; }
        }
        // 长模式 (>4) 且无通配符 → BMH；否则朴素
        m_useBMH = (!hasWildcard && patLen > 4);
        m_hasMask = hasWildcard;

        if (m_useBMH) {
            bmh_init(m_bmh, pattern, patLen);
        } else {
            memcpy(m_pattern, pattern, patLen);
            memcpy(m_mask, mask, patLen);
        }
    }

    // 在 buffer 中搜索，输出匹配位置到 out，最多 maxOut 个
    size_t search(const uint8_t* buffer, size_t bufSize,
                  uintptr_t* out, size_t maxOut) const {
        if (m_patLen == 0 || bufSize < m_patLen) return 0;

        if (!m_useBMH) {
            // 朴素搜索
            size_t limit = bufSize - m_patLen + 1;
            size_t count = 0;
            if (m_hasMask) {
                for (size_t i = 0; i < limit && count < maxOut; i++) {
                    bool match = true;
                    for (size_t j = 0; j < m_patLen; j++) {
                        if (m_mask[j] && buffer[i + j] != m_pattern[j]) {
                            match = false; break;
                        }
                    }
                    if (match) out[count++] = i;
                }
            } else {
                for (size_t i = 0; i < limit && count < maxOut; i++) {
                    if (memcmp(buffer + i, m_pattern, m_patLen) == 0) {
                        out[count++] = i;
                    }
                }
            }
            return count;
        }

        if (m_hasMask) {
            return bmh_search_masked(m_bmh, buffer, bufSize, m_mask, out, maxOut);
        } else {
            return bmh_search(m_bmh, buffer, bufSize, out, maxOut);
        }
    }

    size_t patternLength() const { return m_patLen; }

private:
    BMHContext m_bmh;
    uint8_t m_pattern[256];
    uint8_t m_mask[256];
    size_t m_patLen;
    bool m_useBMH;
    bool m_hasMask = false;
};

} // namespace FastSearch

#endif // FASTSEARCH_HPP

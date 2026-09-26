#pragma once

// 基于 AsmJit 的 AArch64 文本汇编器（imgui 侧，不走 socket）。
// 把 "nop" / "mov x0, xzr" / "ldr x0, [x1, #8]" 这类单条指令
// 转换成机器码字节。AsmJit 2.x 没有文本解析器，
// 因此在交给 AArch64 汇编器之前先在这里解析操作数。

#include <asmjit/a64.h>

#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace udt_asm {

using asmjit::Arch;
using asmjit::CodeBuffer;
using asmjit::CodeHolder;
using asmjit::Environment;
using asmjit::Error;
using asmjit::Imm;
using asmjit::InstId;
using asmjit::Operand_;

namespace a64 = asmjit::a64;
namespace arm = asmjit::arm;

static inline std::string Trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

// 按分隔符切分，忽略 []（内存操作数）内部的分隔符。
static inline void SplitTop(const std::string& s, char sep,
                            std::vector<std::string>& out) {
    out.clear();
    std::string cur;
    int depth = 0;
    for (char c : s) {
        if (c == '[') depth++;
        else if (c == ']') depth--;
        if (c == sep && depth == 0) {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    out.push_back(cur);
}

static inline bool ParseImm(const char* s, int64_t& out) {
    const char* p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == '#') p++;
    bool neg = false;
    if (*p == '-') { neg = true; p++; }
    else if (*p == '+') p++;
    if (!*p) return false;
    int base = 10;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { base = 16; p += 2; }
    else if (p[0] == '0' && (p[1] == 'b' || p[1] == 'B')) { base = 2; p += 2; }
    if (!*p) return false;
    char* end = nullptr;
    out = strtoll(p, &end, base);
    if (!end || *end) return false;
    if (neg) out = -out;
    return true;
}

// 解析 AArch64 条件码（cset w0, ne / b.ne 等），返回 asmjit
// 的 CondCode 数值（kEQ=2, kNE=3, ...，与 opcode 字段差 2）。
static inline bool ParseCondCode(const std::string& tok, uint32_t& cc) {
    if      (tok == "eq") cc = (uint32_t)arm::CondCode::kEQ;
    else if (tok == "ne") cc = (uint32_t)arm::CondCode::kNE;
    else if (tok == "cs" || tok == "hs") cc = (uint32_t)arm::CondCode::kCS;
    else if (tok == "cc" || tok == "lo") cc = (uint32_t)arm::CondCode::kCC;
    else if (tok == "mi") cc = (uint32_t)arm::CondCode::kMI;
    else if (tok == "pl") cc = (uint32_t)arm::CondCode::kPL;
    else if (tok == "vs") cc = (uint32_t)arm::CondCode::kVS;
    else if (tok == "vc") cc = (uint32_t)arm::CondCode::kVC;
    else if (tok == "hi") cc = (uint32_t)arm::CondCode::kHI;
    else if (tok == "ls") cc = (uint32_t)arm::CondCode::kLS;
    else if (tok == "ge") cc = (uint32_t)arm::CondCode::kGE;
    else if (tok == "lt") cc = (uint32_t)arm::CondCode::kLT;
    else if (tok == "gt") cc = (uint32_t)arm::CondCode::kGT;
    else if (tok == "le") cc = (uint32_t)arm::CondCode::kLE;
    else if (tok == "al") cc = (uint32_t)arm::CondCode::kAL;
    else return false;
    return true;
}

static inline bool ParseGpReg(const std::string& tok, a64::Gp& out) {
    if (tok == "xzr") { out = a64::Gp::make_x(a64::Gp::kIdZr); return true; }
    if (tok == "wzr") { out = a64::Gp::make_w(a64::Gp::kIdZr); return true; }
    if (tok == "sp")  { out = a64::Gp::make_x(a64::Gp::kIdSp); return true; }
    if (tok == "wsp") { out = a64::Gp::make_w(a64::Gp::kIdSp); return true; }
    if (tok == "fp")  { out = a64::Gp::make_x(a64::Gp::kIdFp); return true; }
    if (tok == "lr")  { out = a64::Gp::make_x(a64::Gp::kIdLr); return true; }
    if (tok.size() >= 2 && (tok[0] == 'x' || tok[0] == 'w')) {
        unsigned id = 0;
        for (size_t i = 1; i < tok.size(); ++i) {
            if (!isdigit((unsigned char)tok[i])) return false;
            id = id * 10 + (unsigned)(tok[i] - '0');
            if (id > 30) return false;
        }
        out = (tok[0] == 'x') ? a64::Gp::make_x(id) : a64::Gp::make_w(id);
        return true;
    }
    return false;
}

static inline bool ParseVecReg(const std::string& tok, a64::Vec& out) {
    if (tok.size() >= 2 &&
        (tok[0] == 'b' || tok[0] == 'h' || tok[0] == 's' ||
         tok[0] == 'd' || tok[0] == 'q')) {
        unsigned id = 0;
        for (size_t i = 1; i < tok.size(); ++i) {
            if (!isdigit((unsigned char)tok[i])) return false;
            id = id * 10 + (unsigned)(tok[i] - '0');
            if (id > 31) return false;
        }
        switch (tok[0]) {
            case 'b': out = a64::Vec::make_b(id); return true;
            case 'h': out = a64::Vec::make_h(id); return true;
            case 's': out = a64::Vec::make_s(id); return true;
            case 'd': out = a64::Vec::make_d(id); return true;
            case 'q': out = a64::Vec::make_q(id); return true;
            default: return false;
        }
    }
    if (tok.size() >= 2 && tok[0] == 'v') {
        size_t i = 1;
        unsigned id = 0;
        while (i < tok.size() && isdigit((unsigned char)tok[i])) {
            id = id * 10 + (unsigned)(tok[i] - '0');
            i++;
        }
        if (i == 1 || id > 31) return false;
        std::string arr = tok.substr(i);
        if (arr.empty()) {
            out = a64::Vec::make_v128(id);
            return true;
        }
        if (arr == ".8b")  { out = a64::Vec::make_v64_with_element_type(a64::VecElementType::kB, id); return true; }
        if (arr == ".16b") { out = a64::Vec::make_v128_with_element_type(a64::VecElementType::kB, id); return true; }
        if (arr == ".4h")  { out = a64::Vec::make_v64_with_element_type(a64::VecElementType::kH, id); return true; }
        if (arr == ".8h")  { out = a64::Vec::make_v128_with_element_type(a64::VecElementType::kH, id); return true; }
        if (arr == ".2s")  { out = a64::Vec::make_v64_with_element_type(a64::VecElementType::kS, id); return true; }
        if (arr == ".4s")  { out = a64::Vec::make_v128_with_element_type(a64::VecElementType::kS, id); return true; }
        if (arr == ".1d")  { out = a64::Vec::make_v64_with_element_type(a64::VecElementType::kD, id); return true; }
        if (arr == ".2d")  { out = a64::Vec::make_v128_with_element_type(a64::VecElementType::kD, id); return true; }
    }
    return false;
}

static inline bool ParseShiftOp(const std::string& tok, arm::Shift& out) {
    std::string s = Trim(tok);
    size_t sp = s.find_first_of(" \t");
    std::string op = (sp == std::string::npos) ? s : s.substr(0, sp);
    std::string arg = (sp == std::string::npos) ? "" : Trim(s.substr(sp));
    int64_t n = 0;
    if (!arg.empty() && !ParseImm(arg.c_str(), n)) return false;
    uint32_t v = (uint32_t)n;
    if (op == "lsl")  { out = arm::Shift(arm::ShiftOp::kLSL, v); return true; }
    if (op == "lsr")  { out = arm::Shift(arm::ShiftOp::kLSR, v); return true; }
    if (op == "asr")  { out = arm::Shift(arm::ShiftOp::kASR, v); return true; }
    if (op == "ror")  { out = arm::Shift(arm::ShiftOp::kROR, v); return true; }
    if (op == "uxtw") { out = arm::Shift(arm::ShiftOp::kUXTW, v); return true; }
    if (op == "sxtw") { out = arm::Shift(arm::ShiftOp::kSXTW, v); return true; }
    if (op == "uxtx") { out = arm::Shift(arm::ShiftOp::kUXTX, v); return true; }
    if (op == "sxtx") { out = arm::Shift(arm::ShiftOp::kSXTX, v); return true; }
    return false;
}

// 解析 "[base]"、"[base, #imm]"、"[base, #imm]!"、"[base], #imm"、
// "[base, index]"、"[base, index, shift #n]" 等内存操作数。
static inline bool ParseMem(const std::string& tok, a64::Mem& out) {
    std::string s = Trim(tok);
    if (s.empty() || s[0] != '[') return false;
    size_t close = s.find(']');
    if (close == std::string::npos) return false;
    std::string inner = Trim(s.substr(1, close - 1));
    std::string tail = Trim(s.substr(close + 1));

    bool pre = (tail == "!");
    bool post = false;
    int64_t postOff = 0;
    if (!tail.empty() && !pre) {
        if (tail[0] != ',') return false;
        if (!ParseImm(Trim(tail.substr(1)).c_str(), postOff)) return false;
        post = true;
    }

    std::vector<std::string> parts;
    SplitTop(inner, ',', parts);
    if (parts.empty() || parts.size() > 3) return false;

    std::string baseTok = Trim(parts[0]);
    a64::Gp base;
    if (!ParseGpReg(baseTok, base)) return false;

    if (parts.size() == 1) {
        if (pre) return false;
        if (post) {
            out = a64::ptr_post(base, (int32_t)postOff);
            return true;
        }
        out = a64::ptr(base, 0);
        return true;
    }

    std::string p1 = Trim(parts[1]);
    int64_t off = 0;
    a64::Gp idx;
    if (ParseImm(p1.c_str(), off)) {
        if (pre) out = a64::ptr_pre(base, (int32_t)off);
        else     out = a64::ptr(base, (int32_t)off);
        return true;
    }
    if (!ParseGpReg(p1, idx)) return false;
    if (parts.size() == 2) {
        if (pre) out = a64::ptr_pre(base, idx);
        else     out = a64::ptr(base, idx);
        return true;
    }
    arm::Shift sh;
    if (!ParseShiftOp(parts[2], sh)) return false;
    out = a64::ptr(base, idx, sh);
    return true;
}

// 常用系统寄存器名 → MRS/MSR 编码字段（指令 bits[20:5]，
// = (op0&3)<<14 | op1<<11 | CRn<<7 | CRm<<3 | op2）。
// 字段值已用 llvm-mc 交叉核对。
struct SysRegEntry { const char* name; uint32_t field; };
static const SysRegEntry kSysRegs[] = {
    {"tpidr_el0",   0xDE82}, {"tpidrro_el0", 0xDE83},
    {"cntfrq_el0",  0xDF00}, {"cntpct_el0",  0xDF01},
    {"cntvct_el0",  0xDF02}, {"midr_el1",    0xC000},
    {"mpidr_el1",   0xC005}, {"currentel",   0xC212},
    {"daif",        0xDA11}, {"nzcv",        0xDA10},
    {"fpcr",        0xDA20}, {"fpsr",        0xDA21},
    {"ctr_el0",     0xD801}, {"dczid_el0",   0xD807},
    {"sctlr_el1",   0xC080}, {"esr_el1",     0xC290},
    {"far_el1",     0xC300}, {"vbar_el1",    0xC600},
};

static inline bool LookupSysReg(const std::string& name, uint32_t& field) {
    for (const SysRegEntry& sr : kSysRegs) {
        if (name == sr.name) { field = sr.field; return true; }
    }
    return false;
}

// 解析通用寄存器 token，返回编码用的 5 位寄存器号。
static inline bool ParseGpId(const std::string& tok, uint32_t& id) {
    a64::Gp gp;
    if (!ParseGpReg(tok, gp)) return false;
    id = (uint32_t)gp.id() & 0x1F;
    return true;
}

// AArch64 逻辑立即数编码（tst/ands/bics/mov 别名等）：
// 把值分解为元素尺寸 es、旋转量 immr、1 的个数 s。
// 立即数 = ROR(ones(s), immr) 在 es 内复制；N=1 仅当 es=64。
// 已用 clang 对 #0xff/#0xffff0000/#0x80000000/#0xff00ff00/
// #0x780/#0x5555..55/x0 #0xff 等逐一核对。
static inline bool EncodeLogicalImm(uint64_t v, bool is64,
                                    uint32_t& n, uint32_t& immr,
                                    uint32_t& imms) {
    if (!is64 && (v >> 32)) return false;
    unsigned es = is64 ? 64u : 32u;
    // 收缩元素尺寸：高半与低半相等则可收缩。
    while (es > 2) {
        unsigned half = es / 2;
        uint64_t hm = (1ULL << half) - 1;
        if ((v & hm) != ((v >> half) & hm)) break;
        es = half;
    }
    uint64_t mask = (es == 64) ? ~0ULL : (1ULL << es) - 1;
    uint64_t pat = v & mask;
    if (pat == 0 || pat == mask) return false;  // 全 0 / 全 1 非法
    // 必须是"一段连续的 1"：旋转到最低位后应为 (1<<s)-1。
    unsigned p = 0;                              // 最低置位位
    while (!(pat >> p & 1)) ++p;
    uint64_t rot;
    if (p == 0) {
        rot = pat;
    } else if (es == 64) {
        rot = (pat >> p) | (pat << (64 - p));
    } else {
        rot = ((pat >> p) | (pat << (es - p))) & mask;
    }
    uint32_t s = 0;
    for (uint64_t t = rot; t; t >>= 1) s += (uint32_t)(t & 1);
    if (rot != ((1ULL << s) - 1)) return false;  // 不是单段 1
    n = (es == 64) ? 1u : 0u;
    immr = (es - p) % es;
    if (es == 64) {
        imms = s - 1;
    } else {
        unsigned lg = 0;
        while ((1u << lg) < es) ++lg;
        // es=32 前缀 0,16→0x20,8→0x30,4→0x38,2→0x3C。
        imms = (((1u << (5 - lg)) - 1u) << (lg + 1)) | (s - 1);
    }
    return true;
}

// 特殊操作数系统指令（dc/ic/at/tlbi）：操作名 → 基址。
// base 已含除 Rt 外的全部位段（clang/llvm-objdump 核对）；
// 无 Rt 的变体 Rt 字段恒为 11111，直接给出完整编码。
struct SysOpEntry { const char* name; uint32_t base; bool hasRt; };
static const SysOpEntry kDcOps[] = {
    {"zva",   0xD50B7420u, true},  {"cvac",  0xD50B7A20u, true},
    {"cvap",  0xD50B7C20u, true},  {"cvadp", 0xD50B7D20u, true},
    {"civac", 0xD50B7E20u, true},
};
static const SysOpEntry kIcOps[] = {
    {"iallu", 0xD508751Fu, false}, {"ivau",  0xD50B7520u, true},
};
static const SysOpEntry kAtOps[] = {
    {"s1e0r", 0xD5087840u, true},  {"s1e0w", 0xD5087860u, true},
    {"s1e1r", 0xD5087800u, true},  {"s1e1w", 0xD5087820u, true},
};
static const SysOpEntry kTlbiOps[] = {
    {"vmalle1", 0xD508871Fu, false}, {"alle1",  0xD50C879Fu, false},
    {"alle1is", 0xD50C839Fu, false}, {"vae1",   0xD5088720u, true},
    {"vae1is",  0xD5088320u, true},  {"alle2",  0xD50C871Fu, false},
    {"alle2is", 0xD50C831Fu, false}, {"alle3",  0xD50E871Fu, false},
    {"alle3is", 0xD50E831Fu, false},
};
static const SysOpEntry kRctxOps[] = {  // CFP/DVP/CPP RCTX, Xt
    {"cfp", 0xD50B7380u, true}, {"dvp", 0xD50B73A0u, true},
    {"cpp", 0xD50B73E0u, true},
};
// 屏障变体名 → CRm 字段。
struct BarrierEntry { const char* name; uint32_t crm; };
static const BarrierEntry kBarrierOps[] = {
    {"sy", 15}, {"st", 14}, {"ld", 13},
    {"ish", 11}, {"ishst", 10}, {"ishld", 9},
    {"nsh", 7},  {"nshst", 6},  {"nshld", 5},
    {"osh", 3},  {"oshst", 2},  {"oshld", 1},
};
// 无操作数固定编码指令。
struct FixedInsnEntry { const char* name; uint32_t word; };
static const FixedInsnEntry kFixedInsns[] = {
    {"paciasp", 0xD503233Fu}, {"pacibsp", 0xD503237Fu},
    {"autiasp", 0xD50323BFu}, {"autibsp", 0xD50323FFu},
    {"eret",    0xD69F03E0u}, {"sevl",    0xD50320BFu},
    {"csdb",    0xD503229Fu}, {"yield",   0xD503203Fu},
    {"wfe",     0xD503205Fu}, {"wfi",     0xD503207Fu},
};
static const FixedInsnEntry kBtiOps[] = {  // bti <c|j|jc>
    {"c", 0xD503245Fu}, {"j", 0xD503249Fu}, {"jc", 0xD50324DFu},
};

template <typename T>
static inline bool LookupName(const T* table, size_t n,
                              const std::string& name, uint32_t& base,
                              bool& hasRt) {
    for (size_t i = 0; i < n; ++i) {
        if (name == table[i].name) {
            base = table[i].base;
            hasRt = table[i].hasRt;
            return true;
        }
    }
    return false;
}

// 无符号立即数解析（逻辑立即数可能超过 INT64_MAX，strtoll 会溢出）。
static inline bool ParseImmU(const char* s, uint64_t& out) {
    const char* p = s;
    while (*p && isspace((unsigned char)*p)) p++;
    if (*p == '#') p++;
    if (*p == '+') p++;
    if (!*p) return false;
    int base = 10;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) { base = 16; p += 2; }
    else if (p[0] == '0' && (p[1] == 'b' || p[1] == 'B')) { base = 2; p += 2; }
    if (!*p) return false;
    char* end = nullptr;
    out = strtoull(p, &end, base);
    if (!end || *end) return false;
    return true;
}

// 尝试把 asmjit 指令库没有收录的指令直接编码。
// 覆盖：sdiv/udiv、sxtb/sxth/sxtw/uxtb/uxth/uxtw（SBFM/UBFM 别名）、
// sbfm/ubfm、extr、rev、smulh/umulh、tbz/tbnz、svc、ret（规范编码）。
// 所有基址与字段位置均已用 clang/llvm-objdump 交叉核对。
// 返回值语义同 TryAssembleLiteralLoad。
static inline int TryAssembleSpecial(
        const std::string& mnem, const std::vector<std::string>& toks,
        std::vector<uint8_t>& bytes, std::string& err) {
    // 收集非空 token（与通用路径行为一致）。
    std::vector<std::string> v;
    for (const auto& t : toks) {
        std::string s = Trim(t);
        if (!s.empty()) v.push_back(s);
    }
    uint32_t w;
    bool ok = false;

    if (mnem == "sdiv" || mnem == "udiv") {
        // DIV: base | Rm<<16 | Rn<<5 | Rd。
        uint32_t rd, rn, rm;
        if (v.size() != 3 || !ParseGpId(v[0], rd) ||
            !ParseGpId(v[1], rn) || !ParseGpId(v[2], rm)) return 0;
        bool x = (v[0][0] == 'x');
        w = (x ? 0x9AC00000u : 0x1AC00000u) |
            (mnem == "udiv" ? 0x800u : 0xC00u) |
            (rm << 16) | (rn << 5) | rd;
        ok = true;
    } else if (mnem == "sxtb" || mnem == "sxth" || mnem == "sxtw" ||
               mnem == "uxtb" || mnem == "uxth" || mnem == "uxtw") {
        // SXTW/UXTW 只支持 64 位目标寄存器，其余按目标宽度选基址。
        if (v.size() != 2) return 0;
        uint32_t rd, rn;
        if (!ParseGpId(v[0], rd) || !ParseGpId(v[1], rn)) {
            err = "无法解析寄存器操作数";
            return 2;
        }
        bool x = (v[0][0] == 'x');
        uint32_t base;
        if      (mnem == "sxtb") base = x ? 0x93401C00u : 0x13001C00u;
        else if (mnem == "sxth") base = x ? 0x93403C00u : 0x13003C00u;
        else if (mnem == "sxtw") base = 0x93407C00u;
        else if (mnem == "uxtb") base = x ? 0xD3401C00u : 0x53001C00u;
        else if (mnem == "uxth") base = x ? 0xD3403C00u : 0x53003C00u;
        else                     base = 0xD3407C00u;  // uxtw
        if (!x && (mnem == "sxtw" || mnem == "uxtw")) {
            err = mnem + " 需要 64 位目标寄存器 (x)";
            return 2;
        }
        w = base | (rn << 5) | rd;
        ok = true;
    } else if (mnem == "sbfm" || mnem == "ubfm") {
        // BFM 家族: base | immr<<16 | imms<<10 | Rn<<5 | Rd。
        if (v.size() != 4) return 0;
        uint32_t rd, rn;
        int64_t r, s;
        if (!ParseGpId(v[0], rd) || !ParseGpId(v[1], rn) ||
            !ParseImm(v[2].c_str(), r) || !ParseImm(v[3].c_str(), s)) return 0;
        bool x = (v[0][0] == 'x');
        int64_t maxs = x ? 63 : 31;
        if (r < 0 || s < 0 || r > maxs || s > maxs) {
            err = "位段范围超出限制";
            return 2;
        }
        if (mnem == "ubfm" && s < r) {
            err = "ubfm 要求 imms >= immr";
            return 2;
        }
        uint32_t base;
        if      (mnem == "sbfm") base = x ? 0x93400000u : 0x13000000u;
        else                     base = x ? 0xD3400000u : 0x53000000u;
        w = base | ((uint32_t)r << 16) | ((uint32_t)s << 10) | (rn << 5) | rd;
        ok = true;
    } else if (mnem == "extr") {
        // EXTR: base | Rm<<16 | lsb<<10 | Rn<<5 | Rd。
        if (v.size() != 4) return 0;
        uint32_t rd, rn, rm;
        int64_t lsb;
        if (!ParseGpId(v[0], rd) || !ParseGpId(v[1], rn) ||
            !ParseGpId(v[2], rm) || !ParseImm(v[3].c_str(), lsb)) return 0;
        bool x = (v[0][0] == 'x');
        if (lsb < 0 || lsb > (x ? 63 : 31)) {
            err = "extr 的 LSB 超出范围";
            return 2;
        }
        w = (x ? 0x93C00000u : 0x13800000u) |
            (rm << 16) | ((uint32_t)lsb << 10) | (rn << 5) | rd;
        ok = true;
    } else if (mnem == "rev") {
        if (v.size() != 2) return 0;
        uint32_t rd, rn;
        if (!ParseGpId(v[0], rd) || !ParseGpId(v[1], rn)) {
            err = "无法解析寄存器操作数";
            return 2;
        }
        w = ((v[0][0] == 'x') ? 0xDAC00C00u : 0x5AC00800u) | (rn << 5) | rd;
        ok = true;
    } else if (mnem == "smulh" || mnem == "umulh") {
        // 仅 64 位: base | Rm<<16 | 31<<10 | Rn<<5 | Rd（Ra=xzr）。
        uint32_t rd, rn, rm;
        if (v.size() != 3 || !ParseGpId(v[0], rd) ||
            !ParseGpId(v[1], rn) || !ParseGpId(v[2], rm)) return 0;
        if (v[0][0] != 'x') {
            err = mnem + " 仅支持 64 位寄存器 (x)";
            return 2;
        }
        w = (mnem == "smulh" ? 0x9B400000u : 0x9BC00000u) |
            (rm << 16) | (31u << 10) | (rn << 5) | rd;
        ok = true;
    } else if (mnem == "tbz" || mnem == "tbnz") {
        // bit31=b40<5>, bit24=选择 tbnz, bits[23:19]=b40<4:0>,
        // bits[18:5]=imm14, bits[4:0]=Rt。
        if (v.size() != 3) return 0;
        uint32_t rt;
        int64_t bit, off;
        if (!ParseGpId(v[0], rt) ||
            !ParseImm(v[1].c_str(), bit) || !ParseImm(v[2].c_str(), off)) {
            err = "无法解析 tbz/tbnz 操作数";
            return 2;
        }
        if (bit < 0 || bit > 63) {
            err = "tbz/tbnz 位号超出 0..63";
            return 2;
        }
        if (bit >= 32 && v[0][0] != 'x') {
            err = "测试 32 位以上位号需要 64 位寄存器 (x)";
            return 2;
        }
        if (off % 4 != 0 || off < -0x8000 || off > 0x7FFC) {
            err = "tbz/tbnz 跳转偏移需 4 字节对齐且在 ±32KB 内";
            return 2;
        }
        w = 0x36000000u | ((bit >= 32) ? 0x80000000u : 0) |
            (mnem == "tbnz" ? 0x01000000u : 0) |
            (((uint32_t)bit & 0x1F) << 19) |
            (((uint32_t)(off >> 2) & 0x3FFF) << 5) | rt;
        ok = true;
    } else if (mnem == "svc") {
        int64_t imm;
        if (v.size() != 1 || !ParseImm(v[0].c_str(), imm)) return 0;
        if (imm < 0 || imm > 0xFFFF) {
            err = "svc 立即数超出 0..0xFFFF";
            return 2;
        }
        w = 0xD4000000u | ((uint32_t)imm << 5) | 1u;
        ok = true;
    } else if (mnem == "ret") {
        // 用规范的 RET 编码（0xD65F0000），而不是 BR x30 别名。
        if (v.empty()) {
            w = 0xD65F03C0u;  // ret = ret x30
            ok = true;
        } else if (v.size() == 1 && v[0][0] == 'x') {
            uint32_t rn;
            if (!ParseGpId(v[0], rn)) {
                err = "无法解析寄存器: " + v[0];
                return 2;
            }
            w = 0xD65F0000u | (rn << 5);
            ok = true;
        } else {
            err = "ret 最多接受一个 x 寄存器";
            return 2;
        }
    } else if (mnem == "tst") {
        // TST = ANDS 且 Rd=xzr：寄存器/寄存器+移位/逻辑立即数。
        if (v.size() < 2 || v.size() > 3) return 0;
        uint32_t rn;
        if (!ParseGpId(v[0], rn)) return 0;  // 首操作数必须是寄存器
        bool x = (v[0][0] == 'x');
        uint64_t immu;
        bool asImm = (v.size() == 2) && ParseImmU(v[1].c_str(), immu);
        if (!asImm && v.size() == 2) {
            int64_t neg;
            if (ParseImm(v[1].c_str(), neg)) {
                err = "非法逻辑立即数: " + v[1];
                return 2;
            }
        }
        if (asImm) {
            uint32_t n, immr, imms;
            if (!EncodeLogicalImm(immu, x, n, immr, imms)) {
                err = "非法逻辑立即数: " + v[1];
                return 2;
            }
            w = (x ? 0xF2000000u : 0x72000000u) | (n << 22) |
                (immr << 16) | (imms << 10) | (rn << 5) | 31u;
        } else {
            uint32_t rm;
            if (!ParseGpId(v[1], rm)) {
                err = "无法解析 tst 操作数: " + v[1];
                return 2;
            }
            uint32_t so = 0, amount = 0;
            if (v.size() == 3) {
                std::string sop = v[2], sarg;
                size_t sp2 = sop.find_first_of(" \t");
                if (sp2 != std::string::npos) {
                    sarg = Trim(sop.substr(sp2 + 1));
                    sop = Trim(sop.substr(0, sp2));
                }
                if      (sop == "lsl") so = 0;
                else if (sop == "lsr") so = 1;
                else if (sop == "asr") so = 2;
                else if (sop == "ror") so = 3;
                else {
                    err = "tst 不支持移位类型: " + sop;
                    return 2;
                }
                int64_t amt = 0;
                if (!ParseImm(sarg.c_str(), amt) || amt < 0 ||
                    amt >= (x ? 64 : 32)) {
                    err = "无法解析移位量: " + sarg;
                    return 2;
                }
                amount = (uint32_t)amt;
            }
            w = (x ? 0xEA000000u : 0x6A000000u) | (so << 22) |
                (rm << 16) | (amount << 10) | (rn << 5) | 31u;
        }
        ok = true;
    } else if (mnem == "ror" || mnem == "rorv") {
        // ror Rd, Rn, #lsb = EXTR Rd, Rn, Rn, #lsb；ror Rd, Rn, Rm = RORV。
        if (v.size() < 2 || v.size() > 3) return 0;
        uint32_t rd, rn;
        if (!ParseGpId(v[0], rd) || !ParseGpId(v[1], rn)) return 0;
        bool x = (v[0][0] == 'x');
        if (v.size() == 2) return 0;  // 缺少旋转量，交给通用路径报错
        int64_t lsb;
        if (ParseImm(v[2].c_str(), lsb)) {
            if (lsb < 0 || lsb >= (x ? 64 : 32)) {
                err = "ror 旋转量超出范围";
                return 2;
            }
            w = (x ? 0x93C00000u : 0x13800000u) | (rn << 16) |
                ((uint32_t)lsb << 10) | (rn << 5) | rd;
        } else {
            uint32_t rm;
            if (!ParseGpId(v[2], rm)) {
                err = "无法解析旋转量或寄存器: " + v[2];
                return 2;
            }
            w = (x ? 0x9AC02C00u : 0x1AC02C00u) | (rm << 16) |
                (rn << 5) | rd;
        }
        ok = true;
    } else if (mnem == "sbc" || mnem == "sbcs") {
        uint32_t rd, rn, rm;
        if (v.size() != 3 || !ParseGpId(v[0], rd) ||
            !ParseGpId(v[1], rn) || !ParseGpId(v[2], rm)) return 0;
        bool x = (v[0][0] == 'x');
        w = (x ? 0xDA000000u : 0x5A000000u) |
            (mnem == "sbcs" ? 0x20000000u : 0) |
            (rm << 16) | (rn << 5) | rd;
        ok = true;
    } else if (mnem == "smaddl" || mnem == "umaddl" ||
               mnem == "smsubl" || mnem == "umsubl") {
        // XDd, Wn, Wm, Xa：base | Rm<<16 | Ra<<10 | Rn<<5 | Rd。
        uint32_t rd, rn, rm, ra;
        if (v.size() != 4 || !ParseGpId(v[0], rd) ||
            !ParseGpId(v[1], rn) || !ParseGpId(v[2], rm) ||
            !ParseGpId(v[3], ra)) return 0;
        if (v[0][0] != 'x' || v[3][0] != 'x') {
            err = mnem + " 的目标与累加寄存器必须为 64 位 (x)";
            return 2;
        }
        uint32_t base = (mnem == "smaddl") ? 0x9B200000u :
                        (mnem == "umaddl") ? 0x9BA00000u :
                        (mnem == "smsubl") ? 0x9B208000u : 0x9BA08000u;
        w = base | (rm << 16) | (ra << 10) | (rn << 5) | rd;
        ok = true;
    } else if (mnem == "dmb" || mnem == "dsb" || mnem == "isb") {
        // 屏障指令：dmb/dsb <变体>，isb 固定 sy。
        uint32_t crm = 15;
        if (mnem != "isb") {
            if (v.size() != 1) return 0;
            bool found = false;
            for (const BarrierEntry& b : kBarrierOps) {
                if (v[0] == b.name) { crm = b.crm; found = true; break; }
            }
            if (!found) {
                err = "未知屏障变体: " + v[0];
                return 2;
            }
        } else if (!v.empty()) {
            return 0;
        }
        uint32_t base = (mnem == "dmb") ? 0xD50330A0u :
                        (mnem == "dsb") ? 0xD5033080u : 0xD50330C0u;
        w = base | (crm << 8) | 0x1Fu;
        ok = true;
    } else if (mnem == "dc" || mnem == "ic" || mnem == "at" ||
               mnem == "tlbi") {
        // 特殊操作数系统指令：<助记符> <操作名>[, <x寄存器>]。
        if (v.empty()) return 0;
        const SysOpEntry* table = nullptr;
        size_t tn = 0;
        if      (mnem == "dc")   { table = kDcOps;   tn = sizeof(kDcOps)   / sizeof(kDcOps[0]); }
        else if (mnem == "ic")   { table = kIcOps;   tn = sizeof(kIcOps)   / sizeof(kIcOps[0]); }
        else if (mnem == "at")   { table = kAtOps;   tn = sizeof(kAtOps)   / sizeof(kAtOps[0]); }
        else                     { table = kTlbiOps; tn = sizeof(kTlbiOps) / sizeof(kTlbiOps[0]); }
        uint32_t base;
        bool hasRt;
        if (!LookupName(table, tn, v[0], base, hasRt)) return 0;
        if (hasRt) {
            uint32_t rt;
            if (v.size() != 2 || !ParseGpId(v[1], rt)) return 0;
            w = base | rt;
        } else {
            if (v.size() != 1) return 0;
            w = base;
        }
        ok = true;
    } else if (mnem == "cfp" || mnem == "dvp" || mnem == "cpp") {
        // CFP/DVP/CPP RCTX, Xt（FEAT_SPECRES）。
        uint32_t base, rt;
        bool hasRt;
        if (!LookupName(kRctxOps, sizeof(kRctxOps) / sizeof(kRctxOps[0]),
                        mnem, base, hasRt)) return 0;
        if (v.size() != 2 || Trim(v[0]) != "rctx" ||
            !ParseGpId(v[1], rt)) {
            err = mnem + " 的写法为 " + mnem + " rctx, <x寄存器>";
            return 2;
        }
        w = base | rt;
        ok = true;
    } else if (mnem == "bti") {
        bool found = false;
        if (v.size() == 1) {
            for (const FixedInsnEntry& f : kBtiOps) {
                if (v[0] == f.name) {
                    w = f.word;
                    ok = true;
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            err = "bti 的写法为 bti <c|j|jc>";
            return 2;
        }
    } else if (mnem == "pacia" || mnem == "pacib") {
        // PACIXA Xd, Xn：base | 修饰符<<5 | Rd。
        uint32_t rd, mod;
        if (v.size() != 2 || !ParseGpId(v[0], rd) ||
            !ParseGpId(v[1], mod)) return 0;
        w = (mnem == "pacia" ? 0xDAC10000u : 0xDAC10400u) |
            (mod << 5) | rd;
        ok = true;
    } else if (mnem == "xpaci") {
        uint32_t rd;
        if (v.size() != 1 || !ParseGpId(v[0], rd)) return 0;
        w = 0xDAC143E0u | rd;
        ok = true;
    } else if (v.empty()) {
        // 无操作数固定编码（paciasp/eret/wfi 等）。
        bool found = false;
        for (const FixedInsnEntry& f : kFixedInsns) {
            if (mnem == f.name) { w = f.word; ok = true; found = true; break; }
        }
        if (!found) return 0;
    }

    if (!ok) return 0;
    bytes.clear();
    bytes.push_back((uint8_t)(w & 0xFF));
    bytes.push_back((uint8_t)((w >> 8) & 0xFF));
    bytes.push_back((uint8_t)((w >> 16) & 0xFF));
    bytes.push_back((uint8_t)((w >> 24) & 0xFF));
    return 1;
}

// 尝试把 ldr/ldrsw 的字面量加载形式（ldr x0, [pc, #0xc]）直接编码。
// AsmJit 不支持以 PC 为基址的内存操作数，而字面量加载的偏移是
// 显式给出的，按 ARM 手册编码即可：imm19（<<2，±1MB，4 字节对齐）。
// 返回 0 = 不是字面量加载写法（交回通用路径处理）；
//       1 = 已编码成功（bytes 已填充）；
//       2 = 是字面量加载但参数非法（err 已设置）。
static inline int TryAssembleLiteralLoad(
        const std::string& mnem, const std::vector<std::string>& toks,
        std::vector<uint8_t>& bytes, std::string& err) {
    if (mnem != "ldr" && mnem != "ldrsw") return 0;

    // 过滤空 token（与通用路径行为一致）。
    std::vector<std::string> v;
    for (const auto& t : toks) {
        std::string s = Trim(t);
        if (!s.empty()) v.push_back(s);
    }
    if (v.size() != 2) return 0;

    std::string regTok = v[0];
    std::string memTok = v[1];
    if (memTok.empty()) return 0;

    bool bracket = (memTok[0] == '[');
    if (bracket) {
        if (memTok.back() != ']') return 0;  // ]! / ],#imm 等写法不合法，交给通用路径报错
        memTok = Trim(memTok.substr(1, memTok.size() - 2));
    }

    int64_t off = 0;
    if (bracket) {
        std::vector<std::string> parts;
        SplitTop(memTok, ',', parts);
        if (parts.empty() || Trim(parts[0]) != "pc" || parts.size() > 2)
            return 0;  // 基址不是 pc，交给通用路径（ParseMem 会给出报错）
        if (parts.size() == 2) {
            std::string offTok = Trim(parts[1]);
            if (!ParseImm(offTok.c_str(), off)) {
                err = "无法解析字面量偏移: " + offTok;
                return 2;
            }
        }
    } else {
        // 无方括号的 #imm / imm 也按 PC 相对偏移接受。
        if (!ParseImm(memTok.c_str(), off)) return 0;
    }

    // 目标寄存器 → 编码基址与 Rt。
    uint32_t base;
    uint32_t rt;
    a64::Gp gp;
    a64::Vec vec;
    if (ParseGpReg(regTok, gp)) {
        if (regTok == "sp" || regTok == "wsp") {
            err = "字面量加载不能以 sp 为目标寄存器";
            return 2;
        }
        rt = (uint32_t)gp.id() & 0x1F;  // asmjit 中 xzr 的 id 是 63,编码只取低 5 位
        if (mnem == "ldrsw") {
            if (regTok[0] != 'x') {
                err = "ldrsw 需要 64 位目标寄存器 (x)";
                return 2;
            }
            base = 0x98000000u;
        } else {
            base = (regTok[0] == 'x') ? 0x58000000u : 0x18000000u;
        }
    } else if (mnem == "ldr" && ParseVecReg(regTok, vec)) {
        // SIMD/FP 字面量加载仅支持 s/d/q（b/h 无此形式）。
        char k = regTok[0];
        if (k == 's')      base = 0x1C000000u;
        else if (k == 'd') base = 0x5C000000u;
        else if (k == 'q') base = 0x9C000000u;
        else { err = "字面量加载仅支持 w/x/s/d/q 寄存器"; return 2; }
        rt = (uint32_t)vec.id();
    } else {
        err = "无法解析目标寄存器: " + regTok;
        return 2;
    }

    if (off % 4 != 0) {
        err = "字面量偏移必须是 4 的倍数";
        return 2;
    }
    if (off < -(1 << 20) || off > ((1 << 20) - 4)) {
        err = "字面量偏移超出 ±1MB 范围";
        return 2;
    }
    uint32_t imm19 = (uint32_t)((off >> 2) & 0x7FFFF);
    uint32_t w = base | (imm19 << 5) | rt;
    bytes.clear();
    bytes.push_back((uint8_t)(w & 0xFF));
    bytes.push_back((uint8_t)((w >> 8) & 0xFF));
    bytes.push_back((uint8_t)((w >> 16) & 0xFF));
    bytes.push_back((uint8_t)((w >> 24) & 0xFF));
    return 1;
}

static inline bool ParseOperand(const std::string& tok, Operand_& out,
                                std::string& err) {
    if (tok.empty()) { err = "空操作数"; return false; }
    if (tok[0] == '[') {
        a64::Mem m;
        if (!ParseMem(tok, m)) {
            err = "无法解析内存操作数: " + tok;
            return false;
        }
        out = m;
        return true;
    }
    a64::Gp gp;
    if (ParseGpReg(tok, gp)) { out = gp; return true; }
    a64::Vec vec;
    if (ParseVecReg(tok, vec)) { out = vec; return true; }
    arm::Shift sh;
    if (ParseShiftOp(tok, sh)) { out = Imm(sh); return true; }
    int64_t imm = 0;
    if (ParseImm(tok.c_str(), imm)) { out = Imm(imm); return true; }
    err = "无法解析操作数: " + tok;
    return false;
}

// 把单条 AArch64 指令从文本汇编到 `bytes`。
static inline bool Assemble(const char* text, std::vector<uint8_t>& bytes,
                            std::string& err) {
    bytes.clear();
    if (!text) { err = "空指令"; return false; }
    std::string s = Trim(text);
    if (s.empty()) { err = "空指令"; return false; }
    for (auto& c : s) c = (char)tolower((unsigned char)c);

    size_t sp = s.find_first_of(" \t");
    std::string mnem = (sp == std::string::npos) ? s : s.substr(0, sp);
    std::string opsStr =
        (sp == std::string::npos) ? "" : Trim(s.substr(sp + 1));

    // 助记符可能带条件码后缀：b.ne / csel.eq 等。
    uint32_t condVal = 0;   // asmjit CondCode 数值（kAL=0, kEQ=2, ...）
    bool hasCond = false;
    size_t dot = mnem.find('.');
    if (dot != std::string::npos) {
        std::string ccStr = mnem.substr(dot + 1);
        if (!ParseCondCode(ccStr, condVal)) {
            err = "无法解析条件码: " + ccStr;
            return false;
        }
        mnem = mnem.substr(0, dot);
        hasCond = true;
    }

    std::vector<std::string> toks;
    SplitTop(opsStr, ',', toks);

    // cset 家族的条件码是最后一个操作数（cset w0, ne / csel w0,w1,w2,gt），
    // asmjit 中它们以 Imm 操作数形式传给编码器。
    static const char* kCondOpMnems[] = {
        "cset", "csetm", "csel", "csinc", "csinv", "csneg",
        "cinc", "cinv", "cneg", "ccmn", "ccmp"
    };
    bool condOpMnem = false;
    for (const char* m : kCondOpMnems) {
        if (mnem == m) { condOpMnem = true; break; }
    }
    if (condOpMnem && !hasCond && !toks.empty()) {
        uint32_t cc = 0;
        if (ParseCondCode(Trim(toks.back()), cc)) {
            condVal = cc;
            hasCond = true;
            toks.pop_back();
        }
    }

    // ldr/ldrsw 字面量加载（ldr x0, [pc, #0xc]）：asmjit 不支持
    // PC 基址；以及 asmjit 指令库未收录的指令（udiv/sdiv/tbz 等）。
    // 两者都走手工编码。
    {
        int lit = TryAssembleLiteralLoad(mnem, toks, bytes, err);
        if (lit == 1) return true;
        if (lit == 2) return false;
        int sp = TryAssembleSpecial(mnem, toks, bytes, err);
        if (sp == 1) return true;
        if (sp == 2) return false;
    }

    // 后索引写法（[x0], #imm / [x0], x1）的逗号在方括号外，
    // SplitTop 会把它切成独立 token，这里合并回内存操作数。
    for (size_t i = 0; i + 1 < toks.size(); ++i) {
        std::string t = Trim(toks[i]);
        if (t.size() >= 2 && t[0] == '[' && t.back() == ']') {
            std::string nxt = Trim(toks[i + 1]);
            int64_t dummy;
            a64::Gp dummyGp;
            if (!nxt.empty() &&
                (ParseImm(nxt.c_str(), dummy) || ParseGpReg(nxt, dummyGp))) {
                toks[i] = t + ", " + nxt;
                toks.erase(toks.begin() + i + 1);
            }
        }
    }

    // mrs/msr 的系统寄存器名换成 asmjit MRS/MSR 期望的 Imm 字段值
    // （探针验证：mrs x0, Imm(0xDE82) → D53BD040 = tpidr_el0）。
    if (mnem == "mrs" || mnem == "msr") {
        size_t want = (mnem == "msr") ? 0 : 1;  // msr 的系统寄存器在前
        size_t n = 0;
        for (size_t i = 0; i < toks.size(); ++i) {
            std::string t = Trim(toks[i]);
            if (t.empty()) continue;
            if (n == want) {
                int64_t dummy;
                if (!ParseImm(t.c_str(), dummy)) {
                    uint32_t field;
                    if (!LookupSysReg(t, field)) {
                        err = "未知系统寄存器: " + t;
                        return false;
                    }
                    static const char kHexD[] = "0123456789ABCDEF";
                    std::string hex = "0x";
                    for (int sh = 12; sh >= 0; sh -= 4)
                        hex += kHexD[(field >> sh) & 0xF];
                    toks[i] = hex;
                }
                break;
            }
            ++n;
        }
    }

    Operand_ ops[4];
    size_t opCount = 0;
    for (const auto& t : toks) {
        std::string tok = Trim(t);
        if (tok.empty()) continue;
        if (opCount >= 4) { err = "操作数过多"; return false; }
        if (!ParseOperand(tok, ops[opCount], err)) return false;
        opCount++;
    }
    // cset 家族：把条件码作为最后一个 Imm 操作数追加
    if (condOpMnem && hasCond) {
        if (opCount >= 4) { err = "操作数过多"; return false; }
        ops[opCount++] = Imm((int64_t)condVal);
    }

    InstId id = asmjit::InstAPI::string_to_inst_id(
        Arch::kAArch64, mnem.c_str(), mnem.size());
    if (id == asmjit::BaseInst::kIdNone) {
        err = "未知指令: " + mnem;
        return false;
    }
    // 分支等以 inst_id 携带条件码的指令（b.ne 等）
    if (hasCond && !condOpMnem)
        id = asmjit::BaseInst::compose_arm_inst_id(id, (arm::CondCode)condVal);

    Environment env(Arch::kAArch64);
    CodeHolder code;
    if (code.init(env, 0) != Error::kOk) {
        err = "asmjit 初始化失败";
        return false;
    }
    a64::Assembler a(&code);
    Error e = a._emit_op_array(id, ops, opCount);
    if (e != Error::kOk) {
        // string_to_inst_id() 可能返回汇编器无法直接编码的别名 id；
        // 扫描所有拼写相同的助记符 id，
        // 尝试第一个能编码成功的。
        bytes.clear();
        for (InstId alt = 1; alt < a64::Inst::_kIdCount; alt++) {
            asmjit::String name;
            if (asmjit::InstAPI::inst_id_to_string(
                    Arch::kAArch64, alt,
                    asmjit::InstStringifyOptions::kNone, name) != Error::kOk)
                continue;
            if (name.size() != mnem.size() ||
                memcmp(name.data(), mnem.c_str(), mnem.size()) != 0)
                continue;
            CodeHolder altCode;
            if (altCode.init(env, 0) != Error::kOk) continue;
            a64::Assembler altA(&altCode);
            e = altA._emit_op_array(alt, ops, opCount);
            if (e != Error::kOk) continue;
            const CodeBuffer& abuf = altCode.text_section()->buffer();
            bytes.assign(abuf.data(), abuf.data() + abuf.size());
            break;
        }
        if (bytes.empty()) {
            err = std::string("汇编失败: ") +
                  asmjit::DebugUtils::error_as_string(e);
            return false;
        }
        return true;
    }
    const CodeBuffer& buf = code.text_section()->buffer();
    bytes.assign(buf.data(), buf.data() + buf.size());
    if (bytes.empty()) { err = "未生成任何字节"; return false; }
    return true;
}

} // 命名空间 udt_asm

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

    // RET 是 BR 的别名（默认 x30），指令库中没有单独收录。
    if (mnem == "ret") {
        if (opCount <= 1) {
            if (opCount == 0)
                ops[opCount++] = a64::Gp::make_x(a64::Gp::kIdLr);
            id = asmjit::InstAPI::string_to_inst_id(
                Arch::kAArch64, "br", 2);
        } else {
            err = "无法解析指令: " + mnem;
            return false;
        }
    }
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

#pragma once

// imgui 侧使用的 Capstone 反汇编封装。解码在应用进程内完成
// （绝不经过 agent socket），因此繁忙的 Lua 脚本 / hook
// 不会拖慢反汇编器，反之亦然。

#include <capstone/capstone.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace udt_disasm {

enum class Arch {
    Arm64 = 0,
    Arm = 1,
};

struct Insn {
    uint64_t    addr = 0;
    uint8_t     bytes[8] = {0};
    size_t      size = 0;
    std::string mnemonic;
    std::string op_str;
};

inline std::string BytesToHex(const uint8_t* data, size_t n) {
    static const char* kHex = "0123456789ABCDEF";
    std::string s;
    s.reserve(n * 3);
    for (size_t i = 0; i < n; ++i) {
        if (i) s.push_back(' ');
        s.push_back(kHex[data[i] >> 4]);
        s.push_back(kHex[data[i] & 0xF]);
    }
    return s;
}

// 从 base 开始解码 code[0..size) 中最多 maxInsns 条指令。
// 至少成功解码一条指令时返回 true。
inline bool Disassemble(Arch arch, const uint8_t* code, size_t size,
                        uint64_t base, size_t maxInsns,
                        std::vector<Insn>& out) {
    out.clear();
    if (!code || size == 0 || maxInsns == 0) return false;

    csh handle = 0;
    cs_arch a = CS_ARCH_AARCH64;
    cs_mode m = CS_MODE_LITTLE_ENDIAN;
    if (arch == Arch::Arm) {
        a = CS_ARCH_ARM;
        m = CS_MODE_ARM;
    }
    if (cs_open(a, m, &handle) != CS_ERR_OK) return false;

    cs_insn* insn = cs_malloc(handle);
    if (!insn) {
        cs_close(&handle);
        return false;
    }

    const uint8_t* p = code;
    size_t remaining = size;
    uint64_t addr = base;
    bool ok = false;
    while (out.size() < maxInsns &&
           cs_disasm_iter(handle, &p, &remaining, &addr, insn)) {
        Insn it;
        it.addr = insn->address;
        it.size = insn->size;
        if (it.size > sizeof(it.bytes)) it.size = sizeof(it.bytes);
        if (it.size) memcpy(it.bytes, insn->bytes, it.size);
        it.mnemonic = insn->mnemonic;
        it.op_str = insn->op_str;
        out.push_back(std::move(it));
        ok = true;
    }

    cs_free(insn, 1);
    cs_close(&handle);
    return ok;
}

} // 命名空间 udt_disasm

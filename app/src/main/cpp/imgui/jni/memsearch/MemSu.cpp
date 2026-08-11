#include "MemSu.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// 定义于 native-lib.cpp（JNI 桥），通过 su 执行 shell 命令并返回输出。
extern std::string RunSuCommand(const std::string& cmd);

// 页对齐批量读取：su + dd（bs=4096）+ xxd -p，要求读满全部字节。
// 只要有一页读不到（目标地址不可读）就返回 false，由调用方跳过。
static bool SuReadPages(int pid, uintptr_t pageAddr, size_t bytes, void* out) {
    if (bytes == 0 || (pageAddr & 4095) != 0 || (bytes & 4095) != 0)
        return false;
    size_t pages = bytes / 4096;
    char cmd[320];
    snprintf(cmd, sizeof(cmd),
             "dd if=/proc/%d/mem bs=4096 skip=%llu count=%zu 2>/dev/null | xxd -p",
             pid, (unsigned long long)(pageAddr / 4096), pages);
    std::string hex = RunSuCommand(cmd);

    unsigned char* dst = static_cast<unsigned char*>(out);
    size_t got = 0;
    int hi = -1;
    for (size_t i = 0; i < hex.size() && got < bytes; ++i) {
        char c = hex[i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else continue;
        if (hi < 0) hi = d;
        else {
            dst[got++] = (unsigned char)((hi << 4) | d);
            hi = -1;
        }
    }
    return got == bytes;
}

bool MemSu::read(uintptr_t address, void* buffer, size_t size) {
    if (size == 0) return true;
    uintptr_t page = address & ~(uintptr_t)4095;
    size_t off = (size_t)(address - page);
    size_t bytes = (off + size + 4095) & ~(size_t)4095;
    std::vector<uint8_t> tmp(bytes);
    if (!SuReadPages(pid, page, bytes, tmp.data())) return false;
    memcpy(buffer, tmp.data() + off, size);
    return true;
}

bool MemSu::write(uintptr_t address, const void* buffer, size_t size) {
    if (size == 0) return true;
    // 写入体积限制，避免构造过长的 shell 命令
    if (size > 65536) return false;

    std::string hex;
    const unsigned char* p = static_cast<const unsigned char*>(buffer);
    for (size_t i = 0; i < size; ++i) {
        char b[8];
        snprintf(b, sizeof(b), "\\x%02x", p[i]);
        hex += b;
    }
    char cmd[140000];
    snprintf(cmd, sizeof(cmd),
             "printf \"%s\" | dd of=/proc/%d/mem bs=1 seek=%llu conv=notrunc 2>&1",
             hex.c_str(), pid, (unsigned long long)address);
    std::string out = RunSuCommand(cmd);
    return out.find("records in") != std::string::npos;
}

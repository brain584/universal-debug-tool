//
// Created by brain584 on 2026/2/14.
//

#ifndef IMGUIDEMO_MEMMODIFY_TOOL_H
#define IMGUIDEMO_MEMMODIFY_TOOL_H
#include <sys/mman.h>
#include <unistd.h>
#include <cstdio>
#include <stdlib.h>
#include <cstring>      // memcpy, strncpy
#include <cstdint>      // uint32_t, uintptr_t
#include <string>       // std::string
#include <vector>       // std::vector

static inline uintptr_t get_module_base(const char* module_name) {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        return 0;
    }

    char line[512];
    uintptr_t base = 0;
    bool found = false;

    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, module_name) && strstr(line, "r-xp")) {
            char* end;
            base = strtoul(line, &end, 16);
            found = true;
            break;
        }
    }
    fclose(maps);

    if (!found) {
        return 0;
    }

    return base;
}

// 修改内存页保护
static int set_memory_protection(void* addr, size_t size, int protection) {
    long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = (uintptr_t)addr & ~(page_size - 1);
    uintptr_t page_end = ((uintptr_t)addr + size + page_size - 1) & ~(page_size - 1);
    size_t total_size = page_end - page_start;

    return mprotect((void*)page_start, total_size, protection);
}

// 获取地址当前的保护属性（通过解析 /proc/self/maps）
static int get_memory_protection(void* addr) {
    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return PROT_READ | PROT_EXEC; // fallback 假设为代码段

    char line[512];
    uintptr_t target = (uintptr_t)addr;
    int prot = 0;

    while (fgets(line, sizeof(line), maps)) {
        uintptr_t start, end;
        char perms[5] = {0};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (target >= start && target < end) {
                if (perms[0] == 'r') prot |= PROT_READ;
                if (perms[1] == 'w') prot |= PROT_WRITE;
                if (perms[2] == 'x') prot |= PROT_EXEC;
                break;
            }
        }
    }
    fclose(maps);

    // 没找到时默认可读写执行
    if (prot == 0) prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    return prot;
}

// 通用内存写入函数（写入后恢复原始保护）
int write_memory(uintptr_t base_address, uint32_t offset, const void* data, size_t size) {
    if (base_address == 0 || data == NULL || size == 0) {
        return 0;
    }

    void* target_addr = (void*)(base_address + offset);

    // 保存原始保护
    int orig_prot = get_memory_protection(target_addr);
    // 加上写权限（不破坏原有的读和执行）
    int new_prot = orig_prot | PROT_WRITE;
    if (set_memory_protection(target_addr, size, new_prot) != 0) {
        return 0;
    }

    // 写入数据
    memcpy(target_addr, data, size);

    // 清除指令缓存（ARM架构需要）
#if defined(__arm__) || defined(__aarch64__)
    __builtin___clear_cache((char*)target_addr, (char*)target_addr + size);
#endif

    // 恢复原始保护
    set_memory_protection(target_addr, size, orig_prot);
    return 1;
}

// 以下是对不同数据类型的专门函数

int write_int(uintptr_t base_address, uint32_t offset, int value) {
    return write_memory(base_address, offset, &value, sizeof(int));
}

int write_int32(uintptr_t base_address, uint32_t offset, int32_t value) {
    return write_memory(base_address, offset, &value, sizeof(int32_t));
}

int write_uint32(uintptr_t base_address, uint32_t offset, uint32_t value) {
    return write_memory(base_address, offset, &value, sizeof(uint32_t));
}

int write_int64(uintptr_t base_address, uint32_t offset, int64_t value) {
    return write_memory(base_address, offset, &value, sizeof(int64_t));
}

int write_uint64(uintptr_t base_address, uint32_t offset, uint64_t value) {
    return write_memory(base_address, offset, &value, sizeof(uint64_t));
}

int write_float(uintptr_t base_address, uint32_t offset, float value) {
    return write_memory(base_address, offset, &value, sizeof(float));
}

int write_double(uintptr_t base_address, uint32_t offset, double value) {
    return write_memory(base_address, offset, &value, sizeof(double));
}

int write_bool(uintptr_t base_address, uint32_t offset, int value) {
    uint8_t bool_value = value ? 1 : 0;
    return write_memory(base_address, offset, &bool_value, sizeof(uint8_t));
}

int write_bytes(uintptr_t base_address, uint32_t offset, const uint8_t* bytes, size_t length) {
    return write_memory(base_address, offset, bytes, length);
}

// 字符串写入（固定长度）
int write_string(uintptr_t base_address, uint32_t offset, const char* str, size_t max_length) {
    if (str == NULL) {
        return 0;
    }

    std::vector<char> buffer(max_length, 0);
    strncpy(buffer.data(), str, max_length - 1);
    buffer[max_length - 1] = '\0'; // 确保结尾

    return write_memory(base_address, offset, buffer.data(), max_length);
}

// 读取 DWORD（32 位无符号整数）
uint32_t read_Dword_mem(uintptr_t address) {
    uint32_t value = 0;
    memcpy(&value, reinterpret_cast<const void*>(address), sizeof(value));
    return value;
}

// 自定义 UTF-16 -> UTF-8 转换（替代弃用的 codecvt）
static inline std::string utf16_to_utf8(const char16_t* utf16, size_t length) {
    std::string utf8;
    for (size_t i = 0; i < length; ++i) {
        char16_t wc = utf16[i];
        if (wc < 0x80) {
            utf8.push_back(static_cast<char>(wc));
        } else if (wc < 0x800) {
            utf8.push_back(static_cast<char>(0xC0 | (wc >> 6)));
            utf8.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
        } else if (wc >= 0xD800 && wc <= 0xDBFF) { // 处理代理对
            if (i + 1 < length) {
                char16_t low = utf16[i + 1];
                if (low >= 0xDC00 && low <= 0xDFFF) {
                    uint32_t codepoint = 0x10000 + ((wc - 0xD800) << 10) + (low - 0xDC00);
                    utf8.push_back(static_cast<char>(0xF0 | (codepoint >> 18)));
                    utf8.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F)));
                    utf8.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F)));
                    utf8.push_back(static_cast<char>(0x80 | (codepoint & 0x3F)));
                    ++i;
                    continue;
                }
            }
            // 无效代理对，插入替换字符 U+FFFD
            utf8.push_back(0xEF);
            utf8.push_back(0xBF);
            utf8.push_back(0xBD);
        } else {
            utf8.push_back(static_cast<char>(0xE0 | (wc >> 12)));
            utf8.push_back(static_cast<char>(0x80 | ((wc >> 6) & 0x3F)));
            utf8.push_back(static_cast<char>(0x80 | (wc & 0x3F)));
        }
    }
    return utf8;
}

// 读取 UTF-16 字符串（length 为字节数），返回 UTF-8 字符串
std::string read_utf16_mem(uintptr_t address, int length_bytes) {
    if (length_bytes <= 0 || length_bytes % 2 != 0) {
        return "";
    }
    size_t char_count = length_bytes / 2;
    std::vector<char16_t> buffer(char_count);
    memcpy(buffer.data(), reinterpret_cast<const void*>(address), length_bytes);

    return utf16_to_utf8(buffer.data(), char_count);
}

uintptr_t read_pointer(uintptr_t address) {
    if (address == 0) return 0;
    uintptr_t ptr = 0;
    memcpy(&ptr, reinterpret_cast<const void*>(address), sizeof(ptr));
    return ptr;
}

#endif //IMGUIDEMO_MEMMODIFY_TOOL_H
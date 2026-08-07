#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <cstdio>
#include <unistd.h>
#include <sys/types.h>
#include <elf.h>

// ARM64 专用定义
using Elf_Ehdr = Elf64_Ehdr;
using Elf_Phdr = Elf64_Phdr;
using Elf_Shdr = Elf64_Shdr;
using Elf_Sym  = Elf64_Sym;
using Elf_Dyn  = Elf64_Dyn;
using Elf_Addr = Elf64_Addr;

// ARM64 系统调用号
namespace Syscall {
    constexpr long MMAP        = 222;
    constexpr long MUNMAP      = 215;
    constexpr long MPROTECT    = 226;
    constexpr long MEMFD_CREATE = 279;
    constexpr long FCNTL       = 25;
    constexpr long PRCTL       = 167;
}

// 内存映射信息
struct MapEntry {
    uintptr_t start;
    uintptr_t end;
    int prot;
    size_t offset;
    std::string path;
    
    size_t size() const { return end - start; }
    bool isReadable() const { return prot & 0x1; }
    bool isWritable() const { return prot & 0x2; }
    bool isExecutable() const { return prot & 0x4; }
};

// 注入结果
struct InjectionResult {
    bool success = false;
    uintptr_t handle = 0;
    uintptr_t base = 0;
    std::string error;
    
    operator bool() const { return success; }
};

// 日志宏
#include <android/log.h>
#define LOG_TAG "NewInjector"
#define LOGI(...) do { fprintf(stdout, "[I/" LOG_TAG "] " __VA_ARGS__); fputc('\n', stdout); fflush(stdout); __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__); } while (0)
#define LOGE(...) do { fprintf(stdout, "[E/" LOG_TAG "] " __VA_ARGS__); fputc('\n', stdout); fflush(stdout); __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); } while (0)
#define LOGW(...) do { fprintf(stdout, "[W/" LOG_TAG "] " __VA_ARGS__); fputc('\n', stdout); fflush(stdout); __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__); } while (0)

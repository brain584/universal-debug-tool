#pragma once

#include "Types.h"
#include <vector>
#include <string>
#include <unordered_map>

class ElfParser {
public:
    ElfParser() = default;
    ~ElfParser() = default;
    
    // 从文件加载
    bool loadFromFile(const std::string& path);
    
    // 从内存加载（远程进程）
    bool loadFromMemory(pid_t pid, uintptr_t base);
    
    // 验证 ELF
    bool isValid() const { return m_valid; }
    
    // 获取基地址
    uintptr_t base() const { return m_base; }
    
    // 获取入口点
    uintptr_t entry() const { return m_entry; }
    
    // 获取加载大小
    size_t loadSize() const { return m_loadSize; }
    
    // 查找符号
    uintptr_t findSymbol(const std::string& name) const;
    
    // 手动设置基址（如果从文件加载但需要指定运行时基址）
    void setBase(uintptr_t base);
    
    // 获取文件路径
    const std::string& filePath() const { return m_filePath; }
    
    // 获取段信息
    const std::vector<MapEntry>& segments() const { return m_segments; }
    
    // 获取 phdr 地址
    uintptr_t phdr() const { return m_base + m_header.e_phoff; }
    
    // 获取 dynamic 段地址
    uintptr_t dynamic() const { return m_dynamicAddr; }
    
    // 获取字符串表
    uintptr_t stringTable() const { return m_dynstr; }
    
    // 获取符号表
    uintptr_t symbolTable() const { return m_dynsym; }

private:
    bool parseHeader();
    bool parseDynamic();
    bool parseGnuHash();
    bool parseSysvHash();
    uintptr_t findSymbolByGnuHash(const std::string& name) const;
    uintptr_t findSymbolBySysvHash(const std::string& name) const;
    uintptr_t findSymbolLinear(const std::string& name) const;
    
    // GNU hash 函数
    static uint32_t gnuHash(const char* name);
    // SYSV hash 函数
    static uint32_t sysvHash(const char* name);
    
    bool m_valid = false;
    uintptr_t m_base = 0;
    uintptr_t m_entry = 0;
    size_t m_loadSize = 0;
    std::string m_filePath;
    
    Elf_Ehdr m_header{};
    std::vector<Elf_Phdr> m_phdrs;
    std::vector<MapEntry> m_segments;
    
    // 动态段
    uintptr_t m_dynamicAddr = 0;
    uintptr_t m_dynstr = 0;
    uintptr_t m_dynsym = 0;
    size_t m_dynsymCount = 0;
    
    // GNU hash 表
    uintptr_t m_gnuHash = 0;
    uint32_t m_gnuHashNbuckets = 0;
    uint32_t m_gnuHashSymndx = 0;
    uint32_t m_gnuHashMaskwords = 0;
    uint32_t m_gnuHashShift2 = 0;
    
    // SYSV hash 表
    uintptr_t m_sysvHash = 0;
    uint32_t m_sysvHashNbuckets = 0;
    uint32_t m_sysvHashNchains = 0;
    
    // 符号缓存
    mutable std::unordered_map<std::string, uintptr_t> m_symbolCache;
    
    // 用于远程读取
    pid_t m_remotePid = 0;
    std::vector<uint8_t> m_localData;
    
    // 本地符号表（从文件解析）
    uintptr_t m_localSymtabOffset = 0;
    size_t m_localSymCount = 0;
    uintptr_t m_localStrtabOffset = 0;
};

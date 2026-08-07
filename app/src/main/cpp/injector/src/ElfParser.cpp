#include "ElfParser.h"
#include "Utils.h"
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>

// 辅助方法：从远程进程读取内存（使用 /proc/[pid]/mem）
static ssize_t readRemote(pid_t pid, uintptr_t addr, void* buf, size_t len) {
    char memPath[64];
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", pid);
    
    int fd = open(memPath, O_RDONLY);
    if (fd >= 0) {
        if (lseek64(fd, addr, SEEK_SET) != -1) {
            ssize_t ret = read(fd, buf, len);
            close(fd);
            if (ret > 0) return ret;
        }
        close(fd);
    }
    
    // 回退到 process_vm_readv
    struct iovec local = { buf, len };
    struct iovec remote = { reinterpret_cast<void*>(addr), len };
    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

bool ElfParser::loadFromFile(const std::string& path) {
    m_filePath = path;
    m_localData = Utils::readFile(path);
    
    if (m_localData.size() < sizeof(Elf_Ehdr)) {
        return false;
    }
    
    memcpy(&m_header, m_localData.data(), sizeof(Elf_Ehdr));
    
    // 验证 ELF 魔数
    if (memcmp(m_header.e_ident, ELFMAG, SELFMAG) != 0) {
        return false;
    }
    
    // 验证是 64 位
    if (m_header.e_ident[EI_CLASS] != ELFCLASS64) {
        return false;
    }
    
    // 验证是 ARM64
    if (m_header.e_machine != EM_AARCH64) {
        return false;
    }
    
    m_entry = m_header.e_entry;
    m_valid = parseHeader() && parseDynamic();
    // 解析文件中的 section 符号表（如果有）
    if (m_valid) {
        // 解析 section header 中的 .symtab/.strtab
        if (!m_localData.empty()) {
            // parse section headers
            if (m_header.e_shoff && m_header.e_shnum) {
                size_t shentsize = sizeof(Elf_Shdr);
                size_t shTableSize = (size_t)m_header.e_shnum * shentsize;
                if (m_header.e_shoff + shTableSize <= m_localData.size()) {
                    // section header string table
                    uint32_t shstrIndex = m_header.e_shstrndx;
                    if (shstrIndex < m_header.e_shnum) {
                        const Elf_Shdr* shTable = reinterpret_cast<const Elf_Shdr*>(m_localData.data() + m_header.e_shoff);
                        const Elf_Shdr& shstr = shTable[shstrIndex];
                        if (shstr.sh_offset + shstr.sh_size <= m_localData.size()) {
                            for (uint16_t i = 0; i < m_header.e_shnum; ++i) {
                                const Elf_Shdr& sh = shTable[i];
                                if (sh.sh_type == SHT_SYMTAB) {
                                    // 找到符号表，读取它和对应的字符串表（sh_link）
                                    if (sh.sh_offset + sh.sh_size <= m_localData.size() && sh.sh_entsize >= sizeof(Elf_Sym) && sh.sh_entsize != 0) {
                                        uint32_t count = (uint32_t)(sh.sh_size / sh.sh_entsize);
                                        uint32_t strIndex = sh.sh_link;
                                        if (strIndex < m_header.e_shnum) {
                                            const Elf_Shdr& strSh = shTable[strIndex];
                                            if (strSh.sh_offset + strSh.sh_size <= m_localData.size()) {
                                                m_localSymtabOffset = (uintptr_t)sh.sh_offset;
                                                m_localSymCount = count;
                                                m_localStrtabOffset = (uintptr_t)strSh.sh_offset;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return m_valid;
}

bool ElfParser::loadFromMemory(pid_t pid, uintptr_t base) {
    m_remotePid = pid;
    m_base = base;
    
    // 使用 readRemote 读取 ELF header
    if (readRemote(pid, base, &m_header, sizeof(m_header)) != sizeof(m_header)) {
        LOGE("Failed to read ELF header from %p", (void*)base);
        return false;
    }
    
    // 验证 ELF 魔数
    if (memcmp(m_header.e_ident, ELFMAG, SELFMAG) != 0) {
        LOGE("Invalid ELF magic at %p", (void*)base);
        return false;
    }
    
    // 验证是 64 位
    if (m_header.e_ident[EI_CLASS] != ELFCLASS64) {
        LOGE("Not a 64-bit ELF");
        return false;
    }
    
    // 验证是 ARM64
    if (m_header.e_machine != EM_AARCH64) {
        LOGE("Not an ARM64 ELF (machine=%d)", m_header.e_machine);
        return false;
    }
    
    m_entry = base + m_header.e_entry;
    m_valid = parseHeader() && parseDynamic();
    return m_valid;
}

bool ElfParser::parseHeader() {
    // 读取程序头
    m_phdrs.resize(m_header.e_phnum);
    size_t phdrsSize = m_phdrs.size() * sizeof(Elf_Phdr);
    
    if (m_remotePid > 0) {
        if (readRemote(m_remotePid, m_base + m_header.e_phoff, m_phdrs.data(), phdrsSize) != (ssize_t)phdrsSize) {
            LOGE("Failed to read program headers");
            return false;
        }
    } else {
        if (m_header.e_phoff + phdrsSize > m_localData.size()) {
            return false;
        }
        memcpy(m_phdrs.data(), m_localData.data() + m_header.e_phoff, phdrsSize);
    }
    
    // 计算加载大小和收集段信息
    uintptr_t minAddr = UINTPTR_MAX;
    uintptr_t maxAddr = 0;
    
    for (const auto& phdr : m_phdrs) {
        if (phdr.p_type == PT_LOAD) {
            uintptr_t start = phdr.p_vaddr;
            uintptr_t end = phdr.p_vaddr + phdr.p_memsz;
            if (start < minAddr) minAddr = start;
            if (end > maxAddr) maxAddr = end;
            
            // 记录段信息
            MapEntry seg;
            seg.start = m_base + phdr.p_vaddr;
            seg.end = seg.start + phdr.p_memsz;
            seg.prot = 0;
            if (phdr.p_flags & PF_R) seg.prot |= 0x1;
            if (phdr.p_flags & PF_W) seg.prot |= 0x2;
            if (phdr.p_flags & PF_X) seg.prot |= 0x4;
            seg.offset = phdr.p_offset;
            m_segments.push_back(seg);
        }
        else if (phdr.p_type == PT_DYNAMIC) {
            // 如果是远程解析，dynamic 地址为运行时地址；如果是本地文件解析，则记录为文件偏移
            if (m_remotePid > 0) {
                m_dynamicAddr = m_base + phdr.p_vaddr;
            } else {
                m_dynamicAddr = phdr.p_offset;
            }
        }
    }
    
    m_loadSize = maxAddr - minAddr;
    return true;
}

bool ElfParser::parseDynamic() {
    if (!m_dynamicAddr) return true;
    // 如果是本地文件加载（m_remotePid == 0），我们不从远程进程读取 dynamic 表（已通过 section 解析本地符号）
    if (m_remotePid == 0) return true;
    
    // 读取动态段
    std::vector<Elf_Dyn> dyns;
    dyns.reserve(64);
    
    uintptr_t addr = m_dynamicAddr;
    while (true) {
        Elf_Dyn dyn;
        if (readRemote(m_remotePid, addr, &dyn, sizeof(dyn)) != sizeof(dyn)) {
            LOGE("Failed to read dynamic entry at %p", (void*)addr);
            break;
        }
        
        dyns.push_back(dyn);
        if (dyn.d_tag == DT_NULL) break;
        addr += sizeof(Elf_Dyn);
    }
    
    // 解析动态段
    for (const auto& dyn : dyns) {
        switch (dyn.d_tag) {
            case DT_STRTAB:
                m_dynstr = dyn.d_un.d_ptr;
                break;
            case DT_SYMTAB:
                m_dynsym = dyn.d_un.d_ptr;
                break;
            case DT_GNU_HASH:
                m_gnuHash = dyn.d_un.d_ptr;
                break;
            case DT_HASH:
                m_sysvHash = dyn.d_un.d_ptr;
                break;
        }
    }
    
    // 修复地址：如果地址小于基地址，则需要加上基地址（参考原项目）
    auto fixAddress = [this](uintptr_t& addr) {
        if (addr && addr < m_base) {
            addr += m_base;
        }
    };
    
    fixAddress(m_dynstr);
    fixAddress(m_dynsym);
    fixAddress(m_gnuHash);
    fixAddress(m_sysvHash);
    
    // 解析 hash 表
    if (m_gnuHash) {
        parseGnuHash();
    }
    if (m_sysvHash) {
        parseSysvHash();
    }
    
    return true;
}

// 设置基址
void ElfParser::setBase(uintptr_t base) {
    if (m_base == base) return;
    m_base = base;

    // 如果已经解析过 program headers，则重建 segments、dynamic 地址和 loadSize
    if (!m_phdrs.empty()) {
        m_segments.clear();
        uintptr_t minAddr = UINTPTR_MAX;
        uintptr_t maxAddr = 0;

        for (const auto& phdr : m_phdrs) {
            if (phdr.p_type == PT_LOAD) {
                MapEntry seg;
                seg.start = m_base + phdr.p_vaddr;
                seg.end = seg.start + phdr.p_memsz;
                seg.prot = 0;
                if (phdr.p_flags & PF_R) seg.prot |= 0x1;
                if (phdr.p_flags & PF_W) seg.prot |= 0x2;
                if (phdr.p_flags & PF_X) seg.prot |= 0x4;
                seg.offset = phdr.p_offset;
                m_segments.push_back(seg);

                if (phdr.p_vaddr < minAddr) minAddr = phdr.p_vaddr;
                if (phdr.p_vaddr + phdr.p_memsz > maxAddr) maxAddr = phdr.p_vaddr + phdr.p_memsz;
            } else if (phdr.p_type == PT_DYNAMIC) {
                if (m_remotePid > 0) {
                    m_dynamicAddr = m_base + phdr.p_vaddr;
                } else {
                    m_dynamicAddr = phdr.p_offset;
                }
            }
        }

        if (minAddr != UINTPTR_MAX && maxAddr > minAddr) {
            m_loadSize = maxAddr - minAddr;
        }
    }

    // 更新入口点为运行时地址
    m_entry = m_base + m_header.e_entry;
}


bool ElfParser::parseGnuHash() {
    if (!m_gnuHash || m_remotePid <= 0) return false;
    
    // GNU hash 表头: nbuckets, symndx, maskwords, shift2
    uint32_t header[4];
    if (readRemote(m_remotePid, m_gnuHash, header, sizeof(header)) != sizeof(header)) {
        LOGE("Failed to read GNU hash header");
        return false;
    }
    
    m_gnuHashNbuckets = header[0];
    m_gnuHashSymndx = header[1];
    m_gnuHashMaskwords = header[2];
    m_gnuHashShift2 = header[3];
    
    return true;
}

bool ElfParser::parseSysvHash() {
    if (!m_sysvHash || m_remotePid <= 0) return false;
    
    // SYSV hash 表头: nbuckets, nchains
    uint32_t header[2];
    if (readRemote(m_remotePid, m_sysvHash, header, sizeof(header)) != sizeof(header)) {
        LOGE("Failed to read SYSV hash header");
        return false;
    }
    
    m_sysvHashNbuckets = header[0];
    m_sysvHashNchains = header[1];
    m_dynsymCount = m_sysvHashNchains;
    
    return true;
}

uint32_t ElfParser::gnuHash(const char* name) {
    uint32_t h = 5381;
    for (const unsigned char* s = reinterpret_cast<const unsigned char*>(name); *s; ++s) {
        h = (h << 5) + h + *s;
    }
    return h;
}

uint32_t ElfParser::sysvHash(const char* name) {
    uint32_t h = 0, g;
    for (const unsigned char* s = reinterpret_cast<const unsigned char*>(name); *s; ++s) {
        h = (h << 4) + *s;
        g = h & 0xf0000000;
        if (g) h ^= g >> 24;
        h &= ~g;
    }
    return h;
}

uintptr_t ElfParser::findSymbolByGnuHash(const std::string& name) const {
    if (!m_gnuHash || !m_dynsym || !m_dynstr || m_remotePid <= 0) {
        return 0;
    }
    
    uint32_t hash = gnuHash(name.c_str());
    
    // 计算各部分偏移
    uintptr_t bloomAddr = m_gnuHash + 16;  // 跳过 header
    uintptr_t bucketsAddr = bloomAddr + m_gnuHashMaskwords * sizeof(uint64_t);
    uintptr_t chainsAddr = bucketsAddr + m_gnuHashNbuckets * sizeof(uint32_t);
    
    // 检查 bloom filter
    uint64_t bloom;
    uint32_t bloomIdx = (hash / 64) % m_gnuHashMaskwords;
    if (readRemote(m_remotePid, bloomAddr + bloomIdx * sizeof(uint64_t), &bloom, sizeof(bloom)) != sizeof(bloom)) {
        return 0;
    }
    
    uint64_t mask = (1ULL << (hash % 64)) | (1ULL << ((hash >> m_gnuHashShift2) % 64));
    if ((bloom & mask) != mask) {
        return 0;  // 符号肯定不存在
    }
    
    // 查找 bucket
    uint32_t bucket;
    uint32_t bucketIdx = hash % m_gnuHashNbuckets;
    if (readRemote(m_remotePid, bucketsAddr + bucketIdx * sizeof(uint32_t), &bucket, sizeof(bucket)) != sizeof(bucket)) {
        return 0;
    }
    
    if (bucket == 0) {
        return 0;  // 空 bucket
    }
    
    // 遍历 chain
    uint32_t symIdx = bucket;
    uint32_t hash1 = hash | 1;
    
    while (true) {
        // 读取 chain 值
        uint32_t chainVal;
        if (readRemote(m_remotePid, chainsAddr + (symIdx - m_gnuHashSymndx) * sizeof(uint32_t), &chainVal, sizeof(chainVal)) != sizeof(chainVal)) {
            break;
        }
        
        // 检查 hash 是否匹配
        if ((chainVal | 1) == hash1) {
            // 读取符号
            Elf_Sym sym;
            if (readRemote(m_remotePid, m_dynsym + symIdx * sizeof(Elf_Sym), &sym, sizeof(sym)) == sizeof(sym)) {
                // 读取符号名
                char symName[256] = {0};
                readRemote(m_remotePid, m_dynstr + sym.st_name, symName, sizeof(symName) - 1);
                
                if (name == symName && sym.st_value != 0) {
                    return m_base + sym.st_value;
                }
            }
        }
        
        // 检查是否是 chain 末尾
        if (chainVal & 1) {
            break;
        }
        
        ++symIdx;
    }
    
    return 0;
}

uintptr_t ElfParser::findSymbolBySysvHash(const std::string& name) const {
    if (!m_sysvHash || !m_dynsym || !m_dynstr || m_remotePid <= 0) {
        return 0;
    }
    
    uint32_t hash = sysvHash(name.c_str());
    uint32_t bucketIdx = hash % m_sysvHashNbuckets;
    
    // 读取 bucket
    uintptr_t bucketsAddr = m_sysvHash + 8;  // 跳过 nbuckets, nchains
    uintptr_t chainsAddr = bucketsAddr + m_sysvHashNbuckets * sizeof(uint32_t);
    
    uint32_t symIdx;
    if (readRemote(m_remotePid, bucketsAddr + bucketIdx * sizeof(uint32_t), &symIdx, sizeof(symIdx)) != sizeof(symIdx)) {
        return 0;
    }
    
    // 遍历 chain
    while (symIdx != 0) {
        // 读取符号
        Elf_Sym sym;
        if (readRemote(m_remotePid, m_dynsym + symIdx * sizeof(Elf_Sym), &sym, sizeof(sym)) == sizeof(sym)) {
            // 读取符号名
            char symName[256] = {0};
            readRemote(m_remotePid, m_dynstr + sym.st_name, symName, sizeof(symName) - 1);
            
            if (name == symName && sym.st_value != 0) {
                return m_base + sym.st_value;
            }
        }
        
        // 读取下一个 chain
        if (readRemote(m_remotePid, chainsAddr + symIdx * sizeof(uint32_t), &symIdx, sizeof(symIdx)) != sizeof(symIdx)) {
            break;
        }
    }
    
    return 0;
}

uintptr_t ElfParser::findSymbolLinear(const std::string& name) const {
    if (!m_dynsym || !m_dynstr || m_remotePid <= 0) {
        return 0;
    }
    
    size_t maxSymbols = m_dynsymCount > 0 ? m_dynsymCount : 10000;
    
    for (size_t i = 0; i < maxSymbols; ++i) {
        Elf_Sym sym;
        if (readRemote(m_remotePid, m_dynsym + i * sizeof(Elf_Sym), &sym, sizeof(sym)) != sizeof(sym)) {
            break;
        }
        
        if (sym.st_name == 0) continue;
        
        char symName[256] = {0};
        readRemote(m_remotePid, m_dynstr + sym.st_name, symName, sizeof(symName) - 1);
        
        if (name == symName && sym.st_value != 0) {
            return m_base + sym.st_value;
        }
    }
    
    return 0;
}

uintptr_t ElfParser::findSymbol(const std::string& name) const {
    // 检查缓存
    auto it = m_symbolCache.find(name);
    if (it != m_symbolCache.end()) {
        return it->second;
    }
    
    uintptr_t addr = 0;
    
    // 优先使用 GNU hash
    if (m_gnuHash) {
        addr = findSymbolByGnuHash(name);
    }
    
    // 回退到 SYSV hash
    if (!addr && m_sysvHash) {
        addr = findSymbolBySysvHash(name);
    }
    
    // 最后使用线性搜索
    if (!addr) {
        addr = findSymbolLinear(name);
    }
    
    // 如果动态表/散列未命中，尝试在本地文件的 .symtab 中查找（用于 local 符号）
    if (!addr && !m_localData.empty() && m_localSymtabOffset && m_localStrtabOffset && m_localSymCount > 0) {
        for (size_t i = 0; i < m_localSymCount; ++i) {
            size_t off = m_localSymtabOffset + i * sizeof(Elf_Sym);
            if (off + sizeof(Elf_Sym) > m_localData.size()) break;
            const Elf_Sym* sym = reinterpret_cast<const Elf_Sym*>(m_localData.data() + off);
            if (sym->st_name == 0) continue;
            size_t nameOff = m_localStrtabOffset + sym->st_name;
            if (nameOff >= m_localData.size()) continue;
            const char* symName = reinterpret_cast<const char*>(m_localData.data() + nameOff);
            if (name == symName && sym->st_value != 0) {
                addr = m_base + sym->st_value;
                break;
            }
        }
    }

    if (addr) {
        m_symbolCache[name] = addr;
    }
    
    return addr;
}

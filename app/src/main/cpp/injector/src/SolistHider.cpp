#include "SolistHider.h"
#include "Utils.h"
#include <cstring>
#include <string>
#include <dlfcn.h>
#include <link.h>



/*


__dl__Z17solist_add_soinfoP6soinfo  
; __unwind {
                ADRP            X8, #__dl__ZL6sonext@PAGE ; Alternative name is '__dl_$x'
                LDR             X9, [X8,#__dl__ZL6sonext@PAGEOFF]
                STR             X0, [X8,#__dl__ZL6sonext@PAGEOFF]
                STR             X0, [X9,#0x28]
                RET
; } 

__dl__Z15solist_get_headv                        
; __unwind {
                ADRP            X8, #__dl__ZL6solist@PAGE ; Alternative name is '__dl_$x'
                LDR             X0, [X8,#__dl__ZL6solist@PAGEOFF]
                RET
; } 

__dl__Z17solist_get_somainv                    
; __unwind {
                ADRP            X8, #__dl__ZL6somain@PAGE ; Alternative name is '__dl_$x'
                LDR             X0, [X8,#__dl__ZL6somain@PAGEOFF]
                RET
; } 

*/








SolistHider::SolistHider(RemoteProcess* remote) : m_remote(remote) {}

bool SolistHider::init() {
    // 查找 linker
    auto linkerMap = Utils::findMapByName(m_remote->pid(), "/linker64");
    if (linkerMap.start == 0) {
        linkerMap = Utils::findMapByName(m_remote->pid(), "/linker");
    }
    
    if (linkerMap.start == 0) {
        LOGE("Cannot find linker in target process");
        return false;
    }
    
    // 优先尝试从文件加载 linker 的符号表（以便获取本地/静态符号）
    if (!linkerMap.path.empty() && Utils::fileExists(linkerMap.path)) {
        if (m_linkerElf.loadFromFile(linkerMap.path)) {
            // 设置运行时基址，用于将符号值转换为运行时地址
            m_linkerElf.setBase(linkerMap.start);
        } else {
            // 回退到从内存解析
            if (!m_linkerElf.loadFromMemory(m_remote->pid(), linkerMap.start)) {
                LOGE("Failed to parse linker ELF from memory");
                return false;
            }
        }
    } else {
        if (!m_linkerElf.loadFromMemory(m_remote->pid(), linkerMap.start)) {
            LOGE("Failed to parse linker ELF");
            return false;
        }
    }
    
    LOGI("Linker base: %p", (void*)m_linkerElf.base());
    
    return findLinkerSymbols();
}

bool SolistHider::findLinkerSymbols() {
    // 尝试查找 __dl__ZL6solist 和 __dl__ZL6sonext
    // 这些是 linker 内部符号，可能需要通过其他方式获取
    
    // 方法1: 直接查找符号（可能被 strip）
    m_solistAddr = m_linkerElf.findSymbol("__dl__ZL6solist");
    m_sonextAddr = m_linkerElf.findSymbol("__dl__ZL6sonext");
    
    if (m_solistAddr && m_sonextAddr) {
        LOGI("Found solist: %p, sonext: %p", (void*)m_solistAddr, (void*)m_sonextAddr);
        
        // 读取实际的 solist 指针
        uintptr_t solist = 0;
        m_remote->readMemory(m_solistAddr, &solist, sizeof(solist));
        
        if (solist) {
            return findSoinfoOffsets(solist);
        }
    }
    // 方法2: per-function ADRP 解析（三个独立解析函数）

    // 解析 __dl__Z17solist_add_soinfoP6soinfo -> sonext
    uintptr_t addr = m_linkerElf.findSymbol("__dl__Z17solist_add_soinfoP6soinfo");
    if (addr && parseSolistAddSoinfo(addr)) {
        LOGI("Found sonext via __dl__Z17solist_add_soinfoP6soinfo");
    }

    // 解析 __dl__Z15solist_get_headv -> solist
    addr = m_linkerElf.findSymbol("__dl__Z15solist_get_headv");
    if (addr && parseSolistGetHead(addr)) {
        LOGI("Found solist via __dl__Z15solist_get_headv");
    }

    // // 解析 __dl__Z17solist_get_somainv -> solist
    // addr = m_linkerElf.findSymbol("__dl__Z17solist_get_somainv");
    // if (addr && parseSolistGetSomain(addr)) {
    //     LOGI("Found solist via __dl__Z17solist_get_somainv");
    // }

    if (m_solistAddr && m_sonextAddr) {
        LOGI("Found solist: %p, sonext: %p (by ADRP parsing)", (void*)m_solistAddr, (void*)m_sonextAddr);
        uintptr_t solist = 0;
        m_remote->readMemory(m_solistAddr, &solist, sizeof(solist));
        if (solist) return findSoinfoOffsets(solist);
    }

    LOGW("Cannot find linker symbols, solist hiding may not work");
    return false;
}

bool SolistHider::findSoinfoOffsets(uintptr_t soinfo) {
    // 使用固定偏移：base=0x10,size=0x18, next=0x28
    if (!soinfo) return false;
    m_offsets.base = 0x10;
    m_offsets.size = 0x18;
    m_offsets.next = 0x28;
    m_nextIsIndirect = false;

    // 验证 solist 中第二个 soinfo 的 ELF 魔数（提高可信度）
    uintptr_t secondSoinfo = 0;
    if (m_remote->readMemory(soinfo + m_offsets.next, &secondSoinfo, sizeof(secondSoinfo)) != sizeof(secondSoinfo) || secondSoinfo == 0) {
        LOGW("Using fixed soinfo offsets but cannot read second soinfo at soinfo+0x28");
        m_offsets.valid = true;
        return true;
    }

    uintptr_t secondBase = 0;
    if (m_remote->readMemory(secondSoinfo + m_offsets.base, &secondBase, sizeof(secondBase)) != sizeof(secondBase) || secondBase == 0) {
        LOGW("Using fixed soinfo offsets but cannot read base of second soinfo");
        m_offsets.valid = true;
        return true;
    }

    uint8_t magic[4];
    if (m_remote->readMemory(secondBase, magic, 4) == 4 && memcmp(magic, ELFMAG, SELFMAG) == 0) {
        m_offsets.valid = true;
        LOGI("Verified second soinfo base %p using fixed offsets", (void*)secondBase);
    } else {
        m_offsets.valid = true;
        LOGW("Fixed offsets used but ELF magic invalid at second soinfo base %p", (void*)secondBase);
    }

    return true;
}

// Helper: decode ADRP immediate (page)
static uintptr_t decodeAdrpImmStatic(uint32_t insn, uintptr_t insnAddr) {
    uint32_t immlo = (insn >> 29) & 0x3;
    uint32_t immhi = (insn >> 5) & 0x7FFFF;
    int64_t imm21 = (int64_t)((immhi << 2) | immlo);
    if (imm21 & (1 << 20)) imm21 |= ~((1 << 21) - 1);
    int64_t page = ((int64_t)insnAddr & ~0xFFFLL) + (imm21 << 12);
    return (uintptr_t)page;
}

bool SolistHider::parseSolistGetHead(uintptr_t funcAddr) {
    const size_t READ_BYTES = 40;
    std::vector<uint8_t> code(READ_BYTES);
    if (m_remote->readMemory(funcAddr, code.data(), code.size()) != (ssize_t)code.size()) {
        return false;
    }

    for (size_t off = 0; off + 8 <= code.size(); off += 4) {
        uint32_t insn = *reinterpret_cast<uint32_t*>(code.data() + off);
        if (insn == 0xD65F03C0) break;
        if ((insn & 0x9F000000) != 0x90000000) continue; // ADRP
        uintptr_t insnAddr = funcAddr + off;
        uintptr_t page = decodeAdrpImmStatic(insn, insnAddr);
        uint32_t insn2 = *reinterpret_cast<uint32_t*>(code.data() + off + 4);
        if ((insn2 & 0xFFC00000) != 0xF9400000) continue; // LDR unsigned imm
        int rd = insn & 0x1F;
        int rn = (insn2 >> 5) & 0x1F;
        int rt = insn2 & 0x1F;
        if (rn != rd) continue;
        int size = (insn2 >> 30) & 0x3;
        uint32_t imm12 = (insn2 >> 10) & 0xFFF;
        uintptr_t symAddr = page + ((uintptr_t)imm12 << size);
        uintptr_t symVal = 0;
        if (m_remote->readMemory(symAddr, &symVal, sizeof(symVal)) != sizeof(symVal)) continue;
        if (rt == 0 && !m_solistAddr) {
            m_solistAddr = symAddr;
            LOGI("parseSolistGetHead mapped func@%p -> solist %p", (void*)funcAddr, (void*)symAddr);
            return true;
        }
    }
    return false;
}

bool SolistHider::parseSolistGetSomain(uintptr_t funcAddr) {
    // Same logic as parseSolistGetHead
    return parseSolistGetHead(funcAddr);
}

bool SolistHider::parseSolistAddSoinfo(uintptr_t funcAddr) {
    // 只解析函数头部的 ADRP+LDR 指令对，获取 solist_tail 地址
    uint8_t code[8];
    if (m_remote->readMemory(funcAddr, code, sizeof(code)) != (ssize_t)sizeof(code)) {
        return false;
    }

    uint32_t insn = *reinterpret_cast<uint32_t*>(code);
    uint32_t insn2 = *reinterpret_cast<uint32_t*>(code + 4);

    // ADRP Xn, #page
    if ((insn & 0x9F000000) != 0x90000000) return false;
    // LDR Xt, [Xn, #imm]
    if ((insn2 & 0xFFC00000) != 0xF9400000) return false;

    int rd = insn & 0x1F;
    int rn = (insn2 >> 5) & 0x1F;
    if (rn != rd) return false;

    uintptr_t page = decodeAdrpImmStatic(insn, funcAddr);
    int size = (insn2 >> 30) & 0x3;
    uint32_t imm12 = (insn2 >> 10) & 0xFFF;
    uintptr_t symAddr = page + ((uintptr_t)imm12 << size);

    if (!m_sonextAddr) {
        m_sonextAddr = symAddr;
        LOGI("parseSolistAddSoinfo func@%p -> sonext(solist_tail) %p", (void*)funcAddr, (void*)symAddr);
        return true;
    }
    return false;
}

template<typename T>
T SolistHider::readSoinfoField(uintptr_t soinfo, uint32_t offset) {
    T value = 0;
    m_remote->readMemory(soinfo + offset, &value, sizeof(value));
    return value;
}

template<typename T>
bool SolistHider::writeSoinfoField(uintptr_t soinfo, uint32_t offset, T value) {
    return m_remote->writeMemory(soinfo + offset, &value, sizeof(value)) == sizeof(value);
}

bool SolistHider::removeFromSolist(const ElfParser& elf) {
    if (!m_offsets.valid) {
        LOGE("SolistHider not properly initialized");
        return false;
    }

    LOGI("Resetting g_module_load_counter...");
    solist_reset_counters(elf);

    LOGI("Removing ELF %p from solist...", (void*)elf.base());
    
    // 读取 solist 头
    uintptr_t solist = 0;
    if (m_remote->readMemory(m_solistAddr, &solist, sizeof(solist)) != sizeof(solist)) {
        LOGE("Failed to read solist");
        return false;
    }
    
    LOGI("solist head: %lx", solist);
    
    // 遍历链表查找目标 soinfo
    uintptr_t prev = 0;
    uintptr_t curr = solist;
    
    while (curr) {
        uintptr_t base = readSoinfoField<uintptr_t>(curr, m_offsets.base);
        //LOGI(" soinfo base: %lx", base);
        
        if (base == elf.base()) {
            // 找到了
            LOGI("Found target soinfo: %p", (void*)curr);
            
            // 获取 next（处理可能的 pointer-to-pointer）
            uintptr_t next = readSoinfoField<uintptr_t>(curr, m_offsets.next);
            if (m_nextIsIndirect) {
                uintptr_t deref = 0;
                if (m_remote->readMemory(next, &deref, sizeof(deref)) == sizeof(deref)) {
                    next = deref;
                } else {
                    next = 0;
                }
            }
            
            if (prev == 0) {
                // 是链表头，不能直接移除
                LOGE("Target is solist head, cannot remove");
                return false;
            }

            // 修改前一个节点的 next 指针（如果 next 字段是 indirect，则需要写入 *prev->next）
            if (m_nextIsIndirect) {
                // 读取 prev->next 字段（应为指向指针的位置）
                uintptr_t prevField = readSoinfoField<uintptr_t>(prev, m_offsets.next);
                if (prevField == 0) {
                    LOGE("Prev field pointer is null");
                    return false;
                }
                if (m_remote->writeMemory(prevField, &next, sizeof(next)) != sizeof(next)) {
                    LOGE("Failed to update *prev->next (indirect)");
                    return false;
                }
            } else {
                // 直接写 prev->next
                if (!writeSoinfoField(prev, m_offsets.next, next)) {
                    LOGE("Failed to update prev->next");
                    return false;
                }
            }
            
            LOGI("Removed soinfo %p from solist", (void*)curr);
            
            // 检查是否需要更新 sonext
            uintptr_t sonext = 0;
            if (m_remote->readMemory(m_sonextAddr, &sonext, sizeof(sonext)) == sizeof(sonext)) {
                if (sonext == curr) {
                    // 更新 sonext 为 prev
                    m_remote->writeMemory(m_sonextAddr, &prev, sizeof(prev));
                    LOGI("Updated sonext to %p", (void*)prev);
                }
            }
            
            return true;
        }
        
        prev = curr;
        // 读取下一个节点，处理 indirect 情形
        uintptr_t nextField = readSoinfoField<uintptr_t>(curr, m_offsets.next);
        if (m_nextIsIndirect) {
            uintptr_t nextNode = 0;
            if (nextField && m_remote->readMemory(nextField, &nextNode, sizeof(nextNode)) == sizeof(nextNode)) {
                curr = nextNode;
            } else {
                curr = 0;
            }
        } else {
            curr = nextField;
        }
    }
    
    LOGE("Target ELF not found in solist");
    return false;
}

bool SolistHider::solist_reset_counters(const ElfParser &elf) {
    (void)elf;
    uintptr_t g_module_load_counter = m_linkerElf.findSymbol("__dl__ZL21g_module_load_counter");
    if (!g_module_load_counter) {
        LOGW("g_module_load_counter symbol not found");
        return false;
    }

    uint64_t counter = 0;
    ssize_t rr = m_remote->readMemory(g_module_load_counter, &counter, sizeof(counter));
    if (rr != (ssize_t)sizeof(counter)) {
        LOGE("Failed to read g_module_load_counter at %p", (void*)g_module_load_counter);
        return false;
    }

    LOGI("g_module_load_counter: address 0x%lx, value 0x%lx", (unsigned long)g_module_load_counter, (unsigned long)counter);
    if (counter == 0) {
        LOGI("g_module_load_counter already zero, nothing to do");
        return true;
    }

    counter--;
    ssize_t wr = m_remote->writeMemory(g_module_load_counter, &counter, sizeof(counter));
    if (wr != (ssize_t)sizeof(counter)) {
        LOGE("Failed to write g_module_load_counter at %p", (void*)g_module_load_counter);
        return false;
    }

    LOGI("reset g_module_load_counter to 0x%lx", (unsigned long)counter);
    return true;
}

bool SolistHider::patchForDlclose(const ElfParser& elf) {
    if (!m_offsets.valid) {
        LOGE("SolistHider not properly initialized");
        return false;
    }

    uintptr_t solist = 0;
    if (m_remote->readMemory(m_solistAddr, &solist, sizeof(solist)) != sizeof(solist)) {
        LOGE("Failed to read solist");
        return false;
    }

    uintptr_t curr = solist;
    while (curr) {
        uintptr_t base = readSoinfoField<uintptr_t>(curr, m_offsets.base);

        if (base == elf.base()) {
            LOGI("Found target soinfo: %p, patching for dlclose hide", (void*)curr);

            constexpr uint32_t GAP_SIZE_OFFSET = 0x250;
            constexpr uint32_t FINI_ARRAY_COUNT_OFFSET = 0xb0;

            // 读取原始值
            uintptr_t origSize = readSoinfoField<uintptr_t>(curr, m_offsets.size);
            uintptr_t origGapSize = readSoinfoField<uintptr_t>(curr, GAP_SIZE_OFFSET);
            uintptr_t origFiniCount = readSoinfoField<uintptr_t>(curr, FINI_ARRAY_COUNT_OFFSET);

            LOGI("  [before] size=0x%lx, gap_size_=0x%lx, fini_array_count_=0x%lx",
                 (unsigned long)origSize, (unsigned long)origGapSize, (unsigned long)origFiniCount);

            uintptr_t zero64 = 0;

            // patch size = 0 → soinfo_free 跳过 munmap(base, size)
            writeSoinfoField(curr, m_offsets.size, zero64);
            LOGI("  soinfo->size = 0 (offset 0x%x)", m_offsets.size);

            // patch gap_size_ = 0 → 跳过 munmap(gap_start, gap_size)
            writeSoinfoField(curr, GAP_SIZE_OFFSET, zero64);
            LOGI("  soinfo->gap_size_ = 0 (offset 0x%x)", GAP_SIZE_OFFSET);

            // patch fini_array_count_ = 0 → call_destructors 跳过 DT_FINI_ARRAY
            writeSoinfoField(curr, FINI_ARRAY_COUNT_OFFSET, zero64);
            LOGI("  soinfo->fini_array_count_ = 0 (offset 0x%x)", FINI_ARRAY_COUNT_OFFSET);

            return true;
        }

        uintptr_t nextField = readSoinfoField<uintptr_t>(curr, m_offsets.next);
        if (m_nextIsIndirect) {
            uintptr_t nextNode = 0;
            if (nextField && m_remote->readMemory(nextField, &nextNode, sizeof(nextNode)) == sizeof(nextNode)) {
                curr = nextNode;
            } else {
                curr = 0;
            }
        } else {
            curr = nextField;
        }
    }

    LOGE("Target ELF not found in solist for dlclose patching");
    return false;
}
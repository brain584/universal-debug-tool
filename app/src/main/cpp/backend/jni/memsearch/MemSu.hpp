#ifndef UDT_MEMSU_HPP
#define UDT_MEMSU_HPP

#include "Membase.hpp"

// 基于 su 的 MemBase 实现：GUI 进程非 root，无法直接 open
// /proc/<pid>/mem，因此改用 su + dd 管道读写目标进程内存。
// 供 SearchEngine（imgui 侧）作为后端使用。
class MemSu : public MemBase {
public:
    MemSu() = default;
    explicit MemSu(int pid) { set_pid(pid); }

    bool read(uintptr_t address, void* buffer, size_t size) override;
    bool write(uintptr_t address, const void* buffer, size_t size) override;
};

#endif

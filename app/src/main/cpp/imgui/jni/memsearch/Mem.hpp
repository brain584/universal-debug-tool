#ifndef MEM_H
#define MEM_H

#include "Membase.hpp"
#include "ProcIO.hpp"
#include "Process.hpp"
#include <string>
#include <vector>

class Mem : public MemBase
{
public:
    Mem();
    explicit Mem(int pid);
    Mem(std::string process_name) : Mem(Process::get_pid_by_name(process_name.c_str())) {}
    ~Mem() override;

    Mem(const Mem &) = delete;
    Mem &operator=(const Mem &) = delete;

    Mem(Mem &&other) noexcept
        : MemBase(other), m_io(std::move(other.m_io)) {}

    Mem &operator=(Mem &&other) noexcept {
        if (this != &other) { set_pid(other.get_pid()); m_io = std::move(other.m_io); }
        return *this;
    }

    // ── MemBase 接口 ──────────────────────────────
    bool read(uintptr_t address, void *buffer, size_t size) override;
    bool write(uintptr_t address, const void *buffer, size_t size) override;

private:
    ProcIO m_io;
};

#endif

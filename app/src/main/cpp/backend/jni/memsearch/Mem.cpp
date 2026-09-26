#include "Mem.hpp"
#include <cstdio>
#include <unistd.h>

Mem::Mem() {
    set_pid(getpid());
    m_io.open(pid);
}

Mem::Mem(int pid) {
    set_pid(pid);
    m_io.open(pid);
}

Mem::~Mem() = default;  // ProcIO 自动 close

bool Mem::read(uintptr_t address, void *buffer, size_t size) {
    return m_io.read(address, buffer, size);      // pvm → pread
}

bool Mem::write(uintptr_t address, const void *buffer, size_t size) {
    return m_io.write(address, buffer, size);     // pvm → pwrite
}

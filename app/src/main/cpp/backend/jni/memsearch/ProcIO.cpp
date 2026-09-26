#include "ProcIO.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <cstring>

// ============================================================
// fd 管理
// ============================================================

bool ProcIO::open(int pid) {
    close();
    if (pid < 0) return false;
    std::string path = "/proc/" + std::to_string(pid) + "/mem";
    m_fd = ::open(path.c_str(), O_RDWR);
    if (m_fd < 0)
        m_fd = ::open(path.c_str(), O_RDONLY);
    if (m_fd >= 0) m_pid = pid;
    return m_fd >= 0;
}

void ProcIO::close() {
    if (m_fd >= 0) { ::close(m_fd); m_fd = -1; }
    m_pid = -1;
}

// ============================================================
// process_vm_readv / writev (静态, 架构自适应)
// ============================================================

#if defined(__aarch64__)
    #define SYS_PVM_RD 270
    #define SYS_PVM_WR 271
#elif defined(__arm__)
    #define SYS_PVM_RD 376
    #define SYS_PVM_WR 377
#elif defined(__x86_64__)
    #define SYS_PVM_RD 310
    #define SYS_PVM_WR 311
#elif defined(__i386__)
    #define SYS_PVM_RD 347
    #define SYS_PVM_WR 348
#else
    #define SYS_PVM_RD 310
    #define SYS_PVM_WR 311
#endif

bool ProcIO::pvmRead(int pid, uintptr_t addr, void* buf, size_t size) {
    struct iovec local[1], remote[1];
    local[0].iov_base = buf;
    local[0].iov_len  = size;
    remote[0].iov_base = reinterpret_cast<void*>(addr);
    remote[0].iov_len  = size;
    return syscall(SYS_PVM_RD, pid, local, 1, remote, 1, 0) == static_cast<ssize_t>(size);
}

bool ProcIO::pvmWrite(int pid, uintptr_t addr, const void* buf, size_t size) {
    struct iovec local[1], remote[1];
    local[0].iov_base = const_cast<void*>(buf);
    local[0].iov_len  = size;
    remote[0].iov_base = reinterpret_cast<void*>(addr);
    remote[0].iov_len  = size;
    return syscall(SYS_PVM_WR, pid, local, 1, remote, 1, 0) == static_cast<ssize_t>(size);
}

// ============================================================
// pread64 / pwrite64
// ============================================================

bool ProcIO::pread(uintptr_t addr, void* buf, size_t size) const {
    if (m_fd < 0) return false;
    return pread64(m_fd, buf, size, static_cast<off64_t>(addr)) == static_cast<ssize_t>(size);
}

bool ProcIO::pwrite(uintptr_t addr, const void* buf, size_t size) const {
    if (m_fd < 0) return false;
    return pwrite64(m_fd, buf, size, static_cast<off64_t>(addr)) == static_cast<ssize_t>(size);
}

// ============================================================
// 组合: pvm → pread / pvm → pwrite
// ============================================================

bool ProcIO::read(uintptr_t addr, void* buf, size_t size) const {
    if (pvmRead(m_pid, addr, buf, size)) return true;
    return pread(addr, buf, size);
}

bool ProcIO::write(uintptr_t addr, const void* buf, size_t size) const {
    if (pvmWrite(m_pid, addr, buf, size)) return true;
    return pwrite(addr, buf, size);
}

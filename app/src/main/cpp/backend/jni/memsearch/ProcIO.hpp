#ifndef PROCIO_HPP
#define PROCIO_HPP

#include <cstdint>
#include <cstddef>
#include <string>

class ProcIO {
public:
    ProcIO() = default;
    ~ProcIO() { close(); }

    // 禁止拷贝，允许移动
    ProcIO(const ProcIO&) = delete;
    ProcIO& operator=(const ProcIO&) = delete;
    ProcIO(ProcIO&& other) noexcept
        : m_pid(other.m_pid), m_fd(other.m_fd) {
        other.m_fd = -1; other.m_pid = -1;
    }
    ProcIO& operator=(ProcIO&& other) noexcept {
        if (this != &other) { close(); m_pid = other.m_pid; m_fd = other.m_fd;
            other.m_fd = -1; other.m_pid = -1; }
        return *this;
    }

    // ── 生命周期 ──────────────────────────────────
    bool open(int pid);
    void close();
    bool isOpen() const { return m_fd >= 0; }
    int  fd() const { return m_fd; }
    int  pid() const { return m_pid; }

    // ── 读写 ──────────────────────────────────────
    // process_vm_readv (首选, 无需 fd)
    static bool pvmRead(int pid, uintptr_t addr, void* buf, size_t size);
    static bool pvmWrite(int pid, uintptr_t addr, const void* buf, size_t size);

    // pread64 / pwrite64 (回退, 需要 fd)
    bool pread(uintptr_t addr, void* buf, size_t size) const;
    bool pwrite(uintptr_t addr, const void* buf, size_t size) const;

    // 组合: pvm → pread (最常用)
    bool read(uintptr_t addr, void* buf, size_t size) const;
    bool write(uintptr_t addr, const void* buf, size_t size) const;

private:
    int m_pid = -1;
    int m_fd = -1;
};

#endif

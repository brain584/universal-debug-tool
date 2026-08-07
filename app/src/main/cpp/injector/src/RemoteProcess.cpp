#include "RemoteProcess.h"
#include "Utils.h"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/elf.h>
#include <cstring>
#include <cerrno>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdarg>
#include <dirent.h>

// 验证返回指针是否有效（参考原项目）
#define IsValidRetPtr(x) (uintptr_t(x) > 0 && uintptr_t(x) != uintptr_t(-1) && \
                          uintptr_t(x) != uintptr_t(-4) && uintptr_t(x) != uintptr_t(-8))

RemoteProcess::RemoteProcess(pid_t pid) : m_pid(pid) {}

RemoteProcess::~RemoteProcess() {
    if (m_attached) {
        detach();
    }
}

bool RemoteProcess::attach() {
    if (m_attached) return true;
    
    errno = 0;
    if (ptrace(PTRACE_ATTACH, m_pid, nullptr, nullptr) == -1L) {
        LOGE("PTRACE_ATTACH failed for pid %d: %s", m_pid, strerror(errno));
        return false;
    }
    
    int status;
    if (waitpid(m_pid, &status, 0) != m_pid || !WIFSTOPPED(status)) {
        LOGE("Error waiting for pid %d to stop: %s", m_pid, strerror(errno));
        ptrace(PTRACE_DETACH, m_pid, nullptr, nullptr);
        return false;
    }
    
    // 检查停止信号
    int sig = WSTOPSIG(status);
    LOGI("Attached to process %d, stopped by signal %d", m_pid, sig);
    
    // 如果不是 SIGSTOP，可能有问题
    if (sig != SIGSTOP) {
        LOGW("Process stopped by signal %d instead of SIGSTOP", sig);
    }
    
    m_attached = true;
    return true;
}

bool RemoteProcess::detach() {
    if (!m_attached) return true;
    
    errno = 0;
    if (ptrace(PTRACE_DETACH, m_pid, nullptr, nullptr) == -1L) {
        LOGE("PTRACE_DETACH failed for pid %d: %s", m_pid, strerror(errno));
        return false;
    }
    
    m_attached = false;
    LOGI("Detached from process %d", m_pid);
    return true;
}

bool RemoteProcess::stop() {
    return kill(m_pid, SIGSTOP) == 0;
}

bool RemoteProcess::resume() {
    return kill(m_pid, SIGCONT) == 0;
}

bool RemoteProcess::cont() {
    if (!m_attached) {
        LOGE("PTRACE_CONT failed, not attached to %d", m_pid);
        return false;
    }
    
    errno = 0;
    // 传递 0 作为信号参数，抑制待处理的信号
    if (ptrace(PTRACE_CONT, m_pid, nullptr, nullptr) == -1L) {
        LOGE("PTRACE_CONT failed for pid %d: %s", m_pid, strerror(errno));
        return false;
    }
    return true;
}

bool RemoteProcess::getRegs(pt_regs* regs) {
    if (!regs) return false;
    
    if (!m_attached) {
        LOGE("getRegs failed, not attached to %d", m_pid);
        return false;
    }
    
    errno = 0;
    struct iovec iov = { regs, sizeof(*regs) };
    if (ptrace(PTRACE_GETREGSET, m_pid, NT_PRSTATUS, &iov) == -1L) {
        LOGE("PTRACE_GETREGSET failed for pid %d: %s", m_pid, strerror(errno));
        return false;
    }
    return true;
}

bool RemoteProcess::setRegs(const pt_regs* regs) {
    if (!regs) return false;
    
    if (!m_attached) {
        LOGE("setRegs failed, not attached to %d", m_pid);
        return false;
    }
    
    errno = 0;
    struct iovec iov = { const_cast<pt_regs*>(regs), sizeof(*regs) };
    if (ptrace(PTRACE_SETREGSET, m_pid, NT_PRSTATUS, &iov) == -1L) {
        LOGE("PTRACE_SETREGSET failed for pid %d: %s", m_pid, strerror(errno));
        return false;
    }
    return true;
}

ssize_t RemoteProcess::readMemory(uintptr_t addr, void* buf, size_t len) {
    // 优先使用 /proc/[pid]/mem（参考原项目 KittyMemIO）
    char memPath[64];
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", m_pid);
    
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
    
    errno = 0;
    ssize_t ret = process_vm_readv(m_pid, &local, 1, &remote, 1, 0);
    if (ret < 0) {
        LOGE("readMemory failed: %s (addr=%p, len=%zu)", strerror(errno), (void*)addr, len);
    }
    return ret;
}

ssize_t RemoteProcess::writeMemory(uintptr_t addr, const void* buf, size_t len) {
    // 优先使用 /proc/[pid]/mem（参考原项目 KittyMemIO）
    char memPath[64];
    snprintf(memPath, sizeof(memPath), "/proc/%d/mem", m_pid);
    
    int fd = open(memPath, O_RDWR);
    if (fd >= 0) {
        if (lseek64(fd, addr, SEEK_SET) != -1) {
            ssize_t ret = write(fd, buf, len);
            close(fd);
            if (ret > 0) {
                return ret;
            }
            LOGW("write to /proc/pid/mem failed: %s", strerror(errno));
        } else {
            LOGW("lseek64 failed: %s", strerror(errno));
        }
        close(fd);
    } else {
        LOGW("Failed to open %s: %s", memPath, strerror(errno));
    }
    
    // 回退到 process_vm_writev
    struct iovec local = { const_cast<void*>(buf), len };
    struct iovec remote = { reinterpret_cast<void*>(addr), len };
    
    errno = 0;
    ssize_t ret = process_vm_writev(m_pid, &local, 1, &remote, 1, 0);
    if (ret < 0) {
        LOGE("writeMemory failed: %s (addr=%p, len=%zu)", strerror(errno), (void*)addr, len);
    }
    return ret;
}

std::string RemoteProcess::readString(uintptr_t addr, size_t maxLen) {
    std::string result;
    result.resize(maxLen);
    
    ssize_t n = readMemory(addr, result.data(), maxLen);
    if (n <= 0) return "";
    
    size_t len = strnlen(result.data(), n);
    result.resize(len);
    return result;
}

// 参考原项目 KittyTrace.cpp 的 callFunctionFrom 实现
uintptr_t RemoteProcess::callFunctionFrom(uintptr_t callerAddr, uintptr_t funcAddr, int nargs, ...) {
    if (!funcAddr) return 0;
    
    if (!m_attached) {
        LOGE("callFunction failed, not attached to %d", m_pid);
        return 0;
    }
    
    // 如果没有指定 caller，使用默认 caller（参考原项目）
    if (!callerAddr) {
        callerAddr = m_defaultCaller;
    }
    
    pt_regs backup_regs, return_regs, tmp_regs;
    memset(&backup_regs, 0, sizeof(backup_regs));
    memset(&return_regs, 0, sizeof(return_regs));
    memset(&tmp_regs, 0, sizeof(tmp_regs));
    
    // 备份当前寄存器
    if (!getRegs(&backup_regs)) {
        return 0;
    }
    
    memcpy(&tmp_regs, &backup_regs, sizeof(backup_regs));
    
    // 失败时恢复寄存器
    auto failure_return = [&]() -> uintptr_t {
        LOGE("callFunction: Failed to call function %p with %d args", (void*)funcAddr, nargs);
        setRegs(&backup_regs);
        return 0;
    };
    
    va_list vl;
    va_start(vl, nargs);
    
    // ARM64: 前8个参数放入 x0-x7 (user_regs_struct.regs[0-7])
    for (int i = 0; i < nargs && i < 8; ++i) {
        tmp_regs.regs[i] = va_arg(vl, uintptr_t);
    }
    
    // 超过8个参数需要压栈
    if (nargs > 8) {
        tmp_regs.sp -= sizeof(uintptr_t) * (nargs - 8);
        uintptr_t stack = tmp_regs.sp;
        for (int i = 8; i < nargs; ++i) {
            uintptr_t arg = va_arg(vl, uintptr_t);
            if (writeMemory(stack, &arg, sizeof(uintptr_t)) != sizeof(uintptr_t)) {
                va_end(vl);
                return failure_return();
            }
            stack += sizeof(uintptr_t);
        }
    }
    
    va_end(vl);
    
    // 设置返回地址 (LR = x30 = regs[30])
    tmp_regs.regs[30] = callerAddr;
    
    // 设置函数地址 (PC)
    tmp_regs.pc = funcAddr;
    
    LOGI("callFunction: calling %p with %d args", (void*)funcAddr, nargs);
    
    // 设置寄存器并继续执行
    if (!setRegs(&tmp_regs)) {
        LOGE("callFunction: setRegs failed");
        return failure_return();
    }
    
    if (!cont()) {
        LOGE("callFunction: cont failed");
        return failure_return();
    }
    
    // 等待 SIGSEGV 或 SIGILL（由于返回地址无效导致）
    int status = 0;
    int loopCount = 0;
    do {
        errno = 0;
        pid_t wp = waitpid(m_pid, &status, WUNTRACED);
        
        if (wp != m_pid) {
            LOGE("callFunction: waitpid returned %d: %s", wp, strerror(errno));
            return failure_return();
        }
        
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            // SIGSEGV 或 SIGILL 表示函数已返回（跳转到无效地址）
            if (sig == SIGSEGV || sig == SIGILL) {
                break;
            }
            // 其他信号，继续执行
            if (!cont()) {
                return failure_return();
            }
            continue;
        }
        
        if (WIFEXITED(status)) {
            LOGE("callFunction: Target process exited (%d)", WEXITSTATUS(status));
            return 0;
        }
        
        if (WIFSIGNALED(status)) {
            LOGE("callFunction: Target process terminated (%d)", WTERMSIG(status));
            return 0;
        }
        
        if (++loopCount > 100) {
            LOGE("callFunction: too many iterations");
            return failure_return();
        }
        
        if (!cont()) {
            return failure_return();
        }
    } while (true);
    
    // 获取返回值
    if (!getRegs(&return_regs)) {
        return failure_return();
    }
    
    uintptr_t result = return_regs.regs[0];  // x0 是返回值
    
    // 恢复寄存器
    setRegs(&backup_regs);
    
    return result;
}

uintptr_t RemoteProcess::findSyscallGadget() {
    if (m_syscallAddr) return m_syscallAddr;
    
    // 通过本地符号计算远程地址（参考原项目 findRemoteOfSymbol）
    m_syscallAddr = findRemoteSymbol("syscall", reinterpret_cast<uintptr_t>(&::syscall));
    
    if (m_syscallAddr) {
        LOGI("Remote syscall at %p", (void*)m_syscallAddr);
    } else {
        LOGE("Cannot find remote syscall");
    }
    
    return m_syscallAddr;
}

// 参考原项目 RemoteSyscall 的实现
uintptr_t RemoteProcess::remoteAlloc(size_t size, int prot) {
    uintptr_t syscallAddr = findSyscallGadget();
    if (!syscallAddr) return 0;
    
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    
    // mmap(NULL, size, prot, flags, 0, 0)
    // 注意：原项目传递 7 个参数，最后两个是 0, 0（fd 和 offset）
    uintptr_t ret = callFunctionFrom(0, syscallAddr, 7,
        (uintptr_t)Syscall::MMAP,  // syscall number
        (uintptr_t)0,              // addr = NULL
        (uintptr_t)size,           // size
        (uintptr_t)prot,           // prot
        (uintptr_t)flags,          // flags
        (uintptr_t)0,              // fd = 0 (ignored for MAP_ANONYMOUS)
        (uintptr_t)0               // offset = 0
    );
    
    LOGI("remoteAlloc: syscall mmap returned %p (size=%zu, prot=%d)", (void*)ret, size, prot);
    
    if (!IsValidRetPtr(ret)) {
        LOGE("Remote mmap failed, ret=%p", (void*)ret);
        return 0;
    }
    
    return ret;
}

bool RemoteProcess::remoteFree(uintptr_t addr, size_t size) {
    if (!addr || !size) return false;
    
    uintptr_t syscallAddr = findSyscallGadget();
    if (!syscallAddr) return false;
    
    callFunctionFrom(0, syscallAddr, 3,
        (uintptr_t)Syscall::MUNMAP,
        addr,
        (uintptr_t)size
    );
    
    return true;
}

uintptr_t RemoteProcess::remoteAllocString(const std::string& str) {
    uintptr_t syscallAddr = findSyscallGadget();
    if (!syscallAddr) return 0;
    
    size_t size = str.size() + 1;
    
    // 分配内存
    uintptr_t remoteMem = callFunctionFrom(0, syscallAddr, 7,
        (uintptr_t)Syscall::MMAP,
        (uintptr_t)0,
        (uintptr_t)size,
        (uintptr_t)(PROT_READ | PROT_WRITE),
        (uintptr_t)(MAP_PRIVATE | MAP_ANONYMOUS),
        (uintptr_t)0,
        (uintptr_t)0
    );
    
    LOGI("remoteAllocString: mmap returned %p for %zu bytes", (void*)remoteMem, size);
    
    if (!IsValidRetPtr(remoteMem)) {
        LOGE("Failed to allocate memory for string, ret=%p", (void*)remoteMem);
        return 0;
    }
    
    // 写入字符串
    ssize_t written = writeMemory(remoteMem, str.c_str(), size);
    if (written != (ssize_t)size) {
        LOGE("Failed to write string to remote memory: wrote %zd of %zu bytes", written, size);
        remoteFree(remoteMem, size);
        return 0;
    }
    
    LOGI("remoteAllocString: wrote '%s' to %p", str.c_str(), (void*)remoteMem);
    return remoteMem;
}

int RemoteProcess::remoteMemfdCreate(const std::string& name, unsigned int flags) {
    uintptr_t syscallAddr = findSyscallGadget();
    if (!syscallAddr) return -1;
    
    // 先分配字符串
    uintptr_t nameAddr = remoteAllocString(name);
    if (!nameAddr) return -1;
    
    // memfd_create(name, flags)
    int fd = (int)callFunctionFrom(0, syscallAddr, 3,
        (uintptr_t)Syscall::MEMFD_CREATE,
        nameAddr,
        (uintptr_t)flags
    );
    
    // 释放字符串内存
    remoteFree(nameAddr, name.size() + 1);
    
    return fd;
}

long RemoteProcess::syscall(long nr, uintptr_t a0, uintptr_t a1, 
                            uintptr_t a2, uintptr_t a3,
                            uintptr_t a4, uintptr_t a5) {
    uintptr_t syscallAddr = findSyscallGadget();
    if (!syscallAddr) return -1;
    
    return (long)callFunctionFrom(0, syscallAddr, 7, (uintptr_t)nr, a0, a1, a2, a3, a4, a5);
}

uintptr_t RemoteProcess::findRemoteSymbol(const char* localSymName, uintptr_t localAddr) {
    // 找到本地符号所在的库
    auto localMaps = Utils::parseMaps(getpid());
    MapEntry localLib{};
    
    for (const auto& map : localMaps) {
        if (localAddr >= map.start && localAddr < map.end && !map.path.empty()) {
            localLib = map;
            break;
        }
    }
    
    if (localLib.start == 0 || localLib.path.empty()) {
        LOGE("Cannot find local lib for symbol %s at %p", localSymName, (void*)localAddr);
        return 0;
    }
    
    // 计算偏移（相对于段起始地址）
    uintptr_t offsetInSegment = localAddr - localLib.start;
    
    LOGI("Local %s: %p in %s (offset=0x%lx, segment_offset=0x%lx)", 
         localSymName, (void*)localAddr, localLib.path.c_str(), offsetInSegment, localLib.offset);
    
    // 在远程进程中找到相同的库的相同段（通过 offset 匹配）
    auto remoteMaps = Utils::parseMaps(m_pid);
    MapEntry remoteLib{};
    
    // 提取文件名用于匹配
    std::string fileName = localLib.path;
    size_t pos = fileName.rfind('/');
    if (pos != std::string::npos) {
        fileName = fileName.substr(pos + 1);
    }
    
    // 查找具有相同 offset 的段
    for (const auto& map : remoteMaps) {
        if (map.path.find(fileName) != std::string::npos && map.offset == localLib.offset) {
            remoteLib = map;
            break;
        }
    }
    
    // 如果没找到相同 offset 的段，尝试找任何匹配的段
    if (remoteLib.start == 0) {
        for (const auto& map : remoteMaps) {
            if (map.path.find(fileName) != std::string::npos) {
                remoteLib = map;
                break;
            }
        }
    }
    
    if (remoteLib.start == 0) {
        LOGE("Cannot find remote lib: %s", localLib.path.c_str());
        return 0;
    }
    
    uintptr_t remoteAddr = remoteLib.start + offsetInSegment;
    LOGI("Remote %s: %p in %s", localSymName, (void*)remoteAddr, remoteLib.path.c_str());
    
    return remoteAddr;
}

uintptr_t RemoteProcess::findDefaultCaller() {
    if (m_defaultCaller) return m_defaultCaller;

    const char* candidates[] = {
        "libc.so",
        "libdl.so",
        nullptr
    };
    
    for (int i = 0; candidates[i]; ++i) {
        auto map = Utils::findMapByName(m_pid, candidates[i]);
        if (map.start != 0) {
            m_defaultCaller = map.start;
            LOGI("Default caller: %p (%s)", (void*)m_defaultCaller, candidates[i]);
            return m_defaultCaller;
        }
    }
    
    LOGW("Cannot find default caller library");
    return 0;
}

bool RemoteProcess::freezeAllThreads() {
    m_frozenTids.clear();

    char taskPath[64];
    snprintf(taskPath, sizeof(taskPath), "/proc/%d/task", m_pid);

    DIR* dir = opendir(taskPath);
    if (!dir) {
        LOGE("Failed to open %s: %s", taskPath, strerror(errno));
        return false;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name[0] == '.') continue;

        pid_t tid = atoi(entry->d_name);
        if (tid <= 0 || tid == m_pid) continue;

        errno = 0;
        if (ptrace(PTRACE_ATTACH, tid, nullptr, nullptr) == -1L) {
            LOGW("Failed to attach to tid %d: %s", tid, strerror(errno));
            continue;
        }

        int status;
        if (waitpid(tid, &status, __WALL) == tid && WIFSTOPPED(status)) {
            m_frozenTids.push_back(tid);
        } else {
            LOGW("waitpid failed for tid %d, detaching", tid);
            ptrace(PTRACE_DETACH, tid, nullptr, nullptr);
        }
    }

    closedir(dir);
    LOGI("Frozen %zu extra threads", m_frozenTids.size());
    return true;
}

bool RemoteProcess::thawAllThreads() {
    for (pid_t tid : m_frozenTids) {
        if (ptrace(PTRACE_DETACH, tid, nullptr, nullptr) == -1L) {
            LOGW("Failed to detach from tid %d: %s", tid, strerror(errno));
        }
    }
    LOGI("Thawed %zu extra threads", m_frozenTids.size());
    m_frozenTids.clear();
    return true;
}

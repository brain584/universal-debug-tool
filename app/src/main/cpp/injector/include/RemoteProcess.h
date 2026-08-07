#pragma once

#include "Types.h"
#include <sys/user.h>

// ARM64 使用 user_regs_struct（参考原项目）
#if defined(__aarch64__)
using pt_regs = struct user_regs_struct;
#endif

class RemoteProcess {
public:
    explicit RemoteProcess(pid_t pid);
    ~RemoteProcess();
    
    // 禁止拷贝
    RemoteProcess(const RemoteProcess&) = delete;
    RemoteProcess& operator=(const RemoteProcess&) = delete;
    
    // ptrace 操作
    bool attach();
    bool detach();
    bool isAttached() const { return m_attached; }
    
    // 进程控制
    bool stop();
    bool resume();
    bool cont();  // PTRACE_CONT
    
    // 寄存器操作
    bool getRegs(pt_regs* regs);
    bool setRegs(const pt_regs* regs);
    
    // 内存操作
    ssize_t readMemory(uintptr_t addr, void* buf, size_t len);
    ssize_t writeMemory(uintptr_t addr, const void* buf, size_t len);
    std::string readString(uintptr_t addr, size_t maxLen = 256);
    
    // 远程函数调用（参考原项目 KittyTrace）
    uintptr_t callFunctionFrom(uintptr_t callerAddr, uintptr_t funcAddr, int nargs, ...);
    
    // 远程系统调用
    long syscall(long nr, uintptr_t a0 = 0, uintptr_t a1 = 0, 
                 uintptr_t a2 = 0, uintptr_t a3 = 0,
                 uintptr_t a4 = 0, uintptr_t a5 = 0);
    
    // 远程内存分配
    uintptr_t remoteAlloc(size_t size, int prot);
    bool remoteFree(uintptr_t addr, size_t size);
    uintptr_t remoteAllocString(const std::string& str);
    
    // 远程 memfd
    int remoteMemfdCreate(const std::string& name, unsigned int flags);
    
    // 查找远程符号
    uintptr_t findRemoteSymbol(const char* localSymName, uintptr_t localAddr);
    
    // 设置默认 caller 地址
    void setDefaultCaller(uintptr_t addr) { m_defaultCaller = addr; }
    uintptr_t defaultCaller() const { return m_defaultCaller; }
    
    pid_t pid() const { return m_pid; }

    // 冻结/解冻目标进程的所有线程（ptrace attach/detach 除主线程外的所有 TID）
    bool freezeAllThreads();
    bool thawAllThreads();

private:
    uintptr_t findSyscallGadget();
    uintptr_t findDefaultCaller();

    pid_t m_pid;
    bool m_attached = false;
    uintptr_t m_syscallAddr = 0;
    uintptr_t m_defaultCaller = 0;
    std::vector<pid_t> m_frozenTids;
};

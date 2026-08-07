#pragma once

#include "Types.h"
#include <functional>
#include <string>

// 进程启动事件
struct ProcessStartEvent {
    pid_t pid;
    int uid;
    std::string processName;
};

class ProcessMonitor {
public:
    ProcessMonitor() = default;
    ~ProcessMonitor();
    
    // 禁止拷贝
    ProcessMonitor(const ProcessMonitor&) = delete;
    ProcessMonitor& operator=(const ProcessMonitor&) = delete;
    
    // 等待指定包名的进程启动
    // 返回进程 PID，失败返回 -1
    pid_t waitForProcess(const std::string& packageName, int timeoutMs = -1);
    
    // 监控进程启动（回调方式）
    // 回调返回 true 停止监控
    bool monitor(std::function<bool(const ProcessStartEvent&)> callback, int timeoutMs = -1);
    
    // 停止监控
    void stop();

private:
    // 通过 logcat 监控 am_proc_start 事件
    bool monitorViaLogcat(std::function<bool(const ProcessStartEvent&)> callback, int timeoutMs);
    
    // 通过 inotify 监控 /proc 目录
    bool monitorViaInotify(std::function<bool(const ProcessStartEvent&)> callback, int timeoutMs);
    
    bool m_running = false;
    int m_inotifyFd = -1;
};

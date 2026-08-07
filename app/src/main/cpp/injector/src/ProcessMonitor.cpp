#include "ProcessMonitor.h"
#include "Utils.h"
#include <android/log.h>
#include <sys/system_properties.h>
#include <sys/inotify.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <cstring>
#include <fstream>
#include <chrono>

// Android log 相关结构
extern "C" {

struct logger_entry {
    uint16_t len;
    uint16_t hdr_size;
    int32_t pid;
    uint32_t tid;
    uint32_t sec;
    uint32_t nsec;
    uint32_t lid;
    uint32_t uid;
};

#define LOGGER_ENTRY_MAX_LEN (5 * 1024)

struct log_msg {
    union {
        unsigned char buf[LOGGER_ENTRY_MAX_LEN + 1];
        struct logger_entry entry;
    };
};

// 弱符号声明
__attribute__((weak)) struct logger_list* android_logger_list_alloc(int mode, unsigned int tail, pid_t pid);
__attribute__((weak)) void android_logger_list_free(struct logger_list* list);
__attribute__((weak)) int android_logger_list_read(struct logger_list* list, struct log_msg* log_msg);
__attribute__((weak)) struct logger* android_logger_open(struct logger_list* list, log_id_t id);

// am_proc_start 事件结构
struct android_event_header_t {
    int32_t tag;
} __attribute__((packed));

struct android_event_int_t {
    int8_t type;
    int32_t data;
} __attribute__((packed));

struct android_event_string_t {
    int8_t type;
    int32_t length;
    char data[];
} __attribute__((packed));

struct android_event_list_t {
    int8_t type;
    int8_t element_count;
} __attribute__((packed));

struct android_event_am_proc_start {
    android_event_header_t tag;
    android_event_list_t list;
    android_event_int_t user;
    android_event_int_t pid;
    android_event_int_t uid;
    android_event_string_t process_name;
} __attribute__((packed));

} // extern "C"

ProcessMonitor::~ProcessMonitor() {
    stop();
}

void ProcessMonitor::stop() {
    m_running = false;
    if (m_inotifyFd >= 0) {
        close(m_inotifyFd);
        m_inotifyFd = -1;
    }
}

pid_t ProcessMonitor::waitForProcess(const std::string& packageName, int timeoutMs) {
    pid_t resultPid = -1;
    
    monitor([&](const ProcessStartEvent& event) -> bool {
        if (event.processName == packageName) {
            resultPid = event.pid;
            return true;  // 停止监控
        }
        return false;
    }, timeoutMs);
    
    return resultPid;
}

bool ProcessMonitor::monitor(std::function<bool(const ProcessStartEvent&)> callback, int timeoutMs) {
    // 优先使用 logcat 方式
    if (android_logger_list_alloc && android_logger_open && android_logger_list_read) {
        return monitorViaLogcat(callback, timeoutMs);
    }
    
    // 回退到 inotify 方式
    return monitorViaInotify(callback, timeoutMs);
}

bool ProcessMonitor::monitorViaLogcat(std::function<bool(const ProcessStartEvent&)> callback, int timeoutMs) {
    LOGI("Monitoring via logcat...");
    
    // 保存并清除 log tag 过滤
    char savedLogTag[256] = {0};
    __system_property_get("persist.log.tag", savedLogTag);
    __system_property_set("persist.log.tag", "");
    
    auto loggerList = android_logger_list_alloc(0, 1, 0);
    if (!loggerList) {
        LOGE("Failed to allocate logger list");
        return false;
    }
    
    auto logger = android_logger_open(loggerList, LOG_ID_EVENTS);
    if (!logger) {
        LOGE("Failed to open events logger");
        android_logger_list_free(loggerList);
        return false;
    }
    
    m_running = true;
    bool firstMsg = true;
    bool result = false;
    
    auto startTime = std::chrono::steady_clock::now();
    
    while (m_running) {
        // 检查超时
        if (timeoutMs > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();
            if (elapsed >= timeoutMs) {
                LOGI("Monitor timeout");
                break;
            }
        }
        
        struct log_msg msg{};
        int ret = android_logger_list_read(loggerList, &msg);
        
        if (ret <= 0) {
            break;
        }
        
        // 跳过第一条消息（可能是旧的）
        if (firstMsg) {
            firstMsg = false;
            continue;
        }
        
        // 解析事件
        auto* header = reinterpret_cast<const android_event_header_t*>(
            &msg.buf[msg.entry.hdr_size]);
        
        // am_proc_start 的 tag 是 30014
        if (header->tag != 30014) {
            continue;
        }
        
        auto* event = reinterpret_cast<const android_event_am_proc_start*>(header);
        
        ProcessStartEvent startEvent;
        startEvent.pid = event->pid.data;
        startEvent.uid = event->uid.data;
        startEvent.processName = std::string(event->process_name.data, event->process_name.length);
        
        LOGI("Process started: %s (pid=%d)", startEvent.processName.c_str(), startEvent.pid);
        
        if (callback(startEvent)) {
            result = true;
            break;
        }
    }
    
    android_logger_list_free(loggerList);
    
    // 恢复 log tag
    if (savedLogTag[0]) {
        __system_property_set("persist.log.tag", savedLogTag);
    }
    
    return result;
}

bool ProcessMonitor::monitorViaInotify(std::function<bool(const ProcessStartEvent&)> callback, int timeoutMs) {
    LOGI("Monitoring via inotify...");
    
    m_inotifyFd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
    if (m_inotifyFd < 0) {
        LOGE("Failed to init inotify: %s", strerror(errno));
        return false;
    }
    
    // 监控 /proc 目录
    int wd = inotify_add_watch(m_inotifyFd, "/proc", IN_CREATE);
    if (wd < 0) {
        LOGE("Failed to add watch on /proc: %s", strerror(errno));
        close(m_inotifyFd);
        m_inotifyFd = -1;
        return false;
    }
    
    m_running = true;
    bool result = false;
    
    auto startTime = std::chrono::steady_clock::now();
    
    char buffer[4096];
    
    while (m_running) {
        // 检查超时
        int pollTimeout = -1;
        if (timeoutMs > 0) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();
            if (elapsed >= timeoutMs) {
                LOGI("Monitor timeout");
                break;
            }
            pollTimeout = timeoutMs - elapsed;
        }
        
        struct pollfd pfd = { m_inotifyFd, POLLIN, 0 };
        int pollRet = poll(&pfd, 1, pollTimeout > 0 ? pollTimeout : 100);
        
        if (pollRet < 0) {
            if (errno == EINTR) continue;
            break;
        }
        
        if (pollRet == 0) continue;
        
        ssize_t len = read(m_inotifyFd, buffer, sizeof(buffer));
        if (len <= 0) continue;
        
        // 处理事件
        for (char* ptr = buffer; ptr < buffer + len; ) {
            auto* event = reinterpret_cast<struct inotify_event*>(ptr);
            
            if (event->len > 0 && (event->mask & IN_CREATE)) {
                // 检查是否是数字目录（进程目录）
                char* end;
                pid_t pid = strtol(event->name, &end, 10);
                
                if (*end == '\0' && pid > 0) {
                    // 读取进程名
                    std::string cmdlinePath = Utils::format("/proc/%d/cmdline", pid);
                    std::ifstream cmdline(cmdlinePath);
                    std::string processName;
                    std::getline(cmdline, processName, '\0');
                    
                    if (!processName.empty()) {
                        ProcessStartEvent startEvent;
                        startEvent.pid = pid;
                        startEvent.uid = 0;  // inotify 方式无法获取 uid
                        startEvent.processName = processName;
                        
                        LOGI("Process created: %s (pid=%d)", processName.c_str(), pid);
                        
                        if (callback(startEvent)) {
                            result = true;
                            goto done;
                        }
                    }
                }
            }
            
            ptr += sizeof(struct inotify_event) + event->len;
        }
    }
    
done:
    inotify_rm_watch(m_inotifyFd, wd);
    close(m_inotifyFd);
    m_inotifyFd = -1;
    
    return result;
}

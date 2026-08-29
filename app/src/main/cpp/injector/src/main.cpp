#include "Types.h"
#include "Utils.h"
#include "Injector.h"
#include "ProcessMonitor.h"
#include "BreakpointService.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <unistd.h>
#include <getopt.h>
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <android/log.h>

// 中继模式：以 root 连接 Unix socket 并透明转发
// socket 与 stdin/stdout 之间的字节。imgui 应用通过 `su` 启动它，
// 即使 SELinux 阻止应用自身直接连接，
// 加密 socket 通道也能工作。
static int RunRelay(const char* socket_path) {
    signal(SIGPIPE, SIG_IGN);

    int fd = -1;
    for (int attempt = 0; attempt < 2 && fd < 0; attempt++) {
        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) break;
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        // 通道使用抽象 socket（不创建文件，
        // 因此不适用 SELinux sock_file 限制）。参数是
        // 不带前导 '@' 的抽象名称。
        addr.sun_path[0] = '\0';
        strncpy(&addr.sun_path[1], socket_path, sizeof(addr.sun_path) - 2);
        if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) break;
        __android_log_print(ANDROID_LOG_ERROR, "NewInjector",
                            "relay connect %s failed: %s",
                            socket_path, strerror(errno));
        close(fd);
        fd = -1;
    }
    if (fd < 0) return 1;
    __android_log_print(ANDROID_LOG_INFO, "NewInjector", "relay connected");

    fd_set rfds;
    char buf[8192];
    for (;;) {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        FD_SET(STDIN_FILENO, &rfds);
        int maxfd = fd > STDIN_FILENO ? fd : STDIN_FILENO;
        if (select(maxfd + 1, &rfds, nullptr, nullptr, nullptr) < 0) break;
        if (FD_ISSET(fd, &rfds)) {
            ssize_t r = read(fd, buf, sizeof(buf));
            if (r <= 0) break;
            if (write(STDOUT_FILENO, buf, (size_t)r) != r) break;
        }
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            ssize_t r = read(STDIN_FILENO, buf, sizeof(buf));
            if (r <= 0) break;
            if (write(fd, buf, (size_t)r) != r) break;
        }
    }
    close(fd);
    return 0;
}

// PID 直注入（native ELF 等非应用进程）时没有应用私有目录可放
// agent：把它复制到 /data/local/tmp 并交给 shell 组，
// 保证 root / shell 域的目标进程都能读取（目录权限由调用方
// 先用 root chmod 777 开放）。
static std::string CopyAgentToPublicTmp(const std::string& libPath) {
    std::string base = libPath.substr(libPath.find_last_of('/') + 1);
    std::string dst = "/data/local/tmp/" + base;
    std::ifstream src(libPath, std::ios::binary);
    if (!src) {
        LOGE("Cannot open agent for copy: %s", libPath.c_str());
        return libPath;
    }
    std::ofstream out(dst, std::ios::binary | std::ios::trunc);
    if (!out) {
        LOGE("Cannot write %s", dst.c_str());
        return libPath;
    }
    out << src.rdbuf();
    out.close();
    chmod(dst.c_str(), 0644);
    chown(dst.c_str(), 2000, 2000);  // shell:shell
    LOGI("Agent copied to %s", dst.c_str());
    return dst;
}

void printUsage(const char* prog) {
    printf("Usage: %s [options]\n", prog);
    printf("\nRequired:\n");
    printf("  -p, --pkg <name>     Target package name (可省略，若指定 -i)\n");
    printf("  -l, --lib <path>     Library path to inject\n");
    printf("\nOptional:\n");
    printf("  -i, --pid <pid>      Target PID (if known)\n");
    printf("  -m, --memfd          Use memfd injection\n");
    printf("  -H, --hide-maps      Hide from /proc/[pid]/maps\n");
    printf("  -S, --hide-solist    Hide from linker solist\n");
    printf("  -D, --deep-obfuscate Perform deep ELF obfuscation after injection\n");
    printf("  -C, --dlclose-hide   Hide via patching soinfo + dlclose (alternative to -S)\n");
    printf("  -w, --watch          Watch for process start\n");
    printf("  -d, --delay <us>     Delay before injection (microseconds)\n");
    printf("  -t, --timeout <ms>   Watch timeout (milliseconds)\n");
    printf("  -n, --no-copy        Don't copy lib to private dir (use original path)\n");
    printf("  -r, --relay <path>   Relay a unix socket to stdin/stdout (root)\n");
    printf("  -B, --bp <pid>       Hardware breakpoint/watchpoint service (root)\n");
    printf("  -h, --help           Show this help\n");
}

int main(int argc, char* argv[]) {
    // 禁用缓冲
    setbuf(stdout, nullptr);
    setbuf(stderr, nullptr);
    
    // 参数
    std::string pkgName;
    std::string libPath;
    pid_t targetPid = 0;
    bool useMemfd = false;
    bool hideMaps = false;
    bool hideSolist = false;
    bool deepObfuscate = false;
    bool dlcloseHide = false;
    bool watchMode = false;
    bool copyToPrivate = true;  // 默认启用复制到私有目录
    unsigned int delay = 0;
    int timeout = -1;
    std::string relayPath;
    pid_t bpPid = 0;
    
    // 解析命令行
    static struct option longOpts[] = {
        {"pkg",         required_argument, nullptr, 'p'},
        {"lib",         required_argument, nullptr, 'l'},
        {"pid",         required_argument, nullptr, 'i'},
        {"memfd",       no_argument,       nullptr, 'm'},
        {"hide-maps",   no_argument,       nullptr, 'H'},
        {"hide-solist", no_argument,       nullptr, 'S'},
        {"deep-obfuscate", no_argument, nullptr, 'D'},
        {"dlclose-hide", no_argument, nullptr, 'C'},
        {"watch",       no_argument,       nullptr, 'w'},
        {"delay",       required_argument, nullptr, 'd'},
        {"timeout",     required_argument, nullptr, 't'},
        {"no-copy",     no_argument,       nullptr, 'n'},
        {"relay",       required_argument, nullptr, 'r'},
        {"bp",          required_argument, nullptr, 'B'},
        {"help",        no_argument,       nullptr, 'h'},
        {nullptr, 0, nullptr, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "p:l:i:mHSwd:Dt:nChr:B:", longOpts, nullptr)) != -1) {
        switch (opt) {
            case 'p': pkgName = optarg; break;
            case 'l': libPath = optarg; break;
            case 'i': targetPid = atoi(optarg); break;
            case 'm': useMemfd = true; break;
            case 'H': hideMaps = true; break;
            case 'S': hideSolist = true; break;
            case 'D': deepObfuscate = true; break;
            case 'C': dlcloseHide = true; break;
            case 'w': watchMode = true; break;
            case 'd': delay = atoi(optarg); break;
            case 't': timeout = atoi(optarg); break;
            case 'n': copyToPrivate = false; break;
            case 'r': relayPath = optarg; break;
            case 'B': bpPid = atoi(optarg); break;
            case 'h':
                printUsage(argv[0]);
                return 0;
            default:
                printUsage(argv[0]);
                return 1;
        }
    }

    // 验证参数
    // 断点服务模式不需要注入参数。
    if (bpPid > 0) {
        return RunBreakpointService(bpPid);
    }

    // 中继模式不需要注入参数。
    if (!relayPath.empty()) {
        return RunRelay(relayPath.c_str());
    }

    if (libPath.empty() || (pkgName.empty() && targetPid <= 0)) {
        LOGE("Missing required arguments (need -p <pkg> 或 -i <pid>, 以及 -l <lib>)");
        printUsage(argv[0]);
        return 1;
    }
    
    // 检查库文件
    if (!Utils::fileExists(libPath)) {
        LOGE("Library not found: %s", libPath.c_str());
        return 1;
    }
    
    LOGI("=== NewInjector ===");
    LOGI("Package: %s", pkgName.c_str());
    LOGI("Library: %s", libPath.c_str());
    LOGI("Use memfd: %s", useMemfd ? "yes" : "no");
    LOGI("Hide maps: %s", hideMaps ? "yes" : "no");
    LOGI("Hide solist: %s", hideSolist ? "yes" : "no");
    LOGI("Dlclose hide: %s", dlcloseHide ? "yes" : "no");
    LOGI("Watch mode: %s", watchMode ? "yes" : "no");
    LOGI("Copy to private: %s", copyToPrivate ? "yes" : "no");
    
    // 获取目标 PID
    if (targetPid <= 0) {
        if (watchMode) {
            // 检查进程是否已经运行
            pid_t existingPid = Utils::getProcessPid(pkgName);
            if (existingPid > 0) {
                LOGE("Process already running (pid=%d), cannot use watch mode", existingPid);
                return 1;
            }
            
            LOGI("Waiting for process %s to start...", pkgName.c_str());
            
            ProcessMonitor monitor;
            targetPid = monitor.waitForProcess(pkgName, timeout);
            
            if (targetPid <= 0) {
                LOGE("Timeout waiting for process");
                return 1;
            }
            
            LOGI("Process started with PID: %d", targetPid);
        } else {
            targetPid = Utils::getProcessPid(pkgName);
            if (targetPid <= 0) {
                LOGE("Cannot find process: %s", pkgName.c_str());
                return 1;
            }
        }
    }
    
    LOGI("Target PID: %d", targetPid);

    // PID 直注入：无包名时把 agent 复制到公共可读目录，
    // 目标（root / shell 域）才能 dlopen 它。
    if (pkgName.empty()) {
        libPath = CopyAgentToPublicTmp(libPath);
    }
    
    // 延迟
    if (delay > 0) {
        LOGI("Waiting %u microseconds...", delay);
        usleep(delay);
    }
    
    // 创建注入器
    Injector injector(targetPid);
    
    if (!injector.init()) {
        LOGE("Failed to initialize injector: %s", injector.lastError().c_str());
        return 1;
    }
    
    // 配置
    InjectorConfig config;
    config.libPath = libPath;
    config.pkgName = pkgName;
    config.useMemfd = useMemfd;
    config.hideMaps = hideMaps;
    config.hideSolist = hideSolist;
    config.dlcloseHide = dlcloseHide;
    config.deepObfuscate = deepObfuscate;
    config.dlFlags = RTLD_NOW;
    config.copyToPrivate = copyToPrivate;
    
    // 执行注入
    LOGI("Starting injection...");
    auto result = injector.inject(config);
    
    if (result.success) {
        LOGI("=== Injection successful ===");
        LOGI("Handle: %p", (void*)result.handle);
        LOGI("Base: %p", (void*)result.base);
        return 0;
    } else {
        LOGE("=== Injection failed ===");
        LOGE("Error: %s", result.error.c_str());
        return 1;
    }
}

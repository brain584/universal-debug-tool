#include "Injector.h"
#include "Utils.h"
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <linux/memfd.h>
#include <cstring>
#include <libgen.h>
#include <fstream>
#include <elf.h>
#include <random>

// dlopen 标志
#ifndef RTLD_NOW
#define RTLD_NOW 2
#endif

// android_dlopen_ext 标志
#ifndef ANDROID_DLEXT_USE_LIBRARY_FD
#define ANDROID_DLEXT_USE_LIBRARY_FD 0x10
#endif

Injector::Injector(pid_t pid) : m_pid(pid) {}

Injector::~Injector() {
    cleanupAllocations();
}

bool Injector::init() {
    m_remote = std::make_unique<RemoteProcess>(m_pid);
    
    // 查找远程 dlopen 等函数
    m_remoteDlopen = m_remote->findRemoteSymbol("dlopen", 
        reinterpret_cast<uintptr_t>(&dlopen));
    if (!m_remoteDlopen) {
        m_lastError = "Cannot find remote dlopen";
        return false;
    }
    LOGI("Remote dlopen: %p", (void*)m_remoteDlopen);
    
    m_remoteDlerror = m_remote->findRemoteSymbol("dlerror",
        reinterpret_cast<uintptr_t>(&dlerror));
    LOGI("Remote dlerror: %p", (void*)m_remoteDlerror);
    
    m_remoteDlclose = m_remote->findRemoteSymbol("dlclose",
        reinterpret_cast<uintptr_t>(&dlclose));
    
    // android_dlopen_ext 可选
    void* dlopenExt = dlsym(RTLD_DEFAULT, "android_dlopen_ext");
    if (dlopenExt) {
        m_remoteDlopenExt = m_remote->findRemoteSymbol("android_dlopen_ext",
            reinterpret_cast<uintptr_t>(dlopenExt));
        LOGI("Remote android_dlopen_ext: %p", (void*)m_remoteDlopenExt);
    }
    
    return true;
}

void Injector::cleanupAllocations() {
    if (!m_remote || m_allocations.empty()) return;
    LOGI("cleanupAllocations");
    for (const auto& alloc : m_allocations) {
        m_remote->remoteFree(alloc.first, alloc.second);
    }
    m_allocations.clear();
}

InjectionResult Injector::inject(const InjectorConfig& config) {
    InjectionResult result;

    // 清理上一次运行遗留的过期 agent socket / 密钥文件。刚注入的
    // agent 无法自行删除它们（SELinux 禁止目标应用上下文
    // 在 /data/local/tmp 上执行 unlink），否则
    // bind() 会报 "Address already in use" 失败。我们以 root 运行，
    // 因此可以在这里删除。
    unlink("/data/local/tmp/universal_debug_tool.sock");
    unlink("/data/local/tmp/universal_debug_tool_key.bin");

    // 预先创建共享密钥（即使目标应用的 SELinux 上下文
    // 无法写入 /data/local/tmp，root 也可以写），
    // 无论 agent 自身创建文件是否成功，通道都能工作。
    {
        uint8_t key[44];
        int urand = open("/dev/urandom", O_RDONLY);
        if (urand >= 0) {
            ssize_t rd = read(urand, key, sizeof(key));
            close(urand);
            if (rd == (ssize_t)sizeof(key)) {
                int kf = open("/data/local/tmp/universal_debug_tool_key.bin",
                              O_WRONLY | O_CREAT | O_TRUNC, 0666);
                if (kf >= 0) {
                    (void)write(kf, key, sizeof(key));
                    close(kf);
                    chmod("/data/local/tmp/universal_debug_tool_key.bin", 0666);
                }
            }
        }
    }
    
    // 检查库文件
    if (!Utils::fileExists(config.libPath)) {
        result.error = "Library file not found: " + config.libPath;
        return result;
    }
    
    // 验证是 ARM64 ELF
    ElfParser libElf;
    if (!libElf.loadFromFile(config.libPath)) {
        result.error = "Invalid ELF file or not ARM64";
        return result;
    }
    
    // 使用 libc.so 只读段（offset=0）作为默认 caller
    // 函数返回后跳转到该地址会触发 SIGSEGV，用于捕获远程调用完成
    auto maps = Utils::parseMaps(m_pid);
    uintptr_t defaultCaller = 0;
    for (const auto& map : maps) {
        if (map.path.find("libc.so") != std::string::npos && map.offset == 0) {
            defaultCaller = map.start;
            LOGI("Default caller (libc.so): %p", (void*)defaultCaller);
            break;
        }
    }
    
    m_remote->setDefaultCaller(defaultCaller);
    
    // 附加到进程（PTRACE_ATTACH 会自动停止进程）
    if (!m_remote->attach()) {
        result.error = "Failed to attach to process";
        return result;
    }
    
    // 选择注入方式
    if (config.useMemfd && m_remoteDlopenExt) {
        result = injectWithMemfd(config.libPath, config.dlFlags);
        if (!result.success) {
            LOGW("Memfd injection failed, falling back to dlopen");
            result = injectWithDlopen(config.libPath, config.dlFlags);
        }
    } else {
        // 常规 dlopen 模式
        std::string targetLibPath = config.libPath;
        
        // 如果启用了复制到私有目录，先复制文件
        if (config.copyToPrivate && !config.pkgName.empty()) {
            std::string copiedPath = CopyLibToPrivateDirFixed(config.libPath, config.pkgName);
            if (!copiedPath.empty()) {
                targetLibPath = copiedPath;
                m_copiedLibPath = copiedPath;
                LOGI("Using copied library: %s", targetLibPath.c_str());
            } else {
                LOGW("Failed to copy library to private dir, using original path");
            }
        }
        
        result = injectWithDlopen(targetLibPath, config.dlFlags);

        // 在现代 Android 上，基于文件的 dlopen 可能报 "library not found" 失败，
        // 即使文件存在且可读：应用的 linker
        // namespace 不允许 dlopen() APK / 系统库之外的任意路径。
        // 回退到 memfd + android_dlopen_ext（仍然是
        // ptrace 注入），绕过路径检查。
        if (!result.success && m_remoteDlopenExt) {
            LOGW("dlopen injection failed (%s); retrying with memfd",
                 result.error.c_str());
            result = injectWithMemfd(config.libPath, config.dlFlags);
        }
        
        // 无论成功与否，删除复制的文件
        // 保留复制到磁盘的库文件，使其在
        // /proc/<pid>/maps 中可见（GG 等内存工具可找到）。
    }
    
    if (result.success) {
        // 获取加载后的 ELF 信息
        ElfParser injectedElf;
        if (injectedElf.loadFromMemory(m_pid, result.base)) {

            if (config.dlcloseHide) {
                // dlclose 隐藏流程:
                // 1. 先调用入口点（dlclose 后 handle 失效）
                // 2. patch soinfo 使 dlclose 跳过 munmap/析构
                // 3. dlclose 让 linker 自动清理 solist/soinfo
                // 4. maps 隐藏 + ELF 混淆照常执行
                callEntryPoint(result.handle, injectedElf);
                hideViaDlclose(result.handle, injectedElf);

                if (config.hideMaps) {
                    hideFromMaps(injectedElf);
                }
                if (!obfuscateElfHeader(injectedElf)) {
                    LOGW("ELF header obfuscation failed or skipped");
                }
                if (config.deepObfuscate) {
                    if (!obfuscateElfDeep(injectedElf)) {
                        LOGW("Deep ELF obfuscation failed or skipped");
                    } else {
                        LOGI("Deep ELF obfuscation applied");
                    }
                }
            } else {
                // 原始流程: solist 隐藏 → maps 隐藏 → 入口点 → 混淆
                if (config.hideSolist) {
                    hideFromSolist(injectedElf);
                }

                if (config.hideMaps) {
                    hideFromMaps(injectedElf);
                }

                callEntryPoint(result.handle, injectedElf);

                if (!obfuscateElfHeader(injectedElf)) {
                    LOGW("ELF header obfuscation failed or skipped");
                }
                if (config.deepObfuscate) {
                    if (!obfuscateElfDeep(injectedElf)) {
                        LOGW("Deep ELF obfuscation failed or skipped");
                    } else {
                        LOGI("Deep ELF obfuscation applied");
                    }
                }
            }
        } else {
            LOGW("Failed to parse injected library, skipping entry point call");
        }
    } else {
        // 获取错误信息
        std::string err = getDlerror();
        if (!err.empty()) {
            result.error = err;
        }
    }
    
    // 清理
    cleanupAllocations();
    m_remote->detach();
    
    // 恢复进程执行
    kill(m_pid, SIGCONT);
    
    return result;
}

InjectionResult Injector::injectWithDlopen(const std::string& libPath, int flags) {
    InjectionResult result;
    
    LOGI("Injecting with dlopen: %s", libPath.c_str());
    
    // 在远程进程分配路径字符串
    uintptr_t remotePathAddr = m_remote->remoteAllocString(libPath);
    if (!remotePathAddr) {
        result.error = "Failed to allocate remote memory for path";
        return result;
    }
    m_allocations.push_back({remotePathAddr, libPath.size() + 1});
    
    // 调用 dlopen(path, flags)
    uintptr_t handle = m_remote->callFunctionFrom(0, m_remoteDlopen, 2, 
        remotePathAddr, (uintptr_t)flags);
    
    if (!handle || handle == static_cast<uintptr_t>(-1)) {
        result.error = "dlopen returned NULL";
        return result;
    }
    
    result.handle = handle;
    result.success = true;
    
    // 查找加载的库基址
    auto map = Utils::findMapByName(m_pid, libPath);
    if (map.start) {
        result.base = map.start;
    }
    
    LOGI("Library loaded at %p, handle: %p", (void*)result.base, (void*)result.handle);

    // 校验上报基址处的 ELF 魔数，使内存工具可以信赖
    // 该地址。
    if (result.base != 0) {
        unsigned char magic[4] = {0};
        if (m_remote->readMemory(result.base, magic, sizeof(magic)) == (ssize_t)sizeof(magic)) {
            if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
                LOGI("ELF magic verified at base %p", (void*)result.base);
            } else {
                LOGW("ELF magic NOT found at base %p: %02x %02x %02x %02x",
                     (void*)result.base, magic[0], magic[1], magic[2], magic[3]);
            }
        }
    }
    return result;
}

// 修正后的复制到私有目录实现：目录缺失时创建目标的
// files 目录（注入器以 root 运行）。
// 从目标的 maps 推导其 native lib 目录（/data/app/.../lib/arm64），
// 使注入的库位于应用的 linker namespace 内——dlopen
// 可以工作，内存工具也会把它显示为普通应用库。
std::string Injector::FindAppLibDir() {
    auto maps = Utils::parseMaps(m_pid);
    std::string baseApk;
    for (const auto& m : maps) {
        if (m.path.find("/data/app/") == 0 &&
            m.path.find(".apk") != std::string::npos) {
            baseApk = m.path;
            break;
        }
    }
    if (baseApk.empty()) return "";
    size_t slash = baseApk.rfind('/');
    if (slash == std::string::npos) return "";
    std::string appDir = baseApk.substr(0, slash);
    return appDir + "/lib/arm64";
}

std::string Injector::CopyLibToPrivateDirFixed(const std::string& libPath, const std::string& pkgName) {
    auto ensureDir = [](const std::string& d) -> bool {
        struct stat s;
        if (stat(d.c_str(), &s) == 0 && S_ISDIR(s.st_mode)) return true;
        return mkdir(d.c_str(), 0755) == 0;
    };

    // 优先：应用自己的 native lib 目录（在其 linker namespace 内）。
    std::string privateDir = FindAppLibDir();
    std::string parentDir;
    bool inLibDir = !privateDir.empty();

    if (inLibDir) {
        if (!ensureDir(privateDir)) {
            LOGE("Cannot create lib dir: %s", privateDir.c_str());
            return "";
        }
    } else {
        // 备选：/data/user/0/<pkg>/files（namespace 可能仍会拒绝，
        // 但 inject() 中的 memfd 回退可以兜底）。
        parentDir = Utils::format("/data/user/0/%s", pkgName.c_str());
        privateDir = Utils::format("%s/files", parentDir.c_str());
        if (!ensureDir(parentDir)) {
            parentDir = Utils::format("/data/data/%s", pkgName.c_str());
            privateDir = Utils::format("%s/files", parentDir.c_str());
        }
        if (!ensureDir(parentDir) || !ensureDir(privateDir)) {
            LOGE("Cannot create private directory for package: %s", pkgName.c_str());
            return "";
        }
    }

    // data 目录回退会创建 root 所有的 0700 目录；把它们交给
    // 目标 uid 以便其遍历。lib 目录是全局可读的（0755）。
    if (!inLibDir) {
        uid_t targetUid = 0;
        {
            std::string statusPath = Utils::format("/proc/%d/status", m_pid);
            std::ifstream statusFile(statusPath);
            if (statusFile) {
                std::string line;
                while (std::getline(statusFile, line)) {
                    if (line.find("Uid:") == 0) {
                        unsigned int u = 0;
                        if (sscanf(line.c_str(), "Uid:\t%u", &u) == 1) targetUid = (uid_t)u;
                        break;
                    }
                }
            }
        }
        if (targetUid != 0) {
            if (chown(parentDir.c_str(), targetUid, targetUid) != 0) {
                LOGW("chown %s failed: %s", parentDir.c_str(), strerror(errno));
            }
            if (chown(privateDir.c_str(), targetUid, targetUid) != 0) {
                LOGW("chown %s failed: %s", privateDir.c_str(), strerror(errno));
            }
        }
    }

    // lib 目录使用固定易识别的名称；data 目录使用随机后缀。
    std::string libName;
    size_t lastSlash = libPath.rfind('/');
    libName = (lastSlash != std::string::npos) ? libPath.substr(lastSlash + 1) : libPath;

    std::string targetPath;
    if (inLibDir) {
        targetPath = privateDir + "/" + libName;
    } else {
        targetPath = Utils::format("%s/.%s_%s", privateDir.c_str(),
                                   Utils::randomString(6).c_str(), libName.c_str());
    }

    LOGI("Copying library to private directory:");
    LOGI("  Source: %s", libPath.c_str());
    LOGI("  Target: %s", targetPath.c_str());

    auto libData = Utils::readFile(libPath);
    if (libData.empty()) {
        LOGE("Failed to read source library: %s", libPath.c_str());
        return "";
    }

    if (!Utils::writeFile(targetPath, libData.data(), libData.size())) {
        LOGE("Failed to write library to: %s", targetPath.c_str());
        return "";
    }

    if (chmod(targetPath.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
        LOGW("Failed to set permissions on: %s (errno=%d)", targetPath.c_str(), errno);
    }

    // chown 给目标 uid，使目标进程能读取文件。
    std::string statusPath = Utils::format("/proc/%d/status", m_pid);
    std::ifstream statusFile(statusPath);
    if (statusFile) {
        std::string line;
        while (std::getline(statusFile, line)) {
            if (line.find("Uid:") == 0) {
                uid_t uid;
                if (sscanf(line.c_str(), "Uid:\t%u", &uid) == 1) {
                    if (chown(targetPath.c_str(), uid, uid) != 0) {
                        LOGW("Failed to chown to uid %u: %s", uid, strerror(errno));
                    } else {
                        LOGI("Changed owner to uid: %u", uid);
                    }
                }
                break;
            }
        }
    }

    // 在文件存在后再修正 SELinux 标签（目录 + 文件）。
    std::string rc = "restorecon -R " + privateDir + " 2>/dev/null";
    if (system(rc.c_str()) != 0) {
        LOGW("restorecon failed: %s", privateDir.c_str());
    }

    LOGI("Library copied successfully to: %s", targetPath.c_str());
    return targetPath;
}

std::string Injector::copyLibToPrivateDir(const std::string& libPath, const std::string& pkgName) {
    // 构建目标私有目录路径: /data/user/0/<pkg>/files/
    // 注意: /data/data/<pkg> 是 /data/user/0/<pkg> 的符号链接
    std::string privateDir = Utils::format("/data/user/0/%s/files", pkgName.c_str());
    
    // 检查目录是否存在，如果不存在尝试创建
    struct stat st;
    if (stat(privateDir.c_str(), &st) != 0) {
        LOGW("Private directory does not exist: %s", privateDir.c_str());
        // 尝试使用 /data/data/<pkg>/files 作为备选
        privateDir = Utils::format("/data/data/%s/files", pkgName.c_str());
        if (stat(privateDir.c_str(), &st) != 0) {
            LOGE("Cannot access private directory for package: %s", pkgName.c_str());
            return "";
        }
    }
    
    // 提取库文件名
    std::string libName;
    size_t lastSlash = libPath.rfind('/');
    if (lastSlash != std::string::npos) {
        libName = libPath.substr(lastSlash + 1);
    } else {
        libName = libPath;
    }
    
    // 为避免冲突，添加随机后缀
    std::string randomSuffix = Utils::randomString(6);
    std::string targetPath = Utils::format("%s/.%s_%s", 
        privateDir.c_str(), randomSuffix.c_str(), libName.c_str());
    
    LOGI("Copying library to private directory:");
    LOGI("  Source: %s", libPath.c_str());
    LOGI("  Target: %s", targetPath.c_str());
    
    // 读取源文件
    auto libData = Utils::readFile(libPath);
    if (libData.empty()) {
        LOGE("Failed to read source library: %s", libPath.c_str());
        return "";
    }
    
    // 写入目标文件
    if (!Utils::writeFile(targetPath, libData.data(), libData.size())) {
        LOGE("Failed to write library to: %s", targetPath.c_str());
        return "";
    }
    
    // 设置文件权限为可读可执行 (0755)
    if (chmod(targetPath.c_str(), S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
        LOGW("Failed to set permissions on: %s (errno=%d)", targetPath.c_str(), errno);
        // 继续尝试，可能仍然可以工作
    }
    
    // 获取目标进程的 UID 并尝试修改文件所有者
    // 这样目标进程就有权限访问该文件
    std::string statusPath = Utils::format("/proc/%d/status", m_pid);
    std::ifstream statusFile(statusPath);
    if (statusFile) {
        std::string line;
        while (std::getline(statusFile, line)) {
            if (line.find("Uid:") == 0) {
                uid_t uid;
                if (sscanf(line.c_str(), "Uid:\t%u", &uid) == 1) {
                    if (chown(targetPath.c_str(), uid, uid) != 0) {
                        LOGW("Failed to chown to uid %u: %s", uid, strerror(errno));
                    } else {
                        LOGI("Changed owner to uid: %u", uid);
                    }
                }
                break;
            }
        }
    }
    
    LOGI("Library copied successfully to: %s", targetPath.c_str());
    return targetPath;
}

InjectionResult Injector::injectWithMemfd(const std::string& libPath, int flags) {
    InjectionResult result;
    
    LOGI("Injecting with memfd: %s", libPath.c_str());
    
    // 生成随机名称
    std::string memfdName = Utils::randomString(8);
    
    // 创建远程 memfd
    int remoteFd = m_remote->remoteMemfdCreate(memfdName, MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (remoteFd < 0) {
        result.error = "memfd_create failed";
        return result;
    }
    
    LOGI("Remote memfd created: %d", remoteFd);
    
    // 通过 /proc/[pid]/fd/[fd] 写入库内容
    std::string fdPath = Utils::format("/proc/%d/fd/%d", m_pid, remoteFd);
    
    // 读取库文件
    auto libData = Utils::readFile(libPath);
    if (libData.empty()) {
        result.error = "Failed to read library file";
        return result;
    }
    
    // 写入到远程 memfd
    int fd = open(fdPath.c_str(), O_RDWR);
    if (fd < 0) {
        result.error = "Failed to open remote memfd";
        return result;
    }
    
    ssize_t written = write(fd, libData.data(), libData.size());
    close(fd);
    
    if (written != static_cast<ssize_t>(libData.size())) {
        result.error = "Failed to write to memfd";
        return result;
    }
    
    // 封印 memfd
    m_remote->syscall(Syscall::FCNTL, remoteFd, F_ADD_SEALS,
                      F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL);
    
    // 构造 android_dlextinfo
    struct android_dlextinfo {
        uint64_t flags;
        void* reserved_addr;
        size_t reserved_size;
        int relro_fd;
        int library_fd;
        off64_t library_fd_offset;
        void* library_namespace;
    };
    
    android_dlextinfo extinfo{};
    extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD;  // ANDROID_DLEXT_USE_LIBRARY_FD
    extinfo.library_fd = remoteFd;
    
    // 分配远程内存存储 extinfo
    uintptr_t remoteExtinfo = m_remote->remoteAlloc(sizeof(extinfo), PROT_READ | PROT_WRITE);
    if (!remoteExtinfo) {
        result.error = "Failed to allocate memory for dlextinfo";
        return result;
    }
    m_allocations.push_back({remoteExtinfo, sizeof(extinfo)});
    
    m_remote->writeMemory(remoteExtinfo, &extinfo, sizeof(extinfo));
    
    // 分配名称字符串
    uintptr_t remoteNameAddr = m_remote->remoteAllocString(memfdName);
    if (!remoteNameAddr) {
        result.error = "Failed to allocate memory for name";
        return result;
    }
    m_allocations.push_back({remoteNameAddr, memfdName.size() + 1});
    
    // 调用 android_dlopen_ext(name, flags, extinfo)
    uintptr_t handle = m_remote->callFunctionFrom(0, m_remoteDlopenExt, 3,
        remoteNameAddr, 
        (uintptr_t)flags, 
        remoteExtinfo
    );
    
    if (!handle || handle == static_cast<uintptr_t>(-1)) {
        result.error = "android_dlopen_ext returned NULL";
        return result;
    }
    
    result.handle = handle;
    result.success = true;
    
    // 查找加载的库基址
    std::string memfdPath = "/memfd:" + memfdName;
    auto map = Utils::findMapByName(m_pid, memfdPath);
    if (map.start) {
        result.base = map.start;
    }
    
    LOGI("Library loaded via memfd at %p, handle: %p", (void*)result.base, (void*)result.handle);
    return result;
}

std::string Injector::getDlerror() {
    if (!m_remoteDlerror) return "";
    
    uintptr_t errPtr = m_remote->callFunctionFrom(0, m_remoteDlerror, 0);
    
    if (errPtr && errPtr != static_cast<uintptr_t>(-1)) {
        return m_remote->readString(errPtr);
    }
    return "";
}

uintptr_t Injector::getJavaVM() {
    // 查找 libart.so - 需要找到包含 ELF header 的段
    auto maps = Utils::parseMaps(m_pid);
    MapEntry artMap{};
    
    // 遍历所有 libart.so 的映射，找到包含有效 ELF header 的
    for (const auto& map : maps) {
        if (map.path.find("libart.so") == std::string::npos) continue;
        if (!map.isReadable()) continue;
        
        // 检查是否包含 ELF 魔数
        char magic[4] = {0};
        if (m_remote->readMemory(map.start, magic, sizeof(magic)) == sizeof(magic)) {
            if (memcmp(magic, "\x7f" "ELF", 4) == 0) {
                artMap = map;
                break;
            }
        }
    }
    
    if (artMap.start == 0) {
        LOGE("Cannot find libart.so with valid ELF header");
        return 0;
    }
    
    LOGI("Found libart.so at %p (path: %s)", (void*)artMap.start, artMap.path.c_str());
    
    // 解析 libart
    ElfParser artElf;
    if (!artElf.loadFromMemory(m_pid, artMap.start)) {
        LOGE("Failed to parse libart.so at %p", (void*)artMap.start);
        return 0;
    }
    
    LOGI("Parsed libart.so: base=%p, dynstr=%p, dynsym=%p", 
         (void*)artElf.base(), (void*)artElf.stringTable(), (void*)artElf.symbolTable());
    
    // 查找 JNI_GetCreatedJavaVMs
    uintptr_t getJavaVMs = artElf.findSymbol("JNI_GetCreatedJavaVMs");
    if (!getJavaVMs) {
        LOGE("Cannot find JNI_GetCreatedJavaVMs");
        return 0;
    }
    
    LOGI("JNI_GetCreatedJavaVMs: %p", (void*)getJavaVMs);
    
    // 分配缓冲区: JavaVM* + jsize
    size_t bufSize = sizeof(uintptr_t) + sizeof(int);
    uintptr_t remoteBuf = m_remote->remoteAlloc(bufSize, PROT_READ | PROT_WRITE);
    if (!remoteBuf) {
        return 0;
    }
    m_allocations.push_back({remoteBuf, bufSize});
    
    // 调用 JNI_GetCreatedJavaVMs(vmBuf, 1, &nVMs)
    uintptr_t status = m_remote->callFunctionFrom(0, getJavaVMs, 3,
        remoteBuf,                          // vmBuf
        (uintptr_t)1,                       // bufLen
        remoteBuf + sizeof(uintptr_t)       // nVMs
    );
    
    if (status != 0) {
        LOGE("JNI_GetCreatedJavaVMs failed: %lu", status);
        return 0;
    }
    
    // 读取结果
    uintptr_t jvm = 0;
    m_remote->readMemory(remoteBuf, &jvm, sizeof(jvm));
    
    LOGI("JavaVM: %p", (void*)jvm);
    return jvm;
}

bool Injector::callEntryPoint(uintptr_t handle, const ElfParser& elf) {
    // 先检查注入的库是否包含 JNI_OnLoad，若没有则跳过创建 JavaVM（节省开销）
    uintptr_t jniOnLoad = elf.findSymbol("JNI_OnLoad");
    if (!jniOnLoad) {
        LOGI("JNI_OnLoad not found in library, skipping entry point call");
        return true;
    }

    // 只有在确实存在 JNI_OnLoad 时才获取 JavaVM
    (void)handle;
    uintptr_t jvm = getJavaVM();
    if (!jvm) {
        LOGW("Cannot get JavaVM, skipping JNI_OnLoad");
        return false;
    }

    LOGI("Calling JNI_OnLoad at %p", (void*)jniOnLoad);

    // 调用 JNI_OnLoad(JavaVM*, secretKey)
    // secretKey = 1337 用于被注入库识别
    // 使用默认 caller（会触发 SIGSEGV）
    constexpr uintptr_t SECRET_KEY = 1337;

    uintptr_t ret = m_remote->callFunctionFrom(0, jniOnLoad, 2, jvm, SECRET_KEY);
    LOGI("JNI_OnLoad returned: 0x%lx", ret);

    return true;
}

bool Injector::hideFromMaps(const ElfParser& elf) {
    LOGI("Hiding library from maps...");

    // 冻结所有线程，防止注入库启动的线程在映射替换期间执行代码页导致崩溃
    m_remote->freezeAllThreads();

    auto maps = Utils::parseMaps(m_pid);
    bool success = true;

    for (const auto& map : maps) {
        // 查找属于注入库的映射
        if (map.start < elf.base() || map.start >= elf.base() + elf.loadSize()) {
            continue;
        }

        if (map.path.empty()) continue;

        LOGI("Hiding segment: %lx-%lx", map.start, map.end);

        // 备份内容
        size_t size = map.size();
        std::vector<uint8_t> backup(size);
        if (m_remote->readMemory(map.start, backup.data(), size) != static_cast<ssize_t>(size)) {
            LOGE("Failed to backup segment");
            continue;
        }

        // 直接用 MAP_FIXED 覆盖为匿名映射（原子替换，不需要先 munmap）
        int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
        uintptr_t newAddr = m_remote->syscall(Syscall::MMAP, map.start, size,
                                              (uintptr_t)map.prot, (uintptr_t)flags, 0, 0);

        if (newAddr != map.start) {
            LOGE("Failed to remap segment at original address: got %p", (void*)newAddr);
            success = false;
            break;
        }

        // 恢复内容
        m_remote->writeMemory(map.start, backup.data(), size);
    }

    // 解冻所有线程
    m_remote->thawAllThreads();

    return success;
}

bool Injector::hideFromSolist(const ElfParser& elf) {
    LOGI("Hiding library from solist...");

    if (!m_solistHider) {
        m_solistHider = std::make_unique<SolistHider>(m_remote.get());
        if (!m_solistHider->init()) {
            LOGW("Failed to initialize SolistHider");
            return false;
        }
    }

    return m_solistHider->removeFromSolist(elf);
}

bool Injector::hideViaDlclose(uintptr_t handle, const ElfParser& elf) {
    LOGI("Hiding library via dlclose (patch soinfo + dlclose)...");

    if (!m_remoteDlclose) {
        LOGE("Remote dlclose not available");
        return false;
    }

    // 初始化 SolistHider 以定位 soinfo
    if (!m_solistHider) {
        m_solistHider = std::make_unique<SolistHider>(m_remote.get());
        if (!m_solistHider->init()) {
            LOGE("Failed to initialize SolistHider for dlclose hide");
            return false;
        }
    }

    // 修补 soinfo：size=0、gap_size_=0、fini_array_count_=0
    if (!m_solistHider->patchForDlclose(elf)) {
        LOGE("Failed to patch soinfo for dlclose hide");
        return false;
    }

    // 远程调用 dlclose(handle)
    // linker 会: 跳过 munmap (size==0) → 摘除 solist → 释放 soinfo
    LOGI("Calling remote dlclose(%p)...", (void*)handle);
    uintptr_t ret = m_remote->callFunctionFrom(0, m_remoteDlclose, 1, handle);
    LOGI("dlclose returned: %ld", (long)ret);

    if (ret != 0) {
        LOGW("dlclose returned non-zero: %ld", (long)ret);
    }

    return true;
}

// 将注入库的 ELF 头进行改写，主要是修改 e_ident 的魔数与部分字段，目的是降低通过简单内存搜索检测到注入库的概率
bool Injector::obfuscateElfHeader(const ElfParser& elf) {
    if (!m_remote) return false;

    Elf_Ehdr hdr;
    // 读取远程 ELF header
    if (m_remote->readMemory(elf.base(), &hdr, sizeof(hdr)) != static_cast<ssize_t>(sizeof(hdr))) {
        LOGW("Failed to read ELF header at %p for obfuscation", (void*)elf.base());
        return false;
    }

    LOGI("Original ELF ident bytes at %p: %02x %02x %02x %02x ...",
         (void*)elf.base(),
         static_cast<unsigned>(hdr.e_ident[EI_MAG0]),
         static_cast<unsigned>(hdr.e_ident[EI_MAG1]),
         static_cast<unsigned>(hdr.e_ident[EI_MAG2]),
         static_cast<unsigned>(hdr.e_ident[EI_MAG3]));

    // 随机化 e_ident 的所有字节（包括魔数）以避免被基于静态魔数的扫描发现
    // 注意：此操作在 JNI_OnLoad 调用之后执行（已加载），会使 ELF header 失去可识别性
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(125, 200);

    for (int i = 0; i < EI_NIDENT; ++i) {
        hdr.e_ident[i] = static_cast<unsigned char>(dist(gen));
    }

    // 写回远程内存
    if (m_remote->writeMemory(elf.base(), &hdr, sizeof(hdr)) != static_cast<ssize_t>(sizeof(hdr))) {
        LOGW("Failed to write obfuscated ELF header to %p", (void*)elf.base());
        return false;
    }

    LOGI("Obfuscated ELF header at %p", (void*)elf.base());
    return true;
}

// 深度混淆实现：清除 dynamic 段指向的字符串表/符号表/哈希表，并篡改 phdr 表（破坏性）
bool Injector::obfuscateElfDeep(const ElfParser& elf) {
    if (!m_remote) return false;

    // 读取 ELF header
    Elf_Ehdr hdr;
    if (m_remote->readMemory(elf.base(), &hdr, sizeof(hdr)) != static_cast<ssize_t>(sizeof(hdr))) {
        LOGW("Failed to read ELF header for deep obfuscation at %p", (void*)elf.base());
        return false;
    }

    // 读取 program headers
    size_t phdrsSize = static_cast<size_t>(hdr.e_phnum) * sizeof(Elf_Phdr);
    std::vector<Elf_Phdr> phdrs;
    phdrs.resize(hdr.e_phnum);
    if (phdrsSize > 0) {
        if (m_remote->readMemory(elf.base() + hdr.e_phoff, phdrs.data(), phdrsSize) != static_cast<ssize_t>(phdrsSize)) {
            LOGW("Failed to read program headers for deep obfuscation");
            // 继续尝试 dynamic parsing even if phdrs read failed
        }
    }

    // 查找 PT_DYNAMIC 段以读取 dynamic 表
    uintptr_t dynAddr = 0;
    for (const auto& ph : phdrs) {
        if (ph.p_type == PT_DYNAMIC) {
            dynAddr = elf.base() + ph.p_vaddr;
            break;
        }
    }

    if (!dynAddr) {
        // 回退：使用 ElfParser 中记录的 dynamic（如果有）
        dynAddr = elf.dynamic();
    }

    if (!dynAddr) {
        LOGW("No dynamic segment found for deep obfuscation");
        return false;
    }

    // 读取 dynamic entries
    std::vector<Elf64_Dyn> dyns;
    uintptr_t cur = dynAddr;
    while (true) {
        Elf64_Dyn d;
        if (m_remote->readMemory(cur, &d, sizeof(d)) != static_cast<ssize_t>(sizeof(d))) {
            LOGW("Failed to read dynamic entry at %p", (void*)cur);
            break;
        }
        dyns.push_back(d);
        if (d.d_tag == DT_NULL) break;
        cur += sizeof(d);
        // 安全上限
        if (dyns.size() > 1024) break;
    }

    // 收集需要清除的地址和 strsz
    uintptr_t strtab = 0, symtab = 0, gnu_hash = 0, sysv_hash = 0;
    size_t strsz = 0;
    for (const auto& d : dyns) {
        switch (d.d_tag) {
            case DT_STRTAB: strtab = d.d_un.d_ptr; break;
            case DT_SYMTAB: symtab = d.d_un.d_ptr; break;
            case DT_GNU_HASH: gnu_hash = d.d_un.d_ptr; break;
            case DT_HASH: sysv_hash = d.d_un.d_ptr; break;
            case DT_STRSZ: strsz = static_cast<size_t>(d.d_un.d_val); break;
        }
    }

    // 修复地址（如果是相对地址）
    auto fixAddr = [&](uintptr_t& a) {
        if (!a) return;
        if (a < elf.base()) a += elf.base();
    };
    fixAddr(strtab);
    fixAddr(symtab);
    fixAddr(gnu_hash);
    fixAddr(sysv_hash);

    // 辅助：查找包含 addr 的段以确定大小
    auto findSegSize = [&](uintptr_t addr) -> size_t {
        for (const auto& seg : elf.segments()) {
            if (addr >= seg.start && addr < seg.end) {
                return seg.end - addr;
            }
        }
        return 0;
    };

    // 限制单次清零最大大小，避免巨大写入（1MB）
    const size_t MAX_WIPE = 1024 * 1024;

    // 清零字符串表
    if (strtab) {
        size_t wipeSize = strsz ? strsz : findSegSize(strtab);
        if (wipeSize == 0) wipeSize = 4096;
        if (wipeSize > MAX_WIPE) wipeSize = MAX_WIPE;
        std::vector<uint8_t> zeros(wipeSize, 0);
        if (m_remote->writeMemory(strtab, zeros.data(), wipeSize) != static_cast<ssize_t>(wipeSize)) {
            LOGW("Failed to wipe strtab at %p (size=%zu)", (void*)strtab, wipeSize);
        } else {
            LOGI("Wiped strtab at %p (size=%zu)", (void*)strtab, wipeSize);
        }
    }

    // 清零符号表
    if (symtab) {
        size_t wipeSize = findSegSize(symtab);
        if (wipeSize == 0) wipeSize = 4096;
        if (wipeSize > MAX_WIPE) wipeSize = MAX_WIPE;
        std::vector<uint8_t> zeros(wipeSize, 0);
        if (m_remote->writeMemory(symtab, zeros.data(), wipeSize) != static_cast<ssize_t>(wipeSize)) {
            LOGW("Failed to wipe symtab at %p (size=%zu)", (void*)symtab, wipeSize);
        } else {
            LOGI("Wiped symtab at %p (size=%zu)", (void*)symtab, wipeSize);
        }
    }

    // 清零 GNU hash / SYSV hash
    if (gnu_hash) {
        size_t wipeSize = findSegSize(gnu_hash);
        if (wipeSize == 0) wipeSize = 4096;
        if (wipeSize > MAX_WIPE) wipeSize = MAX_WIPE;
        std::vector<uint8_t> zeros(wipeSize, 0);
        if (m_remote->writeMemory(gnu_hash, zeros.data(), wipeSize) != static_cast<ssize_t>(wipeSize)) {
            LOGW("Failed to wipe gnu_hash at %p", (void*)gnu_hash);
        } else {
            LOGI("Wiped gnu_hash at %p", (void*)gnu_hash);
        }
    }

    if (sysv_hash) {
        size_t wipeSize = findSegSize(sysv_hash);
        if (wipeSize == 0) wipeSize = 4096;
        if (wipeSize > MAX_WIPE) wipeSize = MAX_WIPE;
        std::vector<uint8_t> zeros(wipeSize, 0);
        if (m_remote->writeMemory(sysv_hash, zeros.data(), wipeSize) != static_cast<ssize_t>(wipeSize)) {
            LOGW("Failed to wipe sysv_hash at %p", (void*)sysv_hash);
        } else {
            LOGI("Wiped sysv_hash at %p", (void*)sysv_hash);
        }
    }

    // 将 dynamic 表中的关键指针清零（DT_STRTAB/DT_SYMTAB/DT_GNU_HASH/DT_HASH）
    uintptr_t dynWriteAddr = dynAddr;
    for (size_t i = 0; i < dyns.size(); ++i) {
        Elf64_Dyn d = dyns[i];
        bool modified = false;
        if (d.d_tag == DT_STRTAB || d.d_tag == DT_SYMTAB || d.d_tag == DT_GNU_HASH || d.d_tag == DT_HASH) {
            d.d_un.d_ptr = 0;
            modified = true;
        }
        if (modified) {
            if (m_remote->writeMemory(dynWriteAddr + i * sizeof(Elf64_Dyn), &d, sizeof(d)) != static_cast<ssize_t>(sizeof(d))) {
                LOGW("Failed to write modified dynamic entry at %p", (void*)(dynWriteAddr + i * sizeof(Elf64_Dyn)));
            } else {
                LOGI("Cleared dynamic pointer for tag %lld at %p", (long long)d.d_tag, (void*)(dynWriteAddr + i * sizeof(Elf64_Dyn)));
            }

        }
    }

    // 篡改 program headers：将 p_type 置为 PT_NULL（破坏性）
    if (phdrsSize > 0) {
        for (size_t i = 0; i < phdrs.size(); ++i) {
            phdrs[i].p_type = PT_NULL;
        }
        if (m_remote->writeMemory(elf.base() + hdr.e_phoff, phdrs.data(), phdrsSize) != static_cast<ssize_t>(phdrsSize)) {
            LOGW("Failed to write modified phdrs");
        } else {
            LOGI("Modified phdrs to PT_NULL for deep obfuscation");
        }
    }

    return true;
}

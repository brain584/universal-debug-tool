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

namespace {

// ─────────────────────────────────────────────────────────────────────────────
// P0-3：dlopen 成功后的 JNI_OnLoad 可靠性兜底
//
// 旧实现只在 `injectedElf.loadFromMemory()` 成功时才调用 callEntryPoint()。
// loadFromMemory 依赖「能按名字定位到映射 + ELF/dynamic 段可读」：memfd 分支
// 用 `/memfd:<随机名>` 定位、常规 dlopen 用复制后的路径定位，任一定位失败
// （result.base == 0）都会让 JNI_OnLoad 被**静默跳过** → agent 的
// LuaEngine::SetJavaVM 永不执行 → artHook 拿不到 JavaVM。
//
// 这里补一层不依赖 ELF 解析的兜底：直接用 dlopen 返回的 handle 远程调用
// dlsym(handle, name)。g_remoteDlsym 在 init() 里解析一次（与 dlopen/dlclose
// 同法），失败则惰性重试。
uintptr_t g_remoteDlsym = 0;

// 最近一次 dlopen/android_dlopen_ext 成功返回的 handle（0 = 无）。
// 仅用于「ELF 符号表解析失败」时给 AgentStartWithAuth 做 dlsym 兜底，
// 注入器是单次进程，不存在并发覆盖。
uintptr_t g_lastInjectedHandle = 0;

uintptr_t RemoteDlsym(RemoteProcess* remote, uintptr_t handle, const char* name) {
    if (!remote || !handle || !name || !*name) return 0;
    if (!g_remoteDlsym) {
        g_remoteDlsym = remote->findRemoteSymbol(
            "dlsym", reinterpret_cast<uintptr_t>(&dlsym));
        if (g_remoteDlsym) {
            LOGI("Remote dlsym: %p", (void*)g_remoteDlsym);
        } else {
            LOGE("Cannot resolve remote dlsym（符号兜底不可用，只能走 ELF 符号表）");
        }
    }
    if (!g_remoteDlsym) return 0;

    uintptr_t nameAddr = remote->remoteAllocString(name);
    if (!nameAddr) {
        LOGE("dlsym(\"%s\"): remoteAllocString failed", name);
        return 0;
    }
    uintptr_t sym = remote->callFunctionFrom(0, g_remoteDlsym, 2, handle, nameAddr);
    remote->remoteFree(nameAddr, strlen(name) + 1);
    if (!sym || sym == static_cast<uintptr_t>(-1)) return 0;
    return sym;
}

} // 匿名命名空间

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

    // P0-3：dlsym 用于 JNI_OnLoad / AgentStartWithAuth 的兜底符号解析。
    // 解析失败不影响注入主流程，只影响「内存 ELF 解析失败」时的兜底能力。
    g_remoteDlsym = m_remote->findRemoteSymbol("dlsym",
        reinterpret_cast<uintptr_t>(&dlsym));
    LOGI("Remote dlsym: %p", (void*)g_remoteDlsym);
    
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

    // 清理上一次运行遗留的过期 agent socket；顺带删除旧版本遗留的
    // /data/local/tmp 公共密钥文件（旧实现 0666 落盘，属于安全风险）。
    // 注意：现在**不再创建**任何公共路径的密钥文件；认证材料由调用方
    // （GUI，App 私有目录）生成，见 startAgentWithAuth()。
    unlink("/data/local/tmp/universal_debug_tool.sock");
    unlink("/data/local/tmp/universal_debug_tool_key.bin");
    
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
        // ── P0-3：dlopen 成功后「必定尝试」调用 JNI_OnLoad ────────────────
        // 旧实现整段逻辑都嵌在 `if (injectedElf.loadFromMemory(...))` 里：
        // base 定位失败（memfd 映射名对不上 / 复制路径与 maps 不一致）时，
        // 入口点与 AgentStartWithAuth 都被静默跳过，表现为「注入成功但
        // artHook 拿不到 JavaVM / agent 连不上」。现在：
        //   1) 先用多种方式补定位 base（这里 + injectWithMemfd/Dlopen 内）；
        //   2) 无论内存 ELF 是否解析成功，都调用 callEntryPoint()；
        //      它会在 ELF 符号表失败时用 dlsym(handle) 兜底；
        //   3) 隐藏/混淆仍只在 ELF 解析成功时执行（与旧行为一致，避免拿
        //      残缺的段信息去 patch soinfo/maps）。
        uintptr_t base = result.base;
        if (base == 0) {
            // 按原文件基名再定位一次（findMapByName 支持 basename 匹配）。
            MapEntry byName = Utils::findMapByName(m_pid, config.libPath);
            if (byName.start) {
                base = byName.start;
                result.base = base;
                LOGW("注入返回的 base 为空，按文件基名重新定位到 %p", (void*)base);
            }
        }
        if (base == 0) {
            LOGE("注入成功但拿不到加载基址（base=0）：内存 ELF 解析不可用，"
                 "JNI_OnLoad 将只走 dlsym(handle) 兜底");
        }

        ElfParser injectedElf;
        bool elfOk = (base != 0) && injectedElf.loadFromMemory(m_pid, base);
        if (!elfOk) {
            LOGE("解析注入库的内存 ELF 失败（base=%p）：JNI_OnLoad / "
                 "AgentStartWithAuth 将尝试 dlsym(handle, ...) 兜底；"
                 "两者都失败时 agent 拿不到 JavaVM、socket 也不会监听",
                 (void*)base);
        }

        g_lastInjectedHandle = result.handle;   // 供 dlsym 兜底

        if (config.dlcloseHide) {
            // dlclose 隐藏流程:
            // 1. 先调用入口点（dlclose 后 handle 失效）
            // 2. patch soinfo 使 dlclose 跳过 munmap/析构
            // 3. dlclose 让 linker 自动清理 solist/soinfo
            // 4. maps 隐藏 + ELF 混淆照常执行
            callEntryPoint(result.handle, injectedElf);
            startAgentWithAuth(injectedElf, config);

            if (elfOk) {
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
                LOGW("跳过 dlclose/maps/ELF 混淆：内存 ELF 解析失败"
                     "（避免用残缺段信息做破坏性 patch）");
            }
        } else {
            // P0-3 顺序调整：入口点/认证先做 —— 此时 ELF 头与符号表一定还在，
            // 不必让 JNI_OnLoad 冒 hideFromMaps（段被替换为匿名映射）的风险。
            callEntryPoint(result.handle, injectedElf);
            startAgentWithAuth(injectedElf, config);

            if (elfOk) {
                if (config.hideSolist) {
                    hideFromSolist(injectedElf);
                }

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
                LOGW("跳过 solist/maps/ELF 混淆：内存 ELF 解析失败");
            }
        }
        g_lastInjectedHandle = 0;
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
    } else {
        // P0-3：base=0 会让 inject() 里的内存 ELF 解析失败。此时
        // JNI_OnLoad 只能靠 dlsym(handle) 兜底，把原因打出来便于定位。
        LOGE("dlopen 成功但按路径定位不到映射（%s）：result.base=0，"
             "JNI_OnLoad 将只走 dlsym(handle) 兜底", libPath.c_str());
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
    } else {
        // P0-3：memfd 在 maps 里的显示名受内核/bionic 版本影响（可能带
        // " (deleted)" 或只有名字本身），再按随机名匹配一次。
        auto map2 = Utils::findMapByName(m_pid, memfdName);
        if (map2.start) {
            result.base = map2.start;
            LOGW("memfd 映射名与 \"%s\" 不完全一致，按随机名定位到 %p",
                 memfdPath.c_str(), (void*)result.base);
        } else {
            LOGE("android_dlopen_ext 成功但定位不到 memfd 映射（%s）：result.base=0，"
                 "JNI_OnLoad 将只走 dlsym(handle) 兜底", memfdPath.c_str());
        }
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

namespace {

// 在目标进程里定位 JNI_GetCreatedJavaVMs。
//
// 旧实现只认 libart.so，且只取第一个「可读 + ELF 魔数」的段；一旦：
//   · ROM 把该符号放在 libnativehelper.so / 其它 so；
//   · libart 的 maps 顺序/段权限变化导致取到的不是基址段；
// 就会直接返回 0 → JNI_OnLoad 不调用。这里按「候选库 → 退化扫描所有
// file-backed 模块」两级查找，并把命中位置写进 where 供日志定位。
uintptr_t FindJavaVMsSymbol(RemoteProcess* remote, pid_t pid, std::string* where) {
    if (!remote) return 0;
    auto maps = Utils::parseMaps(pid);

    // 只接受「段起始就是 ELF 头」的映射，避免把可执行段当基址解析。
    auto elfBaseOf = [&](const MapEntry& m) -> uintptr_t {
        if (m.start == 0 || !m.isReadable()) return 0;
        char magic[4] = {0};
        if (remote->readMemory(m.start, magic, sizeof(magic)) != (ssize_t)sizeof(magic))
            return 0;
        return memcmp(magic, "\x7f" "ELF", 4) == 0 ? m.start : 0;
    };

    // 1) 已知候选库（覆盖绝大多数 Android 版本）。
    const char* kCandidates[] = {"libart.so", "libnativehelper.so", nullptr};
    for (int i = 0; kCandidates[i]; ++i) {
        for (const auto& m : maps) {
            if (m.path.find(kCandidates[i]) == std::string::npos) continue;
            uintptr_t base = elfBaseOf(m);
            if (!base) continue;
            ElfParser elf;
            if (!elf.loadFromMemory(pid, base)) {
                LOGE("%s: 解析内存 ELF 失败（base=%p），继续尝试其它候选",
                     kCandidates[i], (void*)base);
                continue;
            }
            uintptr_t sym = elf.findSymbol("JNI_GetCreatedJavaVMs");
            if (!sym) {
                LOGE("%s 里没有 JNI_GetCreatedJavaVMs 符号（base=%p）",
                     kCandidates[i], (void*)base);
                continue;
            }
            if (where)
                *where = std::string(kCandidates[i]) + " base=" +
                         Utils::format("%p", (void*)base);
            return sym;
        }
    }

    // 2) 退化：扫描所有带 .so/apex 的可读映射（上限 64 个模块，防止耗时失控）。
    int scanned = 0;
    for (const auto& m : maps) {
        if (scanned >= 64) break;
        if (m.start == 0 || m.path.empty() || !m.isReadable()) continue;
        if (m.path.find(".so") == std::string::npos &&
            m.path.find("/apex/") == std::string::npos)
            continue;
        uintptr_t base = elfBaseOf(m);
        if (!base) continue;
        ++scanned;
        ElfParser elf;
        if (!elf.loadFromMemory(pid, base)) continue;
        uintptr_t sym = elf.findSymbol("JNI_GetCreatedJavaVMs");
        if (!sym) continue;
        LOGW("JNI_GetCreatedJavaVMs 不在候选库里，退化扫描命中: %s base=%p",
             m.path.c_str(), (void*)base);
        if (where)
            *where = m.path + " base=" + Utils::format("%p", (void*)base);
        return sym;
    }
    return 0;
}

} // 匿名命名空间

uintptr_t Injector::getJavaVM() {
    std::string where;
    uintptr_t getJavaVMs = FindJavaVMsSymbol(m_remote.get(), m_pid, &where);

    // 失败分级 1/4：符号解析失败。
    if (!getJavaVMs) {
        LOGE("getJavaVM 失败[1/4]：目标里找不到 JNI_GetCreatedJavaVMs"
             "（libart.so / libnativehelper.so / 退化扫描均未命中）");
        return 0;
    }
    LOGI("JNI_GetCreatedJavaVMs: %p (%s)", (void*)getJavaVMs, where.c_str());

    // 缓冲区布局：JavaVM* + jsize（与 JNI_GetCreatedJavaVMs 的
    // (JavaVM** vmBuf, jsize bufLen, jsize* nVMs) 参数对应）。
    const size_t bufSize = sizeof(uintptr_t) + sizeof(int32_t);
    uintptr_t remoteBuf = m_remote->remoteAlloc(bufSize, PROT_READ | PROT_WRITE);
    if (!remoteBuf) {
        LOGE("getJavaVM 失败[2/4]：remoteAlloc(%zu) 失败", bufSize);
        return 0;
    }
    m_allocations.push_back({remoteBuf, bufSize});

    // 预填哨兵：callFunctionFrom() 在「远程调用失败」时也返回 0（与 JNI_OK
    // 同值），单看返回值无法区分。若调用根本没执行，nVMs 会保持哨兵值。
    constexpr int32_t kNvmsSentinel = 0x7FFFFFFF;
    uint8_t initBuf[sizeof(uintptr_t) + sizeof(int32_t)] = {0};
    memcpy(initBuf + sizeof(uintptr_t), &kNvmsSentinel, sizeof(int32_t));
    m_remote->writeMemory(remoteBuf, initBuf, bufSize);

    uintptr_t status = 0;
    for (int attempt = 1; attempt <= 3; ++attempt) {
        status = m_remote->callFunctionFrom(0, getJavaVMs, 3,
            remoteBuf,                          // vmBuf
            (uintptr_t)1,                       // bufLen
            remoteBuf + sizeof(uintptr_t)       // nVMs
        );

        uintptr_t jvm = 0;
        int32_t nVMs = kNvmsSentinel;
        bool readOk =
            m_remote->readMemory(remoteBuf, &jvm, sizeof(jvm)) == (ssize_t)sizeof(jvm) &&
            m_remote->readMemory(remoteBuf + sizeof(uintptr_t), &nVMs, sizeof(nVMs)) ==
                (ssize_t)sizeof(nVMs);

        if (!readOk) {
            // 失败分级 3/4：远程调用后读不回缓冲区。
            LOGE("getJavaVM 失败[3/4]：JNI_GetCreatedJavaVMs 调用后读回远程缓冲区失败"
                 "（第 %d/3 次）", attempt);
        } else if (status != 0) {
            // 失败分级 2/4：JNI 明确返回错误码（非 JNI_OK）。
            LOGE("getJavaVM 失败[2/4]：JNI_GetCreatedJavaVMs 返回 %ld（非 JNI_OK，"
                 "应为 0；常见原因：bufLen/参数布局不兼容）（第 %d/3 次）",
                 (long)status, attempt);
        } else if (nVMs == kNvmsSentinel) {
            // 失败分级 4/4：JNI 返回 0 但缓冲区一个字节都没被写 → 远程调用没生效。
            LOGE("getJavaVM 失败[4/4]：远程调用未生效（nVMs 仍是哨兵值，说明 "
                 "callFunctionFrom 失败；见日志里 callFunction: 行）（第 %d/3 次）",
                 attempt);
        } else if (nVMs <= 0) {
            LOGE("getJavaVM 失败：JNI_GetCreatedJavaVMs 返回 JNI_OK 但 nVMs=%d"
                 "（目标进程尚无已创建的 JavaVM）（第 %d/3 次）", (int)nVMs, attempt);
        } else if (jvm == 0) {
            LOGE("getJavaVM 失败：JNI_GetCreatedJavaVMs 返回 JNI_OK(nVMs=%d) 但 "
                 "JavaVM*=NULL（第 %d/3 次）", (int)nVMs, attempt);
        } else {
            LOGI("JavaVM: %p (nVMs=%d%s)", (void*)jvm, (int)nVMs,
                 attempt > 1 ? "，重试后拿到" : "");
            return jvm;
        }
        usleep(50 * 1000);
    }

    LOGE("getJavaVM 最终失败：3 次尝试后仍没有有效 JavaVM；"
         "因此 JNI_OnLoad 无法调用，agent 的 SetJavaVM/artHook 将不可用");
    return 0;
}

bool Injector::callEntryPoint(uintptr_t handle, const ElfParser& elf) {
    // 先查 ELF 符号表；失败（内存 ELF 解析失败 / 符号未进 .dynsym）时
    // 用 dlopen 的 handle 走远程 dlsym 兜底 —— 只要库里真的导出
    // JNI_OnLoad，就一定能拿到地址并尝试调用。
    uintptr_t jniOnLoad = elf.findSymbol("JNI_OnLoad");
    bool viaDlsym = false;
    if (!jniOnLoad) {
        jniOnLoad = RemoteDlsym(m_remote.get(), handle, "JNI_OnLoad");
        viaDlsym = jniOnLoad != 0;
        if (!jniOnLoad) {
            // 失败分级 A：符号找不到（不是 agent / 被 strip / 解析全失败）。
            LOGE("JNI_OnLoad 未调用[A]：注入库里找不到该符号"
                 "（ELF 解析 base=%p 失败，dlsym(handle=%p) 也未命中）。"
                 "若注入的不是 agent/libagent.so，artHook 将拿不到 JavaVM。",
                 (void*)elf.base(), (void*)handle);
            return false;
        }
        LOGW("JNI_OnLoad 通过 dlsym(handle) 兜底解析 = %p（ELF 符号表未命中）",
             (void*)jniOnLoad);
    }
    LOGI("Calling JNI_OnLoad at %p (via %s)", (void*)jniOnLoad,
         viaDlsym ? "dlsym" : "elf-symbol");

    // 失败分级 B：拿不到 JavaVM（getJavaVM 内部已按 1/4~4/4 打具体原因）。
    uintptr_t jvm = getJavaVM();
    if (!jvm) {
        LOGE("JNI_OnLoad 未调用[B]：拿不到 JavaVM（原因见上一条 getJavaVM 失败[N/4] 日志）；"
             "agent 的 LuaEngine::SetJavaVM 不会执行，artHook 将报无 JavaVM");
        return false;
    }

    // 调用 JNI_OnLoad(JavaVM*, reserved)。
    // JNI 规范里 reserved 必须是 nullptr：旧实现传 1337，agent 只把它用来打
    // 一行 "injected by universal_debug_tool" 日志（无功能依赖），这里按规范传 0。
    // 使用默认 caller（返回后跳转到 libc 只读段 → SIGSEGV 捕获函数返回）。
    uintptr_t ret = m_remote->callFunctionFrom(0, jniOnLoad, 2, jvm, (uintptr_t)0);

    // 失败分级 C：远程调用失败/库拒绝初始化。JNI_OnLoad 正常应返回
    // JNI_VERSION_1_6 = 0x00010006；返回 0 表示不能在当前 VM 使用。
    if (ret == 0) {
        LOGE("JNI_OnLoad 调用未成功[C]：返回 0（JNI_ERR/无法确定版本）。"
             "artHook 仍拿不到 JavaVM；需检查 agent 与 VM 版本是否匹配。");
        return false;
    }
    constexpr uintptr_t kJNI_VERSION_1_6 = 0x00010006;
    if (ret != kJNI_VERSION_1_6) {
        LOGW("JNI_OnLoad 返回非常规版本 0x%lx（期望 0x10006）；VM 已交给 agent，"
             "但请确认 agent 版本", (unsigned long)ret);
    } else {
        LOGI("JNI_OnLoad OK：JavaVM=%p 已交给 agent（artHook 可用）", (void*)jvm);
    }
    return true;
}

bool Injector::startAgentWithAuth(const ElfParser& elf, const InjectorConfig& config) {
    // 认证材料：32B key + 12B nonce（由 GUI 生成，存在 App 私有目录），
    // 加上允许直连的 GUI uid。整块通过远程内存写入目标进程，agent 只在内存持有。
    uint8_t material[44];
    if (config.keyFile.empty()) {
        LOGW("no --key-file given; agent will refuse to listen (channel disabled)");
        return false;
    }
    int kf = open(config.keyFile.c_str(), O_RDONLY | O_CLOEXEC);
    if (kf < 0) {
        LOGE("cannot open key file %s: %s", config.keyFile.c_str(), strerror(errno));
        return false;
    }
    size_t got = 0;
    while (got < sizeof(material)) {
        ssize_t r = read(kf, material + got, sizeof(material) - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    close(kf);
    if (got != sizeof(material)) {
        LOGE("key file %s incomplete (%zu/44)", config.keyFile.c_str(), got);
        return false;
    }

    uintptr_t fn = elf.findSymbol("AgentStartWithAuth");
    if (!fn) {
        // 与 JNI_OnLoad 相同：内存 ELF 解析失败时用 handle 走远程 dlsym，
        // 避免「注入成功但 socket 永不监听」。
        fn = RemoteDlsym(m_remote.get(), g_lastInjectedHandle, "AgentStartWithAuth");
        if (fn) {
            LOGW("AgentStartWithAuth 通过 dlsym(handle) 兜底解析 = %p", (void*)fn);
        }
    }
    if (!fn) {
        LOGE("agent has no AgentStartWithAuth symbol (ELF 解析失败且 dlsym 未命中); "
             "channel disabled —— 注入成功但 socket 不会监听");
        return false;
    }

    struct AgentAuthBlob {
        uint32_t magic;
        uint32_t version;
        uint8_t  key[32];
        uint8_t  nonce[12];
        uint32_t client_uid;
    } blob;
    memset(&blob, 0, sizeof(blob));
    blob.magic   = 0x43525441u;   // 'ATRC'
    blob.version = 1;
    memcpy(blob.key, material, 32);
    memcpy(blob.nonce, material + 32, 12);
    blob.client_uid = config.clientUid;

    uintptr_t remote = m_remote->remoteAlloc(sizeof(blob), PROT_READ | PROT_WRITE);
    if (!remote) {
        LOGE("failed to allocate remote memory for auth blob");
        return false;
    }
    if (m_remote->writeMemory(remote, &blob, sizeof(blob)) != (ssize_t)sizeof(blob)) {
        LOGE("failed to write auth blob");
        m_remote->remoteFree(remote, sizeof(blob));
        return false;
    }

    uintptr_t rc = m_remote->callFunctionFrom(0, fn, 1, remote);
    LOGI("AgentStartWithAuth -> %lu (client_uid=%u)", rc, (unsigned)config.clientUid);

    // 用完立即释放并清零远程副本
    memset(&blob, 0, sizeof(blob));
    m_remote->remoteFree(remote, sizeof(blob));
    return rc == 0;
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

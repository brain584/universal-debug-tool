#pragma once

#include "Types.h"
#include "RemoteProcess.h"
#include "ElfParser.h"
#include "SolistHider.h"
#include <memory>

struct InjectorConfig {
    std::string libPath;        // 要注入的库路径
    std::string pkgName;        // 目标包名（用于复制到私有目录）
    int dlFlags = 2;            // RTLD_NOW
    bool useMemfd = false;      // 使用 memfd 注入
    bool hideMaps = false;      // 从 maps 隐藏
    bool hideSolist = false;    // 从 solist 隐藏
    bool dlcloseHide = false;   // 通过 patch soinfo + dlclose 隐藏（替代 hideSolist）
    bool copyToPrivate = true;  // 复制到目标进程私有目录（避免SELinux限制）
    bool deepObfuscate = false; // 注入后进行深度 ELF 混淆（破坏 dynamic/strtab/symtab 等）

    // App 私有目录生成，注入器读取后经远程内存写入目标进程，再调用
    // agent 导出的 AgentStartWithAuth() 启动带认证的 socket 监听。
    std::string keyFile;        // 44 字节（32 key + 12 nonce）的密钥文件路径
    uint32_t clientUid = 0;     // 允许直连的 GUI uid（relay 走 root，另算）
};

class Injector {
public:
    explicit Injector(pid_t pid);
    ~Injector();
    
    // 初始化
    bool init();
    
    // 注入库
    InjectionResult inject(const InjectorConfig& config);
    
    // 获取错误信息
    const std::string& lastError() const { return m_lastError; }

private:
    // 注入方式
    InjectionResult injectWithDlopen(const std::string& libPath, int flags);
    InjectionResult injectWithMemfd(const std::string& libPath, int flags);
    
    // 复制库文件到目标进程私有目录
    std::string copyLibToPrivateDir(const std::string& libPath, const std::string& pkgName);
    std::string CopyLibToPrivateDirFixed(const std::string& libPath, const std::string& pkgName);
    std::string FindAppLibDir();
    
    // 隐藏功能
    bool hideFromMaps(const ElfParser& elf);
    bool hideFromSolist(const ElfParser& elf);
    bool hideViaDlclose(uintptr_t handle, const ElfParser& elf);
    
    // 对已注入库的 ELF 头进行改写以防止内存搜索
    bool obfuscateElfHeader(const ElfParser& elf);
    // 深度混淆：清除 dynamic 段引用的表、篡改 program headers 等（破坏性）
    bool obfuscateElfDeep(const ElfParser& elf);

    // 调用 JNI_OnLoad
    bool callEntryPoint(uintptr_t handle, const ElfParser& elf);
    // 通过远程内存把认证材料交给 agent 并启动带认证的 socket 监听。
    // 失败时通道不可用（不会降级为无密钥监听）。
    bool startAgentWithAuth(const ElfParser& elf, const InjectorConfig& config);
    
    // 获取 JavaVM
    uintptr_t getJavaVM();
    
    // 获取 dlerror
    std::string getDlerror();
    
    pid_t m_pid;
    std::unique_ptr<RemoteProcess> m_remote;
    std::unique_ptr<SolistHider> m_solistHider;
    std::string m_lastError;
    std::string m_copiedLibPath;  // 复制到私有目录后的路径（用于清理）
    
    // 远程函数地址
    uintptr_t m_remoteDlopen = 0;
    uintptr_t m_remoteDlopenExt = 0;
    uintptr_t m_remoteDlclose = 0;
    uintptr_t m_remoteDlerror = 0;
    
    // 分配的远程内存
    std::vector<std::pair<uintptr_t, size_t>> m_allocations;
    
    void cleanupAllocations();
};

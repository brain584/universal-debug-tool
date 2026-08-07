#include "Utils.h"
#include <fstream>
#include <cstdarg>
#include <cstring>
#include <dirent.h>
#include <unistd.h>
#include <random>
 
#include <link.h>
#include <dlfcn.h>

namespace Utils {

std::vector<uint8_t> readFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return {};
    
    auto size = file.tellg();
    file.seekg(0);
    
    std::vector<uint8_t> data(size);
    file.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

bool writeFile(const std::string& path, const void* data, size_t size) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    file.write(static_cast<const char*>(data), size);
    return file.good();
}

pid_t getProcessPid(const std::string& processName) {
    DIR* dir = opendir("/proc");
    if (!dir) return -1;
    
    pid_t result = -1;
    struct dirent* entry;
    
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;
        
        // 检查是否为数字目录
        char* end;
        pid_t pid = strtol(entry->d_name, &end, 10);
        if (*end != '\0') continue;
        
        // 读取 cmdline
        std::string cmdlinePath = format("/proc/%d/cmdline", pid);
        std::ifstream cmdline(cmdlinePath);
        std::string name;
        std::getline(cmdline, name, '\0');
        
        if (name == processName) {
            result = pid;
            break;
        }
    }
    
    closedir(dir);
    return result;
}

std::vector<MapEntry> parseMaps(pid_t pid) {
    std::vector<MapEntry> maps;
    std::string path = format("/proc/%d/maps", pid);
    std::ifstream file(path);
    
    std::string line;
    while (std::getline(file, line)) {
        MapEntry entry{};
        char perms[5] = {0};
        char pathBuf[512] = {0};
        
        int n = sscanf(line.c_str(), "%lx-%lx %4s %lx %*s %*s %511[^\n]",
                       &entry.start, &entry.end, perms, &entry.offset, pathBuf);
        
        if (n >= 4) {
            entry.prot = 0;
            if (perms[0] == 'r') entry.prot |= 0x1;
            if (perms[1] == 'w') entry.prot |= 0x2;
            if (perms[2] == 'x') entry.prot |= 0x4;
            entry.path = pathBuf;
            
            // 去除路径前的空格
            size_t start = entry.path.find_first_not_of(' ');
            if (start != std::string::npos) {
                entry.path = entry.path.substr(start);
            }
            
            maps.push_back(entry);
        }
    }
    
    return maps;
}

MapEntry findMapByName(pid_t pid, const std::string& name) {
    // 尝试多次读取 maps，以防 dlopen 后映射尚未立即出现在 /proc/[pid]/maps
    const int maxAttempts = 25;
    const useconds_t sleepUs = 10000; // 10ms
    // 提取 basename 以便匹配路径中可能只包含文件名的情况
    std::string baseName;
    size_t pos = name.find_last_of('/');
    if (pos != std::string::npos && pos + 1 < name.size()) {
        baseName = name.substr(pos + 1);
    }

    for (int attempt = 0; attempt < maxAttempts; ++attempt) {
        auto maps = parseMaps(pid);

        // 优先查找 offset=0 的段（ELF header 所在位置）
        for (const auto& map : maps) {
            if ((map.path.find(name) != std::string::npos || (!baseName.empty() && map.path.find(baseName) != std::string::npos))
                 && map.offset == 0) {
                return map;
            }
        }

        // 如果没有 offset=0 的段，返回第一个可读段
        for (const auto& map : maps) {
            if ((map.path.find(name) != std::string::npos || (!baseName.empty() && map.path.find(baseName) != std::string::npos))
                 && map.isReadable()) {
                return map;
            }
        }

        // 最后返回第一个匹配的
        for (const auto& map : maps) {
            if (map.path.find(name) != std::string::npos || (!baseName.empty() && map.path.find(baseName) != std::string::npos)) {
                return map;
            }
        }

        // 等待短暂时间再重试
        usleep(sleepUs);
    }

    return {};
}

// 使用 dl_iterate_phdr 解析当前进程已加载的 so 映射（仅限当前进程）
static int dl_phdr_callback(struct dl_phdr_info* info, size_t size, void* data) {
    (void)size;
    if (!info || !data) return 0;
    auto maps = static_cast<std::vector<MapEntry>*>(data);

    std::string path = info->dlpi_name ? info->dlpi_name : "";
    // if (path.empty()) {
    //     // 对于主程序，dlpi_name 可能为空，尝试使用 /proc/self/exe
    //     char exePath[512] = {0};
    //     ssize_t len = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
    //     if (len > 0) {
    //         exePath[len] = '\0';
    //         path = exePath;
    //     }
    // }

    for (int i = 0; i < static_cast<int>(info->dlpi_phnum); ++i) {
        const Elf_Phdr& ph = info->dlpi_phdr[i];
        if (ph.p_type != PT_LOAD) continue;

        MapEntry entry{};
        entry.start = static_cast<uintptr_t>(info->dlpi_addr + ph.p_vaddr);
        entry.end = entry.start + ph.p_memsz;
        entry.offset = static_cast<size_t>(ph.p_offset);
        entry.prot = 0;
        if (ph.p_flags & PF_R) entry.prot |= 0x1;
        if (ph.p_flags & PF_W) entry.prot |= 0x2;
        if (ph.p_flags & PF_X) entry.prot |= 0x4;
        entry.path = path;

        maps->push_back(entry);
    }

    return 0;
}

std::vector<MapEntry> parseMapsWithDl() {
    std::vector<MapEntry> maps;
    dl_iterate_phdr(dl_phdr_callback, &maps);
    return maps;
}

std::string format(const char* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    return buf;
}

std::string getErrorString(int err) {
    return strerror(err);
}

bool fileExists(const std::string& path) {
    return access(path.c_str(), F_OK) == 0;
}

std::string randomString(size_t length) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
    
    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += charset[dis(gen)];
    }
    return result;
}

} // namespace Utils

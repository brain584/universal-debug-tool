#pragma once

#include "Types.h"
#include <vector>
#include <string>

namespace Utils {

// 读取文件内容
std::vector<uint8_t> readFile(const std::string& path);

// 写入文件
bool writeFile(const std::string& path, const void* data, size_t size);

// 获取进程 PID
pid_t getProcessPid(const std::string& processName);

// 解析 /proc/[pid]/maps
std::vector<MapEntry> parseMaps(pid_t pid);

// 使用 dl_iterate_phdr 解析当前进程已加载的 so 映射（仅限当前进程）
std::vector<MapEntry> parseMapsWithDl();

// 查找包含指定名称的映射
MapEntry findMapByName(pid_t pid, const std::string& name);

// 字符串格式化
std::string format(const char* fmt, ...);

// 获取错误信息
std::string getErrorString(int err);

// 检查文件是否存在
bool fileExists(const std::string& path);

// 生成随机字符串
std::string randomString(size_t length);

} // namespace Utils

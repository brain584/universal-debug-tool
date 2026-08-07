# NewInjector

一个简洁的 Android ARM64 共享库注入器。

## 特性

- 仅支持 ARM64 架构
- 基于 ptrace 的进程注入
- 支持传统 dlopen 注入
- 支持 memfd + android_dlopen_ext 无文件注入
- 支持从 /proc/[pid]/maps 隐藏注入库
- 支持从 linker solist 隐藏（绕过 dladdr/dl_iterate_phdr）
- 进程启动监控（通过 logcat 或 inotify）
- 自动调用 JNI_OnLoad 入口点
- 使用 GNU/SYSV hash 表加速符号查找

## 编译

### 环境要求

- Android NDK (设置 NDK_HOME 环境变量)
- CMake 3.10+
- Ninja

### 编译注入器

```bash
# Windows
build.bat

# Linux/macOS
chmod +x build.sh
./build.sh
```

输出文件: `build/injector`

### 编译测试库

```bash
cd testlib

# Windows
build.bat

# Linux/macOS
chmod +x build.sh
./build.sh
```

输出文件: `testlib/build/libtestlib.so`

## 使用方法

```
Usage: injector [options]

Required:
  -p, --pkg <name>     目标应用包名
  -l, --lib <path>     要注入的库路径

Optional:
  -i, --pid <pid>      目标 PID (如果已知)
  -m, --memfd          使用 memfd 注入
  -H, --hide-maps      从 /proc/[pid]/maps 隐藏
  -S, --hide-solist    从 linker solist 隐藏
  -w, --watch          监控进程启动后注入
  -d, --delay <us>     注入前延迟 (微秒)
  -t, --timeout <ms>   监控超时 (毫秒)
  -h, --help           显示帮助
```

### 示例

```bash
# 基本注入
./injector -p com.example.app -l /data/local/tmp/libtest.so

# 使用 memfd 注入
./injector -p com.example.app -l /data/local/tmp/libtest.so -m

# 隐藏注入
./injector -p com.example.app -l /data/local/tmp/libtest.so -m -H -S

# 监控进程启动后注入
./injector -p com.example.app -l /data/local/tmp/libtest.so -w

# 监控并延迟注入
./injector -p com.example.app -l /data/local/tmp/libtest.so -w -d 100000
```

## 被注入库示例

```cpp
#include <jni.h>
#include <android/log.h>
#include <thread>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "MyLib", __VA_ARGS__)

extern "C" JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    // 检查是否由注入器调用 (key = 1337)
    if (reserved != (void*)1337) {
        return JNI_VERSION_1_6;
    }
    
    LOGI("Injected by NewInjector!");
    
    // 获取 JNIEnv
    JNIEnv* env = nullptr;
    vm->GetEnv((void**)&env, JNI_VERSION_1_6);
    
    // 启动工作线程
    std::thread([]() {
        // 你的代码
    }).detach();
    
    return JNI_VERSION_1_6;
}
```

## 项目结构

```
newInjector/
├── CMakeLists.txt          # 主构建文件
├── build.bat               # Windows 构建脚本
├── build.sh                # Linux 构建脚本
├── include/
│   ├── Types.h             # 类型定义
│   ├── Utils.h             # 工具函数
│   ├── ElfParser.h         # ELF 解析器 (支持 GNU/SYSV hash)
│   ├── RemoteProcess.h     # 远程进程操作
│   ├── Injector.h          # 注入器
│   ├── SolistHider.h       # solist 隐藏
│   └── ProcessMonitor.h    # 进程监控
├── src/
│   ├── main.cpp            # 入口
│   ├── Utils.cpp           # 工具实现
│   ├── ElfParser.cpp       # ELF 解析实现
│   ├── RemoteProcess.cpp   # 远程进程实现
│   ├── Injector.cpp        # 注入器实现
│   ├── SolistHider.cpp     # solist 隐藏实现
│   └── ProcessMonitor.cpp  # 进程监控实现
└── testlib/                # 测试库
    ├── CMakeLists.txt
    ├── testlib.cpp
    └── build.bat
```

## 技术原理

1. **ptrace 附加**: 使用 ptrace 附加到目标进程
2. **远程内存操作**: 通过 process_vm_readv/writev 读写远程内存
3. **远程函数调用**: 修改寄存器并执行远程函数
4. **dlopen 注入**: 调用远程 dlopen 加载库
5. **memfd 注入**: 使用 memfd_create + android_dlopen_ext 无文件注入
6. **maps 隐藏**: 将文件映射替换为匿名映射
7. **solist 隐藏**: 修改 linker 内部链表移除 soinfo 节点
8. **符号查找**: 支持 GNU hash 和 SYSV hash 表加速查找
9. **进程监控**: 通过 logcat (am_proc_start) 或 inotify (/proc) 监控进程启动

## 注意事项

- 需要 root 权限或相同 UID
- 仅支持 ARM64 架构
- 目标进程必须已启动
- 不要在库的构造函数中启动线程，使用 JNI_OnLoad

## License

MIT

//
// JNI 桥 —— ATrace 后端。
//
// 只保留与 root 相关的后端能力：su 命令、注入器调用、远程内存读写。
// 原生悬浮窗（overlay_bridge.cpp）复用这些函数。
// 旧的 ImGui 渲染界面（SurfaceView + AImGui）已移除。
//
#include "socket/ChannelKey.h"
#include <jni.h>
#include <android/log.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <signal.h>
#include <string>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

// 自己实现的接口声明（含 SuWrap 的默认参数 merge_stderr=true）。
// 必须包含：默认实参只对"能看见声明"的调用点生效。
#include "SuBridge.h"

#define TAG "ATraceJNI"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ── 注入信息（由 Java 设置）──
static std::mutex  g_inject_mutex;
static std::string g_injector_path;
static std::string g_agent_path;
static std::string g_zpt_path;   // 零 ptrace 注入器（assets/zpt 解压而来）
static std::string g_config_dir;   // App 私有 files 目录（配置文件存放处）

// 配置文件路径（App 私有 files 目录，免 root）。
std::string GetConfigFilePath() {
    return g_config_dir.empty()
               ? ""
               : g_config_dir + "/universal_debug_tool.conf";
}

// 返回解压后的注入器路径（断点服务使用）。
std::string GetInjectorPath() {
    std::lock_guard<std::mutex> lk(g_inject_mutex);
    return g_injector_path;
}

// ─────────────────────────────────────────────────────────────────────────────
//
//  背景（实测）：原来全项目 11 处都写死裸 `su`，靠 PATH 解析。
//  这个假设在 KernelSU 的设备上不成立：
//
//    * KernelSU 的 su 由内核在 **execve 上拦截**（dmesg 可见
//      `KernelSU: newfstatat su->sh!` / `sys_execve su found`），
//      它**不以文件形式出现在普通进程的挂载命名空间**里
//      （`/proc/<app_pid>/root/system/bin/su` = No such file or directory）。
//    * 于是 App 里裸 `su` → ENOENT → 只报一句 "无法启动 su"，
//      完全看不出真因（是没授权？还是 su 没暴露？）。
//
//  实测有效的兜底是 **用 `/system/bin/sh -c` 包一层**：
//  KernelSU 的兼容钩子在处理 sh -c 时能把 `su` 重定向到可用实现；
//  同时给子进程补上 KernelSU 的 bin 目录，让 PATH 解析也能命中。
//
//  所以这里给出统一的 `SuWrap()`：所有需要 root 的命令都必须经它拼装，
//  不要再自己写 "su -c '...'"。
// ─────────────────────────────────────────────────────────────────────────────
namespace {
std::mutex  g_su_mutex;
std::string g_su_explicit;   // 用户在 UI 里手动指定的 su 路径（最高优先级）
bool        g_su_logged = false;

// KernelSU / Magisk 的 su 常见落点，按优先级排列。
const char* const kSuCandidates[] = {
    "/system/bin/su",            // Magisk 与 KernelSU su_compat 模式
    "/data/adb/ksu/bin/su",      // KernelSU 旧版位置（App 可能因 /data/adb 0700 看不到）
    "/system/xbin/su",           // 老 ROM
    "/debug_ramdisk/su",         // Magisk 部分版本
    "/sbin/su",                  // 兼容兜路
    nullptr,
};

std::string ShellQuote(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    out.push_back('\'');
    for (char c : s) {
        if (c == '\'') out += "'\\''";   // 单引号内部转义单引号
        else out.push_back(c);
    }
    out.push_back('\'');
    return out;
}
}  // namespace

// 当前使用的 su 路径（空 = 依赖 PATH 上的裸 `su`），并打一条一次性的日志。
const char* SuPath() {
    static std::string cached;
    static std::string resolved_from;
    static bool done = false;
    std::lock_guard<std::mutex> lk(g_su_mutex);
    // 显式设置变化时必须重新解析（否则 SetSuPath 不会生效）
    if (!done || resolved_from != g_su_explicit) {
        resolved_from = g_su_explicit;
        if (!g_su_explicit.empty()) {
            cached = g_su_explicit;
        } else {
            // 注意：不要在这里用 access() 去探测。KernelSU 的 su 不在文件系统里，
            // access() 必然失败，会把唯一可用的入口也判死。
            // 路径探测只在 BuildSuDiag()（诊断用）里做。
            if (const char* env = getenv("ATRACE_SU")) {
                cached = env;
            } else {
                cached.clear();
            }
        }
        done = true;
    }
    return cached.empty() ? "" : cached.c_str();
}

// 把 "命令字符串" 包成一条能在 App 进程里真正提到权的完整 shell 命令。
//
// 为什么必须经 `/system/bin/sh -c`：裸 `su -c` 在 App 进程里 rc=127
// （KernelSU 的 su 走内核 execve 拦截，需要外层 shell 兜一层），
// 而 `/system/bin/sh -c '...su -c ...'` 实测能拿到 uid=0。
//
// `merge_stderr`：见 SuBridge.h 的说明。
//   true  -> 结尾 `2>&1`        （给人看的输出，popen 抓取）
//   false -> 结尾 `2>/dev/null` （走 stdout 的协议流，绝不能污染）
// 这里**不加** PATH 前缀：su -c 起来的本来就是 root shell，
// 再套一层 `PATH=$PATH:...` 反而让命令形式对 su 分片敏感。
std::string SuWrap(const std::string& cmd, bool merge_stderr) {
    std::string s = SuPath();
    std::string inner;
    if (s.empty()) {
        inner = "su -c " + ShellQuote(cmd);
    } else {
        inner = ShellQuote(s) + " -c " + ShellQuote(cmd);
    }
    return "/system/bin/sh -c " + ShellQuote(inner) +
           (merge_stderr ? " 2>&1 </dev/null" : " 2>/dev/null </dev/null");
}

// 走协议流的调用方（BpService / SocketClient relay）用这个。
//
// 关键：**不套外层 `/system/bin/sh -c`**。调用方自己已经用
// `execl("/system/bin/sh","-c",cmd)` 起了 shell，再套一层会变成
// sh→sh→su→sh 四层，内层引号被吃、参数错位。
// → 子进程秒退 → ReadLoop 判为"断点服务未启动"。
//
// 保持与原始实现逐字一致的形式（用户指出的"先前实现"）：
//     su -c '<cmd>' 2>/dev/null
std::string SuSpawnCommand(const std::string& cmd) {
    std::string s = SuPath();
    std::string head = s.empty() ? std::string("su") : s;
    return head + " -c " + ShellQuote(cmd) + " 2>/dev/null";
}

// 跑一条 root 命令并捕获输出（stdout+stderr 已合并）。空串 = 执行失败。
std::string SuRun(const std::string& cmd) {
    std::string full = SuWrap(cmd);
    FILE* f = popen(full.c_str(), "r");
    if (!f) return "";
    std::string out;
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
    pclose(f);
    return out;
}

// 逐候选路径探一遍，把**实测结果**拼成可读文本（每一步都说明白）。
// 用途：UI 诊断入口 —— 以后再出这类问题不必再登 root 终端翻 dmesg。
std::string BuildSuDiag() {
    std::string r = "su 解析诊断\n";
    r += "App uid=" + std::to_string((long)getuid()) + "\n";
    if (const char* p = getenv("PATH")) r += std::string("PATH=") + p + "\n";
    r += "--- 候选路径实测 ---\n";
    for (int i = 0; kSuCandidates[i]; ++i) {
        const char* p = kSuCandidates[i];
        // 不用 access()：它在 KernelSU 下对不存在于命名空间的文件必然失败，
        // 而我们要的是"文件在不在 + 可不可执行"两个事实。
        std::string c = std::string("/system/bin/sh -c 'test -f ") + p +
                        " && echo F_OK || echo NO_FILE; test -x " + p +
                        " && echo X_OK || echo NO_EXEC' 2>&1";
        std::string v;
        if (FILE* f = popen(c.c_str(), "r")) {
            char b[256] = {0};
            size_t n = fread(b, 1, sizeof(b) - 1, f);
            (void)n;
            pclose(f);
            v = b;
            for (char& ch : v) if (ch == '\n') ch = ' ';
        }
        if (!v.empty()) while (!v.empty() && v.back() == ' ') v.pop_back();
        r += std::string("  ") + p + " -> " + (v.empty() ? "(无输出)" : v) + "\n";
    }
    r += "--- 关键实测：能否真的提到权 ---\n";
    {
        std::string o = SuRun("id");
        // 去掉首尾空白，避免把换行带进 UI
        while (!o.empty() && (o.back() == '\n' || o.back() == ' ')) o.pop_back();
        if (o.find("uid=0") != std::string::npos) {
            r += "  [OK] 已拿到 root: " + o + "\n";
        } else {
            r += "  [FAIL] 提权失败。输出: " + (o.empty() ? std::string("(空)") : o) + "\n";
            r += "  => KernelSU 没有把 su 暴露给本 App 的命名空间。\n";
            r += "     处置: 重启手机；仍不行则在 SukiSU 里重跑一次\"安装/修复\"，\n";
            r += "     再不行就重刷 KernelSU 的 boot。此问题与 ATrace 代码无关。\n";
        }
    }
    r += "--- 生效的命令形式 ---\n  " + SuWrap("id") + "\n";
    if (!g_su_logged) {
        g_su_logged = true;
        LOGI("su 诊断: %s", r.c_str());
    }
    return r;
}

// 允许 UI 手动指定 su 路径（特殊 ROM 兜底）。
void SetSuPath(const std::string& p) {
    std::lock_guard<std::mutex> lk(g_su_mutex);
    g_su_explicit = p;
    // 让下一次 SuPath() 重新解析
    LOGI("手动指定 su 路径 = %s", p.empty() ? "(清空)" : p.c_str());
}

// ── 注入（ptrace）──
// 在 `su` 下为指定参数运行独立注入器可执行文件并返回捕获的输出。
// 必须在后台线程调用：`su` + ptrace 注入可能耗时。
std::string RunInjectorArgs(const std::string& args) {
    // 通道认证参数：把 App 私有目录的密钥文件路径与 GUI uid 传给注入器；
    // 注入器读取后经远程内存写入目标进程（不再落公共路径）。
    std::string chanArgs;
    {
        uint8_t k[ChannelKey::kKeyLen];
        uint8_t n[ChannelKey::kNonceLen];
        if (ChannelKey::Ensure(k, n)) {
            chanArgs = std::string(" --key-file \"") + ChannelKey::Path() +
                       "\" --client-uid " + std::to_string((unsigned)getuid());
        } else {
            return "错误: 通道密钥初始化失败（App 私有目录不可写）";
        }
    }
    if (chanArgs.empty() || ChannelKey::Path().empty()) {
        // 配置目录来自 nativeSetConfigDir（启动 Overlay 时设置）。
        // 没有它就无法生成 App 私有密钥文件，注入后通道也不会监听。
        return "错误: 配置目录未初始化，请先启动 Overlay 再注入";
    }

    std::string inj, agent;
    {
        std::lock_guard<std::mutex> lk(g_inject_mutex);
        inj = g_injector_path;
        agent = g_agent_path;
    }
    if (inj.empty() || agent.empty())
        return "错误: injector/agent 路径未设置";

    // 也不再需要把该目录改成 0777；抽象 socket 不落文件，无需目录写权限。
    // （旧版这里的 `chmod 777 /data/local/tmp` 已移除。）

    // 经 SuWrap 提权执行注入器（内部会补 PATH 并用 sh -c 包一层）。
    // chanArgs 携带 --key-file / --client-uid，由注入器写入目标进程内存。
    // 而它继承了 App 的监听 fd，会导致 28471 端口"假死"（LISTEN 但无人 accept）。
    std::string cmd = SuWrap("timeout 20 " + inj + " " + args + chanArgs + " -l " + agent);
    FILE* f = popen(cmd.c_str(), "r");
    if (!f) return "错误: 无法启动 su（popen 失败，见「注入器自检」诊断）";

    std::string out;
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        out.append(buf, n);
    int rc = pclose(f);

    // 如果注入器没有任何输出（例如在打日志前崩溃），
    // 显示退出码，避免 UI 静默无提示。
    if (out.empty() && rc != 0) {
        out = "injector 无输出，退出码 " + std::to_string(rc);
    }

    if (out.size() > 2048)
        out = out.substr(out.size() - 2048);
    return out;
}

std::string RunInjector(const std::string& pkg) {
    return RunInjectorArgs("-p " + pkg);
}

// 按 PID 注入：用于 native ELF 等非应用进程——没有包名可解析，
// 注入器把 agent 复制到 /data/local/tmp 供目标读取。
std::string RunInjectorPid(int pid) {
    return RunInjectorArgs("-i " + std::to_string(pid));
}

// ── 注入（零 ptrace / data-only）──
// 不改目标一条指令，只改两处**数据**：
//   1) 往目标栈上某个可写缓冲写 agent 路径
//   2) 把那个缓冲对应的 GOT 槽临时指向 dlopen
// 目标就会用**它自己的调用者身份**去 dlopen 我们的 agent（namespace 天然正确）。
// 全程不建立 ptrace 关系 —— TracerPid 那条检测面看不到任何东西。
//
// 前置条件（不满足时输出里会说明原因）：
//   * 必须 root
//   * agent 的 DT_NEEDED 只能依赖系统库（带 libc++_shared.so 这类会加载失败）
//   * 目标里要存在 "arg1==0 且 arg0 可写" 的频繁系统调用作为注入点
std::string RunZeroPtraceInject(int pid, const std::string& pkg_hint) {
    std::string zpt, agent;
    {
        std::lock_guard<std::mutex> lk(g_inject_mutex);
        zpt = g_zpt_path;
        agent = g_agent_path;
    }
    if (zpt.empty() || agent.empty())
        return "错误: 零 ptrace 注入器或 agent 未就绪（检查 assets/zpt 是否已打包）";

    std::string pkg = pkg_hint;
    // 只给了包名：用 pidof 解析出 pid
    if (pid <= 0 && !pkg.empty()) {
        std::string c = SuWrap("pidof " + pkg);
        FILE* f = popen(c.c_str(), "r");
        if (f) {
            char b[256] = {0};
            size_t n = fread(b, 1, sizeof(b) - 1, f);
            pclose(f);
            (void)n;
            pid = atoi(b);
        }
        if (pid <= 0) return "错误: 进程未运行（包名 " + pkg + "）";
    }
    // 只给了 pid：从 cmdline 反查包名（Android 应用进程名就是包名）
    if (pkg.empty() && pid > 0) {
        std::string c = SuWrap("cat /proc/" + std::to_string(pid) + "/cmdline");
        FILE* f = popen(c.c_str(), "r");
        if (f) {
            char buf[512];
            size_t n = fread(buf, 1, sizeof(buf) - 1, f);
            pclose(f);
            buf[n] = 0;
            for (size_t i = 0; i < n; ++i) if (buf[i] == 0 || buf[i] == '\n') { buf[i] = 0; break; }
            pkg = buf;
        }
    }
    if (pkg.empty() || pkg.find('/') != std::string::npos || pkg.find('\'') != std::string::npos)
        return "错误: 无法确定目标包名（pid " + std::to_string(pid) + "）";

    // agent 放哪：**/data/local/tmp**
    //
    // 【踩过的坑】最初我放到目标自己的 data 目录 /data/data/<pkg>/zptp，
    // 结果从 ATrace 里点注入时报：
    //     cp: /data/data/com.example.crc_test/zptp: No such file or directory
    // 是 **ENOENT 而不是 Permission denied** —— 说明 ATrace 这个普通 App 起的
    // `su -c` 所处的挂载命名空间里看不到 /data/data/<pkg>/（在 root 终端里跑同样
    // 的命令是好的）。所以改用 /data/local/tmp：这也是 ATrace 现有 ptrace 注入器
    // 一直用的落点（agent 放那儿供目标读取），本机已验证可用。
    // 注：本机 SELinux 是 Permissive 所以目标能读到；Enforcing 设备上这条路需要额外处理。
    // 落点用 **/data/zptp**（10 字符 + NUL = 11 字节）。
    // 【为什么不用 /data/local/tmp/zptp】那是 20 字符，写进 nanosleep 的 timespec
    // （只有 16 字节）会**越界 8 字节**，压到栈帧保存的 x29/x30 上 ->
    // 目标返回时跳进我们的 ASCII 路径里崩溃（KiHan 实测三次）。
    // /data 的 others 有 x（可穿越），文件 644 后目标读得到。
    // zpt 没有"远程调用函数"的能力，不能像 ptrace 注入器那样直接调
    // AgentStartWithAuth()，所以 agent 以前**从来不监听**（界面却报成功）。
    // 现在把常规注入用的同一份 <filesDir>/channel_key.bin（44B, 0600）交给 zpt：
    // 由它（root）在触发 dlopen 前写成 56B auth blob + 空就绪标记，
    // chown 目标进程 uid / 0600；agent 构造函数读到后自己启动 socket 并回写就绪标记。
    std::string chanArgs;
    {
        if (ChannelKey::Path().empty())
            return "错误: 配置目录未初始化，请先启动 Overlay 再注入";
        uint8_t k[ChannelKey::kKeyLen];
        uint8_t n[ChannelKey::kNonceLen];
        if (!ChannelKey::Ensure(k, n))
            return "错误: 通道密钥初始化失败（App 私有目录不可写），agent 无法启动";
        // 路径是 App 私有目录（无空格/引号），仍然加引号防御。
        chanArgs = std::string(" --key-file \"") + ChannelKey::Path() +
                   "\" --client-uid " + std::to_string((unsigned)getuid());
    }

    const std::string dest = "/data/zptp";
    // 注意：zpt 的日志写到 /data/local/tmp/zpt_trace.txt 和 logcat，**不打印到 stdout**。
    // 所以这里跑完必须把 trace 一起 cat 出来，否则 UI 只会看到"无输出"。
    // 顺带清掉上一次可能残留的 auth 交接文件，避免 agent 读到过期密钥。
    std::string cmd = SuWrap("rm -f /data/local/tmp/zpt_trace.txt "
                      "/data/local/tmp/zpt_auth.bin /data/local/tmp/zpt_auth.ready; "
                      "cp -f " + agent + " " + dest +
                      " && chmod 644 " + dest +
                      " && " + zpt + " --auto " + std::to_string(pid) + " " + dest + chanArgs +
                      "; echo \"[zpt exit=$?]\"; cat /data/local/tmp/zpt_trace.txt 2>/dev/null");

    FILE* f = popen(cmd.c_str(), "r");
    if (!f) return "错误: 无法启动 su（popen 失败，见「注入器自检」诊断）";
    std::string out;
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
    int rc = pclose(f);

    // 失败时补一段现场诊断，避免只能看到一句"没有那个文件"
    if (out.find("No such file") != std::string::npos ||
        out.find("Permission denied") != std::string::npos ||
        out.find("cp:") != std::string::npos ||
        out.find("not found") != std::string::npos ||
        out.find("unable to") != std::string::npos) {
        std::string diag = SuWrap("id; echo ---; ls -ld /data/local/tmp; "
                           "ls -l " + agent + "; ls -l " + zpt + "; "
                           "ls -l " + dest);
        FILE* df = popen(diag.c_str(), "r");
        if (df) {
            out += "\n--- su 环境诊断 ---\n";
            char db[1024];
            size_t dn;
            while ((dn = fread(db, 1, sizeof(db), df)) > 0) out.append(db, dn);
            pclose(df);
        }
        // 追加上 su 解析诊断：这一步能直接区分「su 没暴露给 App」和「注入本身失败」
        out += "\n--- su 解析 ---\n";
        out += BuildSuDiag();
    }

    if (out.empty()) out = "零 ptrace 注入无输出，退出码 " + std::to_string(rc);
    if (out.size() > 4096) out = out.substr(out.size() - 4096);
    // UI 依据这个标记决定显示绿还是红（成功绿 / 失败红）。
    // 才打印【成功】；so 只是"加载了"不再算成功，所以这里的判定不会再误报。
    const bool ok = out.find("【成功】") != std::string::npos;
    return std::string(ok
        ? "[ZPT-OK] 零 ptrace 注入成功（data-only，agent socket 已就绪，全程无 ptrace 关系）\n"
        : "[ZPT-FAIL] 零 ptrace 注入失败（agent 未就绪；原因见下方 zpt trace）\n") + out;
}

// 逐行复制 BpService::Spawn 的启动方式（fork + execl("/system/bin/sh","-c")），
// 用真实命令判断"子进程能否活过 150ms"——这正是 BpService::ReadLoop 的判据。
//
// 为什么必须在 App 内做：`su` 只在**真实 App 进程的挂载命名空间**里可用，
// adb shell 与 run-as 都测不出来（实测两者都返回 rc=127），
// 所以这类问题只能在 App 里自证。
std::string BuildSpawnDiag() {
    std::string inj = GetInjectorPath();
    std::string s = "断点服务启动形态自检\n";
    s += "injector = " + (inj.empty() ? std::string("(未设置)") : inj) + "\n";
    if (inj.empty()) return s + "=> 注入器路径未设置，无法自检。\n";

    int pid = 0;
    {
        FILE* f = popen("/system/bin/ps -A -o PID,NAME 2>/dev/null | grep -m1 crc_test", "r");
        if (f) {
            char b[128] = {0};
            size_t n = fread(b, 1, sizeof(b) - 1, f);
            (void)n;
            pclose(f);
            pid = atoi(b);
        }
    }
    if (pid <= 0) pid = (int)getpid();   // 兜底：拿不到就只验证能否起 su
    s += "目标 pid = " + std::to_string(pid) +
         (pid == (int)getpid() ? "（兜底：用自己）" : "") + "\n";

    struct Variant { const char* name; std::string cmd; };
    std::vector<Variant> vs;
    vs.push_back({"原始形式 su -c '...' 2>/dev/null",
                  SuSpawnCommand(inj + " --bp " + std::to_string(pid))});
    vs.push_back({"su -c '...' 2>&1（旧 SuWrap 的 stderr 合并）",
                  std::string("su -c ") + ShellQuote(inj + " --bp " + std::to_string(pid)) + " 2>&1"});

    for (auto& v : vs) {
        int to_child[2], from_child[2];
        if (pipe(to_child) != 0 || pipe(from_child) != 0) {
            s += "  [" + std::string(v.name) + "] pipe 失败\n";
            continue;
        }
        pid_t child = fork();
        if (child < 0) {
            s += "  [" + std::string(v.name) + "] fork 失败\n";
            continue;
        }
        if (child == 0) {
            dup2(to_child[0], 0);
            dup2(from_child[1], 1);
            close(to_child[0]); close(to_child[1]);
            close(from_child[0]); close(from_child[1]);
            execl("/system/bin/sh", "sh", "-c", v.cmd.c_str(), (char*)nullptr);
            _exit(127);
        }
        close(to_child[0]); close(from_child[1]);
        usleep(150 * 1000);
        int st = 0;
        pid_t w = waitpid(child, &st, WNOHANG);
        std::string line;
        if (w == child) {
            line = "  [" + std::string(v.name) + "] ✗ 子进程 150ms 内已退出";
            if (WIFEXITED(st)) line += "（exit=" + std::to_string(WEXITSTATUS(st)) + "）";
            line += " → BpService 会显示\"未启动\"\n";
        } else {
            line = "  [" + std::string(v.name) + "] ✓ 子进程存活 → 断点服务可正常启动\n";
            kill(child, SIGTERM);
            waitpid(child, &st, 0);
        }
        s += line;
        // 同时把子进程的早期输出读出来（错误信息就在这里）
        char buf[512] = {0};
        ssize_t rn = read(from_child[0], buf, sizeof(buf) - 1);
        if (rn > 0) {
            std::string o(buf, (size_t)rn);
            for (char& c : o) if (c == '\n') c = ' ';
            s += "      子进程输出: " + o + "\n";
        }
        close(to_child[1]);
        close(from_child[0]);
    }
    s += "命令串（原始形式）: " + vs[0].cmd + "\n";
    LOGI("spawn 自检: %s", s.c_str());
    return s;
}

// ── Root 内存辅助函数 ──
// 在 root 下运行命令并返回捕获的输出。
// 注意：现在**经 SuWrap 组装**，所以 cmd 里可以带单引号（会被正确转义），
// 也不再要求调用方自己写 `su -c`。
std::string RunSuCommand(const std::string& cmd) {
    return SuRun(cmd);
}
// 通用 su 执行（供 Kotlin 清理孤儿进程/诊断用，不对外暴露敏感能力）。
extern "C" JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_runSuShell(JNIEnv* env, jobject, jstring cmd) {
    const char* c = cmd ? env->GetStringUTFChars(cmd, nullptr) : "";
    std::string out = RunSuCommand(c ? c : "");
    if (c) env->ReleaseStringUTFChars(cmd, c);
    if (out.empty()) return nullptr;
    return env->NewStringUTF(out.c_str());
}


std::string ReadRemoteMaps(int pid) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "cat /proc/%d/maps", pid);
    return RunSuCommand(cmd);
}

bool ReadRemoteDword(int pid, uintptr_t addr, uint32_t& out) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
        "dd if=/proc/%d/mem bs=1 skip=%llu count=4 2>/dev/null | xxd -p -c 8",
        pid, (unsigned long long)addr);
    std::string hex = RunSuCommand(cmd);
    // xxd -p 按文件顺序打印字节，例如 "78563412\n"
    if (hex.size() < 8) return false;
    uint32_t v = 0;
    for (int i = 0; i < 8; ++i) {
        char c = hex[i];
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return false;
        v = (v << 4) | (uint32_t)d;
    }
    out = v;
    return true;
}

bool ReadRemoteBytes(int pid, uintptr_t addr, void* buf, size_t n) {
    if (n == 0) return true;
    // /proc/<pid>/mem 用 bs=1 + 大 skip 会按字节读并丢弃，慢到不可用
    // （对高位地址尤其明显）。与 MemSu（搜索后端，已验证可用）一致：
    // 按页 dd bs=4096 读取，再裁出目标区间。
    uintptr_t page = addr & ~(uintptr_t)4095;
    size_t off = (size_t)(addr - page);
    size_t bytes = (off + n + 4095) & ~(size_t)4095;
    if (bytes == 0) return false;
    std::vector<uint8_t> tmp(bytes);
    char cmd[320];
    snprintf(cmd, sizeof(cmd),
        "dd if=/proc/%d/mem bs=4096 skip=%llu count=%zu 2>/dev/null | xxd -p",
        pid, (unsigned long long)(page / 4096), bytes / 4096);
    std::string hex = RunSuCommand(cmd);
    unsigned char* out = tmp.data();
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    size_t got = 0;
    int hi = -1;
    for (size_t i = 0; i < hex.size() && got < bytes; ++i) {
        int d = nib(hex[i]);
        if (d < 0) continue;  // 跳过换行 / 空白
        if (hi < 0) {
            hi = d;
        } else {
            out[got++] = (unsigned char)((hi << 4) | d);
            hi = -1;
        }
    }
    if (got != bytes) return false;
    memcpy(buf, tmp.data() + off, n);
    return true;
}

// 内存搜索用的快速页对齐批量读取。addr 必须 4096 对齐，
// n 是 4096 的倍数；用块大小 dd 读取，完整扫描
// 比每字节一次 bs=1 调用快几个数量级。
bool ReadRemoteChunk(int pid, uintptr_t addr, void* buf, size_t n) {
    size_t pages = n / 4096;
    if (pages == 0 || (addr & 4095) != 0) return false;
    char cmd[320];
    snprintf(cmd, sizeof(cmd),
        "dd if=/proc/%d/mem bs=4096 skip=%llu count=%zu 2>/dev/null | xxd -p",
        pid, (unsigned long long)(addr / 4096), pages);
    std::string hex = RunSuCommand(cmd);
    unsigned char* out = static_cast<unsigned char*>(buf);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    size_t got = 0;
    int hi = -1;
    for (size_t i = 0; i < hex.size() && got < n; ++i) {
        int d = nib(hex[i]);
        if (d < 0) continue;
        if (hi < 0) {
            hi = d;
        } else {
            out[got++] = (unsigned char)((hi << 4) | d);
            hi = -1;
        }
    }
    return got > 0;
}

// 搜索改善用的批量页读取器：通过一次 su 调用
//（内部批量）读取远程进程的指定 4KB 页，而不是
// 每个 8MB 块一次 su + dd + xxd 往返。每页恰好输出 4096
// 字节（页面读取失败时输出 0），因此输出可以确定性地切分。
// 仅当整批数据丢失时才返回 false。
bool ReadRemotePages(int pid, const std::vector<uintptr_t>& pages,
                     std::vector<uint8_t>& out) {
    out.clear();
    if (pages.empty()) return true;

    constexpr size_t kBatch = 400;
    const size_t total = pages.size();
    out.resize(total * 4096);

    for (size_t base = 0; base < total; base += kBatch) {
        const size_t cnt = std::min(kBatch, total - base);
        std::string cmd = "for o in";
        for (size_t i = 0; i < cnt; ++i) {
            char num[24];
            snprintf(num, sizeof(num), " %llu",
                     (unsigned long long)(pages[base + i] / 4096));
            cmd += num;
        }
        char pbuf[16];
        snprintf(pbuf, sizeof(pbuf), "%d", pid);
        cmd += "; do dd if=/proc/";
        cmd += pbuf;
        cmd += "/mem bs=4096 skip=$o count=1 2>/dev/null || "
               "dd if=/dev/zero bs=4096 count=1 2>/dev/null; done";

        std::string raw = RunSuCommand(cmd);
        const size_t need = cnt * 4096;
        if (raw.size() < need) return false;
        memcpy(out.data() + base * 4096, raw.data(), need);
    }
    return true;
}

bool WriteRemoteDword(int pid, uintptr_t addr, uint32_t value) {
    unsigned char b0 = (unsigned char)(value & 0xff);
    unsigned char b1 = (unsigned char)((value >> 8) & 0xff);
    unsigned char b2 = (unsigned char)((value >> 16) & 0xff);
    unsigned char b3 = (unsigned char)((value >> 24) & 0xff);
    char cmd[320];
    snprintf(cmd, sizeof(cmd),
        "printf \"\\x%02x\\x%02x\\x%02x\\x%02x\" | dd of=/proc/%d/mem bs=1 seek=%llu conv=notrunc 2>&1",
        b0, b1, b2, b3, pid, (unsigned long long)addr);
    std::string out = RunSuCommand(cmd);
    // dd 成功时打印 "N+0 records in"。
    return out.find("records in") != std::string::npos;
}

extern "C" {

// 注入路径（从 assets 解压的注入器可执行文件 + APK 中
// 打包的 agent .so）。
JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeSetInjectorInfo(
    JNIEnv* env, jobject, jstring injectorPath, jstring agentPath) {
    const char* ip = injectorPath ? env->GetStringUTFChars(injectorPath, nullptr) : nullptr;
    const char* ap = agentPath ? env->GetStringUTFChars(agentPath, nullptr) : nullptr;
    {
        std::lock_guard<std::mutex> lk(g_inject_mutex);
        g_injector_path = ip ? ip : "";
        g_agent_path = ap ? ap : "";
    }
    if (ip) env->ReleaseStringUTFChars(injectorPath, ip);
    if (ap) env->ReleaseStringUTFChars(agentPath, ap);
}


// 零 ptrace 注入器路径（assets/zpt 解压后的位置）。
JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeSetZptPath(JNIEnv* env, jobject, jstring path) {
    const char* p = path ? env->GetStringUTFChars(path, nullptr) : nullptr;
    {
        std::lock_guard<std::mutex> lk(g_inject_mutex);
        g_zpt_path = p ? p : "";
    }
    if (p) env->ReleaseStringUTFChars(path, p);
    LOGI("zero-ptrace injector path = %s", g_zpt_path.c_str());
}

// 配置文件目录（App 私有 files 目录，由 Java 传入）。
JNIEXPORT void JNICALL
Java_com_Alive_Trace_MainActivity_nativeSetConfigDir(
    JNIEnv* env, jobject, jstring dir) {
    const char* d = dir ? env->GetStringUTFChars(dir, nullptr) : nullptr;
    g_config_dir = d ? d : "";
    ChannelKey::SetConfigDir(g_config_dir);
    if (d) env->ReleaseStringUTFChars(dir, d);
}

// 用途：一次调用把「su 在不在、能不能提权」的实测结论返回给 UI。
// 存在的理由：本项目所有 root 调用都以 su 为前置，而 su 是否可用
// 排查了十几轮（App 里只报一句"无法启动 su"，看不出真因）。
// 注意：JNI 符号绑在第 4 段 = 类名。这里用悬浮窗的 NativeBridge
// （injectPkgZero/injectPidZero 也走它），MainActivity 侧不再重复声明。
JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_suDiag(JNIEnv* env, jobject) {
    std::string d = BuildSuDiag();
    return env->NewStringUTF(d.c_str());
}

// 手动指定 su 路径（特殊 ROM 兜底；空串 = 恢复自动解析）。
JNIEXPORT void JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_setSuPath(JNIEnv* env, jobject, jstring path) {
    const char* p = path ? env->GetStringUTFChars(path, nullptr) : nullptr;
    SetSuPath(p ? p : "");
    if (p) env->ReleaseStringUTFChars(path, p);
}

// 断点服务启动形态自检：把"命令形式能不能用"做成 App 内可实测的结论。
// 存在的理由：`su` 只在真实 App 进程的命名空间里可用，adb shell / run-as
// 都测不出来（实测两者都 rc=127），所以这类问题必须让 App 自证。
JNIEXPORT jstring JNICALL
Java_com_Alive_Trace_overlay_NativeBridge_spawnDiag(JNIEnv* env, jobject) {
    std::string d = BuildSpawnDiag();
    return env->NewStringUTF(d.c_str());
}

} // extern "C"

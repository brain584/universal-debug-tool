// root 硬件断点服务（injector --bp）的 ImGui 侧客户端。

#include "bp/BpService.h"

#include <android/log.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <sstream>

#include "Disasm.h"

#define TAG "BpService"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// 由 native-lib.cpp（同一共享库）提供：解压出的注入器
// 可执行文件路径。
extern std::string GetInjectorPath();
extern bool ReadRemoteBytes(int pid, uintptr_t addr, void* buf, size_t n);

namespace {

// "HIT addr=0x.. tid=.. pc=0x.. x0=0x.. x1=0x.. ... sp=0x.. pc=0x.."
static bool ParseHex64(const std::string& s, uint64_t& out) {
    const char* p = s.c_str();
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    if (*p == '\0') return false;
    uint64_t v = 0;
    for (; *p; ++p) {
        int d;
        if (*p >= '0' && *p <= '9')      d = *p - '0';
        else if (*p >= 'a' && *p <= 'f') d = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') d = *p - 'A' + 10;
        else return false;
        v = (v << 4) | (uint64_t)d;
    }
    out = v;
    return true;
}

static bool ParseHitLine(const std::string& line, BpHit& hit) {
    std::istringstream ss(line);
    std::string tok;
    if (!(ss >> tok) || tok != "HIT") return false;
    bool seen_pc = false;   // 开头的 "pc=.." 是元数据，末尾的才是寄存器
    while (ss >> tok) {
        size_t eq = tok.find('=');
        if (eq == std::string::npos) continue;
        std::string key = tok.substr(0, eq);
        uint64_t v = 0;
        if (key == "addr") {
            if (!ParseHex64(tok.substr(eq + 1), v)) continue;
            hit.addr = (uintptr_t)v;
        } else if (key == "tid") {
            hit.tid = atoi(tok.c_str() + eq + 1);
        } else if (key == "pc") {
            if (!ParseHex64(tok.substr(eq + 1), v)) continue;
            if (!seen_pc) {
                hit.pc = v;
                seen_pc = true;
            } else {
                BpHitReg r;
                r.name = key;
                r.value = v;
                hit.regs.push_back(std::move(r));
            }
        } else if (key == "stack") {
            // "stack=0x<sp>>0x..>0x.."：第一项是起始地址
            // (sp)，其余是 sp、sp+8 ... 处的 8 字节数据
            std::string sv = tok.substr(eq + 1);
            size_t start = 0;
            while (start <= sv.size()) {
                size_t sep = sv.find('>', start);
                std::string part = (sep == std::string::npos)
                                       ? sv.substr(start)
                                       : sv.substr(start, sep - start);
                uint64_t sv2 = 0;
                if (ParseHex64(part, sv2)) {
                    if (hit.sp == 0 && hit.stack.empty())
                        hit.sp = sv2;              // 第一项 = 起始地址
                    else
                        hit.stack.push_back(sv2);  // sp、sp+8 ... 处的 8 字节数据
                }
                if (sep == std::string::npos) break;
                start = sep + 1;
            }
        } else {
            if (!ParseHex64(tok.substr(eq + 1), v)) continue;
            BpHitReg r;
            r.name = key;
            r.value = v;
            hit.regs.push_back(std::move(r));
        }
    }
    return hit.addr != 0 || !hit.regs.empty();
}

} // 匿名命名空间

BpService g_bp;

BpService::~BpService() {
    Stop();
}

bool BpService::IsRunning() const {
    return m_running.load();
}

int BpService::TargetPid() const {
    return m_pid.load();
}

void BpService::Start(int pid) {
    if (m_running.load()) return;
    Stop();   // 回收之前的工作线程（如果有）
    if (!Spawn(pid)) {
        SetStatus("错误: 无法启动断点服务（su 失败？）");
        return;
    }
    m_pid.store(pid);
    m_running.store(true);
    SetStatus("启动中...");
    m_thread = std::thread(&BpService::ReadLoop, this);
    LOGI("breakpoint service start pid=%d", pid);
}

bool BpService::Spawn(int pid) {
    std::string inj = GetInjectorPath();
    if (inj.empty()) {
        SetStatus("错误: injector 路径未设置");
        return false;
    }

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "su -c '%s --bp %d' 2>/dev/null",
             inj.c_str(), pid);

    int to_child[2], from_child[2];
    if (pipe(to_child) != 0 || pipe(from_child) != 0) return false;

    pid_t child = fork();
    if (child < 0) {
        close(to_child[0]); close(to_child[1]);
        close(from_child[0]); close(from_child[1]);
        return false;
    }
    if (child == 0) {
        dup2(to_child[0], STDIN_FILENO);
        dup2(from_child[1], STDOUT_FILENO);
        close(to_child[0]); close(to_child[1]);
        close(from_child[0]); close(from_child[1]);
        execl("/system/bin/sh", "sh", "-c", cmd, (char*)nullptr);
        _exit(127);
    }

    close(to_child[0]);
    close(from_child[1]);
    m_child = (int)child;
    m_write_fd = to_child[1];
    m_read_fd = from_child[0];
    return true;
}

void BpService::Stop() {
    if (m_thread.joinable()) {
        m_running.store(false);
        if (m_child > 0) kill(m_child, SIGTERM);
        if (m_write_fd >= 0) close(m_write_fd);   // 子进程 stdin 到达 EOF
        m_write_fd = -1;
        m_thread.join();
        if (m_child > 0) {
            int st = 0;
            waitpid(m_child, &st, WNOHANG);   // 如果子进程已退出则回收
        }
    }
    if (m_read_fd >= 0) close(m_read_fd);
    m_read_fd = -1;
    m_child = -1;
    m_pid.store(0);
    SetStatus("已停止");
}

void BpService::Send(const std::string& line) {
    if (!m_running.load() || m_write_fd < 0) return;
    std::string s = line;
    s += '\n';
    const char* p = s.data();
    size_t left = s.size();
    while (left > 0) {
        ssize_t w = write(m_write_fd, p, left);
        if (w <= 0) break;
        p += w;
        left -= (size_t)w;
    }
}

void BpService::ReadLoop() {
    // 给子进程一点启动时间；如果它立即退出（例如 `su`
    // 失败），报告具体原因而不是笼统的 "stopped"。
    usleep(150 * 1000);
    int wstatus = 0;
    pid_t wres = m_child > 0 ? waitpid(m_child, &wstatus, WNOHANG) : -1;
    if (wres == m_child) {
        SetStatus("错误: 断点服务未启动（su 失败或无 root 权限）");
        m_running.store(false);
        return;
    }

    char buf[4096];
    std::string pending;
    while (m_running.load()) {
        struct pollfd pfd;
        pfd.fd = m_read_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int rc = poll(&pfd, 1, 300);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (rc == 0) continue;
        if (pfd.revents & (POLLHUP | POLLERR)) break;
        if (!(pfd.revents & POLLIN)) continue;

        ssize_t n = read(m_read_fd, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        buf[n] = '\0';
        pending.append(buf, (size_t)n);

        size_t nl;
        while ((nl = pending.find('\n')) != std::string::npos) {
            std::string line = pending.substr(0, nl);
            pending.erase(0, nl + 1);
            if (line.empty()) continue;
            LOGI("bp line: %s", line.c_str());

            if (line.rfind("HIT ", 0) == 0) {
                BpHit hit;
                if (ParseHitLine(line, hit)) {
                    // 尽力而为：反汇编 pc 处的指令（ARM64）。
                    // 在互斥锁外执行：远程读取耗时，
                    // 不能阻塞渲染线程上的 Hits()/Status()。
                    int pid = m_pid.load();
                    if (pid > 0 && hit.pc != 0) {
                        uint8_t bytes[16] = {0};
                        if (ReadRemoteBytes(pid, (uintptr_t)hit.pc, bytes,
                                            sizeof(bytes))) {
                            std::vector<udt_disasm::Insn> insns;
                            if (udt_disasm::Disassemble(
                                    udt_disasm::Arch::Arm64, bytes,
                                    sizeof(bytes), hit.pc, 1, insns) &&
                                !insns.empty()) {
                                hit.disasm = insns[0].mnemonic;
                                if (!insns[0].op_str.empty()) {
                                    hit.disasm += " ";
                                    hit.disasm += insns[0].op_str;
                                }
                            }
                        }
                    }
                    {
                        std::lock_guard<std::mutex> lk(m_mu);
                        m_hits.push_back(std::move(hit));
                        if (m_hits.size() > 30) m_hits.pop_front();
                    }
                }
            } else if (line.rfind("ERR ", 0) == 0) {
                SetStatus("错误: " + line.substr(4));
                SetLastLine(line);
            } else if (line.rfind("INFO breakpoint service started", 0) == 0) {
                SetStatus("运行中 (pid=" + std::to_string(m_pid.load()) + ")");
                SetLastLine(line);
            } else if (line.rfind("OK ", 0) == 0) {
                SetLastLine(line);
            }
        }
    }

    if (m_running.load()) {
        SetStatus("已停止 (断点服务进程退出)");
    }
    m_running.store(false);
}

void BpService::ClearHits() {
    std::lock_guard<std::mutex> lk(m_mu);
    m_hits.clear();
}

std::vector<BpHit> BpService::Hits() const {
    std::vector<BpHit> out;
    std::lock_guard<std::mutex> lk(m_mu);
    out.reserve(m_hits.size());
    for (const BpHit& h : m_hits) out.push_back(h);
    return out;
}

std::string BpService::Status() const {
    std::lock_guard<std::mutex> lk(m_mu);
    return m_status;
}

std::string BpService::LastLine() const {
    std::lock_guard<std::mutex> lk(m_mu);
    return m_last_line;
}

void BpService::SetStatus(const std::string& s) {
    std::lock_guard<std::mutex> lk(m_mu);
    m_status = s;
}

void BpService::SetLastLine(const std::string& s) {
    std::lock_guard<std::mutex> lk(m_mu);
    m_last_line = s;
}

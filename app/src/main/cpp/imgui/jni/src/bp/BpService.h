#pragma once

#include <atomic>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// 断点命中网格中显示的一个寄存器。
struct BpHitReg {
    std::string name;
    uint64_t    value = 0;
};

// 从 root 断点服务解析出的一条 "HIT ..." 记录。
struct BpHit {
    uintptr_t addr = 0;
    int       tid  = 0;
    uint64_t  pc   = 0;
    uint64_t  sp   = 0;                 // 堆栈起始地址（sp）
    std::vector<uint64_t> stack;        // sp、sp+8、sp+16 ... 处的 8 字节数据
    std::string disasm;   // pc 处的 ARM64 指令（尽力而为）
    std::vector<BpHitReg> regs;
};

// root 硬件断点服务的客户端。
//
// 启动注入器可执行文件（在 `su` 下运行 `injector --bp <pid>`）
// 并通过管道与它通信：
//   - Send() 向子进程 stdin 写入行命令；
//   - 读取线程从子进程 stdout 消费 "OK/ERR/INFO" 响应和 "HIT ..." 事件
//     。
//
// 子进程完全由应用控制（私有管道），
// 因此该通道无需 socket 或密钥交换。
class BpService {
public:
    BpService() = default;
    ~BpService();

    void Start(int targetPid);
    void Stop();

    bool IsRunning() const;
    int  TargetPid() const;

    void Send(const std::string& line);   // 即发即忘的命令

    std::string Status() const;           // 供 UI 显示的服务状态
    std::string LastLine() const;         // 最近一条 OK/ERR/INFO 响应
    std::vector<BpHit> Hits() const;      // 最近的命中记录（旧的在前面）
    void ClearHits();

private:
    bool Spawn(int pid);
    void ReadLoop();
    void SetStatus(const std::string& s);
    void SetLastLine(const std::string& s);

    std::thread       m_thread;
    std::atomic<bool> m_running{false};
    std::atomic<int>  m_pid{0};

    int m_child = -1;
    int m_read_fd = -1;
    int m_write_fd = -1;

    mutable std::mutex m_mu;
    std::string m_status;
    std::string m_last_line;
    std::deque<BpHit> m_hits;
};

// imgui UI（main_ui.cpp）使用的全局单例，
// 与渲染器一起停止（native-lib.cpp 可在销毁时调用 Stop）。
extern BpService g_bp;

#ifndef UDT_SOCKET_CLIENT_H
#define UDT_SOCKET_CLIENT_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

// imgui 悬浮层使用的加密通道客户端。
//
// 连接到被注入 agent 的 Unix socket 服务端
// (/data/local/tmp/universal_debug_tool.sock)，加载 agent 写入的共享 ChaCha20 密钥
// 并双向交换分帧加密消息：
// 消息方向如下：
//   - 命令（本客户端 -> agent），agent 返回响应；
//   - 主动事件（agent -> 本客户端），文本以 "EVENT " 开头。
class SocketClient {
public:
    SocketClient();
    ~SocketClient();

    void ConnectAsync();      // 后台连接，绝不阻塞调用方
    void Disconnect();        // 断开连接并停止工作线程

    // 设置目标包名，本客户端将连接该包对应 agent 的 socket
    //（用于推导抽象 socket 名）。在 ConnectAsync 之前调用。
    void SetTargetPackage(const std::string& pkg);

    bool IsConnected() const;
    bool IsConnecting() const;
    int  AgentPid() const;

    std::string StatusText() const;    // 例如 "已连接(pid=1234)" / "未连接: <原因>"
    std::string LastError() const;     // 最近一次连接 / 加载失败原因（正常时为空）
    std::string LastEvent() const;     // agent 推送的最近一条 "EVENT ..."
    std::string LastResponse() const;  // agent 的最近一条普通响应

    // 发送命令并最多等待 timeoutMs 毫秒接收响应。
    std::string SendCommand(const std::string& cmd, int timeoutMs = 3000);

private:
    bool LoadKeyFile();
    int  ConnectOnce();
    int  SpawnRelay(int& read_fd, int& write_fd);
    std::string SocketName() const;
    void ConnectLoop();
    void RecvLoop(int fd);
    void SetStatus(const std::string& s);
    void SetError(const std::string& e);

    std::thread               m_thread;
    std::atomic<bool>         m_running{false};
    std::atomic<bool>         m_connected{false};
    std::atomic<bool>         m_connecting{false};
    std::atomic<int>          m_agent_pid{-1};

    mutable std::mutex        m_status_mutex;
    std::string               m_status;

    mutable std::mutex        m_info_mutex;
    std::string               m_last_error;
    std::string               m_last_event;
    std::string               m_last_response;

    mutable std::mutex        m_io_mutex;   // 保护 m_fd + m_send_counter
    int                       m_fd = -1;
    int                       m_relay_read = -1;
    int                       m_relay_write = -1;
    int                       m_relay_pid = -1;
    std::string               m_target_pkg;   // 由 m_io_mutex 保护
    uint32_t                  m_send_counter = 0;

    uint8_t                   m_key[32];
    uint8_t                   m_nonce[12];

    std::mutex                m_resp_mutex; // 保护 m_resp_ready / m_resp_text
    std::condition_variable   m_resp_cv;
    bool                      m_resp_ready = false;
    std::string               m_resp_text;
};

// imgui UI（ui.cpp / main_ui.cpp）使用的全局单例，
// 与渲染器一起停止（native-lib.cpp）。
extern SocketClient g_socket;

#endif // UDT_SOCKET_CLIENT_H

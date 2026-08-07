#ifndef UDT_AGENT_SOCKET_H
#define UDT_AGENT_SOCKET_H

// Agent 侧加密通道服务端。
//
// 由 agent 构造函数启动（见 main.cpp）。生成随机
// ChaCha20 密钥文件并打开 Unix 域 socket 服务端；imgui 悬浮层
// 连接它并交换分帧加密文本消息。

#ifdef __cplusplus
extern "C" {
#endif

// 启动服务端线程。幂等：可安全调用多次。
// 成功返回 0，线程创建失败返回 -1。
int AgentSocketStart();

// 停止服务端，关闭监听 socket 并删除 socket 文件。
void AgentSocketStop();

#ifdef __cplusplus
}
#endif

#endif // UDT_AGENT_SOCKET_H

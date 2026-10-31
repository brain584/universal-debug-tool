#ifndef UDT_AGENT_SOCKET_H
#define UDT_AGENT_SOCKET_H

// Agent 侧加密通道服务端。
//
// 密钥/对端 uid **不再落盘、也不在加载时生成**：ptrace 注入器把 56B
// AgentAuthBlob 写进目标进程内存后调用 AgentStartWithAuth() 才监听；
// 零 ptrace（data-only）路径则由 agent 构造函数从 root 预置的交接文件读取
// （见 main.cpp 的 TryStartAgentFromHandoff）。抽象 socket，无 socket 文件；
// 客户端连接后交换分帧加密文本消息。

#if defined(__GNUC__)
// 注入器通过 ELF 符号表 dlsym AgentStartWithAuth / JNI_OnLoad；
// agent 现在整体 -fvisibility=hidden，必须显式标这两个（socket 头只标这一个）。
#define AGENT_API __attribute__((visibility("default")))
#else
#define AGENT_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

// 启动服务端线程。幂等：可安全调用多次。
// 成功返回 0，线程创建失败返回 -1。
int AgentSocketStart();

// 用调用方提供的 56B AgentAuthBlob（magic/version/key[32]/nonce[12]/client_uid）
// 设置认证材料并启动监听。blob 可以位于任意内存（注入器写进目标进程的远程内存，
// 或 agent 自己栈上的交接副本）。
// 返回 0 = 已启动（或已在运行）；-1 = blob 为空；-2 = blob 校验失败/启动失败。
AGENT_API int AgentStartWithAuth(const void* blob);

// 停止服务端，关闭监听 socket 并删除 socket 文件。
void AgentSocketStop();

#ifdef __cplusplus
}
#endif

#endif // UDT_AGENT_SOCKET_H

package com.Alive.Trace.overlay

import android.content.Context
import java.io.BufferedInputStream
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets

/**
 *
 * ## 它是干什么的
 * 让**电脑在 cmd 里就能编辑并执行 Lua 脚本**，不需要打开手机的悬浮窗。
 * 电脑侧通过 `adb forward tcp:28471 tcp:28471` 把本机的 127.0.0.1:28471 打到手机的
 * 127.0.0.1:28471（本类监听的端口）上，然后说一个极简的行协议即可。
 *
 * ## 为什么必须由 App 开这个口（而不是纯 adb 就够）
 * Lua 真正的执行方是**目标进程里被注入的 agent**，通道是一个 ChaCha20 加密的
 * **抽象命名空间 Unix socket**（`udt_debug_chan`），密钥只有 root 能读：
 *   · `adb forward` 只能转发 TCP，够不到抽象 Unix socket；
 *   · `adb shell` 在本机拿不到 root（实测 `su: inaccessible or not found`, rc=127），
 *     因为 KernelSU 的 su 只出现在已授权 App 的挂载命名空间里。
 * 所以 privileged 的那一段只能由 App 自己做——也就是本类：
 * 电脑 →(adb forward)→ 本类 →(App 自己的 root/socket 通道)→ agent 执行。
 *
 * ## 协议（行式 + 长度分帧，UTF-8）
 * 请求：`CMD\n`；带载荷的命令随后是 `LEN\n` 再跟恰好 LEN 字节。
 * 响应：`OK\nLEN\n<payload>` 或 `ERR\nLEN\n<message>`。
 *
 * 命令表：
 *   PING                      → "pong"
 *   INFO                      → 多行 key=value（端口/是否连上 agent/草稿路径/IDE 命令）
 *   GET_SCRIPT                → 当前草稿脚本全文
 *   PUT_SCRIPT   <len><body>  → 保存草稿
 *   RUN                       → 执行当前草稿，返回输出
 *   RUN_SCRIPT   <len><body>  → 保存并执行该脚本，返回输出
 *   GET_LOGS                  → 取 agent 的 Lua print 日志
 *   GET_IDE / SET_IDE <len>   → 读写电脑端 IDE 启动命令（如 `code -n "{file}"`）
 *   RESET_SCRIPT              → 草稿恢复为模板
 *   TOOL_LIST                 → 工具清单（JSON 一行）
 *   TOOL_CALL    <len><body>  → 调用工具，body 为 JSON: {"name":..,"args":{..}}
 *   QUIT                      → 断开
 *
 * ## 与 MCP 的关系
 * `TOOL_LIST` / `TOOL_CALL` 就是给电脑端 MCP 代理用的：电脑侧的 stdio MCP 服务把
 * MCP 的 tools/list 与 tools/call 映射到这两个命令上，于是「电脑的 MCP 能调用手机工具」
 * 与「脚本模式」共用同一个 adb 通道，不需要第二个端口。
 */
object AdbBridge {
    /** 固定端口：电脑侧的 .bat 里写死同一个值，改这里要同步改 bat。 */
    const val PORT = 28471

    private const val PREF = "overlay"
    private const val KEY_ENABLED = "adb_script_enabled"
    private const val KEY_MCP = "mcp_enabled"
    private const val KEY_IDE = "adb_ide_cmd"

    private const val DRAFT_REL = "scripts/last.lua"
    /** P1-12：注入后自动执行脚本的固定路径（与草稿分离，避免被 RUN/PUT_SCRIPT 覆盖）。 */
    private const val AUTORUN_REL = "scripts/autorun.lua"
    private const val TEMPLATE =
        "-- ATrace lua（由电脑 cmd 编辑）\n" +
        "-- local base = getBase(\"libagent.so\")\n"

    @Volatile private var serverSocket: ServerSocket? = null
    @Volatile private var acceptThread: Thread? = null
    @Volatile private var running = false
    @Volatile private var lastError: String = ""

    private fun prefs(ctx: Context) = ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)

    // ── 偏好 ──
    fun isEnabled(ctx: Context): Boolean =
        runCatching { prefs(ctx).getBoolean(KEY_ENABLED, false) }.getOrDefault(false)

    fun setEnabled(ctx: Context, on: Boolean) {
        prefs(ctx).edit().putBoolean(KEY_ENABLED, on).apply()
    }

    /**
     * MCP 开关（第二个 checkbox）。
     * 与脚本模式**共用同一个端口**，但工具调用（TOOL_*）只有它打开时才被允许，
     * 这样用户可以在"只给电脑编辑脚本"和"也让 AI 调手机工具"之间自由取舍。
     */
    fun isMcpEnabled(ctx: Context): Boolean =
        runCatching { prefs(ctx).getBoolean(KEY_MCP, false) }.getOrDefault(false)

    fun setMcpEnabled(ctx: Context, on: Boolean) {
        prefs(ctx).edit().putBoolean(KEY_MCP, on).apply()
    }

    fun ideCmd(ctx: Context): String =
        prefs(ctx).getString(KEY_IDE, "") ?: ""

    fun setIdeCmd(ctx: Context, s: String) {
        prefs(ctx).edit().putString(KEY_IDE, s).apply()
    }

    fun isRunning(): Boolean = running
    fun errorText(): String = lastError

    private fun draftFile(ctx: Context): File =
        File(ctx.filesDir, DRAFT_REL).apply { parentFile?.mkdirs() }

    /**
     * P1-12：注入后自动执行脚本的固定路径 `<filesDir>/scripts/autorun.lua`。
     * 由 MCP 的 get_autorun / set_autorun 与 inject_pid 的自动执行共用，
     * 保证路径只在这一处定义（**不是**草稿 last.lua）。
     */
    internal fun autorunFile(ctx: Context): File =
        File(ctx.filesDir, AUTORUN_REL).apply { parentFile?.mkdirs() }

    private fun readDraft(ctx: Context): String =
        runCatching { draftFile(ctx).readText() }.getOrDefault(TEMPLATE)

    private fun writeDraft(ctx: Context, s: String) {
        runCatching { draftFile(ctx).writeText(s) }
    }

    // ── 启停 ──
    /** 启动监听；返回给 UI 显示的一句话（成功或失败原因）。幂等。 */
    /**
     * 清理历史遗留的 injector 子进程。
     *
     * 孤儿进程，并**继承了 28471 的监听 fd** —— 端口一直处于 LISTEN 但没人 accept，
     * 新进程 bind 失败、客户端连接全部超时。App 启动时必须先清掉它们。
     */
    private fun killStaleInjectorHelpers() {
        runCatching {
            NativeBridge.runSuShell(
                "pkill -f 'injector --relay' 2>/dev/null; " +
                "pkill -f '/files/injector -i ' 2>/dev/null; true")
        }
    }

    @Synchronized
    fun start(ctx: Context): String {
        if (running) return "已在监听 127.0.0.1:$PORT"
        return try {
            // 只绑 127.0.0.1：不对局域网暴露，电脑必须经 adb forward 才能进来。
            val ss = ServerSocket(PORT, 8, InetAddress.getByName("127.0.0.1"))
            serverSocket = ss
            running = true
            lastError = ""
            acceptThread = Thread {
                while (running) {
                    val sock = try {
                        ss.accept()
                    } catch (e: Exception) {
                        break
                    }
                    Thread { handleClient(ctx.applicationContext, sock) }
                        .apply { isDaemon = true }.start()
                }
            }.apply { isDaemon = true; name = "adb-bridge-accept"; start() }
            "监听 127.0.0.1:$PORT"
        } catch (e: Exception) {
            // 端口被孤儿进程继承时 bind 会失败：清掉孤儿再试一次。
            lastError = e.message ?: e.toString()
            if (lastError.contains("in use", ignoreCase = true)) {
                killStaleInjectorHelpers()
                Thread.sleep(400)
                return try {
                    val ss = ServerSocket(PORT, 8, InetAddress.getByName("127.0.0.1"))
                    serverSocket = ss
                    running = true
                    lastError = ""
                    acceptThread = Thread {
                        while (running) {
                            val sock = try { ss.accept() } catch (e2: Exception) { break }
                            Thread { handleClient(ctx.applicationContext, sock) }
                                .apply { isDaemon = true }.start()
                        }
                    }.apply { isDaemon = true; name = "adb-bridge-accept"; start() }
                    "监听 127.0.0.1:$PORT（已清理孤儿进程后重试成功）"
                } catch (e2: Exception) {
                    lastError = e2.message ?: e2.toString()
                    running = false
                    "启动失败: $lastError"
                }
            }
            running = false
            "启动失败: $lastError"
        }
    }

    @Synchronized
    fun stop() {
        running = false
        runCatching { serverSocket?.close() }
        serverSocket = null
        acceptThread = null
    }

    /** 按偏好自动应用（App 启动/开关切换时调用）。两个开关任一打开就监听。 */
    fun applyPref(ctx: Context): String {
        val want = isEnabled(ctx) || isMcpEnabled(ctx)
        return if (want) start(ctx) else { stop(); "已关闭" }
    }

    // ── agent 连接（adb 桥命令与 MCP 工具共用）──
    /**
     * 让 agent 连接一次（幂等）。返回 (是否连上, 说明)。
     *
     * 这里先强制断开清状态，再连，并**轮询最多 4s 等真正连上**。
     */
    internal fun connectAgentOnce(timeoutMs: Long = 4000): Pair<Boolean, String> {
        val pkg = OState.pkg.ifEmpty { OState.pname }
        if (pkg.isEmpty()) return false to "ERR: 手机端还未选择目标进程"
        runCatching { NativeBridge.socketDisconnect() }
        runCatching { Thread.sleep(150) }
        runCatching { NativeBridge.socketSetTarget(pkg) }
        runCatching { NativeBridge.socketConnect() }
        var ok = false
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            runCatching { Thread.sleep(200) }
            ok = runCatching { NativeBridge.socketIsConnected() }.getOrDefault(false)
            if (ok) break
        }
        val st = runCatching { NativeBridge.socketStatus() }.getOrDefault("")
        return if (ok) true to "connected ($pkg)"
        else false to "ERR: $st (目标进程里可能没有 agent，请重新注入)"
    }

    // ── 单连接处理 ──
    private fun handleClient(ctx: Context, sock: Socket) {
        val input: InputStream = BufferedInputStream(sock.getInputStream())
        val out: OutputStream = sock.getOutputStream()
        try {
            while (running) {
                val line = readLine(input) ?: break
                val cmd = line.trim()
                if (cmd.isEmpty()) continue
                when (cmd) {
                    "PING" -> respond(out, true, "pong")
                    "INFO" -> respond(out, true, infoText(ctx))
                    "GET_SCRIPT" -> respond(out, true, readDraft(ctx))
                    "PUT_SCRIPT" -> {
                        val body = readPayload(input)
                        writeDraft(ctx, body)
                        respond(out, true, "saved")
                    }
                    "RUN" -> {
                        // 注意：执行失败时 respond 成 ERR 帧，客户端/MCP 才能正确判断
                        val r = runLua(readDraft(ctx))
                        respond(out, !r.startsWith("ERR"), r)
                    }
                    "RUN_SCRIPT" -> {
                        val body = readPayload(input)
                        writeDraft(ctx, body)
                        val r = runLua(body)
                        respond(out, !r.startsWith("ERR"), r)
                    }
                    "GET_LOGS" -> respond(out, true, luaLogs())
                    // 模块列表：给电脑端做 "{{AGENT}}" 占位符替换用。
                    // 注入的 agent 是以 memfd 方式加载的，名字是 /memfd:xxxxx (deleted)，
                    // **每次重新注入都会变**，所以不能让脚本写死。
                    "LIST_MODULES" -> {
                        if (!runCatching { NativeBridge.socketIsConnected() }.getOrDefault(false)) {
                            respond(out, false, "ERR: 未连接 agent")
                        } else {
                            val s = runCatching { NativeBridge.socketModules() }.getOrDefault("")
                            respond(out, s.isNotBlank(), s)
                        }
                    }
                    // 让电脑端也能（重新）连接 agent：App 重启 / 目标重新注入后，
                    // 用户不必再回手机点「连接 agent」。
                    "CONNECT_AGENT" -> {
                        val (ok, msg) = connectAgentOnce()
                        respond(out, ok, msg)
                    }
                    "AGENT_STATUS" -> {
                        val ok = runCatching { NativeBridge.socketIsConnected() }
                            .getOrDefault(false)
                        val st = runCatching { NativeBridge.socketStatus() }.getOrDefault("")
                        val detail = if (ok) {
                            runCatching { NativeBridge.socketAgentStatus() }.getOrDefault("")
                        } else ""
                        respond(out, true, (if (ok) "connected" else "not_connected") +
                                (if (st.isNotBlank()) " | $st" else "") +
                                (if (detail.isNotBlank()) "\n" + detail.trim() else ""))
                    }
                    // 电脑端触发注入（payload = pid 文本）。成功后自动连 agent。
                    "INJECT_PID" -> {
                        val pid = readPayload(input).trim().toIntOrNull() ?: 0
                        if (pid <= 0) {
                            respond(out, false, "ERR: 需要 pid（在载荷里传数字）")
                        } else {
                            val (ok, msg) = McpTools.injectByPid(pid)
                            respond(out, ok, msg)
                        }
                    }
                    // 诊断：确认 App 通过 su 拿到的 uid/上下文（注入依赖 root）。
                    "SU_ID" -> respond(out, true,
                        runCatching { NativeBridge.runSuShell("id") }.getOrDefault(""))
                    "GET_IDE" -> respond(out, true, ideCmd(ctx))
                    "SET_IDE" -> {
                        val body = readPayload(input)
                        setIdeCmd(ctx, body)
                        respond(out, true, "ide_saved")
                    }
                    "RESET_SCRIPT" -> {
                        writeDraft(ctx, TEMPLATE)
                        respond(out, true, TEMPLATE)
                    }
                    "TOOL_LIST" -> if (!isMcpEnabled(ctx)) {
                        respond(out, false, "ERR: MCP 未开启（选项页勾选「MCP 工具通道」）")
                    } else {
                        respond(out, true, McpTools.listJson())
                    }
                    "TOOL_CALL" -> {
                        val body = readPayload(input)
                        if (!isMcpEnabled(ctx)) {
                            respond(out, false, "ERR: MCP 未开启（选项页勾选「MCP 工具通道」）")
                        } else {
                            val r = McpTools.call(ctx, body)
                            respond(out, r.first, r.second)
                        }
                    }
                    "QUIT" -> {
                        respond(out, true, "bye")
                        break
                    }
                    else -> respond(out, false, "unknown command: $cmd")
                }
            }
        } catch (_: Exception) {
            // 电脑端断开就结束这个连接，不影响服务
        } finally {
            runCatching { sock.close() }
        }
    }

    /** 给电脑端看的状态。 */
    private fun infoText(ctx: Context): String {
        val connected = runCatching { NativeBridge.socketIsConnected() }.getOrDefault(false)
        return buildString {
            appendLine("port=$PORT")
            appendLine("agent_connected=$connected")
            appendLine("draft=" + draftFile(ctx).absolutePath)
            appendLine("ide_cmd=" + ideCmd(ctx))
            appendLine("device=" + android.os.Build.MODEL)
            append("script_mode=").append(isEnabled(ctx))
        }
    }

    // ── Lua 执行（与 UI 的「执行」同一套链路）──
    // 供电脑端 RUN 与 MCP 的 run_lua 工具共用（internal 让 McpTools 能调用）。
    internal fun runLuaForTools(script: String): String = runLua(script)

    /** 给 MCP agent_logs 用：返回 agent 全部 Lua 日志。 */
    internal fun toolLogs(): String = luaLogs()

    /**
     * 执行一段 Lua，返回**本次执行**的输出。
     *
     * 导致电脑端看到一大坨旧输出、本次结果被埋在最后（用户反馈"cmd 上无输出"）。
     * 现在改为**水位法**：
     *   1) 执行前记下日志总数（水位）；
     *   2) 执行后轮询，只取水位之后的新增日志；
     *   3) 最多等 2.5s，且抓到的第一波之后再等 200ms 补一次（异步 print）。
     */
    private fun runLua(script: String): String {
        if (!runCatching { NativeBridge.socketIsConnected() }.getOrDefault(false)) {
            return "ERR: SO 通道未连接。请在手机端注入 agent 并连接（选项页 →「连接 agent」）后重试。"
        }
        val watermark = rawLogCount()
        val sent = runCatching { NativeBridge.socketSendLua(script) }
            .getOrDefault("ERR: 发送失败")

        var newLogs: List<String> = emptyList()
        val deadline = System.currentTimeMillis() + 2500
        var rounds = 0
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(if (rounds == 0) 100L else 120L)
            rounds++
            val (count, lines) = parseRawLogs()
            if (count > watermark) {
                newLogs = takeAfter(lines, watermark)
                // 再等一小会儿，接住异步/延后输出的 print
                Thread.sleep(200)
                val (count2, lines2) = parseRawLogs()
                if (count2 > count) newLogs = takeAfter(lines2, watermark)
                break
            }
        }
        return (listOf(sent.trim()) + newLogs)
            .filter { it.isNotBlank() }
            .joinToString("\n")
    }

    /** 取下标 from 之后的元素（容错：from 越界时返回全部）。 */
    private fun takeAfter(lines: List<String>, from: Int): List<String> =
        if (from in 0 until lines.size) lines.drop(from) else lines

    private fun rawLogCount(): Int = parseRawLogs().first

    /**
     * 解析 agent 的 `lua_logs 0` 返回：
     *   第一行 = 当前日志总数；其余行 = 从 0 开始的全部日志（非破坏性读取）。
     * 返回 (总数, 全部日志行)。
     */
    private fun parseRawLogs(): Pair<Int, List<String>> {
        val raw = runCatching { NativeBridge.socketLuaLogs() }.getOrDefault("")
        if (raw.isBlank()) return 0 to emptyList()
        val all = raw.split('\n').map { it.trimEnd('\r') }
        val count = all.firstOrNull()?.trim()?.toIntOrNull() ?: 0
        val body = all.drop(1).filter { it.isNotBlank() }
        return count to body
    }

    private fun luaLogs(): String {
        // GET_LOGS 仍返回全部日志（供客户端 `l` 命令查看完整历史）
        return parseRawLogs().second.joinToString("\n")
    }

    // ── 帧读写 ──
    private fun readLine(input: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\n'.code) return sb.toString()
            if (b != '\r'.code) sb.append(b.toChar())
        }
    }

    /** 读 `LEN\n` + 恰好 LEN 字节。 */
    private fun readPayload(input: InputStream): String {
        val lenLine = readLine(input) ?: return ""
        val len = lenLine.trim().toIntOrNull() ?: return ""
        if (len <= 0) return ""
        val buf = ByteArray(len)
        var off = 0
        while (off < len) {
            val n = input.read(buf, off, len - off)
            if (n < 0) break
            off += n
        }
        return String(buf, 0, off, StandardCharsets.UTF_8)
    }

    private fun respond(out: OutputStream, ok: Boolean, body: String) {
        val bytes = body.toByteArray(StandardCharsets.UTF_8)
        val head = (if (ok) "OK" else "ERR") + "\n" + bytes.size + "\n"
        out.write(head.toByteArray(StandardCharsets.UTF_8))
        out.write(bytes)
        out.flush()
    }
}

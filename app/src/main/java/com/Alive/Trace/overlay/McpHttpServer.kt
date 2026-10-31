package com.Alive.Trace.overlay

import android.content.Context
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedInputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * 手机本地 MCP 服务（HTTP，2026-10-23 新增）。
 *
 * ## 为什么需要它
 * 用户手机上有一个 AI App，可以通过 **URL** 导入 MCP 服务器。
 * 而 `atrace_mcp.py` 是跑在电脑上的 stdio 进程——手机 App 没法启动电脑上的程序，
 * 所以必须由 **ATrace 自己在手机里**提供 MCP 服务，App 连 `127.0.0.1` 即可。
 *
 * ## 同时支持两种传输（兼容性最好）
 *  1) **Streamable HTTP**：`POST http://127.0.0.1:28472/mcp`
 *     - 请求体是 JSON-RPC，响应体直接是 JSON-RPC 应答（`Content-Type: application/json`）。
 *     适用于 `"type": "http"` / `"streamableHttp"` 的客户端。
 *  2) **HTTP+SSE（旧协议）**：
 *     - `GET /sse` 建立事件流，先下发 `event: endpoint` 告知 POST 地址；
 *     - 客户端 `POST /messages?sessionId=...` 发 JSON-RPC，应答通过 SSE 流推回。
 *     适用于 `"type": "sse"` 的客户端。
 *
 * 两者共用同一套工具实现（[McpTools]），和电脑端 MCP、adb 桥完全一致：
 * `run_lua` / `agent_status` / `list_processes` / `list_modules` / `mem_read` / `mem_write`。
 *
 * ## 安全
 * 只绑 `127.0.0.1`（不对外网/局域网暴露），且受选项页「MCP 工具通道」开关控制。
 * 执行类工具（run_lua）本身仍需要目标进程里已注入 agent；读写内存仍需要 root。
 */
object McpHttpServer {
    /** 手机本地 MCP 端口（与 adb 桥的 28471 分开，互不干扰）。 */
    const val PORT = 28472

    private const val TAG = "ATraceMcp"
    private const val PROTOCOL_DEFAULT = "2024-11-05"
    private val PROTOCOL_OK = setOf("2024-11-05", "2025-03-26", "2025-06-18")

    @Volatile private var serverSocket: ServerSocket? = null
    @Volatile private var running = false
    @Volatile private var lastError: String = ""

    /** SSE 会话：sessionId -> 输出流（用于把应答推回事件流）。 */
    private val sseSessions = ConcurrentHashMap<String, OutputStream>()

    fun isRunning(): Boolean = running
    fun errorText(): String = lastError
    fun statusText(): String =
        if (running) "本地 MCP 监听中 http://127.0.0.1:$PORT/mcp"
        else "本地 MCP 未启动" + if (lastError.isNotBlank()) "（$lastError）" else ""

    @Synchronized
    fun start(ctx: Context): String {
        if (running) return statusText()
        return try {
            val ss = ServerSocket(PORT, 16, InetAddress.getByName("127.0.0.1"))
            serverSocket = ss
            running = true
            lastError = ""
            Thread {
                while (running) {
                    val sock = try {
                        ss.accept()
                    } catch (e: Exception) {
                        break
                    }
                    Thread { handleConnection(ctx.applicationContext, sock) }
                        .apply { isDaemon = true }.start()
                }
            }.apply { isDaemon = true; name = "mcp-http-accept"; start() }
            Log.i(TAG, "本地 MCP 已启动: ${statusText()}")
            statusText()
        } catch (e: Exception) {
            lastError = e.message ?: e.toString()
            running = false
            Log.w(TAG, "本地 MCP 启动失败: $lastError")
            "启动失败: $lastError"
        }
    }

    @Synchronized
    fun stop() {
        running = false
        runCatching { serverSocket?.close() }
        serverSocket = null
        sseSessions.values.forEach { runCatching { it.close() } }
        sseSessions.clear()
        Log.i(TAG, "本地 MCP 已停止")
    }

    /**
     * 按「MCP 工具通道」开关自动启停。
     * App 启动与用户在选项页切换 checkbox 时都会调用（幂等）。
     */
    fun applyPref(ctx: Context): String {
        return if (runCatching { AdbBridge.isMcpEnabled(ctx) }.getOrDefault(false)) {
            start(ctx)
        } else {
            stop()
            "已关闭"
        }
    }

    // ─────────────────────────────────────────────────────────── 连接处理

    private class HttpReq(
        val method: String,
        val path: String,
        val query: Map<String, String>,
        val headers: Map<String, String>,
        val body: ByteArray,
    )

    private fun handleConnection(ctx: Context, sock: Socket) {
        try {
            sock.soTimeout = 0
            val input = BufferedInputStream(sock.getInputStream())
            val out = sock.getOutputStream()

            val req = readRequest(input) ?: run { runCatching { sock.close() }; return }
            val pathOnly = req.path.substringBefore('?')

            when {
                req.method == "OPTIONS" -> respondEmpty(out, 204, allowCors = true)
                pathOnly == "/mcp" || pathOnly == "/" -> handleStreamable(ctx, req, out)
                pathOnly == "/sse" -> handleSse(ctx, req, out, sock)
                pathOnly == "/messages" -> handleSseMessage(ctx, req, out)
                pathOnly == "/health" -> respondJson(out, 200, JSONObject().put("ok", true).toString())
                else -> respondJson(out, 404, "{\"error\":\"not found\"}")
            }
        } catch (e: Exception) {
            Log.w(TAG, "连接异常: ${e.message}")
        } finally {
            // /sse 是长连接，不能在这里关；其它一次性请求用完即关
            runCatching {
                if (sock.getOutputStream().let { true }) {
                    // 只有非 SSE 会话才会走到这里；SSE 已在 handleSse 内部保持
                }
            }
        }
    }

    /** Streamable HTTP：POST 进来，直接把 JSON-RPC 应答作为响应体返回。 */
    private fun handleStreamable(ctx: Context, req: HttpReq, out: OutputStream) {
        if (req.method != "POST") {
            respondJson(out, 405, "{\"error\":\"use POST\"}")
            return
        }
        val resp = processJsonRpc(ctx, req.body)
        if (resp == null) {
            // 通知（notification）没有 id：按 MCP 规范回 202，无响应体
            respondEmpty(out, 202, allowCors = true)
        } else {
            respondJson(out, 200, resp.toString())
        }
        runCatching { out.close() }
    }

    /** 旧协议第一步：GET /sse 建立事件流，并告知客户端 POST 地址。 */
    private fun handleSse(ctx: Context, req: HttpReq, out: OutputStream, sock: Socket) {
        if (req.method != "GET") {
            respondJson(out, 405, "{\"error\":\"use GET\"}")
            runCatching { out.close() }
            return
        }
        val sessionId = UUID.randomUUID().toString()
        sseSessions[sessionId] = out
        try {
            val head = buildString {
                append("HTTP/1.1 200 OK\r\n")
                append("Content-Type: text/event-stream; charset=utf-8\r\n")
                append("Cache-Control: no-cache\r\n")
                append("Connection: keep-alive\r\n")
                append("Access-Control-Allow-Origin: *\r\n")
                append("\r\n")
            }
            out.write(head.toByteArray(StandardCharsets.UTF_8))
            // 告知客户端往哪儿 POST（MCP SSE 传输规定的事件）
            writeSseEvent(out, "endpoint", "/messages?sessionId=$sessionId")
            out.flush()
            // 保持连接：定期发注释行做心跳，直到客户端断开或服务停止
            while (running && !sock.isClosed) {
                Thread.sleep(15000)
                out.write(": ping\n\n".toByteArray(StandardCharsets.UTF_8))
                out.flush()
            }
        } catch (_: Exception) {
            // 客户端断开 / 服务停止
        } finally {
            sseSessions.remove(sessionId)
            runCatching { out.close() }
        }
    }

    /** 旧协议第二步：POST /messages?sessionId=... 接收请求，应答从 SSE 流推回。 */
    private fun handleSseMessage(ctx: Context, req: HttpReq, out: OutputStream) {
        if (req.method != "POST") {
            respondJson(out, 405, "{\"error\":\"use POST\"}")
            runCatching { out.close() }
            return
        }
        val sid = req.query["sessionId"]
        val sessionOut = sid?.let { sseSessions[it] }
        if (sessionOut == null) {
            respondJson(out, 404, "{\"error\":\"unknown sessionId\"}")
            runCatching { out.close() }
            return
        }
        val resp = processJsonRpc(ctx, req.body)
        respondEmpty(out, 202, allowCors = true)   // 规范要求先回 202
        if (resp != null) {
            runCatching { writeSseEvent(sessionOut, "message", resp.toString()); sessionOut.flush() }
        }
        runCatching { out.close() }
    }

    private fun writeSseEvent(out: OutputStream, event: String, data: String) {
        val sb = StringBuilder()
        sb.append("event: ").append(event).append('\n')
        // SSE 的 data 字段不能含裸换行：按行拆成多个 data:
        for (line in data.split('\n')) {
            sb.append("data: ").append(line).append('\n')
        }
        sb.append('\n')
        out.write(sb.toString().toByteArray(StandardCharsets.UTF_8))
    }

    // ─────────────────────────────────────────────────────────── JSON-RPC

    /**
     * 处理一条 JSON-RPC 消息。返回 null 表示这是通知（不需要应答）。
     * 支持批量请求（数组）。
     */
    private fun processJsonRpc(ctx: Context, body: ByteArray): Any? {
        val text = String(body, StandardCharsets.UTF_8).trim()
        if (text.isEmpty()) return null
        return try {
            if (text.startsWith("[")) {
                val arr = JSONArray(text)
                val outArr = JSONArray()
                for (i in 0 until arr.length()) {
                    val r = handleOne(ctx, arr.getJSONObject(i))
                    if (r != null) outArr.put(r)
                }
                if (outArr.length() == 0) null else outArr
            } else {
                handleOne(ctx, JSONObject(text))
            }
        } catch (e: Exception) {
            Log.w(TAG, "JSON-RPC 解析失败: ${e.message}")
            JSONObject()
                .put("jsonrpc", "2.0")
                .put("id", JSONObject.NULL)
                .put("error", JSONObject().put("code", -32700).put("message", "parse error"))
        }
    }

    private fun handleOne(ctx: Context, req: JSONObject): JSONObject? {
        val id = if (req.has("id")) req.opt("id") else null
        val method = req.optString("method", "")
        val params = req.optJSONObject("params") ?: JSONObject()

        fun ok(result: Any?): JSONObject =
            JSONObject().put("jsonrpc", "2.0").put("id", id ?: JSONObject.NULL).put("result", result)

        fun err(code: Int, msg: String): JSONObject =
            JSONObject().put("jsonrpc", "2.0").put("id", id ?: JSONObject.NULL)
                .put("error", JSONObject().put("code", code).put("message", msg))

        // 通知类：没有 id，不需要应答
        if (id == null || method.startsWith("notifications/")) {
            Log.i(TAG, "通知: $method")
            return null
        }

        return try {
            when (method) {
                "initialize" -> {
                    // 2026-10-31：回显客户端请求的协议版本。
                    // 之前会把客户端版本降级成 2024-11-05，新版客户端（如
                    // "Server's protocol version is not supported"）会直接拒绝连接。
                    val want = params.optString("protocolVersion", "").trim()
                    val ver = if (want.isNotEmpty()) want else PROTOCOL_DEFAULT
                    ok(JSONObject()
                        .put("protocolVersion", ver)
                        .put("capabilities", JSONObject()
                            .put("tools", JSONObject().put("listChanged", false)))
                        .put("serverInfo", JSONObject()
                            .put("name", "atrace-mobile-mcp")
                            .put("version", "1.0.0"))
                        .put("instructions",
                            "ATrace 手机端 MCP：工具的实际执行发生在手机目标进程内" +
                            "（需先注入并连接 agent）。首次使用可先调 run_lua 执行 api()。" ))
                }
                "ping" -> ok(JSONObject())
                "tools/list" -> {
                    val tools = JSONArray(McpTools.listJson())
                    ok(JSONObject().put("tools", tools))
                }
                "tools/call" -> {
                    val name = params.optString("name", "")
                    val args = params.optJSONObject("arguments") ?: JSONObject()
                    val reqBody = JSONObject().put("name", name).put("args", args)
                    val (success, text) = McpTools.call(ctx, reqBody.toString())
                    ok(JSONObject()
                        .put("content", JSONArray().put(
                            JSONObject().put("type", "text").put("text", text)))
                        .put("isError", !success))
                }
                else -> err(-32601, "Method not found: $method")
            }
        } catch (e: Exception) {
            err(-32603, e.message ?: e.toString())
        }
    }

    // ─────────────────────────────────────────────────────────── HTTP 解析

    private fun readRequest(input: InputStream): HttpReq? {
        // 请求行
        val requestLine = readLineBytes(input) ?: return null
        val parts = requestLine.trim().split(" ")
        if (parts.size < 2) return null
        val method = parts[0].uppercase()
        val target = parts[1]

        // 头
        val headers = HashMap<String, String>()
        while (true) {
            val line = readLineBytes(input) ?: break
            if (line.isEmpty()) break
            val idx = line.indexOf(':')
            if (idx > 0) {
                headers[line.substring(0, idx).trim().lowercase()] =
                    line.substring(idx + 1).trim()
            }
        }

        // 查询串
        val path = target.substringBefore('?')
        val query = HashMap<String, String>()
        val q = target.substringAfter('?', "")
        if (q.isNotEmpty()) {
            for (kv in q.split('&')) {
                if (kv.isEmpty()) continue
                val k = kv.substringBefore('=')
                val v = kv.substringAfter('=', "")
                query[URLDecoder.decode(k, "UTF-8")] = URLDecoder.decode(v, "UTF-8")
            }
        }

        // 体（支持 Content-Length；chunked 也做最小实现）
        val body: ByteArray = when {
            headers["transfer-encoding"]?.contains("chunked", true) == true ->
                readChunkedBody(input)
            headers.containsKey("content-length") ->
                readExact(input, headers["content-length"]!!.toIntOrNull() ?: 0)
            else -> ByteArray(0)
        }
        return HttpReq(method, path, query, headers, body)
    }

    private fun readLineBytes(input: InputStream): String? {
        val sb = StringBuilder()
        while (true) {
            val b = input.read()
            if (b < 0) return if (sb.isEmpty()) null else sb.toString()
            if (b == '\n'.code) {
                var s = sb.toString()
                if (s.endsWith("\r")) s = s.dropLast(1)
                return s
            }
            sb.append(b.toChar())
        }
    }

    private fun readExact(input: InputStream, n: Int): ByteArray {
        if (n <= 0) return ByteArray(0)
        val buf = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = input.read(buf, off, n - off)
            if (r < 0) break
            off += r
        }
        return if (off == n) buf else buf.copyOf(off)
    }

    private fun readChunkedBody(input: InputStream): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        while (true) {
            val sizeLine = readLineBytes(input) ?: break
            val size = sizeLine.substringBefore(';').trim().toIntOrNull(16) ?: break
            if (size == 0) {
                readLineBytes(input)   // 末尾 CRLF
                break
            }
            out.write(readExact(input, size))
            readLineBytes(input)       // 每块后的 CRLF
        }
        return out.toByteArray()
    }

    private fun respondJson(out: OutputStream, code: Int, json: String) {
        val body = json.toByteArray(StandardCharsets.UTF_8)
        val head = buildString {
            append("HTTP/1.1 $code ${if (code == 200) "OK" else "ERR"}\r\n")
            append("Content-Type: application/json; charset=utf-8\r\n")
            append("Content-Length: ${body.size}\r\n")
            append("Access-Control-Allow-Origin: *\r\n")
            append("Access-Control-Allow-Headers: *\r\n")
            append("Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n")
            append("Connection: close\r\n\r\n")
        }
        out.write(head.toByteArray(StandardCharsets.UTF_8))
        out.write(body)
        out.flush()
    }

    private fun respondEmpty(out: OutputStream, code: Int, allowCors: Boolean) {
        val head = buildString {
            append("HTTP/1.1 $code ${if (code == 202) "Accepted" else "No Content"}\r\n")
            if (allowCors) {
                append("Access-Control-Allow-Origin: *\r\n")
                append("Access-Control-Allow-Headers: *\r\n")
                append("Access-Control-Allow-Methods: POST, GET, OPTIONS\r\n")
            }
            append("Connection: close\r\n\r\n")
        }
        out.write(head.toByteArray(StandardCharsets.UTF_8))
        out.flush()
    }
}

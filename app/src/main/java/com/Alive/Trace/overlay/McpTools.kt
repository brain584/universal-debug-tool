package com.Alive.Trace.overlay

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 *
 * ## 它是什么
 * 手机侧真正"干活"的那一层：把 ATrace 已有能力包成**可被电脑调用**的工具。
 * 电脑端的 stdio MCP 服务（`tools/atrace_mcp.py`）把 MCP 协议的
 * `tools/list` / `tools/call` 映射到本类的 `TOOL_LIST` / `TOOL_CALL` 两个命令上，
 * 于是「电脑的 AI/编辑器能调用手机工具」不需要另开端口，也不需要在电脑上装 Android SDK。
 *
 * ## 与「手机本地 MCP」的关系
 * 用户要求：USB 连着 → 电脑 MCP 调手机工具；没连 USB → 可以走本地。
 * 这里只负责"手机侧工具"这一端；电脑侧脚本负责在两种模式间切换
 * （连不上手机时 `--local` 模式直接在本机处理/或提示用户改用手机本地 MCP）。
 *
 * ## 为什么用 org.json
 * Android 自带 `org.json`，不用为了一个 JSON 解析引入第三方依赖，
 * 也不会和项目现有依赖冲突。
 */
object McpTools {

    /** tools/list 的返回：MCP 规范的 JSON 数组（name / description / inputSchema）。 */
    fun listJson(): String {
        fun schema(vararg props: Pair<String, String>, required: List<String>): JSONObject {
            val p = JSONObject()
            for ((k, t) in props) p.put(k, JSONObject().put("type", t))
            return JSONObject()
                .put("type", "object")
                .put("properties", p)
                .put("required", JSONArray(required))
        }

        val arr = JSONArray()
        arr.put(
            JSONObject()
                .put("name", "run_lua")
                .put("description",
                    "在目标进程的 LuaJIT 里执行一段 Lua 脚本，返回本次执行的结果与 print 输出。" +
                    "目标内注入了宿主 API：getBase / hookCPU / hookfunc / removehook / call / msleep / " +
                    "read* / write* / regsOf / setReg / print / api() / help()。" +
                    "**第一次用请先执行 api() 或 help()**，它会返回全部函数的签名(sig)、返回值(ret)、" +
                    "说明(desc) 和示例(example)；api(\"hookfunc\") 可单查一个。")
                .put("inputSchema", schema("script" to "string", required = listOf("script")))
        )
        arr.put(
            JSONObject()
                .put("name", "agent_status")
                .put("description", "查询手机端 agent socket 是否已连接（脚本执行的前提）")
                .put("inputSchema", schema(required = emptyList()))
        )
        arr.put(
            JSONObject()
                .put("name", "list_processes")
                .put("description", "列出设备上的进程（pid 与名称）")
                .put("inputSchema", schema(required = emptyList()))
        )
        arr.put(
            JSONObject()
                .put("name", "list_modules")
                .put("description", "列出目标进程已加载的模块（需先连接 agent）")
                .put("inputSchema", schema(required = emptyList()))
        )
        arr.put(
            JSONObject()
                .put("name", "mem_read")
                .put("description", "读取目标进程内存，返回十六进制字符串")
                .put("inputSchema", schema(
                    "pid" to "integer", "addr" to "string", "len" to "integer",
                    required = listOf("pid", "addr", "len")))
        )
        arr.put(
            JSONObject()
                .put("name", "mem_write")
                .put("description", "写目标进程内存，data 为十六进制字符串（长度需为偶数）")
                .put("inputSchema", schema(
                    "pid" to "integer", "addr" to "string", "data" to "string",
                    required = listOf("pid", "addr", "data")))
        )

        arr.put(
            JSONObject()
                .put("name", "mem_page")
                .put("description",
                    "按页读取目标进程内存并附带反汇编（App 侧 capstone，不占 agent 体积）。" +
                    "每行 4 字节：地址 值 汇编；rows 默认 16（64B），最大 256（1KB）。" +
                    "addr 支持：0x1234 / 1234（十六进制/十进制）、libxxx.so+0x1234、libxxx.so-0x10、" +
                    "0x1000+0x20（模块名支持短名/全路径/包含匹配，需 agent 已连接）。")
                .put("inputSchema", schema(
                    "pid" to "integer", "addr" to "string", "rows" to "integer",
                    "disasm" to "boolean",
                    required = listOf("pid", "addr")))
        )
        arr.put(
            JSONObject()
                .put("name", "inject_pid")
                .put("description",
                    "把 agent 注入到指定进程（需要 root）。默认走传统 ptrace 注入器；" +
                    "zero=true 时走**零 ptrace**（data-only GOT 劫持，不建立 ptrace 关系，TracerPid 不变）。" +
                    "成功后会自动记录目标并尝试连接 agent，随后就能用 run_lua / list_modules / bp_* / search_* / art_*。\n" +
                    "autorun（可选）：注入+连接成功后自动执行的 Lua 源码；不传时若 " +
                    "<filesDir>/scripts/autorun.lua 存在则执行它（用 get_autorun / set_autorun 管理）。" +
                    "autorun 失败不会改变注入成功的结果，但会在返回里说明失败原因。\n" +
                    "**no_autorun=true：本次注入跳过 autorun**（不读已存文件，也不改动它）；" +
                    "想永久关闭用 set_autorun {script:\"\"} 清除。\n" +
                    "若返回「⚠ 旧 agent 仍占用」，说明目标进程里的旧 agent 没退出（固定 socket 名 + 不支持 detach）：" +
                    "先 `adb shell am force-stop <pkg>` 或手动重启目标 App，再重新 inject_pid。")
                .put("inputSchema", schema(
                    "pid" to "integer", "zero" to "boolean", "autorun" to "string",
                    "no_autorun" to "boolean", "stealth" to "boolean",
                    "memfd" to "boolean", "hide_maps" to "boolean", "hide_solist" to "boolean",
                    "dlclose_hide" to "boolean", "deep_obfuscate" to "boolean",
                    "no_copy" to "boolean",
                    required = listOf("pid")))
        )

        // ───────────── #16：拉起并注入（抢"干净注入窗口"）─────────────
        arr.put(
            JSONObject()
                .put("name", "launch_and_inject")
                .put("description",
                    "**拉起目标 App，并在它刚起来时立刻注入**（需要 root）。" +
                    "很多目标启动后几秒就完成初始化/开始自检，等它跑起来再注入会错过最干净的窗口；" +
                    "本工具把「force-stop → am start → 轮询 pid → 注入 → 连 agent → autorun」串成一步，" +
                    "并返回「启动→拿到 pid」和「启动→注入完成」两个耗时。\n" +
                    "参数：pkg（包名，必填）；zero=零 ptrace；restart 默认 true（先 force-stop 拿全新进程）；" +
                    "wait_ms 默认 8000（等进程出现的上限）；activity 可选（显式组件，如 pkg/.MainActivity）；" +
                    "autorun 可选（注入成功后的 Lua，失败不改变注入结果）；" +
                    "no_autorun=true 本次跳过 autorun（不读/不改已存脚本）。\n" +
                    "注意：force-stop 会丢掉目标当前状态；只想注入已运行的进程请用 inject_pid。")
                .put("inputSchema", schema(
                    "pkg" to "string", "zero" to "boolean", "restart" to "boolean",
                    "wait_ms" to "integer", "activity" to "string", "autorun" to "string",
                    "no_autorun" to "boolean", "stealth" to "boolean",
                    "memfd" to "boolean", "hide_maps" to "boolean", "hide_solist" to "boolean",
                    "dlclose_hide" to "boolean", "deep_obfuscate" to "boolean",
                    "no_copy" to "boolean",
                    required = listOf("pkg")))
        )

        // ───────────── 注入后自动执行脚本（P1-12）─────────────
        // 固定路径 <filesDir>/scripts/autorun.lua（与脚本页草稿 last.lua 分离）。
        arr.put(
            JSONObject()
                .put("name", "get_autorun")
                .put("description",
                    "读取「注入后自动执行脚本」：固定路径 <filesDir>/scripts/autorun.lua。" +
                    "未设置（文件不存在）时返回提示而不是报错。")
                .put("inputSchema", schema(required = emptyList()))
        )
        arr.put(
            JSONObject()
                .put("name", "set_autorun")
                .put("description",
                    "写入「注入后自动执行脚本」：固定路径 <filesDir>/scripts/autorun.lua（最大 1MB）。" +
                    "写完后每次 inject_pid 成功且 agent 连上都会自动执行；" +
                    "inject_pid 的 autorun 参数可临时覆盖（不落盘）；no_autorun=true 可单次跳过。" +
                    "**script 传空串 = 清除 autorun**（删除文件，之后注入不再自动执行；这是关闭 autorun 的正规入口）。")
                .put("inputSchema", schema("script" to "string", required = listOf("script")))
        )

        // ───────────── 搜索（对应悬浮窗「搜索」页；与 UI 共用同一份 native 结果集）─────────────
        // 异步语义：searchStart / fuzzyStart / searchRefine / fuzzyFilter 都在 native 里起
        // detached 线程后**立即返回**；进度用 search_status 轮询，结果用 search_page 分页读。
        arr.put(
            JSONObject()
                .put("name", "search_start")
                .put("description",
                    "启动精确/范围搜索（异步，立即返回；用 search_status 看进度、search_page 读结果）。" +
                    "value 支持 100 / 0x64 / 10~20（范围）；type 默认 dword（dword/float/qword/word/byte/double）。" +
                    "areas 省略=全部内存，可传区域名数组（如 [\"stack\",\"c_heap\"]）或整数掩码数组。" +
                    "结果上限 200000 条（达到时 status 会带「(已达上限)」）。" +
                    "注意：与手机悬浮窗共用同一份结果集，新搜索会覆盖旧结果。")
                .put("inputSchema", schema(
                    "pid" to "integer", "value" to "string", "type" to "string",
                    "areas" to "array",
                    required = listOf("pid", "value")))
        )
        arr.put(
            JSONObject()
                .put("name", "search_status")
                .put("description",
                    "查询搜索状态（三合一）：running（后台是否还在跑）/ count（已完成结果数）/ " +
                    "status（native 的中文状态文本，如「精确搜索完成: 37 个结果 (耗时 2.0s)」）。" +
                    "running=false 且 status 不再是「搜索中.../过滤中.../改善中...」即表示结束。")
                .put("inputSchema", schema(required = emptyList()))
        )
        arr.put(
            JSONObject()
                .put("name", "search_page")
                .put("description",
                    "分页读取搜索结果，每行「地址 值 [ascii]」。offset 默认 0，count 默认 20、最大 60。" +
                    "搜索进行中也能调用：只返回已完成的部分；还没有结果时给出明确提示而不是失败。" +
                    "尾部会注明 total/running 与下一页 offset。")
                .put("inputSchema", schema(
                    "offset" to "integer", "count" to "integer", "ascii" to "boolean",
                    required = emptyList()))
        )
        arr.put(
            JSONObject()
                .put("name", "search_refine")
                .put("description",
                    "精确「改善」（异步）：在现有结果里只保留当前值等于 value 的地址。" +
                    "不支持范围写法（10~20 只能用于 search_start）；type 省略时沿用本次/上次搜索类型。")
                .put("inputSchema", schema(
                    "value" to "string", "type" to "string", required = listOf("value")))
        )
        arr.put(
            JSONObject()
                .put("name", "search_reset")
                .put("description",
                    "清空搜索结果与状态。注意：这不会打断正在后台跑的搜索线程，" +
                    "它结束时仍会把结果写回（所以清空前先确认 running=false）。")
                .put("inputSchema", schema(required = emptyList()))
        )
        arr.put(
            JSONObject()
                .put("name", "fuzzy_start")
                .put("description",
                    "模糊搜索初始化（异步快照）：按 type 对目标进程做一次全量取值快照（上限 1000000 条），" +
                    "之后用 fuzzy_filter 按「值的变化」反复筛选。与手机 UI 共用同一份结果集。")
                .put("inputSchema", schema(
                    "pid" to "integer", "type" to "string", "areas" to "array",
                    required = listOf("pid")))
        )
        arr.put(
            JSONObject()
                .put("name", "fuzzy_filter")
                .put("description",
                    "模糊搜索「改善」（异步）：比较快照值与当前值。" +
                    "op 支持 0/unchanged=未变化、1/changed=有变化、2/increased=变大、3/decreased=变小" +
                    "（整数或字符串均可）。可反复调用逐步收敛。")
                .put("inputSchema", schema("op" to "string", required = listOf("op")))
        )

        // ───────────── 硬件断点（root，复用 injector --bp 服务）─────────────
        arr.put(
            JSONObject()
                .put("name", "art_hook")
                .put("description",
                    "Hook 一个 Java/ART 方法（LSPlant，运行期替换，不改 dex）。需要 agent 已注入并连接。\n" +
                    "mode=log（默认）：只记日志，不影响原方法；命中记录用 agent_logs 读取。\n" +
                    "mode=replace：直接返回 value（原方法不执行；value_type=number/boolean/string/null 指定类型，默认自动）。\n" +
                    "mode=script：执行自定义 Lua 回调体（可用 ctx.this / ctx.args / ctx.id；return 值覆盖返回值，return nil 则透传调原方法）。")
                .put("inputSchema", schema(
                    "class" to "string", "method" to "string", "signature" to "string",
                    "mode" to "string", "value" to "string", "value_type" to "string",
                    "script" to "string",
                    required = listOf("class", "method")))
        )
        arr.put(
            JSONObject()
                .put("name", "art_unhook")
                .put("description", "卸载由 art_hook 安装的 Java hook（按 id）。")
                .put("inputSchema", schema("id" to "integer", required = listOf("id")))
        )
        arr.put(
            JSONObject()
                .put("name", "art_hooks")
                .put("description", "列出当前所有 Java hook（id/class/method/signature/mode）。")
                .put("inputSchema", schema(required = emptyList()))
        )
        arr.put(
            JSONObject()
                .put("name", "agent_logs")
                .put("description",
                    "读取目标进程内 agent 的 Lua 日志（含 art_hook 的命中记录、run_lua 的 print）。" +
                    "可选 lines（默认 100，最大 400），返回最后 N 行。")
                .put("inputSchema", schema("lines" to "integer", required = emptyList()))
        )
        arr.put(
            JSONObject()
                .put("name", "bp_status")
                .put("description", "查询硬件断点服务状态：是否运行、目标 pid、状态文本、最近一条 OK/ERR")
                .put("inputSchema", schema(required = emptyList()))
        )
        arr.put(
            JSONObject()
                .put("name", "bp_start")
                .put("description", "启动硬件断点服务（需要 root）。pid 省略时用当前 agent 连接的目标进程")
                .put("inputSchema", schema("pid" to "integer", required = emptyList()))
        )
        arr.put(
            JSONObject()
                .put("name", "bp_stop")
                .put("description", "停止硬件断点服务并清理所有断点")
                .put("inputSchema", schema(required = emptyList()))
        )
        arr.put(
            JSONObject()
                .put("name", "bp_set")
                .put("description",
                    "下硬件断点。addr 可直接给地址，也可用 module+offset（如 module=libtutorial.so, offset=0x1234）。" +
                    "type: x=执行(rw=读写数据)，默认 x；len: 1/2/4/8，执行断点用 4")
                .put("inputSchema", schema(
                    "addr" to "string", "module" to "string", "offset" to "string",
                    "type" to "string", "len" to "integer", required = emptyList()))
        )
        arr.put(
            JSONObject()
                .put("name", "bp_clear")
                .put("description", "清除指定地址的断点")
                .put("inputSchema", schema("addr" to "string", required = listOf("addr")))
        )
        arr.put(
            JSONObject()
                .put("name", "bp_clear_all")
                .put("description", "清除所有断点")
                .put("inputSchema", schema(required = emptyList()))
        )
        arr.put(
            JSONObject()
                .put("name", "bp_hits")
                .put("description",
                    "取最近的断点命中记录，每行 12 段：\n" +
                    "pc|tid|addr|反汇编|sp|栈|寄存器|次数|区域|模块|类型|长度\n" +
                    "其中 pc=真实命中指令地址（执行断点==addr；读写监视点=访问该数据的那条指令），" +
                    "addr=断点地址，disasm 以 pc 为基准。\n" +
                    "**java=true（默认）且 agent 已连接时**，每行末尾会追加第 13 段：\n" +
                    "`|java=<Java 帧1> <- <Java 帧2> <- ...`（按 hit 行的 tid 查该线程的 Java 栈；" +
                    "纯 native 线程没有 Java 栈，则该段不出现）。这就是硬件断点的「Java 层」信息。" +
                    "java=false 可关掉（少一次 agent 往返）。")
                .put("inputSchema", schema(
                    "max" to "integer", "java" to "boolean", required = emptyList()))
        )
        arr.put(
            JSONObject()
                .put("name", "bp_java_stack")
                .put("description",
                    "按 **tid** 查询某个线程的完整 Java 调用栈（一行一帧 className|method|file|line|native）。\n" +
                    "典型用法：`bp_hits` 每行第 2 段就是 tid，拿它来这里看完整栈（bp_hits 只带前 8 帧摘要）。\n" +
                    "需要 agent 已连接（Java 栈要由目标进程内的 agent 问 ART）；" +
                    "纯 native 线程（未被 ART Attach）会报「不是 Java 线程」。")
                .put("inputSchema", schema(
                    "tid" to "integer", "max" to "integer", required = listOf("tid")))
        )
        arr.put(
            JSONObject()
                .put("name", "bp_wait")
                .put("description", "等待断点命中（轮询最多 timeout_sec 秒），常用于「下断点→等命中→看寄存器/栈」")
                .put("inputSchema", schema(
                    "timeout_sec" to "integer", "max" to "integer", required = emptyList()))
        )
        return arr.toString()
    }

    /**
     * tools/call 的实现。
     * @param body JSON: {"name":"run_lua","args":{...}}
     * @return Pair(是否成功, 结果文本)
     */
    fun call(ctx: Context, body: String): Pair<Boolean, String> {
        return try {
            val req = JSONObject(body)
            val name = req.optString("name", "")
            val args = req.optJSONObject("args") ?: JSONObject()
            when (name) {
                "run_lua" -> {
                    val script = args.optString("script", "")
                    if (script.isBlank()) return false to "ERR: 缺少参数 script"
                    val out = AdbBridge.runLuaForTools(script)
                    // Lua 语法/运行错误时 agent 返回 "[Lua 错误] ..."，
                    // 这些也要标记成 isError，否则 MCP 客户端会以为执行成功。
                    val bad = out.startsWith("ERR") || out.contains("[Lua 错误]")
                    // agent 侧已按 watermark 只回本次新日志，这里再加一条边界，肉眼也能分清。
                    (!bad) to ("=== run_lua 本次输出（以上一轮为界） ===\n" + out)
                }
                "agent_status" -> {
                    // 外部 AI 反馈：只回 connected/not_connected 信息太少，
                    // 连的是哪个进程/hook 数都说不清。这里返回 agent 自报的摘要。
                    val c = runCatching { NativeBridge.socketIsConnected() }.getOrDefault(false)
                    if (!c) return true to "not_connected"
                    val st = runCatching { NativeBridge.socketAgentStatus() }.getOrNull().orEmpty()
                    true to ("connected" + if (st.isNotBlank()) " " + st.trim() else "")
                }
                "list_processes" -> {
                    val s = runCatching { NativeBridge.scanProcesses() }.getOrNull().orEmpty()
                    if (s.isBlank()) false to "ERR: 进程扫描失败（需要 root）" else true to s
                }
                "list_modules" -> {
                    if (!runCatching { NativeBridge.socketIsConnected() }.getOrDefault(false))
                        return false to "ERR: 未连接 agent"
                    val s = runCatching { NativeBridge.socketModules() }.getOrNull().orEmpty()
                    if (s.isBlank()) false to "ERR: 获取模块列表失败" else true to s
                }
                "mem_read" -> {
                    val pid = args.optInt("pid", 0)
                    val addr = parseAddr(args.optString("addr", "0"))
                    val len = args.optInt("len", 0)
                    if (pid <= 0 || len <= 0) return false to "ERR: 参数不合法（pid/len）"
                    val data = runCatching { NativeBridge.memRead(pid, addr, len) }.getOrNull()
                    if (data == null) false to "ERR: 读取失败"
                    else true to data.joinToString("") { "%02x".format(it) }
                }
                "mem_write" -> {
                    val pid = args.optInt("pid", 0)
                    val addr = parseAddr(args.optString("addr", "0"))
                    val hex = args.optString("data", "")
                    val bytes = hexToBytes(hex)
                        ?: return false to "ERR: data 不是合法十六进制"
                    if (pid <= 0) return false to "ERR: pid 不合法"
                    val ok = runCatching { NativeBridge.memWrite(pid, addr, bytes) }
                        .getOrDefault(false)
                    ok to (if (ok) "written ${bytes.size} bytes" else "ERR: 写入失败")
                }
                "mem_page" -> {
                    val pid = args.optInt("pid", 0)
                    if (pid <= 0) return false to "ERR: 需要 pid（先用 list_processes 查）"
                    val addrRaw = args.optString("addr", "").trim()
                    if (addrRaw.isEmpty())
                        return false to ("ERR: 缺少 addr（支持 0x1234 / 1234 / libxxx.so+0x1234 / " +
                            "libxxx.so-0x10 / 0x1000+0x20）")
                    val addrRes = resolveAddrExpr(addrRaw)
                    val addr = addrRes.first ?: return false to addrRes.second
                    if (addr <= 0)
                        return false to ("ERR: addr 解析结果不是有效地址（0x" +
                            java.lang.Long.toHexString(addr) + "）")
                    // 表达式形式额外回显解析结果，方便核对模块基址有没有找对。
                    val exprNote = if (addrRaw.contains('+') || addrRaw.contains('-'))
                        "addr: \"$addrRaw\" → 0x" + java.lang.Long.toHexString(addr) + "\n" else ""
                    var rows = args.optInt("rows", 16)
                    if (rows <= 0) rows = 16
                    if (rows > 256) rows = 256
                    val withAsm = args.optBoolean("disasm", true)
                    val data = runCatching { NativeBridge.memRead(pid, addr, rows * 4) }
                        .getOrNull()
                    if (data == null || data.size < rows * 4)
                        return false to "ERR: 读取失败（地址不可读或进程不存在）"
                    val asmMap = HashMap<Long, Pair<String, String>>()
                    if (withAsm) {
                        val block = runCatching { NativeBridge.memDisasmBlock(addr, data) }
                            .getOrNull().orEmpty()
                        for (ln in block.lineSequence()) {
                            val p = ln.split('|')
                            if (p.size >= 3) {
                                val a = p[0].toLongOrNull(16) ?: continue
                                asmMap[a] = p[1] to p[2]
                            }
                        }
                    }
                    true to (exprNote + formatMemPage(addr, rows, data, asmMap, withAsm))
                }
                // ───────────── 搜索（对应悬浮窗「搜索」页）─────────────
                "search_start" -> doSearchStart(args)
                "search_status" -> true to searchStateText()
                "search_page" -> doSearchPage(args)
                "search_refine" -> doSearchRefine(args)
                "search_reset" -> doSearchReset()
                "fuzzy_start" -> doFuzzyStart(args)
                "fuzzy_filter" -> doFuzzyFilter(args)
                // ───────────── 注入 ─────────────
                "inject_pid" -> {
                    val pid = args.optInt("pid", 0)
                    if (pid <= 0) return false to "ERR: 需要 pid（先用 list_processes 查）"
                    val (ok, msg) = injectByPid(pid, args.optBoolean("zero", false),
                        buildInjectorFlags(args))
                    if (!ok) return false to msg
                    // P1-12：注入成功后跑 autorun；no_autorun=true 时本次跳过（不动已存文件）
                    val noAuto = args.optBoolean("no_autorun", false)
                    val auto = if (noAuto)
                        "\nautorun: 已按 no_autorun=true 跳过（已存脚本未改动）"
                    else
                        autorunSection(ctx, args.optString("autorun", ""))
                    true to (msg + auto)
                }
                // ───────────── #16：拉起并注入 ─────────────
                "launch_and_inject" -> doLaunchAndInject(ctx, args)
                // ───────────── 注入后自动执行脚本（P1-12）─────────────
                "get_autorun" -> doGetAutorun(ctx)
                "set_autorun" -> doSetAutorun(ctx, args)
                // ───────────── 硬件断点 ─────────────
                // ───────────── Java/ART hook ─────────────
                "art_hook" -> doArtHook(args)
                "art_unhook" -> doArtUnhook(args)
                "art_hooks" -> doArtHooks()
                "agent_logs" -> doAgentLogs(args)
                "bp_status" -> {
                    val running = runCatching { NativeBridge.bpIsRunning() }
                        .getOrDefault(false)
                    val tpid = runCatching { NativeBridge.bpTargetPid() }.getOrDefault(0)
                    val st = runCatching { NativeBridge.bpStatus() }.getOrNull().orEmpty()
                    val last = runCatching { NativeBridge.bpLastLine() }.getOrNull().orEmpty()
                    true to buildString {
                        appendLine("running=$running")
                        appendLine("target_pid=$tpid")
                        appendLine("status=$st")
                        append("last_line=").append(last)
                    }
                }
                "bp_start" -> {
                    if (runCatching { NativeBridge.bpIsRunning() }.getOrDefault(false)) {
                        val tpid = runCatching { NativeBridge.bpTargetPid() }.getOrDefault(0)
                        return true to "已在运行 (target_pid=$tpid)"
                    }
                    var pid = args.optInt("pid", 0)
                    if (pid <= 0) pid = currentTargetPid()
                    if (pid <= 0) {
                        // App 重启后 agent 尚未连接时，先自动连一次再取 pid
                        val (ok, msg) = AdbBridge.connectAgentOnce()
                        if (ok) pid = currentTargetPid()
                        if (pid <= 0) return false to "ERR: 无法确定目标 pid（$msg）"
                    }
                    // 先清掉可能残留的"错误: ..."状态
                    runCatching { NativeBridge.bpStop() }
                    runCatching { Thread.sleep(120) }
                    NativeBridge.bpStart(pid)
                    // 等服务真正起来（su + injector --bp 启动需要时间）
                    var running = false
                    val deadline = System.currentTimeMillis() + 4000
                    while (System.currentTimeMillis() < deadline) {
                        Thread.sleep(150)
                        running = runCatching { NativeBridge.bpIsRunning() }
                            .getOrDefault(false)
                        if (running) break
                    }
                    val st = runCatching { NativeBridge.bpStatus() }.getOrNull().orEmpty()
                    val last = runCatching { NativeBridge.bpLastLine() }.getOrNull().orEmpty()
                    if (running) {
                        val dropped = BpUi.onTargetChanged(pid)
                        runCatching { OverlayManager.instance?.syncBpChips() }
                        val extra = if (dropped > 0)
                            "\n（已丢弃上一个目标的 $dropped 个断点记录——旧地址在新进程里无意义）" else ""
                        true to "已启动 pid=$pid | $st | $last$extra"
                    } else {
                        false to "ERR: 启动失败 pid=$pid | $st | $last"
                    }
                }
                "bp_stop" -> {
                    NativeBridge.bpStop()
                    BpUi.clearAll()
                    runCatching { OverlayManager.instance?.syncBpChips() }
                    Thread.sleep(200)
                    val running = runCatching { NativeBridge.bpIsRunning() }
                        .getOrDefault(false)
                    true to (if (running) "ERR: 仍在运行" else "stopped")
                }
                "bp_set" -> {
                    if (!runCatching { NativeBridge.bpIsRunning() }.getOrDefault(false))
                        return false to "ERR: 断点服务未运行，请先调 bp_start"
                    // 旧地址会把无意义的地址装到新进程（外部 AI 实测踩到）。
                    val svcPid = runCatching { NativeBridge.bpTargetPid() }.getOrDefault(0)
                    val wantPid = args.optInt("pid", 0).let { if (it > 0) it else currentTargetPid() }
                    if (svcPid > 0 && wantPid > 0 && svcPid != wantPid) {
                        return false to ("ERR: 断点服务绑定 pid=$svcPid，当前目标是 pid=$wantPid。\n" +
                            "旧断点地址在新进程里没有意义：先 bp_clear_all / bp_stop，再对新目标 bp_start。")
                    }
                    val type = args.optString("type", "x").ifBlank { "x" }
                    var len = args.optInt("len", 0)
                    var addr = parseAddr(args.optString("addr", ""))
                    if (addr <= 0) {
                        val module = args.optString("module", "")
                        if (module.isBlank())
                            return false to "ERR: 需要 addr，或 module+offset"
                        val base = moduleBase(module)
                            ?: return false to "ERR: 找不到模块 $module（用 list_modules 看名字）"
                        addr = base + parseAddr(args.optString("offset", "0"))
                    }
                    if (len <= 0) len = if (type == "x") 4 else 4
                    val prev = runCatching { NativeBridge.bpLastLine() }.getOrNull().orEmpty()
                    NativeBridge.bpSet(addr, type, len)
                    val hex = "0x%x".format(addr)
                    val line = waitBpReply(prev, hex, 2500)
                    val ok = line.startsWith("OK")
                    if (ok) {
                        // P1-2：让 MCP 下的断点也出现在悬浮按钮里（0x地址 类型 ×命中数）
                        BpUi.upsert(addr, type, len)
                        runCatching { OverlayManager.instance?.syncBpChips() }
                    }
                    ok to (if (line.isNotBlank())
                        "$line  (addr=$hex type=$type len=$len；悬浮按钮可点击清除)"
                    else "ERR: 服务无响应（addr=$hex）")
                }
                "bp_clear" -> {
                    if (!runCatching { NativeBridge.bpIsRunning() }.getOrDefault(false))
                        return false to "ERR: 断点服务未运行"
                    val addr = parseAddr(args.optString("addr", ""))
                    if (addr <= 0) return false to "ERR: 需要 addr"
                    val prev = runCatching { NativeBridge.bpLastLine() }.getOrNull().orEmpty()
                    NativeBridge.bpClear(addr)
                    val line = waitBpReply(prev, "0x%x".format(addr), 2000)
                    BpUi.clear(addr)
                    runCatching { OverlayManager.instance?.syncBpChips() }
                    line.startsWith("OK") to line
                }
                "bp_clear_all" -> {
                    if (!runCatching { NativeBridge.bpIsRunning() }.getOrDefault(false))
                        return false to "ERR: 断点服务未运行"
                    val prev = runCatching { NativeBridge.bpLastLine() }.getOrNull().orEmpty()
                    NativeBridge.bpClearAll()
                    val line = waitBpReply(prev, "clearall", 2000)
                    BpUi.clearAll()
                    runCatching { OverlayManager.instance?.syncBpChips() }
                    line.startsWith("OK") to line
                }
                "bp_hits" -> {
                    val max = args.optInt("max", 20).coerceIn(1, 200)
                    val hits = runCatching { NativeBridge.bpHits(max) }.getOrNull().orEmpty()
                    if (hits.isBlank()) return true to "(暂无命中)"
                    val fTid = args.optInt("tid", 0)
                    val fModule = args.optString("module", "").trim()
                    val fPc = parseAddr(args.optString("pc", ""))
                    val rawLines = hits.trim().lineSequence().filter { it.isNotBlank() }.toList()
                    val filtered = rawLines.filter { line ->
                        val seg = line.split('|')
                        val tidOk = fTid <= 0 ||
                            (seg.getOrNull(1)?.trim()?.toIntOrNull() == fTid)
                        val modOk = fModule.isBlank() ||
                            (seg.getOrNull(9) ?: "").contains(fModule, true)
                        val pcOk = fPc <= 0L ||
                            (seg.getOrNull(0)?.trim()?.toLongOrNull(16) == fPc)
                        tidOk && modOk && pcOk
                    }
                    // P1-2：把命中数写回悬浮按钮（MCP 轮询也能看到 ×N 增长）
                    runCatching {
                        val cnt = HashMap<Long, Int>()
                        for (l in rawLines) {
                            val seg = l.split('|')
                            val a2 = parseAddr("0x" + (seg.getOrNull(2)?.trim() ?: ""))
                            if (a2 > 0) cnt[a2] = (cnt[a2] ?: 0) + 1
                        }
                        for ((a2, n) in cnt) BpUi.setHits(a2, n)
                        OverlayManager.instance?.syncBpChips()
                    }
                    if (filtered.isEmpty())
                        return true to "(没有符合过滤条件的命中；当前共 ${rawLines.size} 条)"
                    val truncNote =
                        if (rawLines.size >= max)
                            "# 显示 ${filtered.size} 条（请求上限 $max；更早的命中可能已被覆盖，" +
                                "清空可用 bp_clear_hits 后复测）\n"
                        else ""
                    // 向 agent 要该线程的 Java 栈，压缩成前 8 帧追加到行尾。
                    // 同一 tid 只查一次（缓存）；未连 agent / java=false 时原样返回。
                    val wantJava = args.optBoolean("java", true)
                    val agentUp = runCatching { NativeBridge.socketIsConnected() }
                        .getOrDefault(false)
                    if (!wantJava || !agentUp)
                        return true to (truncNote + filtered.joinToString("\n"))
                    val cache = HashMap<Int, String>()
                    val sb = StringBuilder()
                    sb.append(truncNote)
                    for (line in filtered) {
                        if (line.isBlank()) continue
                        sb.append(line)
                        val tid = line.split('|').getOrNull(1)?.trim()?.toIntOrNull() ?: 0
                        if (tid > 0) {
                            val js = cache.getOrPut(tid) {
                                val r = runCatching { NativeBridge.bpJavaStack(tid, 8) }
                                    .getOrNull().orEmpty()
                                compactJavaStack(r)
                            }
                            if (js.isNotEmpty()) sb.append("|java=").append(js)
                        }
                        sb.append('\n')
                    }
                    true to sb.toString().trim()
                }
                // P1-21：按 tid 查完整 Java 栈（bp_hits 每行第 2 段就是 tid）
                "bp_java_stack" -> {
                    val tid = args.optInt("tid", 0)
                    if (tid <= 0) return false to "ERR: 需要 tid（bp_hits 每行第 2 段）"
                    if (!runCatching { NativeBridge.socketIsConnected() }.getOrDefault(false))
                        return false to "ERR: 未连接 agent（Java 栈要由目标进程内的 agent 问 ART）"
                    val maxFrames = args.optInt("max", 24).coerceIn(1, 128)
                    val r = runCatching { NativeBridge.bpJavaStack(tid, maxFrames) }
                        .getOrNull().orEmpty()
                    if (r.isBlank()) return false to "ERR: agent 无响应（3s 超时）"
                    if (r.trim().startsWith("ERR")) return false to r.trim()
                    true to r.trim()
                }
                "bp_wait" -> {
                    val timeoutSec = args.optInt("timeout_sec", 5).coerceIn(1, 120)
                    val max = args.optInt("max", 10).coerceIn(1, 200)
                    if (!runCatching { NativeBridge.bpIsRunning() }.getOrDefault(false))
                        return false to "ERR: 断点服务未运行"
                    val deadline = System.currentTimeMillis() + timeoutSec * 1000L
                    var hits = ""
                    while (System.currentTimeMillis() < deadline) {
                        hits = runCatching { NativeBridge.bpHits(max) }.getOrNull().orEmpty()
                        if (hits.isNotBlank()) break
                        Thread.sleep(200)
                    }
                    if (hits.isBlank()) false to "(${timeoutSec}s 内没有命中)"
                    else true to hits.trim()
                }
                else -> false to "ERR: 未知工具 $name"
            }
        } catch (e: Exception) {
            false to "ERR: ${e.message}"
        }
    }

    /**
     * 当前目标 pid。优先级：
     *   1) socketStatus 里的 "pid=..."（正常注入后 App 知道）；
     *   2) **agent 自报的 pid**（App 重启后 OState 丢失也能拿到，最可靠）；
     *   3) Overlay 选中的进程。
     */
    private fun currentTargetPid(): Int {
        val st = runCatching { NativeBridge.socketStatus() }.getOrNull().orEmpty()
        Regex("pid=(\\d+)").find(st)?.let { return it.groupValues[1].toInt() }
        val info = runCatching { NativeBridge.socketAgentInfo() }.getOrNull().orEmpty()
        Regex("pid=(\\d+)").find(info)?.let { return it.groupValues[1].toInt() }
        return runCatching { OState.pid }.getOrDefault(0)
    }

    /** 从模块列表查基址：支持全路径 / 短名 / 包含匹配（取第一个匹配）。 */
    private fun moduleBase(name: String): Long? {
        val mods = runCatching { NativeBridge.socketModules() }.getOrNull().orEmpty()
        if (mods.isBlank()) return null
        val want = name.trim()
        var partial: Long? = null
        for (line in mods.lineSequence()) {
            val t = line.trim()
            if (t.isEmpty()) continue
            val sp = t.indexOf(' ')
            if (sp <= 0) continue
            val base = t.substring(0, sp).removePrefix("0x").toLongOrNull(16) ?: continue
            val path = t.substring(sp + 1).trim()
            val baseName = path.substringAfterLast('/')
            if (baseName == want || path == want) return base
            if (partial == null && (baseName.contains(want) || path.contains(want))) {
                partial = base
            }
        }
        return partial
    }

    /**
     * 等断点服务的确认行。
     *
     * 两种算"有响应"：出现**新的一行**；或同一地址重复设置导致文本没变、但当前行
     * 已包含本次的地址/关键字（例如连续两次 `set 0x1234 x 4`）。
     */
    private fun waitBpReply(prev: String, expectToken: String, timeoutMs: Int): String {
        val deadline = System.currentTimeMillis() + timeoutMs
        var cur = prev
        while (System.currentTimeMillis() < deadline) {
            Thread.sleep(80)
            cur = runCatching { NativeBridge.bpLastLine() }.getOrDefault(prev)
            if (cur.isBlank()) continue
            if (cur != prev) return cur
            if (expectToken.isNotBlank() && cur.contains(expectToken, ignoreCase = true)) {
                return cur
            }
        }
        return cur
    }

    /**
     * 用传统 ptrace 注入器注入到指定 pid，成功后记录目标并连接 agent。
     *
     * 供 MCP 的 inject_pid 工具与 adb 桥的 INJECT_PID 命令共用。
     * 注意：这是**阻塞**操作（注入本身要几秒），调用方应在工作线程里跑。
     */
    /**
     * 把 NativeBridge.memPage 的 "addr|ok|hex8|disasm|type" 行格式化成 AI 可读文本。
     * 这是「把内存页做成 MCP」的呈现层：AI 拿到地址/字节/汇编就能自己判断，
     * 不需要 agent 里再塞一份反汇编库。
     */
    private fun formatMemPage(base: Long, rows: Int, data: ByteArray,
                              asmMap: Map<Long, Pair<String, String>>,
                              withAsm: Boolean): String {
        val sb = StringBuilder()
        val page = base and 0xFFF.inv()
        sb.append("page=0x").append(java.lang.Long.toHexString(page))
            .append(" start=0x").append(java.lang.Long.toHexString(base))
            .append(" rows=").append(rows).append(" (4 bytes/row)")
            .append(if (withAsm) "  [addr  value  asm]" else "  [addr  value]")
            .append('\n')
        for (i in 0 until rows) {
            val off = i * 4
            val a = base + off
            val v = (data[off].toLong() and 0xFF) or
                    ((data[off + 1].toLong() and 0xFF) shl 8) or
                    ((data[off + 2].toLong() and 0xFF) shl 16) or
                    ((data[off + 3].toLong() and 0xFF) shl 24)
            sb.append("0x").append(java.lang.Long.toHexString(a).padStart(16, '0'))
                .append("  ").append(String.format("%08X", v))
            if (withAsm) {
                val asm = asmMap[a]?.second ?: "?"
                sb.append("  ").append(asm)
            }
            sb.append('\n')
        }
        return sb.toString().trimEnd()
    }

    // ═══════════════════ 搜索页工具的实现（search_* / fuzzy_*）═══════════════════
    //
    // 数据来源与 UI 完全一致：NativeBridge 的 search* / fuzzy* JNI，底层是 App 进程里
    // 的 MemorySearch 引擎（MemSu 后端，走 su 读写目标内存），结果集是 native 里的
    // 全局 g_hits/g_status/g_running —— 与手机悬浮窗「搜索」页**共用同一份**。

    /**
     * 搜索类型提示。
     *
     * native 的 g_type 没有 JNI getter，Kotlin 只知道**自己发起**时传了什么类型。
     * 这里记一份，供 search_page 做值格式化；0 = 未知（搜索是手机悬浮窗发起的），
     * 此时按原始 16 进制显示（不猜类型，避免显示成错误的有符号/浮点值）。
     */
    private object SearchHint {
        @Volatile var type: Int = 0
        @Volatile var pid: Int = 0
    }

    private fun searchRunning(): Boolean =
        runCatching { NativeBridge.searchRunning() }.getOrDefault(false)

    private fun searchCount(): Int =
        runCatching { NativeBridge.searchCount() }.getOrDefault(0)

    private fun searchStatusText(): String =
        runCatching { NativeBridge.searchStatus() }.getOrNull().orEmpty()

    private fun searchTypeLabel(): String =
        if (SearchHint.type > 0)
            "${MT.name(SearchHint.type)} [${MT.letter(SearchHint.type)}] ${MT.size(SearchHint.type)}B"
        else "unknown（由手机端 UI 发起；search_page 按原始 hex 显示）"

    /** 三合一状态文本（search_status 的返回体）。 */
    private fun searchStateText(): String = buildString {
        appendLine("running=${searchRunning()}")
        appendLine("count=${searchCount()}")
        appendLine("status=${searchStatusText()}")
        append("type=").append(searchTypeLabel())
        append("\n结果集与手机悬浮窗「搜索」页共用（native 全局 g_hits）")
    }

    /** "type" 参数 → MT 类型常量；空串返回 null（由调用方决定默认值）。 */
    private fun parseSearchType(s: String): Int? {
        val t = s.trim().lowercase()
        if (t.isEmpty()) return null
        return when (t) {
            "dword", "d", "int", "int32", "u32" -> MT.DWORD
            "float", "f", "f32" -> MT.FLOAT
            "qword", "q", "int64", "long", "u64" -> MT.QWORD
            "word", "w", "int16", "u16", "short" -> MT.WORD
            "byte", "b", "int8", "u8" -> MT.BYTE
            "double", "e", "float64", "f64" -> MT.DOUBLE
            else -> {
                val n = t.toIntOrNull()
                if (n != null && n in intArrayOf(MT.BYTE, MT.WORD, MT.DWORD,
                        MT.QWORD, MT.FLOAT, MT.DOUBLE)) n else null
            }
        }
    }

    /** 解析 type 参数：空 → fallback；非法 → (null, 可读错误)。 */
    private fun resolveTypeArg(args: JSONObject, fallback: Int): Pair<Int?, String> {
        val raw = args.optString("type", "").trim()
        if (raw.isEmpty()) return fallback to ""
        val t = parseSearchType(raw)
            ?: return null to ("ERR: type 非法：\"$raw\"。可用 dword/float/qword/word/byte/double，" +
                "或数值 4/16/32/2/1/64")
        return t to ""
    }

    /** 区域名 → RANGE_* 值（与 cpp/MemToolTypes.h、Pages.kt 的 Areas.list 一致）。 */
    private val AREA_NAMES = linkedMapOf(
        "all" to 0,
        "java_heap" to 2, "java-heap" to 2, "jh" to 2,
        "c_heap" to 1, "c-heap" to 1, "ch" to 1,
        "c_alloc" to 4, "c-alloc" to 4, "ca" to 4,
        "c_data" to 8, "c-data" to 8, "cd" to 8,
        "c_bss" to 16, "c-bss" to 16, "cb" to 16,
        "anonymous" to 32, "anon" to 32, "a" to 32,
        "java" to 65536, "j" to 65536,
        "stack" to 64, "s" to 64,
        "ashmem" to 524288, "as" to 524288,
        "video" to 1048576, "v" to 1048576,
        "other" to -2080896, "o" to -2080896,
        "bad" to 131072, "b" to 131072,
        "code_app" to 16384, "code-app" to 16384, "xa" to 16384,
        "code_system" to 32768, "code-system" to 32768, "xs" to 32768)

    /**
     * 解析 areas 参数：缺省/all → [0]（RANGE_ALL，即全部内存）。
     * 支持 JSON 数组（整数或区域名），也兼容单个字符串 "32,64" / "all"。
     */
    private fun areasArg(args: JSONObject): Pair<IntArray?, String> {
        val arr = args.optJSONArray("areas")
        if (arr != null) {
            val out = ArrayList<Int>(arr.length())
            for (i in 0 until arr.length()) {
                when (val e = arr.opt(i)) {
                    is Number -> out.add(e.toInt())
                    is String -> {
                        val name = e.trim()
                        if (name.isEmpty()) continue
                        val id = AREA_NAMES[name.lowercase()]
                            ?: return null to ("ERR: areas 里的区域名非法：\"$name\"。" +
                                "可用：" + AREA_NAMES.keys.joinToString("/") +
                                "（或直接给 MemToolTypes 的整数）")
                        out.add(id)
                    }
                    else -> return null to "ERR: areas 只接受整数或区域名字符串"
                }
            }
            return if (out.isEmpty()) intArrayOf(0) to "" else out.toIntArray() to ""
        }
        val raw = args.optString("areas", "").trim()
        if (raw.isEmpty() || raw.equals("all", true)) return intArrayOf(0) to ""
        val out = ArrayList<Int>()
        for (part in raw.split(',')) {
            val p = part.trim()
            if (p.isEmpty()) continue
            val id = p.toIntOrNull() ?: AREA_NAMES[p.lowercase()]
                ?: return null to ("ERR: areas 里无法识别：\"$p\"（用逗号分隔的整数或区域名，" +
                    "如 \"stack,c_heap\"）")
            out.add(id)
        }
        return if (out.isEmpty()) intArrayOf(0) to "" else out.toIntArray() to ""
    }

    /**
     * 校验搜索值写法（与 native ParseTarget 一致：100 / 0x64 / 10~20）。
     * 合法返回 null，否则返回可读中文错误。
     */
    private fun valueErrorFor(value: String, type: Int): String? {
        if (value.isEmpty()) return "ERR: value 不能为空（支持 100 / 0x64 / 10~20）"
        val isFloat = type == MT.FLOAT || type == MT.DOUBLE
        val parts = value.split('~')
        if (parts.size > 2) return "ERR: 区间写法只能是 \"最小~最大\"（只允许一个 ~）"
        val re = if (isFloat)
            Regex("^[+-]?(\\d+(\\.\\d*)?|\\.\\d+)([eE][+-]?\\d+)?$")
        else
            Regex("^(0[xX][0-9a-fA-F]+|[+-]?\\d+)$")
        for (part in parts) {
            val s = part.trim()
            if (s.isEmpty()) return "ERR: 区间两端都不能为空（如 10~20）"
            val low = s.lowercase()
            if (isFloat && (low == "inf" || low == "+inf" || low == "-inf" || low == "nan")) continue
            if (!re.matches(s)) {
                return "ERR: value \"$s\" 与类型 ${MT.name(type)} 不符；" +
                    if (isFloat) "浮点写 1.5 / -2 / 1e-3，区间用 1.0~2.0"
                    else "整数写 100 / 0x64，区间用 10~20"
            }
        }
        return null
    }

    /** 从 raw 的低位字节取 ASCII 预览（可打印字符原样，其余 `.'）。 */
    private fun asciiOf(raw: Long, stride: Int): String {
        val n = if (stride in 1..8) minOf(stride, 4) else 4
        val sb = StringBuilder()
        for (i in 0 until n) {
            val b = ((raw ushr (8 * i)) and 0xFF).toInt()
            sb.append(if (b in 0x20..0x7E) b.toChar() else '.')
        }
        return sb.toString()
    }

    /** 启动精确/范围搜索（native 起 detached 线程，本函数立即返回）。 */
    private fun doSearchStart(args: JSONObject): Pair<Boolean, String> {
        val pid = args.optInt("pid", 0)
        if (pid <= 0) return false to "ERR: 缺少 pid（先用 list_processes 查目标进程）"
        if (!runCatching { NativeBridge.procAlive(pid) }.getOrDefault(false))
            return false to "ERR: 进程 $pid 不存在或已退出（用 list_processes 刷新后再试）"
        val value = args.optString("value", "").trim()
        if (value.isEmpty()) return false to "ERR: 缺少 value（支持 100 / 0x64 / 10~20）"
        val typeArg = resolveTypeArg(args, MT.DWORD)
        val type = typeArg.first ?: return false to typeArg.second
        val areaArg = areasArg(args)
        val areas = areaArg.first ?: return false to areaArg.second
        valueErrorFor(value, type)?.let { return false to it }
        if (searchRunning())
            return false to ("ERR: 已有搜索/过滤在后台运行（status=${searchStatusText()}）。" +
                "native 对并发 searchStart 是直接忽略（不报错），请先等它结束（search_status 轮询）")
        SearchHint.type = type
        SearchHint.pid = pid
        runCatching { NativeBridge.searchStart(pid, type, value, areas) }
        return true to buildString {
            appendLine("已启动精确搜索（异步，已立即返回）")
            appendLine("pid=$pid type=${MT.name(type)} value=\"$value\" " +
                "areas=${areas.joinToString(",")}")
            appendLine("running=${searchRunning()} count=${searchCount()}")
            append("status=${searchStatusText()}")
            append("\n说明：count 是上一轮遗留值，本次结果在后台线程结束时才写入；")
            append("用 search_status 轮询 running，完成后再用 search_page 读结果。")
        }
    }

    /** 分页读取结果（搜索进行中也允许，只返回已完成部分）。 */
    private fun doSearchPage(args: JSONObject): Pair<Boolean, String> {
        var offset = args.optInt("offset", 0)
        if (offset < 0) offset = 0
        var count = args.optInt("count", 20)
        if (count <= 0) count = 20
        if (count > 60) count = 60
        val withAscii = args.optBoolean("ascii", false)
        val running = searchRunning()
        val total = searchCount()
        if (total <= 0) {
            // 搜索进行中还没有已完成结果：这不是失败，返回成功 + 说明，避免 AI 当成报错。
            return if (running)
                true to ("搜索进行中（running=true，status=${searchStatusText()}）：" +
                    "目前还没有已完成的结果。用 search_status 轮询，等 running=false 再读。")
            else
                false to "ERR: 还没有搜索结果（先 search_start 精确搜索，或 fuzzy_start 做模糊快照）"
        }
        if (offset >= total)
            return true to "offset=$offset 超出范围（total=$total，最大有效 offset=${total - 1}）"
        val raw = runCatching { NativeBridge.searchPage(offset, count) }.getOrNull().orEmpty()
        if (raw.isBlank())
            return false to ("ERR: 读取结果页失败（total=$total offset=$offset）。" +
                "可能原因：目标进程已退出；或结果集刚被「改善/新搜索」缩小（count 变了）。" +
                "先 search_status 复核 total，再用新的 offset 重试。")
        val type = SearchHint.type
        val stride = if (type > 0) MT.size(type).coerceAtLeast(1) else 4
        val lines = raw.split('\n').filter { it.isNotBlank() }
        val sb = StringBuilder()
        sb.append("results: total=").append(total)
            .append(" offset=").append(offset)
            .append(" shown=").append(lines.size)
            .append(" running=").append(running)
            .append("  type=").append(if (type > 0) MT.name(type) else "unknown")
            .append('\n')
        sb.append("status=").append(searchStatusText()).append('\n')
        for (ln in lines) {
            val f = ln.split('|')
            if (f.size < 2) continue
            // native 给的是 "addr|raw16hex"，地址与值都可能是无符号 64 位，
            // 用 MT.parseHex（内部 parseUnsignedLong，项目内通用）解析。
            val addr = MT.parseHex(f[0]) ?: continue
            val rawVal = MT.parseHex(f[1]) ?: 0L
            sb.append("0x").append(java.lang.Long.toHexString(addr))
            sb.append("  ")
            if (type > 0) {
                sb.append(String.format("%0${MT.size(type) * 2}X", rawVal))
                sb.append("  ").append(MT.fmt(type, rawVal))
            } else {
                // 类型未知（UI 发起的搜索）：只给原始 hex，不瞎解释成有符号/浮点。
                sb.append(java.lang.Long.toHexString(rawVal).uppercase())
                sb.append("  (raw)")
            }
            if (withAscii) sb.append("  |").append(asciiOf(rawVal, stride)).append("|")
            sb.append('\n')
        }
        sb.append("(offset ").append(offset).append("..").append(offset + lines.size - 1)
            .append(" / total ").append(total)
            .append("；下一页 offset=").append(offset + lines.size).append(")")
        return true to sb.toString()
    }

    /** 精确改善（异步，native 用已保存的 pid/结果集，不接受范围）。 */
    private fun doSearchRefine(args: JSONObject): Pair<Boolean, String> {
        val value = args.optString("value", "").trim()
        if (value.isEmpty()) return false to "ERR: 缺少 value（要保留的目标值，如 100 / 0x64）"
        if (value.contains('~'))
            return false to "ERR: 改善不支持范围写法（10~20 只能用于 search_start；" +
                "模糊搜索请用 fuzzy_filter）"
        if (searchRunning())
            return false to ("ERR: 已有搜索/过滤在后台运行（status=${searchStatusText()}），" +
                "等它结束后再改善")
        if (searchCount() <= 0)
            return false to "ERR: 当前没有可改善的结果（先 search_start 精确搜索）"
        val typeArg = resolveTypeArg(args, if (SearchHint.type > 0) SearchHint.type else MT.DWORD)
        val type = typeArg.first ?: return false to typeArg.second
        valueErrorFor(value, type)?.let { return false to it }
        SearchHint.type = type
        runCatching { NativeBridge.searchRefine(type, value) }
        return true to buildString {
            appendLine("已启动「改善」（异步，已立即返回）")
            appendLine("type=${MT.name(type)} value=\"$value\"")
            appendLine("running=${searchRunning()} count=${searchCount()}")
            append("status=${searchStatusText()}")
            append("\n说明：count 在后台过滤结束时才更新；反复用新的 value 改善可逐步收敛。")
        }
    }

    /** 清空结果（不打断后台线程）。 */
    private fun doSearchReset(): Pair<Boolean, String> {
        runCatching { NativeBridge.searchReset() }
        return true to buildString {
            appendLine("已清空搜索结果（search_reset）")
            appendLine("running=${searchRunning()} count=${searchCount()}")
            append("status=${searchStatusText()}")
            if (searchRunning())
                append("\n注意：后台仍有搜索线程在跑，它结束时会把结果写回（先等 running=false 再清更稳）。")
        }
    }

    /** 模糊搜索初始化（全量快照，异步）。 */
    private fun doFuzzyStart(args: JSONObject): Pair<Boolean, String> {
        val pid = args.optInt("pid", 0)
        if (pid <= 0) return false to "ERR: 缺少 pid（先用 list_processes 查目标进程）"
        if (!runCatching { NativeBridge.procAlive(pid) }.getOrDefault(false))
            return false to "ERR: 进程 $pid 不存在或已退出（用 list_processes 刷新后再试）"
        val typeArg = resolveTypeArg(args, MT.DWORD)
        val type = typeArg.first ?: return false to typeArg.second
        val areaArg = areasArg(args)
        val areas = areaArg.first ?: return false to areaArg.second
        if (searchRunning())
            return false to ("ERR: 已有搜索/过滤在后台运行（status=${searchStatusText()}），" +
                "等它结束再初始化")
        SearchHint.type = type
        SearchHint.pid = pid
        runCatching { NativeBridge.fuzzyStart(pid, type, areas) }
        return true to buildString {
            appendLine("已启动模糊搜索初始化（异步快照，已立即返回）")
            appendLine("pid=$pid type=${MT.name(type)} areas=${areas.joinToString(",")}")
            appendLine("running=${searchRunning()} count=${searchCount()}")
            append("status=${searchStatusText()}")
            append("\n下一步：等 running=false（快照完成，上限 1000000 条）后，用 fuzzy_filter 按变化筛选。")
        }
    }

    /** 模糊改善（异步）。 */
    private fun doFuzzyFilter(args: JSONObject): Pair<Boolean, String> {
        val op = parseFuzzyOp(args.opt("op"))
            ?: return false to ("ERR: op 非法（或缺失）。用 0/unchanged=未变化、1/changed=有变化、" +
                "2/increased=变大、3/decreased=变小")
        if (searchRunning())
            return false to ("ERR: 已有搜索/过滤在后台运行（status=${searchStatusText()}），" +
                "等它结束再过滤")
        if (searchCount() <= 0)
            return false to ("ERR: 结果集为空，无法过滤（先 fuzzy_start 做快照；" +
                "精确搜索结果请用 search_refine）")
        runCatching { NativeBridge.fuzzyFilter(op) }
        val opName = when (op) {
            0 -> "未变化"; 1 -> "有变化"; 2 -> "变大"; else -> "变小"
        }
        return true to buildString {
            appendLine("已下发模糊「改善」（异步，已立即返回）")
            appendLine("op=$op ($opName)")
            appendLine("running=${searchRunning()} count=${searchCount()}")
            append("status=${searchStatusText()}")
            append("\n说明：count 在过滤结束时更新；可反复调用逐步收敛。")
        }
    }

    /** op：整数 0..3 或 unchanged/changed/increased/decreased（也接受中文）。 */
    private fun parseFuzzyOp(v: Any?): Int? {
        if (v == null || v == org.json.JSONObject.NULL) return null
        if (v is Number) return v.toInt().takeIf { it in 0..3 }
        return when (v.toString().trim().lowercase()) {
            "0", "unchanged", "same", "no_change", "nochange", "未变化", "未变", "无变化" -> 0
            "1", "changed", "change", "有变化", "变化" -> 1
            "2", "increased", "increase", "up", "变大", "增加", "增加了" -> 2
            "3", "decreased", "decrease", "down", "变小", "减少", "减少了" -> 3
            else -> null
        }
    }

    // ═══════════════════ 注入 ═══════════════════

    /** 用 ptrace 注入器（或零 ptrace）注入到指定 pid；成功后记录目标并连接 agent。 */
    // ───────────── Java/ART hook（MCP 声明式封装，底层走 agent 的 Lua artHook）─────────────
    private fun luaQuote(s: String): String {
        val sb = StringBuilder("\"")
        for (c in s) {
            when (c) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\n' -> sb.append("\\n")
                '\r' -> {}
                '\t' -> sb.append("\\t")
                else -> sb.append(c)
            }
        }
        sb.append('"')
        return sb.toString()
    }

    private fun luaLiteral(v: Any?): String = when (v) {
        null, JSONObject.NULL -> "nil"
        is Boolean -> if (v) "true" else "false"
        is Number -> v.toString()
        is String -> {
            val s = v.trim()
            val asLong = s.toLongOrNull()
            val asDouble = s.toDoubleOrNull()
            when {
                asLong != null -> asLong.toString()
                asDouble != null -> asDouble.toString()
                s.equals("true", true) -> "true"
                s.equals("false", true) -> "false"
                s.equals("nil", true) || s.equals("null", true) -> "nil"
                else -> luaQuote(v)
            }
        }
        else -> luaQuote(v.toString())
    }

    private fun modeHint(mode: String): String = when (mode) {
        "log" -> "回调只打日志、不影响原方法；命中后用 agent_logs 读取（形如 [art] ... HIT ...）。"
        "replace" -> "回调直接返回固定值（原方法不执行；基本类型会自动装箱）。"
        else -> "回调执行你给的 Lua script：return 值覆盖返回值，return nil 透传调原方法。"
    }

    private fun doArtHook(args: JSONObject): Pair<Boolean, String> {
        val cls = args.optString("class", "").trim()
        val method = args.optString("method", "").trim()
        if (cls.isEmpty() || method.isEmpty()) return false to "ERR: 需要 class 和 method"
        val sig = args.optString("signature", "").trim()
        val mode = args.optString("mode", "log").trim().lowercase()
        val body: String = when (mode) {
            "log" -> "  print(\"[art] " + cls + "." + method + " HIT id=\" .. tostring(ctx.id) .. \" this=\" .. tostring(ctx.this))"
            "replace" -> {
                val vt = args.optString("value_type", "auto").trim().lowercase()
                val raw = if (args.has("value")) args.opt("value") else null
                val lit = when (vt) {
                    "number" -> (raw?.toString()?.toDoubleOrNull()?.let { n -> if (n == n.toLong().toDouble()) n.toLong().toString() else n.toString() }) ?: "0"
                    "boolean" -> if (raw == true || raw?.toString().equals("true", true)) "true" else "false"
                    "string" -> luaQuote(raw?.toString() ?: "")
                    "null" -> "nil"
                    else -> luaLiteral(raw)
                }
                "  return " + lit
            }
            "script" -> args.optString("script", "")
            else -> return false to "ERR: mode 只能是 log / replace / script"
        }
        val script = buildString {
            appendLine("local __id, __err = artHook(${luaQuote(cls)}, ${luaQuote(method)}, ${luaQuote(sig)}, function(ctx)")
            appendLine(body)
            appendLine("end)")
            appendLine("if __id then print(\"__ATHOOK_ID__=\" .. tostring(__id)) else print(\"__ATHOOK_ERR__=\" .. tostring(__err)) end")
        }
        val out = runCatching { AdbBridge.runLuaForTools(script) }
            .getOrElse { return false to "ERR: run_lua 异常: ${it.message}" }
        val err = Regex("__ATHOOK_ERR__=(.+)").find(out)?.groupValues?.get(1)
        if (err != null) return false to "ERR: artHook 失败: ${err.trim()}\n$out"
        val id = Regex("__ATHOOK_ID__=(\\d+)").find(out)?.groupValues?.get(1)?.toIntOrNull()
            ?: return false to "ERR: 无法解析 hook id（agent 是否已注入/连接？）\n$out"
        return true to buildString {
            appendLine("已安装 Java hook: id=$id")
            appendLine("class=$cls method=$method signature=${sig.ifEmpty { "(按方法名唯一匹配)" }} mode=$mode")
            appendLine(modeHint(mode))
            append("原始响应：\n").append(out)
        }
    }

    private fun doArtUnhook(args: JSONObject): Pair<Boolean, String> {
        val id = args.optInt("id", 0)
        if (id <= 0) return false to "ERR: 需要 id（art_hooks 可查）"
        val script = "local ok, err = artUnhook($id)\n" +
            "print(\"__ARTUNHOOK__=\" .. tostring(ok) .. \"|\" .. tostring(err))"
        val out = runCatching { AdbBridge.runLuaForTools(script) }
            .getOrElse { return false to "ERR: run_lua 异常: ${it.message}" }
        val m = Regex("__ARTUNHOOK__=(\\w+)\\|(.*)").find(out)
        val ok = m?.groupValues?.get(1)?.equals("true", true) == true
        if (!ok) return false to "ERR: 卸载失败\n$out"
        return true to "已卸载 Java hook id=$id"
    }

    private fun doArtHooks(): Pair<Boolean, String> {
        val script = """
            local hs = artHooks()
            if #hs == 0 then print("__ARTHOOKS__=(none)") else
              for _, h in ipairs(hs) do
                print("__ARTHOOKS__=" .. h.id .. "|" .. h.class .. "|" .. h.method .. "|" .. h.signature .. "|" .. h.mode)
              end
            end
        """.trimIndent()
        val out = runCatching { AdbBridge.runLuaForTools(script) }
            .getOrElse { return false to "ERR: run_lua 异常: ${it.message}" }
        val rows = Regex("__ARTHOOKS__=(.+)").findAll(out).map { it.groupValues[1].trim() }.toList()
        if (rows.isEmpty()) return false to "ERR: 无法读取 hook 列表（agent 是否已注入？）\n$out"
        if (rows.size == 1 && rows[0] == "(none)") return true to "当前没有 Java hook"
        return true to buildString {
            appendLine("当前 Java hook: ${rows.size} 个")
            for (r in rows) appendLine(r)
            append("原始响应：\n").append(out)
        }
    }

    private fun doAgentLogs(args: JSONObject): Pair<Boolean, String> {
        var n = args.optInt("lines", 100)
        if (n <= 0) n = 100
        if (n > 400) n = 400
        val all = runCatching { AdbBridge.toolLogs() }.getOrNull().orEmpty()
        if (all.isBlank()) return true to "（暂无日志）"
        val lines = all.split('\n').filter { it.isNotBlank() }
        val tail = lines.takeLast(n)
        return true to buildString {
            appendLine("agent 日志（共 ${lines.size} 行，返回最后 ${tail.size} 行）：")
            append(tail.joinToString("\n"))
        }
    }

    fun injectByPid(pid: Int, zero: Boolean = false, extraFlags: String = ""): Pair<Boolean, String> {
        if (pid <= 0) return false to "ERR: pid 不合法"

        // P0-1：记录注入前的 agent 实例，注入后对比并打印证据。
        // 固定 socket 名 + 无 detach 时，同进程重复注入会 bind 冲突、客户端连回旧 agent，
        // 没有这行用户无法判断"到底换没换"。
        val oldStatus = if (runCatching { NativeBridge.socketIsConnected() }.getOrDefault(false)) {
            runCatching { NativeBridge.socketAgentStatus() }.getOrNull().orEmpty()
        } else ""
        val oldInst = Regex("instance=(0x[0-9a-f]+)").find(oldStatus)?.groupValues?.get(1)
        val oldPid = Regex("pid=(\\d+)").find(oldStatus)?.groupValues?.get(1)?.toIntOrNull() ?: 0
        val oldHooks = Regex("hooks=(\\d+)").find(oldStatus)?.groupValues?.get(1) ?: "?"
        val wasConnected = oldStatus.isNotBlank()

        // 重注入前先清理旧 agent 的 hook，避免 Dobby 跳板指向已失效的 Lua 状态。
        val cleanup = runCatching { SocketUtil.cleanupHooksBeforeInject("重新注入 pid=$pid") }
            .getOrNull().orEmpty()
        val out = runCatching {
            if (zero) NativeBridge.injectPidZero(pid)
            else if (extraFlags.isBlank()) NativeBridge.injectPid(pid)
            else NativeBridge.injectPidArgs(pid, extraFlags)
        }.getOrNull().orEmpty()
        // runCatching 拦不住 null，必须显式判空，否则后面 out.contains 会抛 NPE
        //（外部 AI 实测过 "Parameter specified as non-null is null"）。
        if (out.isBlank())
            return false to ("注入失败（pid=$pid）：注入器没有返回任何输出" +
                "（进程可能已退出 / 无 root / 注入器缺失）")
        // 两条注入路径的成功标记不同：
        //   · 传统 ptrace 注入器：native 输出含 "Injection successful"
        //   · 零 ptrace（data-only）：native 输出 [ZPT-OK] / [ZPT-FAIL]
        //     （与 UI 的 finishInject 判据一致，见 Pages.kt）
        val zeroOk = out.contains("[ZPT-OK]")
        val ok = out.contains("Injection successful") || zeroOk
        if (!ok) return false to classifyInjectFailure(out, pid, zero)
        // 记录为当前目标：agent 连接需要 pkg 名
        val name = processNameOf(pid)
        if (name.isNotEmpty()) {
            OState.pid = pid
            OState.pname = name
            if (name.contains('.')) OState.pkg = name
        }
        var bpNote = ""
        if (runCatching { NativeBridge.bpIsRunning() }.getOrDefault(false)) {
            val svcPid = runCatching { NativeBridge.bpTargetPid() }.getOrDefault(0)
            if (svcPid > 0 && svcPid != pid) {
                runCatching { NativeBridge.bpStop() }
                BpUi.clearAll()
                runCatching { OverlayManager.instance?.syncBpChips() }
                bpNote = "\n断点服务: 之前绑在 pid=$svcPid，已自动停止并清空旧断点（新目标需重新 bp_start）"
            }
        }
        // 注入成功后 App 侧的 socket 通道要重连一次
        val (cok, cmsg) = AdbBridge.connectAgentOnce(6000)
        val base = out.lineSequence().firstOrNull { it.contains("Base:") }?.trim() ?: ""
        return true to buildString {
            if (zero) append("零 ptrace 注入成功 pid=") else append("注入成功 pid=")
            append(pid)
            if (name.isNotEmpty()) append(" (").append(name).append(")")
            if (base.isNotEmpty()) append(" | ").append(base)
            append("\n方式=").append(
                if (zero) "零 ptrace（data-only GOT 劫持，无 ptrace 关系）"
                else "传统 ptrace 注入器")
            if (extraFlags.isNotBlank())
                append("\n注入器开关=").append(extraFlags.trim())
            if (cleanup.isNotBlank()) append("\n").append(cleanup)
            append("\nagent: ").append(if (cok) cmsg else "未连上 - $cmsg")
            // P0-1：实例证据（旧 → 新）
            val newStatus = if (cok) {
                runCatching { NativeBridge.socketAgentStatus() }.getOrNull().orEmpty()
            } else ""
            val newInst = Regex("instance=(0x[0-9a-f]+)").find(newStatus)?.groupValues?.get(1)
            val newHooks = Regex("hooks=(\\d+)").find(newStatus)?.groupValues?.get(1) ?: "?"
            append("\n[实例] ")
            if (!wasConnected || oldInst == null) {
                append("首次注入，instance=").append(newInst ?: "?")
            } else if (oldInst == newInst) {
                // P2-21：给可执行指令，而不是泛泛的"请重启"。
                // 原因：agent 的抽象 socket 名固定（udt_debug_chan），旧 agent 不退出时新 agent
                // bind 失败、客户端仍连回旧实例；当前 agent 也不支持 __detach__ 热替换。
                val pkgForStop = name.ifEmpty { OState.pkg }
                append("⚠ 旧 agent 仍占用：instance=").append(oldInst)
                    .append(" 未变化（hooks=$oldHooks→$newHooks），新 agent 没能接管连接。")
                append("\n  原因：agent socket 用固定抽象名 udt_debug_chan，旧 agent 未退出时新 agent ")
                append("bind 失败、客户端仍连旧实例；当前 agent 不支持 __detach__ 热替换。")
                append("\n  处理（任选其一，需 root；本工具**不会**自动杀进程）：")
                if (pkgForStop.contains('.'))
                    append("\n    1) adb shell am force-stop ").append(pkgForStop)
                        .append("  然后重新 inject_pid（pid 会变，先用 list_processes 查新 pid）")
                else
                    append("\n    1) adb shell am force-stop <包名>  然后重新 inject_pid（pid 会变）")
                append("\n    2) 在手机上手动强停/重启目标 App，再 inject_pid")
                append("\n  说明：只想复用旧 agent 的话可以继续用当前连接（hook/base 都是旧实例的）。")
            } else {
                append("旧 instance=").append(oldInst).append(" hooks=$oldHooks")
                    .append(" → 新 instance=").append(newInst ?: "?")
                    .append(" hooks=$newHooks（已更换）")
            }
            if (bpNote.isNotBlank()) append(bpNote)
            if (oldPid != 0 && oldPid != pid) {
                append("\n[实例] 注意：注入前连接的是 pid=$oldPid，目标 pid=$pid")
            }
        }
    }

    /**
     *
     * 动机：`inject_pid` 只能往"已经跑起来几十秒"的进程里塞，而很多目标在启动后
     * 几秒就完成初始化 / 开始自检，最干净的注入窗口已经错过。
     * 这里把「force-stop → am start → 轮询 pid → 注入 → 连 agent → autorun」串成一步，
     * 并返回两个耗时，方便判断有没有抢到窗口。
     */
    private fun doLaunchAndInject(ctx: Context, args: JSONObject): Pair<Boolean, String> {
        val pkg = args.optString("pkg", "").trim()
        if (pkg.isEmpty()) return false to "ERR: 需要 pkg（如 com.miui.calculator）"
        val zero = args.optBoolean("zero", false)
        val restart = args.optBoolean("restart", true)
        val waitMs = args.optInt("wait_ms", 8000).coerceIn(500, 30000)
        val explicitActivity = args.optString("activity", "").trim()

        val pm = ctx.packageManager
        val launch = runCatching { pm.getLaunchIntentForPackage(pkg) }.getOrNull()
            ?: return false to "ERR: 找不到 $pkg 的启动入口（未安装 / 不是可启动应用）"
        val comp = launch.component
        val component = when {
            explicitActivity.isNotEmpty() ->
                if (explicitActivity.contains('/')) explicitActivity else "$pkg/$explicitActivity"
            comp != null -> "${comp.packageName}/${comp.className}"
            else -> ""
        }

        val sb = StringBuilder()
        sb.append("launch_and_inject: pkg=").append(pkg)
        if (component.isNotEmpty()) sb.append("  activity=").append(component)
        sb.append('\n')
        val t0 = System.currentTimeMillis()

        // 1) 可选 force-stop：拿全新进程（旧 agent / 旧 hook 一并消失）
        if (restart) {
            runCatching { NativeBridge.runSuShell("am force-stop $pkg") }
            sb.append("1) force-stop：已强停旧进程\n")
            Thread.sleep(120)
        } else {
            sb.append("1) restart=false：不强停，直接拉起（可能拿到旧进程）\n")
        }

        // 2) 拉起：优先 root 的 am start（App 在后台也能拉起），失败再退回 startActivity
        var launchOut = ""
        if (component.isNotEmpty()) {
            launchOut = runCatching { NativeBridge.runSuShell("am start -n $component") }
                .getOrNull().orEmpty().trim()
        }
        val launchLooksBad = launchOut.isEmpty() ||
            launchOut.contains("Error", true) || launchOut.contains("Exception", true) ||
            launchOut.contains("does not exist", true) || launchOut.contains("not found", true)
        if (launchLooksBad) {
            runCatching {
                launch.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                ctx.startActivity(launch)
            }
            if (launchOut.isNotEmpty()) sb.append("   am start 输出：").append(launchOut).append('\n')
        }
        sb.append("2) 已拉起（").append(if (launchLooksBad) "startActivity" else "am start").append("）\n")

        // 3) 轮询 pid（30ms 一次；pidof 走 su，通常几十毫秒内就能看到）
        var pid = 0
        val deadline = System.currentTimeMillis() + waitMs
        while (System.currentTimeMillis() < deadline) {
            val out = runCatching { NativeBridge.runSuShell("pidof $pkg") }.getOrNull().orEmpty()
            val cand = out.trim().split(Regex("\\s+"))
                .firstOrNull { it.isNotEmpty() && it.all { c -> c.isDigit() } }
                ?.toIntOrNull() ?: 0
            if (cand > 0) { pid = cand; break }
            Thread.sleep(30)
        }
        if (pid <= 0) {
            return false to (sb.toString() +
                "ERR: ${waitMs}ms 内没等到 $pkg 的进程（启动失败 / 包名不对 / 被系统拦截）")
        }
        sb.append("3) 拿到 pid=").append(pid)
            .append("（启动→pid 用时 ").append(System.currentTimeMillis() - t0).append("ms）\n")

        // 4) 注入（复用 injectByPid：含旧 hook 清理 / agent 连接 / 实例证据）
        val (ok, msg) = injectByPid(pid, zero, buildInjectorFlags(args))
        if (!ok) return false to (sb.toString() + msg)
        sb.append(msg)
        sb.append("\n4) 启动→注入完成总用时 ").append(System.currentTimeMillis() - t0).append("ms")

        // 5) autorun（与 inject_pid 语义一致：失败只追加说明，不改变注入成功）
        val noAuto = args.optBoolean("no_autorun", false)
        val auto = if (noAuto)
            "\nautorun: 已按 no_autorun=true 跳过（已存脚本未改动）"
        else
            autorunSection(ctx, args.optString("autorun", ""))
        return true to (sb.toString() + auto)
    }

    /**
     * P1-21：把 agent 返回的 Java 栈行（`className|method|file|line|native`）压成一行摘要：
     * `a.B.c(X.java:12) <- a.B.d(X.java:30) <- ...`
     * 错误行（`ERR ...`）与空行会被跳过；解析不出任何帧时返回空串。
     */
    private fun compactJavaStack(raw: String, maxFrames: Int = 8): String {
        if (raw.isBlank()) return ""
        val frames = ArrayList<String>(maxFrames)
        for (ln in raw.lineSequence()) {
            if (ln.isBlank()) continue
            val p = ln.split('|')
            if (p.size < 4) continue          // "ERR ..." 这类行
            frames.add(p[0].trim() + "." + p[1].trim() + "(" + p[2].trim() + ":" + p[3].trim() + ")")
            if (frames.size >= maxFrames) break
        }
        return frames.joinToString(" <- ")
    }

    /**
     * -m memfd / -H hide-maps / -S hide-solist / -C dlclose-hide /
     * -D deep-obfuscate / -n no-copy；`stealth=true` = memfd + hide-maps + dlclose-hide。
     * 注意：零 ptrace（zero=true）路径不使用这些开关。
     */
    private fun buildInjectorFlags(args: JSONObject): String {
        var memfd = args.optBoolean("memfd", false)
        var hideMaps = args.optBoolean("hide_maps", false)
        val hideSolist = args.optBoolean("hide_solist", false)
        var dlcloseHide = args.optBoolean("dlclose_hide", false)
        val deep = args.optBoolean("deep_obfuscate", false)
        val noCopy = args.optBoolean("no_copy", false)
        if (args.optBoolean("stealth", false)) {
            memfd = true; hideMaps = true; dlcloseHide = true
        }
        val sb = StringBuilder()
        if (memfd) sb.append(" -m")
        if (hideMaps) sb.append(" -H")
        if (hideSolist) sb.append(" -S")
        if (dlcloseHide) sb.append(" -C")
        if (deep) sb.append(" -D")
        if (noCopy) sb.append(" -n")
        return sb.toString()
    }

    /**
     *（外部 AI 反馈：只回 "Cannot find remote dlopen" 看不出"进程不存在"）。
     */
    internal fun classifyInjectFailure(out: String, pid: Int, zero: Boolean): String {
        val head = if (zero) "零 ptrace 注入失败（pid=$pid）" else "注入失败（pid=$pid）"
        val t = out.lowercase()
        val body = when {
            t.contains("cannot find remote dlopen") || t.contains("cannot find process") ->
                "\n原因：目标进程可能已经退出（pid 已失效）。\n" +
                    "下一步：用 list_processes 查新 pid；或直接用 launch_and_inject 一步完成拉起+注入。"
            t.contains("no such process") || t.contains("esrch") ->
                "\n原因：进程不存在（可能刚被系统/看门狗杀掉）。\n下一步：list_processes 确认存活后再注入。"
            t.contains("operation not permitted") || t.contains("eperm") || t.contains("ptrace_attach") ->
                "\n原因：无权限 attach（目标 dumpable=0 / 有反调试 / 已被其他 tracer 占用）。\n" +
                    "下一步：① 试 zero=true（不建 ptrace 关系）；② 目标重启后立刻注入（launch_and_inject）；" +
                    "③ 加 stealth=true（memfd / hide-maps / dlclose-hide）。"
            t.contains("library not found") || t.contains("cannot open agent") ->
                "\n原因：agent .so 缺失或不可读。\n下一步：重装/重开 App 后重试（首次注入会自动解压）。"
            zero && t.contains("[zpt-fail]") ->
                "\n原因：零 ptrace 没撞到可劫持窗口（目标缺少 nanosleep/open 调用点，或 400ms 窗口没命中）。\n" +
                    "下一步：改用传统注入 + stealth=true；或先让目标跑一会儿产生调用再重试。"
            else ->
                "\n原因未识别；注入器完整输出：\n" + out.takeLast(1000)
        }
        return head + "\n" + body
    }

    /** 从进程表里按 pid 反查进程名（list_processes 的 "pid|ppid|name" 格式）。 */
    private fun processNameOf(pid: Int): String {
        val table = runCatching { NativeBridge.scanProcesses() }.getOrNull().orEmpty()
        for (line in table.lineSequence()) {
            val parts = line.trim().split('|')
            if (parts.size >= 3 && parts[0].trim().toIntOrNull() == pid) {
                return parts[2].trim()
            }
        }
        return ""
    }

    /** 允许 "0x1234" / "1234" / 十进制数字（JSON number 被 optString 转成十进制）。 */
    private fun parseAddr(s: String): Long {
        val t = s.trim()
        return runCatching {
            when {
                t.startsWith("0x", true) -> t.substring(2).toLong(16)
                t.isEmpty() -> 0L
                // 纯数字且不含 a-f：既可能是十进制也可能是十六进制；地址一般以 0x 给出，
                // 这里对纯数字按十进制处理，避免 1000 被当成 0x1000。
                t.all { it.isDigit() } -> t.toLong()
                else -> t.toLong(16)
            }
        }.getOrDefault(0L)
    }

    private fun hexToBytes(s: String): ByteArray? {
        val t = s.trim().replace(" ", "").replace("\n", "")
        if (t.isEmpty() || t.length % 2 != 0) return null
        if (!t.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
        val out = ByteArray(t.length / 2)
        for (i in out.indices) {
            out[i] = t.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return out
    }

    // ═══════════════════ 地址表达式（P2-16，mem_page 的 addr）═══════════════════

    /**
     * 解析 mem_page 的 addr 表达式。支持：
     *   · 纯数字：`0x1234` / `1234`（十进制）/ `7f3a12c4`（无 0x 前缀的纯 hex，与 parseAddr 语义一致）
     *   · 模块 ± 偏移：`libxxx.so+0x1234` / `libxxx.so-0x10`
     *     （模块名交给 [moduleBase]，支持短名 / 全路径 / 包含匹配，需要 agent 已连接）
     *   · 纯数字加减：`0x1000+0x20` / `0x1000-0x20`
     * 返回 (地址, 错误文本)：成功时第二项为空串；失败时第一项为 null，
     * 且错误文本会指出**哪一段**没解析出来（模块项 / 偏移项 / 运算符个数）。
     */
    private fun resolveAddrExpr(raw: String): Pair<Long?, String> {
        val s = raw.trim()
        if (s.isEmpty()) return null to "ERR: 缺少 addr"
        asPlainNumber(s)?.let { return it to "" }

        // 只认一个运算符：从左往右找"右侧能解析成数字"的 +/-。
        // 这样模块名自带的连字符（如 libfoo-bar.so）不会被误当运算符。
        var opIdx = -1
        var op = ' '
        var i = 1
        while (i < s.length) {
            val c = s[i]
            if (c == '+' || c == '-') {
                val rhsProbe = s.substring(i + 1).trim()
                if (rhsProbe.isNotEmpty() && asPlainNumber(rhsProbe) != null) {
                    if (opIdx >= 0)
                        return null to ("ERR: 只支持一个 + 或 -；\"$s\" 里有多个运算符，" +
                            "更复杂的表达式请先自己算成地址再传")
                    opIdx = i
                    op = c
                }
            }
            i++
        }
        if (opIdx < 0) {
            // 没有运算符：也允许只给模块名 → 直接取该模块基址
            moduleBase(s)?.let { return it to "" }
            return null to ("ERR: 无法解析地址 \"$s\"。支持 0x1234 / 1234 / libxxx.so+0x1234 / " +
                "libxxx.so-0x10 / 0x1000+0x20（模块名需 agent 已连接，可先用 list_modules 确认）")
        }
        val lhs = s.substring(0, opIdx).trim()
        val rhsText = s.substring(opIdx + 1).trim()
        if (lhs.isEmpty()) return null to "ERR: 运算符 \"$op\" 左侧缺少地址或模块名"
        val rhs = asPlainNumber(rhsText)
            ?: return null to "ERR: 偏移项 \"$rhsText\" 不是合法数字（支持 0x1234 / 1234）"
        val baseNum = asPlainNumber(lhs)
        val base: Long
        val baseDesc: String
        if (baseNum != null) {
            base = baseNum
            baseDesc = "0x" + java.lang.Long.toHexString(baseNum)
        } else {
            val b = moduleBase(lhs)
                ?: return null to ("ERR: 模块项 \"$lhs\" 解析失败：没有找到该模块。" +
                    "先确认 agent 已连接，再用 list_modules 看已加载的 so 名" +
                    "（支持短名/全路径/包含匹配）")
            base = b
            baseDesc = "模块 \"$lhs\"(base=0x" + java.lang.Long.toHexString(b) + ")"
        }
        val v = if (op == '+') base + rhs else base - rhs
        if (v <= 0) {
            return null to ("ERR: 计算结果不是有效地址：" + baseDesc + " " + op + " 0x" +
                java.lang.Long.toHexString(rhs) + " = 0x" + java.lang.Long.toHexString(v) +
                "（<= 0 或溢出）")
        }
        return v to ""
    }

    /** 纯数字（十进制 / 0x 十六进制 / 无前缀纯 hex）→ Long；带符号或含其他字符返回 null。 */
    private fun asPlainNumber(s: String): Long? {
        val t = s.trim()
        if (t.isEmpty()) return null
        return runCatching {
            when {
                t.startsWith("0x", true) -> {
                    val h = t.substring(2)
                    if (h.isEmpty() || !h.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' })
                        null
                    else java.lang.Long.parseUnsignedLong(h, 16)
                }
                t.all { it.isDigit() } -> t.toLongOrNull()
                // 无 0x 前缀的纯 hex 串（与 parseAddr 对 "7f3a12c4" 的处理保持一致）
                t.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' } ->
                    java.lang.Long.parseUnsignedLong(t, 16)
                else -> null
            }
        }.getOrNull()
    }

    // ═══════════════════ 注入后自动执行脚本（P1-12）═══════════════════

    /**
     * inject_pid 成功后调用：显式传入的 autorun 优先，否则读固定文件
     * `<filesDir>/scripts/autorun.lua`。返回要**追加**在注入结果后面的文本。
     *
     * 语义：autorun 失败**不改变**注入成功的判定（inject_pid 仍返回 ok），
     * 但这里必须把失败原因写清楚，方便 AI / 人直接定位。
     */
    private fun autorunSection(ctx: Context, explicit: String): String {
        var script = explicit
        val source: String
        if (script.isNotBlank()) {
            source = "参数 autorun"
        } else {
            val f = runCatching { AdbBridge.autorunFile(ctx) }.getOrNull()
                ?: return "\nautorun: 跳过（无法定位 <filesDir>/scripts/autorun.lua）"
            if (!f.isFile)
                return "\nautorun: 跳过（未传 autorun 参数，且 " + f.absolutePath + " 不存在）"
            val read = runCatching { f.readText() }
            if (read.isFailure)
                return "\nautorun: 读取失败（" + f.absolutePath + "）: " +
                    (read.exceptionOrNull()?.message ?: "未知错误")
            script = read.getOrNull().orEmpty()
            source = f.absolutePath
        }
        if (script.isBlank()) return "\nautorun: 跳过（脚本为空）"
        if (!runCatching { NativeBridge.socketIsConnected() }.getOrDefault(false))
            return "\nautorun: 跳过（agent 未连接，SO 通道不可用；注入本身已成功）"
        val out = runCatching { AdbBridge.runLuaForTools(script) }
            .getOrElse { e ->
                return "\nautorun: 执行失败（来源=" + source + "）: run_lua 异常 " +
                    (e.message ?: e.toString()) +
                    "\n（注入本身已成功，autorun 失败不影响注入结果）"
            }
        val bad = out.startsWith("ERR") || out.contains("[Lua 错误]")
        val body = if (out.length > 4000)
            out.take(4000) + "\n…（输出过长已截断；完整脚本日志用 agent_logs 读）"
        else out
        return buildString {
            append("\nautorun: ").append(if (bad) "执行失败" else "已执行")
            append("（来源=").append(source).append("）")
            if (bad) append("；注入本身已成功，autorun 失败不影响注入结果")
            append("\n--- autorun 输出 ---\n").append(body.trimEnd())
            if (bad)
                append("\n提示：常见原因是 Lua 语法错误或调用了不存在的 API" +
                    "（可先 run_lua 执行 api() 查签名）")
        }
    }

    /** get_autorun：读固定路径文件；不存在时返回提示（不算错误）。 */
    private fun doGetAutorun(ctx: Context): Pair<Boolean, String> {
        val f = runCatching { AdbBridge.autorunFile(ctx) }.getOrElse { e ->
            return false to "ERR: 无法定位 autorun 路径: " + (e.message ?: e.toString())
        }
        if (!f.exists())
            return true to ("（未设置 autorun）\n路径: " + f.absolutePath +
                "\n用 set_autorun 写入，或在 inject_pid 里传 autorun 参数临时执行。")
        val read = runCatching { f.readText() }
        if (read.isFailure)
            return false to "ERR: 读取 " + f.absolutePath + " 失败: " +
                (read.exceptionOrNull()?.message ?: "未知错误")
        val text = read.getOrNull().orEmpty()
        return true to buildString {
            append("路径: ").append(f.absolutePath).append('\n')
            append("大小: ").append(f.length()).append(" 字节 / ")
            append(text.length).append(" 字符\n")
            append("--- script ---\n").append(text.trimEnd())
        }
    }

    /** set_autorun：写固定路径文件（>1MB 拒绝，给可读错误）。 */
    private fun doSetAutorun(ctx: Context, args: JSONObject): Pair<Boolean, String> {
        val script = args.optString("script", "")
        val f = runCatching { AdbBridge.autorunFile(ctx) }.getOrElse { e ->
            return false to "ERR: 无法定位 autorun 路径: " + (e.message ?: e.toString())
        }
        if (script.isBlank()) {
            if (!f.exists())
                return true to ("autorun 本来就不存在，无需清除\n路径: " + f.absolutePath)
            val del = runCatching { f.delete() }
            if (del.isFailure || del.getOrDefault(false) != true)
                return false to ("ERR: 删除 " + f.absolutePath + " 失败: " +
                    (del.exceptionOrNull()?.message ?: "delete() 返回 false"))
            return true to buildString {
                append("已清除 autorun（删除文件）\n")
                append("路径: ").append(f.absolutePath).append('\n')
                append("以后 inject_pid / launch_and_inject 不会再自动执行它")
            }
        }
        if (script.length > 1024 * 1024)
            return false to "ERR: script 过大（" + script.length + " 字符 > 1MB 上限）"
        val w = runCatching { f.writeText(script) }
        if (w.isFailure)
            return false to "ERR: 写入 " + f.absolutePath + " 失败: " +
                (w.exceptionOrNull()?.message ?: "未知错误")
        return true to buildString {
            append("已保存 autorun（下次 inject_pid 成功且 agent 连上后自动执行）\n")
            append("路径: ").append(f.absolutePath).append('\n')
            append("大小: ").append(script.length).append(" 字符")
        }
    }
}

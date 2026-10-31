package com.Alive.Trace.overlay

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.widget.Toast
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** 原生悬浮窗的 JNI 桥（实现见 cpp/overlay_bridge.cpp）。 */
object NativeBridge {
    external fun scanProcesses(): String
    external fun injectPkg(pkg: String): String
    external fun injectPid(pid: Int): String
    /**
     * extraArgs 直接拼给注入器，例如 " -m -H -C"（memfd / hide-maps / dlclose-hide）。
     * 支持开关：-m memfd、-H hide-maps、-S hide-solist、-C dlclose-hide、
     *            -D deep-obfuscate、-n no-copy。
     */
    external fun injectPidArgs(pid: Int, extraArgs: String): String
    // 零 ptrace 注入：data-only GOT 劫持，不建立 ptrace 关系（实验）
    external fun injectPkgZero(pkg: String): String
    external fun injectPidZero(pid: Int): String
    /**
     *
     * 两条注入路径（ptrace 与零 ptrace）都以 `su` 为前置，而 su 能否在 App 进程里
     * 提到权取决于 ROM/KernelSU 的挂载与授权状态。此前失败时只有一句
     * "无法启动 su"，看不出真因。这个接口把逐候选路径的实测结果与
     * 「能否真的拿到 uid=0」一起返回，供 UI 直接展示。
     */
    external fun suDiag(): String
    /** 手动指定 su 路径（特殊 ROM 兜底）；传空串恢复自动解析。 */
    external fun setSuPath(path: String)
    /**
     *
     * 断点服务是 `fork + execl("sh","-c",cmd)` 起 `su -c '... --bp <pid>'`，
     * 再用 150ms 存活检查判断成功与否。命令形式一旦被多套一层 shell，
     * 就会出现"子进程秒退 → 界面显示未启动"且**报错被 2>/dev/null 吞掉**。
     * 这个接口用 App 内真实方式复现两种形式，直接给出哪种可用。
     */
    external fun spawnDiag(): String
    external fun killProcess(pid: Int): String
    external fun procAlive(pid: Int): Boolean
    external fun suCmd(cmd: String): String
    external fun memRead(pid: Int, addr: Long, len: Int): ByteArray?
    external fun memFirstAddress(pid: Int): Long
    external fun memPage(pid: Int, addr: Long, rows: Int): String
    external fun memRegions(pid: Int): String
    external fun memWrite(pid: Int, addr: Long, data: ByteArray): Boolean
    external fun searchCount(): Int
    external fun searchStatus(): String
    external fun searchRunning(): Boolean
    external fun searchReset()
    external fun searchPage(offset: Int, count: Int): String
    external fun searchStart(pid: Int, type: Int, value: String, areas: IntArray)
    external fun fuzzyStart(pid: Int, type: Int, areas: IntArray)
    external fun fuzzyFilter(op: Int)
    external fun searchRefine(type: Int, value: String)
    external fun socketSetTarget(pkg: String)
    external fun socketConnect()
    external fun socketDisconnect()
    external fun socketIsConnected(): Boolean
    external fun socketStatus(): String
    external fun socketSendLua(script: String): String
    external fun socketAlloc(size: Long, prot: String): String
    external fun socketModules(): String
    external fun allocRemote(pid: Int, size: Long, prot: String): String
    external fun memDisasm(bytes: ByteArray): String

    /** 批量反汇编：返回每行 "addr|bytes|text"。 */
    external fun memDisasmBlock(base: Long, bytes: ByteArray): String
    external fun asmWrite(pid: Int, addr: Long, text: String): String
    external fun bpStart(pid: Int)
    external fun bpStop()
    external fun bpIsRunning(): Boolean
    external fun bpStatus(): String
    external fun bpSet(addr: Long, type: String, len: Int)
    external fun bpClear(addr: Long)
    external fun bpClearHits()
    /** 清除全部断点（服务端 clearall）。 */
    external fun bpClearAll()
    external fun bpHits(maxN: Int): String
    /**
     * （硬件断点命中行里有 tid；Android 上 tid == Thread.getId()）。
     * 返回一行一帧 "className|method|file|line|native"；失败返回 "ERR ..."。
     */
    external fun bpJavaStack(tid: Int, maxDepth: Int): String
    /** 断点服务最近一条 OK/ERR/INFO 响应（用于确认 set/clear 是否生效）。 */
    external fun bpLastLine(): String
    /** 断点服务当前绑定的目标 pid（未运行返回 0）。 */
    external fun bpTargetPid(): Int
    external fun socketLuaLogs(): String
    /** agent 自身信息："agent pid=<N> socket=@<name>"（App 重启后用于确定目标 pid）。 */
    external fun socketAgentInfo(): String
    /** agent 运行状态摘要（pid/pkg/base/hooks/hits/uptime）。 */
    external fun socketAgentStatus(): String

    /** 以 root 执行一条 shell（仅内部用于清理孤儿进程/诊断）。 */
    external fun runSuShell(cmd: String): String

}

/** 数值类型常量（与 cpp/MemToolTypes.h 一致）。 */
object MT {
    const val BYTE = 1
    const val WORD = 2
    const val DWORD = 4
    const val QWORD = 32
    const val FLOAT = 16
    const val DOUBLE = 64
    // 可写入扩展类型（字符串，仅编辑用，搜索不支持）
    const val ASCII = 100
    const val UTF16 = 101

    fun size(t: Int) = when (t) {
        BYTE -> 1; WORD -> 2; QWORD, DOUBLE -> 8; FLOAT -> 4
        ASCII, UTF16 -> -1; else -> 4
    }

    fun letter(t: Int) = when (t) {
        BYTE -> "B"; WORD -> "W"; DWORD -> "D"; QWORD -> "Q"
        FLOAT -> "F"; ASCII -> "A"; UTF16 -> "U"; else -> "E"
    }

    fun name(t: Int) = when (t) {
        BYTE -> "BYTE"; WORD -> "WORD"; DWORD -> "DWORD"; QWORD -> "QWORD"
        FLOAT -> "FLOAT"; ASCII -> "ASCII"; UTF16 -> "UTF-16LE"; else -> "DOUBLE"
    }

    /**
     * 原来 UI 只显示一个字母（D/F/Q/W/B/E/A/U），用户看不出 E 是 Double、
     * A 是 ASCII，且 ASM 与 Double 都落到 else 分支显示成两个 E。
     */
    fun describe(t: Int) = when (t) {
        BYTE -> "B: Byte (-128 ~ 127)"
        WORD -> "W: Word (-32,768 ~ 32,767)"
        DWORD -> "D: Dword (-2,147,483,648 ~ 2,147,483,647)"
        QWORD -> "Q: Qword (-9,223,372,036,854,775,808 ~ 9,223,372,036,854,775,807)"
        FLOAT -> "F: Float (±3.4e38，7 位有效数字)"
        DOUBLE -> "E: Double (±1.8e308，15 位有效数字)"
        ASCII -> "A: ASCII 字符串（变长）"
        UTF16 -> "U: UTF-16LE 字符串（变长）"
        else -> "?: 未知类型"
    }

    /** 搜索类型选择顺序（D/F 常用在前）。 */
    val all = intArrayOf(DWORD, FLOAT, QWORD, WORD, BYTE, DOUBLE)

    /** 地址统一显示格式（与内存页一致：大写、至少 8 位、无 0x）。 */
    fun addr(a: Long): String = "%08X".format(a)

    /**
     * 把「按类型宽度截断的原始值」还原成该类型的有符号值。
     *
     * 内存里 4 字节的 0xFFFFFFFB 就是 int32 的 -5；但搜索/读取回来的
     * raw 是宽度无关的 Long，高位没有做符号扩展，直接按无符号显示会
     * 变成 4294967291（这就是「d 类型负数溢出显示为正整数」的原因）。
     */
    fun normalizeRaw(t: Int, raw: Long): Long = when (t) {
        BYTE -> raw.toByte().toLong()
        WORD -> raw.toShort().toLong()
        DWORD -> raw.toInt().toLong()
        else -> raw            // QWORD/FLOAT/DOUBLE 本身是 8 字节宽度
    }

    /** 各类型的数值范围文本（供保存时选择格式用）。 */
    fun typeRange(t: Int): String = when (t) {
        BYTE -> "-128 ~ 127"
        WORD -> "-32768 ~ 32767"
        DWORD -> "-2147483648 ~ 2147483647"
        QWORD -> "-9223372036854775808 ~ 9223372036854775807"
        FLOAT -> "约 ±3.4e38 (7 位有效数字)"
        else -> "约 ±1.8e308 (15 位有效数字)"
    }

    /** raw 按类型格式化为显示值。 */
    fun fmt(t: Int, raw: Long): String {
        val v = normalizeRaw(t, raw)
        return when (t) {
            BYTE, WORD, DWORD, QWORD -> v.toString()
            FLOAT -> floatFromBits(v.toInt()).toString()
            else -> doubleFromBits(v).toString()
        }
    }

    private fun floatFromBits(b: Int) = Float.fromBits(b)
    private fun doubleFromBits(b: Long) = Double.fromBits(b)

    /** 显示值文本 → 原始字节（小端）。非法返回 null。 */
    fun encode(t: Int, text: String): ByteArray? = try {
        when (t) {
            ASCII -> text.toByteArray(Charsets.US_ASCII)
            UTF16 -> text.toByteArray(Charsets.UTF_16LE)
            else -> {
                val bb = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
                when (t) {
                    BYTE -> bb.put(text.trim().toByte())
                    WORD -> bb.putShort(text.trim().toShort())
                    DWORD -> bb.putInt(text.trim().toInt())
                    // QWORD 按有符号取值，负数可正常写入（toLong 溢出会抛异常
                    // → 返回 null，调用方提示格式错误）。
                    QWORD -> bb.putLong(text.trim().toLong())
                    FLOAT -> bb.putFloat(text.trim().toFloat())
                    else -> bb.putDouble(text.trim().toDouble())
                }
                val out = ByteArray(size(t))
                bb.flip()
                bb.get(out)
                out
            }
        }
    } catch (_: Exception) {
        null
    }

    /**
     * 十六进制文本 → Long，按无符号解析（最高位为 1 的 64 位值也能正确
     * 读入；Kotlin 的 toLongOrNull(16) 对有符号溢出会返回 null → 被当成 0，
     * 这是断点寄存器/搜索值显示为 0 的元凶之一）。
     */
    fun parseHex(s: String): Long? = try {
        val t = s.trim().removePrefix("0x").removePrefix("0X").ifEmpty { "0" }
        java.lang.Long.parseUnsignedLong(t, 16)
    } catch (_: Exception) {
        null
    }

    /** 无符号十进制/0x 十六进制文本 → Long（断点寄存器等原始值用）。 */
    fun parseUnsigned(s: String): Long {
        val t = s.trim()
        return if (t.startsWith("0x") || t.startsWith("0X"))
            java.lang.Long.parseUnsignedLong(t.substring(2), 16)
        else
            java.lang.Long.parseUnsignedLong(t)
    }

    /** 显示值文本 → raw（long 存储）。非法返回 null。 */
    fun parse(t: Int, text: String): Long? = try {
        when (t) {
            BYTE -> text.trim().toByte().toLong()
            WORD -> text.trim().toShort().toLong()
            DWORD -> text.trim().toInt().toLong()
            QWORD -> text.trim().toLong()
            FLOAT -> text.trim().toFloat().toBits().toLong()
            else -> text.trim().toDouble().toBits()
        }
    } catch (_: Exception) {
        null
    }
}

/** 内存范围（区域）常量与显示名。 */
object Areas {
    const val ALL = 0
    val list = listOf(
        0 to "所有内存 [ALL]",
        2 to "Java堆 [Jh]", 1 to "C堆 [Ch]", 4 to "C分配 [Ca]",
        8 to "C数据 [Cd]", 16 to "C未初始化 [Cb]", 32 to "匿名 [A]",
        65536 to "Java [J]", 64 to "栈 [S]", 524288 to "Ashmem [As]",
        1048576 to "视频 [V]", -2080896 to "其他 [O]", 131072 to "错误 [B]",
        16384 to "代码应用 [Xa]", 32768 to "代码系统 [Xs]",
    )
}

class SavedRow(val addr: Long, var type: Int, var label: String,
               var valueText: String, var frozen: Boolean,
               var name: String = "")   // 用户可自定义标记名

/** 悬浮窗各页共享状态。 */
object OState {
    // 注入方式：true = 零 ptrace（data-only），false = 传统 ptrace 注入器
    var zeroPtrace: Boolean = false
    @Volatile var pid = 0
    @Volatile var pname = "-"
    @Volatile var pkg = ""
    val saved = mutableListOf<SavedRow>()
    var searchType = MT.DWORD
    val areas = mutableListOf(Areas.ALL)
}

/**
 * SO 通道（加密 socket）小工具。
 *
 * 连接目标 socket 名由后端固定（`udt_debug_chan`），因此这里只负责
 * 偏好开关与状态读取——供选项页显示连接状态、以及注入成功后
 * 按「注入后自动连接 socket」自动建连。
 */
object SocketUtil {
    /**
     * 旧 agent 里安装的 Dobby hook 跳板会指向旧 Lua 状态；重注入后一旦目标调用
     * 这些函数就可能 SIGSEGV。这里先尽力卸载一遍（连得上才做），并记录数量。
     *
     * 返回给 UI/日志的一句话说明。
     */
    /**
     * 注入/换目标之前清理旧 agent。
     *
     * （卸 hook → 关 Lua → 停监听），新 agent 才能 bind 同名 socket；
     * 拿不到 pid 时退化为对当前连接执行 remove_all_hook。
     */
    fun cleanupHooksBeforeInject(reason: String): String {
        if (!runCatching { NativeBridge.socketIsConnected() }.getOrDefault(false)) {
            return "未连接旧 agent，跳过 hook 清理"
        }
        val before = runCatching { NativeBridge.socketAgentStatus() }.getOrDefault("")
        val hooksBefore = Regex("hooks=(\\d+)").find(before)?.groupValues?.get(1) ?: "?"
        runCatching { NativeBridge.socketSendLua("remove_all_hook()") }
        runCatching { Thread.sleep(250) }
        return "注入前清理完成（$reason，清理前 hooks=$hooksBefore）"
    }

    private const val PREF = "overlay"
    private const val KEY_AUTO_CONNECT = "inject_autoconnect"

    /**
     * 「零 ptrace 注入」开关的持久化。
     *
     * 写进配置，用户勾一次就记住了 —— 不用每次注入都重新点开对话框去勾。
     * 与「注入后自动连接 socket」同一份 SharedPreferences。
     */
    private const val KEY_ZERO_PTRACE = "inject_zeroptrace"

    fun isZeroPtrace(ctx: Context): Boolean = runCatching {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getBoolean(KEY_ZERO_PTRACE, false)
    }.getOrDefault(false)

    fun setZeroPtrace(ctx: Context, on: Boolean) {
        runCatching {
            ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .edit().putBoolean(KEY_ZERO_PTRACE, on).apply()
        }
    }

    /** ：stealth 注入开关（memfd + hide-maps + dlclose-hide），与 MCP 的 stealth=true 对齐。 */
    fun isStealthInject(ctx: Context): Boolean = runCatching {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getBoolean("inject_stealth", false)
    }.getOrDefault(false)

    fun setStealthInject(ctx: Context, on: Boolean) {
        runCatching {
            ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .edit().putBoolean("inject_stealth", on).apply()
        }
    }

    /** 最近一次成功注入的目标包名（注入后自动连接时用它做通道目标）。 */
    @Volatile var lastInjectedPkg = ""

    fun isAutoConnect(ctx: Context): Boolean = runCatching {
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
            .getBoolean(KEY_AUTO_CONNECT, false)
    }.getOrDefault(false)

    fun setAutoConnect(ctx: Context, on: Boolean) {
        runCatching {
            ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
                .edit().putBoolean(KEY_AUTO_CONNECT, on).apply()
        }
    }

    fun isConnected(): Boolean =
        runCatching { NativeBridge.socketIsConnected() }.getOrDefault(false)

    fun statusText(): String =
        runCatching { NativeBridge.socketStatus() }.getOrDefault("未连接")

    /** 建连前登记目标包名（失败不影响连接：socket 名固定）。 */
    fun prepareTarget(pkg: String) {
        runCatching { NativeBridge.socketSetTarget(pkg) }
    }

    /**
     * 连到上一个目标进程里的旧 agent）。不是的话：杀掉旧宿主进程 + 断开连接。
     * @return true=正常（或无法判断），false=发现并清理了旧 agent
     */
    fun verifyAgentPid(expected: Int): Boolean {
        if (expected <= 0) return true
        if (!isConnected()) return true
        val info = runCatching { NativeBridge.socketAgentInfo() }.getOrNull().orEmpty()
        val apid = Regex("pid=(\\d+)").find(info)?.groupValues?.getOrNull(1)
            ?.toIntOrNull() ?: return true
        if (apid == expected) return true
        android.util.Log.w("ATraceSock",
            "stale agent pid=$apid expected=$expected info=$info -> kill stale")
        runCatching { NativeBridge.runSuShell("kill -9 $apid") }
        runCatching { NativeBridge.socketDisconnect() }
        return false
    }

    /**
     * 注入成功后调用：若已开启「注入后自动连接 socket」则发起连接。
     * 后台轮询到真正连上再提示，避免给出错误的成功观感。
     */
    fun connectIfEnabled(ctx: Context, pkg: String) {
        if (!isAutoConnect(ctx)) return
        prepareTarget(pkg)
        NativeBridge.socketConnect()
        Thread {
            for (i in 0 until 30) {
                Thread.sleep(100)
                if (isConnected()) {
                    if (!verifyAgentPid(OState.pid)) {
                        toast(ctx, "检测到旧 agent（pid 不匹配），已杀掉旧进程并断开；请重新注入目标")
                        return@Thread
                    }
                    toast(ctx, "SO 通道已自动连接")
                    return@Thread
                }
            }
            toast(ctx, "SO 通道自动连接超时: " + statusText())
        }.start()
    }

    /**
     * 注入成功后把目标进程设为当前进程（自动选择）。
     *
     * 目标进程可能刚被拉起，所以带重试；同时清掉上一个进程的搜索
     * 结果，否则搜索/内存会在新进程上读到陈旧地址。
     *
     * 内部起后台线程：调用方可能在主线程（对话框按钮回调），而这里
     * 要轮询扫描 /proc，绝不能卡 UI。
     */
    fun selectProcessAfterInject(overlay: OverlayManager, pkg: String,
                                 pname: String) {
        val target = pkg.ifEmpty { pname }
        Thread {
            var pid = 0
            for (i in 0 until 10) {
                if (target.isNotEmpty()) pid = resolvePidByPkg(target)
                if (pid > 0) break
                Thread.sleep(300)
            }
            val label = when {
                pkg.isNotEmpty() -> pkg
                pname.isNotEmpty() && pname != "-" -> pname
                else -> target
            }
            overlay.onUi {
                if (pkg.isNotEmpty()) OState.pkg = pkg
                if (pid > 0) {
                    val changed = OState.pid != pid
                    OState.pid = pid
                    if (label.isNotEmpty()) OState.pname = label
                    if (changed) {
                        // 换了进程：旧结果对不上号，清掉。
                        runCatching { NativeBridge.searchReset() }
                    }
                    overlay.refreshProcRow()
                    overlay.toast("已选择 [${OState.pid}] ${OState.pname}")
                } else {
                    overlay.toast("注入成功，但未解析到进程（可手动选择）")
                }
            }
        }.start()
    }

    private fun toast(ctx: Context, msg: String) = runCatching {
        android.os.Handler(android.os.Looper.getMainLooper()).post {
            Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show()
        }
    }
}

/** 冻结：后台线程周期性把冻结行的值写回目标进程。 */
object Freezer : Thread("atrace-freeze") {
    @Volatile private var running = false

    @Synchronized
    fun ensureStarted() {
        if (running) return
        running = true
        start()
    }

    fun stopAll() {
        running = false
    }

    override fun run() {
        while (running) {
            val pid = OState.pid
            if (pid > 0) {
                synchronized(OState.saved) {
                    for (r in OState.saved) {
                        if (!r.frozen) continue
                        val data = MT.encode(r.type, r.valueText) ?: continue
                        NativeBridge.memWrite(pid, r.addr, data)
                    }
                }
            }
            try {
                sleep(400)
            } catch (_: InterruptedException) {
                return
            }
        }
    }
}

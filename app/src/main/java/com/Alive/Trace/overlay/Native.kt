package com.Alive.Trace.overlay

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** 原生悬浮窗的 JNI 桥（实现见 cpp/overlay_bridge.cpp）。 */
object NativeBridge {
    external fun scanProcesses(): String
    external fun injectPkg(pkg: String): String
    external fun injectPid(pid: Int): String
    external fun killProcess(pid: Int): String
    external fun procAlive(pid: Int): Boolean
    external fun suCmd(cmd: String): String
    external fun memRead(pid: Int, addr: Long, len: Int): ByteArray?
    external fun memFirstAddress(pid: Int): Long
    external fun memPage(pid: Int, addr: Long, rows: Int): String
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
    external fun asmWrite(pid: Int, addr: Long, text: String): String
    external fun bpStart(pid: Int)
    external fun bpStop()
    external fun bpIsRunning(): Boolean
    external fun bpStatus(): String
    external fun bpSet(addr: Long, type: String, len: Int)
    external fun bpClear(addr: Long)
    external fun bpClearHits()
    external fun bpHits(maxN: Int): String
    external fun socketLuaLogs(): String
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

    /** 搜索类型选择顺序（D/F 常用在前）。 */
    val all = intArrayOf(DWORD, FLOAT, QWORD, WORD, BYTE, DOUBLE)

    /** 地址统一显示格式（与内存页一致：大写、至少 8 位、无 0x）。 */
    fun addr(a: Long): String = "%08X".format(a)

    /** raw 按类型格式化为显示值。 */
    fun fmt(t: Int, raw: Long): String = when (t) {
        BYTE -> raw.toByte().toString()
        WORD -> raw.toShort().toString()
        DWORD -> raw.toInt().toString()
        QWORD -> java.lang.Long.toUnsignedString(raw)
        FLOAT -> floatFromBits(raw.toInt()).toString()
        else -> doubleFromBits(raw).toString()
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
                    QWORD -> bb.putLong(parseUnsigned(text))
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

    /** 无符号十进制/0x 十六进制文本 → Long。 */
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
            QWORD -> parseUnsigned(text)
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
    @Volatile var pid = 0
    @Volatile var pname = "-"
    @Volatile var pkg = ""
    val saved = mutableListOf<SavedRow>()
    var searchType = MT.DWORD
    val areas = mutableListOf(Areas.ALL)
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

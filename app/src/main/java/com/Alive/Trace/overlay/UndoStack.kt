package com.Alive.Trace.overlay

/**
 *
 * 每次写入前记录目标地址原字节；页面上的「撤销修改」按钮恢复**最近一次**修改。
 * 不进磁盘、不清空除非手动（进程重选/重启后自然失效，避免把旧地址恢复到新进程）。
 */
data class UndoEntry(
    val addr: Long,
    val old: ByteArray,
    val note: String = "",
)

object UndoStack {
    private val stack = ArrayDeque<UndoEntry>()
    private const val MAX = 50

    @Synchronized
    fun push(addr: Long, old: ByteArray, note: String = "") {
        if (addr <= 0L || old.isEmpty()) return
        stack.addLast(UndoEntry(addr, old, note))
        while (stack.size > MAX) stack.removeFirst()
    }

    @Synchronized
    fun pop(): UndoEntry? = stack.removeLastOrNull()

    @Synchronized
    fun size(): Int = stack.size

    @Synchronized
    fun clear() = stack.clear()
}

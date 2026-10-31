package com.Alive.Trace.overlay

import java.util.concurrent.CopyOnWriteArrayList

/**
 *
 * 背景：断点可以由三个入口设置——悬浮窗断点页、MCP 的 `bp_set`、Lua 脚本。
 * 旧实现只有悬浮窗断点页调 `OverlayManager.addBpChip()`，MCP 下断点时用户
 * 看不到任何提示（"断点是否还需要？开了几个？"全靠猜），而且按钮文本只有
 * "断点 1 / 断点 2"，不含地址/类型/命中数。
 *
 * 现在所有入口都写这张表，OverlayManager 每秒把表同步成右上角悬浮小按钮：
 *   文本 = `0x地址 类型 ×命中数`（如 `0x75DAE3EE48 x ×12`）
 *   点击 = 清除该断点（最后一个被清除时顺带停掉断点服务）
 */
object BpUi {

    data class Item(
        val addr: Long,
        var type: String,
        var len: Int,
        var hits: Int = 0,
    )

    private val items = CopyOnWriteArrayList<Item>()

    /** 断点服务当前绑定的目标 pid；换了目标就要把旧断点表清掉（见 P1-13）。 */
    @Volatile
    var targetPid: Int = 0

    fun upsert(addr: Long, type: String, len: Int) {
        if (addr <= 0) return
        val t = if (type.isBlank()) "x" else type
        val exist = items.firstOrNull { it.addr == addr }
        if (exist != null) {
            exist.type = t
            exist.len = len
        } else {
            items.add(Item(addr, t, len))
        }
    }

    fun setHits(addr: Long, hits: Int) {
        items.firstOrNull { it.addr == addr }?.hits = hits
    }

    fun clear(addr: Long) {
        items.removeAll { it.addr == addr }
    }

    fun clearAll() {
        items.clear()
    }

    fun snapshot(): List<Item> = items.toList()

    /**
     * 断点服务换了目标进程：清空旧表（旧地址在新进程里没有意义）。
     * 返回被清掉的条数，便于调用方提示。
     */
    fun onTargetChanged(pid: Int): Int {
        if (pid <= 0 || pid == targetPid) return 0
        val n = items.size
        targetPid = pid
        items.clear()
        return n
    }
}

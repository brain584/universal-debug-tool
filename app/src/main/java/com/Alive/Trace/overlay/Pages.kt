package com.Alive.Trace.overlay

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.SeekBar
import android.widget.Spinner
import android.widget.HorizontalScrollView
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.core.content.ContextCompat
import com.Alive.Trace.R
import java.io.File

// ── 页面接口 ──
interface OverlayPage {
    fun build(): View
}

// ── 包名 / 进程辅助 ──

/**
 * 从 `scanProcesses()` 的输出（每行 `pid|uid|cmdline`）里解析某个包名的
 * 主进程 PID。优先精确等于包名的进程（主进程），没有才退化为
 * `包名:子进程` 形式。
 *
 * 必须放在文件级：`SearchPage` 等处也要用，避免嵌套函数无法共享。
 */
internal fun resolvePidByPkg(pkg: String): Int {
    if (pkg.isEmpty()) return 0
    val text = runCatching { NativeBridge.scanProcesses() }.getOrDefault("")
    var fallback = 0
    for (line in text.lineSequence()) {
        val f = line.split('|')
        if (f.size < 3) continue
        val pid = f[0].toIntOrNull() ?: continue
        val cmd = f[2]
        if (cmd == pkg) return pid
        if (fallback == 0 && cmd.startsWith("$pkg:")) fallback = pid
    }
    return fallback
}

// ── UI 辅助函数 ──

internal fun dpc(ctx: Context, v: Int) =
    (v * ctx.resources.displayMetrics.density).toInt()

internal fun tv(ctx: Context, text: String = "", size: Float = 14f,
                color: Int = 0xFF222222.toInt(), mono: Boolean = false): TextView =
    TextView(ctx).apply {
        this.text = text
        textSize = size
        setTextColor(color)
        if (mono) typeface = Typeface.MONOSPACE
    }

private fun btn(ctx: Context, text: String, onClick: () -> Unit): TextView =
    TextView(ctx).apply {
        this.text = text
        textSize = 14f
        setTextColor(0xFF1B5E20.toInt())
        gravity = Gravity.CENTER
        background = GradientDrawable().apply {
            setColor(0xFFE8F5E9.toInt())
            cornerRadius = dpc(ctx, 8).toFloat()
        }
        setPadding(dpc(ctx, 12), dpc(ctx, 7), dpc(ctx, 12), dpc(ctx, 7))
        isClickable = true
        isFocusable = true
        setOnClickListener { onClick() }
    }

/**
 * 带文字的 CheckBox，**强制显式文字色**。
 *
 * 写死的浅色 `0xFFF7F7F7`，而 CheckBox 的文字色若走主题默认值，在**深色模式**下
 * 会变成浅色 → 浅底浅字，选项直接看不见（用户实测：零 ptrace 选项在深色模式下不可见）。
 * 本文件的既有惯例就是所有控件显式 setTextColor，这里把缺失的补齐并收口成一处。
 */
private fun labelCheckBox(ctx: Context, label: String, checked: Boolean,
                          color: Int = 0xFF222222.toInt(),
                          onChange: (Boolean) -> Unit): CheckBox =
    CheckBox(ctx).apply {
        text = label
        textSize = 12f
        isChecked = checked
        setTextColor(color)
        setOnCheckedChangeListener { _, v -> onChange(v) }
    }

private fun edit(ctx: Context, hint: String): EditText =    ClipboardEditText(ctx).apply {
        this.hint = hint
        textSize = 14f
        setTextColor(0xFF222222.toInt())
        setHintTextColor(0xFF999999.toInt())
        isSingleLine = true
        background = GradientDrawable().apply {
            setColor(0xFFF0F0F0.toInt())
            cornerRadius = dpc(ctx, 6).toFloat()
            setStroke(dpc(ctx, 1), 0xFFDDDDDD.toInt())
        }
        setPadding(dpc(ctx, 10), dpc(ctx, 8), dpc(ctx, 10), dpc(ctx, 8))
    }

private fun hrow(ctx: Context): LinearLayout =
    LinearLayout(ctx).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
    }

private fun vcol(ctx: Context): LinearLayout =
    LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }

private fun divider(ctx: Context): View =
    View(ctx).apply { setBackgroundColor(0x14000000) }

/** 通过透明前台 Activity 写剪贴板（Android 10+ 后台写入被禁时的兜底）。 */
private fun copyViaActivity(ctx: Context, text: String) {
    runCatching {
        ctx.startActivity(
            android.content.Intent(ctx, com.Alive.Trace.CopyActivity::class.java)
                .putExtra(com.Alive.Trace.CopyActivity.EXTRA_TEXT, text)
                .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
    }
}

/**
 * 复制文本。Android 10+ 禁止后台应用写剪贴板，而且被拦时
 * `setPrimaryClip` 不抛异常（静默丢弃），所以这里写完必须校验：
 *
 *   1. 开了「兼容复制」→ 直接走透明 Activity（必然成功）；
 *   2. 否则先尝试直写，读回剪贴板校验内容；
 *   3. 校验不通过（被系统丢弃）→ 自动升级到透明 Activity 重写一次。
 *
 * 第 3 步是必要的：输入法菜单里的复制也走这里，如果只依赖选项页
 * 那个开关，默认状态下输入法复制会静默失败（就是"复制没效果"）。
 */
internal fun copyText(ctx: Context, text: String) {
    if (text.isEmpty()) return
    val prefs = runCatching {
        ctx.getSharedPreferences("overlay", Context.MODE_PRIVATE)
    }.getOrNull()
    val compat = runCatching {
        prefs?.getBoolean("copy_compat", false) ?: false
    }.getOrDefault(false)
    if (compat) {
        copyViaActivity(ctx, text)
        return
    }
    val ok = runCatching {
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE)
            as android.content.ClipboardManager
        cm.setPrimaryClip(android.content.ClipData.newPlainText("ATrace", text))
        // 读回校验：后台写入被拦时 setPrimaryClip 不报错，只能这样发现。
        val back = cm.primaryClip?.takeIf { it.itemCount > 0 }
            ?.getItemAt(0)?.coerceToText(ctx)?.toString()
        back == text
    }.getOrDefault(false)
    if (!ok) copyViaActivity(ctx, text)
}

/** 深色模式也可读的 Spinner：显式指定下拉与选中项文字颜色。 */
internal fun darkSpinner(ctx: Context, items: List<String>): Spinner =
    Spinner(ctx).apply {
        val color = 0xFF222222.toInt()
        // 之前只 setBackgroundColor 是直角大灰块，和地址输入框放一起很难看。
        background = GradientDrawable().apply {
            setColor(0xFFF0F0F0.toInt())
            cornerRadius = dpc(ctx, 6).toFloat()
            setStroke(dpc(ctx, 1), 0xFFDDDDDD.toInt())
        }
        setPadding(0, 0, dpc(ctx, 2), 0)
        adapter = object : ArrayAdapter<String>(
            ctx, android.R.layout.simple_spinner_dropdown_item, items) {
            override fun getView(position: Int, convertView: View?,
                                 parent: ViewGroup): View {
                val v = super.getView(position, convertView, parent) as TextView
                v.setTextColor(color)
                v.textSize = 14f
                v.gravity = Gravity.CENTER
                v.setBackgroundColor(Color.TRANSPARENT)
                return v
            }
            override fun getDropDownView(position: Int, convertView: View?,
                                        parent: ViewGroup): View {
                val v = super.getDropDownView(position, convertView, parent)
                    as TextView
                v.setTextColor(color)
                v.textSize = 14f
                v.setBackgroundColor(0xFFF7F7F7.toInt())
                v.setPadding(dpc(ctx, 14), dpc(ctx, 10), dpc(ctx, 14), dpc(ctx, 10))
                return v
            }
        }
    }

/**
 * 读取 addr 处的 8 字节指针并剥掉 ARM64 TBI tag（高 8 位）。
 * 失败/空指针返回 0（0 地址本身也按"空"处理，实际目标里不会有 0 页）。
 */
internal fun readPointerAt(addr: Long): Long {
    if (OState.pid <= 0 || addr <= 0) return 0
    val b = runCatching { NativeBridge.memRead(OState.pid, addr, 8) }
        .getOrNull() ?: return 0
    if (b.size < 8) return 0
    var v = 0L
    for (k in 0 until 8)
        v = v or (((b.getOrNull(k)?.toLong()?.and(0xFF)) ?: 0L) shl (8 * k))
    return v and 0x00FFFFFFFFFFFFFFL
}

/** 写内存并记录旧字节（撤销用）。返回是否成功。 */
internal fun memWriteUndoable(addr: Long, bytes: ByteArray, note: String = ""): Boolean {
    if (OState.pid <= 0) return false
    val old = runCatching { NativeBridge.memRead(OState.pid, addr, bytes.size) }.getOrNull()
    val ok = runCatching { NativeBridge.memWrite(OState.pid, addr, bytes) }.getOrDefault(false)
    if (ok && old != null && old.size == bytes.size) UndoStack.push(addr, old, note)
    return ok
}

/** 撤销最近一次内存修改，返回给用户看的提示。 */
internal fun undoLastWrite(): String {
    val e = UndoStack.pop() ?: return "没有可撤销的修改"
    if (OState.pid <= 0) return "请先选择进程"
    val ok = runCatching { NativeBridge.memWrite(OState.pid, e.addr, e.old) }.getOrDefault(false)
    return if (ok) {
        val extra = if (e.note.isBlank()) "" else " · " + e.note
        "已撤销 0x%X 的修改（恢复 %d 字节）%s".format(e.addr, e.old.size, extra)
    } else "撤销失败（0x%X）".format(e.addr)
}

/**
 * GG 风格「选择要更改的数据类型」列表：每行 = 字母 + 名称 + 范围，
 * 点某行回调 onPick（调用方自己负责关弹窗/重开编辑框）。
 */
internal fun buildTypeChooser(m: OverlayManager, current: Int,
                              onPick: (Int) -> Unit): LinearLayout {
    val ctx = m.act
    val body = vcol(ctx)
    body.addView(tv(ctx, "选择要更改的数据类型（点一行即选中）", 12f,
        0xFF999999.toInt()).apply { setPadding(0, 0, 0, dpc(ctx, 6)) })
    for (t in listOf(MT.DWORD, MT.FLOAT, MT.DOUBLE, MT.WORD, MT.BYTE,
                     MT.QWORD, MT.ASCII, MT.UTF16)) {
        val selected = t == current
        val row = tv(ctx, (if (selected) "● " else "  ") + MT.describe(t),
            14f, if (selected) 0xFF1B8C3C.toInt() else 0xFF222222.toInt())
        row.setPadding(dpc(ctx, 10), dpc(ctx, 10), dpc(ctx, 10), dpc(ctx, 10))
        row.background = GradientDrawable().apply {
            setColor(if (selected) 0x1A1B8C3C else 0x08000000)
            cornerRadius = dpc(ctx, 6).toFloat()
        }
        row.isClickable = true
        row.setOnClickListener { onPick(t) }
        body.addView(row, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dpc(ctx, 4) })
    }
    return body
}

/**
 *
 * 旧的实现把所有动作塞进 dialog 的按钮行，按钮一多就被挤出屏幕
 * （用户实测：长按后「跳转到地址 / 下断点」直接看不见）。现在每一项是
 * 一行可点条目，纵向排列，永不裁切：
 *   跳转到指针（解引用，32 位截断时多一条）/ 跳转到此地址 / 下断点 /
 *   复制地址 / 复制值
 */
internal fun showRowMenu(m: OverlayManager, addr: Long, type: Int, raw: Long,
                        disasm: String = "") {
    val ctx = m.act
    val body = vcol(ctx)
    body.addView(tv(ctx, "0x%08X  值: %s".format(addr, MT.fmt(type, raw)),
        13f, 0xFF444444.toInt()).apply { setPadding(0, 0, 0, dpc(ctx, 6)) })

    fun item(label: String, onClick: () -> Unit) {
        val row = tv(ctx, label, 14f, 0xFF222222.toInt())
        row.setPadding(dpc(ctx, 12), dpc(ctx, 10), dpc(ctx, 12), dpc(ctx, 10))
        row.background = GradientDrawable().apply {
            setColor(0x08000000)
            cornerRadius = dpc(ctx, 6).toFloat()
        }
        row.isClickable = true
        row.setOnClickListener {
            m.dismissDialogs()
            onClick()
        }
        body.addView(row, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dpc(ctx, 4) })
    }

    // 解引用（GG 的「跳转到指针」）：只有长按菜单里提供
    val ptr = readPointerAt(addr)
    if (ptr != 0L) {
        item("跳转到指针 0x%X".format(ptr)) { MemoryPage.jumpTo(m, ptr) }
        val low32 = ptr and 0xFFFFFFFFL
        if (low32 != 0L && low32 != ptr) {
            item("跳转到指针 0x%X（32 位截断）".format(low32)) { MemoryPage.jumpTo(m, low32) }
        }
    } else {
        item("跳转到指针（空/读取失败）") { m.toast("该地址的指针为空，或读取失败") }
    }
    item("跳转到此地址") { MemoryPage.jumpTo(m, addr) }
    val refAddrs = Regex("0x([0-9a-fA-F]{5,16})").findAll(disasm)
        .map { java.lang.Long.parseUnsignedLong(it.groupValues[1], 16) }
        .filter { it > 0x1000L }
        .distinct()
        .toList()
    for (a2 in refAddrs.take(2)) {
        item("转到地址 0x%X（指令引用）".format(a2)) { MemoryPage.jumpTo(m, a2) }
    }
    item("下断点") { bpDialog(m, addr) }
    item("偏移量计算器") { offsetCalcDialog(m, addr) }
    item("指针搜索") { pointerSearchDialog(m, addr) }
    item("搜索附近") { searchNearbyDialog(m, addr) }
    item("自定义勾选") { customSelectDialog(m, addr) }
    item("复制地址") {
        copyText(ctx, "0x%08X".format(addr))
        m.toast("已复制地址")
    }
    item("复制值") {
        val v = runCatching {
            val b = NativeBridge.memRead(OState.pid, addr, MT.size(type))
            if (b == null) MT.fmt(type, raw) else {
                var r2 = 0L
                for (k in 0 until b.size)
                    r2 = r2 or (((b.getOrNull(k)?.toLong()?.and(0xFF)) ?: 0L) shl (8 * k))
                MT.fmt(type, r2)
            }
        }.getOrDefault(MT.fmt(type, raw))
        copyText(ctx, v)
        m.toast("已复制值")
    }
    m.dialog("0x%08X".format(addr), body, listOf(Triple("关闭", false) {}))
}

/** 偏移量计算器：起始地址 + 若干 ±offset，可跳转/复制。 */
internal fun offsetCalcDialog(m: OverlayManager, addr: Long) {
    val ctx = m.act
    val body = vcol(ctx)
    body.addView(tv(ctx, "起始地址", 12f, 0xFF999999.toInt()))
    val baseEdit = edit(ctx, "起始地址 (hex)").apply { setText("%X".format(addr)) }
    body.addView(baseEdit, LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    body.addView(tv(ctx, "偏移链（空格分隔，+/− 混用；0x 前缀按十六进制）",
        12f, 0xFF999999.toInt()).apply { setPadding(0, dpc(ctx, 6), 0, 0) })
    val chainEdit = edit(ctx, "+10 -8 +0x20")
    body.addView(chainEdit, LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    val resultTv = tv(ctx, "", 14f, 0xFF1B8C3C.toInt(), true)
    body.addView(resultTv, LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
        topMargin = dpc(ctx, 8)
    })
    fun calc(): Long? {
        val b = MT.parseHex(baseEdit.text.toString())
        if (b == null || b <= 0) { resultTv.text = "结果: 起始地址无效"; return null }
        var v = b
        val tokens = chainEdit.text.toString().trim()
            .split(Regex("\\s+")).filter { it.isNotEmpty() }
        for (t in tokens) {
            val neg = t.startsWith("-")
            val raw = t.removePrefix("+").removePrefix("-")
            val n = MT.parseHex(raw)
            if (n == null) { resultTv.text = "结果: 偏移 '$t' 无效"; return null }
            v += if (neg) -n else n
        }
        resultTv.text = "结果: 0x%X".format(v)
        return v
    }
    calc()
    m.dialog("偏移量计算器", body, listOf(
        Triple("计算", false) { calc() },
        Triple("复制", false) {
            val v = calc() ?: return@Triple
            copyText(ctx, "0x%X".format(v))
            m.toast("已复制结果")
        },
        Triple("跳转", true) {
            val v = calc() ?: return@Triple
            MemoryPage.jumpTo(m, v)
        }))
}

/** 指针搜索：搜"值等于某地址"的 8 字节指针（QWORD 精确搜索，结果在搜索页）。 */
internal fun pointerSearchDialog(m: OverlayManager, addr: Long) {
    val ctx = m.act
    if (OState.pid <= 0) { m.toast("请先选择进程"); return }
    val body = vcol(ctx)
    body.addView(tv(ctx, "搜索内容等于下面地址的 8 字节指针（QWORD）",
        12f, 0xFF999999.toInt()).apply { setPadding(0, 0, 0, dpc(ctx, 6)) })
    val target = edit(ctx, "指针目标地址 (hex)").apply { setText("%X".format(addr)) }
    body.addView(target, LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    body.addView(tv(ctx, "结果会出现在「搜索」页（类型 QWORD），可继续用精确搜索过滤",
        11f, 0xFF999999.toInt()).apply { setPadding(0, dpc(ctx, 6), 0, 0) })
    m.dialog("指针搜索", body, listOf(
        Triple("取消", false) {},
        Triple("搜索", true) {
            val t = MT.parseHex(target.text.toString())
            if (t == null || t <= 0) { m.toast("地址无效"); return@Triple }
            OState.searchType = MT.QWORD
            runCatching {
                NativeBridge.searchStart(OState.pid, MT.QWORD, "0x%X".format(t),
                    OState.areas.toIntArray())
            }
            m.switchTab("搜索")
            m.toast("指针搜索中…（结果在搜索页）")
        }))
}

/** 搜索附近：以该地址的当前值发起一次精确搜索。 */
internal fun searchNearbyDialog(m: OverlayManager, addr: Long) {
    val ctx = m.act
    if (OState.pid <= 0) { m.toast("请先选择进程"); return }
    val body = vcol(ctx)
    body.addView(tv(ctx, "以该地址的当前值发起精确搜索", 12f,
        0xFF999999.toInt()).apply { setPadding(0, 0, 0, dpc(ctx, 6)) })
    body.addView(tv(ctx, "地址: 0x%X".format(addr), 13f,
        0xFF1B8C3C.toInt(), true))
    val spinner = darkSpinner(ctx, MT.all.map { "${MT.name(it)} [${MT.letter(it)}]" })
        .apply { setSelection(MT.all.indexOf(OState.searchType).coerceAtLeast(0)) }
    body.addView(spinner, LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })
    val valueTv = tv(ctx, "当前值: …", 13f, 0xFF222222.toInt())
    body.addView(valueTv, LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply {
        topMargin = dpc(ctx, 6)
    })
    fun type() = MT.all[spinner.selectedItemPosition]
    fun readValue(): String {
        val t = type()
        val n = MT.size(t)
        if (n <= 0) return ""
        val b = runCatching { NativeBridge.memRead(OState.pid, addr, n) }.getOrNull() ?: return ""
        var raw = 0L
        for (k in 0 until n)
            raw = raw or (((b.getOrNull(k)?.toLong()?.and(0xFF)) ?: 0L) shl (8 * k))
        return MT.fmt(t, raw)
    }
    valueTv.text = "当前值: " + readValue()
    m.dialog("搜索附近", body, listOf(
        Triple("取消", false) {},
        Triple("搜索", true) {
            val t = type()
            val v = readValue()
            if (v.isEmpty()) { m.toast("读取失败"); return@Triple }
            OState.searchType = t
            runCatching { NativeBridge.searchStart(OState.pid, t, v, OState.areas.toIntArray()) }
            m.switchTab("搜索")
            m.toast("搜索中…（$v）")
        }))
}

/** 自定义勾选：以长按地址为起始，勾选 N 行（替代原内存页范围框）。 */
internal fun customSelectDialog(m: OverlayManager, addr: Long) {
    val ctx = m.act
    if (OState.pid <= 0) { m.toast("请先选择进程"); return }
    val body = vcol(ctx)
    body.addView(tv(ctx, "以该地址为起始勾选内存行（正数向下，负数向上）",
        12f, 0xFF999999.toInt()).apply { setPadding(0, 0, 0, dpc(ctx, 6)) })
    body.addView(tv(ctx, "起始地址: 0x%X".format(addr), 13f,
        0xFF1B8C3C.toInt(), true))
    val nEdit = edit(ctx, "行数，如 8 / -8").apply { setText("8") }
    body.addView(nEdit, LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })
    m.dialog("自定义勾选", body, listOf(
        Triple("取消", false) {},
        Triple("应用", true) {
            val n = nEdit.text.toString().trim().toIntOrNull() ?: 0
            if (n == 0) { m.toast("行数无效"); return@Triple }
            MemoryPage.customSelect(m, addr, n)
        }))
}

/** 断点对话框：x/r/w/rw 选类型，长度固定 4 字节。 */
internal fun bpDialog(m: OverlayManager, addr: Long) {
    val ctx = m.act
    if (OState.pid <= 0) { m.toast("请先选择进程"); return }
    val body = vcol(ctx)
    var type = "x"
    val typeRow = hrow(ctx)
    val btns = mutableListOf<Pair<String, TextView>>()
    for (t in listOf("x", "r", "w", "rw")) {
        val b = btn(ctx, t) {
            type = t
            for ((tt, bb) in btns)
                bb.setBackgroundColor(if (tt == type) 0xFFC8E6C9.toInt()
                                      else 0xFFEFEFEF.toInt())
        }
        btns.add(t to b)
        typeRow.addView(b, LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            marginEnd = dpc(ctx, 4)
        })
    }
    for ((tt, bb) in btns)
        bb.setBackgroundColor(if (tt == "x") 0xFFC8E6C9.toInt()
                              else 0xFFEFEFEF.toInt())
    body.addView(typeRow)
    body.addView(tv(ctx, "长度固定 4 字节（按 GG 习惯）", 11f,
        0xFF999999.toInt()).apply { setPadding(0, dpc(ctx, 4), 0, 0) })
    m.dialog("对 %08X 下断点".format(addr), body, listOf(
        Triple("取消", false) {},
        Triple("下断", true) {
            Thread {
                runCatching { NativeBridge.bpStart(OState.pid) }
                Thread.sleep(300)
                runCatching { NativeBridge.bpSet(addr, type, 4) }
                m.onUi {
                    m.addBpChip(addr, type, 4)   // 类型/长度必须传，否则界面永远显示 x
                    m.toast("已下发断点，可用右上角悬浮按钮关闭")
                }
            }.start()
        }))
}

// ── 保存地址：先选内存格式 ──

/**
 * 保存地址前的「选择类型」。列出所有可显示的内存格式及其数值范围
 * （MT.all：D/F/Q/W/B/E），点击某项即以该格式保存。
 *
 * 返回 true 表示弹出了对话框，由回调负责后续保存。
 */
internal fun chooseMemType(m: OverlayManager, current: Int, addr: Long,
                           onPick: (Int) -> Unit) {
    val ctx = m.act
    val body = vcol(ctx)
    body.addView(tv(ctx, "保存地址 ${MT.addr(addr)}", 13f,
        0xFF666666.toInt(), true).apply { setPadding(0, 0, 0, dpc(ctx, 6)) })
    for (t in MT.all) {
        val row = vcol(ctx).apply {
            setPadding(dpc(ctx, 10), dpc(ctx, 8), dpc(ctx, 10), dpc(ctx, 8))
            isClickable = true
            background = GradientDrawable().apply {
                setColor(0x08000000)
                cornerRadius = dpc(ctx, 6).toFloat()
            }
            setOnClickListener {
                m.dismissDialogs()
                onPick(t)
            }
        }
        // 第一行：类型字母 + 名称（占用剩余宽度，长名也不会挤压范围）。
        row.addView(tv(ctx, "${MT.letter(t)}    ${MT.name(t)}", 15f,
            0xFF222222.toInt()))
        // 第二行：数值范围。单行显示、超宽就省略号——之前并排放在
        // 同一行里会把整行撑得极高（QWORD 那行占了"一大坨"）。
        row.addView(tv(ctx, MT.typeRange(t), 11f, 0xFF999999.toInt(), true)
            .apply {
                isSingleLine = true
                ellipsize = android.text.TextUtils.TruncateAt.END
                setPadding(0, dpc(ctx, 2), 0, 0)
            })
        body.addView(row, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dpc(ctx, 4) })
    }
    body.addView(tv(ctx, "当前格式: ${MT.name(current)}", 11f,
        0xFF999999.toInt()).apply { setPadding(dpc(ctx, 2), dpc(ctx, 2), 0, 0) })
    m.dialog("选择类型", body, listOf(Triple("取消", false) {}))
}

/**
 * 以指定格式保存地址：读回当前内存值，按该格式显示。
 * 返回是否真的新增（地址已存在则跳过）。
 */
internal fun saveAddrAs(m: OverlayManager, addr: Long, type: Int): Boolean {
    val size = MT.size(type)
    if (size <= 0 || OState.pid <= 0) return false
    var inserted = false
    synchronized(OState.saved) {
        if (OState.saved.none { it.addr == addr }) {
            val bytes = runCatching {
                NativeBridge.memRead(OState.pid, addr, size)
            }.getOrNull()
            var raw = 0L
            if (bytes != null) {
                for (k in 0 until minOf(size, bytes.size))
                    raw = raw or ((bytes[k].toLong() and 0xFF) shl (8 * k))
            }
            OState.saved.add(SavedRow(addr, type, MT.addr(addr),
                MT.fmt(type, raw), false))
            inserted = true
        }
    }
    return inserted
}

// ── 选项页 ──

class OptionsPage(private val m: OverlayManager) : OverlayPage {
    private var injectAutorunEdit: EditText? = null
    private var pendingAutorun = ""

    private fun injectPrefs() = m.act.getSharedPreferences("overlay", Context.MODE_PRIVATE)
    private fun injectAutorunPath(): String =
        injectPrefs().getString("inject_autorun_path", "") ?: ""
    private fun setInjectAutorunPath(p: String) {
        runCatching { injectPrefs().edit().putString("inject_autorun_path", p).apply() }
    }


    private lateinit var procValue: TextView
    private lateinit var areaValue: TextView
    private lateinit var soValue: TextView
    private var lastSoText = ""
    private var lastSoColor = 0
    private var appInfoCache: Map<String, android.content.pm.ApplicationInfo>? = null
    private val iconCache = HashMap<String, android.graphics.drawable.Drawable?>()

    /** 一次性缓存所有已安装应用（包名 -> ApplicationInfo）。 */
    private fun appInfoMap(): Map<String, android.content.pm.ApplicationInfo> {
        appInfoCache?.let { return it }
        val map = HashMap<String, android.content.pm.ApplicationInfo>()
        runCatching {
            val pm = m.act.packageManager
            @Suppress("DEPRECATION")
            val apps = pm.getInstalledApplications(
                android.content.pm.PackageManager.GET_META_DATA)
            for (ai in apps) map[ai.packageName] = ai
        }
        appInfoCache = map
        return map
    }

    override fun build(): View {
        val ctx = m.act
        runCatching {
            val saved = ctx.getSharedPreferences("overlay", Context.MODE_PRIVATE)
                .getString("areas", null)
            if (saved != null) {
                val list = saved.split(",").mapNotNull { it.toIntOrNull() }
                if (list.isNotEmpty()) {
                    OState.areas.clear()
                    OState.areas.addAll(list)
                }
            }
        }
        val col = vcol(ctx)

        col.addView(section(ctx, "进程"))

        procValue = TextView(ctx).apply {
            text = if (OState.pid > 0) "[${OState.pid}] ${OState.pname}" else "未选择"
            setTextColor(0xFF888888.toInt())
        }
        col.addView(optionRow(ctx, "选择进程", procValue) { processDialog() })
        col.addView(optionRow(ctx, "注入", TextView(ctx).apply {
            text = "按 PID / 包名"
            setTextColor(0xFF888888.toInt())
        }) { injectDialog() })
        // 独立入口：不经过「选择进程」也能直接对任意 PID 注入
        // （native ELF 等非应用进程没有可解析的包名，只能按 PID）。
        col.addView(optionRow(ctx, "按 PID 注入", TextView(ctx).apply {
            text = "直接指定 pid"
            setTextColor(0xFF888888.toInt())
        }) { injectPidDialog() })
        col.addView(optionRow(ctx, "杀死游戏进程", TextView(ctx).apply {
            text = "kill -9"
            setTextColor(0xFF888888.toInt())
        }) {
            if (OState.pid <= 0) { m.toast("请先选择进程"); return@optionRow }
            m.dialog("杀死 [${OState.pid}] ${OState.pname}",
                vcol(ctx), listOf(
                    Triple("取消", false) {}, Triple("杀死", true) {
                        Thread { NativeBridge.killProcess(OState.pid) }.start()
                        m.toast("已发送 kill")
                    }))
        })

        col.addView(section(ctx, "搜索范围"))
        col.addView(TextView(ctx).apply {
            textSize = 12f
            setTextColor(0xFF999999.toInt())
            text = "内存范围只影响搜索结果的类型过滤；即使全不选，" +
                "内存页依然可以浏览全部地址（只是无法搜索）。"
            setPadding(0, 0, 0, dpc(ctx, 6))
        })
        areaValue = TextView(ctx).apply {
            text = areaText()
            setTextColor(0xFF888888.toInt())
        }
        col.addView(optionRow(ctx, "选择内存范围", areaValue) { areasDialog() })

        col.addView(section(ctx, "悬浮窗"))
        col.addView(seekRow(ctx, "悬浮窗大小", m.bubbleDp, 40, 90) { v, label ->
            m.setBubbleSize(v); label.text = "${v}dp"
        })
        col.addView(seekRow(ctx, "悬浮窗透明度", m.panelAlpha, 50, 100) { v, label ->
            m.applyPanelAlpha(v); label.text = "$v%"
        })
        val kbRow = hrow(ctx).apply { setPadding(0, dpc(ctx, 10), 0, dpc(ctx, 10)) }
        kbRow.addView(TextView(ctx).apply {
            text = "启用自带键盘"
            textSize = 16f
            setTextColor(0xFF222222.toInt())
            layoutParams = LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        kbRow.addView(Switch(ctx).apply {
            isChecked = m.act.getSharedPreferences("overlay", Context.MODE_PRIVATE)
                .getBoolean("builtin_kb", false)
            setOnCheckedChangeListener { _, c ->
                m.act.getSharedPreferences("overlay", Context.MODE_PRIVATE)
                    .edit().putBoolean("builtin_kb", c).apply()
                m.toast(if (c) "自带键盘后续接入，当前用系统输入法"
                    else "使用系统输入法")
            }
        })
        col.addView(kbRow)

        val copyRow = hrow(ctx).apply { setPadding(0, dpc(ctx, 4), 0, dpc(ctx, 10)) }
        copyRow.addView(TextView(ctx).apply {
            text = "兼容复制（会短暂切到应用）"
            textSize = 16f
            setTextColor(0xFF222222.toInt())
            layoutParams = LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        copyRow.addView(Switch(ctx).apply {
            isChecked = m.act.getSharedPreferences("overlay", Context.MODE_PRIVATE)
                .getBoolean("copy_compat", false)
            setOnCheckedChangeListener { _, c ->
                m.act.getSharedPreferences("overlay", Context.MODE_PRIVATE)
                    .edit().putBoolean("copy_compat", c).apply()
                m.toast(if (c) "已开启兼容复制" else "已关闭兼容复制")
            }
        })
        col.addView(copyRow)

        col.addView(section(ctx, "SO 通道"))

        // 注入成功后是否自动连接 socket（配合脚本 / hook 使用）。
        val autoRow = hrow(ctx).apply { setPadding(0, dpc(ctx, 4), 0, dpc(ctx, 4)) }
        autoRow.addView(TextView(ctx).apply {
            text = "注入后自动连接 socket"
            textSize = 16f
            setTextColor(0xFF222222.toInt())
            layoutParams = LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        autoRow.addView(Switch(ctx).apply {
            isChecked = SocketUtil.isAutoConnect(m.act)
            setOnCheckedChangeListener { _, c ->
                SocketUtil.setAutoConnect(m.act, c)
                m.toast(if (c) "注入成功后将自动连接 SO 通道"
                    else "已关闭自动连接")
            }
        })
        col.addView(autoRow)

        // 状态行：仅显示是否连接（绿=已连接 / 红=未连接），
        // 点击打开 SO 通道操作面板（连接 / 断开）。
        soValue = TextView(ctx).apply {
            text = "未连接"
            setTextColor(0xFFD32F2F.toInt())
            setTypeface(null, Typeface.BOLD)
        }
        col.addView(optionRow(ctx, "连接 agent (脚本/hook)", soValue) {
            soDialog()
        })

        // ── 电脑连接（adb 调试桥 / MCP）────────────────────────────────────
        // 两个 checkbox 对应用户的两个需求：
        //   ① adb 脚本模式：电脑在 cmd 里编辑并执行 Lua，不需要开悬浮窗；
        //   ② MCP 工具通道：电脑的 MCP 服务可以调用手机工具。
        // 二者**共用同一个 loopback 端口**（28471），电脑通过
        // `adb forward tcp:28471 tcp:28471` 连进来；不是给局域网用的。
        col.addView(section(ctx, "电脑连接（USB 调试）"))

        val adbStatus = TextView(ctx).apply {
            text = if (AdbBridge.isRunning()) "监听中 127.0.0.1:${AdbBridge.PORT}"
                   else "未监听"
            textSize = 12f
            setTextColor(if (AdbBridge.isRunning()) 0xFF1B8C3C.toInt()
                          else 0xFF888888.toInt())
        }
        val adbCb = labelCheckBox(
            ctx, "adb 脚本模式（电脑 cmd 编辑执行 Lua，无需悬浮窗）",
             AdbBridge.isEnabled(m.act), 0xFF222222.toInt()
        ) { on ->
            AdbBridge.setEnabled(m.act, on)
            val msg = AdbBridge.applyPref(m.act)
            adbStatus.text = if (AdbBridge.isRunning())
                "监听中 127.0.0.1:${AdbBridge.PORT}" else "未监听（$msg）"
            adbStatus.setTextColor(if (AdbBridge.isRunning()) 0xFF1B8C3C.toInt()
                                   else 0xFFD32F2F.toInt())
            m.toast(if (on) "已开启：$msg" else "已关闭 adb 脚本模式")
        }
        col.addView(adbCb, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 4) })
        col.addView(adbStatus, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))

        // 电脑端要执行的命令：复制即用
        col.addView(optionRow(ctx, "复制电脑端命令", TextView(ctx).apply {
            text = "adb forward ›"
            setTextColor(0xFF1565C0.toInt())
        }) {
            copyText(ctx, "adb forward tcp:${AdbBridge.PORT} tcp:${AdbBridge.PORT}")
            m.toast("已复制 adb forward 命令")
        })

        // 电脑端 IDE 启动命令（留空 = 电脑端自动探测 code / notepad++ 等）
        val ideValue = TextView(ctx).apply {
            val c = AdbBridge.ideCmd(m.act)
            text = if (c.isEmpty()) "自动探测" else c.take(18)
            setTextColor(0xFF666666.toInt())
        }
        col.addView(optionRow(ctx, "电脑端 IDE 命令", ideValue) {
            val box = edit(ctx, "例如 code -n \"{file}\"（{file} 会被替换成脚本路径）").apply {
                setText(AdbBridge.ideCmd(m.act))
            }
            val b = vcol(ctx)
            b.addView(tv(ctx, "留空则在电脑端自动探测（code / notepad++ / subl / notepad）；" +
                "都找不到时直接在 cmd 里逐行编辑。{file} 是占位符。", 12f,
                0xFF888888.toInt()).apply { setPadding(0, 0, 0, dpc(ctx, 8)) })
            b.addView(box, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT))
            m.dialog("电脑端 IDE 命令", b, listOf(
                Triple("取消", false) {},
                Triple("保存", true) {
                    AdbBridge.setIdeCmd(m.act, box.text.toString().trim())
                    val c = AdbBridge.ideCmd(m.act)
                    ideValue.text = if (c.isEmpty()) "自动探测" else c.take(18)
                    m.toast("已保存")
                }
            ))
        })

        // ② MCP 工具通道
        val mcpStatus = TextView(ctx).apply {
            text = if (AdbBridge.isMcpEnabled(m.act))
                "已开启（手机本地 MCP：http://127.0.0.1:${McpHttpServer.PORT}/mcp）" else "已关闭"
            textSize = 12f
            setTextColor(if (AdbBridge.isMcpEnabled(m.act)) 0xFF1B8C3C.toInt()
                          else 0xFF888888.toInt())
        }
        val mcpCb = labelCheckBox(
            ctx, "MCP 工具通道（电脑 AI/编辑器调用手机工具）",
             AdbBridge.isMcpEnabled(m.act), 0xFF222222.toInt()
        ) { on ->
            AdbBridge.setMcpEnabled(m.act, on)
            AdbBridge.applyPref(m.act)
            // 手机本地 MCP（HTTP）：给手机上的 AI App 用 URL 导入
            val lr = McpHttpServer.applyPref(m.act)
            mcpStatus.text = if (on)
                "已开启（手机本地 MCP：http://127.0.0.1:${McpHttpServer.PORT}/mcp）" else "已关闭"
            mcpStatus.setTextColor(if (on) 0xFF1B8C3C.toInt() else 0xFF888888.toInt())
            m.toast(if (on) "已开启 MCP：$lr" else "已关闭 MCP 工具通道")
        }
        col.addView(mcpCb, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 8) })
        col.addView(mcpStatus, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))
        col.addView(tv(ctx, "两个开关共用端口 ${AdbBridge.PORT}；未连 USB 时电脑端 MCP 可切到本地模式。" +
            "工具清单见 tools/atrace_mcp.py。", 11f, 0xFF888888.toInt()).apply {
            setPadding(0, dpc(ctx, 4), 0, 0)
        })

        // 手机本地 MCP 的导入 JSON：给手机上支持「导入 MCP 服务器 JSON」的 App 直接用。
        // 手机 App 连不了电脑上的 stdio 服务，所以需要这个跑在手机里的 HTTP MCP。
        col.addView(optionRow(ctx, "复制手机 MCP 导入 JSON", TextView(ctx).apply {
            text = "http ›"
            setTextColor(0xFF1565C0.toInt())
        }) {
            copyText(ctx,
                "{\"mcpServers\":{\"atrace\":{\"type\":\"http\",\"url\":\"http://127.0.0.1:" +
                McpHttpServer.PORT + "/mcp\"}}}")
            m.toast("已复制（type=http）；若客户端只认 SSE，用 /sse 那条")
        })

        col.addView(optionRow(ctx, "退出悬浮窗", TextView(ctx).apply {
            text = "›"
            setTextColor(0xFF888888.toInt())
        }) { m.exit() })

        col.addView(divider(ctx), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dpc(ctx, 1)).apply {
            topMargin = dpc(ctx, 12)
        })

        return ScrollView(ctx).apply {
            addView(col, ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT))
        }
    }

    private fun areaText(): String {
        val n = OState.areas.size
        return if (OState.areas.contains(Areas.ALL)) "所有内存" else "$n 项"
    }

    private fun section(ctx: Context, title: String): View =
        TextView(ctx).apply {
            text = title
            textSize = 13f
            setTextColor(0xFF1B8C3C.toInt())
            setTypeface(null, Typeface.BOLD)
            setPadding(0, dpc(ctx, 14), 0, dpc(ctx, 4))
        }

    private fun optionRow(ctx: Context, label: String, value: View,
                          onClick: () -> Unit): View {
        val row = hrow(ctx).apply {
            setPadding(0, dpc(ctx, 12), 0, dpc(ctx, 12))
            isClickable = true
            isFocusable = true
            background = GradientDrawable().apply {
                setColor(0x05000000)
                cornerRadius = dpc(ctx, 8).toFloat()
            }
            setOnClickListener { onClick() }
        }
        row.addView(TextView(ctx).apply {
            text = label
            textSize = 16f
            setTextColor(0xFF222222.toInt())
            layoutParams = LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        value.layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT)
        row.addView(value)
        row.addView(TextView(ctx).apply {
            text = "  "
            setTextColor(0xFFBBBBBB.toInt())
        })
        return row
    }

    private fun seekRow(ctx: Context, label: String, init: Int, lo: Int,
                        hi: Int, onChange: (Int, TextView) -> Unit): View {
        val col = vcol(ctx).apply { setPadding(0, dpc(ctx, 10), 0, dpc(ctx, 4)) }
        val head = hrow(ctx)
        head.addView(TextView(ctx).apply {
            text = label
            textSize = 16f
            setTextColor(0xFF222222.toInt())
            layoutParams = LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        val valLabel = TextView(ctx).apply {
            text = "$init"
            setTextColor(0xFF222222.toInt())
        }
        head.addView(valLabel)
        col.addView(head)
        col.addView(SeekBar(ctx).apply {
            setMax(hi - lo)
            progress = init - lo
            setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
                override fun onProgressChanged(sb: SeekBar?, p: Int, b: Boolean) {
                    if (b) onChange(p + lo, valLabel)
                }
                override fun onStartTrackingTouch(sb: SeekBar?) {}
                override fun onStopTrackingTouch(sb: SeekBar?) {}
            })
        }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))
        return col
    }

    // ── 选择进程对话框 ──
    /** 供 OverlayManager 在外部（注入成功自动选择进程）刷新进程行。 */
    fun setProcLabel(label: String) {
        if (::procValue.isInitialized) procValue.text = label
    }

    /** 供 OverlayManager 在未选进程时自动弹出。 */
    fun openProcessDialog() {
        processDialog()
    }

    private fun processDialog() {
        val ctx = m.act
        val body = vcol(ctx)
        body.addView(tv(ctx, "需要 root 权限扫描 /proc", 12f,
            0xFF1B8C3C.toInt()).apply { setPadding(0, 0, 0, dpc(ctx, 4)) })
        val search = edit(ctx, "搜索 PID / 包名 / 应用名")
        body.addView(search)
        val scanBtn = btn(ctx, "扫描进程") {}
        body.addView(scanBtn, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dpc(ctx, 8); bottomMargin = dpc(ctx, 4)
        })
        val listHost = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }
        body.addView(ScrollView(ctx).apply { addView(listHost) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                dpc(ctx, 280)))

        var lastScan = ""
        fun render(filter: String, rawText: String) {
            val pm = ctx.packageManager
            val apps = appInfoMap()
            val defaultIcon = ctx.getDrawable(android.R.drawable.sym_def_app_icon)
            data class Proc(val pid: String, val uid: String, val cmd: String,
                            val label: String,
                            val pkg: String,
                            val icon: android.graphics.drawable.Drawable?)
            val rows = rawText.split('\n').mapNotNull { l ->
                val f = l.split('|')
                if (f.size < 3) return@mapNotNull null
                val cmd = f[2]
                // 进程名可能是 "com.foo.bar:remote" 之类，先取包名部分。
                val pkgPart = cmd.substringBefore(':')
                val ai = apps[pkgPart]
                val label = if (ai != null) {
                    runCatching { pm.getApplicationLabel(ai).toString() }
                        .getOrDefault(pkgPart)
                } else {
                    cmd.substringAfterLast('/').ifEmpty { cmd }
                }
                val icon = if (ai != null) {
                    iconCache.getOrPut(pkgPart) {
                        runCatching { pm.getApplicationIcon(ai) }.getOrNull()
                    }
                } else null
                val pkgName = if (ai != null) pkgPart else cmd
                Proc(f[0], f[1], cmd, label, pkgName, icon)
            }.filter { p ->
                filter.isEmpty() || p.pid.contains(filter) ||
                    p.label.contains(filter, true) || p.cmd.contains(filter, true)
            }
            m.onUi {
                listHost.removeAllViews()
                for (p in rows.take(400)) {
                    val row = hrow(ctx).apply {
                        setPadding(0, dpc(ctx, 6), 0, dpc(ctx, 6))
                        isClickable = true
                        setOnClickListener {
                            OState.pid = p.pid.toIntOrNull() ?: 0
                            OState.pname = p.label
                            OState.pkg = p.pkg
                            procValue.text = "[${OState.pid}] ${p.label}"
                            m.dismissDialogs()
                            m.toast("已选择: [${p.pid}] ${p.label}")
                        }
                    }
                    row.addView(ImageView(ctx).apply {
                        setImageDrawable(p.icon ?: defaultIcon)
                        layoutParams = LinearLayout.LayoutParams(
                            dpc(ctx, 34), dpc(ctx, 34)).apply {
                            marginEnd = dpc(ctx, 10)
                        }
                    })
                    val info = vcol(ctx).apply {
                        layoutParams = LinearLayout.LayoutParams(0,
                            ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                    }
                    info.addView(TextView(ctx).apply {
                        text = p.label
                        textSize = 14f
                        maxLines = 1
                        setTextColor(0xFF222222.toInt())
                    })
                    info.addView(TextView(ctx).apply {
                        text = "PID ${p.pid} | ${p.cmd}"
                        textSize = 11f
                        setTextColor(0xFF999999.toInt())
                        typeface = Typeface.MONOSPACE
                        maxLines = 1
                    })
                    row.addView(info)
                    listHost.addView(row)
                    listHost.addView(divider(ctx), LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT, dpc(ctx, 1)))
                }
                if (rows.isEmpty())
                    listHost.addView(tv(ctx, "无可用进程（需要 root 授权）", 13f,
                        0xFF999999.toInt()))
            }
        }

        fun doScan() {
            scanBtn.text = "扫描中…"
            scanBtn.isClickable = false
            Thread {
                val text = runCatching { NativeBridge.scanProcesses() }.getOrDefault("")
                m.onUi {
                    scanBtn.text = "扫描进程"
                    scanBtn.isClickable = true
                }
                lastScan = text
                render(search.text.toString(), text)
            }.start()
        }

        search.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) {}
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {
                render(s?.toString() ?: "", lastScan)
            }
        })
        scanBtn.setOnClickListener { doScan() }

        m.dialog("选择进程", body, listOf(Triple("关闭", true) {}))
        doScan()
    }

    // ── 选择内存区域对话框 ──
    private fun areasDialog() {
        val ctx = m.act
        val body = vcol(ctx)
        val boxes = mutableListOf<Pair<Int, CheckBox>>()
        for ((id, name) in Areas.list) {
            val cb = CheckBox(ctx).apply {
                text = name
                textSize = 14f
                setTextColor(0xFF222222.toInt())
                isChecked = OState.areas.contains(id)
                setOnCheckedChangeListener { _, c ->
                    if (c && id == Areas.ALL)
                        boxes.forEach { it.second.isChecked = it.first == Areas.ALL }
                    else if (c) boxes.firstOrNull { it.first == Areas.ALL }
                        ?.second?.isChecked = false
                }
            }
            boxes.add(id to cb)
            body.addView(cb)
        }
        m.dialog("选择内存区域", body, listOf(
            Triple("否", false) {},
            Triple("保存", true) {
                OState.areas.clear()
                for ((id, cb) in boxes) if (cb.isChecked) OState.areas.add(id)
                if (OState.areas.isEmpty()) OState.areas.add(Areas.ALL)
                areaValue.text = areaText()
                m.act.getSharedPreferences("overlay", Context.MODE_PRIVATE)
                    .edit().putString("areas", OState.areas.joinToString(",")).apply()
            }))
    }

    // ── 注入对话框 ──
    private fun injectDialog() {
        val ctx = m.act
        val body = vcol(ctx)
        body.addView(TextView(ctx).apply {
            text = "目标: [${OState.pid}] ${OState.pname}"
            textSize = 13f
            setTextColor(0xFF666666.toInt())
        })
        val pkg = edit(ctx, "包名 (com.xxx.yyy)")
        body.addView(pkg, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })
        // 包名未运行时先拉起应用，等进程起来再注入。
        val autoStart = CheckBox(ctx).apply {
            text = "进程未运行时自动拉起后再注入"
            textSize = 13f
            setTextColor(0xFF333333.toInt())
            isChecked = true
        }
        body.addView(autoStart, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 4) })
        val resultTv = TextView(ctx).apply {
            textSize = 12f
            setTextColor(0xFF444444.toInt())
        }
        body.addView(resultTv, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })

        // 两条注入路径并排放在最底部：包名输入框聚焦弹出键盘后，
        // 对话框会被 ScrollView 滚动，横排能保证两个按钮都还在可视区内
        // （之前纵向堆叠时「当前进程注入」会被滚出屏幕，看起来像没了）。
        val zeroCb = labelCheckBox(
            ctx, "零 ptrace 注入（data-only，反作弊看不到 TracerPid）",
            SocketUtil.isZeroPtrace(m.act)) { SocketUtil.setZeroPtrace(m.act, it) }
        body.addView(zeroCb, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 8) })
        //（memfd 注入 + 隐藏 maps + dlclose 隐藏），解决"agent 落 /data/local/tmp 被扫图发现"。
        val stealthCb = labelCheckBox(
            ctx, "stealth 注入（memfd + 隐藏 maps + dlclose，反扫图）",
            SocketUtil.isStealthInject(m.act)) { SocketUtil.setStealthInject(m.act, it) }
        body.addView(stealthCb, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })

        body.addView(tv(ctx, "注入成功后执行脚本（可选，留空则不执行）：", 12f,
            0xFF666666.toInt()).apply { setPadding(0, dpc(ctx, 8), 0, 0) })
        val autorunEdit = edit(ctx, "/sdcard/autorun.lua")
        autorunEdit.setText(injectAutorunPath())
        injectAutorunEdit = autorunEdit
        body.addView(autorunEdit, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 4) })

        addSuDiagRow(body)

        val btns = hrow(ctx)
        btns.addView(btn(ctx, "当前进程注入") {
            if (OState.pid <= 0) { m.toast("请先选择进程"); return@btn }
            runInject(resultTv, "") { injectPid2(OState.pid) }
        }, LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginEnd = dpc(ctx, 6) })
        btns.addView(btn(ctx, "按包名注入") {
            val name = pkg.text.toString().trim()
            if (name.isEmpty()) { m.toast("请输入包名"); return@btn }
            runInjectPkg(resultTv, name, autoStart.isChecked)
        }, LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        body.addView(btns, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dpc(ctx, 10)
        })
        m.dialog("注入 agent", body, listOf(Triple("关闭", true) {}))
    }

    /**
     *
     * 为什么放在注入对话框里：ptrace 与零 ptrace 两条注入路径的**第一步都是 `su`**。
     * 一旦 su 在 App 进程里提不了权（KernelSU 未把 su 暴露到该命名空间、
     * 或授权状态异常），注入只会失败，而原来的报错是"无法启动 su"这种
     * 无法定位的文案。这里一键把实测结论打出来：
     *   - 每个候选路径「文件在不在 / 可不可执行」
     *   - 当前进程真实的 PATH
     *   - 最关键的一项：`su -c id` 到底有没有拿到 uid=0
     */
    private fun addSuDiagRow(parent: LinearLayout) {
        val ctx = m.act
        val row = hrow(ctx)
        row.addView(btn(ctx, "su 自检") {
            m.toast("检测中…")
            Thread {
                val r = runCatching { NativeBridge.suDiag() }
                    .getOrDefault("su 自检失败（native 调用异常）")
                m.onUi {
                    val body = vcol(ctx)
                    val tv = TextView(ctx).apply {
                        text = r
                        textSize = 12f
                        setTextColor(
                            if (r.contains("[OK]")) 0xFF1B8C3C.toInt()
                            else 0xFFD32F2F.toInt())
                        // 诊断文本按原样显示，方便直接复制给排障方
                        setTextIsSelectable(true)
                        typeface = Typeface.MONOSPACE
                    }
                    val sv = ScrollView(ctx).apply {
                        addView(tv, ViewGroup.LayoutParams(
                            ViewGroup.LayoutParams.MATCH_PARENT,
                            ViewGroup.LayoutParams.WRAP_CONTENT))
                    }
                    body.addView(sv, LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
                    m.dialog("su 自检（注入前置条件）", body,
                        listOf(Triple("关闭", true) {}))
                }
            }.start()
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        val hint = tv(ctx, "两条注入路径的第一步都是 su；失败先点这里", 11f,
            0xFF888888.toInt())
        row.addView(hint, LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 2f).apply { marginStart = dpc(ctx, 8) })
        parent.addView(row, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })
    }

    /**
     * 按 PID 注入：直接对指定 pid 注入，不需要先「选择进程」。
     * 目标可以是 native ELF 等没有包名的进程（注入器会为 PID 直注入
     * 把 agent 复制到公共可读目录供目标 dlopen）。
     */
    private fun injectPidDialog() {
        val ctx = m.act
        val body = vcol(ctx)
        if (OState.pid > 0) {
            body.addView(tv(ctx, "当前已选进程: [${OState.pid}] ${OState.pname}",
                12f, 0xFF666666.toInt()).apply { setPadding(0, 0, 0, dpc(ctx, 6)) })
        }
        val pidInput = edit(ctx, "PID（十进制）")
        body.addView(pidInput, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))
        val resultTv = TextView(ctx).apply {
            textSize = 12f
            setTextColor(0xFF444444.toInt())
        }
        body.addView(resultTv, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })

        val zeroCb = labelCheckBox(
            ctx, "零 ptrace 注入（data-only，反作弊看不到 TracerPid）",
            SocketUtil.isZeroPtrace(m.act)) { SocketUtil.setZeroPtrace(m.act, it) }
        body.addView(zeroCb, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 8) })
        //（memfd 注入 + 隐藏 maps + dlclose 隐藏），解决"agent 落 /data/local/tmp 被扫图发现"。
        val stealthCb = labelCheckBox(
            ctx, "stealth 注入（memfd + 隐藏 maps + dlclose，反扫图）",
            SocketUtil.isStealthInject(m.act)) { SocketUtil.setStealthInject(m.act, it) }
        body.addView(stealthCb, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })

        body.addView(tv(ctx, "注入成功后执行脚本（可选，留空则不执行）：", 12f,
            0xFF666666.toInt()).apply { setPadding(0, dpc(ctx, 8), 0, 0) })
        val autorunEdit = edit(ctx, "/sdcard/autorun.lua")
        autorunEdit.setText(injectAutorunPath())
        injectAutorunEdit = autorunEdit
        body.addView(autorunEdit, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 4) })

        addSuDiagRow(body)

        val btns = hrow(ctx)
        btns.addView(btn(ctx, "注入当前进程") {
            if (OState.pid <= 0) { m.toast("尚未选择进程"); return@btn }
            pidInput.setText(OState.pid.toString())
            runInject(resultTv, "") { injectPid2(OState.pid) }
        }, LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginEnd = dpc(ctx, 6) })
        btns.addView(btn(ctx, "按 PID 注入") {
            val pid = pidInput.text.toString().trim().toIntOrNull()
            if (pid == null || pid <= 0) { m.toast("PID 无效"); return@btn }
            if (!runCatching { NativeBridge.procAlive(pid) }.getOrDefault(false)) {
                m.toast("进程 $pid 不存在")
                return@btn
            }
            runInject(resultTv, "") { injectPid2(pid) }
        }, LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        body.addView(btns, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 10) })
        m.dialog("按 PID 注入", body, listOf(Triple("关闭", true) {}))
    }

    /**
     * 按包名注入：先确认进程在运行，不在（或不存在）时可选拉起
     * 应用，等 PID 出现后再执行注入。注入成功后按偏好自动连接
     * SO 通道（注入器尚未准备好的情况下会提示连接超时）。
     */
    // 按当前选择的注入方式分发：零 ptrace（data-only）或传统 ptrace 注入器。
    /** （P0-1）：stealth 注入开关（与 MCP 的 stealth=true 同义：-m -H -C）。 */
    private fun injectFlags(): String =
        if (SocketUtil.isStealthInject(m.act)) " -m -H -C" else ""

    private fun injectPid2(pid: Int): String {
        runCatching { SocketUtil.cleanupHooksBeforeInject("重新注入 pid=$pid") }
        pendingAutorun = injectAutorunEdit?.text?.toString()?.trim().orEmpty()
        setInjectAutorunPath(pendingAutorun)
        val flags = injectFlags()
        return if (SocketUtil.isZeroPtrace(m.act)) NativeBridge.injectPidZero(pid)
        else if (flags.isBlank()) NativeBridge.injectPid(pid)
        else NativeBridge.injectPidArgs(pid, flags)
    }

    private fun injectPkg2(pkg: String): String {
        runCatching { SocketUtil.cleanupHooksBeforeInject("重新注入 $pkg") }
        pendingAutorun = injectAutorunEdit?.text?.toString()?.trim().orEmpty()
        setInjectAutorunPath(pendingAutorun)
        return if (SocketUtil.isZeroPtrace(m.act)) NativeBridge.injectPkgZero(pkg)
        else NativeBridge.injectPkg(pkg)
    }

    private fun runInjectPkg(resultTv: TextView?, pkg: String, autoStart: Boolean) {
        m.toast("注入中…")
        resultTv?.text = "注入中…"
        Thread {
            var pid = resolvePidByPkg(pkg)
            if (pid <= 0) {
                if (!autoStart) {
                    m.onUi {
                        resultTv?.setTextColor(0xFFD32F2F.toInt())
                        resultTv?.text = "未找到 $pkg 的运行进程（未运行）"
                    }
                    m.toast("$pkg 未运行")
                    return@Thread
                }
                val launch = runCatching {
                    m.act.packageManager.getLaunchIntentForPackage(pkg)
                }.getOrNull()
                if (launch == null) {
                    m.onUi {
                        resultTv?.setTextColor(0xFFD32F2F.toInt())
                        resultTv?.text = if (runCatching {
                                m.act.packageManager.getApplicationInfo(
                                    pkg, 0) }.isSuccess)
                            "该包名没有可启动的界面，请手动打开应用后再注入"
                        else "未安装该包名（或包名输入有误）"
                    }
                    return@Thread
                }
                m.onUi { resultTv?.text = "未运行，正在拉起 $pkg …" }
                runCatching {
                    launch.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                    m.act.startActivity(launch)
                }.onFailure {
                    m.onUi {
                        resultTv?.setTextColor(0xFFD32F2F.toInt())
                        resultTv?.text = "拉起失败: " + (it.message ?: it.toString())
                    }
                    return@Thread
                }
                // 轮询等待进程出现（最多 20 秒）。每次重新解析，
                // 避免选到先起来的多进程/子进程。
                // 最多 ~9s。旧实现 500ms/次（最多 20s），目标反作弊往往在 0.5~2s 内
                // 完成初始化并开始自检，等于把"干净注入窗口"让掉了。
                for (i in 0 until 300) {
                    Thread.sleep(30)
                    pid = resolvePidByPkg(pkg)
                    if (pid > 0) break
                }
                if (pid <= 0) {
                    m.onUi {
                        resultTv?.setTextColor(0xFFD32F2F.toInt())
                        resultTv?.text = "已拉起但 20 秒内未等到进程，请重试"
                    }
                    m.toast("未等到进程")
                    return@Thread
                }
                m.onUi { resultTv?.text = "进程已启动 (pid=$pid)，注入中…" }
            }
            // 旧实现用 -p：注入器会自己再解析一次 pid，且默认把 agent 复制进目标私有目录
            //（copyToPrivate），落点/时序都与 MCP 不同 → 同一目标"用户侧被检测、MCP 不检测"。
            finishInject(resultTv, pkg, runCatching {
                injectPid2(pid)
            }.getOrNull().orEmpty().ifBlank { "注入失败：注入器没有返回输出" })
        }.start()
    }

    private fun runInject(resultTv: TextView?, pkg: String, call: () -> String) {
        m.toast("注入中…")
        if (resultTv != null) resultTv.text = "注入中…"
        Thread {
            val out = runCatching { call() }.getOrNull().orEmpty().ifBlank { "注入失败：注入器没有返回输出" }
            finishInject(resultTv, pkg, out)
        }.start()
    }

    /** 统一的注入结果处理：改写结果文本，并在成功后自动连接 SO 通道。 */
    private fun finishInject(resultTv: TextView?, pkg: String, out: String) {
        // 零 ptrace 路径：native 侧会带上 [ZPT-OK] / [ZPT-FAIL] 标记
        val zeroOk = out.contains("[ZPT-OK]")
        val ok = out.contains("Injection successful") || zeroOk
        val brief = when {
            zeroOk -> "\u2713 零 ptrace 注入成功（data-only，无 ptrace 关系）"
            out.contains("[ZPT-FAIL]") ->
                "\u2717 零 ptrace 注入失败\n" + out.lineSequence()
                    .filter { it.isNotBlank() && !it.contains("[ZPT-FAIL]") }
                    .toList().takeLast(3).joinToString("\n").take(300)
            ok -> {
                val b = out.lineSequence().firstOrNull { it.contains("Base:") }
                "注入成功 " + (b?.substringAfter("Base:")?.trim() ?: "")
            }
            else -> {
                // 复用 MCP 侧同一套文案，而不是只回一句 "Cannot find remote dlopen"。
                val hint = runCatching {
                    McpTools.classifyInjectFailure(out, OState.pid, SocketUtil.isZeroPtrace(m.act))
                }.getOrNull().orEmpty()
                if (hint.isNotBlank()) hint.take(600)
                else out.lineSequence().lastOrNull { it.isNotBlank() }?.take(200) ?: ""
            }
        }
        m.onUi {
            m.toast(if (ok) "注入成功" else "注入失败")
            resultTv?.text = brief
            resultTv?.setTextColor(
                if (ok) 0xFF1B8C3C.toInt() else 0xFFD32F2F.toInt())
        }
        if (ok) {
            val target = pkg.ifEmpty { OState.pkg.ifEmpty { OState.pname } }
            SocketUtil.lastInjectedPkg = target
            // 注入成功后自动把该进程设为当前进程（含冷启动刚拉起的场景）。
            SocketUtil.selectProcessAfterInject(m, pkg, OState.pname)
            SocketUtil.connectIfEnabled(m.act, target)
            // P0-1：注入成功后按用户填写的路径执行脚本
            val autoPath = pendingAutorun.trim()
            if (autoPath.isNotEmpty()) {
                Thread {
                    val src = runCatching { File(autoPath).readText() }.getOrNull()
                    if (src.isNullOrBlank()) {
                        m.onUi { m.toast("autorun 读取失败: $autoPath（不存在或无存储权限）") }
                    } else {
                        val out2 = runCatching { AdbBridge.runLuaForTools(src) }
                            .getOrNull().orEmpty()
                        m.onUi {
                            resultTv?.append("\n--- autorun 输出（$autoPath）---\n" +
                                out2.takeLast(800))
                            m.toast("autorun 已执行")
                        }
                    }
                }.start()
            }
        }
    }
    // ── SO 通道：agent socket/hook 连接 ──

    /**
     * SO 通道操作面板：显式的「连接」/「断开」按钮，外加
     * 「注入后自动连接」开关。状态行是只读显示，不做任何连接动作。
     */
    private fun soDialog() {
        val ctx = m.act
        val body = vcol(ctx)
        val status = TextView(ctx).apply {
            text = SocketUtil.statusText()
            textSize = 13f
            setTextColor(0xFF444444.toInt())
        }
        fun refreshStatus() {
            val c = SocketUtil.isConnected()
            val st = SocketUtil.statusText()
            status.text = if (c) st else "未连接"
            status.setTextColor(if (c) 0xFF1B8C3C.toInt()
                                else 0xFFD32F2F.toInt())
            refreshSoRow()
        }
        refreshStatus()
        body.addView(status)

        val autoCb = CheckBox(ctx).apply {
            text = "注入后自动连接 socket"
            textSize = 13f
            setTextColor(0xFF333333.toInt())
            isChecked = SocketUtil.isAutoConnect(m.act)
            setOnCheckedChangeListener { _, c ->
                SocketUtil.setAutoConnect(m.act, c)
                m.toast(if (c) "注入成功后将自动连接" else "已关闭自动连接")
            }
        }
        body.addView(autoCb, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dpc(ctx, 6); bottomMargin = dpc(ctx, 2)
        })

        val btns = hrow(ctx)
        btns.addView(btn(ctx, "连接") {
            if (SocketUtil.isConnected()) {
                m.toast("已连接")
            } else {
                SocketUtil.prepareTarget(
                    OState.pkg.ifEmpty { OState.pname })
                NativeBridge.socketConnect()
                m.toast("连接中…")
                Thread { Thread.sleep(1200); m.onUi { refreshStatus() } }
                    .start()
            }
        }, LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginEnd = dpc(ctx, 6) })
        btns.addView(btn(ctx, "断开") {
            if (!SocketUtil.isConnected()) {
                m.toast("当前未连接")
            } else {
                NativeBridge.socketDisconnect()
                m.toast("已断开 SO 通道")
                Thread { Thread.sleep(400); m.onUi { refreshStatus() } }.start()
            }
        }, LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        body.addView(btns, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 8) })
        m.dialog("SO 通道", body, listOf(Triple("关闭", true) { refreshStatus() }))
    }

    // ── SO 通道状态：绿=已连接，红=未连接 ──

    /** 立即刷新 SO 通道状态行。 */
    private fun refreshSoRow() {
        if (!::soValue.isInitialized) return
        val c = SocketUtil.isConnected()
        val text = if (c) "已连接" else "未连接"
        val color = if (c) 0xFF1B8C3C.toInt() else 0xFFD32F2F.toInt()
        // 只在真正变化时 setText/setTextColor：半透明悬浮窗每次
        // 无效化都会整窗重绘，无条件刷很费电。
        if (text != lastSoText) { soValue.text = text; lastSoText = text }
        if (color != lastSoColor) {
            soValue.setTextColor(color)
            lastSoColor = color
        }
    }

    /** 由 OverlayManager 每秒轮询（仅当停在选项页时）。 */
    fun onTick() = refreshSoRow()
}

// ── 搜索页 ──

class SearchPage(private val m: OverlayManager) : OverlayPage {

    private val ctx get() = m.act
    private val listHost = LinearLayout(m.act).apply {
        orientation = LinearLayout.VERTICAL
    }
    private val rangeLabel = TextView(m.act).apply {
        textSize = 12f
        setTextColor(0xFF888888.toInt())
    }
    private var offset = 0
    private var total = 0
    private val pageSize = 60
    private val checked = HashSet<Long>()
    private val deleted = HashSet<Long>()
    private var cur: List<Pair<Long, Long>> = emptyList()
    private var lastRunning = false
    @Volatile private var awaitResult = false
    private val rowValueViews = mutableListOf<TextView>()
    private val rowHexViews = mutableListOf<TextView>()
    private var valueTick = 0
    private val progress = android.widget.ProgressBar(m.act)
    private val handler = android.os.Handler(android.os.Looper.getMainLooper())

    override fun build(): View {
        val col = vcol(m.act)
        val r1 = hrow(m.act).apply { setPadding(dpc(ctx, 8), dpc(ctx, 6), dpc(ctx, 8), 0) }
        r1.addView(btn(ctx, "模糊搜索") { fuzzyDialog() },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginEnd = dpc(ctx, 6)
            })
        r1.addView(btn(ctx, "精确搜索") { exactDialog() },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        col.addView(r1)

        val r2 = hrow(m.act).apply { setPadding(dpc(ctx, 8), dpc(ctx, 6), dpc(ctx, 8), 0) }
        r2.addView(btn(ctx, "全选") { checked.addAll(cur.map { it.first }); refreshRows() },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginEnd = dpc(ctx, 4)
            })
        r2.addView(btn(ctx, "全不选") { checked.clear(); refreshRows() },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginEnd = dpc(ctx, 4)
            })
        r2.addView(btn(ctx, "反选") {
            cur.forEach { (a, _) -> if (!checked.remove(a)) checked.add(a) }
            refreshRows()
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            marginEnd = dpc(ctx, 4)
        })
        r2.addView(btn(ctx, "保存选中") { saveChecked() },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        col.addView(r2)

        val r2b = hrow(m.act).apply { setPadding(dpc(ctx, 8), dpc(ctx, 2), dpc(ctx, 8), 0) }
        r2b.addView(btn(ctx, "批量修改选中") { batchEditChecked() },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginEnd = dpc(ctx, 4)
            })
        r2b.addView(btn(ctx, "批量删除选中") { batchDeleteChecked() },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginEnd = dpc(ctx, 4)
            })
        r2b.addView(btn(ctx, "撤销修改") {
            m.toast(undoLastWrite())
            refreshValues()
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        col.addView(r2b)

        progress.visibility = View.GONE
        col.addView(progress, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dpc(ctx, 6)))

        col.addView(divider(ctx), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dpc(ctx, 1)).apply {
            topMargin = dpc(ctx, 6)
        })
        // 结果列表必须放进 ScrollView 才能滚动查看底部的地址。
        col.addView(ScrollView(ctx).apply {
            addView(listHost, ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT))
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))

        val r3 = hrow(m.act).apply { setPadding(dpc(ctx, 8), dpc(ctx, 4), dpc(ctx, 8), dpc(ctx, 4)) }
        r3.addView(btn(ctx, "◀") { if (offset > 0) { offset = (offset - pageSize).coerceAtLeast(0); refresh() } },
            LinearLayout.LayoutParams(dpc(ctx, 52), ViewGroup.LayoutParams.WRAP_CONTENT))
        r3.addView(rangeLabel, LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f)).also {
            rangeLabel.gravity = Gravity.CENTER
        }
        r3.addView(btn(ctx, "▶") {
            if (offset + pageSize < total) { offset += pageSize; refresh() }
        }, LinearLayout.LayoutParams(dpc(ctx, 52), ViewGroup.LayoutParams.WRAP_CONTENT))
        col.addView(r3)

        refresh()
        return col
    }

    /** OverlayManager 每秒轮询：搜索状态 + 结果数值刷新。 */
    fun onTick() {
        val running = runCatching { NativeBridge.searchRunning() }.getOrDefault(false)
        progress.visibility = if (running) View.VISIBLE else View.GONE
        // 搜索结束（或等待结果）时刷新整页。
        if ((lastRunning && !running) || (awaitResult && !running)) {
            awaitResult = false
            refresh()
        }
        lastRunning = running
        // 空闲时每约 2 秒重新读取当前页数值，保证数值与目标进程同步。
        if (!running) {
            valueTick++
            if (valueTick >= 2) {
                valueTick = 0
                refreshValues()
            }
        }
    }

    /** 只更新已显示行的数值，不重建列表（避免滚动位置丢失）。 */
    private fun refreshValues() {
        if (OState.pid <= 0 || cur.isEmpty()) return
        val type = OState.searchType
        val snapshot = cur
        Thread {
            val text = runCatching {
                NativeBridge.searchPage(offset, pageSize)
            }.getOrDefault("")
            val map = HashMap<Long, Long>()
            for (l in text.split('\n')) {
                val f = l.split('|')
                if (f.size < 2) continue
                val a = MT.parseHex(f[0]) ?: continue
                val v = MT.parseHex(f[1]) ?: continue
                map[a] = v
            }
            if (map.isEmpty()) return@Thread
            val hexWidth = MT.size(type) * 2
            m.onUi {
                for (i in snapshot.indices) {
                    val v = map[snapshot[i].first] ?: continue
                    rowValueViews.getOrNull(i)?.text = "  ${MT.fmt(type, v)}"
                    rowHexViews.getOrNull(i)?.text =
                        "%0${hexWidth}X".format(v) + "  ${MT.name(type)}"
                }
            }
        }.start()
    }

    fun refresh() {
        Thread {
            val totalNow = runCatching { NativeBridge.searchCount() }.getOrDefault(0)
            if (offset >= totalNow) offset = 0
            val text = runCatching {
                NativeBridge.searchPage(offset, pageSize)
            }.getOrDefault("")
            val list = text.split('\n').mapNotNull { l ->
                val f = l.split('|')
                if (f.size < 2) null
                else Pair(MT.parseHex(f[0]) ?: return@mapNotNull null,
                    MT.parseHex(f[1]) ?: 0L)
            }.filter { (a, _) -> !deleted.contains(a) }
            m.onUi {
                total = totalNow
                cur = list
                runCatching { renderRows() }.onFailure {
                    android.util.Log.e("ATrace", "renderRows", it) }
            }
        }.start()
    }

    private fun renderRows() {
        val ctx = m.act
        val type = OState.searchType
        listHost.removeAllViews()
        rowValueViews.clear()
        rowHexViews.clear()
        rangeLabel.text = if (total == 0) "无结果" else
            "${offset + 1}-${offset + cur.size} / $total (${MT.letter(type)})"
        m.setCount(total.toString())
        for ((addr, raw) in cur) {
            val row = hrow(ctx).apply {
                setPadding(dpc(ctx, 8), dpc(ctx, 5), dpc(ctx, 8), dpc(ctx, 5))
                background = GradientDrawable().apply {
                    setColor(0x08000000)
                    cornerRadius = dpc(ctx, 6).toFloat()
                }
            }
            // 无文字，仅作勾选控件；仍然显式着色，保持与其它控件一致
            val cb = labelCheckBox(ctx, "", checked.contains(addr)) { c ->
                if (c) checked.add(addr) else checked.remove(addr)
            }
            row.addView(cb)
            val info = vcol(ctx).apply {
                layoutParams = LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                setOnClickListener { editHit(addr, raw) }
                setOnLongClickListener {
                    showRowMenu(m, addr, type, raw)
                    true
                }
            }
            info.addView(hrow(ctx).apply {
                val addrTv = tv(ctx, MT.addr(addr), 14f,
                    0xFF1B8C3C.toInt(), true).apply {
                    layoutParams = LinearLayout.LayoutParams(
                        dpc(ctx, 92), ViewGroup.LayoutParams.WRAP_CONTENT)
                    setOnLongClickListener {
                        showRowMenu(m, addr, type, raw)
                        true
                    }
                }
                addView(addrTv)
                val valueTv = tv(ctx, "  ${MT.fmt(type, raw)}", 14f,
                    0xFF222222.toInt()).apply {
                    setTypeface(null, Typeface.BOLD)
                }
                rowValueViews.add(valueTv)
                addView(valueTv)
            })
            info.addView(hrow(ctx).apply {
                val hexWidth = MT.size(type) * 2
                // 与内存页一致的十六进制格式（无 0x 前缀）。
                val hexTv = tv(ctx, "%0${hexWidth}X".format(raw) +
                    "  ${MT.name(type)}", 11f, 0xFF3465C8.toInt(), true)
                rowHexViews.add(hexTv)
                addView(hexTv)
            })
            row.addView(info)
            row.addView(tv(ctx, "复制", 12f, 0xFF1565C0.toInt()).apply {
                setPadding(dpc(ctx, 6), 0, dpc(ctx, 4), 0)
                setOnClickListener {
                    copyText(ctx, MT.addr(addr))
                    m.toast("已复制地址")
                }
            })
            row.addView(tv(ctx, "删", 14f, 0xFFD32F2F.toInt()).apply {
                setPadding(dpc(ctx, 8), 0, dpc(ctx, 4), 0)
                setOnClickListener {
                    deleted.add(addr)
                    checked.remove(addr)
                    refresh()
                }
            })
            row.setOnLongClickListener {
                showRowMenu(m, addr, type, raw)
                true
            }
            listHost.addView(row)
            listHost.addView(divider(ctx), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dpc(ctx, 1)))
        }
        if (cur.isEmpty())
            listHost.addView(tv(ctx, "暂无结果（点击上方按钮开始搜索）", 13f,
                0xFF999999.toInt()).apply {
                setPadding(dpc(ctx, 8), dpc(ctx, 12), 0, 0)
            })
    }

    private fun refreshRows() {
        // 保留当前页数据并重新渲染（勾选状态存于 checked）。
        val keep = cur
        cur = emptyList()
        cur = keep
        renderRows()
    }

    private fun saveChecked() {
        if (checked.isEmpty()) { m.toast("请先勾选结果"); return }
        // 先让用户确认要按哪种内存格式保存（默认当前搜索类型）。
        val first = checked.firstOrNull() ?: return
        chooseMemType(m, OState.searchType, first) { type -> doSaveChecked(type) }
    }

    private fun doSaveChecked(type: Int) {
        val addrs = checked.toList()
        m.toast("保存中…")
        Thread {
            var n = 0
            synchronized(OState.saved) {
                for (addr in addrs) {
                    if (OState.saved.any { it.addr == addr }) continue
                    val size = MT.size(type)
                    val bytes = runCatching {
                        NativeBridge.memRead(OState.pid, addr, size)
                    }.getOrNull()
                    var raw = 0L
                    if (bytes != null) {
                        for (k in 0 until minOf(size, bytes.size))
                            raw = raw or ((bytes[k].toLong() and 0xFF) shl (8 * k))
                    }
                    OState.saved.add(SavedRow(addr, type, MT.addr(addr),
                        MT.fmt(type, raw), false))
                    n++
                }
            }
            m.onUi {
                checked.clear()
                refreshRows()
                m.toast(if (n > 0) "已保存 $n 条" else "这些地址已在保存列表中")
                m.onSavedChanged()
            }
        }.start()
    }

    /** P1-3：把勾选的多个地址一次写成同一个值。 */
    private fun batchEditChecked() {
        if (checked.isEmpty()) { m.toast("请先勾选结果"); return }
        if (OState.pid <= 0) { m.toast("请先在选项页选择进程"); return }
        val ctx = m.act
        val type = OState.searchType
        val body = vcol(ctx)
        body.addView(tv(ctx, "共 ${checked.size} 个地址，统一写成（${MT.name(type)}）：",
            12f, 0xFF555555.toInt()))
        val input = edit(ctx, MT.fmt(type, 0L))
        body.addView(input, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })
        m.dialog("批量修改 ${checked.size} 个地址", body, listOf(
            Triple("取消", false) {},
            Triple("写入", true) {
                val bytes = MT.encode(type, input.text.toString())
                if (bytes == null) { m.toast("值格式错误"); return@Triple }
                val addrs = checked.toList()
                m.toast("写入中…")
                Thread {
                    var ok = 0
                    for (a in addrs) {
                        if (memWriteUndoable(a, bytes, "搜索批量修改")) ok++
                    }
                    m.onUi {
                        m.toast("已写入 $ok/${addrs.size}")
                        refreshValues()
                    }
                }.start()
            }))
    }

    /** P1-3：批量从本页结果里删除勾选项（只影响列表，不动目标内存）。 */
    private fun batchDeleteChecked() {
        if (checked.isEmpty()) { m.toast("请先勾选结果"); return }
        val n = checked.size
        deleted.addAll(checked)
        checked.clear()
        refreshRows()
        m.toast("已从列表删除 $n 条（未改目标内存）")
    }

    private fun editHit(addr: Long, raw: Long) {
        val type = OState.searchType
            if (OState.pid <= 0) { m.toast("请先在选项页选择进程"); return }
        val ctx = m.act
        val liveRaw = runCatching {
            val n = MT.size(type)
            val b = NativeBridge.memRead(OState.pid, addr, n)
            if (b == null || b.size != n) raw else {
                var r2 = 0L
                for (k in 0 until n)
                    r2 = r2 or (((b.getOrNull(k)?.toLong()?.and(0xFF)) ?: 0L) shl (8 * k))
                r2
            }
        }.getOrDefault(raw)
        val body = vcol(ctx)
        val input = edit(ctx, MT.fmt(type, liveRaw))
        input.setText(MT.fmt(type, liveRaw))
        body.addView(input)
        m.dialog("修改 %08X  %s（当前值）".format(addr, MT.name(type)), body, listOf(
            Triple("取消", false) {},
            Triple("是", true) {
                val bytes = MT.encode(type, input.text.toString())
                if (bytes == null) { m.toast("值格式错误"); return@Triple }
                Thread {
                    val ok = memWriteUndoable(addr, bytes, "搜索修改")
                    m.onUi {
                        m.toast(if (ok) "写入成功（可撤销）" else "写入失败")
                        if (ok) refresh()
                    }
                }.start()
            }))
    }

    // ── 精确搜索对话框 ──
    private fun exactDialog() {
        if (requirePid()) return
        val ctx = m.act
        val body = vcol(ctx)
        val typeRow = hrow(ctx)
        typeRow.addView(tv(ctx, "类型:", 14f).apply {
            layoutParams = LinearLayout.LayoutParams(
                dpc(ctx, 52), ViewGroup.LayoutParams.WRAP_CONTENT)
        })
        val spinner = darkSpinner(ctx,
            MT.all.map { "${MT.name(it)} [${MT.letter(it)}]" }).apply {
            setSelection(MT.all.indexOf(OState.searchType).coerceAtLeast(0))
        }
        typeRow.addView(spinner, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))
        body.addView(typeRow)
        val input = edit(ctx, "数值 (100 / 0x64 / 10~20)")
        body.addView(input, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 8) })
        body.addView(tv(ctx, "支持十进制 / 0x 十六进制 / 10~20 范围", 11f,
            0xFF999999.toInt()).apply { setPadding(0, dpc(ctx, 4), 0, 0) })

        m.dialog("精确搜索", body, listOf(
            Triple("新搜索", false) {
                OState.searchType = MT.all[spinner.selectedItemPosition]
                offset = 0; deleted.clear(); checked.clear()
                NativeBridge.searchStart(OState.pid, OState.searchType,
                    input.text.toString().trim(), OState.areas.toIntArray())
                awaitResult = true
                m.toast("搜索中…")
            },
                Triple("取消", false) {},
                Triple("改善", true) {
                NativeBridge.searchRefine(OState.searchType,
                    input.text.toString().trim())
                awaitResult = true
                        m.toast("过滤中…")
            }))
    }

    // ── 模糊搜索对话框 / 初始化 ──
    private fun fuzzyDialog(forceInit: Boolean = false) {
        if (requirePid()) return
        val hasResults = runCatching { NativeBridge.searchCount() }.getOrDefault(0) > 0
        if (hasResults && !forceInit) {
            // 已有结果：在结果基础上按数值变化过滤。
            val ctx = m.act
            val body = vcol(ctx)
            body.addView(tv(ctx, "在已有结果中筛选（对比本次搜索前后的值）：", 15f,
                0xFF222222.toInt()).apply {
                setPadding(0, 0, 0, dpc(ctx, 8))
            })
            val grid = listOf("无变化" to 0, "有变化" to 1, "增加了" to 2, "减少了" to 3)
            grid.chunked(2).forEach { pairRow ->
                val r = hrow(ctx)
                for ((label, op) in pairRow) {
                    r.addView(btn(ctx, label) {
                        NativeBridge.fuzzyFilter(op)
                        awaitResult = true
                    m.toast("过滤中…")
                    }, LinearLayout.LayoutParams(0,
                        ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                        marginEnd = dpc(ctx, 6); bottomMargin = dpc(ctx, 6)
                    })
                }
                body.addView(r, LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT))
            }
            m.dialog("模糊搜索", body, listOf(
            Triple("否", false) {},
            Triple("重新初始化", true) { fuzzyDialog(true) }))
        } else {
            // 首次模糊搜索：选择数据类型后初始化结果集。
            val ctx = m.act
            val body = vcol(ctx)
            body.addView(tv(ctx, "选择要搜索的数据类型", 14f).apply {
                setPadding(0, 0, 0, dpc(ctx, 6))
            })
            val spinner = darkSpinner(ctx,
                MT.all.map { "${MT.name(it)} [${MT.letter(it)}]" }).apply {
                setSelection(MT.all.indexOf(OState.searchType).coerceAtLeast(0))
            }
            body.addView(spinner)
        m.dialog("模糊搜索", body, listOf(
            Triple("取消", false) {},
            Triple("开始", true) {
                    OState.searchType = MT.all[spinner.selectedItemPosition]
                    offset = 0; deleted.clear(); checked.clear()
                    NativeBridge.fuzzyStart(OState.pid, OState.searchType,
                        OState.areas.toIntArray())
                    awaitResult = true
                            m.toast("模糊搜索初始化中…")
                }))
        }
    }

    private fun requirePid(): Boolean {
        if (OState.pid <= 0) { m.toast("请先在选项页选择进程"); return true }
        return false
    }
}

// ── 保存页 ──

class SavedPage(private val m: OverlayManager) : OverlayPage {

    private val listHost = LinearLayout(m.act).apply {
        orientation = LinearLayout.VERTICAL
    }
    private val valueViews = HashMap<Long, TextView>()
    private var valueTick = 0
    private val sel = HashSet<Long>()

    override fun build(): View {
        val col = vcol(m.act)
        col.addView(TextView(m.act).apply {
            text = "勾选后可批量修改/删除；点条目可修改值或冻结"
            textSize = 12f
            setTextColor(0xFF999999.toInt())
            setPadding(dpc(m.act, 8), dpc(m.act, 4), 0, 0)
        })
        val r1 = hrow(m.act).apply {
            setPadding(dpc(m.act, 8), dpc(m.act, 2), dpc(m.act, 8), 0)
        }
        fun mkRow(): LinearLayout = hrow(m.act).apply {
            setPadding(dpc(m.act, 8), dpc(m.act, 2), dpc(m.act, 8), 0)
        }
        fun rowBtn(row: LinearLayout, label: String, action: () -> Unit) {
            row.addView(btn(m.act, label) { action() },
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                    marginEnd = dpc(m.act, 4)
                })
        }
        // 第一行：选择；第二行：批量操作（避免 5 个按钮挤在一行把"批量修改"折行）
        rowBtn(r1, "全选") {
            synchronized(OState.saved) { sel.addAll(OState.saved.map { it.addr }) }
            refresh()
        }
        rowBtn(r1, "全不选") { sel.clear(); refresh() }
        rowBtn(r1, "反选") {
            synchronized(OState.saved) {
                for (r in OState.saved) {
                    if (!sel.remove(r.addr)) sel.add(r.addr)
                }
            }
            refresh()
        }
        col.addView(r1)
        val r2 = mkRow()
        rowBtn(r2, "批量修改选中") { batchEditSel() }
        rowBtn(r2, "批量删除选中") { batchDeleteSel() }
        rowBtn(r2, "撤销修改") { m.toast(undoLastWrite()); refresh() }
        col.addView(r2)
        col.addView(ScrollView(m.act).apply { addView(listHost) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        refresh()
        return col
    }

    fun refresh() {
        val ctx = m.act
        val rows = synchronized(OState.saved) { OState.saved.toList() }
        m.onUi {
            listHost.removeAllViews()
            valueViews.clear()
            if (rows.isEmpty())
                listHost.addView(tv(ctx, "暂无保存数据",
                    13f, 0xFF999999.toInt()).apply {
                    setPadding(dpc(ctx, 8), dpc(ctx, 12), 0, 0)
                })
            for (r in rows) {
                val row = hrow(ctx).apply {
                    setPadding(dpc(ctx, 8), dpc(ctx, 5), dpc(ctx, 8), dpc(ctx, 5))
                    background = GradientDrawable().apply {
                        setColor(0x08000000)
                        cornerRadius = dpc(ctx, 6).toFloat()
                    }
                }
                // P1-3：多选勾选框
                row.addView(labelCheckBox(ctx, "", sel.contains(r.addr)) { c ->
                    if (c) sel.add(r.addr) else sel.remove(r.addr)
                })
                val info = vcol(ctx).apply {
                    layoutParams = LinearLayout.LayoutParams(0,
                        ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                    setOnClickListener { editRow(r) }
                    setOnLongClickListener {
                        showRowMenu(m, r.addr, r.type,
                            runCatching { MT.parse(r.type, r.valueText) }
                                .getOrNull() ?: 0L)
                        true
                    }
                }
                if (r.name.isNotEmpty()) {
                    info.addView(tv(ctx, "★ ${r.name}", 12f,
                        0xFFEF6C00.toInt()).apply {
                        setPadding(0, 0, 0, dpc(ctx, 2))
                    })
                }
                info.addView(hrow(ctx).apply {
                    val addrTv = tv(ctx, MT.addr(r.addr), 14f,
                        0xFF1B8C3C.toInt(), true).apply {
                        layoutParams = LinearLayout.LayoutParams(
                            dpc(ctx, 92), ViewGroup.LayoutParams.WRAP_CONTENT)
                        setOnLongClickListener {
                            showRowMenu(m, r.addr, r.type,
                                runCatching { MT.parse(r.type, r.valueText) }
                                    .getOrNull() ?: 0L)
                            true
                        }
                    }
                    addView(addrTv)
                    val valueTv = tv(ctx, "  ${r.valueText}", 14f,
                        0xFF222222.toInt()).apply {
                        setTypeface(null, Typeface.BOLD)
                    }
                    valueViews[r.addr] = valueTv
                    addView(valueTv)
                })
                info.addView(hrow(ctx).apply {
                    addView(tv(ctx, "${MT.name(r.type)}" +
                        if (r.frozen) ". 已冻结" else "", 11f,
                        if (r.frozen) 0xFF1B8C3C.toInt() else 0xFF999999.toInt()))
                })
                row.addView(info)
                row.addView(tv(ctx, "标记", 12f, 0xFFEF6C00.toInt()).apply {
                    setPadding(dpc(ctx, 6), 0, dpc(ctx, 4), 0)
                    setOnClickListener { nameDialog(r) }
                })
                row.addView(tv(ctx, "复制", 12f, 0xFF1565C0.toInt()).apply {
                    setPadding(dpc(ctx, 6), 0, dpc(ctx, 4), 0)
                    setOnClickListener {
                        copyText(ctx, MT.addr(r.addr))
                        m.toast("已复制地址")
                    }
                })
                row.addView(tv(ctx, "跳", 14f, 0xFF1565C0.toInt()).apply {
                    setPadding(dpc(ctx, 8), 0, dpc(ctx, 4), 0)
                    setOnClickListener { MemoryPage.jumpTo(m, r.addr) }
                })
                row.addView(tv(ctx, "删", 14f, 0xFFD32F2F.toInt()).apply {
                    setPadding(dpc(ctx, 8), 0, dpc(ctx, 4), 0)
                    setOnClickListener {
                        synchronized(OState.saved) { OState.saved.remove(r) }
                        refresh()
                    }
                })
                row.setOnLongClickListener {
                    showRowMenu(m, r.addr, r.type,
                        runCatching { MT.parse(r.type, r.valueText) }
                            .getOrNull() ?: 0L)
                    true
                }
                listHost.addView(row)
                listHost.addView(divider(ctx), LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, dpc(ctx, 1)))
            }
            m.setCount(rows.count { it.frozen }.toString() + "/" + rows.size)
        }
    }

    /** OverlayManager 每秒轮询：约每 2 秒同步一次保存项数值。 */
    fun onTick() {
        if (OState.pid <= 0) return
        valueTick++
        if (valueTick < 2) return
        valueTick = 0
        val rows = synchronized(OState.saved) { OState.saved.toList() }
        if (rows.isEmpty()) return
        Thread {
            val updates = HashMap<Long, String>()
            for (r in rows) {
                val n = MT.size(r.type)
                if (n <= 0) continue
                val b = runCatching {
                    NativeBridge.memRead(OState.pid, r.addr, n)
                }.getOrNull() ?: continue
                var v = 0L
                for (k in 0 until n)
                    v = v or (((b.getOrNull(k)?.toLong()?.and(0xFF))
                        ?: 0L) shl (8 * k))
                updates[r.addr] = MT.fmt(r.type, v)
            }
            if (updates.isEmpty()) return@Thread
            m.onUi {
                for ((a, v) in updates) {
                    valueViews[a]?.text = "  $v"
                    synchronized(OState.saved) {
                        OState.saved.firstOrNull { it.addr == a }?.valueText = v
                    }
                }
            }
        }.start()
    }

    /** P1-3：批量修改勾选的保存项（按各自类型写入同一个值）。 */
    private fun batchEditSel() {
        if (sel.isEmpty()) { m.toast("请先勾选条目"); return }
        if (OState.pid <= 0) { m.toast("请先在选项页选择进程"); return }
        val ctx = m.act
        val rows = synchronized(OState.saved) { OState.saved.filter { it.addr in sel } }
        if (rows.isEmpty()) { sel.clear(); refresh(); return }
        val body = vcol(ctx)
        body.addView(tv(ctx, "共 ${rows.size} 项：把值统一写成下列内容（按各自类型解析）",
            12f, 0xFF555555.toInt()))
        val input = edit(ctx, MT.fmt(rows.first().type, 0L))
        body.addView(input, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })
        val freeze = CheckBox(ctx).apply {
            text = "写入后冻结"
            textSize = 14f
            setTextColor(0xFF222222.toInt())
            isChecked = rows.all { it.frozen }
        }
        body.addView(freeze)
        m.dialog("批量修改 ${rows.size} 项", body, listOf(
            Triple("取消", false) {},
            Triple("写入", true) {
                val text = input.text.toString()
                val doFreeze = freeze.isChecked
                Thread {
                    var ok = 0
                    for (r in rows) {
                        val bytes = MT.encode(r.type, text) ?: continue
                        val w = memWriteUndoable(r.addr, bytes, "保存页批量修改")
                        if (w) {
                            ok++
                            r.valueText = text
                            r.frozen = doFreeze
                        }
                    }
                    if (doFreeze) Freezer.ensureStarted()
                    m.onUi {
                        m.toast("已写入 $ok/${rows.size}")
                        refresh()
                    }
                }.start()
            }))
    }

    /** P1-3：批量删除勾选的保存项。 */
    private fun batchDeleteSel() {
        if (sel.isEmpty()) { m.toast("请先勾选条目"); return }
        val n = sel.size
        synchronized(OState.saved) { OState.saved.removeAll { it.addr in sel } }
        sel.clear()
        refresh()
        m.toast("已删除 $n 条保存项")
    }

    /** 给保存地址命名/标记。 */
    private fun nameDialog(r: SavedRow) {
        val ctx = m.act
        val body = vcol(ctx)
        body.addView(tv(ctx, MT.addr(r.addr), 14f, 0xFF1B8C3C.toInt(), true))
        val input = edit(ctx, "标记名称（如：血量/金币）").apply { setText(r.name) }
        body.addView(input, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })
        m.dialog("标记 ${MT.addr(r.addr)}", body, listOf(
            Triple("清除", false) { r.name = ""; refresh() },
            Triple("取消", false) {},
            Triple("保存", true) {
                r.name = input.text.toString().trim()
                refresh()
            }))
    }

    private fun editRow(r: SavedRow) {
        val ctx = m.act
        val live = runCatching {
            val n = MT.size(r.type)
            val b = NativeBridge.memRead(OState.pid, r.addr, n)
            if (b == null || b.size != n) null else {
                var v = 0L
                for (k in 0 until n)
                    v = v or (((b.getOrNull(k)?.toLong()?.and(0xFF)) ?: 0L) shl (8 * k))
                MT.fmt(r.type, v)
            }
        }.getOrNull()
        val shown = live ?: r.valueText
        val body = vcol(ctx)
        val input = edit(ctx, shown).apply { setText(shown) }
        body.addView(input)
        val freeze = CheckBox(ctx).apply {
            text = "冻结"
            textSize = 14f
            setTextColor(0xFF222222.toInt())
            isChecked = r.frozen
        }
        body.addView(freeze, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 8) })
        m.dialog("修改 %08X  %s".format(r.addr, MT.name(r.type)), body, listOf(
            Triple("否", false) {},
                        Triple("修改", true) {
                r.valueText = input.text.toString()
                r.frozen = freeze.isChecked
                Freezer.ensureStarted()
                val bytes = MT.encode(r.type, r.valueText)
                if (bytes == null) { m.toast("值格式错误"); return@Triple }
                if (OState.pid <= 0) { m.toast("请先选择进程"); return@Triple }
                Thread {
                    val ok = memWriteUndoable(r.addr, bytes, "保存页修改")
                    m.onUi {
                        m.toast(if (ok) "写入成功（可撤销）" else "写入失败")
                        refresh()
                    }
                }.start()
            }))
    }
}

// ── 内存页 ──

class MemoryPage(private val m: OverlayManager) : OverlayPage {

    companion object {
        @Volatile var pendingJump: Long = 0

        fun jumpTo(m: OverlayManager, addr: Long) {
            pendingJump = addr
            m.switchTab("内存")
            m.onUi { (m.pageObjs["内存"] as? MemoryPage)?.refresh() }
        }

        // 正数 N：起始地址为第一行，向下 N 行；负数 N：起始地址为最后一行，向上 |N| 行。
        @Volatile private var pendingSelStart: Long = 0
        @Volatile private var pendingSelRows: Int = 0

        fun customSelect(m: OverlayManager, startAddr: Long, rows: Int) {
            val n = if (rows == 0) 1 else rows
            val count = kotlin.math.abs(n).coerceAtMost(64)
            val baseAddr = if (n >= 0) (startAddr and -4L)
                           else ((startAddr and -4L) + (n + 1) * 4L)
            pendingSelStart = baseAddr
            pendingSelRows = count
            pendingJump = baseAddr
            m.switchTab("内存")
            m.onUi { (m.pageObjs["内存"] as? MemoryPage)?.refresh() }
        }

        private fun takePendingSel(): Pair<Long, Int>? {
            val s = pendingSelStart
            if (s == 0L) return null
            val r = pendingSelRows
            pendingSelStart = 0
            pendingSelRows = 0
            return s to r
        }
    }

    private val ctx get() = m.act
    // 连续滚动 + 右侧系统滚动条；页首/页尾各一条「地址跳转」。
    private val PAGE = 0x2000L
    private val PAGE_ROWS = (PAGE / 4).toInt()   // 2048 行（0x0000..0x1FFC）
    private var base = -1L                       // 当前页起始（0x2000 对齐）
    private val backStack = ArrayDeque<Long>()
    private val fwdStack = ArrayDeque<Long>()
    private var anchor = -1
    private val checkedAddrs = HashSet<Long>()
    private var muteChecks = false
    private lateinit var addrInput: EditText
    private lateinit var pageLabel: TextView
    private lateinit var recycler: RecyclerView
    private var memAdapter: MemAdapter? = null
    private val pageCache = HashMap<Long, MemRow>()   // 整页按块加载的行缓存
    private val regions = ArrayList<Triple<Long, Long, String>>()  // 内存区间类型（cd/ca/java/xa…）
    private var loadingBase = -1L
    private var loadedBase = -1L
    private val disasmBusy = java.util.concurrent.atomic.AtomicBoolean(false)     // 已完整加载（含反汇编）的页：切页/重开悬浮窗直接复用缓存
    private var pendingScrollAddr = -1L
    private var highlightAddr = -1L   // 跳转目标行高亮
    private val refreshBusy = java.util.concurrent.atomic.AtomicBoolean(false)
    private lateinit var scrollTrack: android.widget.FrameLayout
    private lateinit var scrollThumb: android.view.View
    private data class MemRow(val addr: Long, val ok: Boolean, val value: Long,
                              val disasm: String, val type: String)

    override fun build(): View {
        return try {
            buildInner()
        } catch (t: Throwable) {
            val c = vcol(ctx)
            c.addView(tv(ctx, "内存页构建失败: " + (t.message ?: t.toString()),
                12f, 0xFFD32F2F.toInt(), true).apply {
                setPadding(dpc(ctx, 12), dpc(ctx, 12), dpc(ctx, 12), dpc(ctx, 12))
            })
            c
        }
    }

    private fun buildInner(): View {
        val col = vcol(ctx)
        val nav = hrow(ctx).apply { setPadding(dpc(ctx, 8), dpc(ctx, 6), dpc(ctx, 8), 0) }
        addrInput = edit(ctx, "地址 (hex)").apply {
            layoutParams = LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        nav.addView(addrInput)
        nav.addView(btn(ctx, "跳转") {
            val a = MT.parseHex(addrInput.text.toString())
            if (a == null || a < 0) m.toast("地址无效") else navigateTo(a)
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dpc(ctx, 6) })
        // GG 式：输入地址只跳到"包含它的那一页"，不再把该地址当第一行
        nav.addView(btn(ctx, "返回") { goBack() }.apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dpc(ctx, 6) }
        })
        nav.addView(btn(ctx, "前进") { goForward() }.apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dpc(ctx, 6) }
        })
        col.addView(nav)


        // 「自定义勾选」完成（以长按地址为起始，和 GG 一致）。
        col.addView(tv(ctx,
            "长按行：解引用 / 跳转到地址 / 下断 / 偏移量计算器 / 指针搜索 / 搜索附近 / 自定义勾选",
            11f, 0xFF999999.toInt()).apply {
            setPadding(dpc(ctx, 10), dpc(ctx, 4), dpc(ctx, 10), 0)
        })

        val act = hrow(ctx).apply { setPadding(dpc(ctx, 8), dpc(ctx, 6), dpc(ctx, 8), 0) }
        act.addView(btn(ctx, "刷新") {
            loadedBase = -1L
            pageCache.clear()
            refresh()
        },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginEnd = dpc(ctx, 6)
            })
        act.addView(btn(ctx, "保存勾选") { saveChecked() },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        act.addView(btn(ctx, "分配内存") { allocDialog() },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        pageLabel = tv(ctx, "加载中…", 12f, 0xFF999999.toInt())
        act.addView(pageLabel, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { gravity = Gravity.CENTER })
        col.addView(act)

        val act2 = hrow(ctx).apply { setPadding(dpc(ctx, 8), dpc(ctx, 4), dpc(ctx, 8), 0) }
        act2.addView(btn(ctx, "链接库") { libsDialog() },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginEnd = dpc(ctx, 6)
            })
        act2.addView(btn(ctx, "撤销修改") {
            m.toast(undoLastWrite())
            refresh()
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            marginEnd = dpc(ctx, 6)
        })
        act2.addView(tv(ctx, "长按地址可复制/断点/跳转", 11f,
            0xFF999999.toInt()).apply {
            layoutParams = LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        col.addView(act2)

        col.addView(divider(ctx), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dpc(ctx, 1)).apply {
            topMargin = dpc(ctx, 6)
        })

        runCatching {
            recycler = RecyclerView(ctx).apply {
                layoutManager = LinearLayoutManager(ctx)
                // 关键：关掉系统滚动条。悬浮窗窗口主题里 scrollbarThumb 为 null，
                // 开启后 onDrawScrollBars 会 NPE（实测闪退：ScrollBarDrawable.mutate null）。
                isVerticalScrollBarEnabled = false
            }
            memAdapter = MemAdapter().also { recycler.adapter = it }
            recycler.addOnScrollListener(object : RecyclerView.OnScrollListener() {
                override fun onScrolled(rv: RecyclerView, dx: Int, dy: Int) {
                    syncScrollBar()
                    ensureVisibleDisasm()
                }
            })
            val listRow = LinearLayout(ctx).apply { orientation = LinearLayout.HORIZONTAL }
            listRow.addView(recycler, LinearLayout.LayoutParams(
                0, ViewGroup.LayoutParams.MATCH_PARENT, 1f))
            // 右侧自绘滚动条：轨道 + 滑块（上下留边，全面屏圆角不会遮住）
            scrollTrack = android.widget.FrameLayout(ctx).apply {
                layoutParams = LinearLayout.LayoutParams(dpc(ctx, 14),
                    ViewGroup.LayoutParams.MATCH_PARENT).apply {
                    topMargin = dpc(ctx, 6)
                    bottomMargin = dpc(ctx, 24)
                }
                background = GradientDrawable().apply {
                    setColor(0x1A888888)
                    cornerRadius = dpc(ctx, 7).toFloat()
                }
            }
            scrollThumb = android.view.View(ctx).apply {
                background = GradientDrawable().apply {
                    setColor(0xAA9E9E9E.toInt())
                    cornerRadius = dpc(ctx, 5).toFloat()
                }
                layoutParams = android.widget.FrameLayout.LayoutParams(
                    dpc(ctx, 8), dpc(ctx, 48))
            }
            scrollTrack.addView(scrollThumb)
            scrollTrack.setOnTouchListener { _, e ->
                val th = scrollTrack.height
                if (th <= 0) return@setOnTouchListener false
                when (e.actionMasked) {
                    android.view.MotionEvent.ACTION_DOWN,
                    android.view.MotionEvent.ACTION_MOVE -> {
                        val lm = recycler.layoutManager as? LinearLayoutManager
                        val total = memAdapter?.itemCount ?: 0
                        if (lm != null && total > 1) {
                            val frac = (e.y / th).coerceIn(0f, 1f)
                            lm.scrollToPositionWithOffset(
                                (frac * (total - 1)).toInt(), 0)
                        }
                        true
                    }
                    else -> true
                }
            }
            listRow.addView(scrollTrack)
            col.addView(listRow, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        }.onFailure { e ->
            col.addView(tv(ctx, "内存列表初始化失败: " + (e.message ?: e.toString()),
                12f, 0xFFD32F2F.toInt(), true))
        }
        return col
    }

    private fun saveChecked() {
        if (checkedAddrs.isEmpty()) { m.toast("请先勾选内存行"); return }
        // 内存页默认按 DWORD 显示，但仍先询问要保存成哪种格式。
        val first = checkedAddrs.minOrNull() ?: return
        if (OState.pid <= 0) { m.toast("请先在选项页选择进程"); return }
        chooseMemType(m, MT.DWORD, first) { type ->
            val addrs = checkedAddrs.sorted()
            m.toast("保存中…")
            Thread {
                var n = 0
                for (addr in addrs) {
                    if (saveAddrAs(m, addr, type)) n++
                }
                m.onUi {
                    m.toast(if (n > 0) "已保存 $n 条" else "这些地址已在保存列表中")
                    m.onSavedChanged()
                }
            }.start()
        }
    }

    // 跳转链接库：与 ImGui 一致，从 agent 拉取已加载库列表。
    private fun libsDialog() {
        val ctx = m.act
        val body = vcol(ctx)
        val search = edit(ctx, "搜索库名 (如 libc / il2cpp)")
        body.addView(search, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dpc(ctx, 6) })
        val status = tv(ctx, "准备连接 SO 通道…", 12f, 0xFF999999.toInt())
        body.addView(status)
        val list = vcol(ctx)
        body.addView(ScrollView(ctx).apply { addView(list) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                dpc(ctx, 250)).apply { topMargin = dpc(ctx, 6) })
        m.dialog("跳转链接库", body, listOf(Triple("关闭", true) {}))
        Thread {
            var connected = runCatching { NativeBridge.socketIsConnected() }
                .getOrDefault(false)
            if (!connected) {
                runCatching {
                    NativeBridge.socketSetTarget(
                        OState.pkg.ifEmpty { OState.pname })
                    NativeBridge.socketConnect()
                }
                for (i in 0 until 30) {
                    Thread.sleep(100)
                    connected = runCatching { NativeBridge.socketIsConnected() }
                        .getOrDefault(false)
                    if (connected) break
                }
            }
            if (!connected) {
                val st = runCatching { NativeBridge.socketStatus() }
                    .getOrDefault("未连接")
                m.onUi {
                    status.text = "SO 通道未连接: $st"
                    status.setTextColor(0xFFD32F2F.toInt())
                }
                return@Thread
            }
            val resp = runCatching { NativeBridge.socketModules() }
                .getOrDefault("")
            val libs = resp.split('\n').mapNotNull { l ->
                val f = l.trim().split(" ", limit = 2)
                if (f.size < 2) null
                else Pair(MT.parseHex(f[0]) ?: 0L, f[1])
            }.filter { it.first != 0L }

            // 库名过滤：按基名匹配（用户只会记得 libxxx.so，不会记得目录）。
            val baseNames = libs.map { it.second.substringAfterLast('/') }
            fun render(filter: String) {
                list.removeAllViews()
                val kw = filter.trim()
                val shown = ArrayList<Int>(libs.size)
                for (i in libs.indices) {
                    if (kw.isEmpty() || baseNames[i].contains(kw, true)) shown.add(i)
                }
                if (shown.isEmpty()) {
                    list.addView(tv(ctx, "无匹配链接库", 13f, 0xFF999999.toInt()))
                } else {
                    for (i in shown.take(200)) {
                        val addr = libs[i].first
                        list.addView(tv(ctx,
                            MT.addr(addr) + "  " + baseNames[i],
                            13f, 0xFF1565C0.toInt(), true).apply {
                            setPadding(0, dpc(ctx, 6), 0, dpc(ctx, 6))
                            setOnClickListener {
                                MemoryPage.jumpTo(m, addr)
                                // 跳转后关掉链接库弹窗，直接看到内存页。
                                m.dismissDialogs()
                            }
                        })
                    }
                }
                status.text = if (kw.isEmpty())
                    "共 ${libs.size} 个库，点击跳转"
                else
                    "匹配 ${shown.size} / ${libs.size} 个库（最多显示 200）"
                status.setTextColor(0xFF999999.toInt())
            }

            search.addTextChangedListener(object : TextWatcher {
                override fun afterTextChanged(s: Editable?) {}
                override fun beforeTextChanged(s: CharSequence?, a: Int,
                                               b: Int, c: Int) {}
                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {
                    render(s?.toString() ?: "")
                }
            })

            m.onUi {
                if (libs.isEmpty()) {
                    status.text = if (resp.startsWith("错误")) resp.take(200)
                                  else "未获取到链接库"
                    status.setTextColor(0xFFD32F2F.toInt())
                } else {
                    render(search.text.toString())
                }
            }
        }.start()
    }

    // 分配内存页：注入器 --alloc ptrace 远程 mmap。
    private fun allocDialog() {
        if (OState.pid <= 0) { m.toast("请先在选项页选择进程"); return }
        val ctx = m.act
        val body = vcol(ctx)
        val sizeInput = edit(ctx, "大小（字节）").apply { setText("4096") }
        body.addView(sizeInput)
        val protRow = hrow(ctx)
        val boxes = mutableListOf<Pair<String, CheckBox>>()
        for (p in listOf("r", "w", "x")) {
            val cb = CheckBox(ctx).apply {
                text = p
                setTextColor(0xFF222222.toInt())
                isChecked = p != "x"
            }
            boxes.add(p to cb)
            protRow.addView(cb)
        }
        body.addView(protRow, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 8) })
        body.addView(tv(ctx, "分配完成后可选择跳转到新页或复制地址", 11f,
            0xFF999999.toInt()).apply { setPadding(0, dpc(ctx, 6), 0, 0) })
        m.dialog("分配内存页", body, listOf(
            Triple("取消", false) {},
            Triple("分配", true) {
                val size = sizeInput.text.toString().toLongOrNull() ?: 0L
                if (size <= 0) { m.toast("大小无效"); return@Triple }
                val prot = boxes.filter { it.second.isChecked }
                    .joinToString("") { it.first }
                m.toast("分配中…")
                Thread {
                    // 并对返回地址做 memRead 校验；注入器 --alloc 的结果也要校验，
                    // 避免把错误地址当分配页（GG 里会看到别人的数据）。
                    if (!runCatching { NativeBridge.socketIsConnected() }.getOrDefault(false)) {
                        runCatching { NativeBridge.socketConnect() }
                        Thread.sleep(200)
                    }
                    // 固定 socket 名易连到旧 agent：连上后先校验 pid，不匹配直接清理并按失败处理
                    val staleAgent = !SocketUtil.verifyAgentPid(OState.pid)
                    val connected = !staleAgent &&
                        runCatching { NativeBridge.socketIsConnected() }.getOrDefault(false)

                    fun parseAddr(text: String): Long? {
                        val m = Regex("0x([0-9a-fA-F]{6,16})").findAll(text).lastOrNull()
                            ?: return null
                        return m.groupValues[1].toLongOrNull(16)
                    }
                    fun verify(a: Long): Boolean =
                        runCatching { NativeBridge.memRead(OState.pid, a, 16) }
                            .getOrNull()?.isNotEmpty() == true
                    fun tryOne(pr: String): Pair<Long?, String> {
                        val out = if (connected) {
                            runCatching { NativeBridge.socketAlloc(size, pr) }
                                .getOrDefault("ERR:socket")
                        } else {
                            runCatching { NativeBridge.allocRemote(OState.pid, size, pr) }
                                .getOrDefault("ERR:")
                        }
                        val a = parseAddr(out)
                        val okv = a != null && a > 0x1000 && verify(a)
                        android.util.Log.i("ATraceAlloc",
                            "prot=%s out=%s parsed=%s ok=%s".format(
                                pr, out.replace("\n", " | "),
                                a?.let { "0x%X".format(it) } ?: "null", okv))
                        return if (okv) a to out else null to out
                    }

                    var got: Long? = null
                    var usedProt = prot
                    var lastOut = ""
                    val tries = if (prot.contains("x"))
                        listOf(prot, prot, "rw") else listOf(prot, prot)
                    outer@ for (pr in tries) {
                        val (a, out) = tryOne(pr)
                        lastOut = out
                        if (a != null) { got = a; usedProt = pr; break@outer }
                    }
                    m.onUi {
                        val a = got
                        if (a != null) {
                            if (usedProt != prot)
                                m.toast("rwx 被系统拒绝，已降级为 $usedProt")
                            allocDoneDialog("0x%X".format(a))
                        } else {
                            m.dialog("分配失败", vcol(ctx).apply {
                                addView(tv(ctx,
                                    ("返回内容:\n" + lastOut.take(300) +
                                     "\n\n地址校验失败：该地址在目标进程不可读，可能是注入器 --alloc 返回了错误地址。" +
                                     "\n建议：先在选项页连上 agent（注入后自动连接 socket）再分配。"),
                                    12f, 0xFFD32F2F.toInt()).apply {
                                    setTextIsSelectable(true)
                                })
                            }, listOf(Triple("关闭", true) {}))
                        }
                    }
                }.start()
            }))
    }

    private fun allocDoneDialog(addrText: String) {
        val ctx = m.act
        val body = vcol(ctx)
        body.addView(tv(ctx, "新页地址:", 13f, 0xFF666666.toInt()))
        body.addView(tv(ctx, addrText, 18f, 0xFF1B8C3C.toInt(), true).apply {
            setPadding(0, dpc(ctx, 4), 0, dpc(ctx, 4))
            setOnClickListener { copyText(ctx, addrText) }
        })
        m.dialog("分配成功", body, listOf(
            Triple("复制地址", false) {
                copyText(ctx, addrText)
            },
            Triple("跳转", true) {
                base = addrText.removePrefix("0x").removePrefix("0X")
                    .toLongOrNull(16) ?: base
                refresh()
            }))
    }

    private fun editRow(idx: Int, presetType: Int = MT.DWORD, presetText: String = "") {
        if (OState.pid <= 0) { m.toast("请先在选项页选择进程"); return }
        val addr = base + idx * 4L
        val body = vcol(ctx)
        // 不再是一排让人看不懂的字母（E 是 Double，A 是 ASCII，两个 E 是 ASM 误显示）。
        var type = presetType
        // 输入框先建好：类型列表的回调要读它的当前内容（选完类型重开编辑框时保留）
        val input = edit(ctx, "新值 / ~A8 nop")
        if (presetText.isNotEmpty()) {
            input.setText(presetText)
        } else {
            val n = MT.size(type)
            if (n > 0) {
                val b = runCatching { NativeBridge.memRead(OState.pid, addr, n) }.getOrNull()
                if (b != null && b.size == n) {
                    var raw = 0L
                    for (k in 0 until n)
                        raw = raw or (((b.getOrNull(k)?.toLong()?.and(0xFF)) ?: 0L) shl (8 * k))
                    input.setText(MT.fmt(type, raw))
                }
            }
        }
        // 用户反馈原来不知道这行能点：文字上直接写「当前选中 … ▾ 点此切换」，
        // 下面再补一行说明；点整行打开 GG 风格类型列表。
        val typeBtn = btn(ctx, "当前选中 " + MT.describe(type) + "   ▾ 点此切换类型") {
            val chooser = buildTypeChooser(m, type) { picked ->
                m.dismissDialogs()
                editRow(idx, picked, "")
            }
            m.dialog("选择要更改的数据类型", chooser, listOf(Triple("取消", false) {}))
        }
        typeBtn.gravity = Gravity.CENTER_VERTICAL
        body.addView(typeBtn, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))
        body.addView(tv(ctx, "↑ 点这一行可切换内存类型（当前选中 ${MT.letter(type)}）",
            11f, 0xFF999999.toInt()).apply { setPadding(0, dpc(ctx, 4), 0, 0) })
        body.addView(input, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 8) })
        body.addView(tv(ctx,
            "数值按所选类型写入；~A8 开头按汇编写入；Q 类型输入 78fd6604Ch 则写指针",
            11f, 0xFF999999.toInt()))
        m.dialog("修改 %08X ".format(addr), body, listOf(
            Triple("取消", false) {},
            Triple("写入", true) {
                val txt = input.text.toString().trim()
                //   输入 78fd6604Ch → 解析成 0x78FD6604C 并按 8 字节小端写入
                if (type == MT.QWORD && txt.length > 1 &&
                    (txt.last() == 'h' || txt.last() == 'H') &&
                    txt.dropLast(1).all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }) {
                    val pv = runCatching {
                        java.lang.Long.parseUnsignedLong(txt.dropLast(1), 16)
                    }.getOrNull()
                    if (pv == null) { m.toast("指针格式错误"); return@Triple }
                    val bytes = java.nio.ByteBuffer.allocate(8)
                        .order(java.nio.ByteOrder.LITTLE_ENDIAN).putLong(pv).array()
                    Thread {
                        val ok = memWriteUndoable(addr, bytes, "内存页写指针")
                        m.onUi {
                            m.toast(if (ok) "指针已写入 0x%X（可撤销）".format(pv) else "写入失败")
                            if (ok) refresh()
                        }
                    }.start()
                    return@Triple
                }
                if (txt.startsWith("~A8") || txt.startsWith("~a8")) {
                    val asm = txt.substring(3).trim()
                    if (asm.isEmpty()) { m.toast("汇编语句为空"); return@Triple }
                    Thread {
                        // 汇编写入长度不定：先存 32 字节原字节，撤销时按 32 字节恢复
                        val old = runCatching { NativeBridge.memRead(OState.pid, addr, 32) }.getOrNull()
                        val out = runCatching {
                            NativeBridge.asmWrite(OState.pid, addr,
                                asm)
                        }.getOrDefault("错误: 执行失败")
                        if (out.startsWith("OK") && old != null && old.size == 32) {
                            UndoStack.push(addr, old, "汇编写入")
                        }
                        m.onUi {
                            m.toast(out)
                            if (out.startsWith("OK")) {
                        loadedBase = -1L; pageCache.clear(); refresh()
                    }
                        }
                    }.start()
                    return@Triple
                }
                val bytes = MT.encode(type, input.text.toString())
                if (bytes == null) { m.toast("值格式错误"); return@Triple }
                Thread {
                    val ok = memWriteUndoable(addr, bytes, "内存页修改")
                    m.onUi {
                        m.toast(if (ok) "写入成功（可撤销）" else "写入失败")
                        if (ok) {
                            loadedBase = -1L      // 丢弃反汇编/数值缓存，重新读取
                            pageCache.clear()
                            refresh()
                        }
                    }
                }.start()
            }))
    }

    /** 当前可见的行下标范围（0 基，不含页首/页尾跳转项）。 */
    private fun visibleRowRange(): IntRange {
        val lm = recycler.layoutManager as? LinearLayoutManager ?: return 0 until 0
        val f = lm.findFirstVisibleItemPosition()
        val l = lm.findLastVisibleItemPosition()
        if (f < 0 || l < 0) return 0 until 0
        return (f - 1).coerceAtLeast(0)..(l - 1).coerceAtLeast(0)
    }

    /** 按 512B 块补齐 [fromRow,toRow] 的反汇编（懒加载：先可见区，再其余）。 */
    private fun disasmRows(wantBase: Long, fromRow: Int, toRow: Int) {
        val startOff = (fromRow * 4 / 512) * 512
        val endOff = minOf(PAGE.toInt(),
            (((toRow + 1) * 4 + 511) / 512) * 512)
        var offB = startOff
        while (offB < endOff) {
            val want = minOf(512, PAGE.toInt() - offB)
            val rb = runCatching {
                NativeBridge.memRead(OState.pid, wantBase + offB, want)
            }.getOrNull()
            if (rb != null && rb.isNotEmpty()) {
                val disMap = HashMap<Long, String>()
                val dt = runCatching {
                    NativeBridge.memDisasmBlock(wantBase + offB, rb)
                }.getOrNull().orEmpty()
                for (ln in dt.split('\n')) {
                    if (ln.isBlank()) continue
                    val f = ln.split('|')
                    if (f.size >= 3) {
                        val a2 = MT.parseHex(f[0]) ?: continue
                        disMap[a2] = f[2]
                    }
                }
                var k = 0
                while (k + 4 <= rb.size) {
                    val a2 = wantBase + offB + k
                    val old = pageCache[a2]
                    if (old != null && disMap.containsKey(a2)) {
                        pageCache[a2] = old.copy(disasm = disMap[a2] ?: old.disasm)
                    }
                    k += 4
                }
            }
            offB += 512
        }
        m.onUi { memAdapter?.notifyDataSetChanged() }
    }

    /** 滚动后如果可见行还有缺反汇编的，后台补这一段。 */
    private fun ensureVisibleDisasm() {
        val wantBase = loadedBase
        if (wantBase < 0 || pageCache.isEmpty()) return
        val vr = visibleRowRange()
        if (vr.first > vr.last) return
        var need = false
        for (r in vr.first..vr.last) {
            if (pageCache[wantBase + r * 4L]?.disasm.isNullOrEmpty()) { need = true; break }
        }
        if (!need || !disasmBusy.compareAndSet(false, true)) return
        Thread {
            try { disasmRows(wantBase, vr.first, vr.last) }
            catch (_: Throwable) { }
            finally { disasmBusy.set(false) }
        }.start()
    }

    /** 跳转定位：数据就绪后滚到目标行（立即 + post + postDelayed 三次，覆盖布局未就绪）。 */
    private fun applyJumpScroll(wantBase: Long) {
        val ps = pendingScrollAddr
        pendingScrollAddr = -1L
        m.onUi {
            val idx = if (ps >= 0)
                (((ps - wantBase) / 4L)).toInt().coerceIn(0, PAGE_ROWS - 1) else 0
            fun jumpTo() {
                runCatching {
                    (recycler.layoutManager as? LinearLayoutManager)
                        ?.scrollToPositionWithOffset(idx + 1, 0)
                }
            }
            android.util.Log.i("ATraceMem",
                "JUMP target=%X page=%X idx=%d".format(ps, wantBase, idx))
            jumpTo()
            recycler.post { jumpTo(); syncScrollBar() }
            recycler.postDelayed({ jumpTo(); syncScrollBar() }, 250)
        }
    }

    /** 按 RecyclerView 滚动位置同步右侧自绘滚动条。 */
    /** 某地址属于哪个内存区间类型（cd/ca/java/xa…）。 */
    private fun regionTypeOf(a: Long): String {
        for (r in regions) if (a >= r.first && a < r.second) return r.third
        return ""
    }

    private fun syncScrollBar() {
        runCatching {
            if (!this::scrollThumb.isInitialized || !this::scrollTrack.isInitialized) return
            val th = scrollTrack.height
            if (th <= 0) return
            val lm = recycler.layoutManager as? LinearLayoutManager ?: return
            val total = (memAdapter?.itemCount ?: 0).coerceAtLeast(1)
            val first = lm.findFirstVisibleItemPosition().coerceAtLeast(0)
            val last = lm.findLastVisibleItemPosition().coerceAtLeast(first)
            val vis = (last - first + 1).coerceAtLeast(1)
            val denom = (total - vis).coerceAtLeast(1)
            val frac = (first.toFloat() / denom).coerceIn(0f, 1f)
            val ph = (th * (vis.toFloat() / total)).toInt()
                .coerceIn(dpc(m.act, 40), th)
            (scrollThumb.layoutParams as android.widget.FrameLayout.LayoutParams)
                .apply { height = ph }
            scrollThumb.translationY = (th - ph).coerceAtLeast(0) * frac
        }
    }

    /** 跳转到某地址所在的页（0x2000 对齐），记录历史。 */
    fun navigateTo(addr: Long) {
        if (addr < 0) return
        MemoryPage.pendingJump = 0
        val newBase = addr and -PAGE
        pendingScrollAddr = addr
        highlightAddr = addr
        if (newBase == base) {
            runCatching { recycler.scrollToPosition(0) }
            refresh()
            return
        }
        if (base >= 0) { backStack.addLast(base); fwdStack.clear() }
        base = newBase
        refresh()
    }

    private fun goBack() {
        val prev = backStack.removeLastOrNull() ?: return m.toast("没有可返回的地址")
        if (base >= 0) fwdStack.addLast(base)
        base = prev
        pendingScrollAddr = -1
        refresh()
    }

    private fun goForward() {
        val next = fwdStack.removeLastOrNull() ?: return m.toast("没有可前进的地址")
        if (base >= 0) backStack.addLast(base)
        base = next
        pendingScrollAddr = -1
        refresh()
    }

    // ── RecyclerView 适配器（整页 2048 行 + 页首/页尾跳转行）──────────────
    private inner class RowVH(val root: LinearLayout, val cb: CheckBox,
                              val addr: TextView, val hex: TextView,
                              val asc: TextView, val dv: TextView,
                              val fv: TextView, val dis: TextView,
                              val typeTv: TextView,
                              val copyTv: TextView) :
        RecyclerView.ViewHolder(root)

    private inner class MemAdapter : RecyclerView.Adapter<RecyclerView.ViewHolder>() {
        private val TYPE_HEAD = 0
        private val TYPE_ROW = 1
        private val TYPE_FOOT = 2
        override fun getItemCount(): Int = PAGE_ROWS + 2
        override fun getItemViewType(position: Int): Int = when (position) {
            0 -> TYPE_HEAD
            itemCount - 1 -> TYPE_FOOT
            else -> TYPE_ROW
        }
        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int):
                RecyclerView.ViewHolder {
            if (viewType != TYPE_ROW) {
                val v = btn(ctx, "地址跳转 -") {
                    val target = if (viewType == TYPE_HEAD) {
                        if (base > 0) base - 4 else 0L      // 上一页最后一个地址
                    } else base + PAGE                       // 下一页起始
                    navigateTo(target)
                }
                v.gravity = Gravity.CENTER_VERTICAL
                v.setPadding(dpc(ctx, 10), dpc(ctx, 8), dpc(ctx, 10), dpc(ctx, 8))
                v.isClickable = true
                v.isFocusable = true
                return object : RecyclerView.ViewHolder(v) {}
            }
            val cb = labelCheckBox(ctx, "", false) { }
            val addrTv = tv(ctx, "-", 14f, 0xFF1B8C3C.toInt(), true)
            val hex = tv(ctx, "-", 13f, 0xFF3465C8.toInt(), true).apply {
                isSingleLine = true; ellipsize = android.text.TextUtils.TruncateAt.END
            }
            val asc = tv(ctx, "-", 12f, 0xFF888888.toInt())
            val dv = tv(ctx, "-", 12f, 0xFF0E7FA8.toInt(), true).apply {
                isSingleLine = true; ellipsize = android.text.TextUtils.TruncateAt.END
            }
            val fv = tv(ctx, "-", 12f, 0xFF0E7FA8.toInt(), true).apply {
                isSingleLine = true; ellipsize = android.text.TextUtils.TruncateAt.END
            }
            val l1 = hrow(ctx).apply {
                addView(addrTv, LinearLayout.LayoutParams(
                    dpc(ctx, 92), ViewGroup.LayoutParams.WRAP_CONTENT))
                addView(hex, LinearLayout.LayoutParams(
                    dpc(ctx, 96), ViewGroup.LayoutParams.WRAP_CONTENT))
                addView(asc, LinearLayout.LayoutParams(
                    dpc(ctx, 26), ViewGroup.LayoutParams.WRAP_CONTENT))
            }
            val l2 = hrow(ctx).apply {
                addView(dv, LinearLayout.LayoutParams(
                    dpc(ctx, 150), ViewGroup.LayoutParams.WRAP_CONTENT))
                addView(fv, LinearLayout.LayoutParams(
                    dpc(ctx, 160), ViewGroup.LayoutParams.WRAP_CONTENT))
            }
            val dis = tv(ctx, "", 11f, 0xFF8E24AA.toInt(), true).apply {
                isSingleLine = true; ellipsize = android.text.TextUtils.TruncateAt.END
            }
            val typeTv = tv(ctx, "", 10f, 0xFF8E24AA.toInt()).apply {
                isSingleLine = true
            }
            val l3 = hrow(ctx).apply {
                addView(typeTv, LinearLayout.LayoutParams(
                    dpc(ctx, 62), ViewGroup.LayoutParams.WRAP_CONTENT))
                addView(dis, LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            }
            val info = vcol(ctx).apply {
                layoutParams = LinearLayout.LayoutParams(
                    0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                addView(l1); addView(l2); addView(l3)
            }
            val copyTv = tv(ctx, "复制", 12f, 0xFF1565C0.toInt()).apply {
                setPadding(dpc(ctx, 4), 0, 0, 0)
            }
            val h = hrow(ctx).apply {
                setPadding(dpc(ctx, 8), dpc(ctx, 3), dpc(ctx, 8), dpc(ctx, 3))
                addView(cb, LinearLayout.LayoutParams(
                    dpc(ctx, 30), ViewGroup.LayoutParams.WRAP_CONTENT))
                addView(info); addView(copyTv)
            }
            // 每行底部一条细分隔线（之前 RecyclerView 版没有）
            val root = vcol(ctx).apply {
                addView(h, LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT))
                addView(View(ctx).apply {
                    setBackgroundColor(0x14000000)
                }, LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, dpc(ctx, 1)))
            }
            return RowVH(root, cb, addrTv, hex, asc, dv, fv, dis, typeTv, copyTv)
        }
        override fun onBindViewHolder(holder: RecyclerView.ViewHolder, position: Int) {
          try {
            if (holder !is RowVH) {
                val isHead = getItemViewType(position) == TYPE_HEAD
                val target = if (isHead) {
                    if (base > 0) base - 4 else 0L          // 上一页最后一个地址（GG 显示 ...FFFC）
                } else base + PAGE
                (holder.itemView as TextView).text =
                    "地址跳转 %08X（点此处翻页）".format(target)
                return
            }
            val a = base + (position - 1) * 4L
            holder.addr.text = MT.addr(a)
            val row = pageCache[a]
            if (row == null || !row.ok) {
                holder.hex.text = "00000000"
                holder.asc.text = "'."
                holder.dv.text = "D: 0"
                holder.fv.text = "F: 0.0"
                val tp0 = regionTypeOf(a)
                holder.typeTv.text = if (tp0.isNotEmpty()) tp0 else "other"
                holder.dis.text = row?.disasm?.takeIf { it.isNotEmpty() } ?: "--"
            } else {
                val w = row.value
                holder.hex.text = "%08X".format(w.toInt())
                val c = (w.toInt() and 0xFF)
                holder.asc.text = if (c in 0x20..0x7E) "'${c.toChar()}'" else "'."
                holder.dv.text = "D: ${w and 0xFFFFFFFFL}"
                holder.fv.text = "F: " + java.lang.String.format(
                    "%.4g", java.lang.Float.intBitsToFloat(w.toInt()))
                val tp = regionTypeOf(a)
                holder.typeTv.text = if (tp.isNotEmpty()) tp else "other"

                holder.dis.text = if (row.disasm.isNotEmpty()) row.disasm else "--"
            }
            holder.root.setBackgroundColor(
                if (a == highlightAddr) 0x33FFEB3B else 0x00000000)
            muteChecks = true
            holder.cb.isChecked = checkedAddrs.contains(a)
            muteChecks = false
            holder.cb.setOnCheckedChangeListener { _, c ->
                if (muteChecks) return@setOnCheckedChangeListener
                if (c) { checkedAddrs.add(a); anchor = position - 1 }
                else checkedAddrs.remove(a)
            }
            holder.root.setOnClickListener { editRow(position - 1) }
            val disasm = pageCache[a]?.disasm ?: ""
            holder.root.setOnLongClickListener {
                showRowMenu(m, a, MT.DWORD, 0L, disasm); true
            }
            holder.addr.setOnLongClickListener {
                showRowMenu(m, a, MT.DWORD, 0L, disasm); true
            }
            holder.copyTv.setOnClickListener {
                copyText(ctx, MT.addr(a)); m.toast("已复制地址")
            }
          } catch (t: Throwable) {
            // 单行绑定异常不影响整个列表
          }
        }
    }

    fun refresh() {
        if (OState.pid <= 0) {
            m.onUi { pageLabel.text = "未选择进程"; memAdapter?.notifyDataSetChanged() }
            return
        }
        if (!refreshBusy.compareAndSet(false, true)) return   // 已有线程在刷新
        Thread {
          try {
            if (MemoryPage.pendingJump != 0L) {
                val target = MemoryPage.pendingJump
                MemoryPage.pendingJump = 0
                val newBase = target and -PAGE
                if (base >= 0 && base != newBase) {
                    backStack.addLast(base); fwdStack.clear()
                }
                base = newBase
                // 断点/指针/菜单跳转：页基址 0x2000 对齐，但列表要滚到目标地址
                pendingScrollAddr = target
                highlightAddr = target
            }
            if (base < 0) {
                base = runCatching { NativeBridge.memFirstAddress(OState.pid) }
                    .getOrDefault(0L)
            }
            if (base <= 0) {
                m.onUi { pageLabel.text = "无法定位可读内存" }
                return@Thread
            }
            base = base and -PAGE
            val wantBase = (base and -PAGE)
            android.util.Log.i("ATraceMem",
                "refresh rawBase=%X aligned=%X pid=%d".format(base, wantBase, OState.pid))
            loadingBase = wantBase
            // 立即显示数值+反汇编；后台只静默更新数值，不重算反汇编。
            if (wantBase == loadedBase && pageCache.isNotEmpty()) {
                m.onUi {
                    memAdapter?.notifyDataSetChanged()
                    recycler.post { syncScrollBar() }
                }
                var offB = 0
                while (offB < PAGE.toInt() && loadingBase == wantBase) {
                    val want = minOf(512, PAGE.toInt() - offB)
                    val rb = runCatching {
                        NativeBridge.memRead(OState.pid, wantBase + offB, want)
                    }.getOrNull()
                    if (rb != null && rb.isNotEmpty()) {
                        var k = 0
                        while (k + 4 <= rb.size) {
                            val a2 = wantBase + offB + k
                            var v = 0L
                            for (b in 0 until 4)
                                v = v or (((rb[k + b].toLong() and 0xFF)) shl (8 * b))
                            val oldRow = pageCache[a2]
                            pageCache[a2] = if (oldRow != null)
                                oldRow.copy(value = v, ok = true)
                            else MemRow(a2, true, v, "", "")
                            k += 4
                        }
                    }
                    offB += 512
                }
                m.onUi { memAdapter?.notifyDataSetChanged() }
                applyJumpScroll(wantBase)
                return@Thread
            }
            loadedBase = wantBase
            pageCache.clear()
            // 先本地填 0 立即显示（分配页通常就是 0，避免"空等"）
            for (i in 0 until PAGE_ROWS) {
                val a0 = wantBase + i * 4L
                pageCache[a0] = MemRow(a0, true, 0L, "", "")
            }
            m.onUi { memAdapter?.notifyDataSetChanged() }
            regions.clear()
            for (ln in runCatching { NativeBridge.memRegions(OState.pid) }
                    .getOrDefault("").split('\n')) {
                if (ln.isBlank()) continue
                val f = ln.split('|')
                if (f.size < 3) continue
                val st = MT.parseHex(f[0]) ?: continue
                val en = MT.parseHex(f[1]) ?: continue
                val rawType = f[2]
                val path = if (f.size >= 4) f[3] else ""
                // 统一显示 A（GG 的 A 内存）；有真实文件路径/已知类型才保留原类型
                val known = rawType in listOf("code app", "code system", "java",
                                              "cd", "ca", "xa", "stack")
                val disp = if (path.startsWith("/") || known) rawType else "A"
                regions.add(Triple(st, en, disp))
            }
            // 正常页几十毫秒出全部数值+反汇编；失败/读不满才走下面的分块回退。
            val whole = runCatching {
                NativeBridge.memRead(OState.pid, wantBase, PAGE.toInt())
            }.getOrNull()
            if (whole != null && whole.size == PAGE.toInt()) {
                val disMap = HashMap<Long, String>()
                val dt = runCatching {
                    NativeBridge.memDisasmBlock(wantBase, whole)
                }.getOrNull().orEmpty()
                for (ln in dt.split('\n')) {
                    if (ln.isBlank()) continue
                    val f = ln.split('|')
                    if (f.size >= 3) {
                        val a2 = MT.parseHex(f[0]) ?: continue
                        disMap[a2] = f[2]
                    }
                }
                for (i in 0 until PAGE_ROWS) {
                    val off = i * 4
                    if (off + 4 > whole.size) break
                    val a2 = wantBase + i * 4L
                    var v = 0L
                    for (b in 0 until 4)
                        v = v or (((whole[off + b].toLong() and 0xFF)) shl (8 * b))
                    pageCache[a2] = MemRow(a2, true, v, disMap[a2] ?: "", "")
                }
                m.onUi {
                    memAdapter?.notifyDataSetChanged()
                    recycler.post { syncScrollBar() }
                }
                applyJumpScroll(wantBase)
                return@Thread
            }
            MemoryPage.takePendingSel()?.let { (st, cnt) ->
                for (i in 0 until cnt) checkedAddrs.add(st + i * 4L)
                pendingScrollAddr = st
            }
            m.onUi {
                pageLabel.text = "%08X - %08X".format(
                wantBase and -PAGE, (wantBase and -PAGE) + PAGE - 1)
                addrInput.setText("%08X".format(wantBase and -PAGE))
                memAdapter?.notifyDataSetChanged()
                val ps = pendingScrollAddr
                pendingScrollAddr = -1
                if (ps >= 0) {
                    val idx = (((ps - wantBase) / 4L)).toInt()
                        .coerceIn(0, PAGE_ROWS - 1)
                    fun jumpTo() {
                        runCatching {
                            (recycler.layoutManager as? LinearLayoutManager)
                                ?.scrollToPositionWithOffset(idx + 1, 0)
                        }
                    }
                    android.util.Log.i("ATraceMem",
                        "JUMP target=%X page=%X idx=%d highlight=%X".format(
                            ps, wantBase, idx, highlightAddr))
                    jumpTo()
                    recycler.post {
                        jumpTo(); syncScrollBar()
                        val lm = recycler.layoutManager as? LinearLayoutManager
                        android.util.Log.i("ATraceMem",
                            "JUMP(post) first=%d".format(lm?.findFirstVisibleItemPosition() ?: -99))
                    }
                    recycler.postDelayed({
                        jumpTo(); syncScrollBar()
                        val lm = recycler.layoutManager as? LinearLayoutManager
                        android.util.Log.i("ATraceMem",
                            "JUMP(+250) first=%d".format(lm?.findFirstVisibleItemPosition() ?: -99))
                    }, 250)
                } else {
                    recycler.scrollToPosition(0)
                }
            }
            // Pass1：只读数值（memRead 512B/块），块字节缓存给 Pass2 反汇编复用
            val chunkBytes = 512
            val chunkBuf = HashMap<Int, ByteArray>()
            var offB = 0
            while (offB < PAGE.toInt() && loadingBase == wantBase) {
                val want = minOf(chunkBytes, PAGE.toInt() - offB)
                val rb = runCatching {
                    NativeBridge.memRead(OState.pid, wantBase + offB, want)
                }.getOrNull()
                if (rb != null && rb.isNotEmpty()) {
                    chunkBuf[offB] = rb
                    var k = 0
                    while (k + 4 <= rb.size) {
                        val a2 = wantBase + offB + k
                        var v = 0L
                        for (b in 0 until 4)
                            v = v or (((rb[k + b].toLong() and 0xFF)) shl (8 * b))
                        pageCache[a2] = MemRow(a2, true, v, pageCache[a2]?.disasm ?: "", "")
                        k += 4
                    }
                }
                offB += chunkBytes
            }
            m.onUi {
                memAdapter?.notifyDataSetChanged()
                recycler.post { syncScrollBar() }
            }
            // Pass2：懒加载反汇编——先补当前可见区（立刻看到指令），再补齐整页
            run {
                val vr = visibleRowRange()
                if (vr.first <= vr.last) disasmRows(wantBase, vr.first, vr.last)
                disasmRows(wantBase, 0, PAGE_ROWS - 1)
            }
            m.onUi { recycler.post { syncScrollBar() } }
            offB = 0
            while (offB < PAGE.toInt() && loadingBase == wantBase) {
                val want = minOf(chunkBytes, PAGE.toInt() - offB)
                val rb = runCatching {
                    NativeBridge.memRead(OState.pid, wantBase + offB, want)
                }.getOrNull()
                if (rb != null && rb.isNotEmpty()) {
                    val disMap = HashMap<Long, String>()
                    val dt = runCatching {
                        NativeBridge.memDisasmBlock(wantBase + offB, rb)
                    }.getOrNull().orEmpty()
                    for (ln in dt.split('\n')) {
                        if (ln.isBlank()) continue
                        val f = ln.split('|')
                        if (f.size >= 3) {
                            val a2 = MT.parseHex(f[0]) ?: continue
                            disMap[a2] = f[2]
                        }
                    }
                    if (disMap.isEmpty()) {
                        val rows2 = minOf(64, want / 4)
                        val t2 = runCatching {
                            NativeBridge.memPage(OState.pid, wantBase + offB, rows2)
                        }.getOrDefault("")
                        for (ln in t2.split('\n')) {
                            val f = ln.split('|')
                            if (f.size < 5) continue
                            val a2 = MT.parseHex(f[0]) ?: continue
                            if (f[3].isNotEmpty()) disMap[a2] = f[3]
                        }
                    }
                    var k = 0
                    while (k + 4 <= rb.size) {
                        val a2 = wantBase + offB + k
                        val old = pageCache[a2]
                        if (old != null) {
                            pageCache[a2] = old.copy(disasm = disMap[a2] ?: old.disasm)
                        }
                        k += 4
                    }
                }
                offB += chunkBytes
            }
            m.onUi {
                memAdapter?.notifyDataSetChanged()
                recycler.post { syncScrollBar() }
            }
          } catch (t: Throwable) {
            m.onUi { m.toast("内存页刷新失败: " + (t.message ?: t.toString())) }
          } finally {
              refreshBusy.set(false)
          }
        }.start()
    }
}

// ── 脚本页（Lua 脚本编辑与执行）──

class ScriptPage(private val m: OverlayManager) : OverlayPage {
    private lateinit var editor: EditText
    private lateinit var luaResult: TextView
    // 固定高度的输出面板：竖向滚动外层 + 横向滚动内层（长行不折行，可左右滑）
    private lateinit var luaScroll: ScrollView
    private lateinit var luaHScroll: HorizontalScrollView

    private fun scriptFile(): File =
        File(m.act.filesDir, "scripts/last.lua").apply {
            parentFile?.mkdirs()
        }

    // ── 「选择脚本并执行」用到的偏好键（存 overlay 这一份，与其它设置一致）──
    // KEY_LUA_PATH：最近一次选中的脚本**完整路径**，下次打开对话框默认显示它；
    // KEY_LUA_DIR ：最近一次浏览的**目录**，当上面的文件不在了时用它当起始目录。
    // 首次使用两者都为空 → 默认 /sdcard（用户要求）。
    private fun prefs() = m.act.getSharedPreferences("overlay", Context.MODE_PRIVATE)

    private fun lastScriptPath(): String =
        prefs().getString(KEY_LUA_PATH, "") ?: ""

    private fun lastBrowseDir(): String =
        (prefs().getString(KEY_LUA_DIR, "") ?: "").ifEmpty { "/sdcard" }

    private fun saveScriptPath(p: String) {
        prefs().edit().putString(KEY_LUA_PATH, p).apply()
    }

    private fun saveBrowseDir(p: String) {
        prefs().edit().putString(KEY_LUA_DIR, p).apply()
    }

    /**
     * 是否已获得「任意文件读取」权限。
     *
     * 为什么需要它：用户要求文件浏览器**自己写**、不要调系统文件管理器（SAF）。
     * 在 Android 11+（本机是 Android 16 / targetSdk 36）上，直接按路径遍历 /sdcard
     * 只有一条合法途径 —— 用户手动授予「所有文件访问权限」。
     * Android 10 及以下仍可用运行时权限 READ_EXTERNAL_STORAGE。
     */
    private fun storageGranted(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            runCatching { Environment.isExternalStorageManager() }.getOrDefault(false)
        } else {
            ContextCompat.checkSelfPermission(
                m.act, Manifest.permission.READ_EXTERNAL_STORAGE
            ) == PackageManager.PERMISSION_GRANTED
        }

    /**
     * 引导用户授予存储权限。
     *
     * 原则（用户明确要求）：**不要什么都走 root**。没权限就明确告诉用户去给权限，
     * 给完之后直接可用 —— 而不是偷偷用 su 去读文件。
     */
    private fun requestStoragePermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // 「所有文件访问权限」只能跳到系统设置页由用户手动开，没有运行时弹窗。
            val ok = runCatching {
                m.act.startActivity(
                    Intent(
                        Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:${m.act.packageName}")
                    )
                )
            }.isSuccess
            if (!ok) {
                // 个别 ROM 没有应用级页面，退回列表页
                runCatching {
                    m.act.startActivity(
                        Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                    )
                }
            }
            m.toast("请在设置里开启「所有文件访问权限」，返回后再点「刷新」")
        } else {
            m.act.requestPermissions(
                arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE), REQ_STORAGE
            )
        }
    }

    /** 目录里的一项：目录还是文件（用于自己画列表，不依赖任何系统选择器）。 */
    private data class FsNode(val name: String, val dir: Boolean)

    /**
     * 列出目录内容。返回 null 表示**列不出来**（没权限 / 不存在）。
     * 只用 java.io.File，不调 su —— 权限由用户授予。
     */
    private fun listDir(path: String): List<FsNode>? {
        val f = File(path)
        if (!f.isDirectory) return null
        val arr = runCatching { f.listFiles() }.getOrNull() ?: return null
        return arr.map { FsNode(it.name, it.isDirectory) }
            .sortedWith(
                compareByDescending<FsNode> { it.dir }.thenBy { it.name.lowercase() }
            )
    }

    /** 由路径推断浏览器该从哪个目录开始。 */
    private fun startDirOf(path: String): String {
        val p = path.trim()
        if (p.isEmpty()) return lastBrowseDir()
        val f = File(p)
        return when {
            f.isDirectory -> p
            f.parentFile != null -> f.parentFile!!.absolutePath
            else -> lastBrowseDir()
        }
    }

    /**
     * 「选择脚本并执行」对话框。
     *
     * 一个对话框里同时提供两种选择方式（用户要求）：
     *   1) 直接输入/粘贴路径；
     *   2) 下方的自绘文件浏览器：点目录进入、点文件选中（选中即把路径填进上面的输入框）。
     * 没有存储权限时**不降级走 root**，而是显示「授予存储权限」按钮引导用户授权。
     */
    private fun openScriptDialog() {
        val ctx = m.act
        val body = vcol(ctx)

        // 【焦点锚】对话框一打开就把焦点给这个 0×0 的可聚焦 View，
        // 否则路径输入框会自动获得焦点 → 键盘立刻弹出 → 把下面的文件列表挡住。
        // （实测：不处理时首屏只能看到 4 个目录项，键盘占掉下半屏。）
        body.addView(View(ctx).apply {
            isFocusable = true
            isFocusableInTouchMode = true
        }, LinearLayout.LayoutParams(0, 0))

        body.addView(tv(ctx, "输入脚本路径，或在下方列表里选择（点目录进入、点文件选中）",
            12f, 0xFF999999.toInt()).apply {
            setPadding(0, 0, 0, dpc(ctx, 6))
        })

        val pathEdit = edit(ctx, "/sdcard/演示脚本.lua").apply {
            val init = lastScriptPath().ifEmpty { lastBrowseDir() }
            setText(init)
            setSelection(text.length)
        }
        body.addView(pathEdit, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))

        val dirTv = tv(ctx, "", 12f, 0xFF1B8C3C.toInt()).apply {
            typeface = Typeface.MONOSPACE
            setPadding(0, dpc(ctx, 8), 0, dpc(ctx, 4))
        }
        val msgTv = tv(ctx, "", 12f, 0xFFD32F2F.toInt())
        val listHost = vcol(ctx)
        val listScroll = ScrollView(ctx).apply { addView(listHost) }

        // 当前浏览目录（点目录会改它）
        var curDir: String = startDirOf(pathEdit.text.toString())

        // 刷新列表：目录标题 + 条目 + 权限/错误提示
        fun reload() {
            listHost.removeAllViews()
            dirTv.text = curDir
            msgTv.text = ""
            if (!storageGranted()) {
                msgTv.text = "没有存储访问权限。请点「授予权限」在系统设置里开启" +
                        "「所有文件访问权限」，返回后再点「刷新」。"
                return
            }
            val nodes = listDir(curDir)
            if (nodes == null) {
                msgTv.text = "无法列出该目录（权限不足或目录不存在）"
                return
            }
            if (nodes.isEmpty()) {
                msgTv.text = "（空目录）"
                return
            }
            for (n in nodes) {
                val full = if (curDir == "/") "/${n.name}" else "$curDir/${n.name}"
                val row = TextView(ctx).apply {
                    text = if (n.dir) "▸ ${n.name}/" else "   ${n.name}"
                    textSize = 13f
                    setTextColor(if (n.dir) 0xFF1565C0.toInt() else 0xFF333333.toInt())
                    typeface = Typeface.MONOSPACE
                    setPadding(dpc(ctx, 6), dpc(ctx, 7), dpc(ctx, 6), dpc(ctx, 7))
                    isClickable = true
                    setOnClickListener {
                        if (n.dir) {
                            curDir = full
                            saveBrowseDir(curDir)
                            reload()
                        } else {
                            // 手动选中文件 → 直接填入用户选择的脚本路径（用户要求）
                            pathEdit.setText(full)
                            pathEdit.setSelection(pathEdit.text.length)
                            saveScriptPath(full)
                            saveBrowseDir(curDir)
                            m.toast("已选中 ${n.name}")
                        }
                    }
                }
                listHost.addView(row, LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT))
            }
        }

        body.addView(dirTv, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))

        val nav = hrow(ctx)
        nav.addView(btn(ctx, "上级目录") {
            // 存储根目录（/sdcard 或它的真实路径）再往上就是 "/"，
            // 那里列不出东西（也没有意义），直接拦下避免用户以为坏了。
            val atStorageRoot = curDir == "/sdcard" ||
                    curDir == "/storage/emulated/0" || curDir == "/storage/emulated/0/"
            val parent = File(curDir).parentFile
            when {
                atStorageRoot -> m.toast("已在存储根目录")
                parent == null -> m.toast("已经是根目录")
                else -> {
                    curDir = parent.absolutePath
                    saveBrowseDir(curDir)
                    reload()
                }
            }
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            marginEnd = dpc(ctx, 6)
        })
        nav.addView(btn(ctx, "刷新") { reload() },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginEnd = dpc(ctx, 6)
            })
        nav.addView(btn(ctx, "授予权限") { requestStoragePermission() },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        body.addView(nav, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })

        // 列表固定高度，避免对话框被目录内容撑爆（外层还有一层 ScrollView）
        listScroll.background = GradientDrawable().apply {
            setColor(0xFFF0F0F0.toInt())
            cornerRadius = dpc(ctx, 6).toFloat()
        }
        body.addView(listScroll, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dpc(ctx, 240)).apply {
            topMargin = dpc(ctx, 6)
        })
        body.addView(msgTv, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })

        reload()

        m.dialog("打开脚本并执行", body, listOf(
            Triple("取消", false) {},
            Triple("执行", true) { runLuaFile(pathEdit.text.toString()) }
        ))
    }

    /** 读取指定路径的脚本文件并执行（不经过 root：权限由用户授予）。 */
    private fun runLuaFile(rawPath: String) {
        val path = rawPath.trim()
        if (path.isEmpty()) {
            m.toast("请先输入或选择脚本路径")
            return
        }
        if (!storageGranted()) {
            m.toast("缺少存储权限，请先授予")
            requestStoragePermission()
            return
        }
        val f = File(path)
        if (!f.isFile) {
            m.toast("文件不存在：$path")
            return
        }
        if (f.length() > 1024L * 1024L) {
            m.toast("脚本过大（超过 1MB），拒绝执行")
            return
        }
        val text = runCatching { f.readText() }.getOrNull()
        if (text == null) {
            m.toast("读取失败：$path")
            return
        }
        // 记住这次的选择，下次打开对话框默认就是它（用户要求）
        saveScriptPath(path)
        f.parentFile?.let { saveBrowseDir(it.absolutePath) }
        // 同步到编辑框，用户能看到/接着改这次执行的脚本
        if (::editor.isInitialized) editor.setText(text)
        m.toast("已载入 ${f.name}，开始执行")
        runLua(text)
    }

    /** 实际执行 Lua：走 agent socket（与原「执行」按钮同一套链路）。 */
    private fun runLua(script: String) {
        if (!runCatching { NativeBridge.socketIsConnected() }.getOrDefault(false)) {
            m.toast("请先在选项页连接 SO 通道")
            return
        }
        if (!::luaResult.isInitialized) return
        luaResult.text = "执行中…"
        Thread {
            // 水位法：执行前记下日志条数，执行后只取新增的日志。
            // 以前是"取全部历史日志"，导致之前 help()/api() 打过的几十行
            val watermark = readLogWatermark()
            val sent = runCatching {
                NativeBridge.socketSendLua(script)
            }.getOrDefault("发送失败")
            var newLines: List<String> = emptyList()
            val deadline = System.currentTimeMillis() + 2500
            while (System.currentTimeMillis() < deadline) {
                Thread.sleep(120)
                val (count, lines) = readLuaLogs()
                if (count > watermark) {
                    newLines = if (watermark in 0 until lines.size) lines.drop(watermark) else lines
                    // 再接一下异步 print
                    Thread.sleep(150)
                    val (c2, l2) = readLuaLogs()
                    if (c2 > count) {
                        newLines = if (watermark in 0 until l2.size) l2.drop(watermark) else l2
                    }
                    break
                }
            }
            val shown = if (newLines.size > MAX_LOG_LINES) {
                listOf("…（本次共 ${newLines.size} 行，仅显示最后 $MAX_LOG_LINES 行）") +
                    newLines.takeLast(MAX_LOG_LINES)
            } else newLines
            val body = buildString {
                append(sent.trim())
                if (shown.isNotEmpty()) {
                    append('\n')
                    append(shown.joinToString("\n"))
                }
            }
            // 单行过长也要截断（寄存器 dump 之类），否则横向滚动条会拉得极长
            val text = body.lineSequence()
                .map { if (it.length > MAX_LOG_LINE_LEN)
                    it.take(MAX_LOG_LINE_LEN) + " …(截断)" else it }
                .joinToString("\n")
            m.onUi {
                if (::luaResult.isInitialized) {
                    luaResult.text = text
                    // 新输出后自动滚到底部（竖向），横向保持最左
                    luaScroll.post {
                        runCatching { luaScroll.fullScroll(View.FOCUS_DOWN) }
                        runCatching { luaHScroll.scrollTo(0, 0) }
                    }
                }
            }
        }.start()
    }

    /** 读 agent 日志：返回 (总数, 全部日志行)。首行是总数，其余是非破坏性读取的全部日志。 */
    private fun readLuaLogs(): Pair<Int, List<String>> {
        val raw = runCatching { NativeBridge.socketLuaLogs() }.getOrDefault("")
        if (raw.isBlank()) return 0 to emptyList()
        val all = raw.split('\n')
        val count = all.firstOrNull()?.trim()?.toIntOrNull() ?: 0
        return count to all.drop(1).filter { it.isNotBlank() }
    }

    private fun readLogWatermark(): Int = readLuaLogs().first

    override fun build(): View {
        val ctx = m.act
        val col = vcol(ctx)
        col.addView(tv(ctx, "Lua 脚本", 18f, 0xFF222222.toInt()).apply {
            setTypeface(null, Typeface.BOLD)
            setPadding(dpc(ctx, 8), dpc(ctx, 10), 0, dpc(ctx, 4))
        })
        col.addView(tv(ctx, "通过 agent socket 执行，支持 hookfunc/hookCPU/call 等" +
            " API，用法与 ImGui 端的 agent socket 一致。", 12f,
            0xFF999999.toInt()).apply {
            setPadding(dpc(ctx, 8), 0, dpc(ctx, 8), 0)
        })

        // 「选择脚本并执行」：输入路径 / 自绘文件浏览器两种方式选脚本，选中后直接执行。
        // 单独一行放在编辑框上方，避免和底部按钮挤在一起（键盘弹出时底部容易看不见）。
        col.addView(hrow(ctx).apply {
            setPadding(dpc(ctx, 8), dpc(ctx, 8), dpc(ctx, 8), 0)
            addView(btn(ctx, "选择脚本并执行") { openScriptDialog() },
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))

        editor = ClipboardEditText(ctx).apply {
            gravity = Gravity.TOP
            minLines = 12
            textSize = 13f
            typeface = Typeface.MONOSPACE
            setTextColor(0xFF222222.toInt())
            background = GradientDrawable().apply {
                setColor(0xFFF0F0F0.toInt())
                cornerRadius = dpc(ctx, 8).toFloat()
            }
            setPadding(dpc(ctx, 10), dpc(ctx, 8), dpc(ctx, 10), dpc(ctx, 8))
            setText(runCatching { scriptFile().readText() }.getOrDefault(
                "-- ATrace lua \n-- local base = getBase(\"libtarget.so\")\n"))
        }
        col.addView(ScrollView(ctx).apply { addView(editor) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f).apply {
                topMargin = dpc(ctx, 8)
            })
        val btns = hrow(ctx).apply { setPadding(dpc(ctx, 8), dpc(ctx, 6), dpc(ctx, 8), dpc(ctx, 8)) }
        btns.addView(btn(ctx, "保存草稿") {
            runCatching { scriptFile().writeText(editor.text.toString()) }
            m.toast("已保存")
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            marginEnd = dpc(ctx, 6)
        })
        luaResult = TextView(ctx).apply {
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextColor(0xFF444444.toInt())
            setTextIsSelectable(true)
            // 日志一行一条、不折行：超出宽度用横向滚动查看（原来是自动换行，
            setHorizontallyScrolling(true)
            setPadding(dpc(ctx, 8), dpc(ctx, 6), dpc(ctx, 8), dpc(ctx, 6))
            text = "（执行结果会显示在这里；日志单行显示，可左右滑动看长行）"
            // 长按结果区可复制输出（与脚本内容分开，两者都要能复制）。
            setOnLongClickListener {
                val t = text.toString()
                if (t.isNotEmpty() && t != "执行中…") {
                    copyText(ctx, t)
                    m.toast("已复制输出 ${t.length} 字符")
                }
                true
            }
        }
        luaHScroll = HorizontalScrollView(ctx).apply {
            isHorizontalScrollBarEnabled = true
            addView(luaResult, ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT))
        }
        luaScroll = ScrollView(ctx).apply {
            isVerticalScrollBarEnabled = true
            isFillViewport = true
            addView(luaHScroll, ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT))
        }

        // 输出面板：固定高度（约 170dp），内部竖向滚动；
        // 这样无论日志多少都不会把编辑框和按钮挤出屏幕。
        val logPanel = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            background = GradientDrawable().apply {
                setColor(0xFFF5F5F5.toInt())
                cornerRadius = dpc(ctx, 8).toFloat()
            }
            setPadding(dpc(ctx, 4), dpc(ctx, 4), dpc(ctx, 4), dpc(ctx, 4))
        }
        val logHeader = hrow(ctx).apply {
            addView(tv(ctx, "执行输出", 11f, 0xFF888888.toInt()).apply {
                setPadding(dpc(ctx, 6), 0, 0, 0)
            }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            addView(btn(ctx, "清空") {
                if (::luaResult.isInitialized) luaResult.text = ""
            }, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT))
        }
        logPanel.addView(logHeader, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))
        logPanel.addView(luaScroll, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        col.addView(logPanel, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dpc(ctx, 170)).apply {
            topMargin = dpc(ctx, 4)
        })

        // 复制脚本：优先复制选中的片段，没有选中就复制全文。
        btns.addView(btn(ctx, "复制") {
            val sel = editor.selectionStart.coerceAtLeast(0) to
                editor.selectionEnd.coerceAtLeast(0)
            val text = if (sel.first != sel.second)
                editor.text.substring(sel.first, sel.second)
            else editor.text.toString()
            if (text.isEmpty()) {
                m.toast("脚本为空")
            } else {
                copyText(ctx, text)
                m.toast("已复制 ${text.length} 字符")
            }
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
            marginEnd = dpc(ctx, 6)
        })
        btns.addView(btn(ctx, "执行") {
            runLua(editor.text.toString())
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        col.addView(btns)
        return col
    }

    private companion object {
        // 最近一次选择的脚本路径 / 浏览目录（持久化在 SharedPreferences("overlay")）
        const val KEY_LUA_PATH = "lua_script_path"
        const val KEY_LUA_DIR = "lua_script_dir"
        // Android 10 及以下请求 READ_EXTERNAL_STORAGE 的 requestCode
        const val REQ_STORAGE = 2001
        // 输出面板最多显示多少行 / 单行最长多少字符（避免日志无限膨胀）
        const val MAX_LOG_LINES = 300
        const val MAX_LOG_LINE_LEN = 1200
    }
}

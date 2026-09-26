package com.Alive.Trace.overlay

import android.annotation.SuppressLint
import android.app.Activity
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.ShapeDrawable
import android.graphics.drawable.shapes.OvalShape
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.Alive.Trace.R

/**
 * 原生 View 悬浮窗：可拖动气泡（应用图标）+ 全屏半透明白色面板。
 * 面板内含六个 Tab（选项/搜索/保存/内存/断点/脚本），
 * 所有"对话框"都在面板窗口内部实现（后台 Activity 的系统对话框
 * 不会显示在其他应用上层）。
 */
class OverlayManager(val act: Activity, private val onExit: () -> Unit) {

    private val wm get() = act.getSystemService(Activity.WINDOW_SERVICE) as WindowManager
    private val prefs = act.getSharedPreferences("overlay", Activity.MODE_PRIVATE)
    private val dp get() = act.resources.displayMetrics.density
    private val handler = Handler(Looper.getMainLooper())

    private var bubble: View? = null
    private var panel: View? = null
    private var expanded = false

    // 独立悬浮断点控件：每下一个断点就出现一个小按钮，
    // 显示断点 id，点击销毁并清除该断点。
    private val bpChips = mutableListOf<View>()
    private var bpChipSeq = 0

    var bubbleDp = prefs.getInt("bubble_dp", 52)
    var panelAlpha = prefs.getInt("panel_alpha", 88)  // 0..100
    private var bubbleX = prefs.getInt("bubble_x", 24)
    private var bubbleY = prefs.getInt("bubble_y", 220)

    private lateinit var panelRoot: FrameLayout
    private lateinit var content: FrameLayout
    private lateinit var dialogHost: FrameLayout
    private lateinit var statusTitle: TextView
    private lateinit var footer: TextView
    private lateinit var countView: TextView
    private val tabViews = HashMap<String, TextView>()
    private val pageCache = HashMap<String, View>()
    private var curTab = ""

    val tabs = listOf("选项", "搜索", "保存", "内存", "断点", "脚本")

    fun dp(v: Int): Int = (v * act.resources.displayMetrics.density).toInt()

    private val overlayType: Int
        get() = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        else
            @Suppress("DEPRECATION") WindowManager.LayoutParams.TYPE_PHONE

    // ── 生命周期 ────────────────────────────────────────────────────

    fun show() {
        tickStopped = false
        showBubble()
        tick()
    }

    fun hide() {
        tickStopped = true
        bubble?.let { runCatching { wm.removeView(it) } }
        bubble = null
        panel?.let { runCatching { wm.removeView(it) } }
        panel = null
        clearBpChips()
        expanded = false
        pageCache.clear()
    }

    fun exit() {
        hide()
        onExit()
    }

    private fun showBubble() {
        val size = dp(bubbleDp)
        val v = ImageView(act).apply {
            setImageResource(R.mipmap.ic_launcher)
            scaleType = ImageView.ScaleType.FIT_XY
            clipToOutline = true
            background = ShapeDrawable(OvalShape()).apply {
                paint.style = android.graphics.Paint.Style.STROKE
                paint.strokeWidth = dp(2).toFloat()
                paint.color = 0xCCFFFFFF.toInt()
            }
        }
        val lp = WindowManager.LayoutParams(
            size, size, overlayType,
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.LEFT
            x = bubbleX; y = bubbleY
        }
        installBubbleTouch(v, lp)
        wm.addView(v, lp)
        bubble = v
    }

    @SuppressLint("ClickableViewAccessibility")
    private fun installBubbleTouch(v: View, lp: WindowManager.LayoutParams) {
        var sx = 0f; var sy = 0f; var ox = 0; var oy = 0
        var moved = false
        v.setOnTouchListener { _, e ->
            when (e.actionMasked) {
                MotionEvent.ACTION_DOWN -> {
                    sx = e.rawX; sy = e.rawY; ox = lp.x; oy = lp.y; moved = false
                    true
                }
                MotionEvent.ACTION_MOVE -> {
                    val dx = (e.rawX - sx).toInt()
                    val dy = (e.rawY - sy).toInt()
                    if (!moved && (Math.abs(dx) > 8 || Math.abs(dy) > 8)) moved = true
                    if (moved) {
                        lp.x = ox + dx; lp.y = oy + dy
                        runCatching { wm.updateViewLayout(v, lp) }
                    }
                    true
                }
                MotionEvent.ACTION_UP -> {
                    bubbleX = lp.x; bubbleY = lp.y
                    prefs.edit().putInt("bubble_x", lp.x).putInt("bubble_y", lp.y).apply()
                    if (!moved) expand()
                    true
                }
                else -> false
            }
        }
    }

    // ── 展开面板 ────────────────────────────────────────────────────

    fun expand() {
        if (expanded) return
        bubble?.let { runCatching { wm.removeView(it) } }
        bubble = null
        expanded = true

        panelRoot = buildPanel()
        val lp = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            overlayType,
            WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply {
            softInputMode = WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE
        }
        panelRoot.isFocusableInTouchMode = true
        panelRoot.setOnKeyListener { _, kc, ev ->
            if (kc == KeyEvent.KEYCODE_BACK && ev.action == KeyEvent.ACTION_DOWN) {
                if (dialogHost.visibility == View.VISIBLE) dismissDialogs()
                else collapse()
                true
            } else false
        }
        wm.addView(panelRoot, lp)
        panel = panelRoot
        applyAlpha()
        switchTab(prefs.getString("last_tab", "选项") ?: "选项")
        // 未选择目标进程时，展开面板立即弹出进程选择，避免用户
        // 在搜索/内存页操作时才发现没有目标。
        if (OState.pid <= 0) {
            switchTab("选项")
            (pageObjs["选项"] as? OptionsPage)?.openProcessDialog()
        }
        // pageObjs 随面板重建而清空（页内临时状态存于 OState）。
    }

    fun collapse() {
        panel?.let { runCatching { wm.removeView(it) } }
        panel = null
        expanded = false
        showBubble()
    }

    // ── 面板 UI ─────────────────────────────────────────────────────

    private fun applyAlpha() {
        val col = panelRoot.findViewById<LinearLayout>(R.id.ov_panel_column)
        val a = (panelAlpha * 255 / 100)
        (col.background as? ColorDrawable)?.alpha = a
    }

    private fun buildPanel(): FrameLayout {
        val root = FrameLayout(act)

        val column = LinearLayout(act).apply {
            orientation = LinearLayout.VERTICAL
            id = R.id.ov_panel_column
            background = ColorDrawable(0xFFFFFFFF.toInt())
        }
        root.addView(column, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))

        // ── 头部：图标 + Tab + X ──
        val header = LinearLayout(act).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(8), dp(6), dp(8), dp(6))
        }
        header.addView(ImageView(act).apply {
            setImageResource(R.mipmap.ic_launcher)
            layoutParams = LinearLayout.LayoutParams(dp(30), dp(30)).apply {
                marginEnd = dp(6)
            }
        })
        val tabsScroll = HorizontalScrollView(act).apply {
            isHorizontalScrollBarEnabled = false
            layoutParams = LinearLayout.LayoutParams(0, dp(40), 1f)
        }
        val tabsRow = LinearLayout(act).apply { orientation = LinearLayout.HORIZONTAL }
        for (t in tabs) {
            val tv = TextView(act).apply {
                text = t
                textSize = 15f
                setPadding(dp(12), dp(8), dp(12), dp(8))
                setOnClickListener {
                prefs.edit().putString("last_tab", t).apply()
                switchTab(t)
            }
            }
            tabViews[t] = tv
            tabsRow.addView(tv)
        }
        tabsScroll.addView(tabsRow)
        header.addView(tabsScroll)
        header.addView(TextView(act).apply {
            text = "✕"
            textSize = 20f
            gravity = Gravity.CENTER
            setPadding(dp(10), dp(4), dp(10), dp(4))
            setOnClickListener { collapse() }
        })
        column.addView(header, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))

        // ── 状态行 ──
        val status = LinearLayout(act).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(10), dp(2), dp(10), dp(2))
        }
        statusTitle = TextView(act).apply {
            textSize = 13f
            setTextColor(0xFF333333.toInt())
            layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        status.addView(statusTitle)
        countView = TextView(act).apply {
            textSize = 13f
            setTextColor(0xFF1B8C3C.toInt())
        }
        status.addView(countView)
        column.addView(status, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))

        // ── 分割线 ──
        column.addView(View(act).apply { setBackgroundColor(0x22000000) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(1)))

        // ── 内容 ──
        content = FrameLayout(act)
        column.addView(content, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))

        // ── 底部状态 ──
        footer = TextView(act).apply {
            textSize = 12f
            setTextColor(0xFF777777.toInt())
            setPadding(dp(10), dp(3), dp(10), dp(8))
            text = "就绪"
        }
        column.addView(footer, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))

        dialogHost = FrameLayout(act).apply { visibility = View.GONE }
        root.addView(dialogHost, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        return root
    }

    fun switchTab(name: String) {
        curTab = name
        content.removeAllViews()
        val v = pageCache.getOrPut(name) { createPage(name) }
        (v.parent as? ViewGroup)?.removeView(v)
        content.addView(v, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        // 切换/打开页面时自动刷新对应页的状态（搜索结果数值/内存数值/保存列表）。
        when (name) {
            "搜索" -> (pageObjs[name] as? SearchPage)?.refresh()
            "内存" -> (pageObjs[name] as? MemoryPage)?.refresh()
            "保存" -> (pageObjs[name] as? SavedPage)?.refresh()
        }
        for ((t, tv) in tabViews) {
            val sel = t == name
            tv.setTextColor(if (sel) 0xFF1B8C3C.toInt() else 0xFF444444.toInt())
            tv.setTypeface(null, if (sel) Typeface.BOLD else Typeface.NORMAL)
            tv.setBackgroundColor(if (sel) 0x266ED957 else Color.TRANSPARENT)
        }
    }

    val pageObjs = HashMap<String, Any>()

    fun onSavedChanged() {
        onUi { (pageObjs["保存"] as? SavedPage)?.refresh() }
    }

    private fun createPage(name: String): View {
        val p = when (name) {
            "选项" -> OptionsPage(this)
            "搜索" -> SearchPage(this)
            "保存" -> SavedPage(this)
            "内存" -> MemoryPage(this)
            "断点" -> BpPage(this)
            else -> ScriptPage(this)
        }
        pageObjs[name] = p
        return p.build()
    }

    // ── 面板内对话框 ────────────────────────────────────────────────
    // 后台 Activity 的系统对话框不会显示在其他应用上层，
    // 因此所有对话框都实现为面板窗口内的覆盖视图。

    fun dialog(title: String, body: View,
               buttons: List<Triple<String, Boolean, () -> Unit>>) {
        dismissDialogs()
        val scrim = FrameLayout(act).apply {
            setBackgroundColor(0x66000000.toInt())
            isClickable = true
            setOnClickListener { dismissDialogs() }
        }
        val card = LinearLayout(act).apply {
            orientation = LinearLayout.VERTICAL
            background = GradientDrawable().apply {
                setColor(0xFFF7F7F7.toInt())
                cornerRadius = dp(12).toFloat()
            }
            setPadding(dp(16), dp(14), dp(16), dp(14))
        }
        card.addView(TextView(act).apply {
            text = title
            textSize = 16f
            setTextColor(0xFF222222.toInt())
            setTypeface(null, Typeface.BOLD)
        }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { bottomMargin = dp(10) })
        card.addView(body, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))

        if (buttons.isNotEmpty()) {
            val row = LinearLayout(act).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.END
            }
            for ((label, primary, action) in buttons) {
                row.addView(TextView(act).apply {
                    text = label
                    textSize = 15f
                    setTypeface(null, Typeface.BOLD)
                    setTextColor(if (primary) 0xFF1B8C3C.toInt() else 0xFF555555.toInt())
                    setPadding(dp(14), dp(10), dp(14), dp(2))
                    setOnClickListener {
                        dismissDialogs()
                        action()
                    }
                })
            }
            card.addView(row, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(8) })
        }
        // 对话框放进可滚动宿主并顶部对齐：悬浮窗窗口在键盘弹出时
        // 不一定 resize，顶部对齐保证输入框永远可见。
        card.layoutParams = FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            leftMargin = dp(16); rightMargin = dp(16)
            topMargin = dp(20); bottomMargin = dp(16)
        }
        val scroll = ScrollView(act).apply { addView(card) }
        scrim.addView(scroll, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        dialogHost.addView(scrim, FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        dialogHost.visibility = View.VISIBLE
    }

    fun dismissDialogs() {
        dialogHost.removeAllViews()
        dialogHost.visibility = View.GONE
    }

    fun anyDialogVisible() = dialogHost.visibility == View.VISIBLE

    // ── 设置 ────────────────────────────────────────────────────────

    fun setBubbleSize(dpSize: Int) {
        bubbleDp = dpSize
        prefs.edit().putInt("bubble_dp", dpSize).apply()
        if (!expanded) {
            bubble?.let { runCatching { wm.removeView(it) } }
            bubble = null
            showBubble()
        }
    }

    fun applyPanelAlpha(pct: Int) {
        panelAlpha = pct
        prefs.edit().putInt("panel_alpha", pct).apply()
        if (expanded) applyAlpha()
    }

    // ── 独立悬浮断点控件 ────────────────────────────────────────────
    // 下断后出现一个显示 "断点 <id>" 的小按钮；点击它即销毁该按钮
    // 并向断点服务下发 clear，停止该断点。
    fun addBpChip(addr: Long) {
        if (addr <= 0) return
        val id = ++bpChipSeq
        val chip = TextView(act).apply {
            text = "断点 $id"
            textSize = 12f
            setTextColor(0xFFFFFFFF.toInt())
            setPadding(dp(10), dp(6), dp(10), dp(6))
            background = GradientDrawable().apply {
                setColor(0xEED32F2F.toInt())
                cornerRadius = dp(14).toFloat()
            }
            isClickable = true
            isFocusable = true
            setOnClickListener {
                runCatching { NativeBridge.bpClear(addr) }
                runCatching { wm.removeView(this) }
                bpChips.remove(this)
                layoutBpChips()
                // 最后一个断点被关闭时，同步停止断点服务；命中结果保留。
                if (bpChips.isEmpty()) {
                    runCatching { NativeBridge.bpStop() }
                }
                (pageObjs["断点"] as? BpPage)?.onTick()
            }
        }
        val lp = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            overlayType,
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply { gravity = Gravity.TOP or Gravity.RIGHT }
        runCatching {
            wm.addView(chip, lp)
            bpChips.add(chip)
            layoutBpChips()
        }.onFailure { e ->
            runCatching { wm.removeView(chip) }
            toast("断点控件创建失败: ${e.message}")
        }
    }

    private fun layoutBpChips() {
        bpChips.forEachIndexed { i, v ->
            val lp = v.layoutParams as? WindowManager.LayoutParams ?: return@forEachIndexed
            lp.gravity = Gravity.TOP or Gravity.RIGHT
            lp.x = dp(8)
            lp.y = dp(96) + i * dp(44)
            runCatching { wm.updateViewLayout(v, lp) }
        }
    }

    fun clearBpChips() {
        for (v in bpChips.toList()) runCatching { wm.removeView(v) }
        bpChips.clear()
    }

    // ── 状态刷新 ────────────────────────────────────────────────────

    fun onUi(f: () -> Unit) {
        if (act.isFinishing || act.isDestroyed) return
        act.runOnUiThread(f)
    }

    fun toast(s: String) = onUi {
        Toast.makeText(act, s, Toast.LENGTH_SHORT).show()
    }

    fun setCount(text: String) = onUi { countView.text = text }

    fun setFooter(text: String) = onUi { footer.text = text }

    // 状态轮询：只在文本实际变化时 setText——全屏半透明窗口每次
    // 无效化都会触发整窗重绘（耗电），绝不能无条件刷。
    @Volatile private var tickStopped = false
    private var lastTitle = ""
    private var lastCountText = ""
    private var lastFooter = ""

    private fun tick() {
        if (tickStopped) return
        if (!expanded) {
            handler.postDelayed({ tick() }, 1000)
            return
        }
        // 目标进程退出（主动或被动）后自动重置整个悬浮窗状态。
        val alive = OState.pid <= 0 ||
            runCatching { NativeBridge.procAlive(OState.pid) }.getOrDefault(true)
        if (!alive) {
            resetForDeadProcess()
            handler.postDelayed({ tick() }, 1000)
            return
        }
        val title = "[${OState.pid}] ${OState.pname}"
        if (title != lastTitle) {
            statusTitle.text = title
            lastTitle = title
        }
        val n = runCatching { NativeBridge.searchCount() }.getOrDefault(0)
        runCatching {
            (pageObjs["断点"] as? BpPage)?.let { if (curTab == "断点") it.onTick() }
        }
        val nText = n.toString()
        if (nText != lastCountText) {
            countView.text = nText
            lastCountText = nText
        }
        val st = runCatching { NativeBridge.searchStatus() }.getOrDefault("")
        if (st != lastFooter) {
            footer.text = st
            lastFooter = st
        }
        (pageObjs["搜索"] as? SearchPage)?.let { if (curTab == "搜索") it.onTick() }
        (pageObjs["保存"] as? SavedPage)?.let { if (curTab == "保存") it.onTick() }
        handler.postDelayed({ tick() }, 1000)
    }

    /** 目标进程已死：停服务、清结果、清断点控件并重新选择进程。 */
    private fun resetForDeadProcess() {
        val dead = OState.pid
        runCatching { NativeBridge.bpStop() }
        runCatching { NativeBridge.bpClearHits() }
        runCatching { NativeBridge.searchReset() }
        Freezer.stopAll()
        synchronized(OState.saved) { OState.saved.clear() }
        clearBpChips()
        OState.pid = 0
        OState.pname = "-"
        OState.pkg = ""
        lastTitle = ""
        lastCountText = ""
        lastFooter = ""
        (pageObjs["保存"] as? SavedPage)?.refresh()
        setFooter("进程 $dead 已退出，已重置")
        switchTab("选项")
        (pageObjs["选项"] as? OptionsPage)?.openProcessDialog()
    }
}

package com.Alive.Trace.overlay

import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
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
import com.Alive.Trace.R
import java.io.File

// 
interface OverlayPage {
    fun build(): View
}

//   UI 

internal fun dpc(ctx: Context, v: Int) =
    (v * ctx.resources.displayMetrics.density).toInt()

private fun tv(ctx: Context, text: String = "", size: Float = 14f,
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

private fun edit(ctx: Context, hint: String): EditText =
    EditText(ctx).apply {
        this.hint = hint
        textSize = 14f
        setTextColor(0xFF222222.toInt())
        setHintTextColor(0xFF999999.toInt())
        isSingleLine = true
        background = GradientDrawable().apply {
            setColor(0xFFF0F0F0.toInt())
            cornerRadius = dpc(ctx, 6).toFloat()
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

//   

class OptionsPage(private val m: OverlayManager) : OverlayPage {

    private lateinit var procValue: TextView
    private lateinit var areaValue: TextView

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
            text = " PID / "
            setTextColor(0xFF888888.toInt())
        }) { injectDialog() })
        col.addView(optionRow(ctx, "杀死游戏进程", TextView(ctx).apply {
            text = "kill -9"
            setTextColor(0xFF888888.toInt())
        }) {
            if (OState.pid <= 0) { m.toast("请先选择进程"); return@optionRow }
            m.dialog(" [${OState.pid}] ${OState.pname}",
                vcol(ctx), listOf(
                    Triple("取消", false) {}, Triple("杀死", true) {
                        Thread { NativeBridge.killProcess(OState.pid) }.start()
                        m.toast(" kill")
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

        col.addView(section(ctx, "SO "))
        val soValue = TextView(ctx).apply {
            text = "退出悬浮窗"
            setTextColor(0xFF888888.toInt())
        }
        col.addView(optionRow(ctx, " agent (/hook)", soValue) { soDialog(soValue) })

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
            layoutParams = LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        })
        val valLabel = TextView(ctx).apply { text = "$init" }
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

    //   
    private fun processDialog() {
        val ctx = m.act
        val body = vcol(ctx)
        body.addView(tv(ctx, " root ", 12f,
            0xFF1B8C3C.toInt()).apply { setPadding(0, 0, 0, dpc(ctx, 4)) })
        val search = edit(ctx, " PID / ")
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
            data class Proc(val pid: String, val uid: String, val cmd: String,
                            val isPkg: Boolean, val name: String)
            val rows = rawText.split('\n').mapNotNull { l ->
                val f = l.split('|')
                if (f.size < 3) return@mapNotNull null
                val cmd = f[2]
                val isPkg = Regex("^[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z0-9_]+)+$")
                    .matches(cmd)
                val name = if (isPkg) runCatching {
                    pm.getApplicationLabel(
                        pm.getApplicationInfo(cmd, 0)).toString()
                }.getOrNull() ?: cmd.substringAfterLast('/') else cmd.substringAfterLast('/')
                Proc(f[0], f[1], cmd, isPkg, name)
            }.filter { p ->
                filter.isEmpty() || p.pid.contains(filter) ||
                    p.name.contains(filter, true) || p.cmd.contains(filter, true)
            }
            m.onUi {
                listHost.removeAllViews()
                for (p in rows.take(400)) {
                    val icon = if (p.isPkg) runCatching {
                        pm.getApplicationIcon(p.cmd)
                    }.getOrNull() ?: ctx.getDrawable(
                        android.R.drawable.sym_def_app_icon)
                    else ctx.getDrawable(android.R.drawable.sym_def_app_icon)
                    val row = hrow(ctx).apply {
                        setPadding(0, dpc(ctx, 6), 0, dpc(ctx, 6))
                        isClickable = true
                        setOnClickListener {
                            OState.pid = p.pid.toIntOrNull() ?: 0
                            OState.pname = p.name
                            procValue.text = "[${OState.pid}] ${p.name}"
                            m.dismissDialogs()
                            m.toast(": [${p.pid}] ${p.name}")
                        }
                    }
                    row.addView(ImageView(ctx).apply {
                        setImageDrawable(icon ?: ctx.getDrawable(R.mipmap.ic_launcher))
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
                        text = p.name
                        textSize = 14f
                        maxLines = 1
                        setTextColor(0xFF222222.toInt())
                    })
                    info.addView(TextView(ctx).apply {
                        text = "${p.pid} � ${p.cmd}"
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
                    listHost.addView(tv(ctx, " ( root )", 13f,
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

    //   
    private fun areasDialog() {
        val ctx = m.act
        val body = vcol(ctx)
        val boxes = mutableListOf<Pair<Int, CheckBox>>()
        for ((id, name) in Areas.list) {
            val cb = CheckBox(ctx).apply {
                text = name
                textSize = 14f
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
        m.dialog("输入要搜索的值", body, listOf(
            Triple("否", false) {},
            Triple("改善", true) {
                OState.areas.clear()
                for ((id, cb) in boxes) if (cb.isChecked) OState.areas.add(id)
                if (OState.areas.isEmpty()) OState.areas.add(Areas.ALL)
                areaValue.text = areaText()
                m.act.getSharedPreferences("overlay", Context.MODE_PRIVATE)
                    .edit().putString("areas", OState.areas.joinToString(",")).apply()
            }))
    }

    //   
    private fun injectDialog() {
        val ctx = m.act
        val body = vcol(ctx)
        body.addView(TextView(ctx).apply {
            text = ": [${OState.pid}] ${OState.pname}"
            textSize = 13f
            setTextColor(0xFF666666.toInt())
        })
        val resultTv = TextView(ctx).apply {
            textSize = 12f
            setTextColor(0xFF444444.toInt())
        }
        val byPid = btn(ctx, " (PID)") {
            if (OState.pid <= 0) { m.toast("请先选择进程"); return@btn }
            runInject(resultTv) { NativeBridge.injectPid(OState.pid) }
        }
        body.addView(byPid, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dpc(ctx, 8); bottomMargin = dpc(ctx, 10)
        })
        val pkg = edit(ctx, " ( com.xxx.yyy)")
        body.addView(pkg)
        val byPkg = btn(ctx, "按包名注入") {
            if (pkg.text.isBlank()) { m.toast("请输入包名"); return@btn }
            runInject(resultTv) { NativeBridge.injectPkg(pkg.text.toString().trim()) }
        }
        body.addView(resultTv, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })
        body.addView(byPkg, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 8) })
        m.dialog("注入 agent", body, listOf(Triple("关闭", true) {}))
    }

    private fun runInject(resultTv: TextView?, call: () -> String) {
        m.toast("注入中…")
        if (resultTv != null) resultTv.text = "注入中…"
        Thread {
            val out = runCatching { call() }.getOrDefault("注入失败")
            val ok = out.contains("Injection successful")
            val brief = if (ok) {
                val b = out.lineSequence().firstOrNull { it.contains("Base:") }
                "注入成功 " + (b?.substringAfter("Base:")?.trim() ?: "")
            } else out.lineSequence().lastOrNull { it.isNotBlank() }?.take(200)
                ?: ""
            m.onUi {
                m.toast(if (ok) "注入成功" else "注入失败")
                resultTv?.text = brief
                resultTv?.setTextColor(
                    if (ok) 0xFF1B8C3C.toInt() else 0xFFD32F2F.toInt())
            }
        }.start()
    }
    // SO  agent  socket/hook 
    private fun soDialog(soValue: TextView) {
        val ctx = m.act
        val body = vcol(ctx)
        val status = TextView(ctx).apply {
            text = runCatching { NativeBridge.socketStatus() }.getOrDefault("")
            textSize = 13f
            setTextColor(0xFF444444.toInt())
        }
        fun refreshStatus() {
            status.text = runCatching { NativeBridge.socketStatus() }.getOrDefault("")
            soValue.text = if (runCatching { NativeBridge.socketIsConnected() }
                .getOrDefault(false)) "已连接" else "未连接"
        }
        refreshStatus()
        body.addView(status)
        val btns = hrow(ctx)
        btns.addView(btn(ctx, "连接") {
            NativeBridge.socketSetTarget(OState.pname)
            NativeBridge.socketConnect()
            m.toast("连接中…")
            Thread { Thread.sleep(1200); m.onUi { refreshStatus() } }.start()
        }, LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginEnd = dpc(ctx, 6) })
        btns.addView(btn(ctx, "断开") {
            NativeBridge.socketDisconnect()
            Thread { Thread.sleep(400); m.onUi { refreshStatus() } }.start()
        }, LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        body.addView(btns, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 8) })
        m.dialog("SO 通道", body, listOf(Triple("关闭", true) { refreshStatus() }))
    }
}

//   

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

        progress.visibility = View.GONE
        progress.visibility = View.GONE
        col.addView(progress, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dpc(ctx, 6)))

        col.addView(divider(ctx), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dpc(ctx, 1)).apply {
            topMargin = dpc(ctx, 6)
        })
        col.addView(listHost, LinearLayout.LayoutParams(
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

    /** OverlayManager  500ms  */
    fun onTick() {
        val running = runCatching { NativeBridge.searchRunning() }.getOrDefault(false)
        progress.visibility = if (running) View.VISIBLE else View.GONE
        // awaitResult 
        if ((lastRunning && !running) || (awaitResult && !running)) {
            awaitResult = false
            refresh()
        }
        lastRunning = running
    }

    private fun refresh() {
        Thread {
            val totalNow = runCatching { NativeBridge.searchCount() }.getOrDefault(0)
            if (offset >= totalNow) offset = 0
            val text = runCatching {
                NativeBridge.searchPage(offset, pageSize)
            }.getOrDefault("")
            val list = text.split('\n').mapNotNull { l ->
                val f = l.split('|')
                if (f.size < 2) null
                else Pair(f[0].toLongOrNull(16) ?: return@mapNotNull null,
                    f[1].toLongOrNull(16) ?: 0L)
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
            val cb = CheckBox(ctx).apply {
                isChecked = checked.contains(addr)
                setOnCheckedChangeListener { _, c ->
                    if (c) checked.add(addr) else checked.remove(addr)
                }
            }
            row.addView(cb)
            val info = vcol(ctx).apply {
                layoutParams = LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                setOnClickListener { editHit(addr, raw) }
            }
            info.addView(hrow(ctx).apply {
                addView(tv(ctx, "%08X".format(addr), 14f, 0xFF1B8C3C.toInt(), true))
                addView(tv(ctx, "  ${MT.fmt(type, raw)}", 14f, 0xFF222222.toInt()).apply {
                    setTypeface(null, Typeface.BOLD)
                })
            })
            info.addView(hrow(ctx).apply {
                val hexWidth = MT.size(type) * 2
                addView(tv(ctx, "0x%0${hexWidth}X".format(raw) +
                    "  ${MT.name(type)}", 11f, 0xFF999999.toInt(), true))
            })
            row.addView(info)
            row.addView(tv(ctx, "删", 14f, 0xFFD32F2F.toInt()).apply {
                setPadding(dpc(ctx, 8), 0, dpc(ctx, 4), 0)
                setOnClickListener {
                    deleted.add(addr)
                    checked.remove(addr)
                    refresh()
                }
            })
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
        // 
        val keep = cur
        cur = emptyList()
        cur = keep
        renderRows()
    }

    private fun saveChecked() {
        if (checked.isEmpty()) { m.toast("请先勾选结果"); return }
        val type = OState.searchType
        var n = 0
        synchronized(OState.saved) {
            for ((addr, raw) in cur) {
                if (!checked.contains(addr)) continue
                if (OState.saved.any { it.addr == addr }) continue
                OState.saved.add(SavedRow(addr, type, "%08X".format(addr),
                    MT.fmt(type, raw), false))
                n++
            }
        }
        checked.clear()
        refreshRows()
        m.toast(" $n ")
        m.onSavedChanged()
    }

    private fun editHit(addr: Long, raw: Long) {
        val type = OState.searchType
            if (OState.pid <= 0) { m.toast("请先在选项页选择进程"); return }
        val ctx = m.act
        val body = vcol(ctx)
        val input = edit(ctx, MT.fmt(type, raw))
        input.setText(MT.fmt(type, raw))
        body.addView(input)
        m.dialog(" %08X  %s".format(addr, MT.name(type)), body, listOf(
            Triple("取消", false) {},
            Triple("是", true) {
                val bytes = MT.encode(type, input.text.toString())
                if (bytes == null) { m.toast("值格式错误"); return@Triple }
                Thread {
                    val ok = runCatching {
                        NativeBridge.memWrite(OState.pid, addr, bytes)
                    }.getOrDefault(false)
                    m.onUi {
                        m.toast(if (ok) "写入成功" else "写入失败")
                        if (ok) refresh()
                    }
                }.start()
            }))
    }

    //  
    private fun exactDialog() {
        if (requirePid()) return
        val ctx = m.act
        val body = vcol(ctx)
        val typeRow = hrow(ctx)
        typeRow.addView(tv(ctx, ":", 14f).apply {
            layoutParams = LinearLayout.LayoutParams(
                dpc(ctx, 52), ViewGroup.LayoutParams.WRAP_CONTENT)
        })
        val spinner = Spinner(ctx).apply {
            adapter = ArrayAdapter(ctx, android.R.layout.simple_spinner_dropdown_item,
                MT.all.map { "${MT.name(it)} [${MT.letter(it)}]" })
            setSelection(MT.all.indexOf(OState.searchType).coerceAtLeast(0))
        }
        typeRow.addView(spinner, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))
        body.addView(typeRow)
        val input = edit(ctx, " (100 / 0x64 / 10~20)")
        body.addView(input, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 8) })
        body.addView(tv(ctx, " / 0x /  10~20", 11f,
            0xFF999999.toInt()).apply { setPadding(0, dpc(ctx, 4), 0, 0) })

        m.dialog("模糊搜索", body, listOf(
            Triple("新搜索", false) {
                OState.searchType = MT.all[spinner.selectedItemPosition]
                offset = 0; deleted.clear(); checked.clear()
                NativeBridge.searchStart(OState.pid, OState.searchType,
                    input.text.toString().trim(), OState.areas.toIntArray())
                awaitResult = true
                m.toast("过滤中…")
            },
                Triple("取消", false) {},
                Triple("搜索", true) {
                NativeBridge.searchRefine(OState.searchType,
                    input.text.toString().trim())
                awaitResult = true
                        m.toast("过滤中…")
            }))
    }

    //   / 
    private fun fuzzyDialog(forceInit: Boolean = false) {
        if (requirePid()) return
        val hasResults = runCatching { NativeBridge.searchCount() }.getOrDefault(0) > 0
        if (hasResults && !forceInit) {
            // 
            val ctx = m.act
            val body = vcol(ctx)
            body.addView(tv(ctx, "?", 15f,
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
                    m.toast("模糊搜索初始化中…")
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
            // 
            val ctx = m.act
            val body = vcol(ctx)
            body.addView(tv(ctx, "选择要搜索的数据类型", 14f).apply {
                setPadding(0, 0, 0, dpc(ctx, 6))
            })
            val spinner = Spinner(ctx).apply {
                adapter = ArrayAdapter(ctx,
                    android.R.layout.simple_spinner_dropdown_item,
                    MT.all.map { "${MT.name(it)} [${MT.letter(it)}]" })
                setSelection(MT.all.indexOf(OState.searchType).coerceAtLeast(0))
            }
            body.addView(spinner)
        m.dialog("分配内存页", body, listOf(
            Triple("取消", false) {},
            Triple("是", true) {
                    OState.searchType = MT.all[spinner.selectedItemPosition]
                    offset = 0; deleted.clear(); checked.clear()
                    NativeBridge.fuzzyStart(OState.pid, OState.searchType,
                        OState.areas.toIntArray())
                    awaitResult = true
                            m.toast("已复制地址")
                }))
        }
    }

    private fun requirePid(): Boolean {
        if (OState.pid <= 0) { m.toast("请先在选项页选择进程"); return true }
        return false
    }
}

//   

class SavedPage(private val m: OverlayManager) : OverlayPage {

    private val listHost = LinearLayout(m.act).apply {
        orientation = LinearLayout.VERTICAL
    }

    override fun build(): View {
        val col = vcol(m.act)
        col.addView(TextView(m.act).apply {
            text = "点击条目可修改值或冻结"
            textSize = 12f
            setTextColor(0xFF999999.toInt())
            setPadding(dpc(m.act, 8), dpc(m.act, 4), 0, 0)
        })
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
            if (rows.isEmpty())
                listHost.addView(tv(ctx, "\"\"",
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
                val info = vcol(ctx).apply {
                    layoutParams = LinearLayout.LayoutParams(0,
                        ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                    setOnClickListener { editRow(r) }
                }
                info.addView(hrow(ctx).apply {
                    addView(tv(ctx, "%08X".format(r.addr), 14f,
                        0xFF1B8C3C.toInt(), true))
                    addView(tv(ctx, "  ${r.valueText}", 14f,
                        0xFF222222.toInt()).apply {
                        setTypeface(null, Typeface.BOLD)
                    })
                })
                info.addView(hrow(ctx).apply {
                    addView(tv(ctx, "${MT.name(r.type)}" +
                        if (r.frozen) "· 已冻结" else "", 11f,
                        if (r.frozen) 0xFF1B8C3C.toInt() else 0xFF999999.toInt()))
                })
                row.addView(info)
                row.addView(tv(ctx, "删", 14f, 0xFFD32F2F.toInt()).apply {
                    setPadding(dpc(ctx, 8), 0, dpc(ctx, 4), 0)
                    setOnClickListener {
                        synchronized(OState.saved) { OState.saved.remove(r) }
                        refresh()
                    }
                })
                listHost.addView(row)
                listHost.addView(divider(ctx), LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, dpc(ctx, 1)))
            }
            m.setCount(rows.count { it.frozen }.toString() + "/" + rows.size)
        }
    }

    private fun editRow(r: SavedRow) {
        val ctx = m.act
        val body = vcol(ctx)
        val input = edit(ctx, r.valueText).apply { setText(r.valueText) }
        body.addView(input)
        val freeze = CheckBox(ctx).apply {
            text = "暂无保存（在搜索页勾选后保存）"
            textSize = 14f
            isChecked = r.frozen
        }
        body.addView(freeze, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 8) })
        m.dialog(" %08X  %s".format(r.addr, MT.name(r.type)), body, listOf(
            Triple("否", false) {},
                        Triple("跳转", true) {
                r.valueText = input.text.toString()
                r.frozen = freeze.isChecked
                Freezer.ensureStarted()
                if (r.frozen) {
                    // 
                    val bytes = MT.encode(r.type, r.valueText)
                    if (bytes != null && OState.pid > 0)
                        Thread { NativeBridge.memWrite(OState.pid, r.addr, bytes) }.start()
                }
                refresh()
            }))
    }
}

//  

class MemoryPage(private val m: OverlayManager) : OverlayPage {

    private val ctx get() = m.act
    private val rowsN = 12
    private var base = 0x10000000L
    private var anchor = -1
    private val checkedAddrs = HashSet<Long>()
    private var muteChecks = false
    private lateinit var addrInput: EditText
    private lateinit var rangeInput: EditText
    private lateinit var pageLabel: TextView
    private data class Row(val cb: CheckBox, val addr: TextView, val hex: TextView,
                           val asc: TextView, val dv: TextView, val fv: TextView,
                           val root: LinearLayout)
    private val rows = mutableListOf<Row>()
    private val memDisasmViews = HashMap<Int, TextView>()

    override fun build(): View {
        val col = vcol(ctx)
        val nav = hrow(ctx).apply { setPadding(dpc(ctx, 8), dpc(ctx, 6), dpc(ctx, 8), 0) }
        addrInput = edit(ctx, " (hex)").apply {
            layoutParams = LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        }
        nav.addView(addrInput)
        nav.addView(btn(ctx, "跳转") {
            base = addrInput.text.toString().removePrefix("0x")
                .removePrefix("0X").toLongOrNull(16) ?: base
            refresh()
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dpc(ctx, 6) })
        nav.addView(btn(ctx, "◀") { base -= rowsN * 4; refresh() }.apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dpc(ctx, 6) }
        })
        nav.addView(btn(ctx, "▶") { base += rowsN * 4; refresh() }.apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dpc(ctx, 6) }
        })
        col.addView(nav)

        val range = hrow(ctx).apply {
            setPadding(dpc(ctx, 8), dpc(ctx, 6), dpc(ctx, 8), 0)
        }
        range.addView(tv(ctx, "范围", 13f))
        rangeInput = edit(ctx, "N / -N").apply {
            layoutParams = LinearLayout.LayoutParams(dpc(ctx, 70),
                ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                marginStart = dpc(ctx, 6)
            }
            isSingleLine = true
        }
        range.addView(rangeInput)
        range.addView(btn(ctx, "应用") { applyRange() }.apply {
            layoutParams = LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dpc(ctx, 6) }
        })
        range.addView(tv(ctx, " N ", 11f,
            0xFF999999.toInt()).apply {
            layoutParams = LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginStart = dpc(ctx, 6)
            }
        })
        col.addView(range)

        val act = hrow(ctx).apply { setPadding(dpc(ctx, 8), dpc(ctx, 6), dpc(ctx, 8), 0) }
        act.addView(btn(ctx, "刷新") { refresh() },
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

        col.addView(divider(ctx), LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dpc(ctx, 1)).apply {
            topMargin = dpc(ctx, 6)
        })

        val listHost = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }
        for (i in 0 until rowsN) {
            val cb = CheckBox(ctx)
            val addr = tv(ctx, "-", 14f, 0xFF1B8C3C.toInt(), true)
            val hex = tv(ctx, "-", 14f, 0xFF3465C8.toInt(), true)
            val asc = tv(ctx, "-", 13f, 0xFF888888.toInt())
            val dv = tv(ctx, "-", 13f, 0xFF0E7FA8.toInt(), true)
            val fv = tv(ctx, "-", 13f, 0xFF0E7FA8.toInt(), true)
            val l1 = hrow(ctx).apply {
                addView(addr, LinearLayout.LayoutParams(
                    dpc(ctx, 92), ViewGroup.LayoutParams.WRAP_CONTENT))
                addView(hex, LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                addView(asc)
            }
            val l2 = hrow(ctx).apply {
                addView(dv, LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                addView(fv, LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            }
            val dis = tv(ctx, "", 11f, 0xFF8E24AA.toInt(), true)
            val info = vcol(ctx).apply {
                layoutParams = LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
                setOnClickListener { editRow(i) }
                setOnLongClickListener {
                    val a = base + i * 4L
                    m.dialog("%08X".format(a), vcol(ctx).apply {
                        addView(tv(ctx, ": +$i (0x${(i * 4).toString(16)}))",
                            13f, 0xFF444444.toInt()))
                        addView(tv(ctx, "选择操作：", 12f, 0xFF999999.toInt()).apply {
                            setPadding(0, dpc(ctx, 6), 0, 0)
                        })
                    }, listOf(
            Triple("取消", false) {
                            val cb = ctx.getSystemService(Context.CLIPBOARD_SERVICE)
                                as android.content.ClipboardManager
                            cb.setPrimaryClip(android.content.ClipData.newPlainText(
                                "a", "0x%08X".format(a)))
                m.toast("分配中…")
                        },
                        Triple("复制地址", false) {
                            val b = runCatching {
                                NativeBridge.memRead(OState.pid, a, 4)
                            }.getOrNull() ?: ByteArray(4)
                            var v = 0L
                            for (k in 0 until 4) v = v or
                                (((b.getOrNull(k)?.toLong()?.and(0xFF)) ?: 0L) shl (8 * k))
                            val cb = ctx.getSystemService(Context.CLIPBOARD_SERVICE)
                                as android.content.ClipboardManager
                            cb.setPrimaryClip(android.content.ClipData.newPlainText(
                                "v", "%08X".format(v)))
                            m.toast("(hex)")
                        },
            Triple("分配", true) {
                            base = a
                            refresh()
                        }))
                    true
                }
            }
            info.addView(l1)
            info.addView(l2)
            info.addView(dis)
            memDisasmViews[i] = dis
            val root = hrow(ctx).apply {
                setPadding(dpc(ctx, 8), dpc(ctx, 3), dpc(ctx, 8), dpc(ctx, 3))
                addView(cb)
                addView(info)
                tag = i
            }
            cb.setOnCheckedChangeListener { _, c ->
                if (muteChecks) return@setOnCheckedChangeListener
                val a = base + i * 4L
                if (c) { checkedAddrs.add(a); anchor = i } else checkedAddrs.remove(a)
            }
            rows.add(Row(cb, addr, hex, asc, dv, fv, root))
            listHost.addView(root)
            listHost.addView(divider(ctx), LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dpc(ctx, 1)))
        }
        col.addView(ScrollView(ctx).apply { addView(listHost) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        refresh()
        return col
    }

    private fun applyRange() {
        val n = rangeInput.text.toString().toIntOrNull() ?: return
        if (anchor < 0) { m.toast("请先勾选起始行"); return }
        val idx = if (n >= 0) anchor until (anchor + n).coerceAtMost(rowsN)
        else (anchor + n + 1).coerceAtLeast(0)..anchor
        for (i in idx) rows[i].cb.isChecked = true
    }

    private fun saveChecked() {
        if (checkedAddrs.isEmpty()) { m.toast("请先勾选内存行"); return }
        val addrs = checkedAddrs.sorted()
        var n = 0
        Thread {
            synchronized(OState.saved) {
                for (addr in addrs) {
                    if (OState.saved.any { it.addr == addr }) continue
                    val raw = runCatching {
                        NativeBridge.memRead(OState.pid, addr, 4)
                    }.getOrNull() ?: ByteArray(4)
                    var rv = 0L
                    for (k in 0 until 4)
                        rv = rv or (((raw.getOrNull(k)?.toLong()?.and(0xFF))
                            ?: 0L) shl (8 * k))
                    OState.saved.add(SavedRow(addr, MT.DWORD, "%08X".format(addr),
                        MT.fmt(MT.DWORD, rv), false))
                    n++
                }
            }
            m.onUi {
                m.toast("已保存 $n 条")
                m.onSavedChanged()
            }
        }.start()
    }

    //  --alloc ptrace  mmap
    // 分配内存页：注入器 --alloc ptrace 远程 mmap。
    private fun allocDialog() {
        if (OState.pid <= 0) { m.toast("请先在选项页选择进程"); return }
        val ctx = m.act
        val body = vcol(ctx)
        val sizeInput = edit(ctx, "大小（字节，如 4096）")
        body.addView(sizeInput)
        val protRow = hrow(ctx)
        val boxes = mutableListOf<Pair<String, CheckBox>>()
        for (p in listOf("r", "w", "x")) {
            val cb = CheckBox(ctx).apply {
                text = p
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
                m.toast("已复制")
                Thread {
                    // SO agent  Lua FFI mmap
                    //  ptrace --alloc
                    val connected = runCatching { NativeBridge.socketIsConnected() }
                        .getOrDefault(false)
                    val out = if (connected) {
                        val pbits = prot.map { c ->
                            when (c) { 'r' -> 1; 'w' -> 2; else -> 4 }
                        }.fold(0) { a, b -> a or b }
                        val lua = "local ffi=require('ffi') " +
                            "ffi.cdef[[void* mmap(void*,unsigned long,int,int,int,long long)]] " +
                            "local p=ffi.C.mmap(nil,$size,$pbits,0x22,-1,0) " +
                            "print(string.format('ALLOC 0x%x',tonumber(ffi.cast('uintptr_t',p))))"
                        runCatching { NativeBridge.socketSendLua(lua) }
                            .getOrDefault("ERR:socket")
                        Thread.sleep(800)
                        runCatching { NativeBridge.socketLuaLogs() }.getOrDefault("")
                    } else {
                        runCatching {
                            NativeBridge.allocRemote(OState.pid, size, prot)
                        }.getOrDefault("ERR:")
                    }
                    val line = out.lineSequence()
                        .lastOrNull { it.contains("ALLOC 0x") } ?: ""
                    val addr = line.substringAfter("ALLOC 0x", "").trim()
                        .takeWhile { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
                    m.onUi {
                        if (addr.isNotEmpty()) allocDoneDialog("0x" + addr)
                        else m.toast("分配失败: " + out.take(80))
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
            setOnClickListener {
                val cb = ctx.getSystemService(Context.CLIPBOARD_SERVICE)
                    as android.content.ClipboardManager
                cb.setPrimaryClip(android.content.ClipData.newPlainText("a", addrText))
                m.toast("已复制")
            }
        })
        m.dialog("分配成功", body, listOf(
                        Triple("复制数值", false) {
                val cb = ctx.getSystemService(Context.CLIPBOARD_SERVICE)
                    as android.content.ClipboardManager
                cb.setPrimaryClip(android.content.ClipData.newPlainText("addr", addrText))
                m.toast("已复制")
            },
            Triple("是", true) {
                base = addrText.removePrefix("0x").removePrefix("0X")
                    .toLongOrNull(16) ?: base
                refresh()
            }))
    }

    private fun editRow(idx: Int) {
        if (OState.pid <= 0) { m.toast("请先在选项页选择进程"); return }
        val addr = base + idx * 4L
        val body = vcol(ctx)
        val typeSel = HorizontalScrollView(ctx).apply {
            isHorizontalScrollBarEnabled = false
        }
        val typeRow = hrow(ctx)
        var type = MT.DWORD
        val typeBtns = mutableListOf<Pair<Int, TextView>>()
        fun mark() {
            for ((t, b) in typeBtns)
                b.setBackgroundColor(
                    if (t == type) 0xFFC8E6C9.toInt() else 0xFFEFEFEF.toInt())
        }
        for (t in listOf(MT.DWORD, MT.FLOAT, MT.QWORD, MT.WORD, MT.BYTE,
                          MT.DOUBLE, MT.ASCII, MT.UTF16, -8)) {
            val b = btn(ctx, MT.letter(t)) { type = t; mark() }
            typeBtns.add(t to b)
            typeRow.addView(b, LinearLayout.LayoutParams(
                dpc(ctx, 44), ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                marginEnd = dpc(ctx, 4)
            })
        }
        mark()
        typeSel.addView(typeRow)
        body.addView(typeSel)
        val input = edit(ctx, "新值")
        body.addView(input, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 8) })
        mark()
        body.addView(tv(ctx, "A8 =  nop / ldr x0,[pc,#8]", 11f,
            0xFF999999.toInt()))
        m.dialog(" %08X ".format(addr), body, listOf(
            Triple("否", false) {},
            Triple("是", true) {
                if (type == -8) {
                    Thread {
                        val out = runCatching {
                            NativeBridge.asmWrite(OState.pid, addr,
                                input.text.toString().trim())
                        }.getOrDefault(": ")
                        m.onUi {
                            m.toast(out)
                            if (out.startsWith("OK")) refresh()
                        }
                    }.start()
                    return@Triple
                }
                val bytes = MT.encode(type, input.text.toString())
                if (bytes == null) { m.toast("值格式错误"); return@Triple }
                Thread {
                    val ok = runCatching {
                        NativeBridge.memWrite(OState.pid, addr, bytes)
                    }.getOrDefault(false)
                    m.onUi { m.toast(if (ok) "写入成功" else "写入失败"); if (ok) refresh() }
                }.start()
            }))
    }

    fun refresh() {
        if (OState.pid <= 0) {
            m.onUi {
                pageLabel.text = "未选择进程"
                rows.forEach { r ->
                    r.addr.text = "-"; r.hex.text = "-"
                    r.asc.text = ""; r.dv.text = "-"; r.fv.text = "-"
                }
            }
            return
        }
        Thread {
            val data = runCatching {
                NativeBridge.memRead(OState.pid, base, rowsN * 4)
            }.getOrNull() ?: ByteArray(rowsN * 4)
            m.onUi {
                pageLabel.text = "%08X - %08X".format(base, base + rowsN * 4 - 1)
                addrInput.setText("%08X".format(base))
                muteChecks = true
                for (i in 0 until rowsN)
                    rows[i].cb.isChecked = checkedAddrs.contains(base + i * 4L)
                muteChecks = false
                for (i in 0 until rowsN) {
                    val r = rows[i]
                    Thread {
                        val b = runCatching {
                            NativeBridge.memRead(OState.pid, base + i * 4L, 4)
                        }.getOrNull() ?: ByteArray(4)
                        val d = runCatching {
                            NativeBridge.memDisasm(b)
                        }.getOrDefault("")
                        m.onUi { runCatching { memDisasmViews[i]?.text = d } }
                    }.start()
                    val a = base + i * 4L
                    var w = 0L
                    for (k in 0 until 4)
                        w = w or ((data.getOrNull(i * 4 + k)?.toLong()?.and(0xFF))
                            ?: 0) shl (8 * k)
                    r.addr.text = "%08X".format(a)
                    r.hex.text = "%08X".format(w.toInt())
                    val c = (w.toInt() and 0xFF)
                    r.asc.text = if (c in 0x20..0x7E) "'${c.toChar()}'" else "'�'"
                    r.dv.text = "D: ${MT.fmt(MT.DWORD, w)}"
                    r.fv.text = "F: ${MT.fmt(MT.FLOAT, w)}"
                }
            }
        }.start()
    }
}

//  v1 + 

//  v1 + 

class ScriptPage(private val m: OverlayManager) : OverlayPage {
    private lateinit var editor: EditText

    private fun scriptFile(): File =
        File(m.act.filesDir, "scripts/last.lua").apply {
            parentFile?.mkdirs()
        }

    override fun build(): View {
        val ctx = m.act
        val col = vcol(ctx)
        col.addView(tv(ctx, "Lua ", 18f, 0xFF222222.toInt()).apply {
            setTypeface(null, Typeface.BOLD)
            setPadding(dpc(ctx, 8), dpc(ctx, 10), 0, dpc(ctx, 4))
        })
        col.addView(tv(ctx, " agent socket hookfunc/hookCPU/call" +
            "  API  agent  socket " +
            " ImGui ", 12f,
            0xFF999999.toInt()).apply {
            setPadding(dpc(ctx, 8), 0, dpc(ctx, 8), 0)
        })
        editor = EditText(ctx).apply {
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
        val luaResult = TextView(ctx).apply {
            textSize = 12f
            setTextColor(0xFF444444.toInt())
            setTextIsSelectable(true)
        }
        btns.addView(btn(ctx, "执行") {
            if (!runCatching { NativeBridge.socketIsConnected() }.getOrDefault(false)) {
                m.toast("请先在选项页连接 SO 通道")
                return@btn
            }
            luaResult.text = "执行中…"
            Thread {
                val out = runCatching {
                    NativeBridge.socketSendLua(editor.text.toString())
                }.getOrDefault("执行失败")
                m.onUi { luaResult.text = out.take(400) }
            }.start()
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        col.addView(luaResult, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 4) })
        col.addView(btns)
        return col
    }
}

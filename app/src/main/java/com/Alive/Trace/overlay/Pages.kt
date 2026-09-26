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

// ── 页面接口 ──
interface OverlayPage {
    fun build(): View
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

/**
 * 复制文本。Android 10+ 后台应用写剪贴板受限，这里只做一次
 * 尽力而为的直写，绝不启动前台 Activity（那会把用户从悬浮窗
 * 强制拉回应用界面）。调用方同时弹出可长按选择的文本兜底。
 */
internal fun copyText(ctx: Context, text: String) {
    if (text.isEmpty()) return
    // 兼容模式：部分 ROM 禁止后台应用写剪贴板，此时通过透明前台
    // Activity 写入（会极短暂切到应用，可在选项页开关）。
    val compat = runCatching {
        ctx.getSharedPreferences("overlay", Context.MODE_PRIVATE)
            .getBoolean("copy_compat", false)
    }.getOrDefault(false)
    if (compat) {
        runCatching {
            ctx.startActivity(
                android.content.Intent(ctx,
                    com.Alive.Trace.CopyActivity::class.java)
                    .putExtra(com.Alive.Trace.CopyActivity.EXTRA_TEXT, text)
                    .addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK))
        }
        return
    }
    runCatching {
        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE)
            as android.content.ClipboardManager
        cm.setPrimaryClip(android.content.ClipData.newPlainText("ATrace", text))
    }
}

/** 深色模式也可读的 Spinner：显式指定下拉与选中项文字颜色。 */
internal fun darkSpinner(ctx: Context, items: List<String>): Spinner =
    Spinner(ctx).apply {
        val color = 0xFF222222.toInt()
        adapter = object : ArrayAdapter<String>(
            ctx, android.R.layout.simple_spinner_dropdown_item, items) {
            override fun getView(position: Int, convertView: View?,
                                 parent: ViewGroup): View {
                val v = super.getView(position, convertView, parent) as TextView
                v.setTextColor(color)
                return v
            }
            override fun getDropDownView(position: Int, convertView: View?,
                                        parent: ViewGroup): View {
                val v = super.getDropDownView(position, convertView, parent)
                    as TextView
                v.setTextColor(color)
                return v
            }
        }
    }

/** 搜索/保存行长按菜单：复制地址、复制值、断点。 */
internal fun showRowMenu(m: OverlayManager, addr: Long, type: Int, raw: Long) {
    val ctx = m.act
    val body = vcol(ctx)
    body.addView(tv(ctx, "0x%08X  值: %s".format(addr, MT.fmt(type, raw)),
        13f, 0xFF444444.toInt()))
    m.dialog("0x%08X".format(addr), body, listOf(
        Triple("复制地址", false) {
            copyText(ctx, "0x%08X".format(addr))
            m.toast("已复制地址")
        },
        Triple("复制值", false) {
            val v = runCatching {
                val b = NativeBridge.memRead(OState.pid, addr, MT.size(type))
                if (b == null) MT.fmt(type, raw) else {
                    var r2 = 0L
                    for (k in 0 until b.size)
                        r2 = r2 or (((b.getOrNull(k)?.toLong()?.and(0xFF))
                            ?: 0L) shl (8 * k))
                    MT.fmt(type, r2)
                }
            }.getOrDefault(MT.fmt(type, raw))
            copyText(ctx, v)
            m.toast("已复制值")
        },
        Triple("跳转", false) { MemoryPage.jumpTo(m, addr) },
        Triple("断点", true) { bpDialog(m, addr) }))
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
                    m.addBpChip(addr)
                    m.toast("已下发断点，可用右上角悬浮按钮关闭")
                }
            }.start()
        }))
}

// ── 选项页 ──

class OptionsPage(private val m: OverlayManager) : OverlayPage {

    private lateinit var procValue: TextView
    private lateinit var areaValue: TextView
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
        val soValue = TextView(ctx).apply {
            text = "查看连接状态"
            setTextColor(0xFF888888.toInt())
        }
        col.addView(optionRow(ctx, "连接 agent (脚本/hook)", soValue) {
            soDialog(soValue) })

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
        val resultTv = TextView(ctx).apply {
            textSize = 12f
            setTextColor(0xFF444444.toInt())
        }
        val byPid = btn(ctx, " 当前进程注入") {
            if (OState.pid <= 0) { m.toast("请先选择进程"); return@btn }
            runInject(resultTv) { NativeBridge.injectPid(OState.pid) }
        }
        body.addView(byPid, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply {
            topMargin = dpc(ctx, 8); bottomMargin = dpc(ctx, 10)
        })
        val pkg = edit(ctx, "包名 (com.xxx.yyy)")
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
    // ── SO 通道：agent socket/hook 连接 ──
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
            NativeBridge.socketSetTarget(
                OState.pkg.ifEmpty { OState.pname })
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
        val type = OState.searchType
        var n = 0
        synchronized(OState.saved) {
            for ((addr, raw) in cur) {
                if (!checked.contains(addr)) continue
                if (OState.saved.any { it.addr == addr }) continue
                OState.saved.add(SavedRow(addr, type, MT.addr(addr),
                    MT.fmt(type, raw), false))
                n++
            }
        }
        checked.clear()
        refreshRows()
        m.toast("已保存 $n 条")
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
        m.dialog("修改 %08X  %s".format(addr, MT.name(type)), body, listOf(
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
        val body = vcol(ctx)
        val input = edit(ctx, r.valueText).apply { setText(r.valueText) }
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
                    val ok = runCatching {
                        NativeBridge.memWrite(OState.pid, r.addr, bytes)
                    }.getOrDefault(false)
                    m.onUi {
                        m.toast(if (ok) "写入成功" else "写入失败")
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
    }

    private val ctx get() = m.act
    private val rowsN = 12
    private var base = -1L
    private var anchor = -1
    private val checkedAddrs = HashSet<Long>()
    private var muteChecks = false
    private lateinit var addrInput: EditText
    private lateinit var rangeInput: EditText
    private lateinit var pageLabel: TextView
    private data class Row(val cb: CheckBox, val addr: TextView, val hex: TextView,
                           val asc: TextView, val dv: TextView, val fv: TextView,
                           val root: LinearLayout)
    private data class MemRow(val addr: Long, val ok: Boolean, val value: Long,
                              val disasm: String, val type: String)
    private val rows = mutableListOf<Row>()
    private val memDisasmViews = HashMap<Int, TextView>()

    override fun build(): View {
        val col = vcol(ctx)
        val nav = hrow(ctx).apply { setPadding(dpc(ctx, 8), dpc(ctx, 6), dpc(ctx, 8), 0) }
        addrInput = edit(ctx, "地址 (hex)").apply {
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
        range.addView(tv(ctx, " N 为行数（负数向上）", 11f,
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

        val act2 = hrow(ctx).apply { setPadding(dpc(ctx, 8), dpc(ctx, 4), dpc(ctx, 8), 0) }
        act2.addView(btn(ctx, "链接库") { libsDialog() },
            LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply {
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

        val listHost = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }
        for (i in 0 until rowsN) {
            val cb = CheckBox(ctx)
            val addr = tv(ctx, "-", 14f, 0xFF1B8C3C.toInt(), true)
            addr.setOnLongClickListener {
                showRowMenu(m, base + i * 4L, MT.DWORD, 0L)
                true
            }
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
                    showRowMenu(m, a, MT.DWORD, 0L)
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
                addView(tv(ctx, "复制", 12f, 0xFF1565C0.toInt()).apply {
                    setPadding(dpc(ctx, 4), 0, 0, 0)
                    setOnClickListener {
                        copyText(ctx, MT.addr(base + i * 4L))
                        m.toast("已复制地址")
                    }
                })
                tag = i
            }
            root.setOnLongClickListener {
                showRowMenu(m, base + i * 4L, MT.DWORD, 0L)
                true
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
                    OState.saved.add(SavedRow(addr, MT.DWORD, MT.addr(addr),
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

    // 跳转链接库：与 ImGui 一致，从 agent 拉取已加载库列表。
    private fun libsDialog() {
        val ctx = m.act
        val body = vcol(ctx)
        val status = tv(ctx, "准备连接 SO 通道…", 12f, 0xFF999999.toInt())
        body.addView(status)
        val list = vcol(ctx)
        body.addView(ScrollView(ctx).apply { addView(list) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                dpc(ctx, 260)).apply { topMargin = dpc(ctx, 6) })
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
            m.onUi {
                if (libs.isEmpty()) {
                    status.text = if (resp.startsWith("错误")) resp.take(200)
                                  else "未获取到链接库"
                    status.setTextColor(0xFFD32F2F.toInt())
                } else {
                    status.text = "共 ${libs.size} 个库，点击跳转"
                    status.setTextColor(0xFF999999.toInt())
                    list.removeAllViews()
                    for ((addr, name) in libs.take(200)) {
                        list.addView(tv(ctx,
                            MT.addr(addr) + "  " + name.substringAfterLast('/'),
                            13f, 0xFF1565C0.toInt(), true).apply {
                            setPadding(0, dpc(ctx, 6), 0, dpc(ctx, 6))
                            setOnClickListener { MemoryPage.jumpTo(m, addr) }
                        })
                    }
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
                    // 优先走 agent socket：注入后由 agent 在目标进程内
                    // mmap，地址直接回传；未连接时退化为注入器 --alloc。
                    val connected = runCatching { NativeBridge.socketIsConnected() }
                        .getOrDefault(false)
                    val out = if (connected) {
                        runCatching { NativeBridge.socketAlloc(size, prot) }
                            .getOrDefault("ERR:socket")
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
                        else m.dialog("分配失败", vcol(ctx).apply {
                            addView(tv(ctx, out.take(400), 12f,
                                0xFFD32F2F.toInt()).apply {
                                setTextIsSelectable(true)
                            })
                        }, listOf(Triple("关闭", true) {}))
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
        val input = edit(ctx, "新值 / ~A8 nop")
        body.addView(input, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 8) })
        mark()
        body.addView(tv(ctx, "输入 ~A8 nop 等可写汇编；其余按数值写入", 11f,
            0xFF999999.toInt()))
        m.dialog("修改 %08X ".format(addr), body, listOf(
            Triple("取消", false) {},
            Triple("写入", true) {
                val txt = input.text.toString().trim()
                if (type == -8 || txt.startsWith("~A8")) {
                    val asm = if (type == -8) txt else txt.removePrefix("~A8").trim()
                    if (asm.isEmpty()) { m.toast("汇编语句为空"); return@Triple }
                    Thread {
                        val out = runCatching {
                            NativeBridge.asmWrite(OState.pid, addr,
                                asm)
                        }.getOrDefault("错误: 执行失败")
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
            if (MemoryPage.pendingJump != 0L) {
                base = MemoryPage.pendingJump
                MemoryPage.pendingJump = 0
            }
            if (base < 0) {
                base = runCatching { NativeBridge.memFirstAddress(OState.pid) }
                    .getOrDefault(0L)
            }
            if (base <= 0) {
                m.onUi {
                    pageLabel.text = "无法定位可读内存"
                    rows.forEach { r ->
                        r.addr.text = "-"; r.hex.text = "失败"
                    }
                }
                return@Thread
            }
            base = base and -4L
            val text = runCatching {
                NativeBridge.memPage(OState.pid, base, rowsN)
            }.getOrDefault("")
            val rowsNow = text.split('\n').mapNotNull { l ->
                val f = l.split('|')
                if (f.size < 5) null
                else MemRow(MT.parseHex(f[0]) ?: 0L, f[1] == "1",
                    MT.parseHex(f[2]) ?: 0L, f[3], f[4])
            }
            m.onUi {
                if (rowsNow.size != rowsN) {
                    pageLabel.text = "读取失败 %08X".format(base)
                    addrInput.setText(MT.addr(base))
                    for (i in 0 until rowsN) {
                        val r = rows[i]
                        r.addr.text = MT.addr(base + i * 4L)
                        r.hex.text = "读取失败"
                        r.asc.text = ""
                        r.dv.text = ""
                        r.fv.text = ""
                        memDisasmViews[i]?.text = ""
                    }
                    return@onUi
                }
                pageLabel.text = "%08X - %08X".format(base, base + rowsN * 4 - 1)
                addrInput.setText("%08X".format(base))
                muteChecks = true
                for (i in 0 until rowsN)
                    rows[i].cb.isChecked = checkedAddrs.contains(base + i * 4L)
                muteChecks = false
                for (i in 0 until rowsN) {
                    val r = rows[i]
                    val row = rowsNow.getOrNull(i)
                    val a = base + i * 4L
                    r.addr.text = MT.addr(a)
                    if (row == null || !row.ok) {
                        r.hex.text = "读取失败"
                        r.asc.text = ""
                        r.dv.text = ""
                        r.fv.text = ""
                        memDisasmViews[i]?.text = ""
                    } else {
                        val w = row.value
                        r.hex.text = "%08X".format(w.toInt())
                        val c = (w.toInt() and 0xFF)
                        r.asc.text = if (c in 0x20..0x7E) "'${c.toChar()}'" else "'."
                        r.dv.text = "D: ${w and 0xFFFFFFFFL}"
                        r.fv.text = "F: ${MT.fmt(MT.FLOAT, w)}"
                        memDisasmViews[i]?.text =
                            if (row.disasm.isNotEmpty()) row.disasm + "  " + row.type
                            else row.type
                    }
                }
            }
        }.start()
    }
}

// ── 脚本页（Lua 脚本编辑与执行）──

class ScriptPage(private val m: OverlayManager) : OverlayPage {
    private lateinit var editor: EditText

    private fun scriptFile(): File =
        File(m.act.filesDir, "scripts/last.lua").apply {
            parentFile?.mkdirs()
        }

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
                var out = runCatching {
                    NativeBridge.socketSendLua(editor.text.toString())
                }.getOrDefault("发送失败")
                Thread.sleep(1200)
                val logs = runCatching {
                    NativeBridge.socketLuaLogs()
                }.getOrDefault("")
                // 首行为日志总数，其余才是 print 等新增日志。
                val logText = logs.lineSequence().drop(1)
                    .filter { it.isNotBlank() }.joinToString("\n")
                if (logText.isNotBlank()) out = out.trim() + "\n" + logText
                m.onUi {
                    luaResult.text = out.take(2000)
                    luaResult.setTextIsSelectable(true)
                }
            }.start()
        }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        col.addView(luaResult, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 4) })
        col.addView(btns)
        return col
    }
}

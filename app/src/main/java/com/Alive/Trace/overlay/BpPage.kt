package com.Alive.Trace.overlay

import android.graphics.Typeface
import android.view.View
import android.view.Gravity
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView

/** 断点页：root 硬件断点服务（perf_event_open + 管道）的完整客户端。 */
class BpPage(private val m: OverlayManager) : OverlayPage {

    private val ctx get() = m.act
    private lateinit var statusTv: TextView
    private lateinit var hitsTv: TextView
    private lateinit var addrInput: EditText
    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    private var lastHits = ""
    private var watching = false

    override fun build(): View {
        val col = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpc(ctx, 8), dpc(ctx, 8), dpc(ctx, 8), dpc(ctx, 4))
        }

        col.addView(TextView(ctx).apply {
            text = "硬件断点"
            textSize = 18f
            setTextColor(0xFF222222.toInt())
            typeface = Typeface.DEFAULT_BOLD
        })
        statusTv = TextView(ctx).apply {
            text = "服务未启动"
            textSize = 13f
            setTextColor(0xFF666666.toInt())
        }
        col.addView(statusTv, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 4) })

        val ctl = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, dpc(ctx, 6), 0, 0)
        }
        ctl.addView(bn("启动服务") {
            if (OState.pid <= 0) { m.toast("请先选择进程"); return@bn }
            Thread { NativeBridge.bpStart(OState.pid); m.onUi { refresh() } }.start()
        }, LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginEnd = dpc(ctx, 6) })
        ctl.addView(bn("停止服务") {
            Thread { NativeBridge.bpStop(); m.onUi { refresh() } }.start()
        }, LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        col.addView(ctl, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))

        val addrRow = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dpc(ctx, 8), 0, 0)
        }
        addrInput = EditText(ctx).apply {
            hint = "地址 (hex)"
            textSize = 14f
            isSingleLine = true
        }
        addrInput.layoutParams = LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        addrRow.addView(addrInput)
        val typeSpin = Spinner(ctx).apply {
            adapter = ArrayAdapter(ctx, android.R.layout.simple_spinner_dropdown_item,
                listOf("执行 x", "读 r", "写 w", "读写 rw"))
        }
        addrRow.addView(typeSpin, LinearLayout.LayoutParams(
            dpc(ctx, 96), ViewGroup.LayoutParams.WRAP_CONTENT))
        val lenSpin = Spinner(ctx).apply {
            adapter = ArrayAdapter(ctx, android.R.layout.simple_spinner_dropdown_item,
                listOf("1", "2", "4", "8"))
            setSelection(2)
        }
        addrRow.addView(lenSpin, LinearLayout.LayoutParams(
            dpc(ctx, 60), ViewGroup.LayoutParams.WRAP_CONTENT))
        col.addView(addrRow)

        col.addView(bn("添加断点") {
            val a = addrInput.text.toString().removePrefix("0x")
                .removePrefix("0X").toLongOrNull(16)
            if (a == null || a <= 0) { m.toast("地址无效"); return@bn }
            val types = listOf("x", "r", "w", "rw")
            val len = when (lenSpin.selectedItemPosition) {
                0 -> 1; 1 -> 2; 3 -> 8; else -> 4
            }
            NativeBridge.bpSet(a, types[typeSpin.selectedItemPosition], len)
            m.toast("已下发断点")
        }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })

        val clr = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dpc(ctx, 6), 0, 0)
        }
        val clrInput = EditText(ctx).apply {
            hint = "要清除的地址 (hex)"
            textSize = 14f
            isSingleLine = true
        }
        clrInput.layoutParams = LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
        clr.addView(clrInput)
        clr.addView(bn("清除") {
            val a = clrInput.text.toString().removePrefix("0x").toLongOrNull(16)
            if (a != null && a > 0) NativeBridge.bpClear(a)
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dpc(ctx, 6) })
        clr.addView(bn("清空命中") {
            NativeBridge.bpClearHits()
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dpc(ctx, 6) })
        col.addView(clr)

        col.addView(TextView(ctx).apply {
            text = "命中记录"
            textSize = 13f
            setTextColor(0xFF1B8C3C.toInt())
            setPadding(0, dpc(ctx, 10), 0, dpc(ctx, 2))
        })
        hitsTv = TextView(ctx).apply {
            text = "暂无命中"
            textSize = 12f
            setTextColor(0xFF444444.toInt())
            typeface = Typeface.MONOSPACE
        }
        col.addView(ScrollView(ctx).apply { addView(hitsTv) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))

        refresh()
        startWatch()
        return col
    }

    private fun bn(text: String, onClick: () -> Unit): TextView =
        TextView(ctx).apply {
            this.text = text
            textSize = 14f
            setTextColor(0xFF1B5E20.toInt())
            gravity = Gravity.CENTER
            background = android.graphics.drawable.GradientDrawable().apply {
                setColor(0xFFE8F5E9.toInt())
                cornerRadius = dpc(ctx, 8).toFloat()
            }
            setPadding(dpc(ctx, 12), dpc(ctx, 7), dpc(ctx, 12), dpc(ctx, 7))
            isClickable = true
            setOnClickListener { onClick() }
        }

    private fun refresh() {
        statusTv.text = (if (runCatching { NativeBridge.bpIsRunning() }
            .getOrDefault(false)) "服务运行中 (pid=" + OState.pid + ")"
            else "服务未启动") + " · " +
            runCatching { NativeBridge.bpStatus() }.getOrDefault("")
    }

    /** OverlayManager 每秒轮询：刷新命中列表。 */
    fun onTick() {
        val hits = runCatching { NativeBridge.bpHits(20) }.getOrDefault("")
        if (hits != lastHits) {
            lastHits = hits
            hitsTv.text = if (hits.isBlank()) "暂无命中"
            else hits.split("\n").filter { it.isNotBlank() }.joinToString("\n") { l ->
                val f = l.split("|")
                if (f.size >= 4)
                    "PC %08X  TID %s\n  命中 %s  %s".format(
                        f[0].toLongOrNull(16) ?: 0L, f[1], f[2], f[3])
                else l
            }
        }
        refresh()
    }

    private fun startWatch() {
        if (watching) return
        watching = true
        handler.post(object : Runnable {
            override fun run() {
                if (!watching) return
                onTick()
                handler.postDelayed(this, 700)
            }
        })
    }
}

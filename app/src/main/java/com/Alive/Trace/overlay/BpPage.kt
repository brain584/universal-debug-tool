package com.Alive.Trace.overlay

import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.EditText
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/** 断点页：root 硬件断点服务（perf_event_open + 管道）的完整客户端。 */
class BpPage(private val m: OverlayManager) : OverlayPage {

    private val ctx get() = m.act
    private lateinit var statusTv: TextView
    private lateinit var addrInput: EditText
    private lateinit var hitsHost: LinearLayout
    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    private var lastHits = ""
    private var watching = false
    @Volatile private var tickBusy = false
    private var selectedKey = ""

    private data class Hit(
        val addr: Long, val pc: Long, val tid: String, val disasm: String,
        val sp: Long, val stack: List<Long>, val regs: List<Pair<String, String>>,
        val counter: Int, val region: String, val module: String,
        val bpt: Int, val blen: Int)

    private fun bpTypeLetter(t: Int): String = when (t) {
        1 -> "r"; 2 -> "w"; 3 -> "rw"; 4 -> "x"; else -> "?"
    }

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
            Thread {
                runCatching { NativeBridge.bpStart(OState.pid) }
                m.onUi { refresh() }
            }.start()
        }, LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginEnd = dpc(ctx, 6) })
        // 再用 150ms 存活检查判成败；命令形式一旦被多套 shell 就会"秒退且报错被吞"。
        // 这个按钮用 App 内真实方式跑一遍，直接告诉你哪种形式可用。
        ctl.addView(bn("启动自检") {
            m.toast("自检中…")
            Thread {
                val r = runCatching { NativeBridge.spawnDiag() }
                    .getOrDefault("自检失败（native 调用异常）")
                m.onUi {
                    val body = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }
                    val tv = TextView(ctx).apply {
                        text = r
                        textSize = 12f
                        setTextColor(if (r.contains("✓")) 0xFF1B8C3C.toInt()
                                      else 0xFFD32F2F.toInt())
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
                    m.dialog("断点服务启动自检", body, listOf(Triple("关闭", true) {}))
                }
            }.start()
        }, LinearLayout.LayoutParams(0,
            ViewGroup.LayoutParams.WRAP_CONTENT, 1f).apply { marginEnd = dpc(ctx, 6) })
        ctl.addView(bn("停止服务") {
            Thread {
                runCatching { NativeBridge.bpStop() }
                // 停止服务不清空命中结果（保留现场，便于继续查看）。
                m.onUi {
                    m.clearBpChips()
                    refresh()
                }
            }.start()
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
        // 统一的输入框样式：圆角浅灰底 + 细边框，和 darkSpinner 保持一致
        fun fieldBg() = android.graphics.drawable.GradientDrawable().apply {
            setColor(0xFFF0F0F0.toInt())
            cornerRadius = dpc(ctx, 6).toFloat()
            setStroke(dpc(ctx, 1), 0xFFDDDDDD.toInt())
        }
        val fieldH = dpc(ctx, 44)
        addrInput = ClipboardEditText(ctx).apply {
            hint = "地址 (hex)"
            textSize = 14f
            isSingleLine = true
            setTextColor(0xFF222222.toInt())
            setHintTextColor(0xFF999999.toInt())
            background = fieldBg()
            setPadding(dpc(ctx, 10), 0, dpc(ctx, 10), 0)
            gravity = Gravity.CENTER_VERTICAL
        }
        addrInput.layoutParams = LinearLayout.LayoutParams(0, fieldH, 1f)
        addrRow.addView(addrInput)
        // 类型/长度：与输入框同高、同圆角；宽度按"最短可读"分配（之前 132/92dp 太大像灰块）
        val typeSpin = darkSpinner(ctx,
            listOf("x 执行", "r 读", "w 写", "rw 读写"))
        typeSpin.layoutParams = LinearLayout.LayoutParams(
            dpc(ctx, 108), fieldH).apply { marginStart = dpc(ctx, 6) }
        addrRow.addView(typeSpin)
        val lenSpin = darkSpinner(ctx, listOf("1 字节", "2 字节", "4 字节", "8 字节")).apply {
            setSelection(2)
        }
        lenSpin.layoutParams = LinearLayout.LayoutParams(
            dpc(ctx, 84), fieldH).apply { marginStart = dpc(ctx, 6) }
        addrRow.addView(lenSpin)
        col.addView(addrRow)

        col.addView(bn("添加断点") {
            val a = MT.parseHex(addrInput.text.toString())
            if (a == null || a <= 0) { m.toast("地址无效"); return@bn }
            val types = listOf("x", "r", "w", "rw")
            val len = when (lenSpin.selectedItemPosition) {
                0 -> 1; 1 -> 2; 3 -> 8; else -> 4
            }
            val type = types[typeSpin.selectedItemPosition]
            BpUi.onTargetChanged(OState.pid)
            runCatching { NativeBridge.bpSet(a, type, len) }
            m.addBpChip(a, type, len)
            m.toast("已下发断点，可用右上角悬浮按钮关闭")
        }, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })

        val clr = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, dpc(ctx, 6), 0, 0)
        }
        val clrInput = ClipboardEditText(ctx).apply {
            hint = "要清除的地址 (hex)"
            textSize = 14f
            isSingleLine = true
            setTextColor(0xFF222222.toInt())
            setHintTextColor(0xFF999999.toInt())
            background = android.graphics.drawable.GradientDrawable().apply {
                setColor(0xFFF0F0F0.toInt())
                cornerRadius = dpc(ctx, 6).toFloat()
                setStroke(dpc(ctx, 1), 0xFFDDDDDD.toInt())
            }
            setPadding(dpc(ctx, 10), 0, dpc(ctx, 10), 0)
            gravity = Gravity.CENTER_VERTICAL
        }
        clrInput.layoutParams = LinearLayout.LayoutParams(0, dpc(ctx, 44), 1f)
        clr.addView(clrInput)
        clr.addView(bn("清除") {
            val a = MT.parseHex(clrInput.text.toString())
            if (a != null && a > 0)
                runCatching { NativeBridge.bpClear(a) }
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dpc(ctx, 6) })
        clr.addView(bn("清空命中") {
            runCatching { NativeBridge.bpClearHits() }
            lastHits = ""
            renderHits("")
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { marginStart = dpc(ctx, 6) })
        col.addView(clr)

        col.addView(TextView(ctx).apply {
            text = "命中记录（点击 PC/寄存器/栈地址跳转内存）"
            textSize = 13f
            setTextColor(0xFF1B8C3C.toInt())
            setPadding(0, dpc(ctx, 10), 0, dpc(ctx, 2))
        })
        hitsHost = LinearLayout(ctx).apply { orientation = LinearLayout.VERTICAL }
        col.addView(ScrollView(ctx).apply { addView(hitsHost) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))

        refresh()
        m.syncBpChips()
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

    private fun clickableAddr(text: String, addr: Long): TextView =
        TextView(ctx).apply {
            this.text = text
            textSize = 12f
            setTextColor(0xFF1565C0.toInt())
            typeface = Typeface.MONOSPACE
            setPadding(0, dpc(ctx, 3), 0, dpc(ctx, 3))
            setOnClickListener { MemoryPage.jumpTo(m, addr) }
        }

    private fun refresh() {
        val running = runCatching { NativeBridge.bpIsRunning() }
            .getOrDefault(false)
        val st = runCatching { NativeBridge.bpStatus() }.getOrDefault("")
        applyStatus(running, st)
    }

    private fun parseHit(l: String): Hit? {
        val f = l.split('|')
        if (f.size < 7) return null
        val stack = f[5].split('>').mapNotNull { MT.parseHex(it) }
        // 寄存器保留原始十六进制串显示（避免任何解析/格式化导致显示 0）。
        val regs = f[6].split(',').mapNotNull { r ->
            val kv = r.split('=')
            if (kv.size == 2)
                Pair(kv[0],
                    kv[1].removePrefix("0x").removePrefix("0X").toUpperCase())
            else null
        }
        return Hit(
            addr = MT.parseHex(f[2]) ?: 0L,
            pc = MT.parseHex(f[0]) ?: 0L,
            tid = f[1], disasm = f[3], sp = MT.parseHex(f[4]) ?: 0L,
            stack = stack, regs = regs,
            counter = f.getOrNull(7)?.toIntOrNull() ?: 0,
            region = f.getOrNull(8) ?: "",
            module = f.getOrNull(9) ?: "",
            bpt = f.getOrNull(10)?.toIntOrNull() ?: 0,
            blen = f.getOrNull(11)?.toIntOrNull() ?: 0)
    }

    // 只有"完全相同的断点"（地址 + 类型 + 长度）的结果才归为一组并堆叠；
    // 顶部横向拉条列出各断点，点选后把该断点的所有命中横向展开。
    private fun renderHits(raw: String) {
        hitsHost.removeAllViews()
        val hits = raw.split('\n').filter { it.isNotBlank() }
            .mapNotNull { parseHit(it) }
        if (hits.isEmpty()) {
            hitsHost.addView(tv(ctx, "暂无命中", 13f, 0xFF999999.toInt()))
            return
        }
        val groups = LinkedHashMap<String, MutableList<Hit>>()
        for (h in hits) {
            val k = "%X|%d|%d".format(h.addr, h.bpt, h.blen)
            groups.getOrPut(k) { mutableListOf() }.add(h)
        }
        if (selectedKey !in groups) selectedKey = groups.keys.first()

        // 顶部横向拉条：每个断点一个标签。
        val bar = LinearLayout(ctx).apply { orientation = LinearLayout.HORIZONTAL }
        for ((k, list) in groups) {
            val s = list.first()
            val sel = k == selectedKey
            val b = TextView(ctx).apply {
                text = "%X %s ×%d".format(s.addr, bpTypeLetter(s.bpt), list.size)
                textSize = 13f
                typeface = Typeface.MONOSPACE
                setTextColor(if (sel) 0xFF1B5E20.toInt() else 0xFF444444.toInt())
                background = GradientDrawable().apply {
                    setColor(if (sel) 0xFFC8E6C9.toInt()
                              else 0xFFEFEFEF.toInt())
                    cornerRadius = dpc(ctx, 8).toFloat()
                }
                setPadding(dpc(ctx, 12), dpc(ctx, 6), dpc(ctx, 12), dpc(ctx, 6))
                isClickable = true
                setOnClickListener { selectedKey = k; renderHits(raw) }
            }
            bar.addView(b, LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                marginEnd = dpc(ctx, 6)
            })
        }
        hitsHost.addView(HorizontalScrollView(ctx).apply {
            isHorizontalScrollBarEnabled = true
            addView(bar)
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))

        // 展开：选中断点的所有命中横向排列，左右滑动查看堆叠结果。
        val selList = groups[selectedKey] ?: return
        val row = LinearLayout(ctx).apply { orientation = LinearLayout.HORIZONTAL }
        for (h in selList) {
            row.addView(buildCard(h), LinearLayout.LayoutParams(
                dpc(ctx, 320), ViewGroup.LayoutParams.WRAP_CONTENT).apply {
                marginEnd = dpc(ctx, 8)
            })
        }
        hitsHost.addView(HorizontalScrollView(ctx).apply {
            isHorizontalScrollBarEnabled = true
            addView(row)
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = dpc(ctx, 6) })
    }

    private fun buildCard(h: Hit): View {
        val card = LinearLayout(ctx).apply {
            orientation = LinearLayout.VERTICAL
            background = GradientDrawable().apply {
                setColor(0x0D000000)
                cornerRadius = dpc(ctx, 8).toFloat()
                setStroke(dpc(ctx, 1), 0x22000000)
            }
            setPadding(dpc(ctx, 8), dpc(ctx, 6), dpc(ctx, 8), dpc(ctx, 8))
        }
        // 大号 PC（点击跳转内存页）。
        card.addView(TextView(ctx).apply {
            text = "%X".format(h.pc)
            textSize = 18f
            setTextColor(0xFF2E7D32.toInt())
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            setPadding(0, dpc(ctx, 2), 0, dpc(ctx, 2))
            setOnClickListener { MemoryPage.jumpTo(m, h.pc) }
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))

        // 区域 / 模块。
        val meta = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        if (h.region.isNotEmpty())
            meta.addView(tv(ctx, h.region, 13f,
                0xFF1B8C3C.toInt(), true).apply {
                setPadding(0, 0, dpc(ctx, 8), 0)
            })
        if (h.module.isNotEmpty())
            meta.addView(tv(ctx, h.module, 12f, 0xFF6A1B9A.toInt()))
        card.addView(meta, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.WRAP_CONTENT))
        if (h.disasm.isNotEmpty())
            card.addView(tv(ctx, h.disasm, 12f, 0xFF8E24AA.toInt(), true))
        card.addView(LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(tv(ctx, "命中 ", 11f, 0xFF999999.toInt()))
            addView(clickableAddr("%X".format(h.addr), h.addr))
            addView(tv(ctx, "  TID ${h.tid}", 11f, 0xFF999999.toInt()))
            addView(View(ctx), LinearLayout.LayoutParams(0, 1, 1f))
            if (h.counter > 0)
                addView(tv(ctx, "#${h.counter}", 12f, 0xFF666666.toInt()))
        })

        // 寄存器：每行 4 个。
        for (chunk in h.regs.chunked(4)) {
            val rr = LinearLayout(ctx).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(0, dpc(ctx, 1), 0, dpc(ctx, 1))
            }
            for ((name, vstr) in chunk) {
                val v = MT.parseHex(vstr) ?: 0L
                rr.addView(clickableAddr("$name:$vstr", v).apply {
                    textSize = 11f
                    setTextColor(if (vstr.length > 8)
                        0xFFB8860B.toInt() else 0xFF555555.toInt())
                    setPadding(dpc(ctx, 1), dpc(ctx, 1),
                        dpc(ctx, 4), dpc(ctx, 1))
                }, LinearLayout.LayoutParams(0,
                    ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
            }
            card.addView(rr)
        }

        // 堆栈。
        val stInner = LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
        }
        if (h.sp != 0L)
            stInner.addView(clickableAddr("%X".format(h.sp), h.sp).apply {
                textSize = 11f; setPadding(0, 0, dpc(ctx, 8), 0)
            })
        for (sv in h.stack)
            stInner.addView(clickableAddr("%X".format(sv), sv).apply {
                textSize = 11f; setPadding(0, 0, dpc(ctx, 8), 0)
            })
        card.addView(LinearLayout(ctx).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            addView(tv(ctx, "堆栈: ", 11f, 0xFF999999.toInt()))
            addView(HorizontalScrollView(ctx).apply {
                isHorizontalScrollBarEnabled = false
                addView(stInner)
            }, LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        })
        return card
    }

    /** OverlayManager 每秒轮询：后台取命中（可能触发 su 读 maps），
     *  再回主线程渲染，避免阻塞 UI。 */
    fun onTick() {
        if (tickBusy) return
        tickBusy = true
        Thread {
            val hits = runCatching { NativeBridge.bpHits(60) }.getOrDefault("")
            val running = runCatching { NativeBridge.bpIsRunning() }
                .getOrDefault(false)
            val st = runCatching { NativeBridge.bpStatus() }.getOrDefault("")
            m.onUi {
                tickBusy = false
                if (hits != lastHits) {
                    lastHits = hits
                    renderHits(hits)
                }
                // P1-2：命中数写回 BpUi，悬浮按钮显示 "0x地址 类型 ×命中数"
                val cnt = HashMap<Long, Int>()
                for (line in hits.split('\n')) {
                    val h = parseHit(line) ?: continue
                    cnt[h.addr] = (cnt[h.addr] ?: 0) + 1
                }
                for (it in BpUi.snapshot()) {
                    it.hits = cnt[it.addr] ?: it.hits
                }
                if (running) m.syncBpChips()
                applyStatus(running, st)
            }
        }.start()
    }

    private fun applyStatus(running: Boolean, st: String) {
        statusTv.text = when {
            running && st.isNotBlank() -> "断点服务: $st"
            running -> "断点服务运行中 (pid=${OState.pid})"
            else -> "断点服务未启动"
        }
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

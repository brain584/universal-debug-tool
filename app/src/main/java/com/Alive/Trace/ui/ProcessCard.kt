package com.Alive.Trace.ui

import android.content.Context
import android.util.AttributeSet
import android.widget.LinearLayout
import android.widget.TextView
import com.Alive.Trace.R

/**
 * 目标进程卡片：当前进程名 + 选择进程按钮。
 * 后续接入进程选择后调用 [setProcessName] 更新显示。
 */
class ProcessCard @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : LinearLayout(context, attrs, defStyleAttr) {

    private val nameView: TextView

    /** “选择进程”按钮点击回调。 */
    var onSelectClick: (() -> Unit)? = null

    init {
        orientation = VERTICAL
        background = context.getDrawable(R.drawable.bg_card)
        val pad = resources.getDimensionPixelSize(R.dimen.card_padding)
        setPadding(pad, pad, pad, pad)
        inflate(context, R.layout.view_process_card, this)

        nameView = findViewById(R.id.process_name)
        // 描边按钮随主题强调色（ripple drawable 用 tint 着色，避免
        // drawable 缓存导致换肤后仍显示旧颜色）。
        findViewById<TextView>(R.id.process_select_btn).let { btn ->
            btn.backgroundTintList = android.content.res.ColorStateList.valueOf(
                SystemUi.themeColor(context, R.attr.accentColor))
        }
        findViewById<TextView>(R.id.process_select_btn).setOnClickListener {
            onSelectClick?.invoke()
        }
    }

    /** null 显示“当前未选择进程”。 */
    fun setProcessName(name: String?) {
        nameView.text = name ?: "当前未选择进程"
    }
}

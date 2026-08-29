package com.Alive.Trace.ui

import android.content.Context
import android.util.AttributeSet
import android.widget.LinearLayout
import android.widget.TextView
import com.Alive.Trace.R

/** 关于卡片：版本 / 架构 / 运行时长。 */
class AboutCard @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : LinearLayout(context, attrs, defStyleAttr) {

    private val versionView: TextView
    private val archView: TextView
    private val runtimeView: TextView

    init {
        orientation = VERTICAL
        background = context.getDrawable(R.drawable.bg_card)
        val pad = resources.getDimensionPixelSize(R.dimen.card_padding)
        setPadding(pad, pad, pad, pad)
        inflate(context, R.layout.view_about_card, this)

        versionView = findViewById(R.id.about_version)
        archView = findViewById(R.id.about_arch)
        runtimeView = findViewById(R.id.about_runtime)
    }

    fun setVersion(text: String) { versionView.text = text }
    fun setArch(text: String) { archView.text = text }
    fun setRuntime(text: String) { runtimeView.text = text }
}

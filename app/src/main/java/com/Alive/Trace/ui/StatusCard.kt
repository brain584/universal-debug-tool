package com.Alive.Trace.ui

import android.content.Context
import android.content.res.ColorStateList
import android.util.AttributeSet
import android.widget.LinearLayout
import android.widget.Switch
import android.widget.TextView
import android.view.View
import com.Alive.Trace.R

/**
 * 服务状态卡片：状态圆点 + 状态文字 + Overlay 开关。
 * setRunning() 同时同步文字、圆点与 Switch（不触发回调），
 * 用户手动拨动 Switch 时才回调 [onSwitchChanged]。
 */
class StatusCard @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : LinearLayout(context, attrs, defStyleAttr) {

    private val dot: View
    private val title: TextView
    private val subtitle: TextView
    private val switchView: Switch

    /** 用户拨动开关回调；setRunning() 不会触发。 */
    var onSwitchChanged: ((Boolean) -> Unit)? = null

    private var muteSwitch = false

    init {
        orientation = VERTICAL
        background = context.getDrawable(R.drawable.bg_card)
        val pad = resources.getDimensionPixelSize(R.dimen.card_padding)
        setPadding(pad, pad, pad, pad)
        inflate(context, R.layout.view_status_card, this)

        dot = findViewById(R.id.status_dot)
        title = findViewById(R.id.status_title)
        subtitle = findViewById(R.id.status_subtitle)
        switchView = findViewById(R.id.status_switch)

        switchView.setOnCheckedChangeListener { _, checked ->
            if (!muteSwitch) onSwitchChanged?.invoke(checked)
        }
    }

    /** 同步整个卡片到指定状态（不触发 onSwitchChanged）。 */
    fun setRunning(running: Boolean) {
        muteSwitch = true
        switchView.isChecked = running
        muteSwitch = false

        val accent = SystemUi.themeColor(context, R.attr.accentDimColor)
        dot.backgroundTintList = ColorStateList.valueOf(
            if (running) accent else getColor(R.color.dot_off))
        title.text = if (running) "服务状态：运行中" else "服务状态：未运行"
        title.setTextColor(
            if (running) accent else getColor(R.color.text_secondary))
        subtitle.text = if (running) "Overlay 服务已就绪" else "Overlay 服务未启动"
        // 开关轨道跟随主题强调色。
        switchView.trackTintList = ColorStateList(
            arrayOf(intArrayOf(android.R.attr.state_checked), intArrayOf()),
            intArrayOf(accent, getColor(R.color.switch_track_off)))
    }

    private fun getColor(id: Int): Int = context.getColor(id)
}

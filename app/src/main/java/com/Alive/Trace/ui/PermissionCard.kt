package com.Alive.Trace.ui

import android.content.Context
import android.content.res.ColorStateList
import android.util.AttributeSet
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import com.Alive.Trace.R

/**
 * 权限状态卡片：Root 权限与悬浮窗权限两行。
 * 行可点击：Root 行用于重新检测，悬浮窗行用于跳转授权页。
 */
class PermissionCard @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0,
) : LinearLayout(context, attrs, defStyleAttr) {

    private val rootCheck: ImageView
    private val rootState: TextView
    private val overlayCheck: ImageView
    private val overlayState: TextView

    /** Root 行点击（重新检测）。 */
    var onRootItemClick: (() -> Unit)? = null

    /** 悬浮窗行点击（未授权时跳系统设置）。 */
    var onOverlayItemClick: (() -> Unit)? = null

    init {
        orientation = VERTICAL
        background = context.getDrawable(R.drawable.bg_card)
        val pad = resources.getDimensionPixelSize(R.dimen.card_padding)
        setPadding(pad, pad, pad, pad)
        inflate(context, R.layout.view_permission_card, this)

        rootCheck = findViewById(R.id.perm_root_check)
        rootState = findViewById(R.id.perm_root_state)
        overlayCheck = findViewById(R.id.perm_overlay_check)
        overlayState = findViewById(R.id.perm_overlay_state)

        // 行点击
        (findViewById<LinearLayout>(R.id.perm_root_row)).setOnClickListener {
            onRootItemClick?.invoke()
        }
        (findViewById<LinearLayout>(R.id.perm_overlay_row)).setOnClickListener {
            onOverlayItemClick?.invoke()
        }
    }

    /** Root 权限状态。 */
    fun setRootState(granted: Boolean) {
        applyState(rootCheck, rootState, granted, "已获取", "未获取")
    }

    /** 悬浮窗权限状态。 */
    fun setOverlayState(granted: Boolean) {
        applyState(overlayCheck, overlayState, granted, "已授予", "未授予")
    }

    private fun applyState(check: ImageView, text: TextView,
                           granted: Boolean, okText: String, badText: String) {
        val accent = SystemUi.themeColor(context, R.attr.accentDimColor)
        val color = if (granted) accent else getColor(R.color.dot_off)
        check.imageTintList = ColorStateList.valueOf(color)
        text.text = if (granted) okText else badText
        text.setTextColor(if (granted) accent else getColor(R.color.text_dim))
    }

    private fun getColor(id: Int): Int = context.getColor(id)
}

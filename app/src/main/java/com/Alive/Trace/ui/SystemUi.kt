package com.Alive.Trace.ui

import android.content.Context
import android.util.TypedValue
import android.view.View
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

/**
 * 系统栏适配：targetSdk 35+ 在 Android 15 上强制 edge-to-edge，
 * 内容会画到状态栏 / 导航栏下面，必须用 insets 给根布局让位。
 */
object SystemUi {
    fun applyInsets(root: View) {
        ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            insets
        }
    }

    /** 解析当前主题的属性颜色（colorPrimary / colorPrimaryVariant 等）。 */
    fun themeColor(context: Context, attr: Int): Int {
        val tv = TypedValue()
        context.theme.resolveAttribute(attr, tv, true)
        return tv.data
    }
}

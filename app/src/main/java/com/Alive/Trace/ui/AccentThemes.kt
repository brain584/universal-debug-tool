package com.Alive.Trace.ui

import android.app.Activity
import android.content.Context
import com.Alive.Trace.R

/**
 * 启动界面配色主题：强调色方案，持久化到 SharedPreferences。
 * 切换后需重建 Activity 才能生效（MainActivity 负责）。
 */
object AccentThemes {
    data class Option(val id: String, val label: String, val style: Int)

    val options = listOf(
        Option("green", "配色：绿色（默认）", R.style.Theme_UnversalDebugTool),
        Option("blue", "配色：蓝色", R.style.Theme_UnversalDebugTool_Blue),
        Option("purple", "配色：紫色", R.style.Theme_UnversalDebugTool_Purple),
        Option("orange", "配色：橙色", R.style.Theme_UnversalDebugTool_Orange),
        Option("cyan", "配色：青色", R.style.Theme_UnversalDebugTool_Cyan),
        Option("pink", "配色：粉色", R.style.Theme_UnversalDebugTool_Pink),
    )

    private const val PREFS = "ui_prefs"
    private const val KEY = "accent_theme"

    fun currentId(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY, "green") ?: "green"

    fun currentIndex(context: Context): Int =
        options.indexOfFirst { it.id == currentId(context) }.coerceAtLeast(0)

    /** 必须在 setContentView 之前调用。 */
    fun applyTheme(activity: Activity) {
        activity.setTheme(options[currentIndex(activity)].style)
    }

    fun save(context: Context, id: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY, id).apply()
    }
}

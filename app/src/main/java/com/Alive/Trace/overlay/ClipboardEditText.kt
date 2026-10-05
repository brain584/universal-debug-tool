package com.Alive.Trace.overlay

import android.content.ClipboardManager
import android.content.Context
import android.util.AttributeSet
import android.widget.EditText

/**
 * 修复「输入法（手机键盘）里的复制没有效果」。
 *
 * 背景：悬浮窗属于后台窗口，Android 10+ 禁止后台应用写入剪贴板。
 * 输入法弹出菜单里的「复制」最终会走到 Editor/TextView 自己的
 * 剪贴板写入（ClipboardManager.setPrimaryClip），这一步会被系统
 * 静默拦掉——所以用输入法复制没反应，而项目自己的「复制」按钮
 * （走 copyText，可选兼容模式）是好的。
 *
 * 办法：覆写 onTextContextMenuItem，把 ID_COPY / ID_CUT 的写入改走
 * copyText（即项目已有的、带「兼容复制」兜底的通道），其余菜单项
 * 一律交回系统默认实现。
 *
 * 注意：兼容模式下 copyText 会短暂启动透明 Activity（必然会打断
 * 输入法焦点），这是 Android 10+ 后台写剪贴板的固有限制；不开兼容
 * 模式时则是一次普通写入，没有任何跳转。
 */
class ClipboardEditText @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = android.R.attr.editTextStyle
) : EditText(context, attrs, defStyleAttr) {

    private val clipMgr: ClipboardManager? by lazy {
        runCatching {
            context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        }.getOrNull()
    }

    override fun onTextContextMenuItem(id: Int): Boolean {
        when (id) {
            android.R.id.copy -> {
                val sel = selectedText()
                if (sel.isEmpty()) return super.onTextContextMenuItem(id)
                copyText(context, sel)
                return true
            }
            android.R.id.cut -> {
                val sel = selectedText()
                if (sel.isEmpty()) return super.onTextContextMenuItem(id)
                // 先把选中内容写进剪贴板，再删掉。
                copyText(context, sel)
                val s = selectionStart.coerceAtLeast(0)
                val e = selectionEnd.coerceAtLeast(0)
                if (s != e) text.delete(minOf(s, e), maxOf(s, e))
                return true
            }
            android.R.id.paste -> {
                // 读剪贴板在后台同样可能受限，失败就交回系统默认处理。
                val t = runCatching {
                    clipMgr?.primaryClip?.let { c ->
                        if (c.itemCount > 0) c.getItemAt(0).coerceToText(context)
                            ?.toString() else null
                    }
                }.getOrNull()
                if (t.isNullOrEmpty()) return super.onTextContextMenuItem(id)
                val start = selectionStart.coerceAtLeast(0)
                val end = selectionEnd.coerceAtLeast(0)
                val lo = minOf(start, end)
                val hi = maxOf(start, end)
                text.replace(lo, hi, t)
                return true
            }
        }
        return super.onTextContextMenuItem(id)
    }

    /** 当前选中的文本；没有选中时返回空串。 */
    private fun selectedText(): String {
        val s = selectionStart.coerceAtLeast(0)
        val e = selectionEnd.coerceAtLeast(0)
        if (s == e) return ""
        return runCatching { text.subSequence(minOf(s, e), maxOf(s, e)).toString() }
            .getOrDefault("")
    }
}

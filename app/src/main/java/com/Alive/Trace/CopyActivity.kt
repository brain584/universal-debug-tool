package com.Alive.Trace

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Toast

/**
 * Android 10+ 禁止后台应用读写剪贴板。这个透明 Activity 短暂
 * 进入前台后再写入剪贴板，随后立刻退出，保证复制功能始终可用。
 */
class CopyActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val text = intent?.getStringExtra(EXTRA_TEXT) ?: ""
        if (text.isNotEmpty()) {
            val ok = runCatching {
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("ATrace", text))
                true
            }.getOrDefault(false)
            Toast.makeText(
                this,
                if (ok) "已复制: ${text.take(48)}" else "复制失败，请长按下方文本手动复制",
                Toast.LENGTH_SHORT
            ).show()
        }
        Handler(Looper.getMainLooper()).postDelayed({ finish() }, 80)
    }

    companion object {
        const val EXTRA_TEXT = "atrace_copy_text"
    }
}

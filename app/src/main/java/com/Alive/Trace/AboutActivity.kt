package com.Alive.Trace

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.Alive.Trace.ui.AccentThemes
import com.Alive.Trace.ui.SystemUi

/**
 * 关于页：项目信息（含 GitHub 开源地址）与所用开源库清单
 * （与 README「参考库与改动说明」保持一致）。
 */
class AboutActivity : AppCompatActivity() {

    private data class Lib(val name: String, val usage: String,
                           val license: String, val url: String)

    // 与 README 参考库表一致；修改 README 时同步这里。
    private val libs = listOf(
        Lib("Qimgui", "Android 端 ImGui 悬浮窗基础（已修复触摸穿透、重写 UI）",
            "详见上游", "https://github.com/ohno1007/Qimgui"),
        Lib("imgui", "GUI 渲染", "MIT", "https://github.com/ocornut/imgui"),
        Lib("asmjit", "AArch64 汇编文本写入", "Zlib", "https://github.com/asmjit/asmjit"),
        Lib("capstone", "反汇编", "BSD-3-Clause", "https://github.com/capstone-engine/capstone"),
        Lib("xDL", "so 遍历、基址解析", "MIT", "https://github.com/hexhacking/xDL"),
        Lib("LuaJIT", "脚本引擎", "MIT", "https://github.com/LuaJIT/LuaJIT"),
        Lib("Dobby", "inline hook", "Apache-2.0", "https://github.com/jmpews/Dobby"),
        Lib("AndroidInject", "ptrace 注入器基础", "详见上游", "https://github.com/niqiuqiux/AndroidInject"),
        Lib("MemorySearch", "内存读写 / 搜索（imgui 侧，剔除 Keystone）",
            "MIT", "https://github.com/Aboy-g/MemorySearch"),
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        AccentThemes.applyTheme(this)
        setContentView(R.layout.activity_about)
        SystemUi.applyInsets(findViewById(R.id.about_root))

        findViewById<ImageButton>(R.id.btn_back).setOnClickListener { finish() }

        findViewById<TextView>(R.id.about_github).setOnClickListener {
            startActivity(Intent(Intent.ACTION_VIEW,
                Uri.parse("https://github.com/brain584/universal-debug-tool/")))
        }

        findViewById<TextView>(R.id.about_version).text = run {
            val pi = packageManager.getPackageInfo(packageName, 0)
            val code = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pi.longVersionCode.toInt()
            } else {
                @Suppress("DEPRECATION") pi.versionCode
            }
            "v${pi.versionName} ($code)"
        }
        findViewById<TextView>(R.id.about_arch).text =
            Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"

        val container = findViewById<LinearLayout>(R.id.libs_container)
        val dip = { v: Int ->
            TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(),
                resources.displayMetrics).toInt()
        }
        // 条目点击 ripple 背景（主题属性 → 资源 id）。
        val ripple = TypedValue()
        theme.resolveAttribute(android.R.attr.selectableItemBackground, ripple, true)
        for (lib in libs) {
            val item = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                isClickable = true
                isFocusable = true
                setBackgroundResource(ripple.resourceId)
                setPadding(0, dip(10), 0, dip(10))
                setOnClickListener {
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(lib.url)))
                }
            }

            val row1 = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            val name = TextView(this).apply {
                text = lib.name
                setTextColor(getColor(R.color.text_primary))
                textSize = 15f
                typeface = android.graphics.Typeface.DEFAULT_BOLD
            }
            val license = TextView(this).apply {
                text = lib.license
                setTextColor(SystemUi.themeColor(this@AboutActivity, R.attr.accentColor))
                textSize = 13f
                gravity = Gravity.END
            }
            row1.addView(name, LinearLayout.LayoutParams(
                0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            row1.addView(license, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT))
            item.addView(row1, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT))

            val usage = TextView(this).apply {
                text = lib.usage
                setTextColor(getColor(R.color.text_muted))
                textSize = 13f
            }
            item.addView(usage, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT).apply {
                topMargin = dip(2)
            })

            container.addView(item, LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT))
        }
    }
}

package com.Alive.Trace

import java.io.File

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.provider.Settings
import android.util.Log
import android.view.View
import android.widget.PopupMenu
import android.widget.TextView
import android.widget.Toast
import android.content.res.ColorStateList
import androidx.appcompat.app.AppCompatActivity
import com.Alive.Trace.ui.AboutCard
import com.Alive.Trace.ui.AccentThemes
import com.Alive.Trace.ui.PermissionCard
import com.Alive.Trace.ui.ProcessCard
import com.Alive.Trace.overlay.OverlayManager
import com.Alive.Trace.ui.StatusCard

class MainActivity : AppCompatActivity() {

    private lateinit var statusCard: StatusCard
    private lateinit var processCard: ProcessCard
    private lateinit var permissionCard: PermissionCard
    private lateinit var aboutCard: AboutCard
    private val handler = Handler(Looper.getMainLooper())

    // 原生 View 悬浮窗（ATrace v2，替代 ImGui 界面）。
    private var overlayManager: OverlayManager? = null

    // 运行时长计时（Overlay 启动时刻，0 = 未运行）。
    private var overlayStartElapsed = 0L

    // Root 检测只跑一次（避免每次回到前台都触发 su 授权弹窗），
    // 权限行点击可强制重测。
    private var rootCheckDone = false

    // ── Activity 生命周期 ──

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // 配色主题必须在 setContentView 之前应用。
        AccentThemes.applyTheme(this)
        setContentView(R.layout.activity_main)

        // targetSdk 35+ 强制 edge-to-edge：用 insets 给状态栏/导航栏让位。
        com.Alive.Trace.ui.SystemUi.applyInsets(
            findViewById(R.id.main_root))

        statusCard = findViewById(R.id.status_card)
        processCard = findViewById(R.id.process_card)
        permissionCard = findViewById(R.id.permission_card)
        aboutCard = findViewById(R.id.about_card)

        // 头像：打开关于页。
        findViewById<View>(R.id.avatar_btn).setOnClickListener {
            startActivity(Intent(this, AboutActivity::class.java))
        }

        // 右上角菜单：调整配色。
        findViewById<View>(R.id.btn_more).setOnClickListener { anchor ->
            showThemeMenu(anchor)
        }

        // 开关：启动前检查悬浮窗权限，关闭即停止悬浮层。
        statusCard.onSwitchChanged = { checked ->
            if (checked) {
                if (!Settings.canDrawOverlays(this)) {
                    Toast.makeText(this, "请先授予悬浮窗权限", Toast.LENGTH_LONG).show()
                    val intent = Intent(
                        Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                        Uri.parse("package:$packageName")
                    )
                    startActivityForResult(intent, REQUEST_OVERLAY_PERMISSION)
                    statusCard.setRunning(false)
                } else {
                    startOverlay()
                }
            } else {
                stopOverlay()
            }
        }

        // 底部"启动 Overlay"按钮：与开关同一入口；背景色随主题强调色。
        findViewById<TextView>(R.id.btn_launch).let { launchBtn ->
            launchBtn.backgroundTintList = ColorStateList.valueOf(
                com.Alive.Trace.ui.SystemUi.themeColor(
                    this, R.attr.accentColor))
            launchBtn.setOnClickListener {
                if (overlayManager != null) {
                    Toast.makeText(this, "Overlay 已在运行中", Toast.LENGTH_SHORT).show()
                } else {
                    statusCard.onSwitchChanged?.invoke(true)
                }
            }
        }

        // 目标进程：选择功能在悬浮窗内，这里是占位入口。
        processCard.onSelectClick = {
            Toast.makeText(this, "请启动 Overlay 后在调试界面中选择目标进程",
                Toast.LENGTH_LONG).show()
        }

        // 权限行点击：Root 行重测；悬浮窗行未授权时跳系统设置。
        permissionCard.onRootItemClick = {
            rootCheckDone = false
            checkRootAsync()
        }
        permissionCard.onOverlayItemClick = {
            if (!Settings.canDrawOverlays(this)) {
                startActivity(Intent(
                    Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                    Uri.parse("package:$packageName")))
            }
        }

        // 关于卡片：读取真实包信息与设备架构。
        aboutCard.setVersion(run {
            val pi = packageManager.getPackageInfo(packageName, 0)
            val code = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pi.longVersionCode.toInt()
            } else {
                @Suppress("DEPRECATION") pi.versionCode
            }
            "v${pi.versionName} ($code)"
        })
        aboutCard.setArch(Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown")
        aboutCard.setRuntime("00:00:00")

        permissionCard.setOverlayState(Settings.canDrawOverlays(this))
        checkRootAsync()
        statusCard.setRunning(false)
    }

    override fun onResume() {
        super.onResume()
        // 从系统设置页返回后刷新悬浮窗权限状态。
        permissionCard.setOverlayState(Settings.canDrawOverlays(this))
        if (!rootCheckDone) checkRootAsync()
    }

    override fun onDestroy() {
        super.onDestroy()
        if (overlayManager != null) {
            stopOverlay()
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_OVERLAY_PERMISSION) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
                Settings.canDrawOverlays(this)) {
                Toast.makeText(this, "已授予权限，请再次启动",
                    Toast.LENGTH_SHORT).show()
            }
        }
    }

    // ── 悬浮层管理 ──

    private fun startOverlay() {
        if (overlayManager != null) return

        // 原生 View 悬浮窗（ATrace v2，替代 ImGui 界面）：
        // 可拖动气泡 + 全屏半透明面板，后端复用注入器与 memsearch 引擎。
        overlayManager = OverlayManager(this, onExit = {
            overlayManager = null
            stopOverlayUiState()
        })

        // 悬浮层启动时请求一次 root（触发
        // Magisk/KernelSU 授权弹窗，如果尚未授权）。
        requestRoot()

        // 从 assets 解压独立 ptrace 注入器，并告诉
        // native 侧 agent .so 的位置，这样注入功能可以按需注入。
        val injectorPath = ensureInjectorExtracted()
        val agentPath = ensureAgentExtracted()
        nativeSetInjectorInfo(injectorPath, agentPath)
        nativeSetConfigDir(filesDir.absolutePath)

        overlayManager!!.show()

        statusCard.setRunning(true)
        overlayStartElapsed = SystemClock.elapsedRealtime()
        startRuntimeTicker()
        rootCheckDone = false
        checkRootAsync()

        moveTaskToBack(true)
        Toast.makeText(this, "悬浮窗已启动（拖动图标，点击展开）",
            Toast.LENGTH_SHORT).show()
    }

    private fun stopOverlay() {
        overlayManager?.hide()
        overlayManager = null
        stopOverlayUiState()
        Toast.makeText(this, "悬浮窗已停止", Toast.LENGTH_SHORT).show()
    }

    // 同步启动界面状态并复位计时（不触碰悬浮窗本身）。
    private fun stopOverlayUiState() {
        if (::statusCard.isInitialized) {
            statusCard.setRunning(false)
            stopRuntimeTicker()
            aboutCard.setRuntime("00:00:00")
        }
    }

    // 运行时长计时器：Overlay 运行期间每秒刷新一次。
    private val runtimeTicker = object : Runnable {
        override fun run() {
            if (overlayStartElapsed == 0L) return
            val sec = (SystemClock.elapsedRealtime() - overlayStartElapsed) / 1000
            aboutCard.setRuntime(
                String.format("%02d:%02d:%02d", sec / 3600,
                    (sec % 3600) / 60, sec % 60))
            handler.postDelayed(this, 1000)
        }
    }

    private fun startRuntimeTicker() {
        handler.removeCallbacks(runtimeTicker)
        handler.post(runtimeTicker)
    }

    private fun stopRuntimeTicker() {
        handler.removeCallbacks(runtimeTicker)
        overlayStartElapsed = 0L
    }

    // 通过 su 检测 root 可用性（与 native 侧 RunSuCommand 同一机制）。
    // 只在未检测过时执行，避免反复触发 Magisk/KernelSU 授权弹窗。
    private fun checkRootAsync() {
        Thread {
            val ok = try {
                val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
                p.inputStream.bufferedReader().use { it.readText() }
                    .contains("uid=0")
            } catch (_: Exception) {
                false
            }
            runOnUiThread {
                rootCheckDone = true
                if (!isFinishing && !isDestroyed) permissionCard.setRootState(ok)
            }
        }.start()
    }

    // 右上角菜单：选择配色主题。切换会重建界面；
    // Overlay 随 Activity 停止，需重新启动。
    private fun showThemeMenu(anchor: View) {
        val popup = PopupMenu(this, anchor)
        val menu = popup.menu
        AccentThemes.options.forEachIndexed { i, opt ->
            menu.add(THEME_MENU_GROUP, i, i, opt.label)
        }
        menu.setGroupCheckable(THEME_MENU_GROUP, true, true)
        menu.findItem(AccentThemes.currentIndex(this))?.isChecked = true
        popup.setOnMenuItemClickListener { item ->
            if (item.itemId != AccentThemes.currentIndex(this)) {
                AccentThemes.save(this, AccentThemes.options[item.itemId].id)
                if (overlayManager != null) stopOverlay()
                finish()
                @Suppress("DEPRECATION")
                overridePendingTransition(0, 0)
                startActivity(Intent(this, this.javaClass))
            }
            true
        }
        popup.show()
    }

    private fun requestRoot() {
        Thread {
            try {
                val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
                p.inputStream.bufferedReader().use { it.readText() }
            } catch (_: Exception) {
            }
        }.start()
    }

    // 把注入器可执行文件（由 Gradle 任务
    // buildInjectorExecutable 打包进 assets）解压到应用 files 目录并赋予执行权限。
    // 始终覆盖，新安装的 APK 会替换任何过期副本。
    private fun ensureInjectorExtracted(): String {
        val target = File(filesDir, "injector")
        return try {
            assets.open("injector").use { input ->
                target.outputStream().use { output -> input.copyTo(output) }
            }
            target.setExecutable(true, false)
            target.absolutePath
        } catch (e: Exception) {
            Log.e("ATrace", "extract injector failed: ${e.message}")
            target.absolutePath
        }
    }

    // APK 使用 extractNativeLibs=false，因此 nativeLibraryDir 中
    // 没有真正的 .so 文件——libagent.so 位于 APK zip 内。
    // 把它解压到应用 files 目录（真实文件）并返回路径。
    private fun ensureAgentExtracted(): String {
        val target = File(filesDir, "libagent.so")
        try {
            java.util.zip.ZipFile(File(applicationInfo.sourceDir)).use { zip ->
                val entry = zip.getEntry("lib/arm64-v8a/libagent.so")
                if (entry != null) {
                    zip.getInputStream(entry).use { input ->
                        target.outputStream().use { output -> input.copyTo(output) }
                    }
                    target.setExecutable(true, false)
                }
            }
        } catch (e: Exception) {
            Log.e("ATrace", "extract agent failed: ${e.message}")
        }
        return target.absolutePath
    }

    companion object {
        private const val REQUEST_OVERLAY_PERMISSION = 1001
        private const val THEME_MENU_GROUP = 7

        init {
            System.loadLibrary("unversaldebugtool")
        }
    }

    // Native 方法（后端：注入器路径 / 配置目录）。
    private external fun nativeSetInjectorInfo(injectorPath: String, agentPath: String)
    private external fun nativeSetConfigDir(dir: String)
}

package com.example.unversaldebugtool

import java.io.File

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.PixelFormat
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.text.InputType
import android.util.Log
import android.view.Gravity
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.SurfaceHolder
import android.view.SurfaceView
import android.view.View
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.view.inputmethod.InputConnectionWrapper
import android.view.inputmethod.InputMethodManager
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var checkBox: CheckBox
    private val handler = Handler(Looper.getMainLooper())
    private var overlayAdded = false

    // ── 单窗口悬浮层 ──
    //
    // 一个面板大小的窗口同时包含 SurfaceView（ImGui 渲染）、
    // 隐形 EditText（输入法）和触摸处理。任何地方都没有
    // 全屏窗口，因此屏幕其余部分上面没有任何
    // 覆盖，永远不会被拦截——无论 ROM 如何处理
    // 悬浮窗口。
    //
    // 窗口边界始终精确等于 imgui 面板矩形（由
    // nativeGetPanelRect 以屏幕坐标上报）。移动面板 = 移动
    // 该窗口；缩放 = 缩放该窗口。
    private var panelOverlay: FrameLayout? = null
    private var surfaceView: SurfaceView? = null
    private var imeEditText: EditText? = null
    private var windowManager: WindowManager? = null

    private var isTouchingImGui = false
    private var isDraggingWindow = false
    private var lastRawX = 0f
    private var lastRawY = 0f
    private var seenNativeRunning = false

    // 记住全窗口位置，从胶囊展开时恢复它。
    private var wasPill = false
    private var savedFullPos: Pair<Int, Int>? = null

    // 面板的屏幕位置，与悬浮窗口分开跟踪，
    // 这样弹窗保持窗口全屏时主窗口仍可拖动。
    
    private var panelPosX = 60
    private var panelPosY = 100
    private var panelW = 900
    private var panelH = 620
    private var lastScreenW = 0
    private var lastScreenH = 0

    private val overlayType: Int
        get() = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_PHONE
        }

    // 面板大小、可触摸（它就是 imgui 面板）。NOT_TOUCH_MODAL 让
    // 窗口外的触摸穿透到下层应用。
    private val panelLayoutParams: WindowManager.LayoutParams by lazy {
        WindowManager.LayoutParams(
            900, 620,  // 默认全窗口尺寸（与 UiState 默认值一致）
            overlayType,
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL or
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT
        ).apply {
            gravity = Gravity.TOP or Gravity.LEFT
            x = 60
            y = 100
        }
    }

    // Surface 生命周期回调
    private val surfaceCallback = object : SurfaceHolder.Callback {
        override fun surfaceCreated(holder: SurfaceHolder) {
            nativeSurfaceCreated(holder.surface, holder.surfaceFrame.width(), holder.surfaceFrame.height())
            nativeStartRender()
        }

        override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {
            nativeSurfaceChanged(width, height)
        }

        override fun surfaceDestroyed(holder: SurfaceHolder) {
            nativeStopRender()
            nativeSurfaceDestroyed()
        }
    }

    // ── 悬浮层轮询器（输入法 + 窗口跟踪）──
    private val overlayPoller = object : Runnable {
        override fun run() {
            if (!overlayAdded) return

            val running = nativeIsRunning()
            if (running) seenNativeRunning = true

            // 只有真正运行过至少一次的渲染循环停止时，
            // 才把"退出"按钮完成退出动画视为"自行退出"——
            // 否则第一次轮询可能早于 Surface / 渲染线程启动，
            // 导致错误地取消勾选
            // 该复选框。
            if (!running && seenNativeRunning) {
                Log.d("ImGuiTouch", "native render exited; unchecking Show ImGui")
                checkBox.isChecked = false
                return
            }

            // ── 输入法键盘管理 ──
            // 旋转 / 显示尺寸变化：系统可能移动了
            // 窗口；重新同步位置并重新上报，
            // 使触摸映射和胶囊保持正确。
            val (sw, sh) = realDisplaySize()
            if (sw != lastScreenW || sh != lastScreenH) {
                lastScreenW = sw
                lastScreenH = sh
                clampPanelPos(panelLayoutParams)
                updateSurfaceOrigin()
                updatePanelWindowSize()
            }

            val wantKeyboard = nativeWantKeyboard()
            val editText = imeEditText ?: return
            if (wantKeyboard && !editText.hasFocus()) {
                // 让面板窗口可聚焦并请求系统显示
                // 输入法（softInputMode + 显式 showSoftInput）。
                // 焦点请求延迟到标志变更生效后。
                panelLayoutParams.softInputMode = WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE
                windowManager?.updateViewLayout(panelOverlay, panelLayoutParams.apply {
                    flags = flags and WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE.inv()
                })
                editText.postDelayed({
                    if (!editText.hasFocus()) {
                        editText.requestFocus()
                        editText.onWindowFocusChanged(true)
                    }
                    val imm = getSystemService(INPUT_METHOD_SERVICE) as? InputMethodManager
                    @Suppress("DEPRECATION")
                    imm?.showSoftInput(editText, InputMethodManager.SHOW_FORCED)
                }, 120)
            } else if (!wantKeyboard && editText.hasFocus()) {
                val imm = getSystemService(INPUT_METHOD_SERVICE) as? InputMethodManager
                editText.windowToken?.let { imm?.hideSoftInputFromWindow(it, 0) }
                editText.clearFocus()
                panelOverlay?.clearFocus()
                panelLayoutParams.softInputMode = WindowManager.LayoutParams.SOFT_INPUT_STATE_UNSPECIFIED
                windowManager?.updateViewLayout(panelOverlay, panelLayoutParams.apply {
                    flags = flags or WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                })
            }

            // ── 保持屏幕 <-> ImGui 坐标映射新鲜 ──
            updateSurfaceOrigin()

            // ── 跟踪面板矩形（收起 / 展开 / 缩放）──
            updatePanelWindowSize()

            handler.postDelayed(this, 300)
        }
    }

    // ── Activity 生命周期 ──

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        checkBox = findViewById(R.id.checkbox_imgui)
        windowManager = getSystemService(WINDOW_SERVICE) as WindowManager

        checkBox.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && !Settings.canDrawOverlays(this)) {
                    Toast.makeText(this, "Grant overlay permission, then try again", Toast.LENGTH_LONG).show()
                    val intent = Intent(
                        Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
                        Uri.parse("package:$packageName")
                    )
                    startActivityForResult(intent, REQUEST_OVERLAY_PERMISSION)
                    checkBox.isChecked = false
                } else {
                    startOverlay()
                }
            } else {
                stopOverlay()
            }
        }

        if (nativeIsRunning()) {
            checkBox.isChecked = true
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        if (overlayAdded) {
            stopOverlay()
        }
    }

    // 设备旋转时悬浮层继续运行（configChanges
    // 阻止 Activity 重建）；按真实显示尺寸重新同步一切，
    // 使触摸映射、边界限制和胶囊保持正确。
    override fun onConfigurationChanged(newConfig: android.content.res.Configuration) {
        super.onConfigurationChanged(newConfig)
        if (!overlayAdded) return
        val (sw, sh) = realDisplaySize()
        lastScreenW = sw
        lastScreenH = sh
        clampPanelPos(panelLayoutParams)
        updateSurfaceOrigin()
        updatePanelWindowSize()
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_OVERLAY_PERMISSION) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && Settings.canDrawOverlays(this)) {
                Toast.makeText(this, "Permission granted - tap again", Toast.LENGTH_SHORT).show()
            }
        }
    }

    // ── 悬浮层管理 ──

    private fun startOverlay() {
        if (overlayAdded) return

        val ctx = applicationContext

        val container = FrameLayout(ctx).apply {
            setBackgroundColor(0x00000000) // 完全透明
            setOnTouchListener { _, event -> handleTouch(event) }
        }

        // 输入法键盘使用的隐形 EditText。自定义 EditText 包装
        // InputConnection，使每个输入法操作（字符、退格、
        // 光标移动、回车）都以按键 / 字符事件转发给 ImGui。
        imeEditText = ImGuiEditText(ctx).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setBackgroundColor(0x00000000)
            setTextColor(0x00000000)
            setCursorVisible(false)
            isFocusable = true
            isFocusableInTouchMode = true
            showSoftInputOnFocus = true
            layoutParams = FrameLayout.LayoutParams(1, 1).apply {
                gravity = Gravity.TOP or Gravity.LEFT
            }
        }
        container.addView(imeEditText)

        // 用于 native ImGui 渲染的 SurfaceView；铺满面板窗口。
        surfaceView = SurfaceView(ctx).apply {
            setZOrderOnTop(true)
            holder.setFormat(PixelFormat.TRANSLUCENT)
            holder.addCallback(surfaceCallback)
        }
        container.addView(surfaceView, FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.MATCH_PARENT
        ))

        panelOverlay = container

        try {
            windowManager?.addView(panelOverlay, panelLayoutParams)
            overlayAdded = true

            // 悬浮层启动时请求一次 root（触发
            // Magisk/KernelSU 授权弹窗，如果尚未授权）。
            requestRoot()

            // 从 assets 解压独立 ptrace 注入器，并告诉
            // native agent .so 的位置，这样 imgui 的"注入"按钮可以
            // 按需注入。
            val injectorPath = ensureInjectorExtracted()
            val agentPath = ensureAgentExtracted()
            nativeSetInjectorInfo(injectorPath, agentPath)
            nativeSetConfigDir(filesDir.absolutePath)

            updateSurfaceOrigin()
            updatePanelWindowSize()

            handler.post(overlayPoller)

            moveTaskToBack(true)
            Toast.makeText(this, "ImGui overlay started", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Failed to create overlay: ${e.message}", Toast.LENGTH_LONG).show()
            checkBox.isChecked = false
        }
    }

    private fun stopOverlay() {
        if (!overlayAdded) return

        handler.removeCallbacks(overlayPoller)

        surfaceView?.holder?.removeCallback(surfaceCallback)

        nativeStopRender()
        nativeSurfaceDestroyed()

        try { windowManager?.removeView(panelOverlay) } catch (_: Exception) {}

        panelOverlay = null
        surfaceView = null
        imeEditText = null
        overlayAdded = false

        Toast.makeText(this, "ImGui overlay stopped", Toast.LENGTH_SHORT).show()
    }

    // ── 触摸分发 ──
    //
    // 窗口就是 imgui 面板，因此它收到的每个触摸都属于
    // imgui——没有需要穿透的内容。窗口外的触摸
    // 永远不会到达它（WindowManager 把它们路由到下层应用）。
    //
    // 从标题栏（或收起胶囊上的任意位置）开始的触摸
    // 拖动整个窗口；其他位置的触摸与控件交互。

    private fun handleTouch(event: MotionEvent): Boolean {
        val sx = event.rawX
        val sy = event.rawY

        when (event.actionMasked) {
            MotionEvent.ACTION_DOWN -> {
                // 点击收起胶囊直接展开它。
                // 这不依赖 ImGui 的悬停 / 点击检测，
                // 也不依赖坐标映射，因此展开始终有效。
                if (nativeIsCollapsed()) {
                    nativeExpand()
                    isTouchingImGui = false
                    Log.d("ImGuiTouch", "pill tapped -> expand")
                    return true
                }
                isTouchingImGui = true
                lastRawX = sx
                lastRawY = sy
                isDraggingWindow = nativeIsOnTitleBar(sx, sy)
                nativeTouchEvent(TOUCH_DOWN, sx, sy, event.getPointerId(0))
                Log.d("ImGuiTouch", "DOWN ($sx,$sy) drag=$isDraggingWindow")
                return true
            }
            MotionEvent.ACTION_MOVE -> {
                if (isTouchingImGui) {
                    nativeTouchEvent(TOUCH_MOVE, sx, sy, event.getPointerId(0))
                    if (isDraggingWindow) {
                        val dx = (sx - lastRawX).toInt()
                        val dy = (sy - lastRawY).toInt()
                        if (dx != 0 || dy != 0) {
                            if (nativeIsOverlayExpanded()) {
                                // 弹窗打开：窗口保持全屏；
                                // 只移动面板的渲染位置。
                                panelPosX += dx
                                panelPosY += dy
                                clampPanelPosXY()
                                nativeSetPanelOrigin(panelPosX.toFloat(), panelPosY.toFloat())
                            } else {
                                val lp = panelLayoutParams
                                lp.x += dx
                                lp.y += dy
                                clampPanelPos(lp)
                                panelPosX = lp.x
                                panelPosY = lp.y
                                val v = panelOverlay
                                val loc = IntArray(2)
                                v?.getLocationOnScreen(loc)
                                val (sw, sh) = realDisplaySize()
                                Log.d("ImGuiTouch", "drag lp=(${lp.x},${lp.y}) actual=(${loc[0]},${loc[1]}) win=${v?.width}x${v?.height} screen=${sw}x${sh}")
                                try {
                                    windowManager?.updateViewLayout(panelOverlay, lp)
                                } catch (e: Exception) {
                                    Log.e("ImGuiTouch", "move updateViewLayout failed: ${e.message}")
                                }
                                // 立即同步坐标映射。
                                reportSurfaceOrigin(lp.x, lp.y, lp.width, lp.height)
                                nativeSetPanelOrigin(panelPosX.toFloat(), panelPosY.toFloat())
                            }
                        }
                    }
                    lastRawX = sx
                    lastRawY = sy
                    return true
                }
                return false
            }
            MotionEvent.ACTION_UP, MotionEvent.ACTION_CANCEL -> {
                if (isTouchingImGui) {
                    nativeTouchEvent(TOUCH_UP, sx, sy, event.getPointerId(0))
                    isTouchingImGui = false
                    isDraggingWindow = false
                    Log.d("ImGuiTouch", "UP end")
                    return true
                }
                return false
            }
        }
        return false
    }

    private fun clampPanelPos(lp: WindowManager.LayoutParams) {
        // 只做宽松限制：应用的显示指标在旋转后可能过期，
        // 因此基于屏幕的裁剪会把窗口钉在
        // 错误的位置。改为保持窗口可触达。
        lp.x = lp.x.coerceIn(-lp.width, 5000)
        lp.y = lp.y.coerceIn(-lp.height, 5000)
    }

    private fun clampPanelPosXY() {
        panelPosX = panelPosX.coerceIn(-panelW, 5000)
        panelPosY = panelPosY.coerceIn(-panelH, 5000)
    }

    // ── 窗口尺寸辅助函数 ──

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
            Log.e("ImGuiTouch", "extract injector failed: ${e.message}")
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
            Log.e("ImGuiTouch", "extract agent failed: ${e.message}")
        }
        return target.absolutePath
    }

    // 把悬浮窗口的目标屏幕位置 / 尺寸上报给 native，
    // 保持屏幕 <-> ImGui 坐标转换正确。使用我们自己的
    // LayoutParams 记账（x/y 是我们向 WindowManager 请求的值），
    // 它始终与触摸坐标的转换方式同步。
    private fun updateSurfaceOrigin() {
        val v = panelOverlay ?: return
        val loc = IntArray(2)
        v.getLocationOnScreen(loc)
        val w = v.width
        val h = v.height
        if (w <= 0 || h <= 0) return
        // 用窗口实际的屏幕位置同步记账（系统可能
        // 在旋转 / 缩放时移动它）。
        val lp = panelLayoutParams
        if (lp.x != loc[0] || lp.y != loc[1]) {
            lp.x = loc[0]
            lp.y = loc[1]
        }
        // 仅当窗口不是全屏时，才把窗口位置当作面板位置：
        // 弹窗展开 / 收缩期间窗口是全屏的，
        // 必须保留面板位置。
        val (sw, sh) = realDisplaySize()
        val fullScreen = (w >= sw - 2 && h >= sh - 2)
        if (!nativeIsOverlayExpanded() && !fullScreen) {
            panelPosX = loc[0]
            panelPosY = loc[1]
        }
        reportSurfaceOrigin(loc[0], loc[1], w, h)
        nativeSetPanelOrigin(panelPosX.toFloat(), panelPosY.toFloat())
    }

    private fun reportSurfaceOrigin(x: Int, y: Int, viewW: Int, viewH: Int) {
        val (sw, sh) = realDisplaySize()
        nativeSetSurfaceOrigin(
            x.toFloat(), y.toFloat(),
            viewW.toFloat(), viewH.toFloat(),
            sw.toFloat(), sh.toFloat())
    }

    // 旋转时 Activity 不重建，resources.displayMetrics 可能保持过期（竖屏），
    // 因此使用真实显示尺寸。
    private fun realDisplaySize(): Pair<Int, Int> {
        val p = android.graphics.Point()
        @Suppress("DEPRECATION")
        windowManager?.defaultDisplay?.getRealSize(p)
        if (p.x > 0 && p.y > 0) return p.x to p.y
        val dm = resources.displayMetrics
        return dm.widthPixels to dm.heightPixels
    }

    // 把单个悬浮窗口的尺寸 / 位置设置为 native
    // 上报的面板矩形（屏幕坐标）。处理胶囊 <-> 展开
    // 转换（记住全窗口位置）。
    private fun updatePanelWindowSize() {
        val rect = FloatArray(4)
        nativeGetPanelRect(rect)
        val x = rect[0].toInt()
        val y = rect[1].toInt()
        val w = rect[2].toInt()
        val h = rect[3].toInt()

        if (w <= 0 || h <= 0) {
            Log.d("ImGuiTouch", "panel rect invalid, keeping current bounds")
            return
        }

        val collapsed = nativeIsCollapsed()
        val expanded = nativeIsOverlayExpanded()
        val lp = panelLayoutParams

        if (collapsed && !wasPill) {
            // 收起时：记住全窗口原来的位置。
            savedFullPos = lp.x to lp.y
            wasPill = true
        } else if (!collapsed && wasPill) {
            wasPill = false
        }

        var newX = x
        var newY = y
        if (!collapsed && savedFullPos != null) {
            // 展开时：恢复窗口收起前的位置。
            newX = savedFullPos!!.first
            newY = savedFullPos!!.second
            savedFullPos = null
        }

        if (!collapsed) {
            // 宽松限制：应用的显示指标在旋转后可能过期，
            // 因此绝不要限制到计算出的屏幕尺寸（那会把
            // 面板钉死在横屏）；保持窗口可触达。
            newX = newX.coerceIn(-w, 5000)
            newY = newY.coerceIn(-h, 5000)
        }

        // 收起时系统通过 CENTER_HORIZONTAL 重力
        // 在真实屏幕上居中胶囊（应用的显示指标可能过期）。
        val wantGravity = if (collapsed) Gravity.CENTER_HORIZONTAL or Gravity.TOP
                          else Gravity.TOP or Gravity.LEFT
        val wantX = if (collapsed) 0 else newX
        val wantY = if (collapsed) 28 else newY

        if (lp.width != w || lp.height != h || lp.x != wantX || lp.y != wantY || lp.gravity != wantGravity) {
            Log.d("ImGuiTouch", "panel window -> ($wantX,$wantY) ${w}x${h} (collapsed=$collapsed expanded=$expanded)")
            lp.width = w
            lp.height = h
            lp.x = wantX
            lp.y = wantY
            lp.gravity = wantGravity
            try {
                windowManager?.updateViewLayout(panelOverlay, lp)
            } catch (e: Exception) {
                Log.e("ImGuiTouch", "updateViewLayout failed: ${e.message}")
            }
            // 重新读取窗口实际的位置 / 尺寸（重力可能居中胶囊，
            // 系统可能限制弹窗扩展，因此请求的矩形
            // 不一定就是窗口最终的位置）。
            updateSurfaceOrigin()
        }

        // 跟踪面板矩形（主窗口渲染的位置）。
        // 弹窗打开时窗口是全屏的，面板位置
        // 只能通过拖动改变。
        if (!expanded) {
            if (collapsed) {
                // 系统会居中胶囊；读回其实际位置
                //（可能滞后一轮轮询，随后自行纠正）。
                val loc = IntArray(2)
                panelOverlay?.getLocationOnScreen(loc)
                panelPosX = loc[0]
                panelPosY = loc[1]
            } else {
                panelPosX = newX
                panelPosY = newY
                panelW = w
                panelH = h
            }
        }
        nativeSetPanelOrigin(panelPosX.toFloat(), panelPosY.toFloat())
    }

    // ── 输入法中继 EditText ──
    // 包装 InputConnection，使所有输入法操作都到达 ImGui：
    // 提交的字符、退格 / 前删、光标移动、回车和原始
    // 按键事件。ImGui 的 InputText 是文本的权威来源；
    // 这个 EditText 只是输入法传输通道。
    private inner class ImGuiEditText(context: Context) : EditText(context) {
        private var lastSelEnd = 0

        override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection? {
            val base = super.onCreateInputConnection(outAttrs) ?: return null
            // 纯十六进制 / 地址输入：隐藏英文自动纠正 / 联想，
            // 避免输入法把文本留在组合区不提交。
            outAttrs.inputType =
                InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            lastSelEnd = selectionEnd
            return object : InputConnectionWrapper(base, true) {
                // 输入法组合区中当前持有的文本。带
                // 联想 / 拼音的输入法只发送组合文本并稍后
                // 提交；把它镜像到 ImGui，确保输入始终有效。
                private var composingLen = 0

                private fun forwardChars(text: CharSequence?) {
                    if (text == null) return
                    for (i in text.indices) {
                        nativeKeyEvent(0, 0, text[i].code)
                    }
                }

                private fun deleteChars(n: Int) {
                    repeat(n.coerceAtLeast(0)) {
                        nativeKeyEvent(67 /* AKEYCODE_DEL */, 0, 0)
                        nativeKeyEvent(67 /* AKEYCODE_DEL */, 1, 0)
                    }
                }

                override fun setComposingText(text: CharSequence?, newCursorPosition: Int): Boolean {
                    // 用新文本替换之前组合的文本。
                    deleteChars(composingLen)
                    composingLen = text?.length ?: 0
                    forwardChars(text)
                    lastSelEnd = selectionEnd
                    return super.setComposingText(text, newCursorPosition)
                }

                override fun finishComposingText(): Boolean {
                    composingLen = 0
                    lastSelEnd = selectionEnd
                    return super.finishComposingText()
                }

                override fun commitText(text: CharSequence?, newCursorPosition: Int): Boolean {
                    // 提交的文本替换组合区。
                    deleteChars(composingLen)
                    composingLen = 0
                    forwardChars(text)
                    lastSelEnd = selectionEnd
                    return super.commitText(text, newCursorPosition)
                }

                override fun deleteSurroundingText(beforeLength: Int, afterLength: Int): Boolean {
                    repeat(beforeLength.coerceAtLeast(0)) {
                        nativeKeyEvent(67 /* AKEYCODE_DEL */, 0, 0)
                        nativeKeyEvent(67 /* AKEYCODE_DEL */, 1, 0)
                    }
                    repeat(afterLength.coerceAtLeast(0)) {
                        nativeKeyEvent(112 /* AKEYCODE_FORWARD_DEL */, 0, 0)
                        nativeKeyEvent(112 /* AKEYCODE_FORWARD_DEL */, 1, 0)
                    }
                    lastSelEnd = selectionEnd
                    return super.deleteSurroundingText(beforeLength, afterLength)
                }

                override fun setSelection(start: Int, end: Int): Boolean {
                    val delta = end - lastSelEnd
                    if (delta != 0) {
                        val key = if (delta > 0) 22 /* AKEYCODE_DPAD_RIGHT */
                                  else 21 /* AKEYCODE_DPAD_LEFT */
                        val n = Math.abs(delta).coerceAtMost(64)
                        repeat(n) {
                            nativeKeyEvent(key, 0, 0)
                            nativeKeyEvent(key, 1, 0)
                        }
                        if (end <= 0) {
                            nativeKeyEvent(122 /* AKEYCODE_MOVE_HOME */, 0, 0)
                            nativeKeyEvent(122 /* AKEYCODE_MOVE_HOME */, 1, 0)
                        }
                    }
                    lastSelEnd = end
                    return super.setSelection(start, end)
                }

                override fun performContextMenuAction(id: Int): Boolean {
                    // 输入法"全选"（和文本选择工具栏）发送
                    // 该操作；ImGui 的 InputText 在 Ctrl+A 时全选。
                    if (id == android.R.id.selectAll) {
                        nativeKeyEvent(113 /* AKEYCODE_CTRL_LEFT */, 0, 0)
                        nativeKeyEvent(29 /* AKEYCODE_A */, 0, 0)
                        nativeKeyEvent(29 /* AKEYCODE_A */, 1, 0)
                        nativeKeyEvent(113 /* AKEYCODE_CTRL_LEFT */, 1, 0)
                        lastSelEnd = selectionEnd
                        return true
                    }
                    return super.performContextMenuAction(id)
                }

                override fun performEditorAction(editorAction: Int): Boolean {
                    nativeKeyEvent(66 /* AKEYCODE_ENTER */, 0, 0)
                    nativeKeyEvent(66 /* AKEYCODE_ENTER */, 1, 0)
                    return super.performEditorAction(editorAction)
                }

                override fun sendKeyEvent(event: KeyEvent): Boolean {
                    if (event.keyCode != KeyEvent.KEYCODE_BACK) {
                        // 转发 ctrl/shift 状态，使 Ctrl+A 或
                        // Shift+方向键等组合能到达 ImGui（有些输入法
                        // 以原始按键事件而不是上下文菜单操作发送）。
                        val withCtrl = event.isCtrlPressed &&
                            event.keyCode != KeyEvent.KEYCODE_CTRL_LEFT &&
                            event.keyCode != KeyEvent.KEYCODE_CTRL_RIGHT
                        val withShift = event.isShiftPressed &&
                            event.keyCode != KeyEvent.KEYCODE_SHIFT_LEFT &&
                            event.keyCode != KeyEvent.KEYCODE_SHIFT_RIGHT
                        if (withCtrl)
                            nativeKeyEvent(113 /* AKEYCODE_CTRL_LEFT */, 0, 0)
                        if (withShift)
                            nativeKeyEvent(59 /* AKEYCODE_SHIFT_LEFT */, 0, 0)
                        nativeKeyEvent(event.keyCode, event.action, 0)
                        if (withCtrl)
                            nativeKeyEvent(113 /* AKEYCODE_CTRL_LEFT */, 1, 0)
                        if (withShift)
                            nativeKeyEvent(59 /* AKEYCODE_SHIFT_LEFT */, 1, 0)
                    }
                    return super.sendKeyEvent(event)
                }
            }
        }
    }

    // ── Native 方法 ──

    companion object {
        private const val REQUEST_OVERLAY_PERMISSION = 1001
        const val TOUCH_DOWN = 0
        const val TOUCH_MOVE = 1
        const val TOUCH_UP = 2

        init {
            System.loadLibrary("unversaldebugtool")
        }
    }

    // Surface 生命周期
    private external fun nativeSurfaceCreated(surface: Any, width: Int, height: Int)
    private external fun nativeSurfaceChanged(width: Int, height: Int)
    private external fun nativeSurfaceDestroyed()

    // 渲染控制
    private external fun nativeStartRender()
    private external fun nativeStopRender()

    // 输入
    private external fun nativeTouchEvent(action: Int, x: Float, y: Float, pointerId: Int)
    private external fun nativeKeyEvent(keyCode: Int, action: Int, unicodeChar: Int)

    // 坐标映射
    private external fun nativeSetSurfaceOrigin(x: Float, y: Float, viewW: Float, viewH: Float, screenW: Float, screenH: Float)
    private external fun nativeSetPanelOrigin(x: Float, y: Float)
    private external fun nativeSetInjectorInfo(injectorPath: String, agentPath: String)
    private external fun nativeSetConfigDir(dir: String)

    // 状态查询
    private external fun nativeWantKeyboard(): Boolean
    private external fun nativeWantCaptureMouse(): Boolean
    private external fun nativeIsPointInWindow(x: Float, y: Float): Boolean
    private external fun nativeIsOnTitleBar(x: Float, y: Float): Boolean
    private external fun nativeIsCollapsed(): Boolean
    private external fun nativeIsOverlayExpanded(): Boolean
    private external fun nativeExpand()
    private external fun nativeIsRunning(): Boolean
    private external fun nativeGetPanelRect(rect: FloatArray)
}

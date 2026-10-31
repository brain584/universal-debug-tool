# ATrace 1.2.0

- 版本号提升到 1.2.0（versionCode 1200）

## 新增

- MCP 服务：App 内置 HTTP MCP 服务（默认 `127.0.0.1:28471`），把注入、内存读写/搜索、
  硬件断点、Lua 执行、进程/模块查询等能力暴露给 AI 客户端；工具列表随版本更新
- 硬件断点增强：命中结果补充 Java 线程调用栈（`bpJavaStack`）、模块名 + 偏移、
  命中计数悬浮按钮（地址/类型/命中数，点击可清除）
- Lua API 大幅扩充：数值读写（U8/U16/U32/U64/I8/I16/I32/I64、浮点）、ArtHook 反射
  （`findClass`/`getStatic`/`setStatic`/`listMethods`）、`nativeBacktrace`（回调内使用
  `nativeBacktraceInto`）、`symbol`、编号/汇编辅助等，`api()` 可自检函数与分组
- 内存页 GG 化：整页 0x2000（2048 行）列表 + 右侧滚动条、写死列宽、行内区域类型
  （java/cd/ca/xa/A…）、页首「地址跳转」= 上一页最后一个地址、页尾 = 下一页起始
- 内存页功能补齐：偏移量计算器、指针搜索、搜索附近、自定义勾选、Q 类型写指针
  （`78fd6604Ch` 形式）、撤销修改（Undo）、可读性降级（不可读页显示 0）
- 分配内存页：优先 agent 在目标进程内 mmap，返回地址经 `memRead` 校验；
  rwx 被系统拒绝时自动重试并降级 rw 提示

## 修复

- 悬浮窗内存页改为 RecyclerView 后系统滚动条在无 scrollbar drawable 的悬浮窗主题上
  `ScrollBarDrawable.mutate()` 空指针闪退 → 关闭系统滚动条，改自绘滚动条
- 反汇编慢：capstone 句柄每次 JNI 调用都 `cs_open/cs_close` → 改为全局常驻句柄
- 跳转后概率落在页面首项：整页快路径提前 return 导致滚动代码被跳过 → 三条加载分支
  统一调用定位（立即 + post + postDelayed）
- 写入（数值 / `~A8` 汇编）后仍显示旧值：写入成功后失效页缓存再刷新
- 断点类型恒显示 `x`：长按「下断点」只传了地址 → 补传类型/长度
- 断点进程残留：`injector --bp` 增加 `--parent <App pid>` 看门狗，App 退出即自杀并
  由内核释放 perf 事件
- 固定抽象 socket 名易连到旧 agent（pid 不变）：连接后校验 agent pid，不符则
  `kill -9` 旧宿主进程并断开，分配/自动连接两处均已接入
- 搜索/保存页若干空指针（JNI 返回 null 时 `trim` 崩溃）与注入失败分类提示

## 说明

- 本 APK 为 arm64-v8a debug 变体；注入、断点、内存搜索需要 root
- Android 16 对匿名可执行内存（execmem）有策略限制，rwx 分配可能被降级为 rw

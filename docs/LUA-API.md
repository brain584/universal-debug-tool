# Lua API 速查（在目标进程内执行）

脚本由 agent 内置 LuaJIT 执行，宿主 API 直接可用。

- **第一次用先跑** `api()` / `help()`：返回全部函数的签名、返回值、说明与示例；
  `api("hookfunc")` 可单查一个。
- 电脑上怎么写/跑：见 [MCP.md](MCP.md) 的「电脑写脚本，手机执行」；或直接用
  `tools/atrace_lua.py`（cmd 里编辑 + 执行，手机无需开悬浮窗）。
- 下面的例子均在真实目标（`me.hd.ggtutorial`，Android 16 arm64）上验证过；
  不同 App/类名需自行替换。

## 1. 自检 / 环境

```lua
capabilities() -> table     -- 架构/版本/api 数/ART 状态/hook 能力/limitations
whoami() -> string          -- "pid=.. pkg=.. base=.. hooks=.."
self_info() -> table        -- {pid, pkg, agent_base, hooks, uptime_ms, ...}
artStatus() -> string       -- "ready（LSPlant 已初始化）" / "not initialized"
artVmState() -> string      -- ART VM 状态与当前线程 attach 情况
api([name]) -> table        -- 全部 API 说明
help()                      -- 把清单打到日志
```

```lua
dump(capabilities(), 2)
print(artVmState())
```

## 2. 模块 / 符号 / 扫描

```lua
getBase(name) -> number                  -- 模块基址（未加载返回 0）
clearbase([name]) -> boolean
module_info(name) -> table               -- {name,path,base,size,segments=[...]}
symbols(name[, pattern]) -> array        -- {name, offset, addr, size, type}
symbol(name[, module]) -> number         -- 注意：name 在前、module 在后
scan(name, hex[, mask]) -> array         -- 模块段内字节扫描
scanRange(start, stop, hex[, mask])      -- 任意可读区间扫描
maps() -> array                          -- {start, stop, size, perms, path, ...}
```

```lua
local base = module_info("libc.so").base
print(string.format("0x%x", symbol("getpid", "libc.so")))

-- AOB 扫描（小端：指令 0x90000008 的字节是 08 00 00 90）
for _, a in ipairs(scan("libtutorial.so", "90000008")) do print(hexOf(a)) end

-- 扫堆
for _, r in ipairs(maps()) do
  if tostring(r.path):find("dalvik") then
    local hits = scanRange(r.start, r.stop, "c0 03 5f d6")   -- ret
    if #hits > 0 then print(#hits, "hits in", r.path) end
  end
end
```

> `scan` 会跳过 >64MB 的段；`scanRange` 稀疏 ~855MB/s、带掩码 ~1.6GB/s，
> 全零高密度场景会降到 ~17MB/s。

## 3. 内存读

```lua
readU8/I8/U16/I16/U32/I32(addr) -> number
readU64/I64(addr) -> number|"0x..."       -- 超 2^53 给字符串
readU64Num/I64Num(addr) -> number         -- 恒 number（可能丢精度）
readQwordHex(addr) -> "0x..."             -- 精确位串
readPtr/readPtrNum(addr) -> number        -- 自动剥 TBI tag
readPtrHex(addr) -> "0x..."               -- 带 tag 原值
readFloat/readDouble(addr) -> number
readBytes(addr, len) -> string            -- len ≤ 65536
readString(addr[, maxlen]) -> string
hexOf(x) / ptrOf(x) / u64(x) / untag(x)
```

```lua
local p = readPtrNum(base + 0x650d8)
print(readI32(p))
print(hexOf(p), untag(readPtrHex(p)))
```

## 4. 内存写 / 校验 / 导出

```lua
writeByte/Dword/Qword/Float/Double(addr, v) -> boolean
writePtr(addr, ptr) -> boolean
writeBytes(addr, s) -> boolean
writeString(addr, s[, with_nul]) -> boolean
verify(addr, hex[, mask]) -> true | false, offset, reason
dumpToFile(addr, len, path) -> true, bytes | nil, err
```

```lua
writeDword(ptr, 8888)
print(verify(ptr, "b8 22 00 00"))
dumpToFile(module_info("libc.so").base, 4096, "/data/data/<pkg>/files/head.bin")
```

## 5. 原生 hook

```lua
hookfunc(addr, fn) -> handle            -- instrument：原函数照常执行
hookfunc(addr, nativeAddr) -> handle    -- replace：整体替换
   handle = { addr, orig, trampoline, mode, :remove(), :hits(), :call_original(...) }
hookCPU(addr, fn) -> nil                -- 同 instrument（老写法）
removehook(addr) / remove_all_hook() / hooks()
hookAfter(addr, fn) -> id               -- 返回后回调：ctx.args[1..8], ctx.ret
afterHooks() / removeAfter(id)
regsOf(regs) -> {x0..x28, sp, fp, lr}
setReg(regs, name, value)
```

```lua
-- 观察调用次数
local h = hookfunc(base + m["openat"], function(regs, a)
  _G.n = (_G.n or 0) + 1
end)
print(h:hits()); h:remove()

-- 改返回值：直接挂现成 gadget（mov w0,wzr; ret），别造 RWX 页
local zero = scan("libc.so", "e0 03 1f 2a c0 03 5f d6")[1]
hookfunc(base + m["ptrace"], zero)

-- 看/改返回值
local id = hookAfter(base + m["getpid"], function(ctx)
  print("ret =", ctx.ret)
  return 12898
end)
removeAfter(id)
```

**铁律**：
- 回调里不能 `ffi.*` / 建表 / 拼字符串（会硬报错或崩溃）
- 不能从 Lua 调被 hook 的函数（重入必崩）
- replace 桩必须是原生地址，`hits()` 恒 0
- `hookAfter` 与 `hookfunc` 不能挂同一 target
- 高热函数别挂 Lua 回调

## 6. 栈回溯

```lua
nativeBacktrace([maxDepth]) -> array        -- {addr, module, offset, symbol}
nativeBacktraceInto(buf, max) -> count      -- 只填 PC，回调内使用（buf 必须预先分配）
nativeFrame(addr) -> {addr, module, offset, symbol}
javaStackTrace([maxDepth]) -> array         -- 当前 Java 线程栈
javaThreadStack([tid][, maxDepth]) -> array -- 任意 Java 线程（可传断点命中的 tid）
```

```lua
_G.BUF = ffi.new("uint64_t[64]")
hookfunc(addr, function(regs, a)
  if _G.N < 0 then _G.N = nativeBacktraceInto(_G.BUF, 64) end
end)

for i = 0, _G.N - 1 do
  local f = nativeFrame(tonumber(_G.BUF[i]))
  print(f.module, string.format("+0x%x", f.offset), f.symbol)
end

for _, fr in ipairs(javaStackTrace(12)) do print(fr.text) end
```

> `nativeBacktraceInto` 内部会 `dladdr`，在 `open`/`dlopen` 这类回调里会死锁（loader 锁自锁）。

## 7. ART / Java hook

```lua
artHook(class, method[, signature], fn) -> id | nil, err
   ctx = { id, this, args, signature }
   return nil  = 透传（调原方法）
   return 值   = 覆盖返回值（void 方法返回任意非 nil = 跳过原方法）
artHookAll(class, namePattern, fn)
artUnhook(id) -> boolean
artHooks() -> array
```

```lua
-- 拦截检测线程
artHook("com.example.crc_test.MainActivity$detectRunnable$1", "run", function(ctx)
  return true
end)

-- 拿对象
artHook("...MainActivity", "onResume", "()V", function(ctx)
  _G.ACT = ctx.this
  return nil
end)

local res = artHookAll("...MainActivity", "^on", function(ctx) return nil end)
```

> `artHook` 只能挂**本类声明**的方法；继承来的方法会 `method not found`。

## 8. Java 对象 / 类 / 值

```lua
javaFindClass(name) -> userdata | nil, err
javaNew(class, sig, ...) -> userdata | nil, err
javaCallStatic(class, method, sig, ...) -> value
javaGetStatic(class, name, sig) -> value | nil, err
javaSetStatic(class, name, sig, value) -> true | nil, err
javaFields(obj[, includeSuper]) -> array
javaDump(obj[, maxDepth]) -> string       -- 递归 + 环检测，默认深度 2
javaString(s) / javaBox(v) / javaValue(v)
obj:call(name, sig, ...) / obj:getField / obj:setField / obj:className() / obj[i] / obj:len()
```

```lua
local cls = javaFindClass("me.hd.ggtutorial.ui.activity.MainActivity")
print(javaGetStatic("android.os.Build$VERSION", "SDK_INT", "I"))
javaSetStatic("me.hd.ggtutorial.BuildConfig", "DEBUG", "Z", true)

local hm = javaNew("java.util.HashMap", "()V")
hm:call("put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;", "k1", "v1")
print(javaDump(hm, 2))
print(#javaFields(hm, true))

print(javaString("hello"):call("length", "()I"))
print(javaValue(javaBox(42)))
```

> Java 数组是 **0-based**，`#arr` 是长度；越界返回 nil 不报错。

## 9. 主线程 / 异步

```lua
call(fn) -> id            -- 排队到目标主线程（eglSwapBuffers / ALooper），兜底线程非主线程
call_done(id) -> true | false, err | "pending"
call_stats() -> {pending, done, last_err}
call_sync(fn, ...) -> ... -- 立即在当前线程执行并返回
msleep(ms)
print(...) / dump(v[, depth])
```

```lua
call(function() _G.NBT = nativeBacktrace(10) end)   -- run_lua 期间持锁，下个脚本再读结果
local v = call_sync(function(a) return a * 2 end, 21)  -- 42
```

## 10. 完整实战模板

```lua
-- ① 自检
dump(capabilities(), 1)

-- ② 找类
local cls = javaFindClass("com.example.crc_test.MainActivity$detectRunnable$1")

-- ③ 干掉检测线程
artHook("com.example.crc_test.MainActivity$detectRunnable$1", "run", function(ctx)
  return true
end)

-- ④ 拿对象看状态
artHook("me.hd.ggtutorial.ui.activity.MainActivity", "onResume", "()V", function(ctx)
  if not _G.ACT then
    _G.ACT = ctx.this
    _G.SNAP = javaDump(ctx.this, 1)
  end
  return nil
end)
```

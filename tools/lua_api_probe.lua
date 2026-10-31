-- lua_api_probe.lua —— 验证 ATrace 目标内 Lua API 是否正常（电脑端/手机端都能跑）
--
-- 用法（电脑端）：
--   atrace_lua.bat tools\lua_api_probe.lua
-- 用法（MCP）：把本文件内容作为 run_lua 的 script 传进去。
--
-- 输出解读：
--   [1] 函数数量应为 28（api() 自描述表）
--   [2] 校验类错误必须带函数名/具体原因
--   [3] hook 句柄应为 table，含 mode/addr/remove/hits
--   [4] ffi 调 strlen 触发 hook 后 hits 应 >= 1（重复命中计数问题是已知项）

local function section(t) print("===== " .. t .. " =====") end
local function try(name, fn)
  local ok, err = pcall(fn)
  print(string.format("%-34s -> %s", name, ok and "OK" or ("ERR: " .. tostring(err))))
end

section("[1] api() 自描述")
local a = api()
print("engine = " .. tostring(a.engine))
print("函数数 = " .. #a.functions)
print("notes 数 = " .. #a.notes)
local single = api("hookfunc")
print("api('hookfunc').sig = " .. tostring(single.sig))

section("[2] 参数校验（都必须报错且信息可读）")
try("hookfunc 只给 1 个参数", function() hookfunc(0x1234) end)
try("hookfunc(addr, 0) 空替换地址", function()
  hookfunc(getBase("libc.so") + 0xe2114, 0)
end)
try("hookfunc(addr, 'str') 类型错", function()
  hookfunc(getBase("libc.so") + 0xe2114, "oops")
end)
try("hookfunc(1, fn) 非可执行地址", function() hookfunc(1, function() end) end)
try("readDword() 缺参数（应显示函数名）", function() readDword() end)

section("[3] hook 句柄（table + 方法）")
local libc = getBase("libc.so")
local ffi = require("ffi")
ffi.cdef[[ size_t strlen(const char*); ]]
local addr = libc + 0xe2114              -- strlen
removehook(addr)
local H = hookfunc(addr, function(regs, x) end)
print("handle type = " .. type(H) .. "  mode = " .. tostring(H.mode) ..
      "  addr = 0x" .. string.format("%x", H.addr))
print("有 remove = " .. tostring(H.remove ~= nil) ..
      "  有 hits = " .. tostring(H.hits ~= nil) ..
      "  有 call_original = " .. tostring(H.call_original ~= nil))

section("[4] 触发回调并计数")
local n = ffi.C.strlen("hello")
print("ffi strlen = " .. tostring(n))
print("hits = " .. tostring(H:hits()))
print("remove = " .. tostring(H:remove()))

section("[5] regsOf / setReg（hookCPU 回调里用）")
local function regs_demo()
  removehook(addr)
  hookCPU(addr, function(regs, target_addr)
    local r = regsOf(regs)
    print(string.format("[hookCPU] x0=0x%x lr=0x%x sp=0x%x",
      tonumber(r.x0) or 0, tonumber(r.lr) or 0, tonumber(r.sp) or 0))
    setReg(regs, "x20", 0x1234)          -- 演示改寄存器
  end)
  ffi.C.strlen("xyz")
  msleep(200)
  remove_all_hook()
end
try("hookCPU + regsOf/setReg", regs_demo)

print("===== 探针结束 =====")

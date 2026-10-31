#pragma once
// C ABI between the C++20 LSPlant translation unit (ArtHook.cpp) and the
// C++17 Lua engine (LuaEngine.h). Keep this header free of C++20 features.
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct atrace_lua_result {
    int has_value;      // 1 = Lua callback returned a value that overrides the Java result
    jobject value;      // local ref, valid until the native callback returns
} atrace_lua_result;

// Called from a Java thread while the hooked method is running.
// args = Object[] as LSPlant builds it (args[0] is `this` for non-static methods).
// method_desc = FULL JNI descriptor of the hooked method, e.g. "(Ljava/lang/String;)V"
// ret_desc    = return type descriptor only, e.g. "V" / "I" / "Ljava/lang/String;"
typedef atrace_lua_result (*atrace_lua_call_fn)(int hook_id, jobjectArray args,
                                               const char* method_desc,
                                               const char* ret_desc, int is_static);
typedef void (*atrace_log_fn)(const char* msg);

void atrace_arthook_set_javavm(JavaVM* vm);
void atrace_arthook_set_lua_bridge(atrace_lua_call_fn call, atrace_log_fn log);
JNIEnv* atrace_arthook_env(void);
int  atrace_arthook_ready(void);

// P0-2 diagnostics (one line + "\n" + last error line):
//   init=<0|1> vm=<ptr|(nil)> vmSource=<none|JNI_OnLoad|dlsym-probe> currentThreadAttached=<0|1>
//   lastError=<text|(none)>
// Returns bytes written (excluding NUL), 0 when out/cap are invalid.
int  atrace_arthook_vm_state(char* out, int cap);

int  atrace_arthook_install(const char* cls, const char* name, const char* sig,
                            int lua_ref, char* err, int err_cap);
int  atrace_arthook_unhook(int hook_id, int* lua_ref_out);
int  atrace_arthook_luaref(int hook_id);
int  atrace_arthook_list(char* out, int cap);

// ---- Java object access (used by Lua :call / :getField / :setField / javaNew) ----
// All returned jobjects are local refs. On failure return NULL with err filled.
// NOTE: err[0] == 0 means success, so a void method also legitimately returns NULL.
jobject atrace_java_call(jobject obj, const char* name, const char* sig,
                         jobjectArray args, char* err, int cap);
jobject atrace_java_get_field(jobject obj, const char* name, const char* sig,
                              char* err, int cap);
int atrace_java_set_field(jobject obj, const char* name, const char* sig,
                          jobject value, char* err, int cap);
jobject atrace_java_new(const char* cls, const char* sig, jobjectArray args,
                        char* err, int cap);
int atrace_java_class_name(jobject obj, char* out, int cap);

// P1-9: static call (class loaded through the app class loader; inherited
// statics resolve via GetStaticMethodID, else reflection fallback).
jobject atrace_java_call_static(const char* cls, const char* name, const char* sig,
                                jobjectArray args, char* err, int cap);

// P1-8: dump fields, one line per field: name|descriptor|valueText\n
// (include_super != 0 walks the superclass chain; interfaces are not walked).
// valueText: primitives via their boxed toString, String raw, null -> "null",
// other objects via toString. Returns bytes written (excluding NUL) and
// NUL-terminates out; returns -1 on error (out then holds the error text).
// Truncated to cap-1 bytes when the field list does not fit.
int atrace_java_fields(jobject obj, int include_super, char* out, int cap);

// P1-10: 1 = array, 0 = not an array / invalid object.
int atrace_java_is_array(jobject obj);
// Returns the array length, or -1 when obj is null / not an array.
// elem_desc (if non-null) receives the element descriptor, e.g. I / [B /
// Ljava/lang/String; and is set to "" on failure.
int atrace_java_array_len(jobject obj, char* elem_desc, int cap);
// Returns the element at idx: primitives are boxed (Integer/Long/...), object
// elements are returned as a local ref. NULL + err on failure (not an array,
// index out of range, unsupported element type).
jobject atrace_java_array_get(jobject obj, int idx, char* err, int cap);

// Thread.currentThread().getStackTrace(). One frame per line:
//   className|methodName|fileName|lineNumber|isNative(0|1)\n
// max_depth <= 0 -> default 64. Returns bytes written (excluding NUL) and
// NUL-terminates out; returns -1 on error (out then holds the error text) or
// when the current thread has no Java frames (out empty).
int atrace_java_stack_trace(char* out, int cap, int max_depth);

// selected by Linux tid (on Android Thread.getId() == gettid()).
// Uses Thread.getAllStackTraces(), which briefly suspends the runtime, so call
// it on demand (debugger polling), never in a hot path. Same output format as
// atrace_java_stack_trace. tid <= 0 -> current thread. Returns -1 + error text
// when the tid is not a Java (attached) thread.
int atrace_java_thread_stack(int tid, char* out, int cap, int max_depth);

// (Class.forName(name, false, appClassLoader)), falling back to JNI FindClass
// (boot classloader / array descriptors). Returns a local ref to the jclass, or
// NULL with err filled ("类不存在: ..."). This fixes the silent nil that
// Class.forName(name) gives for app classes (it only sees the boot loader).
jobject atrace_java_find_class(const char* name, char* err, int cap);
// "name|signature" lines (skipping native/abstract, deduped). Returns the number
// of methods, or -1 with err filled. Used by the Lua artHookAll().
int atrace_arthook_list_methods(const char* cls, char* out, int cap,
                                char* err, int errcap);
// for static constants such as TAG / VERSION).
jobject atrace_java_get_static_field(const char* cls, const char* name, const char* sig,
                                     char* err, int cap);
int atrace_java_set_static_field(const char* cls, const char* name, const char* sig,
                                 jobject value, char* err, int cap);

#ifdef __cplusplus
}
#endif

// ArtHook.cpp -- Java/ART method hooking for the agent (LSPlant + Dobby).
// Built as C++20 (LSPlant headers use std::span); the rest of the agent stays C++17.
#include <jni.h>
#include <android/log.h>
#include <dobby.h>
#include <lsplant.hpp>

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <xdl_lzma.h>

#include "ArtHookApi.h"
#include "hook_stub_dex.h"

#define AH_TAG "ArtHook"
#define AH_LOG(...) __android_log_print(ANDROID_LOG_INFO, AH_TAG, __VA_ARGS__)
#define AH_ERR(...) __android_log_print(ANDROID_LOG_ERROR, AH_TAG, __VA_ARGS__)

namespace {

std::atomic<JavaVM*> g_vm{nullptr};
atrace_lua_call_fn g_lua_call = nullptr;
atrace_log_fn g_log = nullptr;

std::mutex g_init_mu;
bool g_inited = false;

// P0-2 diagnostics: distinguish "VM was never handed to us" from "attach failed".
std::mutex g_state_mu;
int g_vm_source = 0;  // 0 = none, 1 = JNI_OnLoad/atrace_arthook_set_javavm, 2 = dlsym probe
std::string g_last_err;

void SetLastErr(const std::string& m) {
    if (m.empty()) return;
    std::lock_guard<std::mutex> lk(g_state_mu);
    g_last_err = m;
}

std::string GetLastErr() {
    std::lock_guard<std::mutex> lk(g_state_mu);
    return g_last_err;
}

typedef jint (*GetCreatedJavaVMsFn)(JavaVM**, jsize, jsize*);

// P0-2: the agent may be injected without JNI_OnLoad ever running (or Env() may
// be called before JNI_OnLoad). libart always exports JNI_GetCreatedJavaVMs;
// use it as a fallback when atrace_arthook_set_javavm() was never called.
JavaVM* ProbeCreatedJavaVM() {
    static GetCreatedJavaVMsFn fn = []() -> GetCreatedJavaVMsFn {
        return reinterpret_cast<GetCreatedJavaVMsFn>(
            dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs"));
    }();
    if (!fn) return nullptr;
    JavaVM* vms[1] = {nullptr};
    jsize count = 0;
    if (fn(vms, 1, &count) != JNI_OK || count <= 0 || !vms[0]) return nullptr;
    return vms[0];
}

// ---------- libart symbol resolver (dynsym + symtab of the on-disk file) ----------
struct ArtElf {
    uintptr_t base = 0;
    std::unordered_map<std::string, uint64_t> by_name;
    std::vector<std::string> sorted_names;
};
ArtElf g_art;

bool LoadArtElf() {
    if (g_art.base != 0 && !g_art.by_name.empty()) return true;
    std::string path;
    uintptr_t base = 0;
    if (FILE* f = fopen("/proc/self/maps", "re")) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            if (!strstr(line, "libart.so")) continue;
            if (!strstr(line, "r--p") && !strstr(line, "r-xp") && !strstr(line, "rw-p")) continue;
            unsigned long long start = 0, end = 0, off = 0;
            char perms[8] = {0};
            char dev[16] = {0};
            unsigned long long ino = 0;
            if (sscanf(line, "%llx-%llx %7s %llx %15s %llu", &start, &end, perms, &off, dev, &ino) != 6) continue;
            char* p = strchr(line, '/');
            if (!p) continue;
            std::string candidate(p);
            while (!candidate.empty() && (candidate.back() == '\n' || candidate.back() == '\r' || candidate.back() == ' '))
                candidate.pop_back();
            if (path.empty()) { base = (uintptr_t)start; path = candidate; }
        }
        fclose(f);
    }
    if (path.empty()) { AH_ERR("LoadArtElf: libart.so not found in maps"); return false; }
    FILE* fp = fopen(path.c_str(), "rb");
    if (!fp) { AH_ERR("LoadArtElf: open %s failed", path.c_str()); return false; }
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (size <= 0) { fclose(fp); return false; }
    std::vector<uint8_t> buf((size_t)size);
    size_t got = fread(buf.data(), 1, buf.size(), fp);
    fclose(fp);
    if (got != buf.size()) return false;

    auto* eh = reinterpret_cast<Elf64_Ehdr*>(buf.data());
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0 || eh->e_shoff == 0) {
        AH_ERR("LoadArtElf: bad ELF header");
        return false;
    }
    auto* sh = reinterpret_cast<Elf64_Shdr*>(buf.data() + eh->e_shoff);
    int shnum = eh->e_shnum;
    if (shnum <= 0 || eh->e_shentsize != sizeof(Elf64_Shdr)) return false;
    const char* shstr = nullptr;
    size_t shstr_size = 0;
    if (eh->e_shstrndx < shnum) {
        shstr = reinterpret_cast<const char*>(buf.data() + sh[eh->e_shstrndx].sh_offset);
        shstr_size = sh[eh->e_shstrndx].sh_size;
    }
    (void)shstr_size;
    int loaded = 0;
    for (int i = 0; i < shnum; ++i) {
        if (sh[i].sh_type != SHT_DYNSYM && sh[i].sh_type != SHT_SYMTAB) continue;
        if (sh[i].sh_entsize != sizeof(Elf64_Sym) || sh[i].sh_link >= (unsigned)shnum) continue;
        const Elf64_Shdr& strsec = sh[sh[i].sh_link];
        const char* strtab = reinterpret_cast<const char*>(buf.data() + strsec.sh_offset);
        size_t strsz = strsec.sh_size;
        auto* syms = reinterpret_cast<Elf64_Sym*>(buf.data() + sh[i].sh_offset);
        size_t count = sh[i].sh_size / sizeof(Elf64_Sym);
        for (size_t k = 0; k < count; ++k) {
            if (syms[k].st_name == 0 || syms[k].st_name >= strsz) continue;
            if (syms[k].st_value == 0) continue;
            const char* nm = strtab + syms[k].st_name;
            if (!nm || !nm[0]) continue;
            if (g_art.by_name.emplace(nm, syms[k].st_value).second) g_art.sorted_names.emplace_back(nm);
            ++loaded;
        }
    }

    // Android strips .symtab from libart.so but keeps .gnu_debugdata
    // (a compressed mini ELF that only contains .symtab/.strtab). LSPlant needs
    // several hidden art symbols that are not exported in .dynsym, so parse it too.
    if (shstr) {
        for (int i = 0; i < shnum; ++i) {
            if (sh[i].sh_type != SHT_PROGBITS) continue;
            if (sh[i].sh_offset + sh[i].sh_size > buf.size()) continue;
            const char* nm = shstr + sh[i].sh_name;
            if (strcmp(nm, ".gnu_debugdata") != 0) continue;
            uint8_t* out = nullptr;
            size_t outsz = 0;
            if (xdl_lzma_decompress(buf.data() + sh[i].sh_offset, sh[i].sh_size, &out, &outsz) != 0 || !out) {
                AH_ERR("LoadArtElf: gnu_debugdata decompress failed");
                break;
            }
            auto* ieh = reinterpret_cast<Elf64_Ehdr*>(out);
            if (memcmp(ieh->e_ident, ELFMAG, SELFMAG) == 0 && ieh->e_shoff != 0 &&
                ieh->e_shoff + (uint64_t)ieh->e_shnum * sizeof(Elf64_Shdr) <= outsz &&
                ieh->e_shentsize == sizeof(Elf64_Shdr)) {
                auto* ish = reinterpret_cast<Elf64_Shdr*>(out + ieh->e_shoff);
                int added = 0;
                for (int j = 0; j < ieh->e_shnum; ++j) {
                    if (ish[j].sh_type != SHT_SYMTAB && ish[j].sh_type != SHT_DYNSYM) continue;
                    if (ish[j].sh_entsize != sizeof(Elf64_Sym) || ish[j].sh_link >= (unsigned)ieh->e_shnum) continue;
                    if (ish[j].sh_offset + ish[j].sh_size > outsz) continue;
                    const Elf64_Shdr& istr = ish[ish[j].sh_link];
                    if (istr.sh_offset + istr.sh_size > outsz) continue;
                    const char* istrtab = reinterpret_cast<const char*>(out + istr.sh_offset);
                    auto* isyms = reinterpret_cast<Elf64_Sym*>(out + ish[j].sh_offset);
                    size_t icount = ish[j].sh_size / sizeof(Elf64_Sym);
                    for (size_t k = 0; k < icount; ++k) {
                        if (isyms[k].st_name == 0 || isyms[k].st_name >= istr.sh_size) continue;
                        if (isyms[k].st_value == 0) continue;
                        const char* iname = istrtab + isyms[k].st_name;
                        if (!iname || !iname[0]) continue;
                        if (g_art.by_name.emplace(iname, isyms[k].st_value).second) {
                            g_art.sorted_names.emplace_back(iname);
                            ++added;
                        }
                    }
                }
                AH_LOG("gnu_debugdata: +%d hidden symbols", added);
            }
            free(out);
            break;
        }
    }
    if (loaded == 0) { AH_ERR("LoadArtElf: no symbols parsed from %s", path.c_str()); return false; }
    std::sort(g_art.sorted_names.begin(), g_art.sorted_names.end());
    g_art.base = base;
    AH_LOG("libart symbols: %zu entries (base=0x%lx, %s)", g_art.by_name.size(), (unsigned long)base, path.c_str());
    return true;
}

void* ResolveSymbol(std::string_view name) {
    auto it = g_art.by_name.find(std::string(name));
    if (it == g_art.by_name.end()) return nullptr;
    return reinterpret_cast<void*>(g_art.base + (uintptr_t)it->second);
}

void* ResolvePrefix(std::string_view prefix) {
    for (const auto& n : g_art.sorted_names) {
        if (n.size() >= prefix.size() && n.compare(0, prefix.size(), prefix) == 0)
            return reinterpret_cast<void*>(g_art.base + (uintptr_t)g_art.by_name[n]);
    }
    return nullptr;
}

// ---------- inline hooker for LSPlant ----------
bool MakePageWritable(void* addr) {
    long ps = sysconf(_SC_PAGESIZE);
    uintptr_t page = reinterpret_cast<uintptr_t>(addr) & ~(uintptr_t)(ps - 1);
    return mprotect(reinterpret_cast<void*>(page), (size_t)ps,
                    PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

void* InlineHooker(void* target, void* hooker) {
    MakePageWritable(target);
    void* backup = nullptr;
    if (DobbyHook(target, hooker, &backup) == 0) return backup;
    return nullptr;
}

bool InlineUnhooker(void* func) { return DobbyDestroy(func) == 0; }

// ---------- JNI helpers ----------
// P0-2: on failure *err gets a message that tells VM-not-initialized apart from
// attach failures (the old code returned a bare nullptr and callers printed
// "no JNIEnv", which made the two cases indistinguishable).
JNIEnv* EnvWithError(std::string* err) {
    JavaVM* vm = g_vm.load();
    if (!vm) {
        vm = ProbeCreatedJavaVM();
        if (vm) {
            {
                std::lock_guard<std::mutex> lk(g_state_mu);
                if (!g_vm.load()) {
                    g_vm.store(vm);
                    g_vm_source = 2;
                }
                vm = g_vm.load();
            }
            AH_LOG("JavaVM recovered via JNI_GetCreatedJavaVMs: %p", (void*)vm);
        }
    }
    if (!vm) {
        std::string m =
            "vm 未初始化: JNI_GetCreatedJavaVMs 未取得 JavaVM（agent 可能未经 JNI_OnLoad 注入）";
        SetLastErr(m);
        if (err) *err = m;
        return nullptr;
    }
    JNIEnv* env = nullptr;
    jint r = vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6);
    if (r == JNI_EDETACHED) {
        if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK || !env) {
            std::string m = "attach 失败: AttachCurrentThread 未能把当前线程附加到 JVM";
            SetLastErr(m);
            if (err) *err = m;
            return nullptr;
        }
    } else if (r != JNI_OK) {
        char b[160];
        snprintf(b, sizeof(b), "attach 失败: GetEnv 返回 %d（VM 存在但当前线程不可用）", (int)r);
        SetLastErr(b);
        if (err) *err = b;
        return nullptr;
    }
    if (!env) {
        std::string m = "attach 失败: JVM 返回空 JNIEnv";
        SetLastErr(m);
        if (err) *err = m;
        return nullptr;
    }
    return env;
}

JNIEnv* Env() { return EnvWithError(nullptr); }

jobject GetAppClassLoader(JNIEnv* env) {
    if (!env) return nullptr;
    jclass at_cls = env->FindClass("android/app/ActivityThread");
    if (at_cls) {
        jmethodID cur = env->GetStaticMethodID(at_cls, "currentApplication",
                                               "()Landroid/app/Application;");
        if (cur) {
            jobject app = env->CallStaticObjectMethod(at_cls, cur);
            if (env->ExceptionCheck()) env->ExceptionClear();
            if (app) {
                jclass app_cls = env->GetObjectClass(app);
                jmethodID get_cl = env->GetMethodID(app_cls, "getClassLoader",
                                                    "()Ljava/lang/ClassLoader;");
                if (get_cl) return env->CallObjectMethod(app, get_cl);
            }
        }
    }
    if (env->ExceptionCheck()) env->ExceptionClear();
    jclass cl_cls = env->FindClass("java/lang/ClassLoader");
    jmethodID sys = env->GetStaticMethodID(cl_cls, "getSystemClassLoader",
                                           "()Ljava/lang/ClassLoader;");
    if (!sys) return nullptr;
    return env->CallStaticObjectMethod(cl_cls, sys);
}

std::string ClassDescriptor(JNIEnv* env, jclass cls) {
    if (!cls) { env->ExceptionClear(); return "?"; }
    jclass class_cls = env->FindClass("java/lang/Class");
    if (!class_cls) { env->ExceptionClear(); return "?"; }
    jmethodID get_name = env->GetMethodID(class_cls, "getName", "()Ljava/lang/String;");
    env->DeleteLocalRef(class_cls);
    if (!get_name) { env->ExceptionClear(); return "?"; }
    jstring js = reinterpret_cast<jstring>(env->CallObjectMethod(cls, get_name));
    if (!js) { env->ExceptionClear(); return "?"; }
    const char* cs = env->GetStringUTFChars(js, nullptr);
    std::string n = cs ? cs : "?";
    if (cs) env->ReleaseStringUTFChars(js, cs);
    env->DeleteLocalRef(js);
    if (n.empty()) return "?";
    if (n[0] == '[') {
        for (char& c : n) if (c == '.') c = '/';
        return n;
    }
    if (n == "void") return "V";
    if (n == "boolean") return "Z";
    if (n == "byte") return "B";
    if (n == "char") return "C";
    if (n == "short") return "S";
    if (n == "int") return "I";
    if (n == "long") return "J";
    if (n == "float") return "F";
    if (n == "double") return "D";
    for (char& c : n) if (c == '.') c = '/';
    return "L" + n + ";";
}

bool FindClassByName(JNIEnv* env, const char* name, jobject loader, jclass* out) {
    jclass class_cls = env->FindClass("java/lang/Class");
    jmethodID for_name = env->GetStaticMethodID(
        class_cls, "forName",
        "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;");
    if (!for_name) return false;
    jstring jn = env->NewStringUTF(name);
    jobject cls = env->CallStaticObjectMethod(class_cls, for_name, jn, JNI_FALSE, loader);
    bool ok = false;
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    } else if (cls) {
        *out = reinterpret_cast<jclass>(cls);
        ok = true;
    }
    env->DeleteLocalRef(jn);
    return ok;
}

struct MethodHit {
    jobject method = nullptr;
    std::string desc;
    bool is_static = false;
};

bool FindMethod(JNIEnv* env, jclass cls, const char* name, const char* sig,
                MethodHit* out, std::string* err) {
    jclass class_cls = env->FindClass("java/lang/Class");
    if (!class_cls) { env->ExceptionClear(); *err = "java.lang.Class not found"; return false; }
    jmethodID get_methods = env->GetMethodID(class_cls, "getDeclaredMethods",
                                             "()[Ljava/lang/reflect/Method;");
    if (!get_methods) {
        env->ExceptionClear();
        env->DeleteLocalRef(class_cls);
        *err = "Class.getDeclaredMethods not found";
        return false;
    }
    jobjectArray arr = reinterpret_cast<jobjectArray>(
        env->CallObjectMethod(cls, get_methods));
    env->DeleteLocalRef(class_cls);
    if (!arr) {
        env->ExceptionClear();
        *err = "getDeclaredMethods returned null (SecurityException?)";
        return false;
    }
    jclass method_cls = env->FindClass("java/lang/reflect/Method");
    if (!method_cls) {
        env->ExceptionClear();
        env->DeleteLocalRef(arr);
        *err = "java.lang.reflect.Method not found";
        return false;
    }
    jmethodID m_name = env->GetMethodID(method_cls, "getName", "()Ljava/lang/String;");
    jmethodID m_ret = env->GetMethodID(method_cls, "getReturnType", "()Ljava/lang/Class;");
    jmethodID m_params = env->GetMethodID(method_cls, "getParameterTypes",
                                          "()[Ljava/lang/Class;");
    jmethodID m_mods = env->GetMethodID(method_cls, "getModifiers", "()I");
    env->DeleteLocalRef(method_cls);
    if (!m_name || !m_ret || !m_params || !m_mods) {
        env->ExceptionClear();
        env->DeleteLocalRef(arr);
        *err = "java.lang.reflect.Method accessors unavailable";
        return false;
    }
    int n = env->GetArrayLength(arr);
    std::vector<MethodHit> hits;
    std::string candidates;
    for (int i = 0; i < n; ++i) {
        jobject m = env->GetObjectArrayElement(arr, i);
        jstring js = reinterpret_cast<jstring>(env->CallObjectMethod(m, m_name));
        if (!js) { env->ExceptionClear(); env->DeleteLocalRef(m); continue; }
        const char* cs = env->GetStringUTFChars(js, nullptr);
        bool same = cs && strcmp(cs, name) == 0;
        env->ReleaseStringUTFChars(js, cs);
        env->DeleteLocalRef(js);
        if (!same) { env->DeleteLocalRef(m); continue; }
        jobjectArray params = reinterpret_cast<jobjectArray>(
            env->CallObjectMethod(m, m_params));
        if (env->ExceptionCheck()) { env->ExceptionClear(); params = nullptr; }
        std::string desc = "(";
        int pn = params ? env->GetArrayLength(params) : 0;
        for (int p = 0; p < pn; ++p) {
            jobject pc = env->GetObjectArrayElement(params, p);
            desc += ClassDescriptor(env, reinterpret_cast<jclass>(pc));
            env->DeleteLocalRef(pc);
        }
        desc += ")";
        jclass ret = reinterpret_cast<jclass>(env->CallObjectMethod(m, m_ret));
        if (env->ExceptionCheck()) { env->ExceptionClear(); ret = nullptr; }
        desc += ClassDescriptor(env, ret);
        if (ret) env->DeleteLocalRef(ret);
        if (params) env->DeleteLocalRef(params);
        if (!sig || !sig[0] || desc == sig) {
            MethodHit hit;
            hit.method = m;
            hit.desc = desc;
            jint mods = env->CallIntMethod(m, m_mods);
            if (env->ExceptionCheck()) { env->ExceptionClear(); mods = 0; }
            hit.is_static = (mods & 0x0008) != 0;
            hits.push_back(hit);
        } else {
            candidates += desc + " ";
        }
        if (hits.size() > 8) break;
    }
    env->DeleteLocalRef(arr);
    if (hits.empty()) {
        *err = std::string("method not found: ") + name +
               (sig && sig[0] ? std::string(" ") + sig : std::string()) +
               (candidates.empty() ? "" : (" (others: " + candidates + ")"));
        return false;
    }
    if (hits.size() > 1 && (!sig || !sig[0])) {
        std::string list;
        for (auto& h : hits) list += h.desc + " ";
        *err = std::string("ambiguous method: ") + name + " -> " + list + "(pass signature)";
        for (auto& h : hits) env->DeleteLocalRef(h.method);
        return false;
    }
    *out = hits[0];
    for (size_t i = 1; i < hits.size(); ++i) env->DeleteLocalRef(hits[i].method);
    return true;
}

// ---------- stub class (dex is embedded) ----------
jclass g_stub_cls = nullptr;
jmethodID g_stub_ctor = nullptr;
jfieldID g_stub_id_field = nullptr;
jobject g_stub_cb_method = nullptr;   // java.lang.reflect.Method for callback(Object[])

jobject JNICALL StubCallback(JNIEnv* env, jobject thiz, jobjectArray args);

bool EnsureStub(JNIEnv* env, std::string* err) {
    if (g_stub_cls) return true;
    jobject bb = env->NewDirectByteBuffer(const_cast<unsigned char*>(kHookStubDex),
                                          (jlong)kHookStubDexLen);
    if (!bb) { *err = "NewDirectByteBuffer failed"; return false; }
    jclass cl_cls = env->FindClass("java/lang/ClassLoader");
    jmethodID get_sys = env->GetStaticMethodID(cl_cls, "getSystemClassLoader",
                                               "()Ljava/lang/ClassLoader;");
    jobject parent = env->CallStaticObjectMethod(cl_cls, get_sys);
    jclass im_cls = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (!im_cls) { *err = "InMemoryDexClassLoader not found (need API 26+)"; return false; }
    jmethodID ctor = env->GetMethodID(im_cls, "<init>",
                                      "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (!ctor) { *err = "InMemoryDexClassLoader.<init> not found"; return false; }
    jobject loader = env->NewObject(im_cls, ctor, bb, parent);
    if (!loader) { *err = "create InMemoryDexClassLoader failed"; return false; }
    jmethodID load_class = env->GetMethodID(cl_cls, "loadClass",
                                            "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring cn = env->NewStringUTF("atrace.HookStub");
    jclass stub = reinterpret_cast<jclass>(env->CallObjectMethod(loader, load_class, cn));
    if (env->ExceptionCheck() || !stub) {
        env->ExceptionClear();
        *err = "load atrace.HookStub failed";
        return false;
    }
    g_stub_cls = reinterpret_cast<jclass>(env->NewGlobalRef(stub));
    g_stub_ctor = env->GetMethodID(g_stub_cls, "<init>", "()V");
    g_stub_id_field = env->GetFieldID(g_stub_cls, "id", "J");
    JNINativeMethod natives[] = {
        {const_cast<char*>("callback"),
         const_cast<char*>("([Ljava/lang/Object;)Ljava/lang/Object;"),
         reinterpret_cast<void*>(StubCallback)},
    };
    if (env->RegisterNatives(g_stub_cls, natives, 1) != 0) {
        env->ExceptionClear();
        *err = "RegisterNatives(callback) failed";
        return false;
    }
    jclass class_cls = env->FindClass("java/lang/Class");
    jmethodID get_declared = env->GetMethodID(
        class_cls, "getDeclaredMethod",
        "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
    jclass class_meta_cls = env->FindClass("java/lang/Class");
    jclass obj_array_cls = env->FindClass("[Ljava/lang/Object;");
    // element type is java.lang.Class; the single element is the Class object of Object[]
    jobjectArray params = env->NewObjectArray(1, class_meta_cls, obj_array_cls);
    jstring cb_name = env->NewStringUTF("callback");
    jobject cb = env->CallObjectMethod(g_stub_cls, get_declared, cb_name, params);
    if (env->ExceptionCheck() || !cb) {
        env->ExceptionClear();
        *err = "getDeclaredMethod(callback) failed";
        return false;
    }
    g_stub_cb_method = env->NewGlobalRef(cb);
    AH_LOG("stub class ready");
    return true;
}

// ---------- hook registry ----------
struct HookRec {
    int id = 0;
    jobject target = nullptr;   // global ref: java.lang.reflect.Method
    jobject backup = nullptr;   // global ref: java.lang.reflect.Method
    int lua_ref = 0;
    std::string desc;         // full JNI signature, e.g. (I)I
    std::string return_desc;  // return type only, e.g. I / Ljava/lang/String;
    bool is_static = false;
    std::string cls;
    std::string name;
    uint64_t hits = 0;
    uint64_t installed_ms = 0;
};

std::mutex g_hooks_mu;
std::unordered_map<int, HookRec> g_hooks;
int g_next_id = 1;

jobject CallBackup(JNIEnv* env, const HookRec& rec, jobjectArray args) {
    jclass method_cls = env->FindClass("java/lang/reflect/Method");
    jmethodID invoke = env->GetMethodID(method_cls, "invoke",
                                        "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    jobject obj = nullptr;
    jobjectArray call_args = args;
    if (!rec.is_static) {
        int n = args ? env->GetArrayLength(args) : 0;
        if (n <= 0) return nullptr;
        obj = env->GetObjectArrayElement(args, 0);
        jclass obj_cls = env->FindClass("java/lang/Object");
        call_args = env->NewObjectArray(n - 1, obj_cls, nullptr);
        for (int i = 1; i < n; ++i) {
            jobject a = env->GetObjectArrayElement(args, i);
            env->SetObjectArrayElement(call_args, i - 1, a);
            env->DeleteLocalRef(a);
        }
    }
    jobject ret = env->CallObjectMethod(rec.backup, invoke, obj, call_args);
    if (env->ExceptionCheck()) {
        AH_ERR("backup invoke threw");
        env->ExceptionDescribe();
        env->ExceptionClear();
        ret = nullptr;
    }
    return ret;
}

jobject JNICALL StubCallback(JNIEnv* env, jobject thiz, jobjectArray args) {
    int id = (int)env->GetLongField(thiz, g_stub_id_field);
    HookRec rec;
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(g_hooks_mu);
        auto it = g_hooks.find(id);
        if (it != g_hooks.end()) {
            it->second.hits++;   // P1-11：命中计数（artHooks 可见）
            rec = it->second;
            found = true;
        }
    }
    if (!found) return CallBackup(env, rec, args);
    atrace_lua_result r{};
    if (g_lua_call) r = g_lua_call(id, args, rec.desc.c_str(), rec.return_desc.c_str(),
                                   rec.is_static ? 1 : 0);
    if (r.has_value) return r.value;
    return CallBackup(env, rec, args);
}

// ---------- init ----------
bool EnsureInit(JNIEnv* env, std::string* err) {
    std::lock_guard<std::mutex> lk(g_init_mu);
    if (g_inited) return true;
    if (!env) {
        *err = "LSPlant init 失败: JNIEnv 为空（VM 未初始化或 attach 失败）";
        SetLastErr(*err);
        return false;
    }
    if (!LoadArtElf()) {
        *err = "LSPlant init 失败: 解析 libart.so 符号失败（/proc/self/maps 或 ELF/gnu_debugdata 解析失败）";
        SetLastErr(*err);
        return false;
    }
    lsplant::InitInfo info{};
    info.inline_hooker = InlineHooker;
    info.inline_unhooker = InlineUnhooker;
    info.art_symbol_resolver = [](std::string_view s) -> void* { return ResolveSymbol(s); };
    info.art_symbol_prefix_resolver = [](std::string_view s) -> void* { return ResolvePrefix(s); };
    if (!lsplant::Init(env, info)) {
        *err = "LSPlant init 失败: lsplant::Init 返回 false（ART 符号缺失或 inline hooker 失败，见 logcat ArtHook/LSPlant）";
        SetLastErr(*err);
        return false;
    }
    if (!EnsureStub(env, err)) {
        *err = "stub 初始化失败: " + *err;
        SetLastErr(*err);
        return false;
    }
    g_inited = true;
    AH_LOG("LSPlant initialized");
    return true;
}


// ---------- Java object access helpers (Lua :call / :getField / :setField / javaNew) ----------
jmethodID MethodInvokeMID(JNIEnv* env) {
    jclass cls = env->FindClass("java/lang/reflect/Method");
    return env->GetMethodID(cls, "invoke",
                            "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
}

void TrySetAccessible(JNIEnv* env, jobject accessible) {
    jclass acc = env->FindClass("java/lang/reflect/AccessibleObject");
    if (!acc) { env->ExceptionClear(); return; }
    jmethodID m = env->GetMethodID(acc, "setAccessible", "(Z)V");
    if (m) env->CallVoidMethod(accessible, m, JNI_TRUE);
    if (env->ExceptionCheck()) env->ExceptionClear();
}

// Unboxes a boxed primitive into a jvalue. Returns false (with any pending
// exception cleared) when o is null / not the expected box class. Object and
// array types are copied through as jvalue.l.
bool UnboxValueEx(JNIEnv* env, char t, jobject o, jvalue* out) {
    *out = jvalue{};
    if (!o) return false;
    const char* cls_name = nullptr;
    const char* method = nullptr;
    const char* method_sig = nullptr;
    switch (t) {
    case 'Z': cls_name = "java/lang/Boolean"; method = "booleanValue"; method_sig = "()Z"; break;
    case 'B': cls_name = "java/lang/Byte"; method = "byteValue"; method_sig = "()B"; break;
    case 'S': cls_name = "java/lang/Short"; method = "shortValue"; method_sig = "()S"; break;
    case 'I': cls_name = "java/lang/Integer"; method = "intValue"; method_sig = "()I"; break;
    case 'J': cls_name = "java/lang/Long"; method = "longValue"; method_sig = "()J"; break;
    case 'F': cls_name = "java/lang/Float"; method = "floatValue"; method_sig = "()F"; break;
    case 'D': cls_name = "java/lang/Double"; method = "doubleValue"; method_sig = "()D"; break;
    case 'C': cls_name = "java/lang/Character"; method = "charValue"; method_sig = "()C"; break;
    default:
        out->l = o;  // object / array: passed through unchanged
        return true;
    }
    jclass c = env->FindClass(cls_name);
    if (!c) { env->ExceptionClear(); return false; }
    // Guard against calling e.g. Long.longValue() on an Integer: ART does not
    // type-check jmethodID vs receiver and would read the wrong object layout.
    if (!env->IsInstanceOf(o, c)) {
        env->DeleteLocalRef(c);
        return false;
    }
    jmethodID m = env->GetMethodID(c, method, method_sig);
    if (!m) { env->ExceptionClear(); env->DeleteLocalRef(c); return false; }
    switch (t) {
    case 'Z': out->z = env->CallBooleanMethod(o, m); break;
    case 'B': out->b = env->CallByteMethod(o, m); break;
    case 'S': out->s = env->CallShortMethod(o, m); break;
    case 'I': out->i = env->CallIntMethod(o, m); break;
    case 'J': out->j = env->CallLongMethod(o, m); break;
    case 'F': out->f = env->CallFloatMethod(o, m); break;
    case 'D': out->d = env->CallDoubleMethod(o, m); break;
    case 'C': out->c = env->CallCharMethod(o, m); break;
    default: break;
    }
    bool ok = !env->ExceptionCheck();
    if (!ok) env->ExceptionClear();
    env->DeleteLocalRef(c);
    return ok;
}

// Lenient variant kept for the pre-existing :setField semantics (a bad boxed
// value silently becomes zero rather than aborting the call).
jvalue UnboxValue(JNIEnv* env, char t, jobject o) {
    jvalue v{};
    UnboxValueEx(env, t, o, &v);
    if (env->ExceptionCheck()) env->ExceptionClear();
    return v;
}

jobject BoxValue(JNIEnv* env, char t, jvalue v) {
    auto cls = [&](const char* n) { return env->FindClass(n); };
    switch (t) {
    case 'Z': {
        jclass c = cls("java/lang/Boolean");
        return env->CallStaticObjectMethod(c, env->GetStaticMethodID(c, "valueOf", "(Z)Ljava/lang/Boolean;"), v.z);
    }
    case 'B': {
        jclass c = cls("java/lang/Byte");
        return env->CallStaticObjectMethod(c, env->GetStaticMethodID(c, "valueOf", "(B)Ljava/lang/Byte;"), v.b);
    }
    case 'S': {
        jclass c = cls("java/lang/Short");
        return env->CallStaticObjectMethod(c, env->GetStaticMethodID(c, "valueOf", "(S)Ljava/lang/Short;"), v.s);
    }
    case 'I': {
        jclass c = cls("java/lang/Integer");
        return env->CallStaticObjectMethod(c, env->GetStaticMethodID(c, "valueOf", "(I)Ljava/lang/Integer;"), v.i);
    }
    case 'J': {
        jclass c = cls("java/lang/Long");
        return env->CallStaticObjectMethod(c, env->GetStaticMethodID(c, "valueOf", "(J)Ljava/lang/Long;"), v.j);
    }
    case 'F': {
        jclass c = cls("java/lang/Float");
        return env->CallStaticObjectMethod(c, env->GetStaticMethodID(c, "valueOf", "(F)Ljava/lang/Float;"), v.f);
    }
    case 'D': {
        jclass c = cls("java/lang/Double");
        return env->CallStaticObjectMethod(c, env->GetStaticMethodID(c, "valueOf", "(D)Ljava/lang/Double;"), v.d);
    }
    case 'C': {
        jclass c = cls("java/lang/Character");
        return env->CallStaticObjectMethod(c, env->GetStaticMethodID(c, "valueOf", "(C)Ljava/lang/Character;"), v.c);
    }
    default:
        return v.l;
    }
}

std::string ThrowableText(JNIEnv* env) {
    jobject th = env->ExceptionOccurred();
    if (!th) return {};
    env->ExceptionClear();
    jclass th_cls = env->FindClass("java/lang/Throwable");
    jmethodID to_string = env->GetMethodID(th_cls, "toString", "()Ljava/lang/String;");
    std::string out = "Java exception";
    if (to_string) {
        jstring js = (jstring)env->CallObjectMethod(th, to_string);
        if (env->ExceptionCheck()) { env->ExceptionClear(); }
        if (js) {
            const char* cs = env->GetStringUTFChars(js, nullptr);
            if (cs) { out = cs; env->ReleaseStringUTFChars(js, cs); }
            env->DeleteLocalRef(js);
        }
    }
    env->DeleteLocalRef(th);
    return out;
}

std::string JStringText(JNIEnv* env, jstring js) {
    if (!js) return "null";
    const char* cs = env->GetStringUTFChars(js, nullptr);
    if (!cs) { env->ExceptionClear(); return "<string unavailable>"; }
    std::string out = cs;
    env->ReleaseStringUTFChars(js, cs);
    return out;
}

// Calls Java toString() on an object. Used for javaFields valueText.
std::string JavaToStringText(JNIEnv* env, jobject o) {
    if (!o) return "null";
    jclass c = env->GetObjectClass(o);
    if (!c) { env->ExceptionClear(); return "<toString failed>"; }
    jmethodID m = env->GetMethodID(c, "toString", "()Ljava/lang/String;");
    std::string out;
    if (!m) {
        env->ExceptionClear();
        out = "<no toString>";
    } else {
        jstring js = reinterpret_cast<jstring>(env->CallObjectMethod(o, m));
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            out = "<toString threw>";
        } else if (!js) {
            out = "<toString null>";
        } else {
            out = JStringText(env, js);
            env->DeleteLocalRef(js);
        }
    }
    env->DeleteLocalRef(c);
    return out;
}

// ---------- P0-6: signature-driven invocation (inherited methods) ----------
struct SigType {
    char kind = 'V';   // JNI descriptor kind: Z B C S I J F D L [ V
    std::string desc;  // full descriptor, e.g. I / [B / Ljava/lang/String;
};

// Parses a JNI signature such as (Ljava/lang/String;I)V into per-parameter
// descriptors + return descriptor.
bool ParseSignature(const char* sig, std::vector<SigType>* params, SigType* ret) {
    if (!sig || sig[0] != '(') return false;
    params->clear();
    const char* p = sig + 1;
    auto parse_one = [](const char*& q, SigType* out) -> bool {
        const char* st = q;
        while (*q == '[') ++q;
        if (*q == 'L') {
            while (*q && *q != ';') ++q;
            if (*q != ';') return false;
            ++q;
        } else if (*q) {
            ++q;
        } else {
            return false;
        }
        out->desc.assign(st, (size_t)(q - st));
        if (st[0] == '[') out->kind = '[';
        else if (st[0] == 'L') out->kind = 'L';
        else out->kind = st[0];
        switch (out->kind) {
        case 'V': case 'Z': case 'B': case 'C': case 'S': case 'I':
        case 'J': case 'F': case 'D': case 'L': case '[': return true;
        default: return false;
        }
    };
    while (*p && *p != ')') {
        SigType sp;
        if (!parse_one(p, &sp) || sp.kind == 'V') return false;
        params->push_back(sp);
    }
    if (*p != ')') return false;
    ++p;
    return parse_one(p, ret) && *p == 0;
}

// Owns the local refs of jobjectArray elements used as jvalue.l, so they are
// released even on early error paths.
struct JArgs {
    JNIEnv* env = nullptr;
    std::vector<jvalue> values;
    std::vector<jobject> refs;
    ~JArgs() {
        if (!env) return;
        for (jobject o : refs) if (o) env->DeleteLocalRef(o);
    }
};

bool BuildJArgs(JNIEnv* env, const std::vector<SigType>& params, jobjectArray args,
                JArgs* out, std::string* err) {
    out->env = env;
    jsize n = args ? env->GetArrayLength(args) : 0;
    if ((size_t)n != params.size()) {
        char b[128];
        snprintf(b, sizeof(b), "参数个数不匹配: 签名要求 %zu 个，实际传入 %d 个",
                 params.size(), (int)n);
        *err = b;
        return false;
    }
    for (jsize i = 0; i < n; ++i) {
        const SigType& sp = params[(size_t)i];
        jobject a = env->GetObjectArrayElement(args, i);
        jvalue v{};
        if (sp.kind == 'L' || sp.kind == '[') {
            // Best-effort receiver/param type check: jvalue calls are not
            // type-checked by ART, a mismatched reference could crash the target
            // instead of throwing IllegalArgumentException. Classes from the app
            // class loader are not resolvable from a native thread here, so the
            // check is skipped for those (see report).
            if (a && sp.kind == 'L' && sp.desc.size() > 2) {
                std::string cname = sp.desc.substr(1, sp.desc.size() - 2);
                jclass expected = env->FindClass(cname.c_str());
                if (expected) {
                    bool ok = env->IsInstanceOf(a, expected) == JNI_TRUE;
                    env->DeleteLocalRef(expected);
                    if (!ok) {
                        env->DeleteLocalRef(a);
                        char b[220];
                        snprintf(b, sizeof(b), "第 %d 个参数类型不匹配（期望 %s）",
                                 (int)i, sp.desc.c_str());
                        *err = b;
                        return false;
                    }
                } else {
                    env->ExceptionClear();
                }
            }
            v.l = a;
        } else if (!UnboxValueEx(env, sp.kind, a, &v)) {
            env->DeleteLocalRef(a);
            char b[160];
            snprintf(b, sizeof(b), "第 %d 个参数不是合法的 %s（需要装箱的基本类型）",
                     (int)i, sp.desc.c_str());
            *err = b;
            return false;
        }
        out->values.push_back(v);
        out->refs.push_back(a);
    }
    return true;
}

// Calls the method through a jmethodID with jvalues built from the signature.
// A void method returns nullptr with *err empty (err[0] == 0 means success).
jobject InvokeWithSig(JNIEnv* env, jobject obj, jclass cls, jmethodID mid,
                      const SigType& ret, JArgs* a, bool is_static,
                      std::string* err) {
    jvalue dummy{};
    jvalue* va = a->values.empty() ? &dummy : a->values.data();
    jvalue rv{};
    switch (ret.kind) {
    case 'V':
        if (is_static) env->CallStaticVoidMethodA(cls, mid, va);
        else env->CallVoidMethodA(obj, mid, va);
        break;
    case 'Z':
        rv.z = is_static ? env->CallStaticBooleanMethodA(cls, mid, va)
                         : env->CallBooleanMethodA(obj, mid, va);
        break;
    case 'B':
        rv.b = is_static ? env->CallStaticByteMethodA(cls, mid, va)
                         : env->CallByteMethodA(obj, mid, va);
        break;
    case 'C':
        rv.c = is_static ? env->CallStaticCharMethodA(cls, mid, va)
                         : env->CallCharMethodA(obj, mid, va);
        break;
    case 'S':
        rv.s = is_static ? env->CallStaticShortMethodA(cls, mid, va)
                         : env->CallShortMethodA(obj, mid, va);
        break;
    case 'I':
        rv.i = is_static ? env->CallStaticIntMethodA(cls, mid, va)
                         : env->CallIntMethodA(obj, mid, va);
        break;
    case 'J':
        rv.j = is_static ? env->CallStaticLongMethodA(cls, mid, va)
                         : env->CallLongMethodA(obj, mid, va);
        break;
    case 'F':
        rv.f = is_static ? env->CallStaticFloatMethodA(cls, mid, va)
                         : env->CallFloatMethodA(obj, mid, va);
        break;
    case 'D':
        rv.d = is_static ? env->CallStaticDoubleMethodA(cls, mid, va)
                         : env->CallDoubleMethodA(obj, mid, va);
        break;
    case 'L':
    case '[':
        rv.l = is_static ? env->CallStaticObjectMethodA(cls, mid, va)
                         : env->CallObjectMethodA(obj, mid, va);
        break;
    default:
        *err = std::string("不支持的返回类型: ") + ret.desc;
        return nullptr;
    }
    if (env->ExceptionCheck()) {
        std::string t = ThrowableText(env);
        *err = "Java 调用抛出异常: " + (t.empty() ? std::string("unknown") : t);
        return nullptr;
    }
    if (ret.kind == 'V') return nullptr;
    jobject boxed = BoxValue(env, ret.kind, rv);
    if (env->ExceptionCheck()) {
        std::string t = ThrowableText(env);
        *err = "返回结果装箱失败: " + (t.empty() ? std::string("unknown") : t);
        return nullptr;
    }
    return boxed;
}

// ---------- P1-10: arrays ----------
bool ArrayElemDescriptor(JNIEnv* env, jobject arr, std::string* desc) {
    jclass class_cls = env->FindClass("java/lang/Class");
    if (!class_cls) { env->ExceptionClear(); return false; }
    jmethodID get_comp = env->GetMethodID(class_cls, "getComponentType",
                                          "()Ljava/lang/Class;");
    if (!get_comp) { env->ExceptionClear(); env->DeleteLocalRef(class_cls); return false; }
    jclass oc = env->GetObjectClass(arr);
    if (!oc) { env->ExceptionClear(); env->DeleteLocalRef(class_cls); return false; }
    jobject comp = env->CallObjectMethod(oc, get_comp);
    env->DeleteLocalRef(oc);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(class_cls);
        return false;
    }
    if (!comp) { env->DeleteLocalRef(class_cls); return false; }
    std::string d = ClassDescriptor(env, reinterpret_cast<jclass>(comp));
    env->DeleteLocalRef(comp);
    env->DeleteLocalRef(class_cls);
    if (d.empty() || d == "?") return false;
    *desc = d;
    return true;
}

// ---------- P1-8: field reading/formatting ----------
bool ReadFieldValue(JNIEnv* env, jobject obj, jclass decl, jfieldID fid,
                    bool is_static, char t, jvalue* out) {
    *out = jvalue{};
    if (is_static) {
        switch (t) {
        case 'Z': out->z = env->GetStaticBooleanField(decl, fid); break;
        case 'B': out->b = env->GetStaticByteField(decl, fid); break;
        case 'C': out->c = env->GetStaticCharField(decl, fid); break;
        case 'S': out->s = env->GetStaticShortField(decl, fid); break;
        case 'I': out->i = env->GetStaticIntField(decl, fid); break;
        case 'J': out->j = env->GetStaticLongField(decl, fid); break;
        case 'F': out->f = env->GetStaticFloatField(decl, fid); break;
        case 'D': out->d = env->GetStaticDoubleField(decl, fid); break;
        case 'L': case '[': out->l = env->GetStaticObjectField(decl, fid); break;
        default: return false;
        }
    } else {
        switch (t) {
        case 'Z': out->z = env->GetBooleanField(obj, fid); break;
        case 'B': out->b = env->GetByteField(obj, fid); break;
        case 'C': out->c = env->GetCharField(obj, fid); break;
        case 'S': out->s = env->GetShortField(obj, fid); break;
        case 'I': out->i = env->GetIntField(obj, fid); break;
        case 'J': out->j = env->GetLongField(obj, fid); break;
        case 'F': out->f = env->GetFloatField(obj, fid); break;
        case 'D': out->d = env->GetDoubleField(obj, fid); break;
        case 'L': case '[': out->l = env->GetObjectField(obj, fid); break;
        default: return false;
        }
    }
    if (env->ExceptionCheck()) { env->ExceptionClear(); return false; }
    return true;
}

std::string FieldValueText(JNIEnv* env, jobject obj, jclass decl, jfieldID fid,
                           bool is_static, const std::string& desc) {
    if (desc.empty()) return "<no descriptor>";
    char t = desc[0];
    jvalue v{};
    if (!ReadFieldValue(env, obj, decl, fid, is_static, t, &v)) return "<read failed>";
    if (t == 'L' || t == '[') {
        if (!v.l) return "null";
        std::string text = (desc == "Ljava/lang/String;")
                               ? JStringText(env, reinterpret_cast<jstring>(v.l))
                               : JavaToStringText(env, v.l);
        env->DeleteLocalRef(v.l);
        return text;
    }
    jobject boxed = BoxValue(env, t, v);
    std::string text = JavaToStringText(env, boxed);
    if (boxed) env->DeleteLocalRef(boxed);
    if (env->ExceptionCheck()) env->ExceptionClear();
    return text;
}

jobject NewViaConstructor(JNIEnv* env, jclass cls, const char* sig, jobjectArray args,
                          std::string* err) {
    jclass class_cls = env->FindClass("java/lang/Class");
    if (!class_cls) { env->ExceptionClear(); *err = "java.lang.Class not found"; return nullptr; }
    jmethodID get_ctors = env->GetMethodID(class_cls, "getDeclaredConstructors",
                                           "()[Ljava/lang/reflect/Constructor;");
    if (!get_ctors) {
        env->ExceptionClear();
        env->DeleteLocalRef(class_cls);
        *err = "Class.getDeclaredConstructors not found";
        return nullptr;
    }
    jobjectArray ctors = (jobjectArray)env->CallObjectMethod(cls, get_ctors);
    env->DeleteLocalRef(class_cls);
    if (!ctors) {
        env->ExceptionClear();
        *err = "getDeclaredConstructors failed";
        return nullptr;
    }
    jclass ctor_cls = env->FindClass("java/lang/reflect/Constructor");
    if (!ctor_cls) {
        env->ExceptionClear();
        env->DeleteLocalRef(ctors);
        *err = "java.lang.reflect.Constructor not found";
        return nullptr;
    }
    jmethodID get_params = env->GetMethodID(ctor_cls, "getParameterTypes",
                                            "()[Ljava/lang/Class;");
    jmethodID new_inst = env->GetMethodID(ctor_cls, "newInstance",
                                          "([Ljava/lang/Object;)Ljava/lang/Object;");
    env->DeleteLocalRef(ctor_cls);
    if (!get_params || !new_inst) {
        env->ExceptionClear();
        env->DeleteLocalRef(ctors);
        *err = "Constructor.getParameterTypes/newInstance unavailable";
        return nullptr;
    }
    jobject result = nullptr;
    int n = env->GetArrayLength(ctors);
    for (int i = 0; i < n; ++i) {
        jobject ctor = env->GetObjectArrayElement(ctors, i);
        jobjectArray params = (jobjectArray)env->CallObjectMethod(ctor, get_params);
        if (env->ExceptionCheck()) { env->ExceptionClear(); params = nullptr; }
        std::string desc = "(";
        int pn = params ? env->GetArrayLength(params) : 0;
        for (int k = 0; k < pn; ++k) {
            jobject pc = env->GetObjectArrayElement(params, k);
            desc += ClassDescriptor(env, (jclass)pc);
            env->DeleteLocalRef(pc);
        }
        desc += ")V";
        if (params) env->DeleteLocalRef(params);
        if (desc == sig) {
            TrySetAccessible(env, ctor);
            result = env->CallObjectMethod(ctor, new_inst, args);
            if (env->ExceptionCheck()) { *err = ThrowableText(env); result = nullptr; }
            env->DeleteLocalRef(ctor);
            break;
        }
        env->DeleteLocalRef(ctor);
    }
    env->DeleteLocalRef(ctors);
    if (!result && err->empty()) *err = "constructor not found: ";
    return result;
}

}  // namespace


extern "C" {

void atrace_arthook_set_javavm(JavaVM* vm) {
    if (!vm) return;
    std::lock_guard<std::mutex> lk(g_state_mu);
    g_vm.store(vm);
    g_vm_source = 1;
}

void atrace_arthook_set_lua_bridge(atrace_lua_call_fn call, atrace_log_fn log) {
    g_lua_call = call;
    g_log = log;
}

JNIEnv* atrace_arthook_env(void) { return Env(); }

int atrace_arthook_ready(void) { return g_inited ? 1 : 0; }

// P0-2: one-line diagnostics for the Lua layer. Returns the number of bytes
// written (excluding the trailing NUL), 0 when out/cap are invalid.
int atrace_arthook_vm_state(char* out, int cap) {
    if (!out || cap <= 0) return 0;
    JavaVM* vm = g_vm.load();
    int source = 0;
    {
        std::lock_guard<std::mutex> lk(g_state_mu);
        source = g_vm_source;
    }
    if (!vm) {
        JavaVM* probed = ProbeCreatedJavaVM();
        if (probed) {
            {
                std::lock_guard<std::mutex> lk(g_state_mu);
                if (!g_vm.load()) {
                    g_vm.store(probed);
                    g_vm_source = 2;
                }
                vm = g_vm.load();
                source = g_vm_source;
            }
        }
    }
    int attached = 0;
    if (vm) {
        JNIEnv* e = nullptr;
        if (vm->GetEnv(reinterpret_cast<void**>(&e), JNI_VERSION_1_6) == JNI_OK && e) attached = 1;
    }
    const char* source_name = source == 1 ? "JNI_OnLoad" : (source == 2 ? "dlsym-probe" : "none");
    std::string last = GetLastErr();
    int n = snprintf(out, (size_t)cap,
                     "init=%d vm=%p vmSource=%s currentThreadAttached=%d\nlastError=%s",
                     g_inited ? 1 : 0, (void*)vm, source_name, attached,
                     last.empty() ? "(none)" : last.c_str());
    if (n < 0) { out[0] = 0; return 0; }
    return n < cap ? n : cap - 1;
}

int atrace_arthook_install(const char* cls, const char* name, const char* sig,
                           int lua_ref, char* err, int err_cap) {
    auto fail = [&](const std::string& msg) -> int {
        if (err && err_cap > 0) snprintf(err, (size_t)err_cap, "%s", msg.c_str());
        SetLastErr(msg);
        AH_ERR("install failed: %s", msg.c_str());
        return -1;
    };
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env) return fail(eerr);
    std::string ierr;
    if (!EnsureInit(env, &ierr)) return fail(ierr);
    if (!cls || !name) return fail("class/method required");
    jobject loader = GetAppClassLoader(env);
    jclass target_cls = nullptr;
    if (!FindClassByName(env, cls, loader, &target_cls)) {
        env->ExceptionClear();
        return fail(std::string("class not found: ") + cls);
    }
    MethodHit hit;
    if (!FindMethod(env, target_cls, name, sig, &hit, &ierr)) return fail(ierr);
    // LSPlant 处理不了 JNI native 的 entry（实测：装上后命中一次就把目标打崩），
    // abstract 没有实现体也 hook 不了。装之前查 Method.getModifiers() 直接给可执行建议。
    {
        jclass method_cls = env->FindClass("java/lang/reflect/Method");
        jmethodID get_mods = method_cls ? env->GetMethodID(method_cls, "getModifiers", "()I") : nullptr;
        if (get_mods) {
            jint mods = env->CallIntMethod(hit.method, get_mods);
            if (env->ExceptionCheck()) { env->ExceptionClear(); mods = 0; }
            constexpr jint kAccNative = 0x0100;
            constexpr jint kAccAbstract = 0x0400;
            if (mods & kAccNative) {
                env->DeleteLocalRef(hit.method);
                env->DeleteLocalRef(target_cls);
                if (loader) env->DeleteLocalRef(loader);
                return fail(std::string("不支持 native 方法: ") + cls + "::" + name +
                            " 是 JNI native 方法（LSPlant 处理不了 native entry，装上会崩目标）。\n"
                            "建议改用：① hookfunc(native 实现地址) —— 先 symbols/scan 找到该 JNI 函数的 native 地址；"
                            "② hookAfter(同左) 观察调用；③ 若要改 Java 层行为，hook 调用它的 Java 方法而非 native 方法。");
            }
            if (mods & kAccAbstract) {
                env->DeleteLocalRef(hit.method);
                env->DeleteLocalRef(target_cls);
                if (loader) env->DeleteLocalRef(loader);
                return fail(std::string("不支持 abstract 方法: ") + cls + "::" + name +
                            "（没有实现体，无法 hook）；请 hook 具体实现类的方法。");
            }
        } else if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        if (method_cls) env->DeleteLocalRef(method_cls);
    }
    jobject stub = env->NewObject(g_stub_cls, g_stub_ctor);
    if (!stub) return fail("new HookStub failed");
    int id = g_next_id++;
    env->SetLongField(stub, g_stub_id_field, (jlong)id);
    jobject backup = lsplant::Hook(env, hit.method, stub, g_stub_cb_method);
    if (!backup) return fail("lsplant::Hook failed (already hooked, or ART symbols missing)");
    HookRec rec;
    rec.id = id;
    rec.target = env->NewGlobalRef(hit.method);
    // lsplant::Hook returns a *global* ref to the backup method (see lsplant.cc:902);
    // take ownership of it as-is and never DeleteLocalRef it.
    rec.backup = backup;
    rec.lua_ref = lua_ref;
    std::string ret_desc = hit.desc;
    size_t rp = ret_desc.find(')');
    if (rp != std::string::npos) ret_desc = ret_desc.substr(rp + 1);
    rec.desc = hit.desc;
    rec.return_desc = ret_desc;
    rec.is_static = hit.is_static;
    rec.cls = cls;
    rec.name = name;
    rec.installed_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    {
        std::lock_guard<std::mutex> lk(g_hooks_mu);
        g_hooks[id] = rec;
    }
    AH_LOG("hooked %s.%s%s id=%d luaRef=%d", cls, name, hit.desc.c_str(), id, lua_ref);
    env->DeleteLocalRef(stub);
    env->DeleteLocalRef(hit.method);
    env->DeleteLocalRef(target_cls);
    if (loader) env->DeleteLocalRef(loader);
    return id;
}

int atrace_arthook_unhook(int hook_id, int* lua_ref_out) {
    JNIEnv* env = Env();
    if (!env) return 0;
    HookRec rec;
    {
        std::lock_guard<std::mutex> lk(g_hooks_mu);
        auto it = g_hooks.find(hook_id);
        if (it == g_hooks.end()) return 0;
        rec = it->second;
        g_hooks.erase(it);
    }
    bool ok = lsplant::UnHook(env, rec.target);
    if (lua_ref_out) *lua_ref_out = rec.lua_ref;
    if (rec.target) env->DeleteGlobalRef(rec.target);
    if (rec.backup) env->DeleteGlobalRef(rec.backup);
    AH_LOG("unhook id=%d -> %d", hook_id, (int)ok);
    return ok ? 1 : 0;
}

int atrace_arthook_luaref(int hook_id) {
    std::lock_guard<std::mutex> lk(g_hooks_mu);
    auto it = g_hooks.find(hook_id);
    return it == g_hooks.end() ? 0 : it->second.lua_ref;
}

int atrace_arthook_list(char* out, int cap) {
    if (!out || cap <= 0) return 0;
    std::lock_guard<std::mutex> lk(g_hooks_mu);
    int n = 0;
    for (auto& kv : g_hooks) {
        const HookRec& r = kv.second;
        n += snprintf(out + n, (size_t)(cap - n > 0 ? cap - n : 0),
                      "%d|%s|%s|%s|%s|%llu|%llu\n", r.id, r.cls.c_str(), r.name.c_str(),
                      r.desc.c_str(), r.is_static ? "static" : "instance",
                      (unsigned long long)r.hits, (unsigned long long)r.installed_ms);
        if (n >= cap) break;
    }
    return n;
}


jobject atrace_java_call(jobject obj, const char* name, const char* sig,
                         jobjectArray args, char* err, int cap) {
    if (err && cap > 0) err[0] = 0;
    auto fail = [&](const std::string& m) -> jobject {
        if (err && cap > 0) snprintf(err, (size_t)cap, "%s", m.c_str());
        SetLastErr(m);
        AH_ERR("java_call %s%s failed: %s", name ? name : "?", sig ? sig : "", m.c_str());
        return nullptr;
    };
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env) return fail(eerr);
    if (!obj) return fail("null object");
    if (!name || !name[0]) return fail("method name required");
    jclass cls = env->GetObjectClass(obj);
    if (!cls) { env->ExceptionClear(); return fail("GetObjectClass failed"); }

    // P0-6 fast path: GetMethodID resolves methods declared on the object's
    // class *and inherited from superclasses / implemented interfaces* (the old
    // getDeclaredMethods fallback only saw methods declared on the class
    // itself). It needs a full JNI signature, which the Lua layer always passes.
    std::string fast_err;
    if (sig && sig[0] == '(') {
        jmethodID mid = env->GetMethodID(cls, name, sig);
        if (mid) {
            std::vector<SigType> params;
            SigType ret;
            if (ParseSignature(sig, &params, &ret)) {
                JArgs a;
                std::string aerr;
                if (BuildJArgs(env, params, args, &a, &aerr)) {
                    std::string ierr;
                    jobject r = InvokeWithSig(env, obj, cls, mid, ret, &a, false, &ierr);
                    if (ierr.empty()) {
                        env->DeleteLocalRef(cls);
                        return r;  // void method: NULL with err[0] == 0
                    }
                    // The method already ran (or ART rejected the call): retrying
                    // through reflection would invoke it a second time.
                    env->DeleteLocalRef(cls);
                    return fail(ierr);
                }
                fast_err = aerr;
            } else {
                fast_err = "invalid JNI signature";
            }
        } else {
            env->ExceptionClear();
            fast_err = "GetMethodID failed";
        }
    }

    // Fallback: the previous java.lang.reflect.Method#invoke path (static
    // methods called through an instance, methods GetMethodID cannot see).
    MethodHit hit;
    std::string ferr;
    if (!FindMethod(env, cls, name, sig, &hit, &ferr)) {
        if (!fast_err.empty()) ferr += " [fast path: " + fast_err + "]";
        env->DeleteLocalRef(cls);
        return fail(ferr);
    }
    jmethodID invoke_mid = MethodInvokeMID(env);
    if (!invoke_mid) {
        env->ExceptionClear();
        env->DeleteLocalRef(cls);
        env->DeleteLocalRef(hit.method);
        return fail("java.lang.reflect.Method.invoke unavailable");
    }
    TrySetAccessible(env, hit.method);
    jobject ret = env->CallObjectMethod(hit.method, invoke_mid, obj, args);
    if (env->ExceptionCheck()) {
        std::string m = ThrowableText(env);
        env->DeleteLocalRef(cls);
        env->DeleteLocalRef(hit.method);
        return fail(m);
    }
    env->DeleteLocalRef(cls);
    env->DeleteLocalRef(hit.method);
    return ret;
}

jobject atrace_java_get_field(jobject obj, const char* name, const char* sig,
                              char* err, int cap) {
    if (err && cap > 0) err[0] = 0;
    auto fail = [&](const std::string& m) -> jobject {
        if (err && cap > 0) snprintf(err, (size_t)cap, "%s", m.c_str());
        SetLastErr(m);
        return nullptr;
    };
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env) return fail(eerr);
    if (!obj || !name || !sig) return fail("null arg");
    jclass cls = env->GetObjectClass(obj);
    jfieldID fid = env->GetFieldID(cls, name, sig);
    if (!fid) { env->ExceptionClear(); env->DeleteLocalRef(cls); return fail("field not found"); }
    jvalue v{};
    switch (sig[0]) {
    case 'Z': v.z = env->GetBooleanField(obj, fid); break;
    case 'B': v.b = env->GetByteField(obj, fid); break;
    case 'S': v.s = env->GetShortField(obj, fid); break;
    case 'I': v.i = env->GetIntField(obj, fid); break;
    case 'J': v.j = env->GetLongField(obj, fid); break;
    case 'F': v.f = env->GetFloatField(obj, fid); break;
    case 'D': v.d = env->GetDoubleField(obj, fid); break;
    case 'C': v.c = env->GetCharField(obj, fid); break;
    default: v.l = env->GetObjectField(obj, fid); break;
    }
    env->DeleteLocalRef(cls);
    return BoxValue(env, sig[0], v);
}

int atrace_java_set_field(jobject obj, const char* name, const char* sig,
                          jobject value, char* err, int cap) {
    if (err && cap > 0) err[0] = 0;
    auto fail = [&](const std::string& m) -> int {
        if (err && cap > 0) snprintf(err, (size_t)cap, "%s", m.c_str());
        SetLastErr(m);
        return 0;
    };
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env) return fail(eerr);
    if (!obj || !name || !sig) return fail("null arg");
    jclass cls = env->GetObjectClass(obj);
    jfieldID fid = env->GetFieldID(cls, name, sig);
    if (!fid) { env->ExceptionClear(); env->DeleteLocalRef(cls); return fail("field not found"); }
    jvalue v = UnboxValue(env, sig[0], value);
    switch (sig[0]) {
    case 'Z': env->SetBooleanField(obj, fid, v.z); break;
    case 'B': env->SetByteField(obj, fid, v.b); break;
    case 'S': env->SetShortField(obj, fid, v.s); break;
    case 'I': env->SetIntField(obj, fid, v.i); break;
    case 'J': env->SetLongField(obj, fid, v.j); break;
    case 'F': env->SetFloatField(obj, fid, v.f); break;
    case 'D': env->SetDoubleField(obj, fid, v.d); break;
    case 'C': env->SetCharField(obj, fid, v.c); break;
    default: env->SetObjectField(obj, fid, v.l); break;
    }
    env->DeleteLocalRef(cls);
    return 1;
}

jobject atrace_java_new(const char* cls_name, const char* sig, jobjectArray args,
                        char* err, int cap) {
    if (err && cap > 0) err[0] = 0;
    auto fail = [&](const std::string& m) -> jobject {
        if (err && cap > 0) snprintf(err, (size_t)cap, "%s", m.c_str());
        SetLastErr(m);
        return nullptr;
    };
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env) return fail(eerr);
    if (!cls_name || !cls_name[0]) return fail("class name required");
    jobject loader = GetAppClassLoader(env);
    jclass cls = nullptr;
    if (!FindClassByName(env, cls_name, loader, &cls)) {
        env->ExceptionClear();
        if (loader) env->DeleteLocalRef(loader);
        return fail(std::string("class not found: ") + cls_name);
    }
    std::string cerr;
    jobject obj = NewViaConstructor(env, cls, sig, args, &cerr);
    env->DeleteLocalRef(cls);
    if (loader) env->DeleteLocalRef(loader);
    if (!obj) return fail(cerr.empty() ? "newInstance failed" : cerr);
    return obj;
}

int atrace_java_class_name(jobject obj, char* out, int cap) {
    if (!out || cap <= 0) return 0;
    out[0] = 0;
    JNIEnv* env = Env();
    if (!env || !obj) return 0;
    jclass ocls = env->GetObjectClass(obj);
    jclass class_cls = env->FindClass("java/lang/Class");
    jmethodID get_name = env->GetMethodID(class_cls, "getName", "()Ljava/lang/String;");
    jstring js = (jstring)env->CallObjectMethod(ocls, get_name);
    env->DeleteLocalRef(ocls);
    if (!js) return 0;
    const char* cs = env->GetStringUTFChars(js, nullptr);
    if (cs) { snprintf(out, (size_t)cap, "%s", cs); env->ReleaseStringUTFChars(js, cs); }
    env->DeleteLocalRef(js);
    return out[0] ? 1 : 0;
}

// P1-9: static method call. Class loading goes through the app class loader
// (same path as atrace_arthook_install / atrace_java_new). Method resolution
// prefers GetStaticMethodID (which also finds inherited statics), then falls
// back to scanning getDeclaredMethods for a static method along the superclass
// chain and invoking it through reflection.
// Returns a local ref (boxed value for primitive returns); a void method
// returns NULL with err[0] == 0, exactly like atrace_java_call.
jobject atrace_java_call_static(const char* cls_name, const char* name, const char* sig,
                                jobjectArray args, char* err, int cap) {
    if (err && cap > 0) err[0] = 0;
    auto fail = [&](const std::string& m) -> jobject {
        if (err && cap > 0) snprintf(err, (size_t)cap, "%s", m.c_str());
        SetLastErr(m);
        AH_ERR("java_call_static %s.%s%s failed: %s", cls_name ? cls_name : "?",
               name ? name : "?", sig ? sig : "", m.c_str());
        return nullptr;
    };
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env) return fail(eerr);
    if (!cls_name || !cls_name[0]) return fail("class name required");
    if (!name || !name[0]) return fail("method name required");

    jobject loader = GetAppClassLoader(env);
    jclass cls = nullptr;
    bool class_ok = FindClassByName(env, cls_name, loader, &cls);
    if (!class_ok) env->ExceptionClear();
    if (loader) env->DeleteLocalRef(loader);
    if (!class_ok) return fail(std::string("class not found: ") + cls_name);

    std::string fast_err;
    if (sig && sig[0] == '(') {
        jmethodID mid = env->GetStaticMethodID(cls, name, sig);
        if (mid) {
            std::vector<SigType> params;
            SigType ret;
            if (ParseSignature(sig, &params, &ret)) {
                JArgs a;
                std::string aerr;
                if (BuildJArgs(env, params, args, &a, &aerr)) {
                    std::string ierr;
                    jobject r = InvokeWithSig(env, nullptr, cls, mid, ret, &a, true, &ierr);
                    if (ierr.empty()) {
                        env->DeleteLocalRef(cls);
                        return r;  // void method: NULL with err[0] == 0
                    }
                    env->DeleteLocalRef(cls);
                    return fail(ierr);
                }
                fast_err = aerr;
            } else {
                fast_err = "invalid JNI signature";
            }
        } else {
            env->ExceptionClear();
            fast_err = "GetStaticMethodID failed";
        }
    }

    jclass class_cls = env->FindClass("java/lang/Class");
    jmethodID get_super = nullptr;
    if (class_cls) {
        get_super = env->GetMethodID(class_cls, "getSuperclass", "()Ljava/lang/Class;");
        if (!get_super) env->ExceptionClear();
    } else {
        env->ExceptionClear();
    }
    jmethodID invoke_mid = MethodInvokeMID(env);
    if (!invoke_mid) {
        env->ExceptionClear();
        env->DeleteLocalRef(cls);
        if (class_cls) env->DeleteLocalRef(class_cls);
        return fail("java.lang.reflect.Method.invoke unavailable");
    }

    std::vector<jclass> chain;
    chain.push_back(cls);
    std::string find_err;
    bool saw_instance = false;
    bool invoked = false;
    jobject result = nullptr;
    for (size_t i = 0; i < chain.size() && !invoked && find_err.empty(); ++i) {
        jclass c = chain[i];
        MethodHit hit;
        std::string e;
        if (FindMethod(env, c, name, sig, &hit, &e)) {
            if (hit.is_static) {
                TrySetAccessible(env, hit.method);
                result = env->CallObjectMethod(hit.method, invoke_mid, nullptr, args);
                if (env->ExceptionCheck()) {
                    find_err = "Java 调用抛出异常: " + ThrowableText(env);
                } else {
                    invoked = true;
                }
                env->DeleteLocalRef(hit.method);
            } else {
                saw_instance = true;
                env->DeleteLocalRef(hit.method);
            }
        } else if (e.rfind("method not found", 0) != 0) {
            find_err = e;  // ambiguous or reflection failure: report as-is
        }
        if (invoked || !find_err.empty()) break;
        if (get_super) {
            jobject sup = env->CallObjectMethod(c, get_super);
            if (env->ExceptionCheck()) { env->ExceptionClear(); sup = nullptr; }
            if (sup) chain.push_back(reinterpret_cast<jclass>(sup));
        }
    }
    for (jclass c : chain) env->DeleteLocalRef(c);
    if (class_cls) env->DeleteLocalRef(class_cls);
    if (!find_err.empty()) return fail(find_err);
    if (!invoked) {
        std::string m = std::string("method not found: ") + name;
        if (sig && sig[0]) m += std::string(" ") + sig;
        if (saw_instance) m += "（找到同名实例方法，但不是 static）";
        if (!fast_err.empty()) m += " [fast path: " + fast_err + "]";
        return fail(m);
    }
    return result;
}

// P1-8: dump all fields of an object, one per line: name|descriptor|valueText.
// include_super != 0 walks the superclass chain (interfaces are NOT walked).
// Returns the number of bytes written into out (excluding the NUL), or -1 on
// error (out then contains the error text). Output is truncated at cap-1 bytes.
int atrace_java_fields(jobject obj, int include_super, char* out, int cap) {
    if (!out || cap <= 0) return -1;
    out[0] = 0;
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env) {
        snprintf(out, (size_t)cap, "%s", eerr.c_str());
        return -1;
    }
    if (!obj) {
        snprintf(out, (size_t)cap, "%s", "null object");
        return -1;
    }

    jclass class_cls = env->FindClass("java/lang/Class");
    jclass field_cls = env->FindClass("java/lang/reflect/Field");
    if (!class_cls || !field_cls) {
        env->ExceptionClear();
        if (class_cls) env->DeleteLocalRef(class_cls);
        if (field_cls) env->DeleteLocalRef(field_cls);
        snprintf(out, (size_t)cap, "%s", "FindClass(java/lang/Class|Field) failed");
        return -1;
    }
    jmethodID get_fields = env->GetMethodID(class_cls, "getDeclaredFields",
                                            "()[Ljava/lang/reflect/Field;");
    jmethodID get_super = env->GetMethodID(class_cls, "getSuperclass",
                                           "()Ljava/lang/Class;");
    jmethodID f_name = env->GetMethodID(field_cls, "getName", "()Ljava/lang/String;");
    jmethodID f_type = env->GetMethodID(field_cls, "getType", "()Ljava/lang/Class;");
    jmethodID f_mods = env->GetMethodID(field_cls, "getModifiers", "()I");
    if (!get_fields || !get_super || !f_name || !f_type || !f_mods) {
        env->ExceptionClear();
        env->DeleteLocalRef(class_cls);
        env->DeleteLocalRef(field_cls);
        snprintf(out, (size_t)cap, "%s", "field reflection methods unavailable");
        return -1;
    }

    std::string buf;
    jclass cur = env->GetObjectClass(obj);
    if (!cur) {
        env->ExceptionClear();
        env->DeleteLocalRef(class_cls);
        env->DeleteLocalRef(field_cls);
        snprintf(out, (size_t)cap, "%s", "GetObjectClass failed");
        return -1;
    }
    while (cur) {
        jobjectArray fields = reinterpret_cast<jobjectArray>(
            env->CallObjectMethod(cur, get_fields));
        if (env->ExceptionCheck()) { env->ExceptionClear(); fields = nullptr; }
        int n = fields ? env->GetArrayLength(fields) : 0;
        for (int i = 0; i < n; ++i) {
            if (buf.size() + 1 >= (size_t)cap) break;
            jobject f = env->GetObjectArrayElement(fields, i);
            if (!f) continue;
            jstring jn = reinterpret_cast<jstring>(env->CallObjectMethod(f, f_name));
            std::string fname;
            if (jn) {
                fname = JStringText(env, jn);
                env->DeleteLocalRef(jn);
            } else {
                env->ExceptionClear();
                fname = "<noname>";
            }
            jclass type_cls = reinterpret_cast<jclass>(env->CallObjectMethod(f, f_type));
            std::string desc = "?";
            if (type_cls) {
                desc = ClassDescriptor(env, type_cls);
                env->DeleteLocalRef(type_cls);
            } else {
                env->ExceptionClear();
            }
            jint mods = env->CallIntMethod(f, f_mods);
            if (env->ExceptionCheck()) { env->ExceptionClear(); mods = 0; }
            bool is_static = (mods & 0x0008) != 0;
            jfieldID fid = nullptr;
            if (fname != "<noname>" && desc != "?") {
                if (is_static) fid = env->GetStaticFieldID(cur, fname.c_str(), desc.c_str());
                else fid = env->GetFieldID(cur, fname.c_str(), desc.c_str());
            }
            if (!fid) env->ExceptionClear();
            std::string val = fid ? FieldValueText(env, obj, cur, fid, is_static, desc)
                                  : std::string("<field id unavailable>");
            buf += fname;
            buf += '|';
            buf += desc;
            buf += '|';
            buf += val;
            buf += '\n';
            env->DeleteLocalRef(f);
        }
        if (fields) env->DeleteLocalRef(fields);
        if (!include_super) break;
        jobject sup = env->CallObjectMethod(cur, get_super);
        if (env->ExceptionCheck()) { env->ExceptionClear(); sup = nullptr; }
        env->DeleteLocalRef(cur);
        cur = reinterpret_cast<jclass>(sup);
    }
    if (cur) env->DeleteLocalRef(cur);
    env->DeleteLocalRef(class_cls);
    env->DeleteLocalRef(field_cls);

    size_t maxn = (size_t)(cap - 1);
    size_t n = buf.size() < maxn ? buf.size() : maxn;
    if (n) memcpy(out, buf.data(), n);
    out[n] = 0;
    return (int)n;
}

// P1-10: is this object an array? 1 = yes, 0 = no / invalid.
int atrace_java_is_array(jobject obj) {
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env || !obj) return 0;
    jclass oc = env->GetObjectClass(obj);
    if (!oc) { env->ExceptionClear(); return 0; }
    jclass class_cls = env->FindClass("java/lang/Class");
    jmethodID is_array = class_cls ? env->GetMethodID(class_cls, "isArray", "()Z") : nullptr;
    if (!is_array) env->ExceptionClear();
    int r = 0;
    if (is_array) {
        r = env->CallBooleanMethod(oc, is_array) ? 1 : 0;
        if (env->ExceptionCheck()) { env->ExceptionClear(); r = 0; }
    }
    env->DeleteLocalRef(oc);
    if (class_cls) env->DeleteLocalRef(class_cls);
    return r;
}

// P1-10: array length + element descriptor (e.g. I / [B / Ljava/lang/String;).
// Returns the length, or -1 when obj is null / not an array (elem_desc left "").
int atrace_java_array_len(jobject obj, char* elem_desc, int cap) {
    if (elem_desc && cap > 0) elem_desc[0] = 0;
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env || !obj) return -1;
    std::string desc;
    if (!ArrayElemDescriptor(env, obj, &desc)) return -1;
    if (elem_desc && cap > 0) snprintf(elem_desc, (size_t)cap, "%s", desc.c_str());
    return (int)env->GetArrayLength(reinterpret_cast<jarray>(obj));
}

// P1-10: array element read. Primitive elements are returned boxed (Integer,
// Long, ...), object elements as a local ref. idx is bounds-checked.
jobject atrace_java_array_get(jobject obj, int idx, char* err, int cap) {
    if (err && cap > 0) err[0] = 0;
    auto fail = [&](const std::string& m) -> jobject {
        if (err && cap > 0) snprintf(err, (size_t)cap, "%s", m.c_str());
        SetLastErr(m);
        return nullptr;
    };
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env) return fail(eerr);
    if (!obj) return fail("null object");
    std::string desc;
    if (!ArrayElemDescriptor(env, obj, &desc)) return fail("not an array");
    jsize len = env->GetArrayLength(reinterpret_cast<jarray>(obj));
    if (idx < 0 || idx >= (int)len) {
        char b[96];
        snprintf(b, sizeof(b), "index out of range: %d (length %d)", idx, (int)len);
        return fail(b);
    }
    char t = desc[0];
    jvalue v{};
    switch (t) {
    case 'Z': { jboolean x = JNI_FALSE; env->GetBooleanArrayRegion(reinterpret_cast<jbooleanArray>(obj), (jsize)idx, 1, &x); v.z = x; break; }
    case 'B': { jbyte x = 0; env->GetByteArrayRegion(reinterpret_cast<jbyteArray>(obj), (jsize)idx, 1, &x); v.b = x; break; }
    case 'C': { jchar x = 0; env->GetCharArrayRegion(reinterpret_cast<jcharArray>(obj), (jsize)idx, 1, &x); v.c = x; break; }
    case 'S': { jshort x = 0; env->GetShortArrayRegion(reinterpret_cast<jshortArray>(obj), (jsize)idx, 1, &x); v.s = x; break; }
    case 'I': { jint x = 0; env->GetIntArrayRegion(reinterpret_cast<jintArray>(obj), (jsize)idx, 1, &x); v.i = x; break; }
    case 'J': { jlong x = 0; env->GetLongArrayRegion(reinterpret_cast<jlongArray>(obj), (jsize)idx, 1, &x); v.j = x; break; }
    case 'F': { jfloat x = 0; env->GetFloatArrayRegion(reinterpret_cast<jfloatArray>(obj), (jsize)idx, 1, &x); v.f = x; break; }
    case 'D': { jdouble x = 0; env->GetDoubleArrayRegion(reinterpret_cast<jdoubleArray>(obj), (jsize)idx, 1, &x); v.d = x; break; }
    case 'L':
    case '[': {
        jobject e = env->GetObjectArrayElement(reinterpret_cast<jobjectArray>(obj), (jsize)idx);
        if (env->ExceptionCheck()) {
            std::string m = ThrowableText(env);
            return fail("array get threw: " + (m.empty() ? std::string("unknown") : m));
        }
        return e;
    }
    default:
        return fail(std::string("unsupported array element type: ") + desc);
    }
    if (env->ExceptionCheck()) {
        std::string m = ThrowableText(env);
        return fail("array get threw: " + (m.empty() ? std::string("unknown") : m));
    }
    jobject boxed = BoxValue(env, t, v);
    if (!boxed) return fail(std::string("BoxValue failed for ") + desc);
    return boxed;
}

// 经典用途：在 artHook 回调里调用，看看"是谁调用了这个被 hook 的方法"
// （之前只能自己用 javaCallStatic/反射拼 Thread.getStackTrace + Array.get）。
// 输出一行一帧：className|method|file|line|isNative
// 把 StackTraceElement[] 格式化成 "className|method|file|line|isNative\n"。
// 抽成公共函数：当前线程栈（atrace_java_stack_trace）与任意线程栈
// （atrace_java_thread_stack，给硬件断点用）共用同一套字段格式。
static std::string FormatStackTraceElements(JNIEnv* env, jobjectArray arr, int max_depth) {
    std::string buf;
    if (!arr) return buf;
    jclass ste_cls = env->FindClass("java/lang/StackTraceElement");
    if (!ste_cls) { env->ExceptionClear(); return buf; }
    jmethodID m_cn = env->GetMethodID(ste_cls, "getClassName", "()Ljava/lang/String;");
    jmethodID m_mn = env->GetMethodID(ste_cls, "getMethodName", "()Ljava/lang/String;");
    jmethodID m_fn = env->GetMethodID(ste_cls, "getFileName", "()Ljava/lang/String;");
    jmethodID m_ln = env->GetMethodID(ste_cls, "getLineNumber", "()I");
    jmethodID m_na = env->GetMethodID(ste_cls, "isNativeMethod", "()Z");
    if (!m_cn || !m_mn || !m_fn || !m_ln || !m_na) {
        env->ExceptionClear();
        env->DeleteLocalRef(ste_cls);
        return buf;
    }
    jsize len = env->GetArrayLength(arr);
    int frames = 0;
    for (jsize i = 0; i < len && frames < max_depth; ++i) {
        if (buf.size() > 60 * 1024) break;   // 防御性上限（调用方 cap 通常 32~64KB）
        jobject e = env->GetObjectArrayElement(arr, i);
        if (env->ExceptionCheck()) { env->ExceptionClear(); continue; }
        if (!e) continue;
        std::string cn, mn, fn;
        jint line = 0;
        jboolean na = JNI_FALSE;
        if (jstring s = (jstring)env->CallObjectMethod(e, m_cn)) { cn = JStringText(env, s); env->DeleteLocalRef(s); }
        else if (env->ExceptionCheck()) env->ExceptionClear();
        if (jstring s = (jstring)env->CallObjectMethod(e, m_mn)) { mn = JStringText(env, s); env->DeleteLocalRef(s); }
        else if (env->ExceptionCheck()) env->ExceptionClear();
        if (jstring s = (jstring)env->CallObjectMethod(e, m_fn)) { fn = JStringText(env, s); env->DeleteLocalRef(s); }
        else if (env->ExceptionCheck()) env->ExceptionClear();
        line = env->CallIntMethod(e, m_ln);
        if (env->ExceptionCheck()) { env->ExceptionClear(); line = 0; }
        na = env->CallBooleanMethod(e, m_na);
        if (env->ExceptionCheck()) { env->ExceptionClear(); na = JNI_FALSE; }
        env->DeleteLocalRef(e);

        buf += cn; buf += '|'; buf += mn; buf += '|'; buf += fn; buf += '|';
        buf += std::to_string((int)line); buf += '|';
        buf += (na == JNI_TRUE ? "1" : "0"); buf += '\n';
        ++frames;
    }
    env->DeleteLocalRef(ste_cls);
    return buf;
}

static int CopyOut(char* out, int cap, const std::string& buf) {
    size_t maxn = (size_t)(cap - 1);
    size_t n = buf.size() < maxn ? buf.size() : maxn;
    if (n) memcpy(out, buf.data(), n);
    out[n] = 0;
    return (int)n;
}

int atrace_java_stack_trace(char* out, int cap, int max_depth) {
    if (!out || cap <= 0) return -1;
    out[0] = 0;
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env) { snprintf(out, (size_t)cap, "%s", eerr.c_str()); return -1; }
    if (max_depth <= 0) max_depth = 64;
    auto fail = [&](const std::string& m) -> int {
        env->ExceptionClear();
        snprintf(out, (size_t)cap, "%s", m.c_str());
        return -1;
    };

    jclass thread_cls = env->FindClass("java/lang/Thread");
    if (!thread_cls) return fail("FindClass(java/lang/Thread) failed");
    jmethodID cur = env->GetStaticMethodID(thread_cls, "currentThread", "()Ljava/lang/Thread;");
    jmethodID gst = env->GetMethodID(thread_cls, "getStackTrace", "()[Ljava/lang/StackTraceElement;");
    if (!cur || !gst) {
        env->DeleteLocalRef(thread_cls);
        return fail("Thread.currentThread/getStackTrace lookup failed");
    }
    jobject th = env->CallStaticObjectMethod(thread_cls, cur);
    if (env->ExceptionCheck() || !th) {
        std::string m = ThrowableText(env);
        env->DeleteLocalRef(thread_cls);
        return fail("Thread.currentThread() failed" + (m.empty() ? std::string() : ": " + m));
    }
    jobjectArray arr = (jobjectArray)env->CallObjectMethod(th, gst);
    if (env->ExceptionCheck() || !arr) {
        std::string m = ThrowableText(env);
        env->DeleteLocalRef(th);
        env->DeleteLocalRef(thread_cls);
        return fail("getStackTrace() failed" + (m.empty() ? std::string() : ": " + m));
    }
    std::string buf = FormatStackTraceElements(env, arr, max_depth);
    env->DeleteLocalRef(arr);
    env->DeleteLocalRef(th);
    env->DeleteLocalRef(thread_cls);
    return CopyOut(out, cap, buf);
}

// P1-21：任意线程（按 Linux tid）的 Java 栈。
// Android 上 Thread.getId() == gettid()，所以用 Thread.getAllStackTraces()
// 找到 tid 对应的 Thread 再取它的 StackTraceElement[]。
// 用途：硬件断点命中只知道 tid/寄存器，靠这个把「这条原生断点属于哪个 Java 调用链」补出来。
int atrace_java_thread_stack(int tid, char* out, int cap, int max_depth) {
    if (!out || cap <= 0) return -1;
    out[0] = 0;
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env) { snprintf(out, (size_t)cap, "%s", eerr.c_str()); return -1; }
    if (max_depth <= 0) max_depth = 64;
    if (tid <= 0) return atrace_java_stack_trace(out, cap, max_depth);
    auto fail = [&](const std::string& m) -> int {
        env->ExceptionClear();
        snprintf(out, (size_t)cap, "%s", m.c_str());
        return -1;
    };

    //（本机：当前线程 getId=12527 而 gettid=12036），所以不能只按 getId 匹配。
    // 改为按「线程名」匹配：读 /proc/self/task/<tid>/comm（内核给的名字，最长 15 字符），
    // 与 Java 的 Thread.getName() 比对（Java 名字更长时内核名是它的前缀）。
    // 主线程特判：主线程的 comm 是**进程名**，而 Java 名字恒为 "main"。
    const bool is_main = (tid == (int)getpid());
    char comm[64] = {0};
    if (!is_main) {
        char cp[64];
        snprintf(cp, sizeof(cp), "/proc/self/task/%d/comm", tid);
        FILE* cf = fopen(cp, "re");
        if (cf) {
            if (fgets(comm, sizeof(comm), cf)) {
                size_t L = strlen(comm);
                while (L > 0 && (comm[L - 1] == '\n' || comm[L - 1] == '\r')) comm[--L] = 0;
            }
            fclose(cf);
        }
    }

    jclass thread_cls = env->FindClass("java/lang/Thread");
    if (!thread_cls) return fail("FindClass(java/lang/Thread) failed");
    jmethodID all_traces = env->GetStaticMethodID(thread_cls, "getAllStackTraces", "()Ljava/util/Map;");
    jmethodID get_id = env->GetMethodID(thread_cls, "getId", "()J");
    jmethodID get_name = env->GetMethodID(thread_cls, "getName", "()Ljava/lang/String;");
    if (!all_traces || !get_id || !get_name) {
        env->DeleteLocalRef(thread_cls);
        return fail("Thread.getAllStackTraces/getId/getName lookup failed");
    }
    jclass map_cls = env->FindClass("java/util/Map");
    jclass set_cls = env->FindClass("java/util/Set");
    jclass iter_cls = env->FindClass("java/util/Iterator");
    jclass entry_cls = env->FindClass("java/util/Map$Entry");
    jmethodID entry_set = map_cls ? env->GetMethodID(map_cls, "entrySet", "()Ljava/util/Set;") : nullptr;
    jmethodID iterator  = set_cls ? env->GetMethodID(set_cls, "iterator", "()Ljava/util/Iterator;") : nullptr;
    jmethodID has_next  = iter_cls ? env->GetMethodID(iter_cls, "hasNext", "()Z") : nullptr;
    jmethodID next      = iter_cls ? env->GetMethodID(iter_cls, "next", "()Ljava/lang/Object;") : nullptr;
    jmethodID get_key   = entry_cls ? env->GetMethodID(entry_cls, "getKey", "()Ljava/lang/Object;") : nullptr;
    jmethodID get_value = entry_cls ? env->GetMethodID(entry_cls, "getValue", "()Ljava/lang/Object;") : nullptr;
    auto cleanup_classes = [&]() {
        if (map_cls) env->DeleteLocalRef(map_cls);
        if (set_cls) env->DeleteLocalRef(set_cls);
        if (iter_cls) env->DeleteLocalRef(iter_cls);
        if (entry_cls) env->DeleteLocalRef(entry_cls);
        env->DeleteLocalRef(thread_cls);
    };
    if (!map_cls || !set_cls || !iter_cls || !entry_cls || !entry_set || !iterator ||
        !has_next || !next || !get_key || !get_value) {
        cleanup_classes();
        return fail("collection accessor lookup failed");
    }

    jobject map = env->CallStaticObjectMethod(thread_cls, all_traces);
    if (env->ExceptionCheck() || !map) {
        std::string m = ThrowableText(env);
        cleanup_classes();
        return fail("Thread.getAllStackTraces() failed" + (m.empty() ? std::string() : ": " + m));
    }
    jobject set = env->CallObjectMethod(map, entry_set);
    jobject iter = set ? env->CallObjectMethod(set, iterator) : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();

    std::string found;
    bool ok = false;
    int guard = 0;
    while (iter) {
        jboolean more = env->CallBooleanMethod(iter, has_next);
        if (env->ExceptionCheck()) { env->ExceptionClear(); break; }
        if (more != JNI_TRUE) break;
        if (++guard > 8192) break;   // 进程线程数上限保护
        jobject entry = env->CallObjectMethod(iter, next);
        if (env->ExceptionCheck() || !entry) { env->ExceptionClear(); continue; }
        jobject th = env->CallObjectMethod(entry, get_key);
        bool match = false;
        if (th) {
            // 1) 线程名匹配（主线程 Java 名叫 "main"；其余用 comm 前缀/精确匹配）
            std::string tname;
            if (jstring jn = (jstring)env->CallObjectMethod(th, get_name)) {
                tname = JStringText(env, jn);
                env->DeleteLocalRef(jn);
            } else if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            if (is_main) {
                match = (tname == "main");
            } else if (comm[0]) {
                match = (tname == comm) ||
                        (tname.size() >= strlen(comm) && tname.compare(0, strlen(comm), comm) == 0);
            }
            // 2) 兜底：getId()==tid（该 ROM 上两者恰好相等时）
            if (!match) {
                jlong jid = env->CallLongMethod(th, get_id);
                if (env->ExceptionCheck()) { env->ExceptionClear(); jid = -1; }
                match = (jid == (jlong)tid);
            }
        }
        if (match) {
            jobjectArray arr = (jobjectArray)env->CallObjectMethod(entry, get_value);
            if (!env->ExceptionCheck() && arr)
                found = FormatStackTraceElements(env, arr, max_depth);
            else if (env->ExceptionCheck())
                env->ExceptionClear();
            if (arr) env->DeleteLocalRef(arr);
            ok = true;
        }
        if (th) env->DeleteLocalRef(th);
        env->DeleteLocalRef(entry);
        if (ok) break;
    }
    if (iter) env->DeleteLocalRef(iter);
    if (set) env->DeleteLocalRef(set);
    env->DeleteLocalRef(map);
    cleanup_classes();

    if (!ok) {
        snprintf(out, (size_t)cap,
                 "tid=%d (comm=%s) 未匹配到 Java 线程（纯 native 线程 / 或线程已退出）",
                 tid, is_main ? "main" : (comm[0] ? comm : "?"));
        return -1;
    }
    return CopyOut(out, cap, found);
}

// 背景：Class.forName(name) 只走 boot classloader，查 App 自己的类必然 nil 且不报错；
// 这里走 Class.forName(name, false, appClassLoader)，失败再退回 JNI FindClass
//（数组描述符 "[B" 和系统类走这条）。
// 背景：javaFields() 能看到 TAG/XXX_VERSION 这类 static 常量，但 obj:getField() 只走
// 实例字段 → 静默 nil。这里提供显式静态接口，getField/setField 失败时也会回退到本接口。
static jclass FindClassForStatic(JNIEnv* env, const char* cls, const char** err_out) {
    std::string bin = cls;
    for (char& c : bin) if (c == '/') c = '.';
    jobject loader = GetAppClassLoader(env);
    jclass out = nullptr;
    bool ok = FindClassByName(env, bin.c_str(), loader, &out);
    if (loader) env->DeleteLocalRef(loader);
    if (!ok) {
        env->ExceptionClear();
        std::string jni = cls;
        for (char& c : jni) if (c == '.') c = '/';
        out = env->FindClass(jni.c_str());
        if (!out) { env->ExceptionClear(); *err_out = "class not found"; }
    }
    return out;
}

jobject atrace_java_get_static_field(const char* cls, const char* name, const char* sig,
                                     char* err, int cap) {
    if (err && cap > 0) err[0] = 0;
    auto fail = [&](const std::string& m) -> jobject {
        if (err && cap > 0) snprintf(err, (size_t)cap, "%s", m.c_str());
        return nullptr;
    };
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env) return fail(eerr);
    if (!cls || !*cls) return fail("需要一个类名（如 com.foo.Bar）");
    if (!name || !*name) return fail("需要一个字段名");
    if (!sig || !*sig) return fail("需要一个字段类型描述符（如 \"I\" / \"Ljava/lang/String;\"）");
    const char* cerr = "class not found";
    jclass c = FindClassForStatic(env, cls, &cerr);
    if (!c) return fail(std::string("类不存在: ") + cls);
    jfieldID fid = env->GetStaticFieldID(c, name, sig);
    if (!fid) {
        env->ExceptionClear();
        env->DeleteLocalRef(c);
        return fail(std::string("静态字段不存在: ") + cls + "." + name + " : " + sig);
    }
    char t = sig[0];
    jobject out = nullptr;
    jvalue v{};
    switch (t) {
    case 'Z': v.z = env->GetStaticBooleanField(c, fid); out = BoxValue(env, 'Z', v); break;
    case 'B': v.b = env->GetStaticByteField(c, fid);    out = BoxValue(env, 'B', v); break;
    case 'S': v.s = env->GetStaticShortField(c, fid);   out = BoxValue(env, 'S', v); break;
    case 'I': v.i = env->GetStaticIntField(c, fid);     out = BoxValue(env, 'I', v); break;
    case 'J': v.j = env->GetStaticLongField(c, fid);    out = BoxValue(env, 'J', v); break;
    case 'F': v.f = env->GetStaticFloatField(c, fid);   out = BoxValue(env, 'F', v); break;
    case 'D': v.d = env->GetStaticDoubleField(c, fid);  out = BoxValue(env, 'D', v); break;
    case 'C': v.c = env->GetStaticCharField(c, fid);    out = BoxValue(env, 'C', v); break;
    case 'L':
    case '[': out = env->GetStaticObjectField(c, fid); break;
    default:
        env->DeleteLocalRef(c);
        return fail(std::string("不支持的字段类型描述符: ") + sig);
    }
    if (env->ExceptionCheck()) {
        std::string m = ThrowableText(env);
        env->DeleteLocalRef(c);
        return fail("读取静态字段异常" + (m.empty() ? std::string() : ": " + m));
    }
    env->DeleteLocalRef(c);
    return out;
}

int atrace_java_set_static_field(const char* cls, const char* name, const char* sig,
                                 jobject value, char* err, int cap) {
    if (err && cap > 0) err[0] = 0;
    auto fail = [&](const std::string& m) -> int {
        if (err && cap > 0) snprintf(err, (size_t)cap, "%s", m.c_str());
        return 0;
    };
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env) return fail(eerr);
    if (!cls || !*cls) return fail("需要一个类名");
    if (!name || !*name) return fail("需要一个字段名");
    if (!sig || !*sig) return fail("需要一个字段类型描述符");
    const char* cerr = "class not found";
    jclass c = FindClassForStatic(env, cls, &cerr);
    if (!c) return fail(std::string("类不存在: ") + cls);
    jfieldID fid = env->GetStaticFieldID(c, name, sig);
    if (!fid) { env->ExceptionClear(); env->DeleteLocalRef(c);
        return fail(std::string("静态字段不存在: ") + cls + "." + name); }
    char t = sig[0];
    jvalue jv{};
    if (!UnboxValueEx(env, t, value, &jv)) {
        env->DeleteLocalRef(c);
        return fail("值类型与字段类型不匹配（字段描述符 " + std::string(sig) + "）");
    }
    switch (t) {
    case 'Z': env->SetStaticBooleanField(c, fid, jv.z); break;
    case 'B': env->SetStaticByteField(c, fid, jv.b); break;
    case 'S': env->SetStaticShortField(c, fid, jv.s); break;
    case 'I': env->SetStaticIntField(c, fid, jv.i); break;
    case 'J': env->SetStaticLongField(c, fid, jv.j); break;
    case 'F': env->SetStaticFloatField(c, fid, jv.f); break;
    case 'D': env->SetStaticDoubleField(c, fid, jv.d); break;
    case 'C': env->SetStaticCharField(c, fid, jv.c); break;
    case 'L':
    case '[': env->SetStaticObjectField(c, fid, jv.l); break;
    default: env->DeleteLocalRef(c); return fail("不支持的字段类型描述符");
    }
    bool ok = !env->ExceptionCheck();
    if (!ok) { std::string m = ThrowableText(env); env->DeleteLocalRef(c);
        return fail("写静态字段异常" + (m.empty() ? std::string() : ": " + m)); }
    env->DeleteLocalRef(c);
    return 1;
}

// 供 Lua artHookAll() 批量安装；跳过 native/abstract（装了会崩/无效）。
// 参数 cls 只作类名；name 过滤在 Lua 侧用 Lua pattern 做，这里不过滤。
int atrace_arthook_list_methods(const char* cls, char* out, int cap,
                                char* err, int errcap) {
    if (err && errcap > 0) err[0] = 0;
    if (!out || cap <= 0) return -1;
    out[0] = 0;
    auto fail = [&](const std::string& m) -> int {
        if (err && errcap > 0) snprintf(err, (size_t)errcap, "%s", m.c_str());
        return -1;
    };
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env) return fail(eerr);
    if (!cls || !*cls) return fail("需要类名，如 com.foo.Bar");

    jclass class_cls = env->FindClass("java/lang/Class");
    jclass method_cls = env->FindClass("java/lang/reflect/Method");
    if (!class_cls || !method_cls) {
        env->ExceptionClear();
        return fail("FindClass(Class|Method) failed");
    }
    jmethodID get_decl = env->GetMethodID(class_cls, "getDeclaredMethods",
                                          "()[Ljava/lang/reflect/Method;");
    jmethodID get_super = env->GetMethodID(class_cls, "getSuperclass",
                                           "()Ljava/lang/Class;");
    jmethodID m_name = env->GetMethodID(method_cls, "getName", "()Ljava/lang/String;");
    jmethodID m_params = env->GetMethodID(method_cls, "getParameterTypes",
                                          "()[Ljava/lang/Class;");
    jmethodID m_ret = env->GetMethodID(method_cls, "getReturnType", "()Ljava/lang/Class;");
    jmethodID m_mods = env->GetMethodID(method_cls, "getModifiers", "()I");
    if (!get_decl || !get_super || !m_name || !m_params || !m_ret || !m_mods) {
        env->ExceptionClear();
        return fail("reflection methods unavailable");
    }

    jobject loader = GetAppClassLoader(env);
    jclass start = nullptr;
    bool ok = false;
    std::string bin = cls;
    for (char& c : bin) if (c == '/') c = '.';
    ok = FindClassByName(env, bin.c_str(), loader, &start);
    if (loader) env->DeleteLocalRef(loader);
    if (!ok) {
        env->ExceptionClear();
        std::string jni = cls;
        for (char& c : jni) if (c == '.') c = '/';
        start = env->FindClass(jni.c_str());
        if (!start) { env->ExceptionClear(); return fail(std::string("类不存在: ") + cls); }
    }

    std::string buf;
    std::unordered_set<std::string> seen;
    int total = 0;
    jclass cur = start;
    bool borrowed_start = true;
    while (cur) {
        jobjectArray arr = reinterpret_cast<jobjectArray>(
            env->CallObjectMethod(cur, get_decl));
        if (env->ExceptionCheck()) { env->ExceptionClear(); arr = nullptr; }
        int n = arr ? env->GetArrayLength(arr) : 0;
        for (int i = 0; i < n; ++i) {
            jobject m = env->GetObjectArrayElement(arr, i);
            if (!m) continue;
            jint mods = env->CallIntMethod(m, m_mods);
            if (env->ExceptionCheck()) { env->ExceptionClear(); mods = 0; }
            if ((mods & 0x0100) || (mods & 0x0400)) {  // native / abstract
                env->DeleteLocalRef(m);
                continue;
            }
            jstring jn = reinterpret_cast<jstring>(env->CallObjectMethod(m, m_name));
            if (!jn) { env->ExceptionClear(); env->DeleteLocalRef(m); continue; }
            std::string mname = JStringText(env, jn);
            env->DeleteLocalRef(jn);
            jobjectArray ptypes = reinterpret_cast<jobjectArray>(
                env->CallObjectMethod(m, m_params));
            if (env->ExceptionCheck()) { env->ExceptionClear(); ptypes = nullptr; }
            jclass rtype = reinterpret_cast<jclass>(env->CallObjectMethod(m, m_ret));
            if (env->ExceptionCheck()) { env->ExceptionClear(); rtype = nullptr; }
            std::string sig = "(";
            int pn = ptypes ? env->GetArrayLength(ptypes) : 0;
            for (int k = 0; k < pn; ++k) {
                jclass pc = reinterpret_cast<jclass>(env->GetObjectArrayElement(ptypes, k));
                if (!pc) { sig += "?"; continue; }
                sig += ClassDescriptor(env, pc);
                env->DeleteLocalRef(pc);
            }
            sig += ")";
            sig += rtype ? ClassDescriptor(env, rtype) : std::string("?");
            if (ptypes) env->DeleteLocalRef(ptypes);
            if (rtype) env->DeleteLocalRef(rtype);
            std::string line = mname + "|" + sig;
            env->DeleteLocalRef(m);
            if (!seen.insert(line).second) continue;
            if (buf.size() + line.size() + 2 >= (size_t)cap) break;
            buf += line;
            buf += '\n';
            total++;
        }
        if (arr) env->DeleteLocalRef(arr);
        jclass sup = reinterpret_cast<jclass>(env->CallObjectMethod(cur, get_super));
        if (env->ExceptionCheck()) { env->ExceptionClear(); sup = nullptr; }
        if (borrowed_start) { env->DeleteLocalRef(cur); borrowed_start = false; }
        cur = sup;
        if (cur) {
            std::string cn = ClassDescriptor(env, cur);
            if (cn == "Ljava/lang/Object;") { env->DeleteLocalRef(cur); cur = nullptr; }
        }
    }
    if (total == 0) return fail(std::string("类 ") + cls + " 没有可 hook 的方法（排除 native/abstract 后为空）");
    snprintf(out, (size_t)cap, "%s", buf.c_str());
    return total;
}

jobject atrace_java_find_class(const char* name, char* err, int cap) {
    if (err && cap > 0) err[0] = 0;
    auto fail = [&](const std::string& m) -> jobject {
        if (err && cap > 0) snprintf(err, (size_t)cap, "%s", m.c_str());
        SetLastErr(m);
        AH_ERR("find_class %s failed: %s", name ? name : "?", m.c_str());
        return nullptr;
    };
    std::string eerr;
    JNIEnv* env = EnvWithError(&eerr);
    if (!env) return fail(eerr);
    if (!name || !name[0]) return fail("类名为空");
    std::string bin = name;
    for (char& c : bin) if (c == '/') c = '.';
    jobject loader = GetAppClassLoader(env);
    jclass cls = nullptr;
    bool ok = FindClassByName(env, bin.c_str(), loader, &cls);
    if (loader) env->DeleteLocalRef(loader);
    if (!ok) {
        env->ExceptionClear();
        std::string jni = name;
        for (char& c : jni) if (c == '.') c = '/';
        jclass c2 = env->FindClass(jni.c_str());
        if (c2) { cls = c2; ok = true; }
        else env->ExceptionClear();
    }
    if (!ok) {
        return fail("类不存在: " + std::string(name) +
                    "（已尝试 app ClassLoader 与 boot ClassLoader；"
                    "内部类用 $ 分隔，如 com.foo.Outer$Inner）");
    }
    return cls;   // local ref
}

}  // extern "C"


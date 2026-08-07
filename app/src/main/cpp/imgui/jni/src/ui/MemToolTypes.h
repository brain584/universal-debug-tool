#pragma once

// 从 AlguiMemTool.h 提取的内存类型 / 区域分类
// （作者 ByteCat，MIT 协议）。这里的判定规则与该库的 BCMAPSFLAG()
// 逐字节一致，因此 imgui 侧对内存的分类与 AlguiMemTool / GG 完全相同。
// 该库自带的搜索函数会直接打开 /proc/<pid>/mem，
// 而（非 root 的）imgui 进程无法对其他进程这样做，
// 所以扫描循环改为在 main_ui.cpp 中
// 基于 su 读取器实现。

#include <cstring>
#include <cstdint>
#include <cstdio>
#include <string>

// 内存区域（与 AlguiMemTool.h 取值一致）。
#define RANGE_ALL 0
#define RANGE_JAVA_HEAP 2
#define RANGE_C_HEAP 1
#define RANGE_C_ALLOC 4
#define RANGE_C_DATA 8
#define RANGE_C_BSS 16
#define RANGE_ANONYMOUS 32
#define RANGE_JAVA 65536
#define RANGE_STACK 64
#define RANGE_ASHMEM 524288
#define RANGE_VIDEO 1048576
#define RANGE_OTHER -2080896
#define RANGE_B_BAD 131072
#define RANGE_CODE_APP 16384
#define RANGE_CODE_SYSTEM 32768

// 数值类型（与 AlguiMemTool.h 取值一致）。
#define TYPE_BYTE 1
#define TYPE_WORD 2
#define TYPE_DWORD 4
#define TYPE_QWORD 32
#define TYPE_FLOAT 16
#define TYPE_DOUBLE 64

// 该库使用的区间分隔符（"10~20"）。
#define R_SEPARATE "~"

// 与 AlguiMemTool.h 相同的分类宏（ARM 32/64，普通模式）。
#define BCMAPSFLAG(mapLine, id)                                                \
    (                                                                          \
        (id) == RANGE_ALL ? true :                                             \
        (id) == RANGE_JAVA_HEAP ? (strstr(mapLine, "rw") != NULL &&            \
                                   strstr(mapLine, "dalvik-") != NULL) :       \
        (id) == RANGE_C_HEAP ? (strstr(mapLine, "rw") != NULL &&               \
                                strstr(mapLine, "[heap]") != NULL) :           \
        (id) == RANGE_C_ALLOC ? (strstr(mapLine, "rw") != NULL &&              \
            (strstr(mapLine, "[anon:libc_malloc]") != NULL ||                  \
             strstr(mapLine, "[anon:scudo") != NULL)) :                        \
        (id) == RANGE_C_DATA ? (strstr(mapLine, " r") != NULL &&               \
            strstr(mapLine, "xp") == NULL &&                                   \
            (strstr(mapLine, "/data/app/") != NULL ||                          \
             strstr(mapLine, "/data/data/") != NULL ||                         \
             strstr(mapLine, "/data/user/") != NULL)) :                        \
        (id) == RANGE_C_BSS ? (strstr(mapLine, "rw") != NULL &&                \
                               strstr(mapLine, "[anon:.bss]") != NULL) :       \
        (id) == RANGE_ANONYMOUS ? (strstr(mapLine, "rw") != NULL &&            \
            strchr(mapLine, '[') == NULL && strchr(mapLine, '/') == NULL) :    \
        (id) == RANGE_JAVA ? (strstr(mapLine, "rw") != NULL &&                 \
                              strstr(mapLine, "dalvik-") != NULL) :            \
        (id) == RANGE_STACK ? (strstr(mapLine, "rw") != NULL &&                \
                               strstr(mapLine, "[stack") != NULL) :            \
        (id) == RANGE_ASHMEM ? (strstr(mapLine, "rw") != NULL &&               \
            strstr(mapLine, "xp") == NULL &&                                   \
            strstr(mapLine, "/dev/ashmem/") != NULL &&                         \
            strstr(mapLine, "dalvik") == NULL) :                               \
        (id) == RANGE_VIDEO ? (strstr(mapLine, "rw") != NULL &&                \
                               strstr(mapLine, "/dev/mali") != NULL) :         \
        (id) == RANGE_B_BAD ? (strstr(mapLine, " r") != NULL &&                \
            (strstr(mapLine, "kgsl-3d0") != NULL ||                            \
             strstr(mapLine, ".ttf") != NULL)) :                               \
        (id) == RANGE_CODE_APP ? (strstr(mapLine, " r") != NULL &&             \
            strstr(mapLine, "xp") != NULL &&                                   \
            (strstr(mapLine, "/data/app/") != NULL ||                          \
             strstr(mapLine, "/data/data/") != NULL ||                         \
             (strstr(mapLine, "/dev/ashmem/") != NULL &&                       \
              strstr(mapLine, "dalvik") != NULL) ||                            \
             strstr(mapLine, "/data/user/") != NULL)) :                        \
        (id) == RANGE_CODE_SYSTEM ? (strstr(mapLine, " r") != NULL &&          \
            strstr(mapLine, "xp") != NULL &&                                   \
            (strstr(mapLine, "/system") != NULL ||                             \
             strstr(mapLine, "/vendor") != NULL ||                             \
             strstr(mapLine, "/apex") != NULL ||                               \
             strstr(mapLine, "/memfd") != NULL ||                              \
             strstr(mapLine, "[vdso") != NULL)) :                              \
        (id) == RANGE_OTHER ? (strstr(mapLine, "rw") != NULL &&                \
            !(strstr(mapLine, "dalvik-") != NULL ||                            \
              strstr(mapLine, "[heap]") != NULL ||                             \
              strstr(mapLine, "[anon:libc_malloc]") != NULL ||                 \
              strstr(mapLine, "[anon:scudo") != NULL ||                        \
              strstr(mapLine, "/data/app/") != NULL ||                         \
              strstr(mapLine, "/data/data/") != NULL ||                        \
              strstr(mapLine, "/data/user/") != NULL ||                        \
              strstr(mapLine, "[anon:.bss]") != NULL ||                        \
              (strchr(mapLine, '[') == NULL && strchr(mapLine, '/') == NULL) ||\
              strstr(mapLine, "[stack") != NULL ||                             \
              strstr(mapLine, "/dev/ashmem/") != NULL ||                       \
              strstr(mapLine, "/dev/mali") != NULL ||                          \
              strstr(mapLine, "kgsl-3d0") != NULL ||                           \
              strstr(mapLine, ".ttf") != NULL ||                               \
              strstr(mapLine, "/system") != NULL ||                            \
              strstr(mapLine, "/vendor") != NULL ||                            \
              strstr(mapLine, "/apex") != NULL ||                              \
              strstr(mapLine, "/memfd") != NULL ||                             \
              strstr(mapLine, "[vdso") != NULL)) :                             \
        true                                                                   \
    )

// 把一条 maps 行（只需 perms / 路径部分）按 AlguiMemTool 的规则顺序
// 分类到内存页使用的相同类别中。
static inline std::string ClassifyMemType(const std::string& perms,
                                          const std::string& path) {
    char line[1024];
    snprintf(line, sizeof(line), "0-0 %s 00000000 00:00 0 %s",
             perms.c_str(), path.c_str());
    if (BCMAPSFLAG(line, RANGE_C_HEAP))       return "cpp heap";
    if (BCMAPSFLAG(line, RANGE_C_ALLOC))      return "cpp alloc";
    if (BCMAPSFLAG(line, RANGE_C_BSS))        return "bss";
    if (BCMAPSFLAG(line, RANGE_ANONYMOUS))    return "anonymous";
    if (BCMAPSFLAG(line, RANGE_STACK))        return "stack";
    if (BCMAPSFLAG(line, RANGE_ASHMEM))       return "ashmem";
    if (BCMAPSFLAG(line, RANGE_VIDEO))        return "video";
    if (BCMAPSFLAG(line, RANGE_B_BAD))        return "bad";
    if (BCMAPSFLAG(line, RANGE_CODE_SYSTEM))  return "code system";
    if (BCMAPSFLAG(line, RANGE_JAVA))         return "java";
    if (BCMAPSFLAG(line, RANGE_C_DATA))       return "cpp data";
    if (BCMAPSFLAG(line, RANGE_CODE_APP))     return "code app";
    return "other";
}

// 搜索页区域下拉框的短显示名（顺序必须与
// kSearchAreaIds 一致）。
static inline const char* MemAreaName(int id) {
    switch (id) {
    case RANGE_ALL:        return "所有内存 [ALL]";
    case RANGE_JAVA_HEAP:  return "Java堆 [Jh]";
    case RANGE_C_HEAP:     return "C堆 [Ch]";
    case RANGE_C_ALLOC:    return "C分配 [Ca]";
    case RANGE_C_DATA:     return "C数据 [Cd]";
    case RANGE_C_BSS:      return "C未初始化 [Cb]";
    case RANGE_ANONYMOUS:  return "匿名 [A]";
    case RANGE_JAVA:       return "Java [J]";
    case RANGE_STACK:      return "栈 [S]";
    case RANGE_ASHMEM:     return "Ashmem [As]";
    case RANGE_VIDEO:      return "视频 [V]";
    case RANGE_OTHER:      return "其他 [O]";
    case RANGE_B_BAD:      return "错误 [B]";
    case RANGE_CODE_APP:   return "代码应用 [Xa]";
    case RANGE_CODE_SYSTEM:return "代码系统 [Xs]";
    default:               return "未知";
    }
}

// 搜索页数值类型下拉框的短显示名。
static inline const char* MemTypeName(int type) {
    switch (type) {
    case TYPE_BYTE:   return "BYTE [B]";
    case TYPE_WORD:   return "WORD [W]";
    case TYPE_DWORD:  return "DWORD [D]";
    case TYPE_QWORD:  return "QWORD [Q]";
    case TYPE_FLOAT:  return "FLOAT [F]";
    case TYPE_DOUBLE: return "DOUBLE [E]";
    default:          return "?";
    }
}

static inline int MemTypeSize(int type) {
    switch (type) {
    case TYPE_BYTE:   return 1;
    case TYPE_WORD:   return 2;
    case TYPE_DWORD:  return 4;
    case TYPE_QWORD:  return 8;
    case TYPE_FLOAT:  return 4;
    case TYPE_DOUBLE: return 8;
    default:          return 4;
    }
}

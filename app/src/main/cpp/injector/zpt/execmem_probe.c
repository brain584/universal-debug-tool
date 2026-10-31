// 干净的能力探针：用普通 C 函数指针调用，排除内联汇编的干扰。
// 关键怀疑点：MTE（内存标记）在 aarch64 Android 16 上对「执行新建可执行页」的影响。
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>

typedef long (*fn_t)(void);

static void flush(void) { fflush(stdout); }

int main(int argc, char** argv) {
    int variant = (argc > 1) ? atoi(argv[1]) : 1;

    printf("uid=%d variant=%d\n", (int)getuid(), variant);
    flush();

    // 先探测 MTE：读 SCTLR_EL1.TCF 不可能，但 PR_MTE_TCF_* prctl 能反映内核支持
    errno = 0;
    int mte = prctl(PR_MTE_TCF_NONE, 0, 0, 0, 0);
    printf("prctl(PR_MTE_TCF_NONE)=%d errno=%d\n", mte, errno);

    int want_rwx = (variant == 1);
    int want_rw_then_x = (variant == 2);
    int want_mte_off_first = (variant == 3 || variant == 4);
    if (variant == 4) want_rwx = 1;

    if (want_mte_off_first) {
        errno = 0;
        int r = prctl(PR_MTE_TCF_NONE, 0, 0, 0, 0);
        printf("MTE off prctl -> %d errno=%d\n", r, errno);
        flush();
    }

    size_t sz = 4096;
    void* p;
    if (want_rwx) {
        p = mmap(NULL, sz, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        printf("mmap RWX -> %p (%s)\n", p, p == MAP_FAILED ? strerror(errno) : "ok");
    } else {
        p = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        printf("mmap RW -> %p (%s)\n", p, p == MAP_FAILED ? strerror(errno) : "ok");
        if (p != MAP_FAILED && want_rw_then_x) {
            errno = 0;
            int r = mprotect(p, sz, PROT_READ | PROT_EXEC);
            printf("mprotect RX -> %d errno=%d (%s)\n", r, errno, strerror(errno));
        }
        if (p != MAP_FAILED && (variant == 3)) {
            errno = 0;
            int r = mprotect(p, sz, PROT_READ | PROT_EXEC);
            printf("mprotect RX -> %d errno=%d\n", r, errno);
        }
        if (p != MAP_FAILED && (variant == 4)) {
            errno = 0;
            int r = mprotect(p, sz, PROT_READ | PROT_WRITE | PROT_EXEC);
            printf("mprotect RWX -> %d errno=%d\n", r, errno);
        }
    }
    flush();
    if (p == MAP_FAILED) return 1;

    // 显示这一页在 maps 里的真实权限
    {
        FILE* f = fopen("/proc/self/maps", "re");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f)) {
                unsigned long long a = 0, b = 0;
                if (sscanf(line, "%llx-%llx", &a, &b) == 2 &&
                    (unsigned long long)p >= a && (unsigned long long)p < b) {
                    printf("maps: %s", line);
                    break;
                }
            }
            fclose(f);
        }
    }
    flush();

    // 写一条 ret 指令
    uint32_t ret = 0xD65F03C0u;
    memcpy(p, &ret, sizeof(ret));
    __builtin___clear_cache((char*)p, (char*)p + 16);

    printf("calling payload @%p ...\n", p);
    flush();
    fn_t fn = (fn_t)p;
    long rv = fn();
    printf("EXECUTE OK rv=%ld\n", rv);
    flush();
    return 0;
}

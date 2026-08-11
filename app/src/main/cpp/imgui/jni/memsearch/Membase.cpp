#include "Membase.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <cstdio>

uintptr_t MemBase::get_module_base(const char *module_name) const
{
    FILE *fp;
    uintptr_t addr = 0;
    char filename[32], buffer[1024];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    fp = fopen(filename, "rt");
    if (fp != nullptr)
    {
        while (fgets(buffer, sizeof(buffer), fp))
        {
            if (strstr(buffer, module_name))
            {
#if defined(__LP64__)
                sscanf(buffer, "%lx-%*s", &addr);
#else
                sscanf(buffer, "%x-%*s", &addr);
#endif
                break;
            }
        }
        fclose(fp);
    }
    return addr;
}

uintptr_t MemBase::get_module_end(const char *module_name) const
{
    FILE *fp;
    uintptr_t temp = 0, addr = 0;
    char filename[32], buffer[1024];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    fp = fopen(filename, "rt");
    if (fp != nullptr)
    {
        while (fgets(buffer, sizeof(buffer), fp))
        {
            if (strstr(buffer, module_name))
            {
#if defined(__LP64__)
                sscanf(buffer, "%lx-%lx %*s", &temp, &addr);
#else
                sscanf(buffer, "%x-%x %*s", &temp, &addr);
#endif
            }
        }
        fclose(fp);
    }
    return addr;
}

ProcMap MemBase::get_address_map(uintptr_t address) const
{
    FILE *fp;
    char filename[32], buffer[1024];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    fp = fopen(filename, "rt");
    if (fp == nullptr)
    {
        fprintf(stderr, "Failed to open maps file for PID %d\n", pid);
        return {};
    }

    ProcMap map;
    while (fgets(buffer, sizeof(buffer), fp))
    {
        uintptr_t start, end;
        char perms[5], dev[12], pathname[256] = {0};
        unsigned long offset;
        unsigned long inode;
#if defined(__LP64__)
        int matched = sscanf(buffer, "%lx-%lx %4s %lx %11s %lu %255[^\n]", &start, &end, perms, &offset, dev, &inode, pathname);
#else
        int matched = sscanf(buffer, "%x-%x %4s %x %11s %lu %255[^\n]", &start, &end, perms, &offset, dev, &inode, pathname);
#endif
        if (matched < 6)        {
            continue; // 格式错误，跳过
        }
        if (address >= start && address < end)
        {
            map.startAddress = start;
            map.endAddress = end;
            map.length = end - start;
            map.protection = 0;
            map.readable = (perms[0] == 'r');
            map.writeable = (perms[1] == 'w');
            map.executable = (perms[2] == 'x');
            map.is_private = (perms[3] == 'p');
            map.is_shared = (perms[3] == 's');
            map.is_ro = (map.readable && !map.writeable);
            map.is_rw = (map.readable && map.writeable);
            map.is_rx = (map.readable && map.executable);
            map.offset = offset;
            map.dev = dev;
            map.inode = inode;
            if (matched == 7)
                map.pathname = pathname;
            else
                map.pathname.clear();
            fclose(fp);
            return map;
        }
    }
    fclose(fp);
    return map;
}

std::vector<ProcMap> MemBase::get_module_maps(const char *module_name) const
{
    FILE *fp;
    char filename[32], buffer[1024];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    fp = fopen(filename, "rt");
    if (fp == nullptr)
    {
        fprintf(stderr, "Failed to open maps file for PID %d\n", pid);
        return {};
    }

    std::vector<ProcMap> maps;
    while (fgets(buffer, sizeof(buffer), fp))
    {
        uintptr_t start, end;
        char perms[5], dev[12], pathname[256] = {0};
        unsigned long offset;
        unsigned long inode;
#if defined(__LP64__)
        int matched = sscanf(buffer, "%lx-%lx %4s %lx %11s %lu %255[^\n]", &start, &end, perms, &offset, dev, &inode, pathname);
#else
        int matched = sscanf(buffer, "%x-%x %4s %x %11s %lu %255[^\n]", &start, &end, perms, &offset, dev, &inode, pathname);
#endif
        if (matched < 6)
        {
            continue; // 格式错误，跳过
        }
        if (strstr(pathname, module_name))
        {
            ProcMap map;
            map.startAddress = start;
            map.endAddress = end;
            map.length = end - start;
            map.protection = 0;
            map.readable = (perms[0] == 'r');
            map.writeable = (perms[1] == 'w');
            map.executable = (perms[2] == 'x');
            map.is_private = (perms[3] == 'p');
            map.is_shared = (perms[3] == 's');
            map.is_ro = (map.readable && !map.writeable);
            map.is_rw = (map.readable && map.writeable);
            map.is_rx = (map.readable && map.executable);
            map.offset = offset;
            map.dev = dev;
            map.inode = inode;
            if (matched == 7)
                map.pathname = pathname;
            maps.push_back(map);
        }
    }
    fclose(fp);
    return maps;
}

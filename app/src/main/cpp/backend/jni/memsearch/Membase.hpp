#ifndef MEMBASE_HPP
#define MEMBASE_HPP

#include <cstdint>
#include "ProcMap.hpp"
#include <vector>
class MemBase
{
public:
    virtual ~MemBase() = default;
    int get_pid() const { return pid; }
    void set_pid(int new_pid) { pid = new_pid; }
    // 原始字节读写，返回是否成功
    virtual bool read(uintptr_t address, void *buffer, size_t size) = 0;
    virtual bool write(uintptr_t address, const void *buffer, size_t size) = 0;

    template <typename T>
    T Read(uintptr_t address)
    {
        T out;
        if (read(address, &out, sizeof(T)))
        {
            return out;
        }
        return T(); // 失败时返回默认值
    }

    template <typename T>
    bool Write(uintptr_t address, const T &value)
    {
        return write(address, &value, sizeof(T));
    }

    virtual uintptr_t get_module_base(const char *module_name) const;
    virtual uintptr_t get_module_end(const char *module_name) const;
    virtual ProcMap get_address_map(uintptr_t address) const ;
    virtual std::vector<ProcMap> get_module_maps(const char *module_name) const;

protected:
    int pid = -1;
};
#endif // MEMBASE_HPP
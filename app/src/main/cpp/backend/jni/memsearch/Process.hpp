#ifndef PROCESS_HPP
#define PROCESS_HPP

#include <vector>
#include "ProcMap.hpp"

namespace Process
{
    struct ProcessInfo
    {
        int pid;
        std::string name;
    };
    
    std::vector<ProcMap> get_process_maps(int pid);
    int get_pid_by_name(const char *process_name);
    std::vector<ProcessInfo> list_processes();
};

#endif // PROCESS_HPP
#include "box.h"

int main()
{
    HMODULE Ntdllbase = NULL;
    PIMAGE_EXPORT_DIRECTORY pImgDir = NULL;
    SYSCALL_INFO info = { 0 };

    INFO("Walking PEB!");

    Ntdllbase = WalkPeb(&pImgDir);
    if (!Ntdllbase)
    {
        PRINT_ERROR("WalkPeb");
        return 1;
    }

    INFO("Hashing API!");

    DWORD apiHash = sdbmrol16(
        "NtWriteVirtualMemory"
    );

    INFO("Resolving syscall!");

    if (MagmaGate(pImgDir, Ntdllbase, apiHash, &info))
    {
        INFO("Nt Addr  : %p", info.Nt_Function);
        INFO("SSN      : %llu", info.SSN);
        INFO("Syscall  : %p", info.SyscallInstruction);
    }

    return 0;
}
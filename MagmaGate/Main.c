#include "box.h"

int main()
{
    PVOID Ntdllbase = NULL;
    PIMAGE_EXPORT_DIRECTORY pImgDir = NULL;
    SYSCALL_INFO info = { 0 };

    INFO("Walking PEB!");

    Ntdllbase = WalkPeb();
    if (!Ntdllbase)
    {
        PRINT_ERROR("WalkPeb");
        return 1;
    }

    INFO("Getting EAT!");

    if (!GetEAT(Ntdllbase, &pImgDir))
    {
        PRINT_ERROR("GetEAT");
        return 1;
    }

    INFO("Hashing API!");

    DWORD apiHash = GetBaseHash(
        "NtWriteVirtualMemory",
        Ntdllbase,
        pImgDir
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
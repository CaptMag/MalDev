#pragma once
#include <Windows.h>

#define SHUTDOWN_PRIVILGE 19
#define OPTION_SHUTDOWN 6

typedef NTSTATUS(NTAPI* pdef_RtlAdjustPrivilege)(
    ULONG privilege,
    BOOLEAN enable,
    BOOLEAN current_thread,
    PBOOLEAN enabled);

typedef NTSTATUS(NTAPI* pdef_NtRaiseHardError)(
    NTSTATUS error_status,
    ULONG number_of_parameters,
    ULONG unicode_string_parameter_mask,
    PULONG_PTR parameters,
    ULONG response_option,
    PULONG reponse);

BOOL BlueScreen();
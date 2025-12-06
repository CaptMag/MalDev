#include <Windows.h>
#include <stdio.h>

typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW); // f u Microsoft

BOOL GetOSInfo()
{


	OSVERSIONINFOEX  versioninfo;
	ZeroMemory(&versioninfo, sizeof(OSVERSIONINFOEX));
	versioninfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == NULL)
    {
        printf("Failed to get ntdll handle\n");
        return FALSE;
    }

    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
    if (RtlGetVersion == NULL)
    {
        printf("Failed to get RtlGetVersion\n");
        return FALSE;
    }

    if (RtlGetVersion(&versioninfo) != 0)
    {
        printf("RtlGetVersion failed\n");
        return FALSE;
    }

	printf("| Major Version : %lu\n"
           "| Minor Version : %lu\n"
           "| Build Number  : %lu\n"
           "| Platform ID   : %lu\n"
           "| Product Type  : %lu\n"
           "_______________________\n",
        versioninfo.dwMajorVersion, versioninfo.dwMinorVersion, versioninfo.dwBuildNumber, versioninfo.dwPlatformId, versioninfo.wProductType);

    switch (versioninfo.dwPlatformId) {
    case VER_PLATFORM_WIN32s:
        printf("(Win32s on Windows 3.1)\n");
        break;
    case VER_PLATFORM_WIN32_WINDOWS:
        printf("(Windows 95/98/ME)\n");
        break;
    case VER_PLATFORM_WIN32_NT:
        printf("(Windows NT/2000/XP/Vista/7/8/10/11)\n");
        break;
    default:
        printf("(Unknown)\n");
    }

    switch (versioninfo.wProductType) {
    case VER_NT_WORKSTATION:
        printf("(Workstation)\n");
        break;
    case VER_NT_DOMAIN_CONTROLLER:
        printf("(Domain Controller)\n");
        break;
    case VER_NT_SERVER:
        printf("(Server)\n");
        break;
    default:
        printf("(Unknown)\n");
    }


    printf("Suite Mask:           0x%04X\n", versioninfo.wSuiteMask);
    if (versioninfo.wSuiteMask & VER_SUITE_SMALLBUSINESS)
        printf("  - Small Business Server\n");
    if (versioninfo.wSuiteMask & VER_SUITE_ENTERPRISE)
        printf("  - Enterprise Edition\n");
    if (versioninfo.wSuiteMask & VER_SUITE_BACKOFFICE)
        printf("  - BackOffice components installed\n");
    if (versioninfo.wSuiteMask & VER_SUITE_COMMUNICATIONS)
        printf("  - Communications Server\n");
    if (versioninfo.wSuiteMask & VER_SUITE_TERMINAL)
        printf("  - Terminal Services\n");
    if (versioninfo.wSuiteMask & VER_SUITE_SMALLBUSINESS_RESTRICTED)
        printf("  - Small Business Server (Restricted)\n");
    if (versioninfo.wSuiteMask & VER_SUITE_EMBEDDEDNT)
        printf("  - Embedded Edition\n");
    if (versioninfo.wSuiteMask & VER_SUITE_DATACENTER)
        printf("  - Datacenter Edition\n");
    if (versioninfo.wSuiteMask & VER_SUITE_SINGLEUSERTS)
        printf("  - Single User Terminal Services\n");
    if (versioninfo.wSuiteMask & VER_SUITE_PERSONAL)
        printf("  - Home Edition\n");
    if (versioninfo.wSuiteMask & VER_SUITE_BLADE)
        printf("  - Web Server (Blade)\n");
    if (versioninfo.wSuiteMask & VER_SUITE_EMBEDDED_RESTRICTED)
        printf("  - Embedded Restricted\n");
    if (versioninfo.wSuiteMask & VER_SUITE_SECURITY_APPLIANCE)
        printf("  - Security Appliance\n");
    if (versioninfo.wSuiteMask & VER_SUITE_STORAGE_SERVER)
        printf("  - Storage Server\n");
    if (versioninfo.wSuiteMask & VER_SUITE_COMPUTE_SERVER)
        printf("  - Compute Cluster Server\n");
    if (versioninfo.wSuiteMask & VER_SUITE_WH_SERVER)
        printf("  - Windows Home Server\n");
    

	return TRUE;
}

int main()
{

	GetOSInfo();

	return 0;
}
#include "func.h"
#include "structures.h"

void printfheader(const char* text)
{

	const int indent = 6; // used to indent the text
	int border = indent + strlen(text); // used to calculate how much border it should put

	for (int i = 0; i < border; i++) putchar("=");
	putchar('\n');

	for (int i = 0; i < indent; i++) putchar(' ');
	printf("%s\n", text);

	for (int i = 0; i < border; i++) putchar("=");
	putchar('\n');

}

char ezprintf(uint32_t reg, uint32_t bit, char t, char f)
{

	return (reg & (1u << bit)) ? t : f;

}

BOOL checkmem()
{

	ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
	MEMORYSTATUSEX ms;
	ms.dwLength = sizeof(MEMORYSTATUSEX);

	printfheader("Memory Space/Usage");

	GlobalMemoryStatusEx(&ms);
	printf("Total page file:\t %llu MB\n", (ms.ullTotalPageFile / DIV));
	printf("Total page file in use:\t %llu MB\n", ((ms.ullTotalPageFile - ms.ullAvailPageFile) / DIV));
	printf("Total physical memory:\t %llu MB\n", (ms.ullTotalPhys / DIV));
	printf("Total physical memory in use:\t %llu MB\n", ((ms.ullTotalPhys - ms.ullAvailPhys) / DIV));
	printf("Virtual memory:\t %llu MB\n", (ms.ullTotalVirtual / DIV));
	printf("Virtual memory in use:\t %llu MB\n", ((ms.ullTotalVirtual - ms.ullAvailVirtual) / DIV));
	printf("Percentage of physical memory in use:\t %u%%\n", ms.dwMemoryLoad);

	if (!GetDiskFreeSpaceEx(L"C:\\", &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes))
	{
		printf("Could Not Get Disk Space! Reason: %lu\n", GetLastError());
	}

	printfheader("Disk Space");

	printf("Total Disk Space: %llu GB\n", totalNumberOfBytes.QuadPart / true_space);
	printf("Total Free Disk Space: %llu GB\n", totalNumberOfFreeBytes.QuadPart / true_space);

	return TRUE;

}

BOOL leaf1info()
{

	printfheader("Leaf 1 Info");


	extern void leaf01(uint32_t * pOut);

	uint32_t cpuinfo[4]; // array that holds the 4 needed registers

	leaf01(cpuinfo);

	uint32_t eax = cpuinfo[0];
	uint32_t ebx = cpuinfo[1];
	uint32_t ecx = cpuinfo[2];
	uint32_t edx = cpuinfo[3];

	uint32_t logical_processors = (ebx >> 16) & 0xFF;
	uint32_t apic_id = (ebx >> 24) & 0xFF;

	uint32_t HV_present = (ecx >> 31) & 0xFF;

	printf("VMX: %c\n", ezprintf(ecx, 5, 'Y', 'N'));

	printf("SSE3: %c\n", ezprintf(ecx, 0, 'Y', 'N'));

	printf("SSSE3: %c\n", ezprintf(ecx, 9, 'Y', 'N'));

	printf("SSE4.1: %c\n", ezprintf(ecx, 19, 'Y', 'N'));

	printf("SSE4.2: %c\n", ezprintf(ecx, 20, 'Y', 'N'));

	printf("MOVBE: %c\n", ezprintf(ecx, 22, 'Y', 'N'));

	printf("OSXSAVE: %c\n", ezprintf(ecx, 27, 'Y', 'N'));

	printf("AVX: %c\n", ezprintf(ecx, 28, 'Y', 'N'));

	printf("HyperVisor: %c\n", ezprintf(ecx, 31, 'Y', 'N'));

	printf("SSE: %c\n", ezprintf(edx, 25, 'Y', 'N'));

	printf("SSE2: %c\n", ezprintf(edx, 26, 'Y', 'N'));

	printf("HTT: %c\n", ezprintf(edx, 28, 'Y', 'N'));

	printf("Amount of Logical Processors: %u\n", logical_processors);

	printf("APIC ID: %u\n", apic_id);

	printf("HV Present: %u\n", HV_present);

	return TRUE;
}

BOOL leaf4info()
{

	printfheader("Lead 4 Info");

	extern void leaf04(uint32_t * pOut);

	uint32_t info[4];

	leaf04(info);

	char ms_hv[13];

	memcpy(ms_hv + 0, &info[1], 4);
	memcpy(ms_hv + 4, &info[2], 4);
	memcpy(ms_hv + 8, &info[3], 4);
	ms_hv[12] = 0;

	printf("Microsoft Hypervisor: %s\n", ms_hv);

	return TRUE;

}
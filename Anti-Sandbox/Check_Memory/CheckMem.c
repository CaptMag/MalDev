#include "func.h"

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
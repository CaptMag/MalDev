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

char ezprintf(uint32_t reg, uint32_t bit, char t, char f)
{

	return (reg & (1u << bit)) ? t : f;

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

	char Hypervisor[13];

	memcpy(Hypervisor + 0, &info[1], 4);
	memcpy(Hypervisor + 4, &info[2], 4);
	memcpy(Hypervisor + 8, &info[3], 4);
	Hypervisor[12] = 0;

	printf("Current Hypervisor: %s\n", Hypervisor);

	if (strcmp(Hypervisor, "VMwareVMware") == 0) {
		WARN("Running in VMware!");
		return FALSE;
	}
	else if (strcmp(Hypervisor, "Microsoft Hv") == 0) {
		WARN("Running in Hyper-V!");
		return FALSE;
	}
	else if (strcmp(Hypervisor, "KVMKVMKVM") == 0) {
		WARN("Running in KVM!");
		return FALSE;
	}
	else if (strcmp(Hypervisor, "VBoxVBoxVBox") == 0) {
		WARN("Running in VirtualBox!");
		return FALSE;
	}
	else if (strcmp(Hypervisor, "TCGTCGTCGTCG") == 0) {
		WARN("Running in QEMU!");
		return FALSE;
	}
	else if (strcmp(Hypervisor, "XenVMMXenVMM") == 0) {
		WARN("Running in Xen");
		return FALSE;
	}
	else {
		WARN("Unknown hypervisor");
	}

	return TRUE;

}
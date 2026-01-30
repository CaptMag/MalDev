#include "func.h"
#include "structures.h"

// https://github.com/saibulusu/SMBIOS-Parser/blob/master/Functions.cpp

void printheader(const char* text)
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

uint8_t* GetNextStruct
(
	SMBIOS_HEADER* cur,
	uint8_t* end
)

{

	uint8_t* p;

	if (!cur)
		return NULL;

	// string begin
	p = (uint8_t*)cur + cur->Length;

	while (p + 1 < end)
	{

		if (p[0] == 0 && p[1] == 0)
			return p + 2;

		p++;

	}


	return NULL;

}

// https://github.com/brunexgeek/smbios-parser/blob/master/smbios.c#L111

const char* getString
(
	SMBIOS_HEADER* cur,
	uint8_t Index
)

{

	char* str;
	uint8_t i = 1;

	if (!cur || Index == 0)
		return "";

	str = (char*)cur + cur->Length;

	while (*str && i < Index)
	{

		while (*str != 0)
			str++;

		str++;
		i++;

	}

	if (!*str)
		return "";

	return str;

}

void ParseType0
(
	SMBIOS_HEADER* hdr
)

{

	if (hdr->Length < sizeof(SMBIOS_TYPE0))
		return;

	SMBIOS_TYPE0* t0 = (SMBIOS_TYPE0*)hdr;

	printf("BIOS Vendor: %s\n", getString(hdr, t0->Vendor));

	printf("BIOS Version: %s\n", getString(hdr, t0->Version));

}

void ParseType1
(
	SMBIOS_HEADER* hdr
)

{

	printheader("SMBIOS Type 1");

	if (hdr->Length < sizeof(SMBIOS_TYPE1))
		return;

	SMBIOS_TYPE1* t1 = (SMBIOS_TYPE1*)hdr;

	printf("Machine Manufactuer: %s\n", getString(hdr, t1->Manufacturer));
	printf("Product Name: %s\n", getString(hdr, t1->ProductName));
	printf("Version: %s\n", getString(hdr, t1->Version));
	printf("Serial Number: %s\n", getString(hdr, t1->SerialNumber));

	int n = sizeof(t1->UUID) / sizeof(t1->UUID[0]);

	for (int i = 0; i < n; i++)
	{
		printf("%d ", t1->UUID[i]);
	}

}

void ParseType2
(
	SMBIOS_HEADER* hdr
)

{

	printheader("SMBIOS Type 2");

	if (hdr->Length < sizeof(SMBIOS_TYPE2))
		return;

	SMBIOS_TYPE2* t2 = (SMBIOS_TYPE2*)hdr;

	printf("Manufactuer: %s\n", getString(hdr, t2->Manufacturer));
	printf("Product Name: %s\n", getString(hdr, t2->Product));
	printf("Version: %s\n", getString(hdr, t2->Version));
	printf("Serial Number: %s\n", getString(hdr, t2->SerialNumber));
	printf("AssetTag: %s\n", getString(hdr, t2->AssetTag));
	printf("Location in Chassis: %s\n", getString(hdr, t2->LocationInChassis));

}

BOOL sysFirmware()
{

	DWORD size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
	void* buffer = malloc(size);

	if (!GetSystemFirmwareTable('RSMB', 0, buffer, size))
	{
		printf("Failed to Gather SMBIOS Table Information! Reason: %lu\n", GetLastError());
	}

	RawSMBIOSData* raw = (RawSMBIOSData*)buffer;

	uint8_t* p = raw->SMBIOSTableData;
	uint8_t* end = p + raw->Length;

	while (p < end)
	{


		SMBIOS_HEADER* smHeader = (SMBIOS_HEADER*)p;

		if (smHeader->Length < sizeof(SMBIOS_HEADER))
			break;

		printf("Type: %u, Handle: 0x%04X\n", smHeader->Type, smHeader->Handle);

		switch (smHeader->Type)
		{

			case 0:
				ParseType0(smHeader);
				break;

			case 1:
				ParseType1(smHeader);
				break;

			case 2:
				ParseType2(smHeader);
				break;

			case 127:
				return TRUE;

			default:
				return TRUE;
		}

		p = GetNextStruct(smHeader, end);
		if (!p)
			break;

	}

	return TRUE;

}
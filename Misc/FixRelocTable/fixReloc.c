
#include "utils.h"

BOOL fixReloc
(
	IN DWORD RelocRVA,
	IN PVOID localBuffer,
	IN DWORD_PTR dwDelta
)
{

	if (!localBuffer || RelocRVA == 0)
		return FALSE;

	PIMAGE_BASE_RELOCATION Reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)localBuffer + RelocRVA);
	PBASE_RELOCATION_ENTRY relocationRVA = NULL;

	while (Reloc->SizeOfBlock)
	{
		DWORD size = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		relocationRVA = (PBASE_RELOCATION_ENTRY)(Reloc + 1);

		INFO("VirtualAddress: 0x%08X | SizeofBlock: 0x%04d | Size: 0x%04d", Reloc->VirtualAddress, Reloc->SizeOfBlock, size);

		for (DWORD i = 0; i < size; i++)
		{
			if (relocationRVA[i].Type == IMAGE_REL_BASED_DIR64)
			{
				ULONGLONG* PatchedAddress = (ULONGLONG*)((PBYTE)localBuffer + Reloc->VirtualAddress + relocationRVA[i].Offset);
				*PatchedAddress += (ULONGLONG)dwDelta;
			}
		}
		Reloc = (PIMAGE_BASE_RELOCATION)((PBYTE)Reloc + Reloc->SizeOfBlock);
	}

	return TRUE;

}
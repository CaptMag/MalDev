#include "Win32.h"

extern __declspec(dllexport) BOOLEAN NativeReflectiveLoader(LPVOID lpParameter)
{

	Win32				 NativeLoaderApi				= { 0 };
	fnDllMain			 DllMain						= NULL;
	PIMAGE_TLS_DIRECTORY TlsDir							= NULL;
	PIMAGE_TLS_CALLBACK* TlsCallback					= NULL;

	ULONG_PTR			 CurrentAddress					= 0;
	ULONG_PTR			 HeaderValue					= 0;

	PVOID				 ReflectiveLoaderBaseAddress	= NULL;
	PVOID				 ImageBase						= NULL;
	PVOID				 EntryPoint						= NULL;

	DWORD_PTR			 Delta							= 0;
	DWORD				 RelocRVA						= 0;
	DWORD				 TlsRva							= 0;

	CurrentAddress = U_PTR(NativeReflectiveLoader);

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

	ReflectiveLoaderBaseAddress = C_PTR(CurrentAddress);

	
	NativeLoaderApi.Module.Ntdll					 = GetModuleByHash(ntdll_dll_HASH);

	NativeLoaderApi.Api.LdrGetProcedureAddress		 = ResolveHashedFunction(&NativeLoaderApi, NativeLoaderApi.Module.Ntdll, LdrGetProcedureAddress_HASH);
	NativeLoaderApi.Api.NtAllocateVirtualMemory		 = ResolveHashedFunction(&NativeLoaderApi, NativeLoaderApi.Module.Ntdll, NtAllocateVirtualMemory_HASH);
	NativeLoaderApi.Api.NtProtectVirtualMemory		 = ResolveHashedFunction(&NativeLoaderApi, NativeLoaderApi.Module.Ntdll, NtProtectVirtualMemory_HASH);
	NativeLoaderApi.Api.NtFlushInstructionCache		 = ResolveHashedFunction(&NativeLoaderApi, NativeLoaderApi.Module.Ntdll, NtFlushInstructionCache_HASH);
	NativeLoaderApi.Api.RtlMultiByteToUnicodeN		 = ResolveHashedFunction(&NativeLoaderApi, NativeLoaderApi.Module.Ntdll, RtlMultiByteToUnicodeN_HASH);
	NativeLoaderApi.Api.LdrLoadDll					 = ResolveHashedFunction(&NativeLoaderApi, NativeLoaderApi.Module.Ntdll, LdrLoadDll_HASH);

	NativeLoaderApi.PeHeaders.pImgNtHdrs			 = (PIMAGE_NT_HEADERS64)(U_PTR(ReflectiveLoaderBaseAddress) + ((PIMAGE_DOS_HEADER)ReflectiveLoaderBaseAddress)->e_lfanew);
	NativeLoaderApi.PeHeaders.pImgSecHdr			 = IMAGE_FIRST_SECTION(NativeLoaderApi.PeHeaders.pImgNtHdrs);
	
	NativeLoaderApi.PeHeaders.pEntryImportDataDir	 = &NativeLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	NativeLoaderApi.PeHeaders.pEntryExportDataDir	 = &NativeLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	NativeLoaderApi.PeHeaders.pEntryBaseRelocDataDir = &NativeLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	NativeLoaderApi.PeHeaders.pEntryExceptionDataDir = &NativeLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	NativeLoaderApi.PeHeaders.pEntryTLSDataDir		 = &NativeLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

	SIZE_T AllocationSize = NativeLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.SizeOfImage;
	if (!NT_SUCCESS(NativeLoaderApi.Api.NtAllocateVirtualMemory(NtCurrentProcess(), &ImageBase, 0, &AllocationSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE)))
	{
		return FALSE;
	}

	for (DWORD i = 0; i < NativeLoaderApi.PeHeaders.pImgNtHdrs->FileHeader.NumberOfSections; i++)
	{

		if (NativeLoaderApi.PeHeaders.pImgSecHdr[i].SizeOfRawData == 0)
			continue;

		__movsb
		(
			(PUCHAR)(U_PTR(ImageBase) + NativeLoaderApi.PeHeaders.pImgSecHdr[i].VirtualAddress),
			(PUCHAR)(U_PTR(ReflectiveLoaderBaseAddress) + NativeLoaderApi.PeHeaders.pImgSecHdr[i].PointerToRawData),
			NativeLoaderApi.PeHeaders.pImgSecHdr[i].SizeOfRawData
		);

	}

	Delta = (U_PTR(ImageBase) - NativeLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.ImageBase);
	RelocRVA = NativeLoaderApi.PeHeaders.pEntryBaseRelocDataDir->VirtualAddress;

	if (!ResolveIAT(ImageBase, NativeLoaderApi.PeHeaders.pEntryImportDataDir, &NativeLoaderApi))
	{
		return FALSE;
	}

	if (!RelocSections(RelocRVA, ImageBase, Delta))
	{
		return FALSE;
	}

	if (!ChangeMemoryProtection(ImageBase, NativeLoaderApi.PeHeaders.pImgNtHdrs, &NativeLoaderApi))
	{
		return FALSE;
	}

	TlsRva = NativeLoaderApi.PeHeaders.pEntryTLSDataDir->VirtualAddress;
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

	if (!NT_SUCCESS(NativeLoaderApi.Api.NtFlushInstructionCache(NtCurrentProcess(), NULL, 0)))
		return FALSE;

	EntryPoint = C_PTR((U_PTR(ImageBase) + NativeLoaderApi.PeHeaders.pImgNtHdrs->OptionalHeader.AddressOfEntryPoint));
	if (!EntryPoint)
		return FALSE;

	DllMain = (fnDllMain)EntryPoint;
	DllMain((HINSTANCE)ImageBase, DLL_PROCESS_ATTACH, NULL);

	return TRUE;

}
#include "box.h"
#include "Aes.h"

// https://github.com/Cracked5pider/CodeCave/blob/main/EkkoEx/EkkoEx.c

const BYTE Nonce[] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B
};

VOID AesGenKey
(
	OUT PBYTE *AesKey,
	OUT DWORD *AesKeyLen
)
{

	BCRYPT_ALG_HANDLE hAlg = NULL;
	PBYTE Key = 0;
	DWORD KeyLen = 0;

	Key = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 256);
	KeyLen = 256;

	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
	{
		return;
	}

	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0)))
		return;

	*AesKey = Key;
	*AesKeyLen = KeyLen;

}

PBYTE AesEncrypt
(
	IN PBYTE Buffer,
	IN DWORD BufferSize,
	OUT DWORD* EncryptedSize,
	IN PBYTE AesKey,
	OUT PBYTE* pTag,
	OUT PBYTE* pCipherText
)
{

	CONTEXT CtxThread = { 0 };
	CtxThread.ContextFlags = CONTEXT_FULL;
	GetThreadContext(GetCurrentThread(), &CtxThread);

	CONTEXT  Rop[10] = { 0 };
	pAesApi Api = { 0 };
	RtlSecureZeroMemory(&Api, sizeof(Api));

	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	DWORD pcbResult = 0;
	PBYTE CipherText = 0;
	DWORD EncryptedBytes = 0;
	PBYTE Tag = 0;
	PBYTE StackBuffer[10];

	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
	BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

	for (int i = 0; i < 10; i++)
	{
		StackBuffer[i] = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x100);
	}

	for (int i = 0; i < 10; i++)
	{
		memcpy(&Rop[i], &CtxThread, sizeof(CONTEXT));
		Rop[i].Rsp = (DWORD64)StackBuffer[i];
		Rop[i].Rsp -= 8;
	}

	/*
	
		You may see me use the RSP + 0x123 bytes for parameters that exceed the standard 4 registers.
		the reason for this is because of Microsoft's ABI software convention

		Although there are many more volatile registers, Microsoft has capped this to allow
		only 4 registers to pass in the first 4 arguments RCX, RDX, R8, R9 (and RIP for the Api), 
		after that, arguments must be written onto the stack.

		After these registers are used it's very risky to use any memory above the RSP,
		this is because on the x64 stack usage, the OS/Debugger can overwrite this memory
		borking our entire program

		https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170#x64-register-usage
		https://learn.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-170
		https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/windows-x64-calling-convention-stack-frame

	*/

	Rop[0].Rip = Api->BCryptOpenAlgorithmProvider;
	Rop[0].Rcx = &hAlg;
	Rop[0].Rdx = BCRYPT_AES_ALGORITHM;
	Rop[0].R8 = NULL;
	Rop[0].R9 = 0;

	Rop[1].Rip = Api->BCryptSetProperty;
	Rop[1].Rcx = hAlg;
	Rop[1].Rdx = BCRYPT_CHAINING_MODE;
	Rop[1].R8 = (PBYTE)BCRYPT_CHAIN_MODE_GCM;
	Rop[1].R9 = sizeof(BCRYPT_CHAIN_MODE_GCM);
	*(DWORD64*)(StackBuffer[1] + 0x20) = (DWORD64)0;

	Rop[2].Rip = Api->BCryptGenerateSymmetricKey;
	Rop[2].Rcx = hAlg;
	Rop[2].Rdx = &hKey;
	Rop[2].R8 = NULL;
	Rop[2].R9 = 0;
	*(DWORD64*)(StackBuffer[2] + 0x20) = (DWORD64)AesKey;
	*(DWORD64*)(StackBuffer[2] + 0x28) = (DWORD64)AES_KEY_SIZE;
	*(DWORD64*)(StackBuffer[2] + 0x30) = (DWORD64)0;

	Tag = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, GCM_TAG_SIZE);

	authInfo.cbNonce = GCM_NONCE_SIZE;
	authInfo.pbNonce = (PBYTE)Nonce;
	authInfo.pbTag = Tag;
	authInfo.cbTag = GCM_TAG_SIZE;

	Rop[3].Rip = Api->BCryptEncrypt;
	Rop[3].Rcx = hKey;
	Rop[3].Rdx = Buffer;
	Rop[3].R8 = BufferSize;
	Rop[3].R9 = &authInfo;
	*(DWORD64*)(StackBuffer[3] + 0x20) = (DWORD64)NULL;
	*(DWORD64*)(StackBuffer[3] + 0x28) = (DWORD64)0;
	*(DWORD64*)(StackBuffer[3] + 0x30) = (DWORD64)CipherText;
	*(DWORD64*)(StackBuffer[3] + 0x38) = (DWORD64)pcbResult;
	*(DWORD64*)(StackBuffer[3] + 0x40) = (DWORD64)&EncryptedBytes;
	*(DWORD64*)(StackBuffer[3] + 0x48) = (DWORD64)0;

	*pCipherText = CipherText;
}

PBYTE AesDecrypt
(
	IN PBYTE *pCipherText,
	IN DWORD *pCipherSize,
	IN PBYTE *pTag,
	IN DWORD TagSize,
	IN PBYTE Key,
	OUT PDWORD pPlainTextSize,
	OUT PBYTE* pPlainText
)
{

	CONTEXT CtxThread = { 0 };
	CtxThread.ContextFlags = CONTEXT_FULL;
	GetThreadContext(GetCurrentThread(), &CtxThread);

	CONTEXT Rop[10] = { 0 };
	pAesApi Api = { 0 };
	RtlSecureZeroMemory(&Api, sizeof(Api));

	NTSTATUS status = NULL;
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	PBYTE PlainText = 0;
	PBYTE CipherText = 0;
	PBYTE Tag = 0;
	DWORD CipherSize = 0;
	DWORD PlainTextSize = 0;
	DWORD DecryptedBytes = 0;
	PBYTE StackBuffer[10];
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
	BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

	for (int i = 0; i < 10; i++)
	{
		StackBuffer[i] = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x100);
	}

	for (int i = 0; i < 10; i++)
	{
		memcpy(&Rop[i], &CtxThread, sizeof(CONTEXT));
		Rop[i].Rsp = (DWORD64)StackBuffer[i];
		Rop[i].Rsp -= 8;
	}

	Rop[0].Rip = Api->BCryptOpenAlgorithmProvider;
	Rop[0].Rcx = &hAlg;
	Rop[0].Rdx = BCRYPT_AES_ALGORITHM;
	Rop[0].R8 = NULL;
	Rop[0].R9 = 0;

	Rop[1].Rip = Api->BCryptSetProperty;
	Rop[1].Rcx = hAlg;
	Rop[1].Rdx = BCRYPT_CHAINING_MODE;
	Rop[1].R8 = (PBYTE)BCRYPT_CHAIN_MODE_GCM;
	Rop[1].R9 = sizeof(BCRYPT_CHAIN_MODE_GCM);
	*(DWORD64*)(StackBuffer[1] + 0x20) = (DWORD64)0;

	Rop[2].Rip = Api->BCryptGenerateSymmetricKey;
	Rop[2].Rcx = hAlg;
	Rop[2].Rdx = &hKey;
	Rop[2].R8 = NULL;
	Rop[2].R9 = 0;
	*(DWORD64*)(StackBuffer[2] + 0x20) = (DWORD64)Key;
	*(DWORD64*)(StackBuffer[2] + 0x28) = (DWORD64)AES_KEY_SIZE;
	*(DWORD64*)(StackBuffer[2] + 0x30) = (DWORD64)0;

	authInfo.cbNonce = GCM_NONCE_SIZE;
	authInfo.pbNonce = (PBYTE)Nonce;
	authInfo.pbTag = Tag;
	authInfo.cbTag = TagSize;

	Rop[3].Rip = Api->BCryptDecrypt;
	Rop[3].Rcx = hKey;
	Rop[3].Rdx = CipherText;
	Rop[3].R8 = CipherSize;
	Rop[3].R9 = &authInfo;
	*(DWORD64*)(StackBuffer[3] + 0x20) = (DWORD64)NULL;
	*(DWORD64*)(StackBuffer[3] + 0x28) = (DWORD64)0;
	*(DWORD64*)(StackBuffer[3] + 0x30) = (DWORD64)NULL;
	*(DWORD64*)(StackBuffer[3] + 0x38) = (DWORD64)0;
	*(DWORD64*)(StackBuffer[3] + 0x40) = (DWORD64)&PlainTextSize;
	*(DWORD64*)(StackBuffer[3] + 0x48) = (DWORD64)0;

	PlainText = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, CipherSize);

	Rop[4].Rip = Api->BCryptDecrypt;
	Rop[4].Rcx = hKey;
	Rop[4].Rdx = CipherText;
	Rop[4].R8 = CipherSize;
	Rop[4].R9 = &authInfo;
	*(DWORD64*)(StackBuffer[4] + 0x20) = (DWORD64)NULL;
	*(DWORD64*)(StackBuffer[4] + 0x28) = (DWORD64)0;
	*(DWORD64*)(StackBuffer[4] + 0x30) = (DWORD64)PlainText;
	*(DWORD64*)(StackBuffer[4] + 0x38) = (DWORD64)PlainTextSize;
	*(DWORD64*)(StackBuffer[4] + 0x40) = (DWORD64)&DecryptedBytes;
	*(DWORD64*)(StackBuffer[4] + 0x48) = (DWORD64)0;

	*pCipherSize = CipherSize;
	*pCipherText = CipherText;
	*pTag = Tag;
	*pPlainText = PlainText;
}
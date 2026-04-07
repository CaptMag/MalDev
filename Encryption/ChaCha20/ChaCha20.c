#include "common.h"
#include "ChaCha20.h"

BOOL ChaCha20
(
	IN PBYTE Nonce,
	IN PBYTE Buffer,
	IN DWORD BufferSize,
	OUT DWORD* EncryptedSize,
	IN PBYTE Key,
	OUT PBYTE* pTag,
	OUT PBYTE* pCipherText
)
{

	PBYTE Tag = 0;
	PBYTE CipherText = 0;
	DWORD EncryptedBytes = 0;
	DWORD pcbResult = 0;

	BCRYPT_ALG_HANDLE hAlg = 0;
	BCRYPT_KEY_HANDLE hKey = 0;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
	BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

	if (!NT_SUCCESS(BCryptGenRandom(NULL, Key, CHACHA20_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
	{
		WARN("Failed To Generate Random Numbers!");
		PRINT_ERROR("BCryptGenRandom");
	}

	if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, L"CHACHA20_POLY1305", NULL, 0)))
	{
		WARN("Failed To Open Algorithm For ChaCha20-Poly135!");
		PRINT_ERROR("BCryptOpenAlgorithmProvider");
		return FALSE;
	}

	if (!NT_SUCCESS(BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, Key, CHACHA20_SIZE, 0)))
	{
		WARN("Failed To Create Symmetric Key!");
		PRINT_ERROR("BCryptGenerateSymmetricKey");
		return FALSE;
	}

	Tag = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, CHACHA20_TAG_SIZE);
	if (Tag == NULL)
	{
		WARN("Failed To Allocate 16 bytes to ChaCha20 Tag!");
		PRINT_ERROR("HeapAlloc");
		return FALSE;
	}


	authInfo.cbNonce = CHACHA20_NONCE_SIZE;
	authInfo.pbNonce = Nonce;
	authInfo.pbTag = Tag;
	authInfo.cbTag = CHACHA20_TAG_SIZE;

	if (!NT_SUCCESS(BCryptEncrypt(hKey, Buffer, BufferSize, &authInfo, NULL, 0, NULL, 0, &pcbResult, NULL)))
	{
		WARN("Failed To Encrypt!");
		PRINT_ERROR("BCryptEncrypt");
		return FALSE;
	}

	CipherText = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pcbResult);
	if (CipherText == NULL)
	{
		WARN("Failed To Allocate Enough Bytes for CipherText!");
		PRINT_ERROR("HeapAlloc");
		return FALSE;
	}

	if (!NT_SUCCESS(BCryptEncrypt(hKey, Buffer, BufferSize, &authInfo, NULL, 0, CipherText, pcbResult, &EncryptedBytes, 0)))
	{
		WARN("Failed To Encrypt!");
		PRINT_ERROR("BCryptEncrypt");
		return FALSE;
	}

	*EncryptedSize = EncryptedBytes;
	*pTag = Tag;
	*pCipherText = CipherText;

	BCryptDestroyKey(hKey);
	BCryptCloseAlgorithmProvider(hAlg, 0);

	return TRUE;

}
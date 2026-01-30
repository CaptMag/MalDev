#include "box.h"
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

// https://stackoverflow.com/questions/30720414/how-to-chain-bcryptencrypt-and-bcryptdecrypt-calls-using-aes-in-gcm-mode

#define AES_KEY_SIZE 32
#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE 16

const BYTE AESKey[] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

const BYTE Nonce[] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B
};

PVOID AesEncrypt
(
	IN PBYTE Buffer,
	IN DWORD BufferSize,
	OUT DWORD* EncryptedSize,
	OUT PBYTE* pTag
)

{

	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	DWORD pcbResult;
	PBYTE CipherText;
	DWORD EncryptedBytes;
	PBYTE Tag;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
	BCRYPT_INIT_AUTH_MODE_INFO(authInfo);

	status = BCryptOpenAlgorithmProvider(
		&hAlg,
		BCRYPT_AES_ALGORITHM,
		NULL,
		0
	);

	if (status != STATUS_SUCCESS)
	{
		PRINT_ERROR("BCryptOpenAlgorithmProvider");
		return NULL;
	}

	status = BCryptSetProperty(
		hAlg,
		BCRYPT_CHAINING_MODE,
		(PBYTE)BCRYPT_CHAIN_MODE_GCM,
		sizeof(BCRYPT_CHAIN_MODE_GCM),
		0
	);

	if (status != STATUS_SUCCESS)
	{
		PRINT_ERROR("BCryptSetProperty");
		return NULL;
	}

	status = BCryptGenerateSymmetricKey(
		hAlg,
		&hKey,
		NULL, 0,
		AESKey, AES_KEY_SIZE,
		0
	);

	if (status != STATUS_SUCCESS)
	{
		PRINT_ERROR("BCryptGenerateSymmetricKey");
		return NULL;
	}

	Tag = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, GCM_TAG_SIZE);
	if (Tag == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		return NULL;
	}

	authInfo.cbNonce = GCM_NONCE_SIZE;
	authInfo.pbNonce = (PBYTE)Nonce;
	authInfo.pbTag = Tag;
	authInfo.cbTag = GCM_TAG_SIZE;

	status = BCryptEncrypt(
		hKey,
		Buffer, BufferSize,
		&authInfo,
		NULL, 0,
		NULL, 0,
		&pcbResult,
		NULL
	);

	if (status != STATUS_SUCCESS)
	{
		PRINT_ERROR("BCryptEncrypt");
		return NULL;
	}

	CipherText = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pcbResult);
	if (CipherText == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		return NULL;
	}

	status = BCryptEncrypt(
		hKey,
		Buffer, BufferSize,
		&authInfo,
		NULL, 0,
		CipherText, pcbResult,
		&EncryptedBytes,
		0
	);

	if (status != STATUS_SUCCESS)
	{
		PRINT_ERROR("BCryptEncrypt");
		return NULL;
	}

	*EncryptedSize = EncryptedBytes;
	*pTag = Tag;

	return CipherText;

}

PVOID AesDecrypt
(
	IN PBYTE CipherText,
	IN DWORD CipherSize,
	IN PBYTE Tag,
	IN DWORD TagSize,
	OUT PDWORD pPlainTextSize
)
{

	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlg;
	BCRYPT_KEY_HANDLE hKey;
	PBYTE PlainText;
	DWORD PlainTextSize;
	DWORD DecryptedBytes;
	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;

	status = BCryptOpenAlgorithmProvider(
		&hAlg,
		BCRYPT_AES_ALGORITHM,
		NULL,
		0
	);

	if (status != STATUS_SUCCESS)
	{
		PRINT_ERROR("BCryptOpenAlgorithmProvider");
		return NULL;
	}

	status = BCryptSetProperty(
		hAlg,
		BCRYPT_CHAINING_MODE,
		(PBYTE)BCRYPT_CHAIN_MODE_GCM,
		sizeof(BCRYPT_CHAIN_MODE_GCM),
		0
	);

	if (status != STATUS_SUCCESS)
	{
		PRINT_ERROR("BCryptSetProperty");
		return NULL;
	}

	status = BCryptGenerateSymmetricKey(
		hAlg,
		&hKey,
		NULL, 0,
		AESKey, AES_KEY_SIZE,
		0
	);

	if (status != STATUS_SUCCESS)
	{
		PRINT_ERROR("BCryptGenerateSymmetricKey");
		return NULL;
	}

	authInfo.cbNonce = GCM_NONCE_SIZE;
	authInfo.pbNonce = (PBYTE)Nonce;
	authInfo.pbTag = Tag;
	authInfo.cbTag = TagSize;

	status = BCryptDecrypt(
		hKey,
		CipherText, CipherSize,
		&authInfo,
		NULL, 0,
		NULL, 0,
		&PlainTextSize,
		0
	);

	if (status != STATUS_SUCCESS)
	{
		PRINT_ERROR("BCryptDecrypt");
		return NULL;
	}

	PlainText = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PlainTextSize);
	if (PlainText == NULL)
	{
		PRINT_ERROR("HeapAlloc");
		return NULL;
	}

	BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
	authInfo.cbNonce = GCM_NONCE_SIZE;
	authInfo.pbNonce = (PBYTE)Nonce;
	authInfo.pbTag = Tag;
	authInfo.cbTag = TagSize;

	status = BCryptDecrypt(
		hKey,
		CipherText, CipherSize,
		&authInfo,
		NULL, 0,
		PlainText,
		PlainTextSize,
		&DecryptedBytes,
		0
	);

	if (status != STATUS_SUCCESS)
	{
		PRINT_ERROR("BCryptDecrypt");
		return NULL;
	}

	*pPlainTextSize = DecryptedBytes;

	return PlainText;

}
#pragma once
#include <Windows.h>

typedef NTSTATUS(WINAPI* pBCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
typedef NTSTATUS(WINAPI* pBCryptSetProperty)(BCRYPT_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
typedef NTSTATUS(WINAPI* pBCryptGenerateSymmetricKey)(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
typedef NTSTATUS(WINAPI* pBCryptEncrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
typedef NTSTATUS(WINAPI* pBCryptDecrypt)(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
typedef LPVOID(WINAPI* pHeapAlloc)(HANDLE, DWORD, SIZE_T);

typedef struct {
    pBCryptOpenAlgorithmProvider    BCryptOpenAlgorithmProvider;    /**>> Open Encryption Algorithm*/
    pBCryptSetProperty              BCryptSetProperty;              /**>> Set Encryption Type*/
    pBCryptGenerateSymmetricKey     BCryptGenerateSymmetricKey;     /**>> Generating (AES) Encryption Symmetric Key*/
    pBCryptEncrypt                  BCryptEncrypt;                  /**>> Encryption*/
    pBCryptDecrypt                  BCryptDecrypt;                  /**>> Decryption*/
    pHeapAlloc                      HeapAlloc;                      /**>> Allocate Space onto The Heap*/
} AesApi, * pAesApi;

const BYTE Nonce[] =
{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B
};


/**
* @brief
*   Generate a randomized AES-256-GCM Encryption Key
* 
* @param AesKey
*   OUT param for 256-bit AES Key
* 
* @param AesKeyLen
*   Length Of Aes Key
*
* @return
*   return NULL on failure, nothing on success
*/
VOID AesGenKey
(
    OUT PBYTE* AesKey,
    OUT DWORD* AesKeyLen
);


/**
* @brief
*   AES-256-GCM Encryption using ROP chains
*/
PBYTE AesEncrypt
(
    IN PBYTE Buffer,
    IN DWORD BufferSize,
    OUT DWORD* EncryptedSize,
    IN PBYTE AesKey,
    OUT PBYTE* pTag,
    OUT PBYTE* pCipherText
);

PBYTE AesDecrypt
(
    IN PBYTE CipherText,
    IN DWORD CipherSize,
    IN PBYTE Tag,
    IN DWORD TagSize,
    IN PBYTE Key,
    OUT PDWORD pPlainTextSize,
    OUT PBYTE* pPlainText
);
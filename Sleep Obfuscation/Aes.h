#pragma once
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#define AES_KEY_SIZE 32
#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE 16

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

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
* 
* @param Buffer
*   Target Process Buffer
* 
* @param BufferSize
*   Target Buffer Size
* 
* @param EncryptedSize
*   AES Encrypted Buffer Size
* 
* @param AesKey
*   Randomized AES Key (Derived from AesGenKey)
* 
* @param pTag
*   Ensures Integrity of Cipher Text
* 
* @param pCipherText
*   Used To Hold Newly Encrypted Cipher Text
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

/**
* @brief
*   Used to Decrypt AES-256-GCM
* 
* @param pCipherText
*   Encrypted Text
* 
* @param pCipherSize
*   Encrypted Text Size
* 
* @param pTag
*   Used To Ensure Integrity of Decrypted Text
* 
* @param Key
*   Randomized AES Key (Derived From AesGenKey)
* 
* @param pPlainTextSize
*   Used To Hold The Size of Newly Decrypted Text
* 
* @param pPlainText
*   Newly Unencrypted Plain Text
*/
PBYTE AesDecrypt
(
    IN PBYTE* pCipherText,
    IN DWORD* pCipherSize,
    IN PBYTE* pTag,
    IN DWORD TagSize,
    IN PBYTE Key,
    OUT PDWORD pPlainTextSize,
    OUT PBYTE* pPlainText
);
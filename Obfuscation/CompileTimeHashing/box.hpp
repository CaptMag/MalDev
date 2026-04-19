#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

#define OKAY(MSG, ...) printf("[+] "		  MSG "\n", ##__VA_ARGS__)
#define INFO(MSG, ...) printf("[*] "          MSG "\n", ##__VA_ARGS__)
#define WARN(MSG, ...) fprintf(stderr, "[-] " MSG "\n", ##__VA_ARGS__)
#define CHAR(MSG, ...) printf("[>] Press <Enter> to "		MSG "\n", ##__VA_ARGS__)
#define PRINT_ERROR(MSG, ...) fprintf(stderr, "[!] " MSG "Failed! Error: 0x%lx""\n", GetLastError())

// Note, when using constexpr, you have to fully define the function inside the header file, not just declare it

// Manual Definition for MessageBoxA. Used for testing :)
typedef int (WINAPI* fnMessageBoxA)(
    HWND   hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT   uType
);

/**
* Generating a random key using the TIME macro
* 
* Takes the current time and multiples it by each digit,
* it then adds them together, making a randomized seed
*/ 
constexpr int RandomSeed(void)
{
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
};

constexpr auto HashKey = RandomSeed() % 0XFF;

/**
* 
* This macro has 2 things that it must do
* 
* First is the API call, this is just to replace it with the actual API
* Example: OpenProcess would replace all instances of 'API'
* 
* Secondly, this has a '##_Hashing', this just appends this to the end of the selected API
* Example: OpenProcess --> OpenProcess_Hashing
* 
*/
#define CompileTimeHash(API) constexpr auto API##_Hashing = sdbmrol16((IN const PCHAR) #API)

/**
* 
* This macro is used for the comparison in GetHashAddress
* 
* The reason for using this, is because we already have the string defined (our Function Hash)
* Therefore, we would need to compare this to its respective API Function
* 
*/
#define RuntimeHash(API) sdbmrol16((IN const PCHAR)API)

// constexpr strlen replacement
constexpr UINT ConstexprStrLen(const PCHAR str)
{
	UINT len = 0;
	while (str[len] != '\0') len++;
	return len;
}

// constexpr toupper replacement
constexpr char ConstexprToUpper(char c)
{
	return (c >= 'a' && c <= 'z') ? (c - 32) : c;
}

/**
* @brief
*   Hashing algorithm using a randomly generated key
*   consists of sdbm, rol16, & XOR
*
* @return DWORD
*   return the hash on success, nothing on failure
*/
constexpr DWORD sdbmrol16
(
	IN const PCHAR String
)
{

	UINT hash = HashKey;
	UINT StringLen = ConstexprStrLen(String);

	for (UINT i = 0; i < StringLen; i++)
	{
		hash = (hash << 16) | (hash >> (32 - 16)); // move left by 16
		hash = (ConstexprToUpper(String[i])) + (hash << 6) + (hash << 16) - hash; // sdbm
		hash = hash ^ i; // xor
	}

	return hash;

}

/**
* @brief
*   Wrapper for GetProcAddress, but reads via CompileTimeHash
*   Typically GetProcAddress follows the same order as this function (somewhat)
*   However, instead we will be matching the supplied function hash with its respective hash value
* 
* @param BaseAddress
*   This is just used in order to properly use (and fine) the DOS and NT Headers
* 
* @param ApiHash
*   The hash of its respective API
* 
* @return PVOID
*   Return the Api Address on Success, NULL on Failure
*/
PVOID GetHashAddress
(
    IN PVOID BaseAddress,
    IN DWORD ApiHash
);
#include "box.h"

DWORD sdbmrol16
(
	IN PCHAR String
)
{

	UINT hash = 0;
	UINT StringLen = strlen(String);

	for (UINT i = 0; i < StringLen; i++)
	{
		hash = (hash << 16) | (hash >> (32 - 16)); // move left by 16
		hash = (toupper(String[i])) + (hash << 6) + (hash << 16) - hash; // sdbm
		hash = hash ^ i; // xor
	}

	INFO("string: %s | hash: %u", String, hash);
	return hash;

}
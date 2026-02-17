#include "box.h"

DWORD djb2
(
	IN PCHAR String
)
{

	UINT hash = 5381;
	UINT StringLen = strlen(String);

	for (UINT i = 0; i < StringLen; i++)
	{
		hash = hash ^ i; // XOR
		hash = ((hash << 5) + hash) + (toupper(String[i]));
	}

	INFO("string: %s | hash: %u", String, hash);
	return hash;

}
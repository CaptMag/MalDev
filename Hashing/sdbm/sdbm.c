#include "box.h"

DWORD sdbm
(
	IN PCHAR String
)
{

	UINT hash = 0;
	UINT StringLen = strlen(String);

	for (UINT i = 0; i < StringLen; i++)
	{
		hash = toupper(String[i]) + (hash << 6) + (hash << 16) - hash;
		hash = hash ^ i;
	}

	INFO("string: %s | hash: %u", String, hash);
	return hash;

}
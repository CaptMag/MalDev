#include "Windows.h"

// https://www.w3resource.com/c-programming-exercises/c-snippets/implementing-custom-memcpy-function-in-c.php
// https://stackoverflow.com/questions/75400447/assignment-create-my-own-memcpy-why-cast-the-destination-and-source-pointers-t
// https://www.geeksforgeeks.org/dsa/write-your-own-strcmp-which-ignores-cases/
// https://stackoverflow.com/questions/19641291/how-to-create-my-own-strcpy-function

PVOID pMemcpy
(
	IN PVOID Destination,
	IN const PVOID Source,
	IN SIZE_T Size
)
{

	if (!Destination || !Source || Size <= 0)
		return NULL;

	UCHAR* cDestination = Destination;
	const UCHAR* cSource = Source;

	for (size_t i = 0; i < Size; i++)
	{
		cDestination[i] = cSource[i];
	}

	return Destination;

}

PVOID pStrcpy
(
	IN PCHAR Destination,
	IN PCHAR Source,
	IN SIZE_T Size
)
{

	if (!Destination || !Source || Size <= 0)
		return FALSE;

	for (size_t i = 0; i < Size; i++)
	{
		Destination[i] = Source[i];
	}

	return Destination;

}

INT pStrcmp
(
	IN const PCHAR String1,
	IN const PCHAR String2
)
{

	if (!String1 || !String2)
		return EXIT_FAILURE;

	int i = 0;
	while (String1[i] && String2[i])
	{
		if (String1[i] != String2[i])
		{
			return (String1[i] > String2[i]) ? 1 : -1;
		}
		i++;
	}

	if (String1[i] == String2[i])
		return 0;
	else
		return (String1[i] > String2[i]) ? 1 : -1;

}
#include "box.h"

// http://www.cse.yorku.ca/~oz/hash.html
// https://stackoverflow.com/questions/10696223/reason-for-the-number-5381-in-the-djb-hash-function

int main()
{

	PCHAR String = "VirtualAlloc";

	djb2(String);
	sdbm(String);
	sdbmrol16(String);

	return 0;

}
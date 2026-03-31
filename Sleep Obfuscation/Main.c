#include "Aes.h"
#include "box.h"

int main()
{

	LARGE_INTEGER SleepTime;
	SleepTime.QuadPart = -(4 * 1000 * 10000LL);

	SleepObfusc(&SleepTime);

	OKAY("Done!");
	return 0;

}
#include "Aes.h"
#include "box.h"

int main()
{

	LARGE_INTEGER SleepTime;
	SleepTime.QuadPart = (4 * 1000);

	SleepObfusc(&SleepTime);

	return 0;

}
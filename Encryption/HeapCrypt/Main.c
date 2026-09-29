#include "HeapCrypt.h"

// Reference: https://github.com/SaadAhla/HeapCrypt

int main()
{

	while (TRUE)
	{

		INFO("Suspending Threads...");
		SuspendThreads();

		My_Sleep(4000);

		ResumeThreads();
		INFO("Thread Resumed!");

	}

	OKAY("Done!");

	getchar();

	return 0;

}
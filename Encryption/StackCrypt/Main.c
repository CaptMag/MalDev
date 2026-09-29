#include "Encrypt.h"

// Reference: https://github.com/SaadAhla/StackCrypt

int main()
{

	while (TRUE)
	{

		INFO("Suspending Threads...");
		ThreadCryptSuspend();

		Sleep(4000);

		ThreadCryptResume();
		INFO("Thread Resumed!");

	}

	OKAY("Done!");

	getchar();

	return 0;

}
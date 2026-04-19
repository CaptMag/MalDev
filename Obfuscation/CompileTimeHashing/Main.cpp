#include "box.hpp"

CompileTimeHash(MessageBoxA);

int main()
{

	HMODULE User32 = LoadLibraryA("user32.dll");
	if (User32 == NULL)
	{
		PRINT_ERROR("LoadLibraryA");
		return 1;
	}

	fnMessageBoxA pMessageBoxA = (fnMessageBoxA)GetHashAddress(User32, MessageBoxA_Hashing);

	pMessageBoxA(NULL, "CompileTime Hashing w / constexpr", "Test", MB_OK);

	CHAR("Quit...");
	getchar();

	return 0;

}
CC = x86_64-w64-mingw32-gcc

INJECTOR_CFLAGS = -O2 -Wall -Wextra

DLL_CFLAGS = -Os -Wall -Wextra \
	-ffreestanding \
	-fno-stack-protector

DLL_LDFLAGS = -shared -nostdlib

all: ReflectiveDllInjector.exe ReflectiveLoader.dll

ReflectiveDllInjector.exe:
	$(CC) $(INJECTOR_CFLAGS) \
		ReflectiveDllInjector/Main.c \
		ReflectiveDllInjector/ReflectiveInjector.c \
		-o $@

ReflectiveLoader.dll:
	$(CC) \
		$(DLL_CFLAGS) \
		-shared \
		-nostdlib \
		-Wl,-e,DllMain \
		ReflectiveLoader/DllMain.c \
		ReflectiveLoader/Win32.c \
		ReflectiveLoader/ReflectiveLoader.c \
		-luser32 \
		-o $@
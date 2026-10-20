CC = x86_64-w64-mingw32-gcc

INJECTOR_CFLAGS = -O2 -Wall -Wextra

DLL_CFLAGS = -Os -Wall -Wextra \
	-ffreestanding \
	-fno-stack-protector

DLL_LDFLAGS = -shared -nostdlib

all: ReflectiveDllInjector.exe ReflectiveLoader.dll

ReflectiveDllInjector.exe:
	$(CC) $(INJECTOR_CFLAGS) \
		NativeInjector/Main.c \
		NativeInjector/NativeInjector.c \
		-o $@

ReflectiveLoader.dll:
	$(CC) \
		$(DLL_CFLAGS) \
		-shared \
		-nostdlib \
		-Wl,-e,DllMain \
		NativeReflectiveLoader/DllMain.c \
		NativeReflectiveLoader/Win32.c \
		NativeReflectiveLoader/NativeLoader.c \
		-luser32 \
		-o $@
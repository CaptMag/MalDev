CC = x86_64-w64-mingw32-gcc

EXE = DllInjector.exe
DLL = Dll/Dll.dll

EXE_SOURCES = Main.c DllInjector.c
DLL_SOURCES = Dll/DllMain.c

all: $(EXE) $(DLL)

$(EXE): $(EXE_SOURCES)
	$(CC) -o $@ $(EXE_SOURCES)

$(DLL): $(DLL_SOURCES)
	$(CC) -shared -o $@ $(DLL_SOURCES)
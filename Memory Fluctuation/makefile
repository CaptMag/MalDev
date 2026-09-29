CC = x86_64-w64-mingw32-gcc

ASM = "C:/Program Files/NASM/nasm.exe"
ASMFLAGS = -f bin

ASM_SRC = PopCalc/CalcShellcode.asm
ASM_OBJ = CalcShellcode.bin

TARGET = ShellcodeFluctuation.exe
SOURCES = ShellcodeFluctuation/Main.c ShellcodeFluctuation/ShellcodeFluctuation.c

all: $(TARGET)

$(ASM_OBJ): $(ASM_SRC)
	$(ASM) $(ASMFLAGS) $(ASM_SRC) -o $(ASM_OBJ)

$(TARGET): $(SOURCES) $(ASM_OBJ)
	$(CC) -o $(TARGET) $(SOURCES)
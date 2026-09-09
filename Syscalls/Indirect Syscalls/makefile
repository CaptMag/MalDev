ASM = "C:/Program Files/NASM/nasm.exe"
ASMFLAGS = -f win64

CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall

TARGET = IndirectSyscalls.exe
C_SOURCES = Main.c Syscalls.c Invocation.c
ASM_SRC = IndirectSyscalls.asm
ASM_OBJ = IndirectSyscalls.o

all: $(ASM_OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(C_SOURCES) $(ASM_OBJ)

$(ASM_OBJ): $(ASM_SRC)
	$(ASM) $(ASMFLAGS) $(ASM_SRC) -o $(ASM_OBJ)
ASM = "C:/Program Files/NASM/nasm.exe"
ASMFLAGS = -f win64

CC = x86_64-w64-mingw32-gcc
CFLAGS = -Wall

TARGET = DirectSyscalls.exe
C_SOURCES = Main.c Syscalls.c Invocation.c
ASM_SRC = DirectSyscalls.asm
ASM_OBJ = DirectSyscalls.o

all: $(ASM_OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(C_SOURCES) $(ASM_OBJ)

$(ASM_OBJ): $(ASM_SRC)
	$(ASM) $(ASMFLAGS) $(ASM_SRC) -o $(ASM_OBJ)
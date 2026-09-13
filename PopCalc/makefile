ASM = "C:/Program Files/NASM/nasm.exe"
ASMFLAGS = -f bin

ASM_SRC = CalcShellcode.asm
ASM_OBJ = CalcShellcode.bin

$(ASM_OBJ): $(ASM_SRC)
	$(ASM) $(ASMFLAGS) $(ASM_SRC) -o $(ASM_OBJ)
	
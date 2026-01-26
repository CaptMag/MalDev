# MagmaGate (inspired by Hell's Gate)

MagmaGate is my version of Hell's/Halo's Gate, following similar principles of both

MagmaGate does the following:

Walk the PEB (used to grab Ntdll Base Address)

Grab a function pointer to the Export Address Table (EAT)

Get Base Hash --> API Hashing function using the export directory as a seed

GrabSSN --> Used to grab both the SSN and Syscall Instruction Address of an Unhooked Function

SSNUnhook --> Same as GrabSSN but for Hooked Functions

relative_jmp --> used to detect any jmp instructions (hooks)

absolute_jmp --> used to detect any inline hooking

MagmaGate --> Ties everything together and grab all the necessary information

## Example of NtWriteVirtualMemory

<p align="center">
    <img height="400" alt="OffensiveRust" src="syscall.jpg">
</p>

## Credits

Obviously I did not create this myself, nor am I claiming to be.

That being said, credit where credit is due, these are all the sources I used to create MagmaGate

https://github.com/am0nsec/HellsGate/blob/master/HellsGate/main.c  
https://github.com/Maldev-Academy/HellHall/blob/main/Hell'sHall/Hell'sHall/HellsHall.c  
https://github.com/VirtualAlllocEx/DEFCON-31-Syscalls-Workshop/blob/main/05_Bonus_Chapter_2_POC/IDSC_PEB_EAT/IDSC_PEB_EAT/IDSC_PEB_EAT.c  
https://tuttlem.github.io/2024/10/26/simple-hashing-algorithms.html  
https://blog.sektor7.net/#!res/2021/halosgate.md  
https://stackoverflow.com/questions/1546141/jmp-to-absolute-address-op-codes#2049606  
https://www.cnblogs.com/VxerLee/p/15184023.html  
https://asm-docs.microagi.org/x86/syscall.html  
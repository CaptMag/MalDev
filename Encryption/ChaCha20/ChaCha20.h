#pragma once
#include <Windows.h>
#include <bcrypt.h>

#define CHACHA20_SIZE 32
#define CHACHA20_TAG_SIZE 16
#define CHACHA20_NONCE_SIZE 12

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
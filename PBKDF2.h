#pragma once

#include <stddef.h>

#define ITERATIONS 15000
#define SALT_LEN 64

char *PBKDF2_HMAC_SHA_512(char *In, size_t InLen);
char *PBKDF2_HMAC_SHA_512Ex(char *In, size_t InLen, char *Salt, size_t SaltLen, size_t Iterations);
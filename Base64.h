#pragma once

#include "Global.h"
#include <stddef.h>
#include <stdbool.h>

size_t MEM_OUT Base64Encode(const unsigned char* buffer, size_t Len, char** Out);
bool MEM_OUT Base64Decode(char* b64message, unsigned char** buffer, size_t* length);
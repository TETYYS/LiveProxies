#include "Base64.h"
#include "Global.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

size_t MEM_OUT Base64Encode(const unsigned char *In, size_t Len, OUT char **Out)
{
	BUF_MEM *bufferPtr;

	BIO *bio = BIO_push(BIO_new(BIO_f_base64()), BIO_new(BIO_s_mem()));

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, In, Len);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);

	size_t len = bufferPtr->length;

	*Out = malloc(len + 1);
	memcpy(*Out, bufferPtr->data, len);
	(*Out)[len] = 0x00;

	BIO_free_all(bio);

	return len;
}

static size_t CalcDecodeLength(const char* b64input)
{
	size_t len = strlen(b64input),
		padding = 0;

	if (b64input[len - 1] == '=' && b64input[len - 2] == '=')
		padding = 2;
	else if (b64input[len - 1] == '=')
		padding = 1;

	return (len * 3) / 4 - padding;
}

bool MEM_OUT Base64Decode(char* b64message, unsigned char** buffer, size_t* length)
{

	int decodeLen = CalcDecodeLength(b64message);
	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

	BIO *bio = BIO_push(BIO_new(BIO_f_base64()), BIO_new_mem_buf(b64message, -1));

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	*length = BIO_read(bio, *buffer, strlen(b64message));
	if (*length != decodeLen) {
		free(*buffer);
		return false;
	}
	BIO_free_all(bio);

	return true;
}
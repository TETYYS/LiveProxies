#include "Base64.h"
#include "Global.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>

size_t MEM_OUT Base64Encode(const unsigned char* buffer, size_t length, char** b64text) {
	// outputs with NUL
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64text = realloc(bufferPtr->data, bufferPtr->length + 1); // HACK HACK oops
	(*b64text)[bufferPtr->length] = 0x00;
	return bufferPtr->length;
}

static size_t CalcDecodeLength(const char* b64input) {
	size_t len = strlen(b64input),
		padding = 0;

	if (b64input[len - 1] == '=' && b64input[len - 2] == '=')
		padding = 2;
	else if (b64input[len - 1] == '=')
		padding = 1;

	return (len * 3) / 4 - padding;
}

bool MEM_OUT Base64Decode(char* b64message, unsigned char** buffer, size_t* length) {
	BIO *bio, *b64;

	int decodeLen = CalcDecodeLength(b64message);
	*buffer = (unsigned char*)malloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

	bio = BIO_new_mem_buf(b64message, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	*length = BIO_read(bio, *buffer, strlen(b64message));
	if (*length != decodeLen) {
		free(*buffer);
		return false;
	}
	BIO_free_all(bio);

	return true;
}
#include "PBKDF2.h"
#include "Base64.h"
#include "Global.h"
#include <stdint.h>
#include <math.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include "Logger.h"

MEM_OUT char *PBKDF2_HMAC_SHA_512(char *In, size_t InLen)
{
	uint8_t salt[SALT_LEN];

	RAND_bytes(salt, SALT_LEN);

	return PBKDF2_HMAC_SHA_512Ex(In, InLen, salt, SALT_LEN, ITERATIONS);
}

MEM_OUT char *PBKDF2_HMAC_SHA_512Ex(char *In, size_t InLen, char *Salt, size_t SaltLen, size_t Iterations)
{
	char *pbkdf2b64, *saltb64, *ret;
	size_t pbkdf2b64Len, saltb64Len;
	uint8_t pbkdf2[512 / 8];

	PKCS5_PBKDF2_HMAC(In, InLen, Salt, SaltLen, Iterations, EVP_sha512(), 512 / 8, pbkdf2);
	pbkdf2b64Len = Base64Encode(pbkdf2, 512 / 8, &pbkdf2b64); {
		saltb64Len = Base64Encode(Salt, SaltLen, &saltb64); {
			ret = malloc((INTEGER_VISIBLE_SIZE(ITERATIONS) + saltb64Len + pbkdf2b64Len + 2) * sizeof(char) /* $ */ + 1 /* NULL */);
			sprintf(ret, "%d$%s$%s", ITERATIONS, saltb64, pbkdf2b64);
		} free(saltb64);
	} free(pbkdf2b64);

	return ret;
}
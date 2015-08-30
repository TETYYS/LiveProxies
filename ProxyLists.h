#pragma once

#include "IPv6Map.h"
#include "Global.h"
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>
#include <openssl/ossl_typ.h>

uint8_t hashSalt[64];

typedef enum _PROXY_TYPE {
	PROXY_TYPE_HTTP = 1,
	PROXY_TYPE_HTTPS = 2,
	PROXY_TYPE_SOCKS4 = 4,
	PROXY_TYPE_SOCKS4A = 8,
	PROXY_TYPE_SOCKS5 = 16,
	PROXY_TYPE_SOCKS4_TO_SSL = 32,
	PROXY_TYPE_SOCKS4A_TO_SSL = 64,
	PROXY_TYPE_SOCKS5_TO_SSL = 128,
	PROXY_TYPE_SOCKS5_WITH_UDP = 256
} PROXY_TYPE;

#define PROXY_TYPE_COUNT 9
#define PROXY_TYPE_SOCKS_GENERIC (PROXY_TYPE_SOCKS4 | PROXY_TYPE_SOCKS4A | PROXY_TYPE_SOCKS5)
#define PROXY_TYPE_SOCKS_GENERIC_SSL (PROXY_TYPE_SOCKS4_TO_SSL | PROXY_TYPE_SOCKS4A_TO_SSL | PROXY_TYPE_SOCKS5_TO_SSL)
#define PROXY_TYPE_ALL (PROXY_TYPE_HTTP | PROXY_TYPE_HTTPS | PROXY_TYPE_SOCKS_GENERIC | PROXY_TYPE_SOCKS_GENERIC_SSL | PROXY_TYPE_SOCKS5_WITH_UDP)

typedef enum _ANONYMITY {
	ANONYMITY_NONE = 0,
	ANONYMITY_TRANSPARENT = 1,
	ANONYMITY_ANONYMOUS = 2,
	ANONYMITY_MAX = 3
} ANONYMITY;

typedef struct _PROXY {
	IPv6Map *ip;
	uint16_t port;
	PROXY_TYPE type; // PROXY_TYPE
	ANONYMITY anonymity; // ANONYMITY
	const char *country;
	bool rechecking;
	uint64_t httpTimeoutMs;
	uint64_t timeoutMs;
	uint64_t liveSinceMs;
	uint64_t lastCheckedMs;
	uint8_t retries;
	uint32_t successfulChecks;
	uint32_t failedChecks;
	X509 *invalidCert;
} PROXY;

typedef void(*SingleCheckCallback)(void *UProxy);

typedef struct _UNCHECKED_PROXY {
	IPv6Map *ip;
	uint16_t port;
	PROXY_TYPE type;
	bool checking;
	uint8_t retries;
	bool checkSuccess;
	struct bufferevent *assocBufferEvent;

	/* PROXY_TYPE_HTTP
	 *	7 - Send HTTP request
	 * PROXY_TYPE_HTTPS
	 *	0 - Send CONNECT request
	 *	1 - Receive CONNECT response
	 *	6 - SSL hanshake
	 *	7 - Send HTTP request
	 * PROXY_TYPE_SOCKS4/A
	 *	0 - Send SOCKS4/A packet
	 *	1 - Receive answer
	 *	7 - Send HTTP request
	 * PROXY_TYPE_SOCKS5
	 *	0 - Send SOCKS5 auth packet
	 *	1 - Receive auth response
	 *	2 - Send SOCKS5 main packet
	 *	3 - Receive response
	 *	7 - Send HTTP request
	 * PROXY_TYPE_SOCKS4/A_TO_SSL
	 *	0 - Send SOCKS4/A packet
	 *	1 - Receive answer
	 *	6 - SSL hanshake
	 *	7 - Send HTTP request
	 * PROXY_TYPE_SOCKS5_TO_SSL
	 *	0 - Send SOCKS5 auth packet
	 *	1 - Receive auth response
	 *	2 - Send SOCKS5 main packet
	 *	3 - Receive response
	 *	6 - SSL hanshake
	 *	7 - Send HTTP request
	 * PROXY_TYPE_SOCKS5_WITH_UDP
	 *	0 - Send SOCKS5 auth packet
	 *	1 - Receive auth response
	 *	2 - Send SOCKS5 main packet
	 *	3 - Receive response
	 *	4 - Send UDP packet
	 */
	/*
	 * Universal stages - 6, 7, (8 - final)
	 */
	uint8_t stage;

	// This one blocks EVWrite called timeout event in case WServer is processing UProxy while EVWrite timeout event tries to free it
	pthread_mutex_t processing;

	struct event *timeout;

	uint8_t hash[512 / 8]; // SHA-512
	uint64_t requestTimeMs;
	uint64_t requestTimeHttpMs;
	PROXY *associatedProxy;

	X509 *invalidCert;

	SingleCheckCallback singleCheckCallback;
	void *singleCheckCallbackExtraData;
} UNCHECKED_PROXY;

UNCHECKED_PROXY	**UncheckedProxies;
uint64_t		SizeUncheckedProxies;
pthread_mutex_t	LockUncheckedProxies;

PROXY	 		**CheckedProxies;
uint64_t		SizeCheckedProxies;
pthread_mutex_t	LockCheckedProxies;

bool ProxyIsSSL(PROXY_TYPE In);
char *ProxyGetTypeString(PROXY_TYPE In);
bool ProxyAdd(PROXY *Proxy);
uint8_t UProxyAdd(UNCHECKED_PROXY *UProxy);
bool UProxyRemove(UNCHECKED_PROXY *UProxy);
bool ProxyRemove(PROXY *Proxy);
void GenerateHashForUProxy(UNCHECKED_PROXY *In);
void UProxyFree(UNCHECKED_PROXY *In);
void ProxyFree(PROXY *In);
UNCHECKED_PROXY *UProxyFromProxy(PROXY *In);
UNCHECKED_PROXY *AllocUProxy(IPv6Map *Ip, uint16_t Port, PROXY_TYPE Type, struct event *Timeout, PROXY *AssociatedProxy);
char *GenerateUidForProxy(PROXY *In);
PROXY *GetProxyFromUid(char *Uid);
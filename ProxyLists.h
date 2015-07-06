#pragma once

#include "IPv6Map.h"
#include "Global.h"
#include <stdint.h>
#include <semaphore.h>
#include <stdbool.h>

uint8_t hashSalt[64];

typedef enum _PROXY_TYPE {
	PROXY_TYPE_HTTP = 1,
	PROXY_TYPE_SOCKS4 = 2,
	PROXY_TYPE_SOCKS4A = 4,
	PROXY_TYPE_SOCKS5 = 8
} PROXY_TYPE;

#define PROXY_TYPE_COUNT 4
#define PROXY_TYPE_SOCKS_GENERIC (PROXY_TYPE_SOCKS4 | PROXY_TYPE_SOCKS4A | PROXY_TYPE_SOCKS5)
#define PROXY_TYPE_ALL (PROXY_TYPE_HTTP | PROXY_TYPE_SOCKS_GENERIC)

typedef enum _ANONIMITY {
	ANONYMITY_NONE,
	ANONYMITY_TRANSPARENT,
	ANONYMITY_ANONYMOUS,
	ANONYMITY_MAX
} ANONIMITY;

typedef struct _PROXY {
	IPv6Map *ip;
	uint16_t port;
	char type; // PROXY_TYPE
	ANONIMITY anonymity; // ANONYMITY
	const char *country;
	uint64_t httpTimeoutMs;
	uint64_t timeoutMs;
	uint64_t liveSinceMs;
	uint64_t lastChecked;
	bool rechecking;
	uint8_t retries;
	uint32_t successfulChecks;
	uint32_t failedChecks;
} PROXY;

typedef struct _UNCHECKED_PROXY {
	IPv6Map *ip;
	uint16_t port;
	PROXY_TYPE type; // PROXY_TYPE
	bool checking;
	uint8_t retries;
	bool checkSuccess;

	// This one blocks EVWrite called timeout event in case WServer is processing UProxy while EVWrite timeout event tries to free it
	sem_t processing;

	struct event *timeout;

	uint8_t hash[512 / 8]; // SHA-512
	uint64_t requestTimeMs;
	uint64_t requestTimeHttpMs;
	PROXY *associatedProxy;
} UNCHECKED_PROXY;

UNCHECKED_PROXY	**uncheckedProxies;
uint32_t		sizeUncheckedProxies;
sem_t			lockUncheckedProxies;

PROXY	 		**checkedProxies;
uint32_t		sizeCheckedProxies;
sem_t			lockCheckedProxies;

bool ProxyAdd(PROXY *Proxy);
bool UProxyAdd(UNCHECKED_PROXY *UProxy);
bool UProxyRemove(UNCHECKED_PROXY *UProxy);
bool ProxyRemove(PROXY *Proxy);
void GenerateHashForUProxy(UNCHECKED_PROXY *In);
void UProxyFree(UNCHECKED_PROXY *In);
void ProxyFree(PROXY *In);
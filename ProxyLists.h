#pragma once

#include "IPv6Map.h"
#include "Global.h"
#include <stdint.h>
#include "CPH_Threads.h"
#include <stdbool.h>
#include <openssl/ossl_typ.h>
#include "DNS.h"

#define PROXY_IDENTIFIER_LEN 32

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
	
	int certErr;
	X509 *invalidCert;
	uint8_t identifier[PROXY_IDENTIFIER_LEN];
} PROXY;

typedef void(*SingleCheckCallback)(void *UProxy);

typedef enum _UPROXY_CUSTOM_PAGE_STAGE {
	UPROXY_CUSTOM_PAGE_STAGE_INITIAL_PACKET = 0,
	UPROXY_CUSTOM_PAGE_STAGE_DDL_PAGE = 1,
	UPROXY_CUSTOM_PAGE_STAGE_END = 2
} UPROXY_CUSTOM_PAGE_STAGE;

typedef void(*SingleCheckCallbackCPage)(void *UProxy, UPROXY_CUSTOM_PAGE_STAGE Stage);

typedef enum _UPROXY_STAGE {
	UPROXY_STAGE_INITIAL_PACKET = 0,
	UPROXY_STAGE_INITIAL_RESPONSE = 1,
	UPROXY_STAGE_SOCKS5_MAIN_PACKET = 2,
	UPROXY_STAGE_SOCKS5_DNS_RESOLVE = 2, // This is not a typo
	UPROXY_STAGE_SOCKS5_RESPONSE = 3,
	UPROXY_STAGE_UDP_PACKET = 4,
	UPROXY_STAGE_SSL_HANDSHAKE = 5,
	UPROXY_STAGE_HTTP_REQUEST = 6,
	UPROXY_STAGE_HTTP_RESPONSE = 7,
	UPROXY_STAGE_HTTP_DDL_PAGE = 8
} UPROXY_STAGE;

typedef struct _UNCHECKED_PROXY {
	IPv6Map *ip;
	uint16_t port;

	uint16_t targetPort;
	IPv6Map *targetIPv4;
	IPv6Map *targetIPv6;

	PROXY_TYPE type;
	bool checking;
	uint8_t retries;
	bool checkSuccess;
	struct bufferevent *assocBufferEvent;

	/* PROXY_TYPE_HTTP
	 *	6 - Send HTTP request
	 *	7, 8 - Download legit page
	 * PROXY_TYPE_HTTPS
	 *	0 - Send CONNECT request
	 *	1 - Receive CONNECT response
	 *	5 - SSL hanshake
	 *	6 - Send HTTP request
	 *	7, 8 - Download legit page
	 * PROXY_TYPE_SOCKS4/A
	 *	0 - Send SOCKS4/A packet
	 *	1 - Receive answer
	 *	6 - Send HTTP request
	 *	7, 8 - Download legit page
	 * PROXY_TYPE_SOCKS5
	 *	0 - Send SOCKS5 auth packet
	 *	1 - Receive auth response
	 *	2 - Send SOCKS5 main packet
	 *	3 - Receive response
	 *	6 - Send HTTP request
	 *	7, 8 - Download legit page
	 * PROXY_TYPE_SOCKS4/A_TO_SSL
	 *	0 - Send SOCKS4/A packet
	 *	1 - Receive answer
	 *	5 - SSL hanshake
	 *	6 - Send HTTP request
	 *	7, 8 - Download legit page
	 * PROXY_TYPE_SOCKS5_TO_SSL
	 *	0 - Send SOCKS5 auth packet
	 *	1 - Receive auth response
	 *	2 - Send SOCKS5 main packet
	 *	3 - Receive response
	 *	5 - SSL hanshake
	 *	6 - Send HTTP request
	 *	7, 8 - Download legit page
	 * PROXY_TYPE_SOCKS5_WITH_UDP
	 *	0 - Send SOCKS5 auth packet
	 *	1 - Receive auth response
	 *	2 - Send SOCKS5 main packet
	 *	3 - Receive response
	 *	4 - Send UDP packet
	 *	7, 8 - Receive UDP packet
	 */
	// Universal stages - 5, 6, 7, 8
	UPROXY_STAGE stage;

	// This one blocks EVWrite called timeout event in case the Server is processing UProxy while EVWrite timeout event tries to free it
	pthread_mutex_t processing;

	struct event *timeout;
	struct event *udpRead;

	uint8_t identifier[PROXY_IDENTIFIER_LEN];
	uint64_t requestTimeMs;
	uint64_t requestTimeHttpMs;
	PROXY *associatedProxy;

	X509 *invalidCert;

	char *pageTarget;
	char *pageTargetPostData;
	bool getResponse;
	SingleCheckCallback singleCheckCallback;
	void *singleCheckCallbackExtraData;
	
	IP_TYPE dnsResolveInProgress;
	DNS_LOOKUP_ASYNC_EX **dnsLookups;
	size_t dnsLookupsCount;
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
PROXY *GetProxyByIdentifier(uint8_t *In);
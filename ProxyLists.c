#include "ProxyLists.h"
#include "Global.h"
#include "Logger.h"
#include "IPv6Map.h"
#include "ProxyRequest.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <event2/event.h>
#include <assert.h>
#include "Base64.h"
#include "Websocket.h"
#include "Config.h"
#include <openssl/rand.h>

static bool MultiFlag(uint64_t Flag)
{
	return (Flag & (Flag - 1)) != 0 && Flag != 1;
}

bool ProxyIsSSL(PROXY_TYPE In)
{
	return In == PROXY_TYPE_HTTPS || In == PROXY_TYPE_SOCKS4_TO_SSL || In == PROXY_TYPE_SOCKS4A_TO_SSL || In == PROXY_TYPE_SOCKS5_TO_SSL;
}

static char *ProxyTypes[] = { "HTTP", "HTTPS", "SOCKS4", "SOCKS4A", "SOCKS5", "SOCKS4 -> SSL", "SOCKS4A -> SSL", "SOCKS5 -> SSL", "SOCKS5 UDP", "N/A" };

char *ProxyGetTypeString(PROXY_TYPE In)
{
	switch (In) {
		case PROXY_TYPE_HTTP: return ProxyTypes[0];	break;
		case PROXY_TYPE_HTTPS: return ProxyTypes[1]; break;
		case PROXY_TYPE_SOCKS4: return ProxyTypes[2]; break;
		case PROXY_TYPE_SOCKS4A: return ProxyTypes[3]; break;
		case PROXY_TYPE_SOCKS5: return ProxyTypes[4]; break;
		case PROXY_TYPE_SOCKS4_TO_SSL: return ProxyTypes[5]; break;
		case PROXY_TYPE_SOCKS4A_TO_SSL: return ProxyTypes[6]; break;
		case PROXY_TYPE_SOCKS5_TO_SSL: return ProxyTypes[7]; break;
		case PROXY_TYPE_SOCKS5_WITH_UDP: return ProxyTypes[8]; break;
		default: return ProxyTypes[9];
	}
}

bool ProxyAdd(PROXY *Proxy)
{
	pthread_mutex_lock(&LockCheckedProxies); {
		for (uint64_t x = 0; x < SizeCheckedProxies; x++) {
			if (Proxy->type == CheckedProxies[x]->type &&
				Proxy->port == CheckedProxies[x]->port &&
				IPv6MapEqual(Proxy->ip, CheckedProxies[x]->ip)) {
				CheckedProxies[x]->anonymity = Proxy->anonymity;
				CheckedProxies[x]->failedChecks = Proxy->failedChecks;
				CheckedProxies[x]->httpTimeoutMs = Proxy->httpTimeoutMs;
				CheckedProxies[x]->lastCheckedMs = Proxy->lastCheckedMs;
				CheckedProxies[x]->retries = Proxy->retries;
				CheckedProxies[x]->successfulChecks = Proxy->successfulChecks;
				CheckedProxies[x]->timeoutMs = Proxy->timeoutMs;
				free(Proxy);
				pthread_mutex_unlock(&LockCheckedProxies);
				return false;
			}
		}
		SizeCheckedProxies++;
		CheckedProxies = realloc(CheckedProxies, sizeof(CheckedProxies) * SizeCheckedProxies);
		CheckedProxies[SizeCheckedProxies - 1] = Proxy;
	} pthread_mutex_unlock(&LockCheckedProxies);

	uint64_t network = htobe64(SizeCheckedProxies);
	WebsocketClientsNotify(&network, sizeof(network), WEBSOCKET_SERVER_COMMAND_SIZE_PROXIES);

	uint8_t ipType = GetIPType(Proxy->ip) == IPV4 ? 0x04 : 0x06;
	char *identifierb64;
	Base64Encode(Proxy->identifier, PROXY_IDENTIFIER_LEN, &identifierb64); {
		size_t offset = 0;
		uint8_t buffer[sizeof(uint8_t) /* ipType */ +
			(ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE) /* IP */ +
			sizeof(uint16_t) + /* port */
			sizeof(uint16_t) + /* type */
			(2 * sizeof(char)) + /* country */
			sizeof(uint8_t) + /* anonymity */
			(sizeof(uint64_t) * 4) + /* Connection, HTTP/S timeouts, live since and last checked */
			sizeof(uint8_t) + /* retries */
			(sizeof(uint32_t) * 2) + /* successful and failed checks */
			strlen(identifierb64) /* uid */];

#define MAP_TYPE(x, type) *((type*)(&(x)))

		buffer[offset] = ipType; offset += sizeof(uint8_t);
		memcpy(buffer + offset, ipType == 0x04 ? &(Proxy->ip->Data[3]) : Proxy->ip->Data, (ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE)); offset += (ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE);
		MAP_TYPE(buffer[offset], uint16_t) = htons(Proxy->port); offset += sizeof(uint16_t);
		MAP_TYPE(buffer[offset], uint16_t) = htons((uint16_t)Proxy->type); offset += sizeof(uint16_t);
		memcpy(buffer + offset, Proxy->country, 2 * sizeof(char)); offset += 2 * sizeof(char);
		buffer[offset] = (uint8_t)Proxy->anonymity; offset += sizeof(uint8_t);
		MAP_TYPE(buffer[offset], uint64_t) = htobe64(Proxy->timeoutMs); offset += sizeof(uint64_t);
		MAP_TYPE(buffer[offset], uint64_t) = htobe64(Proxy->httpTimeoutMs); offset += sizeof(uint64_t);
		MAP_TYPE(buffer[offset], uint64_t) = htobe64(Proxy->liveSinceMs); offset += sizeof(uint64_t);
		MAP_TYPE(buffer[offset], uint64_t) = htobe64(Proxy->lastCheckedMs); offset += sizeof(uint64_t);
		buffer[offset] = Proxy->retries; offset += sizeof(uint8_t);
		MAP_TYPE(buffer[offset], uint32_t) = htonl(Proxy->successfulChecks); offset += sizeof(uint32_t);
		MAP_TYPE(buffer[offset], uint32_t) = htonl(Proxy->failedChecks); offset += sizeof(uint32_t);
		memcpy(buffer + offset, identifierb64, strlen(identifierb64));

		WebsocketClientsNotify(buffer, sizeof(buffer), WEBSOCKET_SERVER_COMMAND_PROXY_ADD);
	} free(identifierb64);

	return true;
}

uint8_t UProxyAdd(UNCHECKED_PROXY *UProxy)
{
	uint8_t ret = 0;
	pthread_mutex_lock(&LockUncheckedProxies); {
		for (uint64_t x = 0; x < SizeUncheckedProxies; x++) {
			if (MemEqual(UProxy->identifier, UncheckedProxies[x]->identifier, PROXY_IDENTIFIER_LEN)) {
				char *ip = IPv6MapToString2(UProxy->ip); {
					Log(LOG_LEVEL_WARNING, "Warning: tried to add already added unchecked proxy (%s:%d) (type %d)", ip, UProxy->port, UProxy->type);
				} free(ip);
				pthread_mutex_unlock(&LockUncheckedProxies);
				return ret;
			}
		}
	} pthread_mutex_unlock(&LockUncheckedProxies);
	Log(LOG_LEVEL_DEBUG, "UProxyAdd: size %d", SizeUncheckedProxies);

	if (MultiFlag(UProxy->type)) {
		for (size_t x = 0; x < PROXY_TYPE_COUNT; x++) {
			if ((UProxy->type & (PROXY_TYPE)pow(2, x)) == (PROXY_TYPE)pow(2, x)) {
				IPv6Map *ip = malloc(sizeof(IPv6Map));
				memcpy(ip, UProxy->ip->Data, sizeof(IPv6Map));
				ret += UProxyAdd(AllocUProxy(ip, UProxy->port, (PROXY_TYPE)pow(2, x), NULL, NULL));
			}
		}
	} else {
		pthread_mutex_lock(&LockUncheckedProxies); {
			SizeUncheckedProxies++;
			UncheckedProxies = realloc(UncheckedProxies, sizeof(UncheckedProxies) * SizeUncheckedProxies);
			UncheckedProxies[SizeUncheckedProxies - 1] = UProxy;
		} pthread_mutex_unlock(&LockUncheckedProxies);

		uint64_t network = htobe64(SizeUncheckedProxies);
		WebsocketClientsNotify(&network, sizeof(network), WEBSOCKET_SERVER_COMMAND_SIZE_UPROXIES);

		uint8_t ipType = GetIPType(UProxy->ip) == IPV4 ? 0x04 : 0x06;
		size_t offset = 0;
		uint8_t buffer[sizeof(uint8_t) /* ipType */ +
			(ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE) /* IP */ +
			sizeof(uint16_t) + /* port */
			sizeof(uint16_t) + /* type */
			sizeof(bool) + /* currently checking */
			sizeof(uint8_t) + /* retries */
			sizeof(bool) /* rechecking */];

#define MAP_TYPE(x, type) *((type*)(&(x)))

		buffer[offset] = ipType; offset += sizeof(uint8_t);
		memcpy(buffer + offset, ipType == 0x04 ? &(UProxy->ip->Data[3]) : UProxy->ip->Data, (ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE)); offset += (ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE);
		MAP_TYPE(buffer[offset], uint16_t) = htons(UProxy->port); offset += sizeof(uint16_t);
		MAP_TYPE(buffer[offset], uint16_t) = htons((uint16_t)UProxy->type); offset += sizeof(uint16_t);
		buffer[offset] = UProxy->checking; offset += sizeof(bool);
		buffer[offset] = UProxy->retries; offset += sizeof(uint8_t);
		buffer[offset] = UProxy->associatedProxy != NULL;

		WebsocketClientsNotify(buffer, sizeof(buffer), WEBSOCKET_SERVER_COMMAND_UPROXY_ADD);

		ret++;
	}
	return ret;
}

bool UProxyRemove(UNCHECKED_PROXY *UProxy)
{
	bool found = false;

	uint8_t ipType = GetIPType(UProxy->ip) == IPV4 ? 0x04 : 0x06;
	size_t offset = 0;
	uint8_t buffer[sizeof(uint8_t) /* ipType */ +
		(ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE) /* IP */ +
		sizeof(uint16_t) + /* port */
		sizeof(uint16_t) /* type */];

#define MAP_TYPE(x, type) *((type*)(&(x)))

	buffer[offset] = ipType; offset += sizeof(uint8_t);
	memcpy(buffer + offset, ipType == 0x04 ? &(UProxy->ip->Data[3]) : UProxy->ip->Data, (ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE)); offset += (ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE);
	MAP_TYPE(buffer[offset], uint16_t) = htons(UProxy->port); offset += sizeof(uint16_t);
	MAP_TYPE(buffer[offset], uint16_t) = htons((uint16_t)UProxy->type); offset += sizeof(uint16_t);

	WebsocketClientsNotify(buffer, sizeof(buffer), WEBSOCKET_SERVER_COMMAND_UPROXY_REMOVE);

	pthread_mutex_lock(&LockUncheckedProxies); {
		for (uint64_t x = 0; x < SizeUncheckedProxies; x++) {
			if (UProxy == UncheckedProxies[x]) {
				uint8_t ipType = GetIPType(UProxy->ip) == IPV4 ? 0x04 : 0x06;
				size_t offset = 0;
				uint8_t buffer[sizeof(uint8_t) /* ipType */ +
					(ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE) /* IP */ +
					sizeof(uint16_t) + /* port */
					sizeof(uint16_t) /* type */];
				buffer[offset] = ipType; offset += sizeof(uint8_t);
				memcpy(buffer + offset, UProxy->ip->Data, (ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE)); offset += (ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE);
				buffer[offset] = htons(UProxy->port); offset += sizeof(uint16_t);
				buffer[offset] = htons((uint16_t)UProxy->type); offset += sizeof(uint16_t);

				WebsocketClientsNotify(buffer, sizeof(buffer), WEBSOCKET_SERVER_COMMAND_UPROXY_REMOVE);

				UProxyFree(UncheckedProxies[x]);
				SizeUncheckedProxies--;
				if (SizeUncheckedProxies > 0)
					UncheckedProxies[x] = UncheckedProxies[SizeUncheckedProxies];
				UncheckedProxies = realloc(UncheckedProxies, SizeUncheckedProxies * sizeof(UncheckedProxies));
				found = true;
				break;
			}
		}
		uint64_t network = htobe64(SizeUncheckedProxies);
		WebsocketClientsNotify(&network, sizeof(network), WEBSOCKET_SERVER_COMMAND_SIZE_UPROXIES);

		Log(LOG_LEVEL_DEBUG, "UProxyRemove: size %d", SizeUncheckedProxies);
	} pthread_mutex_unlock(&LockUncheckedProxies);
	return found;
}

bool ProxyRemove(PROXY *Proxy)
{
	bool found = false;

	uint8_t ipType = GetIPType(Proxy->ip) == IPV4 ? 0x04 : 0x06;
	size_t offset = 0;
	uint8_t buffer[sizeof(uint8_t) /* ipType */ +
		(ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE) /* IP */ +
		sizeof(uint16_t) + /* port */
		sizeof(uint16_t) /* type */];

#define MAP_TYPE(x, type) *((type*)(&(x)))

	buffer[offset] = ipType; offset += sizeof(uint8_t);
	memcpy(buffer + offset, ipType == 0x04 ? &(Proxy->ip->Data[3]) : Proxy->ip->Data, (ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE)); offset += (ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE);
	MAP_TYPE(buffer[offset], uint16_t) = htons(Proxy->port); offset += sizeof(uint16_t);
	MAP_TYPE(buffer[offset], uint16_t) = htons((uint16_t)Proxy->type); offset += sizeof(uint16_t);

	WebsocketClientsNotify(buffer, sizeof(buffer), WEBSOCKET_SERVER_COMMAND_PROXY_REMOVE);

	pthread_mutex_lock(&LockCheckedProxies); {
		for (uint64_t x = 0; x < SizeCheckedProxies; x++) {
			if (Proxy == CheckedProxies[x]) {
				uint8_t ipType = GetIPType(Proxy->ip) == IPV4 ? 0x04 : 0x06;
				size_t offset = 0;
				uint8_t buffer[sizeof(uint8_t) /* ipType */ +
					(ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE) /* IP */ +
					sizeof(uint16_t) + /* port */
					sizeof(uint16_t) /* type */];
				buffer[offset] = ipType; offset += sizeof(uint8_t);
				memcpy(buffer + offset, Proxy->ip->Data, (ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE)); offset += (ipType == 0x04 ? IPV4_SIZE : IPV6_SIZE);
				buffer[offset] = htons(Proxy->port); offset += sizeof(uint16_t);
				buffer[offset] = htons((uint16_t)Proxy->type); offset += sizeof(uint16_t);

				WebsocketClientsNotify(buffer, sizeof(buffer), WEBSOCKET_SERVER_COMMAND_PROXY_REMOVE);

				ProxyFree(CheckedProxies[x]);
				SizeCheckedProxies--;
				if (SizeCheckedProxies > 0)
					CheckedProxies[x] = CheckedProxies[SizeCheckedProxies];
				CheckedProxies = realloc(CheckedProxies, SizeCheckedProxies * sizeof(CheckedProxies));
				found = true;
				break;
			}
		}

		uint64_t network = htobe64(SizeCheckedProxies);
		WebsocketClientsNotify(&network, sizeof(network), WEBSOCKET_SERVER_COMMAND_SIZE_PROXIES);
	} pthread_mutex_unlock(&LockCheckedProxies);

	return found;
}

UNCHECKED_PROXY *AllocUProxy(IPv6Map *Ip, uint16_t Port, PROXY_TYPE Type, struct event *Timeout, PROXY *AssociatedProxy)
{
	UNCHECKED_PROXY *UProxy = malloc(sizeof(UNCHECKED_PROXY));
	UProxy->ip = Ip;
	UProxy->port = Port;
	UProxy->type = Type;
	UProxy->checking = false;
	UProxy->retries = UProxy->requestTimeMs = UProxy->requestTimeHttpMs = UProxy->stage = 0;
	UProxy->checkSuccess = false;
	pthread_mutex_init(&(UProxy->processing), NULL);
	UProxy->timeout = Timeout;
	RAND_pseudo_bytes((unsigned char*)(&UProxy->identifier), PROXY_IDENTIFIER_LEN);
	UProxy->associatedProxy = AssociatedProxy;
	UProxy->singleCheckCallback = NULL;
	UProxy->invalidCert = NULL;
	UProxy->pageTarget = NULL;
	UProxy->targetPort = 0;
	UProxy->targetIPv4 = NULL;
	UProxy->targetIPv6 = NULL;
	UProxy->udpRead = NULL;
	return UProxy;
}

UNCHECKED_PROXY *UProxyFromProxy(PROXY *In)
{
	Log(LOG_LEVEL_DEBUG, "UProxyFromProxy: In: %p", In);
	IPv6Map *ip = malloc(sizeof(IPv6Map));
	memcpy(ip, In->ip->Data, IPV6_SIZE);

	return AllocUProxy(ip, In->port, In->type, NULL, In);
}

PROXY *GetProxyByIdentifier(uint8_t *In)
{
	pthread_mutex_lock(&LockCheckedProxies); {
		for (uint64_t x = 0;x < SizeCheckedProxies;x++) {
			if (MemEqual(In, CheckedProxies[x]->identifier, PROXY_IDENTIFIER_LEN)) {
				pthread_mutex_unlock(&LockCheckedProxies);
				return CheckedProxies[x];
			}
		}
	} pthread_mutex_unlock(&LockCheckedProxies);
	return NULL;
}

void UProxyFree(UNCHECKED_PROXY *In)
{
	if (In->invalidCert != NULL)
		X509_free(In->invalidCert);
	if (In->timeout != NULL) {
		event_del(In->timeout);
		event_free(In->timeout);
	}
	pthread_mutex_destroy(&(In->processing));
	if (In->pageTarget != NULL)
		free(In->pageTarget);
	if (In->targetIPv4 != NULL && In->targetIPv4 != GlobalIp4)
		free(In->targetIPv4);
	if (In->targetIPv6 != NULL && In->targetIPv6 != GlobalIp6)
		free(In->targetIPv6);
	free(In->ip);
	free(In);
}

void ProxyFree(PROXY *In)
{
	if (In->invalidCert != NULL)
		X509_free(In->invalidCert);
	free(In->ip);
	free(In);
}
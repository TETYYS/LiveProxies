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

static bool MultiFlag(uint64_t Flag)
{
	return (Flag & (Flag - 1)) != 0 && Flag != 1;
}

bool ProxyIsSSL(PROXY_TYPE In)
{
	return In == PROXY_TYPE_HTTPS || In == PROXY_TYPE_SOCKS4_TO_SSL || In == PROXY_TYPE_SOCKS4A_TO_SSL || In == PROXY_TYPE_SOCKS5_TO_SSL;
}

static char *ProxyTypes[] = { "HTTP", "HTTPS", "SOCKS4", "SOCKS4A", "SOCKS5", "SOCKS4 -> SSL", "SOCKS4A -> SSL", "SOCKS5 -> SSL", "SOCKS5 UDP", "N/A"};

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
			if (memcmp(Proxy->ip->Data, CheckedProxies[x]->ip->Data, IPV6_SIZE) == 0 && Proxy->port == CheckedProxies[x]->port && Proxy->type == CheckedProxies[x]->type) {
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

	return true;
}

uint8_t UProxyAdd(UNCHECKED_PROXY *UProxy)
{
	uint8_t ret = 0;
	pthread_mutex_lock(&LockUncheckedProxies); {
		for (uint64_t x = 0; x < SizeUncheckedProxies; x++) {
			if (memcmp(UProxy->hash, UncheckedProxies[x]->hash, 512 / 8) == 0) {
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
		for (size_t x = 0; x < PROXY_TYPE_COUNT - 1 /* -1 because of type 1 */; x++) {
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

		ret++;
	}
	return ret;
}

bool UProxyRemove(UNCHECKED_PROXY *UProxy)
{
	bool found = false;

	pthread_mutex_lock(&LockUncheckedProxies); {
		for (uint64_t x = 0; x < SizeUncheckedProxies; x++) {
			if (UProxy == UncheckedProxies[x]) {
				UProxyFree(UncheckedProxies[x]);
				SizeUncheckedProxies--;
				if (SizeUncheckedProxies > 0)
					UncheckedProxies[x] = UncheckedProxies[SizeUncheckedProxies];
				UncheckedProxies = realloc(UncheckedProxies, SizeUncheckedProxies * sizeof(UncheckedProxies));
				found = true;
				break;
			}
		}
	} pthread_mutex_unlock(&LockUncheckedProxies);

	uint64_t network = htobe64(SizeUncheckedProxies);
	WebsocketClientsNotify(&network, sizeof(network), WEBSOCKET_SERVER_COMMAND_SIZE_UPROXIES);

	Log(LOG_LEVEL_DEBUG, "UProxyRemove: size %d", SizeUncheckedProxies);
	return found;
}

bool ProxyRemove(PROXY *Proxy)
{
	bool found = false;

	pthread_mutex_lock(&LockCheckedProxies); {
		for (uint64_t x = 0; x < SizeCheckedProxies; x++) {
			if (Proxy == CheckedProxies[x]) {
				ProxyFree(CheckedProxies[x]);
				SizeCheckedProxies--;
				if (SizeCheckedProxies > 0)
					CheckedProxies[x] = CheckedProxies[SizeCheckedProxies];
				CheckedProxies = realloc(CheckedProxies, SizeCheckedProxies * sizeof(CheckedProxies));
				found = true;
				break;
			}
		}
	} pthread_mutex_unlock(&LockCheckedProxies);

	uint64_t network = htobe64(SizeCheckedProxies);
	WebsocketClientsNotify(&network, sizeof(network), WEBSOCKET_SERVER_COMMAND_SIZE_PROXIES);

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
	GenerateHashForUProxy(UProxy);
	UProxy->associatedProxy = AssociatedProxy;
	UProxy->singleCheckCallback = NULL;
	return UProxy;
}

UNCHECKED_PROXY *UProxyFromProxy(PROXY *In)
{
	Log(LOG_LEVEL_DEBUG, "UProxyFromProxy: In: %p", In);
	IPv6Map *ip = malloc(sizeof(IPv6Map));
	memcpy(ip, In->ip->Data, IPV6_SIZE);

	return AllocUProxy(ip, In->port, In->type, NULL, In);
}

void GenerateHashForUProxy(UNCHECKED_PROXY *In)
{
	size_t dataSize = IPV6_SIZE + sizeof(uint16_t)+sizeof(In->type) + sizeof(hashSalt);

	char *data = malloc(dataSize); {
		memcpy(data, In->ip->Data, IPV6_SIZE);
		memcpy(data + IPV6_SIZE, &(In->port), sizeof(uint16_t));
		memcpy(data + IPV6_SIZE + sizeof(uint16_t), &(In->type), sizeof(In->type));
		memcpy(data + IPV6_SIZE + sizeof(uint16_t)+sizeof(In->type), hashSalt, sizeof(hashSalt));

		SHA512(data, dataSize, In->hash);
	} free(data);

	// 👌
}

char *GenerateUidForProxy(PROXY *In)
{
	uint8_t uid[IPV6_SIZE + sizeof(uint16_t) + sizeof(PROXY_TYPE)];
	memcpy(uid, In->ip->Data, IPV6_SIZE);
	*((uint16_t*)(uid + IPV6_SIZE)) = In->port;
	*((PROXY_TYPE*)(uid + IPV6_SIZE + sizeof(uint16_t))) = In->type;

	char *uidb64;
	Base64Encode(uid, IPV6_SIZE + sizeof(uint16_t) + sizeof(PROXY_TYPE), &uidb64);
	return uidb64;
}

PROXY *GetProxyFromUid(char *Uid)
{
	PROXY *proxy = NULL;

	uint8_t *uid;
	size_t len;
	if (!Base64Decode(Uid, &uid, &len))
		return NULL;
	{
		if (len != IPV6_SIZE + sizeof(uint16_t) + sizeof(PROXY_TYPE)) {
			free(uid);
			return NULL;
		}

		pthread_mutex_lock(&LockCheckedProxies); {
			for (uint64_t x = 0;x < SizeCheckedProxies;x++) {
				if (memcmp(uid, CheckedProxies[x]->ip->Data, IPV6_SIZE) == 0 && *((uint16_t*)(uid + IPV6_SIZE)) == CheckedProxies[x]->port && *((PROXY_TYPE*)(uid + IPV6_SIZE + sizeof(uint16_t))) == CheckedProxies[x]->type) {
					proxy = CheckedProxies[x];
					break;
				}
			}
		} pthread_mutex_unlock(&LockCheckedProxies);
	} free(uid);

	return proxy;
}

void UProxyFree(UNCHECKED_PROXY *In)
{
	if (In->timeout != NULL) {
		event_del(In->timeout);
		event_free(In->timeout);
	}
	pthread_mutex_destroy(&(In->processing));
	free(In->ip);
	free(In);
}

void ProxyFree(PROXY *In)
{
	free(In->ip);
	free(In);
}
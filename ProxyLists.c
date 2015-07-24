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

static bool MultiFlag(char Flag)
{
	return (Flag & (Flag - 1)) != 0 && Flag != 1;
}

bool ProxyIsSSL(PROXY_TYPE In)
{
	return In == PROXY_TYPE_HTTPS || In == PROXY_TYPE_SOCKS4_TO_SSL || In == PROXY_TYPE_SOCKS4A_TO_SSL || In == PROXY_TYPE_SOCKS5_TO_SSL;
}

static char *ProxyTypes[] = { "HTTP", "HTTPS", "SOCKS4", "SOCKS4A", "SOCKS5", "SOCKS4 -> SSL", "SOCKS4A -> SSL", "SOCKS5 -> SSL", "N/A"};

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
		default: return ProxyTypes[8];
	}
}

bool ProxyAdd(PROXY *Proxy)
{
	pthread_mutex_lock(&lockCheckedProxies); {
		for (uint32_t x = 0; x < sizeCheckedProxies; x++) {
			if (memcmp(Proxy->ip->Data, checkedProxies[x]->ip->Data, IPV6_SIZE) == 0 && Proxy->port == checkedProxies[x]->port && Proxy->type == checkedProxies[x]->type) {
				checkedProxies[x]->anonymity = Proxy->anonymity;
				checkedProxies[x]->failedChecks = Proxy->failedChecks;
				checkedProxies[x]->httpTimeoutMs = Proxy->httpTimeoutMs;
				checkedProxies[x]->lastChecked = Proxy->lastChecked;
				checkedProxies[x]->retries = Proxy->retries;
				checkedProxies[x]->successfulChecks = Proxy->successfulChecks;
				checkedProxies[x]->timeoutMs = Proxy->timeoutMs;
				free(Proxy);
				pthread_mutex_unlock(&lockCheckedProxies);
				return false;
			}
		}
		checkedProxies = (PROXY**)realloc(checkedProxies, ++sizeCheckedProxies * sizeof(checkedProxies));
		checkedProxies[sizeCheckedProxies - 1] = Proxy;
	} pthread_mutex_unlock(&lockCheckedProxies);
	return true;
}

uint8_t UProxyAdd(UNCHECKED_PROXY *UProxy)
{
	uint8_t ret = 0;
	pthread_mutex_lock(&lockUncheckedProxies); {
		for (uint32_t x = 0; x < sizeUncheckedProxies; x++) {
			if (memcmp(UProxy->hash, uncheckedProxies[x]->hash, 512 / 8) == 0) {
				char *ip = IPv6MapToString2(UProxy->ip); {
					Log(LOG_LEVEL_WARNING, "Warning: tried to add already added unchecked proxy (%s:%d) (type %d)", ip, UProxy->port, UProxy->type);
				} free(ip);
				pthread_mutex_unlock(&lockUncheckedProxies);
				return ret;
			}
		}
	} pthread_mutex_unlock(&lockUncheckedProxies);
	Log(LOG_LEVEL_DEBUG, "UProxyAdd: size %d", sizeUncheckedProxies);

	if (MultiFlag(UProxy->type)) { // matches 0, 1, 2, 4, 8, 16...
		for (size_t x = 0; x < PROXY_TYPE_COUNT - 1 /* -1 because of type 1 */; x++) {
			if ((UProxy->type & (uint32_t)pow(2, x)) == (uint32_t)pow(2, x)) {
				UNCHECKED_PROXY *newProxy = malloc(sizeof(UNCHECKED_PROXY));
				memcpy(newProxy, UProxy, sizeof(UNCHECKED_PROXY));
				newProxy->type = (uint32_t)pow(2, x);
				newProxy->ip = malloc(sizeof(IPv6Map));
				memcpy(newProxy->ip->Data, UProxy->ip->Data, sizeof(IPv6Map));
				GenerateHashForUProxy(newProxy);
				pthread_mutex_init(&(newProxy->processing), NULL);
				ret += UProxyAdd(newProxy);
			}
		}
	} else {
		pthread_mutex_lock(&lockUncheckedProxies); {
			uncheckedProxies = (UNCHECKED_PROXY**)realloc(uncheckedProxies, sizeof(uncheckedProxies) * ++sizeUncheckedProxies);
			uncheckedProxies[sizeUncheckedProxies - 1] = UProxy;
		} pthread_mutex_unlock(&lockUncheckedProxies);
		ret++;
	}
	return ret;
}

bool UProxyRemove(UNCHECKED_PROXY *UProxy)
{
	bool found = false;

	pthread_mutex_lock(&lockUncheckedProxies); {
		for (uint32_t x = 0; x < sizeUncheckedProxies; x++) {
			if (UProxy == uncheckedProxies[x]) {
				UProxyFree(uncheckedProxies[x]);
				sizeUncheckedProxies--;
				uncheckedProxies[x] = uncheckedProxies[sizeUncheckedProxies];
				uncheckedProxies = (UNCHECKED_PROXY**)realloc(uncheckedProxies, sizeUncheckedProxies * sizeof(uncheckedProxies));
				found = true;
				break;
			}
		}
	} pthread_mutex_unlock(&lockUncheckedProxies);
	Log(LOG_LEVEL_DEBUG, "UProxyRemove: size %d", sizeUncheckedProxies);
	return found;
}

bool ProxyRemove(PROXY *Proxy)
{
	bool found = false;

	pthread_mutex_lock(&lockCheckedProxies); {
		for (uint32_t x = 0; x < sizeCheckedProxies; x++) {
			if (Proxy == checkedProxies[x]) {
				ProxyFree(checkedProxies[x]);
				sizeCheckedProxies--;
				checkedProxies[x] = checkedProxies[sizeCheckedProxies];
				checkedProxies = (PROXY**)realloc(checkedProxies, sizeCheckedProxies * sizeof(checkedProxies));
				found = true;
				break;
			}
		}
	} pthread_mutex_unlock(&lockCheckedProxies);
	return found;
}

UNCHECKED_PROXY *UProxyFromProxy(PROXY *In)
{
	Log(LOG_LEVEL_DEBUG, "UProxyFromProxy: In: %16x", In);
	UNCHECKED_PROXY *ret = malloc(sizeof(UNCHECKED_PROXY));
	Log(LOG_LEVEL_DEBUG, "UProxyFromProxy: UProxy: %16x", ret);
	ret->ip = malloc(sizeof(IPv6Map));
	Log(LOG_LEVEL_DEBUG, "UProxyFromProxy: UProxy->ip: %16x", ret->ip);

	memcpy(ret->ip->Data, In->ip->Data, IPV6_SIZE);
	ret->port = In->port;
	pthread_mutex_init(&(ret->processing), NULL);
	ret->requestTimeMs = ret->requestTimeHttpMs = 0;
	ret->checking = false;
	ret->type = In->type;
	GenerateHashForUProxy(ret);
	Log(LOG_LEVEL_DEBUG, "UProxyFromProxy: UProxy->hash: %16x", ret->hash);
	ret->associatedProxy = In;
	Log(LOG_LEVEL_DEBUG, "UProxyFromProxy: UProxy->associatedProxy: %16x", ret->associatedProxy);
	Log(LOG_LEVEL_DEBUG, "UProxyFromProxy: UProxy: %16x", ret);

	return ret;
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
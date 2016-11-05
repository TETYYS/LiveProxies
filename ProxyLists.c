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
#include "CPH_Threads.h"
#include <event2/event.h>
#include "Base64.h"
#include "Websocket.h"
#include "Config.h"
#include "PortableEndian.h"
#include <openssl/rand.h>
#include <math.h>

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
	return ProxyTypes[(size_t)log2((double)In)];
	/*switch (In) {
		case PROXY_TYPE_HTTP: return ProxyTypes[0];
		case PROXY_TYPE_HTTPS: return ProxyTypes[1];
		case PROXY_TYPE_SOCKS4: return ProxyTypes[2];
		case PROXY_TYPE_SOCKS4A: return ProxyTypes[3];
		case PROXY_TYPE_SOCKS5: return ProxyTypes[4];
		case PROXY_TYPE_SOCKS4_TO_SSL: return ProxyTypes[5];
		case PROXY_TYPE_SOCKS4A_TO_SSL: return ProxyTypes[6];
		case PROXY_TYPE_SOCKS5_TO_SSL: return ProxyTypes[7];
		case PROXY_TYPE_SOCKS5_WITH_UDP: return ProxyTypes[8];
		default: return ProxyTypes[9];
	}*/
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
	WebsocketClientsNotify(&network, sizeof(network), WEBSOCKET_SERVER_COMMAND_SIZE_PROXIES, SizeUncheckedProxies == 0 ? true : false);

	uint8_t ipType = GetIPType(Proxy->ip) == IPV4 ? 0x04 : 0x06;
	char *identifierb64;
	size_t identifierb64Len = Base64Encode(Proxy->identifier, PROXY_IDENTIFIER_LEN, &identifierb64); {
		typedef struct {
			uint8_t ipType;
			uint32_t IPv6[4];
		} __attribute__((packed)) BUFFER6;
		
		typedef struct {
			uint8_t ipType;
			uint32_t IPv4;
		} __attribute__((packed)) BUFFER4;
		
		typedef struct {
			uint16_t port;
			uint16_t type;
			char country[2];
			uint8_t anonimity;
			uint64_t timeout;
			uint64_t httpTimeout;
			uint64_t liveSince;
			uint64_t lastChecked;
			uint8_t retries;
			uint32_t successfulChecks;
			uint32_t failedChecks;
			uint8_t identifierb64[identifierb64Len];
		} __attribute__((packed)) BUFFERU;
		
		BUFFER6 b6;
		BUFFER4 b4;
		BUFFERU buffer;
		
		if (ipType == 0x04) {
			b4.ipType = ipType;
			b4.IPv4 = Proxy->ip->Data[3];
		} else {
			b6.ipType = ipType;
			memcpy(&(b6.IPv6[0]), Proxy->ip->Data, IPV6_SIZE);
		}
		
		buffer.port = htons(Proxy->port);
		buffer.type = htons((uint16_t)Proxy->type);
		buffer.country[0] = Proxy->country[0];
		buffer.country[1] = Proxy->country[1];
		buffer.anonimity = (uint8_t)Proxy->anonymity;
		buffer.timeout = htobe64(Proxy->timeoutMs);
		buffer.httpTimeout = htobe64(Proxy->httpTimeoutMs);
		buffer.liveSince = htobe64(Proxy->liveSinceMs);
		buffer.lastChecked = htobe64(Proxy->lastCheckedMs);
		buffer.retries = Proxy->retries;
		buffer.successfulChecks = htonl(Proxy->successfulChecks);
		buffer.failedChecks = htonl(Proxy->failedChecks);
		memcpy(&(buffer.identifierb64[0]), identifierb64, strlen(identifierb64));
		
		if (ipType == 0x04) {
			uint8_t bufferAll[sizeof(BUFFER4) + sizeof(BUFFERU)];
			memcpy(bufferAll, &b4, sizeof(BUFFER4));
			memcpy((void*)((size_t)bufferAll + sizeof(BUFFER4)), &buffer, sizeof(BUFFERU));
			WebsocketClientsNotify((void*)bufferAll, sizeof(BUFFER4) + sizeof(BUFFERU), WEBSOCKET_SERVER_COMMAND_PROXY_ADD, false);
		} else {
			uint8_t bufferAll[sizeof(BUFFER6) + sizeof(BUFFERU)];
			memcpy(bufferAll, &b6, sizeof(BUFFER6));
			memcpy((void*)((size_t)bufferAll + sizeof(BUFFER6)), &buffer, sizeof(BUFFERU));
			WebsocketClientsNotify((void*)bufferAll, sizeof(BUFFER6) + sizeof(BUFFERU), WEBSOCKET_SERVER_COMMAND_PROXY_ADD, false);
		}
#undef buffer
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
		WebsocketClientsNotify(&network, sizeof(network), WEBSOCKET_SERVER_COMMAND_SIZE_UPROXIES, false);

		uint8_t ipType = GetIPType(UProxy->ip) == IPV4 ? 0x04 : 0x06;
		
		typedef struct {
			uint8_t ipType;
			uint32_t IPv6[4];
		} __attribute__((packed)) BUFFER6;
		
		typedef struct {
			uint8_t ipType;
			uint32_t IPv4;
		} __attribute__((packed)) BUFFER4;
		
		typedef struct {
			uint16_t port;
			uint16_t type;
			bool checking;
			uint8_t retries;
			bool rechecking;
		} __attribute__((packed)) BUFFERU;

		BUFFER6 b6;
		BUFFER4 b4;
		BUFFERU buffer;
		
		if (ipType == 0x04) {
			b4.ipType = ipType;
			b4.IPv4 = UProxy->ip->Data[3];
		} else {
			b6.ipType = ipType;
			memcpy(&(b6.IPv6[0]), UProxy->ip->Data, IPV6_SIZE);
		}
		
		buffer.port = htons(UProxy->port);
		buffer.type = htons((uint16_t)UProxy->type);
		buffer.checking = UProxy->checking;
		buffer.retries = UProxy->retries;
		buffer.rechecking = (UProxy->associatedProxy != NULL);

		if (ipType == 0x04) {
			uint8_t bufferAll[sizeof(BUFFER4) + sizeof(BUFFERU)];
			memcpy(bufferAll, &b4, sizeof(BUFFER4));
			memcpy((void*)((size_t)bufferAll + sizeof(BUFFER4)), &buffer, sizeof(BUFFERU));
			WebsocketClientsNotify((void*)bufferAll, sizeof(BUFFER4) + sizeof(BUFFERU), WEBSOCKET_SERVER_COMMAND_UPROXY_ADD, false);
		} else {
			uint8_t bufferAll[sizeof(BUFFER6) + sizeof(BUFFERU)];
			memcpy(bufferAll, &b6, sizeof(BUFFER6));
			memcpy((void*)((size_t)bufferAll + sizeof(BUFFER6)), &buffer, sizeof(BUFFERU));
			WebsocketClientsNotify((void*)bufferAll, sizeof(BUFFER6) + sizeof(BUFFERU), WEBSOCKET_SERVER_COMMAND_UPROXY_ADD, false);
		}
#undef buffer
		
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
				uint8_t ipType = GetIPType(UProxy->ip) == IPV4 ? 0x04 : 0x06;
				
				typedef struct {
					uint8_t ipType;
					uint32_t IPv6[4];
				} __attribute__((packed)) BUFFER6;
		
				typedef struct {
					uint8_t ipType;
					uint32_t IPv4;
				} __attribute__((packed)) BUFFER4;
				
				typedef struct {
					uint16_t port;
					uint16_t type;
				} __attribute__((packed)) BUFFERU;

				BUFFER6 b6;
				BUFFER4 b4;
				BUFFERU buffer;
				
				if (ipType == 0x04) {
					b4.ipType = ipType;
					b4.IPv4 = UProxy->ip->Data[3];
				}
				else {
					b6.ipType = ipType;
					memcpy(&(b6.IPv6[0]), UProxy->ip->Data, IPV6_SIZE);
				}
				
				buffer.port = htons(UProxy->port);
				buffer.type = htons((uint16_t)UProxy->type);
				
				if (ipType == 0x04) {
					uint8_t bufferAll[sizeof(BUFFER4) + sizeof(BUFFERU)];
					memcpy(bufferAll, &b4, sizeof(BUFFER4));
					memcpy((void*)((size_t)bufferAll + sizeof(BUFFER4)), &buffer, sizeof(BUFFERU));
					WebsocketClientsNotify((void*)bufferAll, sizeof(BUFFER4) + sizeof(BUFFERU), WEBSOCKET_SERVER_COMMAND_UPROXY_REMOVE, false);
				} else {
					uint8_t bufferAll[sizeof(BUFFER6) + sizeof(BUFFERU)];
					memcpy(bufferAll, &b6, sizeof(BUFFER6));
					memcpy((void*)((size_t)bufferAll + sizeof(BUFFER6)), &buffer, sizeof(BUFFERU));
					WebsocketClientsNotify((void*)bufferAll, sizeof(BUFFER6) + sizeof(BUFFERU), WEBSOCKET_SERVER_COMMAND_UPROXY_REMOVE, false);
				}

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
		WebsocketClientsNotify(&network, sizeof(network), WEBSOCKET_SERVER_COMMAND_SIZE_UPROXIES, SizeUncheckedProxies == 0 ? true : false);

		Log(LOG_LEVEL_DEBUG, "UProxyRemove: size %d", SizeUncheckedProxies);
	} pthread_mutex_unlock(&LockUncheckedProxies);
	return found;
}

bool ProxyRemove(PROXY *Proxy)
{
	bool found = false;

	pthread_mutex_lock(&LockCheckedProxies); {
		for (uint64_t x = 0; x < SizeCheckedProxies; x++) {
			if (Proxy == CheckedProxies[x]) {
				uint8_t ipType = GetIPType(Proxy->ip) == IPV4 ? 0x04 : 0x06;
				
				typedef struct {
					uint8_t ipType;
					uint32_t IPv6[4];
				} __attribute__((packed)) BUFFER6;
		
				typedef struct {
					uint8_t ipType;
					uint32_t IPv4;
				} __attribute__((packed)) BUFFER4;
				
				typedef struct {
					uint16_t port;
					uint16_t type;
				} __attribute__((packed)) BUFFERU;

				BUFFER6 b6;
				BUFFER4 b4;
				BUFFERU buffer;
				
				if (ipType == 0x04) {
					b4.ipType = ipType;
					b4.IPv4 = Proxy->ip->Data[3];
				}
				else {
					b6.ipType = ipType;
					memcpy(&(b6.IPv6[0]), Proxy->ip->Data, IPV6_SIZE);
				}
				
				buffer.port = htons(Proxy->port);
				buffer.type = htons((uint16_t)Proxy->type);
				
				if (ipType == 0x04) {
					uint8_t bufferAll[sizeof(BUFFER4) + sizeof(BUFFERU)];
					memcpy(bufferAll, &b4, sizeof(BUFFER4));
					memcpy((void*)((size_t)bufferAll + sizeof(BUFFER4)), &buffer, sizeof(BUFFERU));
					WebsocketClientsNotify((void*)bufferAll, sizeof(BUFFER4) + sizeof(BUFFERU), WEBSOCKET_SERVER_COMMAND_PROXY_REMOVE, false);
				} else {
					uint8_t bufferAll[sizeof(BUFFER6) + sizeof(BUFFERU)];
					memcpy(bufferAll, &b6, sizeof(BUFFER6));
					memcpy((void*)((size_t)bufferAll + sizeof(BUFFER6)), &buffer, sizeof(BUFFERU));
					WebsocketClientsNotify((void*)bufferAll, sizeof(BUFFER6) + sizeof(BUFFERU), WEBSOCKET_SERVER_COMMAND_PROXY_REMOVE, false);
				}

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
		WebsocketClientsNotify(&network, sizeof(network), WEBSOCKET_SERVER_COMMAND_SIZE_PROXIES, false);
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
	RAND_pseudo_bytes((unsigned char*)(&UProxy->identifier), PROXY_IDENTIFIER_LEN); // TODO: Hash table anti-collision
	UProxy->associatedProxy = AssociatedProxy;
	UProxy->pageTargetPostData = NULL;
	UProxy->singleCheckCallback = NULL;
	UProxy->invalidCert = NULL;
	UProxy->pageTarget = NULL;
	UProxy->getResponse = false;
	UProxy->targetPort = 0;
	UProxy->targetIPv4 = NULL;
	UProxy->targetIPv6 = NULL;
	UProxy->dnsResolveInProgress = 0;
	UProxy->dnsLookups = NULL;
	UProxy->dnsLookupsCount = 0;
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
	if (In->dnsLookupsCount > 0) {
		for (size_t x = 0; x < In->dnsLookupsCount; x++) {
			dns_fini(In->dnsLookups[x]->dnsCtx);
			event_del(In->dnsLookups[x]->evDNS);
			event_free(In->dnsLookups[x]->evDNS);
			free(In->dnsLookups[x]);
		}
		free(In->dnsLookups);
	}
	
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
	if (In->assocBufferEvent != NULL)
		bufferevent_free(In->assocBufferEvent);
	free(In);
}

void ProxyFree(PROXY *In)
{
	if (In->invalidCert != NULL)
		X509_free(In->invalidCert);
	free(In->ip);
	free(In);
}
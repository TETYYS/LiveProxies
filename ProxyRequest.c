#include "ProxyRequest.h"
#include "ProxyLists.h"
#include "Global.h"
#include "Base64.h"
#include "Logger.h"
#include "Config.h"
#include "ProxyRemove.h"
#include "DNS.h"
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/bufferevent_ssl.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#ifdef __linux__
	#include <arpa/inet.h>
	#include <unistd.h>
#endif
#include <time.h>
#include <limits.h>
#include <assert.h>

static void RequestFree(evutil_socket_t fd, short what, UNCHECKED_PROXY *UProxy)
{
	//Log(LOG_LEVEL_DEBUG, "RequestFree BuffEvent free %p", UProxy->assocBufferEvent);

	bufferevent_free(UProxy->assocBufferEvent);

	if (UProxy->timeout != NULL) {
		event_del(UProxy->timeout);
		event_free(UProxy->timeout);
		UProxy->timeout = NULL;
	} else {
		Log(LOG_LEVEL_ERROR, "Timeout-less proxy");
		Log(LOG_LEVEL_ERROR, "Please report this bug");
		assert(false);
	}

	if (UProxy->udpRead != NULL) {
		event_del(UProxy->udpRead);
		event_free(UProxy->udpRead);
		UProxy->udpRead = NULL;
	}

	//char *ip = IPv6MapToString(UProxy->ip); {
		//Log(LOG_LEVEL_DEBUG, "RequestFree -> %s", ip);
	//} free(ip);

	InterlockedDecrement(&CurrentlyChecking);

	pthread_mutex_lock(&LockUncheckedProxies); {
	} pthread_mutex_unlock(&LockUncheckedProxies);

	pthread_mutex_lock(&(UProxy->processing));

	if (UProxy->associatedProxy == NULL) {
		if (!UProxy->checkSuccess)
			UProxy->retries++;
		if (UProxy->retries >= AcceptableSequentialFails || UProxy->checkSuccess) {
			char *ip = IPv6MapToString(UProxy->ip); {
				Log(LOG_LEVEL_DEBUG, "RequestFree: Removing proxy %s...", ip);
			} free(ip);
			UProxyRemove(UProxy);
		} else {
			pthread_mutex_unlock(&(UProxy->processing));
			UProxy->checking = false;
		}
	} else {
		if (UProxy->pageTarget == NULL) {
			char *ip = IPv6MapToString(UProxy->ip); {
				Log(LOG_LEVEL_DEBUG, "RequestFree: Removing proxy %s and updating parent...", ip);
			} free(ip);

			if (!UProxy->checkSuccess)
				UProxyFailUpdateParentInfo(UProxy);
			else
				UProxySuccessUpdateParentInfo(UProxy);

			if (UProxy->singleCheckCallback != NULL)
				UProxy->singleCheckCallback(UProxy);
		} else if (UProxy->getResponse)
			((SingleCheckCallbackCPage)(UProxy->singleCheckCallback))(UProxy, UPROXY_CUSTOM_PAGE_STAGE_END);

		UProxyRemove(UProxy);
	}
}

typedef enum _SOCKS_TYPE {
	SOCKS_TYPE_CONNECT = 0x01,
	SOCKS_TYPE_BIND = 0x02,
	SOCKS_TYPE_UDP_ASSOCIATE = 0x03
} SOCKS_TYPE;

static bool SOCKS4(SOCKS_TYPE Type, UNCHECKED_PROXY *UProxy)
{
	if (Type == SOCKS_TYPE_UDP_ASSOCIATE)
		return false;

	if (UProxy->stage == UPROXY_STAGE_INITIAL_PACKET) {
		/*
		field 1: SOCKS version number, 1 byte, must be 0x04 for this version
		field 2: command code, 1 byte:
		0x01 = establish a TCP/IP stream connection
		0x02 = establish a TCP/IP port binding
		field 3: network byte order port number, 2 bytes
		field 4: network byte order IP address, 4 bytes
		field 5: the user ID string, variable length, terminated with a null (0x00)
		*/
		
		struct {
			uint8_t ver;
			uint8_t cmd;
			uint16_t port;
			uint32_t IPv4;
			uint8_t userId;
		} __attribute__((packed)) buffer;
		
		buffer.ver = 0x04;
		buffer.cmd = 0x01; // CONNECT
		buffer.port = htons(UProxy->targetPort);
		buffer.IPv4 = htonl(UProxy->targetIPv4->Data[3]);
		buffer.userId = 0x00;

		bufferevent_write(UProxy->assocBufferEvent, &buffer, 9);
		bufferevent_setwatermark(UProxy->assocBufferEvent, EV_READ, 8, 0);
		
		return true;
	} else if (UProxy->stage == UPROXY_STAGE_INITIAL_RESPONSE) {
		size_t len = evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent));
		uint8_t data[2];
		if (len != 8)
			return false;

		evbuffer_remove(bufferevent_get_input(UProxy->assocBufferEvent), data, 2);
		Log(LOG_LEVEL_DEBUG, "SOCKS4: Stage 2 data[1]: %d", data[1]);
		return data[1] == 0x5A;
	} else {
		assert(false);
		return false;
	}
}

typedef enum _SOCKS5_RET_STATUS {
	SOCKS5_RET_STATUS_FAILURE = 0,
	SOCKS5_RET_STATUS_SUCCESS = 1,
	SOCKS5_RET_STATUS_IPV4_FAILED = 2,
	SOCKS5_RET_STATUS_IPV6_FAILED = 3
} SOCKS5_RET_STATUS;

static SOCKS5_RET_STATUS SOCKS5(SOCKS_TYPE Type, uint16_t *Port, UNCHECKED_PROXY *UProxy, char *Domain)
{
	/*
	field 1: SOCKS version number (must be 0x05 for this version)
	field 2: number of authentication methods supported, 1 byte
	field 3: authentication methods, variable length, 1 byte per method supported
	0x00: No authentication
	0x01: GSSAPI
	0x02: Username/Password
	0x03–0x7F: methods assigned by IANA
	0x80–0xFE: methods reserved for private use

	+----+-----+-------+------+----------+----------+
	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	+----+-----+-------+------+----------+----------+
	| 1  |  1  | X'00' |  1   | Variable |    2     |
	+----+-----+-------+------+----------+----------+


	o  VER    protocol version: X'05'
	o  CMD
	o		CONNECT X'01'
	o		BIND X'02'
	o		UDP ASSOCIATE X'03'
	o  RSV    RESERVED
	o  ATYP   address type of following address
	o		IP V4 address: X'01'
	o		DOMAINNAME: X'03'
	o		IP V6 address: X'04'
	o  DST.ADDR       desired destination address // network octet order? nope
	o  DST.PORT desired destination port in network octet order
	*/

	switch (UProxy->stage) {
		case UPROXY_STAGE_INITIAL_PACKET:
		{
			uint8_t buff[3];
			buff[0] = 0x05;
			buff[1] = 1; // 1 auth
			buff[2] = 0x00; // no auth
			bufferevent_write(UProxy->assocBufferEvent, buff, 3);
			bufferevent_setwatermark(UProxy->assocBufferEvent, EV_READ, 2, 0);
			break;
		}
		case UPROXY_STAGE_INITIAL_RESPONSE:
		{
			size_t len = evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent));
			uint8_t data[2];
			Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 1 data len: %d", len);
			if (len != 2)
				return false;

			evbuffer_remove(bufferevent_get_input(UProxy->assocBufferEvent), data, 2);
			Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 1 data[1]: %d", data[1]);
			return data[1] == 0x00;
		}
		case UPROXY_STAGE_SOCKS5_MAIN_PACKET:
		{
			IP_TYPE ipType = GetIPType(UProxy->ip); // Prefered

			if (ipType == IPV4 && UProxy->targetIPv4 == NULL)
				ipType = IPV6;
			if (ipType == IPV6 && UProxy->targetIPv6 == NULL)
				ipType = IPV4;
			// -> Real

			size_t domainLen = Domain != NULL ? strlen(Domain) : 0;
			
			uint8_t *buff;
			if (UProxy->pageTarget != NULL && SOCKS5ResolveDomainsRemotely)	{
				Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 2 Domain");
				buff = alloca(5 + domainLen + sizeof(uint16_t));
			} else {
				if (ipType == IPV4) {
					Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 2 IPV4");
					buff = alloca(4 + IPV4_SIZE + sizeof(uint16_t));
				} else {
					Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 2 IPV6");
					buff = alloca(4 + IPV6_SIZE + sizeof(uint16_t));
				}
			}
			
			size_t portOffset;
			
			buff[0] = 0x05; // again?
			buff[1] = Type;
			buff[2] = 0x00; // RESERVED
			if (UProxy->pageTarget != NULL && SOCKS5ResolveDomainsRemotely && Domain != NULL) {
				buff[3] = 0x03;
				buff[4] = (uint8_t)domainLen;
				memcpy(&(buff[5]), Domain, domainLen);
				portOffset = 1 + domainLen;
			} else {
				buff[3] = ipType == IPV4 ? 0x01 : 0x04; // who was 0x02?
			
				if (ipType == IPV4) {
					(*(uint32_t*)(&(buff[4]))) = UProxy->targetIPv4->Data[3];
					portOffset = IPV4_SIZE;
				} else {
					memcpy(&(buff[4]), UProxy->targetIPv6->Data, IPV6_SIZE);
					portOffset = IPV6_SIZE;
				}
				*((uint16_t*)&(buff[4 + portOffset])) = Type != SOCKS_TYPE_UDP_ASSOCIATE ? htons(*Port) : 0;
			}
			
			Log(LOG_LEVEL_DEBUG, "portOffset %d", portOffset);
			
			bufferevent_write(UProxy->assocBufferEvent, buff, 4 + portOffset + sizeof(uint16_t));
			bufferevent_setwatermark(UProxy->assocBufferEvent, EV_READ, 10, 0);
			
			break;
		}
		case UPROXY_STAGE_SOCKS5_RESPONSE:
		{
			bufferevent_setwatermark(UProxy->assocBufferEvent, EV_READ, 1, 0);
			size_t len = evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent));
			
			if (len < 4) {
				Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 3 data len failure 1");
				return false;
			}
			
			uint8_t header[4];
			
			evbuffer_remove(bufferevent_get_input(UProxy->assocBufferEvent), header, 4);
			size_t addressType = header[3];
			
			Log(LOG_LEVEL_DEBUG, "data[1] %x", header[1]);
			
			if (header[1] == 0x08 || header[1] == 0x02) {
				Log(LOG_LEVEL_DEBUG, "ipType %s", addressType == 0x01 ? "SOCKS5_RET_STATUS_IPV4_FAILED" : "SOCKS5_RET_STATUS_IPV6_FAILED");
				return addressType == 0x01 ? SOCKS5_RET_STATUS_IPV4_FAILED : SOCKS5_RET_STATUS_IPV6_FAILED; // Recoverable failure, tries to connect with different address type.
			}
			
			size_t domainLen, dataLen;
			if (addressType == 0x03) {
				evbuffer_remove(bufferevent_get_input(UProxy->assocBufferEvent), header, 1);
				domainLen = header[0];
				dataLen = domainLen + sizeof(uint16_t);
			} else if (addressType == 0x01) {
				dataLen = IPV4_SIZE + sizeof(uint16_t);
			} else if (addressType == 0x04) {
				dataLen = IPV6_SIZE + sizeof(uint16_t);
			} else {
				Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 3 malformed packet");
				return false;
			}
			
			uint8_t data[dataLen];
			len = evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent));
			
			Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 3 data len: %d", len);

			if (len != dataLen) {
				Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 3 data len failure 2");
				return false;
			}
			
			evbuffer_remove(bufferevent_get_input(UProxy->assocBufferEvent), data, dataLen);

			memcpy(Port, &(data[dataLen - 2]), 2);
			*Port = ntohs(*Port);
			
			Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 3 port: %d", *Port);
			
			return true;
		}
		default: {
			assert(false);
			break;
		}
	}
	return true;
}

void ProxyDNSReResolved(struct dns_cb_data *data)
{
	DNS_LOOKUP_ASYNC_EX *ex = data->context;
	UNCHECKED_PROXY *newProxy = ex->object;
	
	Log(LOG_LEVEL_DEBUG, "ProxyDNSReResolved");
	pthread_mutex_lock(&(newProxy->processing));
	
	if (data->addr_len <= 0) {
		// Secondary address type failed, delete proxy
		UProxyFree(newProxy);
		return;
	}
	
	if (!ex->ipv6) {
		newProxy->targetIPv4 = zalloc(sizeof(IPv6Map));
		memcpy(&(newProxy->targetIPv4->Data[3]), data->addr, IPV4_SIZE);
		newProxy->targetIPv4->Data[2] = 0xFFFF0000;

#if DEBUG
		char *ip = IPv6MapToString2(newProxy->targetIPv4); {
			Log(LOG_LEVEL_DEBUG, "ProxyDNSReResolved IPv4 %s", ip);
		} free(ip);
#endif
	} else if (ex->ipv6) {
		newProxy->targetIPv6 = malloc(sizeof(IPv6Map));
		memcpy(newProxy->targetIPv6->Data, data->addr, IPV6_SIZE);

#if DEBUG
		char *ip = IPv6MapToString2(newProxy->targetIPv6); {
			Log(LOG_LEVEL_DEBUG, "ProxyDNSReResolved IPv6 %s", ip);
		} free(ip);
#endif
	} else {
		assert(false);
		return;
	}
	
	UProxyAdd(newProxy);
	RequestAsync(newProxy);
	
	pthread_mutex_unlock(&(newProxy->processing));
}

void ProxyDNSResolved(struct dns_cb_data *data)
{
	DNS_LOOKUP_ASYNC_EX *ex = (DNS_LOOKUP_ASYNC_EX*)data->context;
	UNCHECKED_PROXY *UProxy = (UNCHECKED_PROXY*)ex->object;

	pthread_mutex_lock(&(UProxy->processing));
	
	if (!ex->ipv6)
		UProxy->dnsResolveInProgress &= ~IPV4;
	
	if (ex->ipv6)
		UProxy->dnsResolveInProgress &= ~IPV6;
	
	if (data->addr_len > 0) {
		bool firstResolve = UProxy->targetIPv4 == NULL && UProxy->targetIPv6 == NULL;
		
		if (!ex->ipv6 && UProxy->targetIPv4 == NULL) {
			UProxy->targetIPv4 = zalloc(sizeof(IPv6Map));
			memcpy(&(UProxy->targetIPv4->Data[3]), data->addr, IPV4_SIZE);
			UProxy->targetIPv4->Data[2] = 0xFFFF0000;

#if DEBUG
			char *ip = IPv6MapToString2(UProxy->targetIPv4); {
				Log(LOG_LEVEL_DEBUG, "ProxyDNSResolved IPv4 %s", ip);
			} free(ip);
#endif
		}
		else if (ex->ipv6 && UProxy->targetIPv6 == NULL) {
			UProxy->targetIPv6 = malloc(sizeof(IPv6Map));
			memcpy(UProxy->targetIPv6->Data, data->addr, IPV6_SIZE);

#if DEBUG
			char *ip = IPv6MapToString2(UProxy->targetIPv6); {
				Log(LOG_LEVEL_DEBUG, "ProxyDNSResolved IPv6 %s", ip);
			} free(ip);
#endif
		}

		if (firstResolve) {
			Log(LOG_LEVEL_DEBUG, "ProxyDNSResolved -> ProxyHandleData CONNECT");
			pthread_mutex_unlock(&(UProxy->processing));
			ProxyHandleData(UProxy, EV_TYPE_CONNECT);
		} else
			pthread_mutex_unlock(&(UProxy->processing));
	} else if (UProxy->targetIPv4 == NULL && UProxy->targetIPv6 == NULL && UProxy->dnsResolveInProgress == 0) {
		bufferevent_setcb(UProxy->assocBufferEvent, NULL, NULL, NULL, NULL);
		if (UProxy->timeout != NULL)
			event_active(UProxy->timeout, EV_TIMEOUT, 0);
		else {
			Log(LOG_LEVEL_ERROR, "Timeout-less proxy 2");
			Log(LOG_LEVEL_ERROR, "Please report this bug");
			assert(false);
		}
		if (data->error != DNS_DOES_NOT_EXIST)
			Log(LOG_LEVEL_WARNING, "Failed to lookup CPage DNS");
		
		pthread_mutex_unlock(&(UProxy->processing));
	} else
		pthread_mutex_unlock(&(UProxy->processing));
	
	ex->resolveDone = true;
}

static void ProxyDNSFreed(DNS_LOOKUP_ASYNC_EX *Ex)
{
	UNCHECKED_PROXY *UProxy = Ex->object;
	Log(LOG_LEVEL_DEBUG, "DNS FREEEEEEEEEEEEEEEEEEEEEEED! IPv6? %s", Ex->ipv6 ? "ye" : "nah");
	
	pthread_mutex_lock(&(UProxy->processing));
	
	for (size_t x = 0; x < UProxy->dnsLookupsCount; x++) {
		if (UProxy->dnsLookups[x] == Ex) {
			UProxy->dnsLookupsCount--;
			if (UProxy->dnsLookupsCount > 0) {
				UProxy->dnsLookups[x] = UProxy->dnsLookups[UProxy->dnsLookupsCount];
			} else {
				free(UProxy->dnsLookups);
				UProxy->dnsLookups = NULL;
			}
			
			pthread_mutex_unlock(&(UProxy->processing));
			return;
		}
	}
}

static void ProxyDNSResolve(UNCHECKED_PROXY *UProxy, char *Domain)
{
	if (UProxy->pageTarget == NULL)
		return;

	UProxy->dnsResolveInProgress = IPV4 | IPV6;
	UProxy->dnsLookups = malloc(sizeof(DNS_LOOKUP_ASYNC_EX*) * 2);
	UProxy->dnsLookups[0] = DNSResolveAsync(UProxy, Domain, true, ProxyDNSResolved, ProxyDNSFreed);
	if (UProxy->dnsLookups[0] != NULL)
		UProxy->dnsLookupsCount++;
	
	UProxy->dnsLookups[UProxy->dnsLookupsCount] = DNSResolveAsync(UProxy, Domain, false, ProxyDNSResolved, ProxyDNSFreed);
	if (UProxy->dnsLookups[UProxy->dnsLookupsCount] != NULL)
		UProxy->dnsLookupsCount++;
}

static MEM_OUT char *ProxyParseUrl(UNCHECKED_PROXY *UProxy, bool OnlyDomain, bool IncludePort, OUT char **Path)
{
	char *domain;

	if (strstr(UProxy->pageTarget, "https://") == NULL && strstr(UProxy->pageTarget, "http://") == NULL && strstr(UProxy->pageTarget, "udp://") == NULL)
		return NULL;

	if (strncmp(UProxy->pageTarget, "https", 5) == 0) {
		domain = strdup(UProxy->pageTarget + 8);
	} else if (strncmp(UProxy->pageTarget, "http", 4) == 0)
		domain = strdup(UProxy->pageTarget + 7);
	else
		domain = strdup(UProxy->pageTarget + 6);

	char *pathStart = strstr(domain, "/");
	if (pathStart != NULL) {
		if (Path != NULL)
			*Path = strdup(pathStart);
		*pathStart = 0x00;
	} else {
		if (Path != NULL)
			*Path = NULL;
	}

	char *portStart = strchr(domain, ':');
	if (portStart == NULL) {
		if (!OnlyDomain)
			UProxy->targetPort = strstr(UProxy->pageTarget, "https://") != NULL ? HTTPS_DEFAULT_PORT : HTTP_DEFAULT_PORT;
	} else {
		*portStart = 0x00;
		if (IncludePort) {
			UProxy->targetPort = atoi(portStart + sizeof(char));
			if (UProxy->targetPort == 80 || UProxy->targetPort == 443)
				*portStart = ':';
		}
	}
	if (OnlyDomain)
		return domain;

	IPv6Map *ip = StringToIPv6Map(domain);
	if (ip != NULL) {
		if (GetIPType(ip) == IPV6)
			UProxy->targetIPv6 = ip;
		else
			UProxy->targetIPv4 = ip;
	}

	return domain;
}

void ProxyHandleData(UNCHECKED_PROXY *UProxy, PROXY_HANDLE_DATA_EV_TYPE EVType)
{
	Log(LOG_LEVEL_DEBUG, "ProxyHandleData: Proxy %s (%d), stage %d EVType %s", ProxyGetTypeString(UProxy->type), UProxy->type, UProxy->stage, EVType == EV_TYPE_READ ? "EV_TYPE_READ" : (EVType == EV_TYPE_WRITE ? "EV_TYPE_WRITE" : "EV_TYPE_CONNECT"));
	char *reqString;
#define EVTYPE_CASE(x) if (EVType != x) { pthread_mutex_unlock(&(UProxy->processing)); Log(LOG_LEVEL_DEBUG, "PROCESSING UNLOCK!CASE"); return; }
#define EVTYPE_CASE_NOT(x) if (EVType == x) { pthread_mutex_unlock(&(UProxy->processing)); Log(LOG_LEVEL_DEBUG, "PROCESSING UNLOCK!CASE NOT"); return; }

	Log(LOG_LEVEL_DEBUG, "PROCESSING LOCK!");
	pthread_mutex_lock(&(UProxy->processing));
	
	switch (UProxy->type) {
		case PROXY_TYPE_HTTP: {
			// Initial plain HTTP stage, go straight to sending HTTP request

			if (UProxy->stage != UPROXY_STAGE_HTTP_RESPONSE && UProxy->stage != UPROXY_STAGE_HTTP_DDL_PAGE) {
				EVTYPE_CASE(EV_TYPE_CONNECT);
				UProxy->stage = UPROXY_STAGE_HTTP_REQUEST;
			}
			break;
		}
		case PROXY_TYPE_HTTPS: {
			switch (UProxy->stage) {
				case UPROXY_STAGE_INITIAL_PACKET: {
					// Initial HTTPS stage, format CONNECT request and send it, proceed to stage 1

					EVTYPE_CASE(EV_TYPE_CONNECT);

					if (UProxy->pageTarget == NULL) {
						Log(LOG_LEVEL_DEBUG, "Proxy type HTTPS target const");
						char *host = HostHostnameSSL != NULL ? HostHostnameSSL : GetHost(GetIPType(UProxy->ip), ProxyIsSSL(UProxy->type));
						Log(LOG_LEVEL_DEBUG, "Proxy type HTTPS target const host %s", host);

						reqString = StrReplaceToNew(RequestStringSSL, "{HOST}", host); {
							if (strstr(reqString, "{KEY_VAL}") != NULL) {
								char *key;
								Base64Encode(UProxy->identifier, PROXY_IDENTIFIER_LEN, &key); {
									StrReplaceOrig(&reqString, "{KEY_VAL}", key);
								} free(key);
							}

							Log(LOG_LEVEL_DEBUG, "HTTPS ReqString:");
							Log(LOG_LEVEL_DEBUG, reqString);

							bufferevent_write(UProxy->assocBufferEvent, (void*)reqString, strlen(reqString));
						} free(reqString);
					} else {
						Log(LOG_LEVEL_DEBUG, "Proxy type HTTPS target page");
						char *domain = ProxyParseUrl(UProxy, true, true, NULL); {
							if (domain == NULL)
								goto fail;

							reqString = StrReplaceToNew(RequestStringSSL, "{HOST}", domain);
							if (strstr(reqString, "{KEY_VAL}") != NULL) {
								char *key;
								Base64Encode(UProxy->identifier, PROXY_IDENTIFIER_LEN, &key); {
									StrReplaceOrig(&reqString, "{KEY_VAL}", key);
								} free(key);
							}
							Log(LOG_LEVEL_DEBUG, "Proxy type HTTPS target page domain", domain);
						} free(domain);

						Log(LOG_LEVEL_DEBUG, "HTTPS ReqString:");
						Log(LOG_LEVEL_DEBUG, reqString);

						bufferevent_write(UProxy->assocBufferEvent, (void*)reqString, strlen(reqString));
						free(reqString);
					}

					UProxy->stage = UPROXY_STAGE_INITIAL_RESPONSE;
					break;
				}
				case UPROXY_STAGE_INITIAL_RESPONSE: {
					// HTTPS stage 1, check if CONNECT request response is 200

					EVTYPE_CASE(EV_TYPE_READ);
					// HTTP/1.1 200

					size_t len = evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent));
					char data[12];
					if (len < 12)
						goto fail;

					evbuffer_remove(bufferevent_get_input(UProxy->assocBufferEvent), data, 12);
					if (strncmp(data + 9, "200", 3) != 0)
						goto fail;

					Log(LOG_LEVEL_DEBUG, "Proxy type HTTPS CONNECT read OK");

					UProxy->stage = UPROXY_STAGE_SSL_HANDSHAKE;
					break;
				}
				default: {
					assert(false);
					break;
				}
			}
			break;
		}
		case PROXY_TYPE_SOCKS4:
		case PROXY_TYPE_SOCKS4A:
		case PROXY_TYPE_SOCKS4_TO_SSL:
		case PROXY_TYPE_SOCKS4A_TO_SSL: {
			if (GetIPType(UProxy->ip) == IPV4) // ???
				goto fail;

			switch (UProxy->stage) {
				case UPROXY_STAGE_INITIAL_PACKET: {
					EVTYPE_CASE(EV_TYPE_CONNECT);

					if (UProxy->pageTarget == NULL) {
						SOCKS4(SOCKS_TYPE_CONNECT, UProxy);
						UProxy->stage = UPROXY_STAGE_INITIAL_RESPONSE;
					} else {
						char *domain = ProxyParseUrl(UProxy, false, false, NULL); {
							if (domain == NULL)
								goto fail;
							if (UProxy->targetIPv4 == NULL && UProxy->targetIPv6 == NULL) {
								ProxyDNSResolve(UProxy, domain);
								free(domain);
								
								Log(LOG_LEVEL_DEBUG, "PROCESSING UNLOCK!1");
								pthread_mutex_unlock(&(UProxy->processing));
								return;
							} else {
								SOCKS4(SOCKS_TYPE_CONNECT, UProxy);
								UProxy->stage = UPROXY_STAGE_INITIAL_RESPONSE;
							}
						} free(domain);
					}
					break;
				}
				case UPROXY_STAGE_INITIAL_RESPONSE: {
					EVTYPE_CASE(EV_TYPE_READ);

					if (!SOCKS4(SOCKS_TYPE_CONNECT, UProxy))
						goto fail;
					UProxy->stage = ProxyIsSSL(UProxy->type) ? UPROXY_STAGE_SSL_HANDSHAKE : UPROXY_STAGE_HTTP_REQUEST;
				}
				default: {
					assert(false);
					break;
				}
			}
			break;
		}
		case PROXY_TYPE_SOCKS5:
		case PROXY_TYPE_SOCKS5_TO_SSL:
		case PROXY_TYPE_SOCKS5_WITH_UDP: {
			uint16_t port = UProxy->targetPort;
			SOCKS_TYPE socksType = UProxy->type == PROXY_TYPE_SOCKS5_WITH_UDP ? SOCKS_TYPE_UDP_ASSOCIATE : SOCKS_TYPE_CONNECT;

			switch (UProxy->stage) {
				case UPROXY_STAGE_INITIAL_PACKET: {
					EVTYPE_CASE(EV_TYPE_CONNECT);

					SOCKS5(0, NULL, UProxy, NULL);
					Log(LOG_LEVEL_DEBUG, "SOCKS5 advance to stage 1");
					UProxy->stage = UPROXY_STAGE_INITIAL_RESPONSE;
					break;
				}
				case UPROXY_STAGE_INITIAL_RESPONSE: {
					EVTYPE_CASE(EV_TYPE_READ);

					if (SOCKS5(0, NULL, UProxy, NULL)) {
						Log(LOG_LEVEL_DEBUG, "SOCKS5 advance to stage 2");
						
						Log(LOG_LEVEL_DEBUG, "UPROXY_STAGE_INITIAL_RESPONSE: UProxy->pageTarget != NULL: %s", UProxy->pageTarget != NULL ? "true" : "false");
						Log(LOG_LEVEL_DEBUG, "!SOCKS5ResolveDomainsRemotely: %s", !SOCKS5ResolveDomainsRemotely ? "true" : "false");
						Log(LOG_LEVEL_DEBUG, "UProxy->targetIPv4 == NULL: %s", UProxy->targetIPv4 == NULL ? "true" : "false");
						Log(LOG_LEVEL_DEBUG, "UProxy->targetIPv6 == NULL: %s", UProxy->targetIPv6 == NULL ? "true" : "false");
						/* 
						 * IPv4 and IPv6 null check for if when contacted SOCKS5 proxy rejected first IP type and system re-requests with other one.
						 * In this case targetIPv4 or targetIPv6 will be already filled in.
						 */
						if (UProxy->pageTarget != NULL && !SOCKS5ResolveDomainsRemotely && UProxy->targetIPv4 == NULL && UProxy->targetIPv6 == NULL) {
							char *domain = ProxyParseUrl(UProxy, false, false, NULL); {
								if (domain == NULL) {
									Log(LOG_LEVEL_DEBUG, "SOCKS5 stage 2 domain NULL");
									goto fail;
								}

								UProxy->stage = UPROXY_STAGE_SOCKS5_DNS_RESOLVE;
								ProxyDNSResolve(UProxy, domain);
								Log(LOG_LEVEL_DEBUG, "SOCKS5 stage 2 pending resolve");
							} free(domain);
							
							Log(LOG_LEVEL_DEBUG, "PROCESSING UNLOCK!2");
							pthread_mutex_unlock(&(UProxy->processing));
							return;
						} else
							UProxy->stage = UPROXY_STAGE_SOCKS5_MAIN_PACKET;
						
						Log(LOG_LEVEL_DEBUG, "UPROXY_STAGE_SOCKS5_MAIN_PACKET: UProxy->pageTarget != NULL: %s", UProxy->pageTarget != NULL ? "true" : "false");
						Log(LOG_LEVEL_DEBUG, "SOCKS5ResolveDomainsRemotely: %s", SOCKS5ResolveDomainsRemotely ? "true" : "false");
						// Case described above in comments doesn't happen if domains are resolved remotely
						if (UProxy->pageTarget != NULL && SOCKS5ResolveDomainsRemotely) {
							char *domain = ProxyParseUrl(UProxy, false, false, NULL); {
								if (domain == NULL) {
									Log(LOG_LEVEL_DEBUG, "SOCKS5 stage 2 domain 2 NULL");
									goto fail;
								}
								
								SOCKS5(socksType, &port, UProxy, domain);
							} free(domain);
						} else
							SOCKS5(socksType, &port, UProxy, NULL);
						UProxy->stage = UPROXY_STAGE_SOCKS5_RESPONSE;
						
						Log(LOG_LEVEL_DEBUG, "SOCKS5 advance to stage 3");

						// This handles two stages because after first stage, there's no one to send packet after receiving response
					} else
						goto fail;
					break;
				}
				case UPROXY_STAGE_SOCKS5_DNS_RESOLVE: {
					EVTYPE_CASE(EV_TYPE_CONNECT);

					Log(LOG_LEVEL_DEBUG, "SOCKS5 DNS stage");

					if (UProxy->pageTarget == NULL)
						goto fail;

					if (UProxy->targetIPv4 == NULL && UProxy->targetIPv6 == NULL) {
						Log(LOG_LEVEL_DEBUG, "SOCKS5 couldn't resolve domain");
						goto fail;
					}
					
					// Execute stage 2 ending after DNS resolve
					SOCKS5(socksType, &port, UProxy, NULL);
					Log(LOG_LEVEL_DEBUG, "SOCKS5 advance to stage 3 (DNS)");
					UProxy->stage = UPROXY_STAGE_SOCKS5_RESPONSE;
					break;
				}
				case UPROXY_STAGE_SOCKS5_RESPONSE: {
					EVTYPE_CASE(EV_TYPE_READ);

					size_t socksRet = SOCKS5(socksType, &port, UProxy, NULL);
					if (socksRet == 1) {
						if (UProxy->type == PROXY_TYPE_SOCKS5_WITH_UDP) {
							Log(LOG_LEVEL_DEBUG, "SOCKS5 advance to stage UDP");
							UProxy->stage = UPROXY_STAGE_HTTP_RESPONSE;

							int hSock;

							UProxy->requestTimeHttpMs = GetUnixTimestampMilliseconds();

							if ((hSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) != -1) {
								Log(LOG_LEVEL_DEBUG, "UDP socket");
								IP_TYPE ipType = GetIPType(UProxy->ip); // Preffered
								if (ipType == IPV4 && UProxy->targetIPv4 == NULL)
									ipType = IPV6;
								if (ipType == IPV6 && UProxy->targetIPv6 == NULL)
									ipType = IPV4;
								// -> Real

								Log(LOG_LEVEL_DEBUG, "UDP IP Type %d", ipType);

								uint8_t *buff = malloc(PROXY_IDENTIFIER_LEN + 6 + (ipType == IPV4 ? IPV4_SIZE : IPV6_SIZE)); {
									buff[0] = 0x00;
									buff[1] = 0x00;
									buff[2] = 0x00;
									buff[3] = ipType == IPV4 ? 0x01 : 0x04;
									memcpy(&(buff[4]), ipType == IPV4 ? &(UProxy->targetIPv4->Data[3]) : UProxy->targetIPv6->Data, ipType == IPV4 ? IPV4_SIZE : IPV6_SIZE);
									*((uint16_t*)&(buff[4 + (ipType == IPV4 ? IPV4_SIZE : IPV6_SIZE)])) = htons(ServerPortUDP);
									memcpy(&(buff[6 + (ipType == IPV4 ? IPV4_SIZE : IPV6_SIZE)]), UProxy->identifier, PROXY_IDENTIFIER_LEN);

									Log(LOG_LEVEL_DEBUG, "UDP buff construct");
									struct sockaddr *sa = IPv6MapToRaw(UProxy->ip, port); {
										if (sendto(hSock, buff, PROXY_IDENTIFIER_LEN + 6 + (ipType == IPV4 ? IPV4_SIZE : IPV6_SIZE), 0, sa, GetIPType(UProxy->ip) == IPV4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) == -1) {
											Log(LOG_LEVEL_DEBUG, "UDP send fail");
											free(sa);
											close(hSock);
											free(buff);
											goto fail;
										}
										Log(LOG_LEVEL_DEBUG, "UDP sent ;)");
									} free(sa);
								} free(buff);

								if (UProxy->pageTarget != NULL) {
									Log(LOG_LEVEL_DEBUG, "Waiting for UDP response...");
									UProxy->udpRead = event_new(levRequestBase, hSock, EV_READ | EV_PERSIST, (event_callback_fn)EVRead, UProxy);
									event_add(UProxy->udpRead, NULL);
								} else
									close(hSock);
							}
						} else {
							Log(LOG_LEVEL_DEBUG, "SOCKS5 stage 3");
							UProxy->stage = ((UProxy->targetPort == HTTPS_DEFAULT_PORT && UProxy->pageTarget != NULL) || ProxyIsSSL(UProxy->type)) ? UPROXY_STAGE_SSL_HANDSHAKE : UPROXY_STAGE_HTTP_REQUEST;
							Log(LOG_LEVEL_DEBUG, "SOCKS5 advance to stage %d (%s)", UProxy->stage, UProxy->stage == UPROXY_STAGE_SSL_HANDSHAKE ? "SSL" : "HTTP");
						}
					} else if (socksRet == SOCKS5_RET_STATUS_IPV4_FAILED || socksRet == SOCKS5_RET_STATUS_IPV6_FAILED) {
						/*
						 * Recoverable failure. This may happen when a IPv6/4 address is fed to SOCKS5 proxy but it doesn't support it.
						 * Wait for IPv4/6 and request again.
						 */
						Log(LOG_LEVEL_DEBUG, "SOCKS5 ip recoverable failure %s", socksRet == SOCKS5_RET_STATUS_IPV6_FAILED ? "SOCKS5_RET_STATUS_IPV6_FAILED" : "SOCKS5_RET_STATUS_IPV4_FAILED");
						Log(LOG_LEVEL_DEBUG, "SOCKS5 ip recoverable failure lookups %d", UProxy->dnsLookupsCount);
						Log(LOG_LEVEL_DEBUG, "SOCKS5 ip recoverable failure lookups IPv4 %p", UProxy->targetIPv4);
						Log(LOG_LEVEL_DEBUG, "SOCKS5 ip recoverable failure lookups IPv6 %p", UProxy->targetIPv6);
					
						
						// Empty the failed target so that system wouldn't try to pass it to SOCKS5 proxy again
						if (socksRet == SOCKS5_RET_STATUS_IPV6_FAILED)
							UProxy->targetIPv6 = NULL;
						else
							UProxy->targetIPv4 = NULL;
						
						Log(LOG_LEVEL_DEBUG, "SOCKS5 ip recoverable failure lookups IPv4 %p", UProxy->targetIPv4);
						Log(LOG_LEVEL_DEBUG, "SOCKS5 ip recoverable failure lookups IPv6 %p", UProxy->targetIPv6);
						
						// Find any existing lookups
						ssize_t fLookup = -1;
						for (size_t x = 0; x < UProxy->dnsLookupsCount; x++) {
							if ((!UProxy->dnsLookups[x]->ipv6 && socksRet == SOCKS5_RET_STATUS_IPV6_FAILED) ||
								(UProxy->dnsLookups[x]->ipv6 && socksRet == SOCKS5_RET_STATUS_IPV4_FAILED))
								fLookup = x;
						}
						
						if (fLookup == -1 && UProxy->targetIPv4 == NULL && UProxy->targetIPv6 == NULL) {
							Log(LOG_LEVEL_DEBUG, "SOCKS5 ip recoverable failure just became unrecoverable");
							// Screwed
							goto fail;
						}
						
						// Duplicate uproxy
						IPv6Map *prxIp = malloc(sizeof(IPv6Map));
						memcpy(prxIp, UProxy->ip, sizeof(IPv6Map));
						UNCHECKED_PROXY *newProxy = AllocUProxy(prxIp, UProxy->port, UProxy->type, NULL, UProxy->associatedProxy);
						newProxy->targetPort = UProxy->targetPort;
						
						DNS_LOOKUP_ASYNC_EX *curLookup = NULL;
						
						if (fLookup != -1) {
							Log(LOG_LEVEL_DEBUG, "SOCKS5 ip recoverable failure lookups fLookup != -1");
							curLookup = UProxy->dnsLookups[fLookup];
						
							pthread_mutex_lock(&(curLookup->preDoneLock));
						} else {
							Log(LOG_LEVEL_DEBUG, "SOCKS5 ip recoverable failure lookups socksRet %s", socksRet == SOCKS5_RET_STATUS_IPV6_FAILED ? "SOCKS5_RET_STATUS_IPV6_FAILED" : "SOCKS5_RET_STATUS_IPV4_FAILED");
							
							if (socksRet == SOCKS5_RET_STATUS_IPV6_FAILED) {
								newProxy->targetIPv4 = zalloc(sizeof(IPv6Map));
								memcpy(newProxy->targetIPv4, UProxy->targetIPv4, sizeof(IPv6Map));
								Log(LOG_LEVEL_DEBUG, "SOCKS5 ip recoverable failure lookups copied IPv4");
							} else {
								newProxy->targetIPv6 = malloc(sizeof(IPv6Map));
								memcpy(newProxy->targetIPv6, UProxy->targetIPv6, sizeof(IPv6Map));
								Log(LOG_LEVEL_DEBUG, "SOCKS5 ip recoverable failure copied IPv6");
							}
						}
								
						if (UProxy->pageTarget != NULL) {
							newProxy->pageTarget = malloc(strlen(UProxy->pageTarget) + 1);
							strcpy(newProxy->pageTarget, UProxy->pageTarget);
						}
								
						newProxy->getResponse = UProxy->getResponse;
						newProxy->singleCheckCallback = UProxy->singleCheckCallback;
						newProxy->singleCheckCallbackExtraData = UProxy->singleCheckCallbackExtraData;
								
						if (UProxy->targetIPv6 != NULL || UProxy->targetIPv4 != NULL) {
							// New proxy will have already resolved IPv4/6
							UProxyAdd(newProxy);
							RequestAsync(newProxy);
							Log(LOG_LEVEL_DEBUG, "SOCKS5 ip recoverable failure lookups added new proxy");
						} else {
							// Scoop out current DNS lookup from the array so ProxyFree doesn't free it
							UProxy->dnsLookupsCount--;
							if (UProxy->dnsLookupsCount > 0) {
								UProxy->dnsLookups[fLookup] = UProxy->dnsLookups[UProxy->dnsLookupsCount];
							} else {
								free(UProxy->dnsLookups);
								UProxy->dnsLookups = NULL;
							}
							
							curLookup->object = newProxy;
							curLookup->fxDone = ProxyDNSReResolved;
							Log(LOG_LEVEL_DEBUG, "SOCKS5 ip recoverable failure redirected fxDone callback");
						}
						
						if (fLookup != -1) {
							Log(LOG_LEVEL_DEBUG, "UNLOCK preDoneLock!!!");
							pthread_mutex_unlock(&(curLookup->preDoneLock));
						}
						
						UProxy->getResponse = false; // Prevent CPage final stage from being launched as if UProxy failed
						goto fail; // Free old proxy silently
					} else
						goto fail;
					
					break;
				}
				default: {
					assert(false);
					break;
				}
			}
			break;
		}
	}

	switch (UProxy->stage) {
		case UPROXY_STAGE_SSL_HANDSHAKE: {
			struct evbuffer *buff = bufferevent_get_input(UProxy->assocBufferEvent);
			evbuffer_drain(buff, evbuffer_get_length(buff));
			Log(LOG_LEVEL_DEBUG, "Establishing SSL connection...");
			// Begin REAL SSL

			struct bufferevent *sslBuffEvent;
			sslBuffEvent = bufferevent_openssl_socket_new(levRequestBase, bufferevent_getfd(UProxy->assocBufferEvent), SSL_new(RequestBaseSSLCTX), BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
			bufferevent_setfd(UProxy->assocBufferEvent, -1);
			bufferevent_free(UProxy->assocBufferEvent);
			UProxy->assocBufferEvent = sslBuffEvent;

			if (UProxy->assocBufferEvent != NULL) {
				bufferevent_setcb(UProxy->assocBufferEvent, (bufferevent_data_cb)EVRead, (bufferevent_data_cb)EVWrite, (bufferevent_event_cb)EVEvent, UProxy);
				bufferevent_enable(UProxy->assocBufferEvent, EV_READ | EV_WRITE);
			} else {
				Log(LOG_LEVEL_DEBUG, "SSL BuffEvent fail");
				goto fail;
			}
			
			UProxy->stage = UPROXY_STAGE_HTTP_REQUEST;
			Log(LOG_LEVEL_DEBUG, "-> UPROXY_STAGE_HTTP_REQUEST");
			
			break;
		}
		case UPROXY_STAGE_HTTP_REQUEST: {
			EVTYPE_CASE_NOT(EV_TYPE_WRITE);

			if ((UProxy->targetPort == HTTPS_DEFAULT_PORT && UProxy->pageTarget != NULL) || ProxyIsSSL(UProxy->type)) {
				// SSL
				SSL *ssl = bufferevent_openssl_get_ssl(UProxy->assocBufferEvent);
				X509 *cert = SSL_get_peer_certificate(ssl); {
					uint8_t hash[EVP_MAX_MD_SIZE];
					unsigned int trash;

					X509_digest(cert, EVP_sha512(), hash, &trash);

					if (!MemEqual(hash, SSLFingerPrint, 512 / 8 /* SHA-512 */))
						UProxy->invalidCert = X509_dup(cert);
					else
						UProxy->invalidCert = NULL;
				} X509_free(cert);
			}
			else
				UProxy->invalidCert = NULL;
			
			Log(LOG_LEVEL_DEBUG, "UPROXY_STAGE_HTTP_REQUEST");

			UProxy->requestTimeHttpMs = GetUnixTimestampMilliseconds();
			Log(LOG_LEVEL_DEBUG, "Sending HTTP request");
			char *key;
			Base64Encode(UProxy->identifier, PROXY_IDENTIFIER_LEN, &key); {
				Log(LOG_LEVEL_DEBUG, "Page target: %s", UProxy->pageTarget);
				if (UProxy->pageTargetPostData != NULL) {
					Log(LOG_LEVEL_DEBUG, "Page target POST data: %s", UProxy->pageTargetPostData);
				}

				if (UProxy->pageTarget == NULL) {
					char *host = GetHost(GetIPType(UProxy->ip), ProxyIsSSL(UProxy->type));

					reqString = StrReplaceToNew(RequestString, "{HOST}", host);
					StrReplaceOrig(&reqString, "{PAGE_PATH}", "/prxchk");
				} else {
					char *path;
					char *domain = ProxyParseUrl(UProxy, true, true, &path); {
						if (domain == NULL) {
							free(key);
							goto fail;
						}

						if (UProxy->pageTargetPostData != NULL) {
							reqString = StrReplaceToNew(POSTRequestString, "{HOST}", domain);

							if (strlen(UProxy->pageTargetPostData) < 1) {
								// ??? TODO:
								free(domain);
								free(key);
								goto fail;
							}

							char *lenStr = malloc(INTEGER_VISIBLE_SIZE(strlen(UProxy->pageTargetPostData))); {
								sprintf(lenStr, "%zu", strlen(UProxy->pageTargetPostData));
								if (!StrReplaceOrig(&reqString, "{DATA_LEN}", lenStr)) {
									free(key);
									free(lenStr);
									free(domain);
									goto fail;
								}
							} free(lenStr);

							if (!StrReplaceOrig(&reqString, "{POST_DATA}", UProxy->pageTargetPostData)) {
								free(key);
								free(domain);
								goto fail;
							}
						} else
							reqString = StrReplaceToNew(RequestString, "{HOST}", domain);
						//StrReplaceOrig(&reqString, "{PAGE_PATH}", path == NULL ? "/" : path);
						StrReplaceOrig(&reqString, "{PAGE_PATH}", UProxy->pageTarget);
					} free(domain);
					if (path != NULL)
						free(path);
				}
				if (strstr(reqString, "{KEY_VAL}") != NULL)
					StrReplaceOrig(&reqString, "{KEY_VAL}", key);
				else {
					free(key);
					goto fail;
				}
			} free(key);

			Log(LOG_LEVEL_DEBUG, "ReqString:");
			Log(LOG_LEVEL_DEBUG, reqString);

			bufferevent_write(UProxy->assocBufferEvent, (void*)reqString, strlen(reqString));
			free(reqString);
			UProxy->stage = UPROXY_STAGE_HTTP_RESPONSE;
			Log(LOG_LEVEL_DEBUG, "Advance to stage 8 (final)");
			break;
		}
		case UPROXY_STAGE_HTTP_RESPONSE:
		case UPROXY_STAGE_HTTP_DDL_PAGE:
		{
			EVTYPE_CASE(EV_TYPE_READ);

			UProxy->checkSuccess = true;
			
			Log(LOG_LEVEL_DEBUG, "Stage 7 / 8 len %d", evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent)));

			if (UProxy->pageTarget != NULL && UProxy->getResponse) {
				if (evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent)) == 0) {
					Log(LOG_LEVEL_DEBUG, "ProxyHandleData stage 8 / 9 DROP");
					
					Log(LOG_LEVEL_DEBUG, "PROCESSING UNLOCK!3");
					pthread_mutex_unlock(&(UProxy->processing));
					return;
				}
				// ????

#if DEBUG
				char testBuff[evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent))];
				evbuffer_copyout(bufferevent_get_input(UProxy->assocBufferEvent), &testBuff, evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent)));
				Log(LOG_LEVEL_DEBUG, "In buffer: %s (%d)", testBuff, evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent)));
#endif
				((SingleCheckCallbackCPage)UProxy->singleCheckCallback)(UProxy, UProxy->stage == UPROXY_STAGE_HTTP_RESPONSE ? UPROXY_CUSTOM_PAGE_STAGE_INITIAL_PACKET : UPROXY_CUSTOM_PAGE_STAGE_DDL_PAGE);
				UProxy->stage = UPROXY_STAGE_HTTP_DDL_PAGE;
				// EOF is called out as an error to RequestFree
			}
			default: {
				assert(false);
				break;
			}
		}
	}

	Log(LOG_LEVEL_DEBUG, "PROCESSING UNLOCK!FINAL");
	pthread_mutex_unlock(&(UProxy->processing));
	
#undef EVTYPE_CASE
#undef EVTYPE_CASE_NOT

	return;
fail:
	Log(LOG_LEVEL_DEBUG, "ProxyHandleData failure Proxy %s at stage %d", ProxyGetTypeString(UProxy->type), UProxy->stage);
	bufferevent_setcb(UProxy->assocBufferEvent, NULL, NULL, NULL, NULL);
	if (UProxy->timeout != NULL)
		event_active(UProxy->timeout, EV_TIMEOUT, 0);
	
	Log(LOG_LEVEL_DEBUG, "PROCESSING UNLOCK!FAIL FINAL");
	pthread_mutex_unlock(&(UProxy->processing));
}

void EVEvent(struct bufferevent *BuffEvent, uint16_t Event, UNCHECKED_PROXY *UProxy)
{
	//Log(LOG_LEVEL_DEBUG, "EVEvent %02x", Event);

	if (Event == BEV_EVENT_EOF && UProxy->stage == UPROXY_STAGE_HTTP_DDL_PAGE)
		UProxy->checkSuccess = true;

	if (Event == BEV_EVENT_CONNECTED) {
		//char *ip = IPv6MapToString(UProxy->ip); {
			//Log(LOG_LEVEL_DEBUG, "EVEvent: event connected %s (size %d)", ip, SizeUncheckedProxies);
		//} free(ip);

		ProxyHandleData(UProxy, EV_TYPE_CONNECT);
	} else {
		//if ((UProxy->targetPort == HTTPS_DEFAULT_PORT && UProxy->pageTarget != NULL) || ProxyIsSSL(UProxy->type))
			//Log(LOG_LEVEL_DEBUG, "SSL stage %d error %02x -> %d", UProxy->stage, Event, bufferevent_get_openssl_error(BuffEvent));

#if DEBUG
		//char *ip = IPv6MapToString(UProxy->ip); {
			//Log(LOG_LEVEL_DEBUG, "EVEvent: event timeout / fail %s", ip);
		//} free(ip);
		//Log(LOG_LEVEL_DEBUG, "EVEvent: BuffEvent: %08x event %02x", BuffEvent, Event);
#endif
		RequestFree(bufferevent_getfd(BuffEvent), Event, UProxy);
	}
}

void EVRead(struct bufferevent *BuffEvent, UNCHECKED_PROXY *UProxy)
{
	ProxyHandleData(UProxy, EV_TYPE_READ);
}

void EVWrite(struct bufferevent *BuffEvent, UNCHECKED_PROXY *UProxy)
{
	ProxyHandleData(UProxy, EV_TYPE_WRITE);
}

void RequestAsync(UNCHECKED_PROXY *UProxy)
{
	struct sockaddr *sa = IPv6MapToRaw(UProxy->ip, UProxy->port);

#if DEBUG
	char *ip = IPv6MapToString(UProxy->ip); {
		Log(LOG_LEVEL_DEBUG, "RequestAsync: [%s]:%d", ip, UProxy->port);
		if (GetIPType(UProxy->ip) == IPV4) {
			char *asd = calloc(1, 64 /* whatever */); {
				inet_ntop(AF_INET, &(((struct sockaddr_in*)sa)->sin_addr), asd, INET_ADDRSTRLEN);
				Log(LOG_LEVEL_DEBUG, "RequestAsync 2: [%s]:%d", asd, ntohs(((struct sockaddr_in*)sa)->sin_port));
			} free(asd);
		} else {
			char *asd = calloc(1, 64 /* whatever */); {
				inet_ntop(AF_INET6, &(((struct sockaddr_in6*)sa)->sin6_addr), asd, INET6_ADDRSTRLEN);
				Log(LOG_LEVEL_DEBUG, "RequestAsync 2: [%s]:%d", asd, ntohs(((struct sockaddr_in6*)sa)->sin6_port));
			} free(asd);
		}
	} free(ip);
#endif

	UProxy->assocBufferEvent = bufferevent_socket_new(levRequestBase, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);

	Log(LOG_LEVEL_DEBUG, "RequestAsync: new socket");

	//bufferevent_set_timeouts(UProxy->assocBufferEvent, &GlobalTimeoutTV, &GlobalTimeoutTV);
	bufferevent_setcb(UProxy->assocBufferEvent, (bufferevent_data_cb)EVRead, (bufferevent_data_cb)EVWrite, (bufferevent_event_cb)EVEvent, UProxy);
	bufferevent_enable(UProxy->assocBufferEvent, EV_READ | EV_WRITE);

	UProxy->requestTimeMs = GetUnixTimestampMilliseconds();
	Log(LOG_LEVEL_DEBUG, "RequestAsync: UProxy request time: %llu", UProxy->requestTimeMs);

	InterlockedIncrement(&CurrentlyChecking);

	if (UProxy->timeout == NULL) {
		UProxy->timeout = event_new(levRequestBase, -1, EV_TIMEOUT, (event_callback_fn)RequestFree, UProxy);
		event_add(UProxy->timeout, &GlobalTimeoutTV);
	}

	UProxy->checking = true;
	bufferevent_socket_connect(UProxy->assocBufferEvent, sa, sizeof(struct sockaddr_in6)); // socket creation should never fail, because IP is always valid (but != dead)
	free(sa);
}

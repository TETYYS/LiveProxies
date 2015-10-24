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
#include <assert.h>
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

static void RequestFree(evutil_socket_t fd, short what, UNCHECKED_PROXY *UProxy)
{
	Log(LOG_LEVEL_DEBUG, "RequestFree BuffEvent free %p", UProxy->assocBufferEvent);

	bufferevent_free(UProxy->assocBufferEvent);

	if (UProxy->timeout != NULL) {
		event_del(UProxy->timeout);
		event_free(UProxy->timeout);
		UProxy->timeout = NULL;
	} else
		assert(false);

	if (UProxy->udpRead != NULL) {
		event_del(UProxy->udpRead);
		event_free(UProxy->udpRead);
		UProxy->udpRead = NULL;
	}

	char *ip = IPv6MapToString(UProxy->ip); {
		Log(LOG_LEVEL_DEBUG, "RequestFree -> %s", ip);
	} free(ip);

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
		} else
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
		char buff[1 + 1 + sizeof(uint16_t) + IPV4_SIZE + 1 /* ? */];
		buff[0] = 0x04;
		buff[1] = 0x01; // CONNECT
		*((uint16_t*)(&(buff[2]))) = htons(UProxy->targetPort);
		*((uint32_t*)(&(buff[4]))) = htonl(UProxy->targetIPv4->Data[3]);
		buff[8] = 0x00;

		bufferevent_write(UProxy->assocBufferEvent, buff, 9);
		bufferevent_setwatermark(UProxy->assocBufferEvent, EV_READ, 8, 0);
	} else if (UProxy->stage == UPROXY_STAGE_INITIAL_RESPONSE) {
		size_t len = evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent));
		uint8_t data[2];
		if (len != 8)
			return false;

		evbuffer_remove(bufferevent_get_input(UProxy->assocBufferEvent), data, 2);
		Log(LOG_LEVEL_DEBUG, "SOCKS4: Stage 2 data[1]: %d", data[1]);
		return data[1] == 0x5A;
	}
}

static bool SOCKS5(SOCKS_TYPE Type, uint16_t *Port, UNCHECKED_PROXY *UProxy)
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
			break;
		}
		case UPROXY_STAGE_SOCKS5_MAIN_PACKET:
		{
			IP_TYPE ipType = GetIPType(UProxy->ip); // Prefered

			if (ipType == IPV4 && UProxy->targetIPv4 == NULL)
				ipType = IPV6;
			if (ipType == IPV6 && UProxy->targetIPv6 == NULL)
				ipType = IPV4;
			// -> Real

			uint8_t *buff;
			if (ipType == IPV4) {
				Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 2 IPV4");
				uint8_t tBuff[4 + IPV4_SIZE + sizeof(uint16_t)];
				buff = tBuff;
			} else {
				Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 2 IPV6");
				uint8_t tBuff[4 + IPV6_SIZE + sizeof(uint16_t)];
				buff = tBuff;
			}
			buff[0] = 0x05; // again?
			buff[1] = Type;
			buff[2] = 0x00; // RESERVED
			buff[3] = ipType == IPV4 ? 0x01 : 0x04; // who was 0x02?
			if (ipType == IPV4)
				(*(uint32_t*)(&(buff[4]))) = UProxy->targetIPv4->Data[3];
			else
				memcpy(&(buff[4]), UProxy->targetIPv6->Data, IPV6_SIZE);
			*((uint16_t*)&(buff[4 + (ipType == IPV4 ? IPV4_SIZE : IPV6_SIZE)])) = Type != SOCKS_TYPE_UDP_ASSOCIATE ? htons(*Port) : 0;

			bufferevent_write(UProxy->assocBufferEvent, buff, 4 + (ipType == IPV4 ? IPV4_SIZE : IPV6_SIZE) + sizeof(uint16_t));
			bufferevent_setwatermark(UProxy->assocBufferEvent, EV_READ, 10, 0);
			break;
		}
		case UPROXY_STAGE_SOCKS5_RESPONSE:
		{
			bufferevent_setwatermark(UProxy->assocBufferEvent, EV_READ, 1, 0);
			size_t len = evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent));
			uint8_t data[10];
			Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 3 data len: %d", len);
			if (len < 10)
				return false;

			evbuffer_remove(bufferevent_get_input(UProxy->assocBufferEvent), data, 10);

			Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 3 data[1]: %d", data[1]);
			Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 3 port: %d", ntohs(*((uint16_t*)&(data[8]))));
			*Port = ntohs(*((uint16_t*)&(data[8])));

			Log(LOG_LEVEL_DEBUG, "data[1] %x", data[1]);

			return data[1] == 0x00;
			break;
		}
	}
	return true;
}

//void ProxyDNSResolved(int Err, struct evutil_addrinfo *Addr, UNCHECKED_PROXY *UProxy)
void ProxyDNSResolved(struct dns_cb_data *data)
{
	DNS_LOOKUP_ASYNC_EX *ex = (DNS_LOOKUP_ASYNC_EX*)data->context;
	UNCHECKED_PROXY *UProxy = (UNCHECKED_PROXY*)ex->object;

	if (data->addr_len <= 0) {
		bufferevent_setcb(UProxy->assocBufferEvent, NULL, NULL, NULL, NULL);
		if (UProxy->timeout != NULL)
			event_active(UProxy->timeout, EV_TIMEOUT, 0);
		if (data->error != DNS_DOES_NOT_EXIST)
			Log(LOG_LEVEL_WARNING, "Failed to lookup CPage DNS");

		ex->resolveDone = true;

		return;
	} else {
		if (data->query_type == DNS_RR_TYPE_A && UProxy->targetIPv4 == NULL) {
			assert(data->addr_len == IPV4_SIZE);

			UProxy->targetIPv4 = zalloc(sizeof(IPv6Map));
			memcpy(&(UProxy->targetIPv4->Data[3]), data->addr, IPV4_SIZE);
			UProxy->targetIPv4->Data[2] = 0xFFFF0000;

#if DEBUG
			char *ip = IPv6MapToString2(UProxy->targetIPv4); {
				Log(LOG_LEVEL_DEBUG, "ProxyDNSResolved IPv4 %s", ip);
			} free(ip);
#endif
		}
		if (data->query_type == DNS_RR_TYPE_AAAA && UProxy->targetIPv6 == NULL) {
			assert(data->addr_len == IPV6_SIZE);

			UProxy->targetIPv6 = malloc(sizeof(IPv6Map));
			memcpy(UProxy->targetIPv6->Data, data->addr, IPV6_SIZE);

#if DEBUG
			char *ip = IPv6MapToString2(UProxy->targetIPv6); {
				Log(LOG_LEVEL_DEBUG, "ProxyDNSResolved IPv6 %s", ip);
			} free(ip);
#endif
		}

		Log(LOG_LEVEL_DEBUG, "ProxyDNSResolved -> ProxyHandleData CONNECT");
		ProxyHandleData(UProxy, EV_TYPE_CONNECT);

		ex->resolveDone = true;
	}
}

static void ProxyDNSResolve(UNCHECKED_PROXY *UProxy, char *Domain)
{
	if (UProxy->pageTarget == NULL)
		return;

	DNSResolveAsync(UProxy, Domain, false, ProxyDNSResolved);
	DNSResolveAsync(UProxy, Domain, true, ProxyDNSResolved);
}

int sslCreated2 = 0;
size_t bts = 0;

static MEM_OUT char *ProxyParseUrl(UNCHECKED_PROXY *UProxy, bool OnlyDomain, bool IncludePort, OUT char **Path)
{
	char *domain;

	if (strstr(UProxy->pageTarget, "https://") == NULL && strstr(UProxy->pageTarget, "http://") == NULL && strstr(UProxy->pageTarget, "udp://") == NULL)
		return NULL;

	if (strncmp(UProxy->pageTarget, "https", 5) == 0) {
		domain = strdup(UProxy->pageTarget + (8 * sizeof(char)));
	} else if (strncmp(UProxy->pageTarget, "http", 4) == 0)
		domain = strdup(UProxy->pageTarget + (7 * sizeof(char)));
	else
		domain = strdup(UProxy->pageTarget + (6 * sizeof(char)));

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
	//Log(LOG_LEVEL_DEBUG, "ProxyHandleData: Proxy %s (%d), stage %d", ProxyGetTypeString(UProxy->type), UProxy->type, UProxy->stage);
	char *reqString;
#define EVTYPE_CASE(x) if (EVType != x) return;
#define EVTYPE_CASE_NOT(x) if (EVType == x) return;

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
						char *host = GetHost(GetIPType(UProxy->ip), ProxyIsSSL(UProxy->type));
						Log(LOG_LEVEL_DEBUG, "Proxy type HTTPS target const host %s", host);

						reqString = StrReplaceToNew(RequestStringSSL, "{HOST}", host); {
							if (strstr(reqString, "{KEY_VAL}") != NULL) {
								char *key;
								size_t key64Len = Base64Encode(UProxy->identifier, PROXY_IDENTIFIER_LEN, &key); {
									StrReplaceOrig(&reqString, "{KEY_VAL}", key);
								} free(key);
							}

							Log(LOG_LEVEL_DEBUG, "HTTPS ReqString:");
							Log(LOG_LEVEL_DEBUG, reqString);

							bufferevent_write(UProxy->assocBufferEvent, (void*)reqString, strlen(reqString) * sizeof(char));
						} free(reqString);
					} else {
						Log(LOG_LEVEL_DEBUG, "Proxy type HTTPS target page");
						char *domain = ProxyParseUrl(UProxy, true, true, NULL); {
							if (domain == NULL)
								goto fail;

							reqString = StrReplaceToNew(RequestStringSSL, "{HOST}", domain);
							if (strstr(reqString, "{KEY_VAL}") != NULL) {
								char *key;
								size_t key64Len = Base64Encode(UProxy->identifier, PROXY_IDENTIFIER_LEN, &key); {
									StrReplaceOrig(&reqString, "{KEY_VAL}", key);
								} free(key);
							}
							Log(LOG_LEVEL_DEBUG, "Proxy type HTTPS target page domain", domain);
						} free(domain);

						Log(LOG_LEVEL_DEBUG, "HTTPS ReqString:");
						Log(LOG_LEVEL_DEBUG, reqString);

						bufferevent_write(UProxy->assocBufferEvent, (void*)reqString, strlen(reqString) * sizeof(char));
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
			}
			break;
		}
		case PROXY_TYPE_SOCKS5:
		case PROXY_TYPE_SOCKS5_TO_SSL:
		case PROXY_TYPE_SOCKS5_WITH_UDP: {
			uint16_t port = UProxy->targetPort;
			SOCKS_TYPE socksType = UProxy->type == PROXY_TYPE_SOCKS5_WITH_UDP ? SOCKS_TYPE_UDP_ASSOCIATE : SOCKS_TYPE_CONNECT;

			Log(LOG_LEVEL_DEBUG, "SOCKS5 port %d", port);

			switch (UProxy->stage) {
				case UPROXY_STAGE_INITIAL_PACKET: {
					EVTYPE_CASE(EV_TYPE_CONNECT);

					SOCKS5(0, NULL, UProxy);
					Log(LOG_LEVEL_DEBUG, "SOCKS5 advance to stage 1");
					UProxy->stage = UPROXY_STAGE_INITIAL_RESPONSE;
					break;
				}
				case UPROXY_STAGE_INITIAL_RESPONSE: {
					EVTYPE_CASE(EV_TYPE_READ);

					if (SOCKS5(0, NULL, UProxy)) {
						Log(LOG_LEVEL_DEBUG, "SOCKS5 advance to stage 2");
						UProxy->stage = UPROXY_STAGE_SOCKS5_MAIN_PACKET;
						if (UProxy->pageTarget != NULL) {
							char *domain = ProxyParseUrl(UProxy, false, false, NULL); {
								if (domain == NULL) {
									Log(LOG_LEVEL_DEBUG, "SOCKS5 stage 2 domain NULL");
									goto fail;
								}

								assert(UProxy->targetIPv4 == NULL && UProxy->targetIPv6 == NULL);
								UProxy->stage = UPROXY_STAGE_SOCKS5_DNS_RESOLVE;
								ProxyDNSResolve(UProxy, domain);
								Log(LOG_LEVEL_DEBUG, "SOCKS5 stage 2 pending resolve");
							} free(domain);
							return;
						}
						SOCKS5(socksType, &port, UProxy);
						Log(LOG_LEVEL_DEBUG, "SOCKS5 advance to stage 3");
						UProxy->stage = UPROXY_STAGE_SOCKS5_RESPONSE;

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

					assert(UProxy->targetIPv4 != NULL || UProxy->targetIPv6 != NULL);

					// Execute stage 2 ending after DNS resolve
					SOCKS5(socksType, &port, UProxy);
					Log(LOG_LEVEL_DEBUG, "SOCKS5 advance to stage 3 (DNS)");
					UProxy->stage = UPROXY_STAGE_SOCKS5_RESPONSE;
					break;
				}
				case UPROXY_STAGE_SOCKS5_RESPONSE: {
					EVTYPE_CASE(EV_TYPE_READ);

					if (SOCKS5(socksType, &port, UProxy)) {
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
					} else
						goto fail;
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
#if DEBUG
			struct bufferevent *test = UProxy->assocBufferEvent;
#endif

			UProxy->assocBufferEvent = bufferevent_openssl_filter_new(levRequestBase,
																	  UProxy->assocBufferEvent,
																	  SSL_new(RequestBaseSSLCTX),
																	  BUFFEREVENT_SSL_CONNECTING,
																	  BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
			Log(LOG_LEVEL_DEBUG, "SSL2 created %d", ++sslCreated2);
			bufferevent_openssl_set_allow_dirty_shutdown(UProxy->assocBufferEvent, false);

			if (UProxy->assocBufferEvent != NULL) {
#if DEBUG
				if (bufferevent_openssl_get_ssl(UProxy->assocBufferEvent) == NULL) {
					Log(LOG_LEVEL_DEBUG, "SSL2 NULL!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
				} else {
					Log(LOG_LEVEL_DEBUG, "SSL2 UNDERLYING! -> %p", bufferevent_get_underlying(UProxy->assocBufferEvent));
					if (bufferevent_get_underlying(UProxy->assocBufferEvent) == test)
						Log(LOG_LEVEL_DEBUG, "SSL2 UNDERLYING POSITIVE (y) -> %p vs %p", bufferevent_get_underlying(UProxy->assocBufferEvent), test);
					else
						Log(LOG_LEVEL_DEBUG, "SSL2 UNDERLYING NEGATIVE, WHAT'S GOING ON???? (y) -> %p vs %p", bufferevent_get_underlying(UProxy->assocBufferEvent), test);
				}
#endif
				bufferevent_setcb(UProxy->assocBufferEvent, (bufferevent_data_cb)EVRead, (bufferevent_data_cb)EVWrite, (bufferevent_event_cb)EVEvent, UProxy);
				bufferevent_set_timeouts(UProxy->assocBufferEvent, &GlobalTimeoutTV, &GlobalTimeoutTV);
				bufferevent_enable(UProxy->assocBufferEvent, EV_READ | EV_WRITE);
			} else {
				Log(LOG_LEVEL_DEBUG, "SSL BuffEvent fail");
				goto fail;
			}

			UProxy->stage = UPROXY_STAGE_HTTP_REQUEST;
			// SSL handshake brings up EVEvent connect so this falls to stage 7 later
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
			} else
				UProxy->invalidCert = NULL;

			UProxy->requestTimeHttpMs = GetUnixTimestampMilliseconds();
			Log(LOG_LEVEL_DEBUG, "Sending HTTP request");
			char *key;
			size_t key64Len = Base64Encode(UProxy->identifier, PROXY_IDENTIFIER_LEN, &key); {
				Log(LOG_LEVEL_DEBUG, "Page target: %s", UProxy->pageTarget);

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

						reqString = StrReplaceToNew(RequestString, "{HOST}", domain);
						StrReplaceOrig(&reqString, "{PAGE_PATH}", path == NULL ? "/" : path);
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

			bufferevent_write(UProxy->assocBufferEvent, (void*)reqString, strlen(reqString) * sizeof(char));
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

			//Log(LOG_LEVEL_DEBUG, "Stage 7 / 8 len %d", evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent)));

			if (UProxy->pageTarget != NULL) {
				if (evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent)) == 0) {
					Log(LOG_LEVEL_DEBUG, "ProxyHandleData stage 8 / 9 DROP");
					return;
				}
				// ????

#if DEBUG
				char testBuff[evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent))];
				evbuffer_copyout(bufferevent_get_input(UProxy->assocBufferEvent), &testBuff, evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent)));
				bts += evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent));
				Log(LOG_LEVEL_DEBUG, "BTS %d", bts);
				//Log(LOG_LEVEL_DEBUG, "In buffer: %s (%d)", testBuff, evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent)));
#endif
				pthread_mutex_lock(&(UProxy->processing));
				((SingleCheckCallbackCPage)(UProxy->singleCheckCallback))(UProxy, UProxy->stage == UPROXY_STAGE_HTTP_RESPONSE ? UPROXY_CUSTOM_PAGE_STAGE_INITIAL_PACKET : UPROXY_CUSTOM_PAGE_STAGE_DDL_PAGE);
				UProxy->stage = UPROXY_STAGE_HTTP_DDL_PAGE;
				// EOF is called out as an error to RequestFree

				/*if (UProxy->timeout != NULL)
					event_active(UProxy->timeout, EV_TIMEOUT, 0);*/
			}
		}
		break;
	}

#undef EVTYPE_CASE
#undef EVTYPE_CASE_NOT

	return;
fail:
	Log(LOG_LEVEL_DEBUG, "ProxyHandleData failure Proxy %s at stage %d", ProxyGetTypeString(UProxy->type), UProxy->stage);
	bufferevent_setcb(UProxy->assocBufferEvent, NULL, NULL, NULL, NULL);
	if (UProxy->timeout != NULL)
		event_active(UProxy->timeout, EV_TIMEOUT, 0);
}

void EVEvent(struct bufferevent *BuffEvent, uint16_t Event, UNCHECKED_PROXY *UProxy)
{
	Log(LOG_LEVEL_DEBUG, "EVEvent %02x", Event);

	if (Event == BEV_EVENT_EOF && UProxy->stage == UPROXY_STAGE_HTTP_DDL_PAGE)
		UProxy->checkSuccess = true;

	if (Event == BEV_EVENT_CONNECTED) {
		char *ip = IPv6MapToString(UProxy->ip); {
			Log(LOG_LEVEL_DEBUG, "EVEvent: event connected %s (size %d)", ip, SizeUncheckedProxies);
		} free(ip);

		ProxyHandleData(UProxy, EV_TYPE_CONNECT);
	} else {
		if ((UProxy->targetPort == HTTPS_DEFAULT_PORT && UProxy->pageTarget != NULL) || ProxyIsSSL(UProxy->type))
			Log(LOG_LEVEL_DEBUG, "SSL stage %d error %02x -> %d", UProxy->stage, Event, bufferevent_get_openssl_error(BuffEvent));

#if DEBUG
		char *ip = IPv6MapToString(UProxy->ip); {
			Log(LOG_LEVEL_DEBUG, "EVEvent: event timeout / fail %s", ip);
		} free(ip);
		Log(LOG_LEVEL_DEBUG, "EVEvent: BuffEvent: %08x event %02x", BuffEvent, Event);
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

	bufferevent_set_timeouts(UProxy->assocBufferEvent, &GlobalTimeoutTV, &GlobalTimeoutTV);
	bufferevent_setcb(UProxy->assocBufferEvent, (bufferevent_data_cb)EVRead, (bufferevent_data_cb)EVWrite, (bufferevent_event_cb)EVEvent, UProxy);
	bufferevent_enable(UProxy->assocBufferEvent, EV_READ | EV_WRITE);

	UProxy->requestTimeMs = GetUnixTimestampMilliseconds();
	Log(LOG_LEVEL_DEBUG, "RequestAsync: UProxy request time: %llu", UProxy->requestTimeMs);

	InterlockedIncrement(&CurrentlyChecking);

	UProxy->timeout = event_new(levRequestBase, -1, EV_TIMEOUT, (event_callback_fn)RequestFree, UProxy);
	event_add(UProxy->timeout, &GlobalTimeoutTV);

	UProxy->checking = true;
	assert(bufferevent_socket_connect(UProxy->assocBufferEvent, sa, sizeof(struct sockaddr_in6)) == 0); // socket creation should never fail, because IP is always valid (!= dead)
	free(sa);
}
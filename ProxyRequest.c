#include "ProxyRequest.h"
#include "ProxyLists.h"
#include "Global.h"
#include "Base64.h"
#include "Logger.h"
#include "Config.h"
#include "ProxyRemove.h"
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
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

typedef struct _REQUEST_FREE_STRUCT {
	UNCHECKED_PROXY *UProxy;
	struct bufferevent *BuffEvent;
	bool freeBufferEvent;
} REQUEST_FREE_STRUCT;

static void RequestFree(evutil_socket_t fd, short what, REQUEST_FREE_STRUCT *In)
{
	Log(LOG_LEVEL_DEBUG, "RequestFree");
	UNCHECKED_PROXY *UProxy = In->UProxy;
	struct bufferevent *BuffEvent = In->BuffEvent;
	if (In->freeBufferEvent) {
		Log(LOG_LEVEL_DEBUG, "BuffEvent free %p", BuffEvent);
		bufferevent_free(BuffEvent);
	}
	free(In);

	if (UProxy->timeout != NULL) {
		event_del(UProxy->timeout);
		event_free(UProxy->timeout);
		UProxy->timeout = NULL;
	}

	char *ip = IPv6MapToString(UProxy->ip); {
		Log(LOG_LEVEL_DEBUG, "RequestFree -> %s", ip);
	} free(ip);

	InterlockedDecrement(&CurrentlyChecking, 1);

	pthread_mutex_lock(&LockUncheckedProxies); {
	} pthread_mutex_unlock(&LockUncheckedProxies);

	struct timespec tm;
	tm.tv_sec = 1;

	pthread_mutex_lock(&(UProxy->processing)); // locks only on EVWrite called timeout

	if (UProxy->associatedProxy == NULL) {
		if (!UProxy->checkSuccess)
			UProxy->retries++;
		if (UProxy->retries >= AcceptableSequentialFails || UProxy->checkSuccess) {
			char *ip = IPv6MapToString(UProxy->ip); {
				Log(LOG_LEVEL_DEBUG, "RequestFree: Removing proxy %s...", ip);
			} free(ip);
			UProxyRemove(UProxy);
		} else {
			UProxy->checking = false;
		}
	} else {
		char *ip = IPv6MapToString(UProxy->ip); {
			Log(LOG_LEVEL_DEBUG, "RequestFree: Removing proxy %s and updating parent...", ip);
		} free(ip);

		if (!UProxy->checkSuccess)
			UProxyFailUpdateParentInfo(UProxy);
		else
			UProxySuccessUpdateParentInfo(UProxy);

		if (UProxy->singleCheckCallback != NULL)
			UProxy->singleCheckCallback(UProxy);

		UProxyRemove(UProxy);
	}

	pthread_mutex_unlock(&(UProxy->processing));
}

typedef enum _SOCKS_TYPE {
	SOCKS_TYPE_CONNECT = 0x01,
	SOCKS_TYPE_BIND = 0x02,
	SOCKS_TYPE_UDP_ASSOCIATE = 0x03
} SOCKS_TYPE;

static bool SOCKS4(SOCKS_TYPE Type, uint16_t Port, UNCHECKED_PROXY *UProxy, struct bufferevent *BuffEvent)
{
	if (Type == SOCKS_TYPE_UDP_ASSOCIATE)
		return false;

	if (UProxy->stage == 1) {
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
		*((uint16_t*)(&(buff[2]))) = htons(Port);
		*((uint32_t*)(&(buff[4]))) = htonl(GlobalIp4->Data[3]);
		buff[8] = 0x00;

		bufferevent_write(BuffEvent, buff, 9);
		bufferevent_setwatermark(BuffEvent, EV_READ, 8, 0);
	} else if (UProxy->stage == 2) {
		size_t len = evbuffer_get_length(bufferevent_get_input(BuffEvent));
		uint8_t data[2];
		if (len != 8)
			return false;

		evbuffer_remove(bufferevent_get_input(BuffEvent), data, 2);
		Log(LOG_LEVEL_DEBUG, "SOCKS4: Stage 2 data[1]: %d", data[1]);
		return data[1] == 0x5A;
	}
}

static bool SOCKS5(SOCKS_TYPE Type, uint16_t *Port, UNCHECKED_PROXY *UProxy, struct bufferevent *BuffEvent)
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
		case 0:
		{
			uint8_t buff[3];
			buff[0] = 0x05;
			buff[1] = 1; // 1 auth
			buff[2] = 0x00; // no auth
			bufferevent_write(BuffEvent, buff, 3);
			bufferevent_setwatermark(BuffEvent, EV_READ, 2, 0);
			break;
		}
		case 1:
		{
			size_t len = evbuffer_get_length(bufferevent_get_input(BuffEvent));
			uint8_t data[2];
			Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 1 data len: %d", len);
			if (len != 2)
				return false;

			evbuffer_remove(bufferevent_get_input(BuffEvent), data, 2);
			Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 1 data[1]: %d", data[1]);
			return data[1] == 0x00;
			break;
		}
		case 2:
		{

			IP_TYPE ipType = GetIPTypePreffered(GetIPType(UProxy->ip));
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
				(*(uint32_t*)(&(buff[4]))) = GlobalIp4->Data[3];
			else
				memcpy(&(buff[4]), GlobalIp4->Data, IPV6_SIZE);
			*((uint16_t*)&(buff[4 + (ipType == IPV4 ? IPV4_SIZE : IPV6_SIZE)])) = Type != SOCKS_TYPE_UDP_ASSOCIATE ? htons(*Port) : 0;

			bufferevent_write(BuffEvent, buff, 4 + (ipType == IPV4 ? IPV4_SIZE : IPV6_SIZE) + sizeof(uint16_t));
			bufferevent_setwatermark(BuffEvent, EV_READ, 10, 0);
			break;
		}
		case 3:
		{
			size_t len = evbuffer_get_length(bufferevent_get_input(BuffEvent));
			uint8_t data[10];
			Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 3 data len: %d", len);
			if (len < 10)
				return false;

			evbuffer_remove(bufferevent_get_input(BuffEvent), data, 10);

			Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 3 data[1]: %d", data[1]);
			Log(LOG_LEVEL_DEBUG, "SOCKS5: Stage 3 port: %d", ntohs(*((uint16_t*)&(data[8]))));
			*Port = ntohs(*((uint16_t*)&(data[8])));

			return data[1] == 0x00;
			break;
		}
	}
	return true;
}

typedef enum _PROXY_HANDLE_DATA_EV_TYPE {
	EV_TYPE_READ,
	EV_TYPE_WRITE,
	EV_TYPE_CONNECT
} PROXY_HANDLE_DATA_EV_TYPE;

static void ProxyHandleData(UNCHECKED_PROXY *UProxy, struct bufferevent *BuffEvent, PROXY_HANDLE_DATA_EV_TYPE EVType)
{
	Log(LOG_LEVEL_DEBUG, "ProxyHandleData: Proxy %s (%d), stage %d", ProxyGetTypeString(UProxy->type), UProxy->type, UProxy->stage);
	char *reqString;
#define EVTYPE_CASE(x) if (EVType != x) return;
#define EVTYPE_CASE_NOT(x) if (EVType == x) return;

	switch (UProxy->type) {
		case PROXY_TYPE_HTTP: {
			EVTYPE_CASE(EV_TYPE_CONNECT);
			UProxy->stage = 7;
			break;
		}
		case PROXY_TYPE_HTTPS: {
			switch (UProxy->stage) {
				case 0: {
					EVTYPE_CASE(EV_TYPE_CONNECT);

					char *host = GetHost(GetIPType(UProxy->ip), ProxyIsSSL(UProxy->type));
					size_t rawOrigLen = strlen(RequestStringSSL);
					size_t baseLen = (rawOrigLen - 4 /* %s for Host and CONNECT header */) + (strlen(host) * 2);
					size_t fullOrigLen = (sizeof(char) * rawOrigLen) + 1;

					reqString = malloc((sizeof(char) * baseLen) + 1 /* NUL */); {
						memcpy(reqString, RequestStringSSL, fullOrigLen);
						char *reqStringFormat = malloc(fullOrigLen); {
							memcpy(reqStringFormat, reqString, fullOrigLen);
							sprintf(reqString, reqStringFormat, host, host);
						} free(reqStringFormat);
						reqString[baseLen] = 0x00;
						bufferevent_write(BuffEvent, (void*)reqString, strlen(reqString) * sizeof(char));
					} free(reqString);

					UProxy->stage = 1;
					break;
				}
				case 1: {
					EVTYPE_CASE(EV_TYPE_READ);
					// HTTP/1.1 200

					size_t len = evbuffer_get_length(bufferevent_get_input(BuffEvent));
					char data[12];
					if (len < 12)
						goto fail;

					evbuffer_remove(bufferevent_get_input(BuffEvent), data, 12);
					if (strncmp(data + 9, "200", 3) != 0)
						goto fail;

					UProxy->stage = 6;
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
				case 0: {
					EVTYPE_CASE(EV_TYPE_CONNECT);

					SOCKS4(SOCKS_TYPE_CONNECT, ProxyIsSSL(UProxy->type) ? SSLServerPort : ServerPort, UProxy, BuffEvent);
					UProxy->stage = 1;

					break;
				}
				case 1: {
					EVTYPE_CASE(EV_TYPE_READ);

					SOCKS4(SOCKS_TYPE_CONNECT, ProxyIsSSL(UProxy->type) ? SSLServerPort : ServerPort, UProxy, BuffEvent);
					UProxy->stage = ProxyIsSSL(UProxy->type) ? 6 : 7;
				}
			}
			break;
		}
		case PROXY_TYPE_SOCKS5:
		case PROXY_TYPE_SOCKS5_TO_SSL:
		case PROXY_TYPE_SOCKS5_WITH_UDP: {
			uint16_t port = UProxy->type == PROXY_TYPE_SOCKS5_WITH_UDP ? ServerPortUDP : (ProxyIsSSL(UProxy->type) ? SSLServerPort : ServerPort);
			SOCKS_TYPE socksType = UProxy->type == PROXY_TYPE_SOCKS5_WITH_UDP ? SOCKS_TYPE_UDP_ASSOCIATE : SOCKS_TYPE_CONNECT;

			Log(LOG_LEVEL_DEBUG, "SOCKS5 port %d", port);

			switch (UProxy->stage) {
				case 0: {
					EVTYPE_CASE(EV_TYPE_CONNECT);

					SOCKS5(socksType, &port, UProxy, BuffEvent);
					Log(LOG_LEVEL_DEBUG, "SOCKS5 advance to stage 1");
					UProxy->stage = 1;
					break;
				}
				case 1: {
					EVTYPE_CASE(EV_TYPE_READ);

					if (SOCKS5(socksType, &port, UProxy, BuffEvent)) {
						Log(LOG_LEVEL_DEBUG, "SOCKS5 advance to stage 2");
						UProxy->stage = 2;
						SOCKS5(socksType, &port, UProxy, BuffEvent);
						Log(LOG_LEVEL_DEBUG, "SOCKS5 advance to stage 3");
						UProxy->stage = 3;

						// This handles two stages because after first stage, there's no one to send packet after receiving response
					} else
						goto fail;
					break;
				}
				case 3: {
					EVTYPE_CASE(EV_TYPE_READ);

					if (SOCKS5(socksType, &port, UProxy, BuffEvent)) {
						if (UProxy->type == PROXY_TYPE_SOCKS5_WITH_UDP) {
							Log(LOG_LEVEL_DEBUG, "SOCKS5 advance to stage 4 (UDP)");
							UProxy->stage = 8;

							int hSock;

							UProxy->requestTimeHttpMs = GetUnixTimestampMilliseconds();

							if ((hSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) != -1) {
								Log(LOG_LEVEL_DEBUG, "UDP socket");
								struct sockaddr *sa = IPv6MapToRaw(UProxy->ip, port); {
									IP_TYPE ipType = GetIPTypePreffered(GetIPType(UProxy->ip));
									Log(LOG_LEVEL_DEBUG, "UDP IP Type %d", ipType);

									uint8_t buff[512 / 8 + 6 + (ipType == IPV4 ? IPV4_SIZE : IPV6_SIZE)];
									buff[0] = 0x00;
									buff[1] = 0x00;
									buff[2] = 0x00;
									buff[3] = ipType == IPV4 ? 0x01 : 0x04;
									memcpy(&(buff[4]), ipType == IPV4 ? &(GlobalIp4->Data[3]) : GlobalIp6->Data, ipType == IPV4 ? IPV4_SIZE : IPV6_SIZE);
									*((uint16_t*)&(buff[4 + (ipType == IPV4 ? IPV4_SIZE : IPV6_SIZE)])) = htons(ServerPortUDP);
									memcpy(&(buff[6 + (ipType == IPV4 ? IPV4_SIZE : IPV6_SIZE)]), UProxy->hash, 512 / 8);

									Log(LOG_LEVEL_DEBUG, "UDP buff construct");

									if (sendto(hSock, buff, 512 / 8 + 6 + (ipType == IPV4 ? IPV4_SIZE : IPV6_SIZE), 0, sa, GetIPType(UProxy->ip) == IPV4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) == -1) {
										Log(LOG_LEVEL_DEBUG, "UDP send fail");
										free(sa);
										close(hSock);
										goto fail;
									}
									Log(LOG_LEVEL_DEBUG, "UDP sent ;)");
								} free(sa);
								close(hSock);
							}
						} else {
							Log(LOG_LEVEL_DEBUG, "SOCKS5 advance to stage %d (%s)", ProxyIsSSL(UProxy->type) ? 6 : 7, ProxyIsSSL(UProxy->type) ? "SSL" : "HTTP");
							UProxy->stage = ProxyIsSSL(UProxy->type) ? 6 : 7;
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
		case 6: {
			struct evbuffer *buff = bufferevent_get_input(BuffEvent);
			evbuffer_drain(buff, evbuffer_get_length(buff));
			Log(LOG_LEVEL_DEBUG, "Establishing SSL connection...");
			// Begin REAL SSL
			BuffEvent = bufferevent_openssl_filter_new(levRequestBase,
													   BuffEvent,
													   SSL_new(RequestBaseSSLCTX),
													   BUFFEREVENT_SSL_CONNECTING,
													   BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
			bufferevent_openssl_set_allow_dirty_shutdown(BuffEvent, 1);

			if (BuffEvent != NULL) {
				bufferevent_setcb(BuffEvent, (bufferevent_data_cb)EVRead, (bufferevent_data_cb)EVWrite, (bufferevent_event_cb)EVEvent, UProxy);
				bufferevent_set_timeouts(BuffEvent, &GlobalTimeoutTV, &GlobalTimeoutTV);
			} else {
				Log(LOG_LEVEL_DEBUG, "SSL BuffEvent fail");
				goto fail;
			}

			UProxy->stage = 7;
			// SSL handshake brings up EVEvent connect so this falls to stage 7 later
			break;
		}
		case 7: {
			EVTYPE_CASE_NOT(EV_TYPE_WRITE);

			UProxy->requestTimeHttpMs = GetUnixTimestampMilliseconds();
			Log(LOG_LEVEL_DEBUG, "Sending HTTP request");
			char *key;
			size_t key64Len = Base64Encode(UProxy->hash, 512 / 8, &key); {
				char *host = GetHost(GetIPType(UProxy->ip), ProxyIsSSL(UProxy->type));
				size_t rawOrigLen = strlen(RequestString);
				size_t baseLen = (rawOrigLen - 2 /* %s for Host header */) + strlen(host);
				size_t fullOrigLen = (sizeof(char) * rawOrigLen) + 1;

				reqString = malloc((sizeof(char) * (baseLen + key64Len + 4 /* \r\n\r\n */)) + 1 /* NUL */);
				memcpy(reqString, RequestString, fullOrigLen);

				char reqStringFormat[fullOrigLen];
				memcpy(reqStringFormat, reqString, fullOrigLen);
				sprintf(reqString, reqStringFormat, host);

				memcpy(reqString + baseLen, key, key64Len * sizeof(char));
				reqString[baseLen + key64Len] = '\r';
				reqString[baseLen + key64Len + 1] = '\n';
				reqString[baseLen + key64Len + 2] = '\r';
				reqString[baseLen + key64Len + 3] = '\n';
				reqString[baseLen + key64Len + 4] = 0x00;
			} free(key);

			bufferevent_write(BuffEvent, (void*)reqString, strlen(reqString) * sizeof(char));
			free(reqString);
			UProxy->stage = 8;
			Log(LOG_LEVEL_DEBUG, "Advance to stage 8 (final)");
			break;
		}
		case 8:
		{
			bufferevent_setcb(BuffEvent, NULL, NULL, NULL, NULL);
			break;
		}
	}

	return;
fail:
	Log(LOG_LEVEL_DEBUG, "ProxyHandleData failure Proxy %s at stage %d", ProxyGetTypeString(UProxy->type), UProxy->stage);
	bufferevent_setcb(BuffEvent, NULL, NULL, NULL, NULL);
	if (UProxy->timeout != NULL)
		event_active(UProxy->timeout, EV_TIMEOUT, 0);
}

void CALLBACK EVEvent(struct bufferevent *BuffEvent, uint16_t Event, UNCHECKED_PROXY *UProxy)
{
	Log(LOG_LEVEL_DEBUG, "EVEvent %02x", Event);
	pthread_mutex_lock(&LockUncheckedProxies); {
		bool found = false;
		for (uint64_t x = 0; x < SizeUncheckedProxies; x++) {
			if (UncheckedProxies[x] == UProxy) {
				found = true;
				break;
			}
		}
		if (!found) {
			Log(LOG_LEVEL_DEBUG, "EVEvent: UProxy doesn't exist");
			pthread_mutex_unlock(&LockUncheckedProxies);
			return;
		}
	} pthread_mutex_unlock(&LockUncheckedProxies);

	if (Event == BEV_EVENT_CONNECTED) {
		char *ip = IPv6MapToString(UProxy->ip); {
			Log(LOG_LEVEL_DEBUG, "EVEvent: event connected %s (size %d)", ip, SizeUncheckedProxies);
		} free(ip);

		ProxyHandleData(UProxy, BuffEvent, EV_TYPE_CONNECT);
	} else {
		if (ProxyIsSSL(UProxy->type))
			Log(LOG_LEVEL_DEBUG, "SSL stage %d error %02x", UProxy->stage, Event);

		bufferevent_setcb(BuffEvent, NULL, NULL, NULL, NULL);
#if DEBUG
		char *ip = IPv6MapToString(UProxy->ip); {
			Log(LOG_LEVEL_DEBUG, "EVEvent: event timeout / fail %s", ip);
		} free(ip);
		Log(LOG_LEVEL_DEBUG, "EVEvent: BuffEvent: %08x event %02x", BuffEvent, Event);
#endif
		if (UProxy->timeout != NULL)
			event_active(UProxy->timeout, EV_TIMEOUT, 0);
	}
}

void CALLBACK EVRead(struct bufferevent *BuffEvent, UNCHECKED_PROXY *UProxy)
{
	pthread_mutex_lock(&LockUncheckedProxies); {
		bool found = false;
		for (uint64_t x = 0; x < SizeUncheckedProxies; x++) {
			if (UncheckedProxies[x] == UProxy) {
				found = true;
				break;
			}
		}
		if (!found) {
			Log(LOG_LEVEL_DEBUG, "EVRead: UProxy doesn't exist");
			pthread_mutex_unlock(&LockUncheckedProxies);
			return;
		}
	} pthread_mutex_unlock(&LockUncheckedProxies);

	ProxyHandleData(UProxy, BuffEvent, EV_TYPE_READ);
}

void CALLBACK EVWrite(struct bufferevent *BuffEvent, UNCHECKED_PROXY *UProxy)
{
	Log(LOG_LEVEL_DEBUG, "EVWrite");

	pthread_mutex_lock(&LockUncheckedProxies); {
		bool found = false;
		for (uint64_t x = 0; x < SizeUncheckedProxies; x++) {
			if (UncheckedProxies[x] == UProxy) {
				found = true;
				break;
			}
		}
		if (!found) {
			Log(LOG_LEVEL_DEBUG, "EVWrite: UProxy doesn't exist");
			pthread_mutex_unlock(&LockUncheckedProxies);
			return;
		}
	} pthread_mutex_unlock(&LockUncheckedProxies);

	ProxyHandleData(UProxy, BuffEvent, EV_TYPE_WRITE);
}

void RequestAsync(UNCHECKED_PROXY *UProxy)
{
	struct event_base *base;

	// getting tired of struct bullshit!!!
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

	struct bufferevent *buffEvent;

	buffEvent = bufferevent_socket_new(levRequestBase, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);

	Log(LOG_LEVEL_DEBUG, "RequestAsync: new socket");

	bufferevent_set_timeouts(buffEvent, &GlobalTimeoutTV, &GlobalTimeoutTV);
	bufferevent_setcb(buffEvent, (bufferevent_data_cb)EVRead, (bufferevent_data_cb)EVWrite, (bufferevent_event_cb)EVEvent, UProxy);
	bufferevent_enable(buffEvent, EV_READ | EV_WRITE);

	UProxy->requestTimeMs = GetUnixTimestampMilliseconds();
	Log(LOG_LEVEL_DEBUG, "RequestAsync: UProxy request time: %llu", UProxy->requestTimeMs);

	InterlockedIncrement(&CurrentlyChecking, 1);

	REQUEST_FREE_STRUCT *s = malloc(sizeof(REQUEST_FREE_STRUCT));
	s->BuffEvent = buffEvent;
	s->UProxy = UProxy;
	s->freeBufferEvent = true;

	UProxy->timeout = event_new(levRequestBase, -1, EV_TIMEOUT, (event_callback_fn)RequestFree, s);
	event_add(UProxy->timeout, &GlobalTimeoutTV);

	UProxy->checking = true;
	assert(bufferevent_socket_connect(buffEvent, sa, sizeof(struct sockaddr_in6)) == 0); // socket creation should never fail, because IP is always valid (!= dead)
	free(sa);
}
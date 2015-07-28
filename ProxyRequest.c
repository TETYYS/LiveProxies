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
	if (In->freeBufferEvent)
		bufferevent_free(BuffEvent);
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

	pthread_mutex_lock(&lockUncheckedProxies); {
	} pthread_mutex_unlock(&lockUncheckedProxies);

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
			pthread_mutex_unlock(&(UProxy->processing));
		}
	} else {
		char *ip = IPv6MapToString(UProxy->ip); {
			Log(LOG_LEVEL_DEBUG, "RequestFree: Removing proxy %s and updating parent...", ip);
		} free(ip);

		if (!UProxy->checkSuccess)
			UProxyFailUpdateParentInfo(UProxy);
		if (UProxy->singleCheck != NULL)
			pthread_mutex_unlock(UProxy->singleCheck);
		else
			UProxyRemove(UProxy);
	}
}

void CALLBACK EVRead(struct bufferevent *BuffEvent, UNCHECKED_PROXY *UProxy)
{
	Log(LOG_LEVEL_DEBUG, "EVRead");
	if (UProxy->sslStage == 1) {
		pthread_mutex_lock(&lockUncheckedProxies); {
			bool found = false;
			for (size_t x = 0; x < sizeUncheckedProxies; x++) {
				if (uncheckedProxies[x] == UProxy) {
					found = true;
					break;
				}
			}
			if (!found) {
				Log(LOG_LEVEL_DEBUG, "EVRead: UProxy doesn't exist");
				pthread_mutex_unlock(&lockUncheckedProxies);
				return;
			}
		} pthread_mutex_unlock(&lockUncheckedProxies);

		struct evbuffer *buff = bufferevent_get_input(BuffEvent);
		evbuffer_drain(buff, evbuffer_get_length(buff));

		// Begin REAL SSL

		Log(LOG_LEVEL_DEBUG, "SSL stage 1 -> 2");

		UProxy->sslStage = 2;

		BuffEvent = bufferevent_openssl_filter_new(levRequestBase,
												   BuffEvent,
												   SSL_new(RequestBaseSSLCTX),
												   BUFFEREVENT_SSL_CONNECTING,
												   BEV_OPT_CLOSE_ON_FREE | BEV_OPT_THREADSAFE);
		bufferevent_openssl_set_allow_dirty_shutdown(BuffEvent, 1);

		if (BuffEvent != NULL) {
			Log(LOG_LEVEL_DEBUG, "SSL BuffEvent SET <------------------------------");
			bufferevent_setcb(BuffEvent, (bufferevent_data_cb)EVRead, (bufferevent_data_cb)EVWrite, (bufferevent_event_cb)EVEvent, UProxy);
			bufferevent_set_timeouts(BuffEvent, &GlobalTimeoutTV, &GlobalTimeoutTV);
		} else {
			Log(LOG_LEVEL_DEBUG, "SSL BuffEvent NULL");
		}
	}
}

void CALLBACK EVWrite(struct bufferevent *BuffEvent, UNCHECKED_PROXY *UProxy)
{
	/*pthread_mutex_lock(&lockUncheckedProxies); {
		bool found = false;
		for (size_t x = 0; x < sizeUncheckedProxies; x++) {
			if (uncheckedProxies[x] == UProxy) {
				found = true;
				break;
			}
		}
		if (!found) {
			Log(LOG_LEVEL_DEBUG, "EVWrite: UProxy doesn't exist");
			pthread_mutex_unlock(&lockUncheckedProxies);
			return;
		}
	} pthread_mutex_unlock(&lockUncheckedProxies);*/
	Log(LOG_LEVEL_DEBUG, "EVWrite");
}

typedef enum _SOCKS_TYPE {
	CONNECT = 0x01,
	BIND = 0x02,
	UDP_ASSOCIATE = 0x03
} SOCKS_TYPE;

static void SendSOCKS4Packet(SOCKS_TYPE Type, uint16_t Port, UNCHECKED_PROXY *UProxy, struct bufferevent *BuffEvent)
{
	if (Type == UDP_ASSOCIATE)
		return;

	/*
	field 1: SOCKS version number, 1 byte, must be 0x04 for this version
	field 2: command code, 1 byte:
	0x01 = establish a TCP/IP stream connection
	0x02 = establish a TCP/IP port binding
	field 3: network byte order port number, 2 bytes
	field 4: network byte order IP address, 4 bytes
	field 5: the user ID string, variable length, terminated with a null (0x00)
	*/
	char buff[1 + 1 + sizeof(uint16_t)+IPV4_SIZE + 1 /* ? */];
	buff[0] = 0x04;
	buff[1] = 0x01; // CONNECT
	*((uint16_t*)(&(buff[2]))) = htons(Port);
	*((uint32_t*)(&(buff[4]))) = htonl(GlobalIp4->Data[3]);
	buff[8] = 0x00;

	bufferevent_write(BuffEvent, buff, 9);
}

static void SendSOCKS5Packet(SOCKS_TYPE Type, uint16_t Port, UNCHECKED_PROXY *UProxy, struct bufferevent *BuffEvent)
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

	char *buff;
	IP_TYPE type = GetIP(UProxy->ip);
	if (type == IPV4)
		buff = malloc(7 + IPV4_SIZE + sizeof(uint16_t));
	else
		buff = malloc(7 + IPV6_SIZE + sizeof(uint16_t));
	{
		buff[0] = 0x05;
		buff[1] = 1; // 1 auth
		buff[2] = 0x00; // no auth

		buff[3] = 0x05; // again?
		buff[4] = Type;
		buff[5] = 0x00; // RESERVED
		buff[6] = type == IPV4 ? 0x01 : 0x04; // who was 0x02?
		if (type == IPV4)
			(*(uint32_t*)(&(buff[7]))) = GlobalIp4->Data[3];
		else
			memcpy(&(buff[7]), GlobalIp4->Data, IPV6_SIZE);
		*((uint16_t*)&(buff[7 + (type == IPV4 ? IPV4_SIZE : IPV6_SIZE)])) = htons(Port);

		bufferevent_write(BuffEvent, buff, 7 + (type == IPV4 ? IPV4_SIZE : IPV6_SIZE) + sizeof(uint16_t));
	} free(buff);
}

void CALLBACK EVEvent(struct bufferevent *BuffEvent, uint16_t Event, UNCHECKED_PROXY *UProxy)
{
	Log(LOG_LEVEL_DEBUG, "EVEvent %02x", Event);
	pthread_mutex_lock(&lockUncheckedProxies); {
		bool found = false;
		for (size_t x = 0; x < sizeUncheckedProxies; x++) {
			if (uncheckedProxies[x] == UProxy) {
				found = true;
				break;
			}
		}
		if (!found) {
			Log(LOG_LEVEL_DEBUG, "EVEvent: UProxy doesn't exist");
			pthread_mutex_unlock(&lockUncheckedProxies);
			return;
		}
	} pthread_mutex_unlock(&lockUncheckedProxies);

	if (Event == BEV_EVENT_CONNECTED) {
		char *ip = IPv6MapToString(UProxy->ip); {
			Log(LOG_LEVEL_DEBUG, "EVEvent: event connected %s", ip);
		} free(ip);

		char *reqString;
		IP_TYPE type = GetIPType(UProxy->ip);
		char *host = GetHost(type, ProxyIsSSL(UProxy->type));

		if (!ProxyIsSSL(UProxy->type) || (ProxyIsSSL(UProxy->type) && UProxy->sslStage == 2)) {
			char *key;
			size_t key64Len = Base64Encode(UProxy->hash, 512 / 8, &key); {
				size_t rawOrigLen = strlen(RequestString);
				size_t baseLen = (rawOrigLen - 2 /* %s for Host header */) + strlen(host);
				size_t fullOrigLen = (sizeof(char) * rawOrigLen) + 1;

				reqString = malloc((sizeof(char)* (baseLen + key64Len + 4 /* \r\n\r\n */)) + 1 /* NUL */);
				memcpy(reqString, RequestString, fullOrigLen);
				char *reqStringFormat = malloc(fullOrigLen); {
					memcpy(reqStringFormat, reqString, fullOrigLen);
					sprintf(reqString, reqStringFormat, host);
				} free(reqStringFormat);
				memcpy(reqString + baseLen, key, key64Len * sizeof(char));
				reqString[baseLen + key64Len] = '\r';
				reqString[baseLen + key64Len + 1] = '\n';
				reqString[baseLen + key64Len + 2] = '\r';
				reqString[baseLen + key64Len + 3] = '\n';
				reqString[baseLen + key64Len + 4] = 0x00;
			} free(key);
		} else {
			size_t rawOrigLen = strlen(RequestStringSSL);
			size_t baseLen = (rawOrigLen - 4 /* %s for Host and CONNECT header */) + (strlen(host) * 2);
			size_t fullOrigLen = (sizeof(char) * rawOrigLen) + 1;

			reqString = malloc((sizeof(char) * baseLen) + 1 /* NUL */);
			memcpy(reqString, RequestStringSSL, fullOrigLen);
			char *reqStringFormat = malloc(fullOrigLen); {
				memcpy(reqStringFormat, reqString, fullOrigLen);
				sprintf(reqString, reqStringFormat, host, host);
			} free(reqStringFormat);
			reqString[baseLen] = 0x00;
		}
		if (UProxy->type == PROXY_TYPE_HTTP || (ProxyIsSSL(UProxy->type) && UProxy->sslStage == 2)) {
			Log(LOG_LEVEL_DEBUG, "HTTP / SSL stage 2");
			UProxy->requestTimeHttpMs = GetUnixTimestampMilliseconds();
			bufferevent_write(BuffEvent, (void*)reqString, strlen(reqString) * sizeof(char));
			free(reqString);
		}
		if (UProxy->type == PROXY_TYPE_HTTPS && UProxy->sslStage == 0) {
			Log(LOG_LEVEL_DEBUG, "SSL stage 0 -> 1");
			/*
			CONNECT www.example.com:443 HTTP/1.1
			Host: www.example.com:443
			*/

			UProxy->sslStage = 1;

			// reqString formatted for stage != 2

			bufferevent_write(BuffEvent, (void*)reqString, strlen(reqString) * sizeof(char));
			free(reqString);
		}
		if ((UProxy->type == PROXY_TYPE_SOCKS4 || UProxy->type == PROXY_TYPE_SOCKS4A ||
			UProxy->type == PROXY_TYPE_SOCKS4_TO_SSL || UProxy->type == PROXY_TYPE_SOCKS4A_TO_SSL) &&
			GlobalIp4 == NULL) {
			// ????
			REQUEST_FREE_STRUCT *s = malloc(sizeof(REQUEST_FREE_STRUCT));
			s->BuffEvent = BuffEvent;
			s->UProxy = UProxy;
			s->freeBufferEvent = true;
			RequestFree(0, 0, s);
			return;
		}

		if (UProxy->type == PROXY_TYPE_SOCKS4 || UProxy->type == PROXY_TYPE_SOCKS4A) {
			SendSOCKS4Packet(CONNECT, ServerPort, UProxy, BuffEvent);
			bufferevent_write(BuffEvent, reqString, strlen(reqString) * sizeof(char));
		}
		if (UProxy->type == PROXY_TYPE_SOCKS4_TO_SSL || UProxy->type == PROXY_TYPE_SOCKS4A_TO_SSL) {
			UProxy->sslStage = 1;
			SendSOCKS4Packet(CONNECT, SSLServerPort, UProxy, BuffEvent);
		}
		if (UProxy->type == PROXY_TYPE_SOCKS5) {
			SendSOCKS5Packet(CONNECT, ServerPort, UProxy, BuffEvent);
			bufferevent_write(BuffEvent, reqString, strlen(reqString) * sizeof(char));
		}
		if (UProxy->type == PROXY_TYPE_SOCKS5_TO_SSL) {
			UProxy->sslStage = 1;
			SendSOCKS5Packet(CONNECT, SSLServerPort, UProxy, BuffEvent);
		}
		if (UProxy->type == PROXY_TYPE_SOCKS5_WITH_UDP) {
			SendSOCKS5Packet(UDP_ASSOCIATE, ServerPortUDP, UProxy, BuffEvent);
			bufferevent_write(BuffEvent, UProxy->hash, 512 / 8);
		}
		if (!ProxyIsSSL(UProxy->type))
			bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);
	} else {
		if (ProxyIsSSL(UProxy->type))
			Log(LOG_LEVEL_DEBUG, "SSL stage %d error %02x", UProxy->sslStage, Event);

		bufferevent_setcb(BuffEvent, NULL, NULL, NULL, NULL);
#if DEBUG
		char *ip = IPv6MapToString(UProxy->ip); {
			Log(LOG_LEVEL_DEBUG, "EVEvent: event timeout / fail %s", ip);
		} free(ip);
		Log(LOG_LEVEL_DEBUG, "EVEvent: BuffEvent: %08x event %02x", BuffEvent, Event);
#endif

		REQUEST_FREE_STRUCT *s = malloc(sizeof(REQUEST_FREE_STRUCT));
		s->BuffEvent = BuffEvent;
		s->UProxy = UProxy;
		s->freeBufferEvent = true;
		ip = IPv6MapToString(UProxy->ip); {
			Log(LOG_LEVEL_DEBUG, "RequestFree call struct for %s", ip);
		} free(ip);
		RequestFree(0, 0, s);
	}
}

void RequestAsync(UNCHECKED_PROXY *UProxy)
{
	struct event_base *base;

	if (UProxy->singleCheck != NULL)
		pthread_mutex_lock(UProxy->singleCheck);

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
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
//#include <event2/bufferevent_ssl.h>
#include <poll.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct _REQUEST_FREE_STRUCT {
	UNCHECKED_PROXY *UProxy;
	struct bufferevent *BuffEvent;
	bool freeBufferEvent;
} REQUEST_FREE_STRUCT;

static void RequestFree(evutil_socket_t fd, short what, REQUEST_FREE_STRUCT *In) {
	UNCHECKED_PROXY *UProxy = In->UProxy;
	struct bufferevent *BuffEvent = In->BuffEvent;
	if (In->freeBufferEvent)
		bufferevent_free(BuffEvent);
	free(In);

	char *ip = IPv6MapToString(UProxy->ip); {
		Log(LOG_LEVEL_DEBUG, "RequestFree -> %s", ip);
	} free(ip);

	InterlockedDecrement(&CurrentlyChecking, 1);

	/*sem_wait(&lockUncheckedProxies); {
	} sem_post(&lockUncheckedProxies);*/
	sem_wait(&(UProxy->processing)); // locks only on EVWrite called timeout
	
	if (UProxy->associatedProxy == NULL) {
		if (UProxy->retries > AcceptableSequentialFails || UProxy->checkSuccess) {
			char *ip = IPv6MapToString(UProxy->ip); {
				Log(LOG_LEVEL_DEBUG, "RequestFree: Removing proxy %s...", ip);
			} free(ip);
			UProxyRemove(UProxy);
		} else {
			UProxy->retries++;
			UProxy->checking = false;
			sem_post(&(UProxy->processing));
		}
	} else {
		Log(LOG_LEVEL_DEBUG, "RequestFree: Free'ing proxy and updating parent");
		UProxyFailUpdateParentInfo(UProxy);
		UProxyFree(UProxy);
	}
}

static void CALLBACK EVWrite(struct bufferevent *BuffEvent, UNCHECKED_PROXY *UProxy) {
	// Pass!
	// It should be in WServer now.
	Log(LOG_LEVEL_DEBUG, "EVWrite");
	UProxy->requestTimeHttpMs = GetUnixTimestampMilliseconds();
}

static void CALLBACK EVEvent(struct bufferevent *BuffEvent, uint16_t Event, UNCHECKED_PROXY *UProxy) {
	sem_wait(&lockUncheckedProxies); {
		bool found = false;
		for (size_t x = 0; x < sizeUncheckedProxies; x++) {
			if (uncheckedProxies[x] == UProxy) {
				found = true;
				break;
			}
		}
		if (!found) {
			sem_post(&lockUncheckedProxies);
			return;
		}
	} sem_post(&lockUncheckedProxies);

	if (Event == BEV_EVENT_CONNECTED) {
		char *ip = IPv6MapToString(UProxy->ip); {
			Log(LOG_LEVEL_DEBUG, "EVEvent: event connected %s", ip);
		} free(ip);
		char *key;
		char *reqString;
		size_t key64Len = Base64Encode(UProxy->hash, 512 / 8, &key); {
			size_t baseLen = strlen(RequestString);

			reqString = calloc(baseLen + key64Len + 1 /* null */ + 2 /* \n\n */, 1);
			memcpy(reqString, RequestString, baseLen);
			memcpy(reqString + baseLen, key, key64Len * sizeof(char));
			reqString[baseLen + key64Len] = '\n';
			reqString[baseLen + key64Len + 1] = '\n';
			reqString[baseLen + key64Len + 2] = 0x00;
		} free(key);

		struct evbuffer *evBuff = evbuffer_new(); {

			if (UProxy->type == PROXY_TYPE_HTTP) {
				bufferevent_setwatermark(BuffEvent, EV_WRITE, strlen(reqString) * sizeof(char), 0);
				bufferevent_write(BuffEvent, (void*)reqString, strlen(reqString) * sizeof(char));
				free(reqString);
			}
			if ((UProxy->type == PROXY_TYPE_SOCKS4 | UProxy->type == PROXY_TYPE_SOCKS4A) && GetIPType(GlobalIp) == IPV6) {
				// ????
				REQUEST_FREE_STRUCT *s = malloc(sizeof(REQUEST_FREE_STRUCT));
				s->BuffEvent = BuffEvent;
				s->UProxy = UProxy;
				s->freeBufferEvent = true;
				RequestFree(0, 0, s);
				return;
			}
			if (UProxy->type == PROXY_TYPE_SOCKS4 || UProxy->type == PROXY_TYPE_SOCKS4A) {
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
				*((uint16_t*)(&(buff[2]))) = htons(ServerPort);
				*((uint32_t*)(&(buff[4]))) = htonl(GlobalIp->Data[3]);
				buff[8] = 0x00;

				bufferevent_setwatermark(BuffEvent, EV_WRITE, 9 + (strlen(reqString) * sizeof(char)), 0);
				evbuffer_add_reference(evBuff, buff, 9, (evbuffer_ref_cleanup_cb)free, buff);
				evbuffer_add_reference(evBuff, reqString, strlen(reqString) * sizeof(char), (evbuffer_ref_cleanup_cb)free, reqString);
				bufferevent_write_buffer(BuffEvent, evBuff);

				// some servers are not happy with two blocks of data?
			}
			if (UProxy->type == PROXY_TYPE_SOCKS5) {
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
				IPV6_TYPE type = GetIPType(GlobalIp);
				if (type == IPV4)
					buff = malloc(7 + IPV4_SIZE + sizeof(uint16_t));
				else
					buff = malloc(7 + IPV6_SIZE + sizeof(uint16_t));
				buff[0] = 0x05;
				buff[1] = 1; // 1 auth
				buff[2] = 0x00; // no auth

				buff[3] = 0x05; // again?
				buff[4] = 0x01; // CONNECT
				buff[5] = 0x00; // RESERVED
				buff[6] = type == IPV4 ? 0x01 : 0x04; // who was 0x02?
				if (type == IPV4)
					(*(uint32_t*)(&(buff[7]))) = GlobalIp->Data[3];
				else {
					for (size_t x = 0; x < 4; x++) {
						uint32_t block;
						block = GlobalIp->Data[x];
						memcpy(&(buff[7 + (x * 4)]), &block, IPV6_SIZE);
					}
					// if IPv6 is 16 bytes, then why sockaddr structure specifies 14???
				}
				*((uint16_t*)&(buff[(type == IPV4 ? 7 + IPV4_SIZE : 7 + IPV6_SIZE)])) = htons(ServerPort);

				bufferevent_setwatermark(BuffEvent, EV_WRITE, 7 + (type == IPV4 ? IPV4_SIZE : IPV6_SIZE) + sizeof(uint16_t)+(strlen(reqString) * sizeof(char)), 0);
				evbuffer_add_reference(evBuff, buff, 7 + (type == IPV4 ? IPV4_SIZE : IPV6_SIZE) + sizeof(uint16_t), (evbuffer_ref_cleanup_cb)free, buff);
				evbuffer_add_reference(evBuff, reqString, strlen(reqString) * sizeof(char), (evbuffer_ref_cleanup_cb)free, reqString);
				if (bufferevent_write_buffer(BuffEvent, evBuff) == -1)
					Log(LOG_LEVEL_DEBUG, "SOCKS5 write error");
			}
		} evbuffer_free(evBuff);
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);
	}
	else if (Event & BEV_EVENT_ERROR) {
		bufferevent_setcb(BuffEvent, NULL, NULL, NULL, NULL);
		event_del(UProxy->timeout);
		event_free(UProxy->timeout);
		UProxy->timeout = NULL;

		char *ip = IPv6MapToString(UProxy->ip); {
			Log(LOG_LEVEL_DEBUG, "EVEvent: event timeout / fail %s", ip);
		} free(ip);
		Log(LOG_LEVEL_DEBUG, "EVEvent: timeout BuffEvent: %08x event %d", BuffEvent, Event);
		
		REQUEST_FREE_STRUCT *s = malloc(sizeof(REQUEST_FREE_STRUCT));
		s->BuffEvent = BuffEvent;
		s->UProxy = UProxy;
		s->freeBufferEvent = false;
		ip = IPv6MapToString(UProxy->ip); {
			Log(LOG_LEVEL_DEBUG, "RequestFree call struct for %s", ip);
		} free(ip);
		RequestFree(0, 0, s);
	}
}

void RequestAsync(UNCHECKED_PROXY *UProxy) {
	struct event_base *base;
	struct bufferevent **bevs;

	// getting tired of struct bullshit!!!
	struct sockaddr *sa = IPv6MapToRaw(UProxy->ip, UProxy->port);

#if DEBUG
	char *ip = IPv6MapToString(UProxy->ip); {
		Log(LOG_LEVEL_DEBUG, "RequestAsync: [%s]:%d", ip, UProxy->port);
		if (GetIPType(UProxy->ip) == IPV4) {
			char *asd = calloc(1, 64 /* whatever */);
			inet_ntop(AF_INET, &(((struct sockaddr_in*)sa)->sin_addr), asd, INET_ADDRSTRLEN);
			Log(LOG_LEVEL_DEBUG, "RequestAsync 2: [%s]:%d", asd, ntohs(((struct sockaddr_in*)sa)->sin_port));
		} else {
			char *asd = calloc(1, 64 /* whatever */);
			inet_ntop(AF_INET6, &(((struct sockaddr_in6*)sa)->sin6_addr), asd, INET6_ADDRSTRLEN);
			Log(LOG_LEVEL_DEBUG, "RequestAsync 2: [%s]:%d", asd, ntohs(((struct sockaddr_in6*)sa)->sin6_port));
		}
	} free(ip);
#endif

	struct bufferevent *buffEvent = bufferevent_socket_new(levRequestBase, -1, BEV_OPT_CLOSE_ON_FREE);
	struct timeval timeout;
	timeout.tv_sec = GlobalTimeout / 1000;
	timeout.tv_usec = (GlobalTimeout % 1000) * 1000;

	Log(LOG_LEVEL_DEBUG, "RequestAsync: new socket");

	bufferevent_set_timeouts(buffEvent, &timeout, &timeout);
	bufferevent_setcb(buffEvent, NULL, (bufferevent_data_cb)EVWrite, (bufferevent_data_cb)EVEvent, UProxy);
	bufferevent_enable(buffEvent, EV_READ | EV_WRITE);

	UProxy->requestTimeMs = GetUnixTimestampMilliseconds();
	Log(LOG_LEVEL_DEBUG, "RequestAsync: UProxy request time: %llu", UProxy->requestTimeMs);

	InterlockedIncrement(&CurrentlyChecking, 1);

	REQUEST_FREE_STRUCT *s = malloc(sizeof(REQUEST_FREE_STRUCT));
	s->BuffEvent = buffEvent;
	s->UProxy = UProxy;
	s->freeBufferEvent = true;

	UProxy->timeout = event_new(levRequestBase, -1, EV_TIMEOUT, (event_callback_fn)RequestFree, s);
	event_add(UProxy->timeout, &timeout);

	bufferevent_socket_connect(buffEvent, sa, sizeof(struct sockaddr_in6)); // socket creation should never fail, because IP is always valid (!= dead)
}
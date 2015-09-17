#pragma once

#include <event2/event.h>
#include <event2/bufferevent.h>
#include <openssl/ssl.h>
#include <stddef.h>
#include "ProxyLists.h"

#define HTTPS_DEFAULT_PORT 443
#define HTTP_DEFAULT_PORT 80

char *RequestUA;
char *RequestHeaderKey;
char *RequestString;
size_t RequestStringLen;
char *RequestStringSSL;

char *Host4;
char *Host6;

char *Host4SSL;
char *Host6SSL;

struct event_base *levRequestBase;
struct evdns_base *levRequestDNSBase;
SSL_CTX *RequestBaseSSLCTX;

void RequestAsync(UNCHECKED_PROXY *UProxy);

void CALLBACK EVEvent(struct bufferevent *BuffEvent, uint16_t Event, UNCHECKED_PROXY *UProxy);
void CALLBACK EVWrite(struct bufferevent *BuffEvent, UNCHECKED_PROXY *UProxy);
void CALLBACK EVRead(struct bufferevent *BuffEvent, UNCHECKED_PROXY *UProxy);

typedef enum _PROXY_HANDLE_DATA_EV_TYPE {
	EV_TYPE_READ,
	EV_TYPE_WRITE,
	EV_TYPE_CONNECT
} PROXY_HANDLE_DATA_EV_TYPE;

void ProxyDNSResolved(int Err, struct evutil_addrinfo *Addr, UNCHECKED_PROXY *UProxy);
void ProxyHandleData(UNCHECKED_PROXY *UProxy, PROXY_HANDLE_DATA_EV_TYPE EVType);
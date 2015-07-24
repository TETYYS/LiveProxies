#pragma once

#include <event2/event.h>
#include <evhtp.h>
#include <event2/bufferevent.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <pthread.h>
#include "ProxyLists.h"

char *RequestString;
char *RequestStringSSL;
evhtp_kvs_t *RequestHeaders;
char *Host4;
char *Host6;

char *Host4SSL;
char *Host6SSL;

struct event_base *levRequestBase;
SSL_CTX *RequestBaseSSLCTX;

void RequestAsync(UNCHECKED_PROXY *UProxy);

void CALLBACK EVEvent(struct bufferevent *BuffEvent, uint16_t Event, UNCHECKED_PROXY *UProxy);
void CALLBACK EVWrite(struct bufferevent *BuffEvent, UNCHECKED_PROXY *UProxy);
void CALLBACK EVRead(struct bufferevent *BuffEvent, UNCHECKED_PROXY *UProxy);
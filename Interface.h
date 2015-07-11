#pragma once

#include <evhttp.h>
#include <pthread.h>
#include "IPv6Map.h"

#define HTTP_AUTHORIZATION_REALM "Live Proxies interface - private access"

typedef struct _AUTH_WEB {
	char *username;
	char *rndVerify;
	uint64_t expiry;
	IPv6Map *ip;
} AUTH_WEB;

typedef struct _AUTH_LOCAL {
	char *username;
	char *password;
} AUTH_LOCAL;

pthread_mutex_t AuthWebLock;
AUTH_WEB **AuthWebList;
size_t AuthWebCount;

pthread_mutex_t AuthLocalLock;
AUTH_LOCAL **AuthLocalList;
size_t AuthLocalCount;

void InterfaceWeb(struct evhttp_request *evRequest, void *arg);
void InterfaceWebUnchecked(struct evhttp_request *evRequest, void *arg);
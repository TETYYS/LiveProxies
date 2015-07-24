#pragma once

#include <evhtp.h>
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
	const char *username;
	const char *password;
} AUTH_LOCAL;

pthread_mutex_t AuthWebLock;
AUTH_WEB **AuthWebList;
size_t AuthWebCount;

pthread_mutex_t AuthLocalLock;
AUTH_LOCAL **AuthLocalList;
size_t AuthLocalCount;

void InterfaceWeb(evhtp_request_t *evRequest, void *arg);
void InterfaceWebUnchecked(evhtp_request_t *evRequest, void *arg);
void InterfaceProxyRecheck(evhtp_request_t *evRequest, void *arg);
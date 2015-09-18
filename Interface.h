#pragma once

#include <pthread.h>
#include <event2/bufferevent.h>
#include "IPv6Map.h"

#define HTTP_AUTHORIZATION_REALM "Live Proxies interface - private access"
#define SIZE_RND_VERIFY 64
#define AUTH_COOKIE "LPAuth"

typedef enum _INTERFACE_PAGES {
	INTERFACE_PAGE_HOME = 0,
	INTERFACE_PAGE_UPROXIES = 1,
	INTERFACE_PAGE_PROXIES = 2,
	INTERFACE_PAGE_PRXSRC = 3,
	INTERFACE_PAGE_STATS = 4,
	INTERFACE_PAGE_RECHECK = 5,
	INTERFACE_PAGE_SPAMHAUS = 6,
	INTERFACE_PAGE_RDNS = 7,
	INTERFACE_PAGE_CHECK = 8,
	INTERFACE_PAGE_ADD = 9,
	INTERFACE_PAGE_TOOLS = 10
} INTERFACE_PAGES;

typedef struct _INTERFACE_PAGE {
	INTERFACE_PAGES page;
	char *name;
} INTERFACE_PAGE;

INTERFACE_PAGE *InterfacePages;
size_t InterfacePagesSize;

typedef struct _INTERFACE_INFO {
	char *user;
	INTERFACE_PAGE *currentPage;
} INTERFACE_INFO;

typedef struct _AUTH_WEB {
	char *username;
	uint8_t *rndVerify;
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

void InterfaceInit();
void InterfaceProxies					(struct bufferevent *BuffEvent, char *Buff);
void InterfaceUncheckedProxies			(struct bufferevent *BuffEvent, char *Buff);
void InterfaceProxyRecheck				(struct bufferevent *BuffEvent, char *Buff);
void InterfaceHome						(struct bufferevent *BuffEvent, char *Buff);
void InterfaceProxySources				(struct bufferevent *BuffEvent, char *Buff);
void InterfaceStats						(struct bufferevent *BuffEvent, char *Buff);
void InterfaceRawSpamhausZen			(struct bufferevent *BuffEvent, char *Buff);
void InterfaceRawReverseDNS				(struct bufferevent *BuffEvent, char *Buff);
void InterfaceRawRecheck				(struct bufferevent *BuffEvent, char *Buff);
void InterfaceRawHttpBL					(struct bufferevent *BuffEvent, char *Buff);
void InterfaceRawUProxyAdd				(struct bufferevent *BuffEvent, char *Buff);
void InterfaceTools						(struct bufferevent *BuffEvent, char *Buff);
void InterfaceRawUProxyAddProcessPost	(struct bufferevent *BuffEvent, char *Buff);
void InterfaceRawGetCustomPage			(struct bufferevent *BuffEvent, char *Buff);
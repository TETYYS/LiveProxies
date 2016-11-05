#include "Interface.h"
#include "ProxyLists.h"
#include "IPv6Map.h"
#include "Global.h"
#include "Logger.h"
#include "Config.h"
#include "Base64.h"
#include "PBKDF2.h"
#include "SingleCheck.h"
#include "HtmlTemplate.h"
#include <event2/buffer.h>
#include <event2/event.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include "Server.h"
#include "Harvester.h"
#include <event2/bufferevent.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>

void InterfaceInit()
{
	InterfacePagesSize = 9;
	InterfacePages = malloc(InterfacePagesSize * sizeof(INTERFACE_PAGE));
	InterfacePages[0].name = "Home";
	InterfacePages[0].page = INTERFACE_PAGE_HOME;
	InterfacePages[1].name = "Unchecked proxies";
	InterfacePages[1].page = INTERFACE_PAGE_UPROXIES;
	InterfacePages[2].name = "Checked proxies";
	InterfacePages[2].page = INTERFACE_PAGE_PROXIES;
	InterfacePages[3].name = "Proxy sources";
	InterfacePages[3].page = INTERFACE_PAGE_PRXSRC;
	InterfacePages[4].name = "Statistics";
	InterfacePages[4].page = INTERFACE_PAGE_STATS;
	InterfacePages[5].name = "Proxy recheck";
	InterfacePages[5].page = INTERFACE_PAGE_RECHECK;
	InterfacePages[6].name = "Tools";
	InterfacePages[6].page = INTERFACE_PAGE_TOOLS;
	InterfacePages[7].name = "CPAGE_RAW";
	InterfacePages[7].page = INTERFACE_PAGE_CPAGE_RAW;
	InterfacePages[8].name = "Settings";
	InterfacePages[8].page = INTERFACE_PAGE_SETTINGS;
}

// Please lock AuthWebLock
static void AuthWebRemove(size_t Index)
{
	free(AuthWebList[Index]->username);
	free(AuthWebList[Index]->rndVerify);
	free(AuthWebList[Index]->ip);
	free(AuthWebList[Index]);
	AuthWebCount--;
	if (AuthWebCount > 0)
		AuthWebList[Index] = AuthWebList[AuthWebCount];
	AuthWebList = realloc(AuthWebList, AuthWebCount * sizeof(*AuthWebList));
}

static bool AuthVerify(char *Buff, struct evbuffer *OutBuff, int Fd, WEB_INTERFACE_INFO *InterfaceInfo, bool AllowOnlyCookie)
{
	InterfaceInfo->user = NULL;
	if (AuthLocalList == NULL) {
		Log(LOG_LEVEL_DEBUG, "AUTH list NULL");
		goto end;
	}

	/* Authorize by cookie */ {
		if (AuthWebList == NULL)
			goto endCookie;

		char *cookie;

		if (!HTTPFindHeader("Cookie: ", Buff, &cookie, NULL, NULL))
			goto endCookie;

		char *lpAuth; // not this is not long pointer
		char *cookieLpAuth = strstr(cookie, AUTH_COOKIE);
		if (cookieLpAuth == NULL)
			goto endCookie;

		char *cookieDelimiter = strchr(cookieLpAuth, '=');
		if (cookieDelimiter == NULL)
			goto endCookie;

		*cookieDelimiter = 0x00;
		lpAuth = cookieDelimiter + 1;
		char *nextCookie = strchr(lpAuth, ';');
		if (nextCookie != NULL)
			nextCookie = 0x00;

		pthread_mutex_lock(&AuthWebLock); {
			for (size_t x = 0; x < AuthWebCount; x++) {
				if (strcmp((const char*)AuthWebList[x]->rndVerify, lpAuth) != 0) {
					if (AuthWebList[x]->expiry < (GetUnixTimestampMilliseconds() / 1000))
						AuthWebRemove(x);
					continue;
				}
				if (AuthWebList[x]->expiry >= (GetUnixTimestampMilliseconds() / 1000)) {
					free(cookie);
					if (!AllowOnlyCookie)
						evbuffer_add(OutBuff, "HTTP/1.1 200 OK\r\nContent-Length: ", 33);
					InterfaceInfo->user = AuthWebList[x]->username;
					AuthWebList[x]->expiry = (size_t)(GetUnixTimestampMilliseconds() / 1000) + AuthLoginExpiry;
					pthread_mutex_unlock(&AuthWebLock);
					return true;
				} else {
					AuthWebRemove(x);
					pthread_mutex_unlock(&AuthWebLock);
					goto endCookie; // Auth token expired
				}
				break;
			}
		} pthread_mutex_unlock(&AuthWebLock);
	} /* End authorize by cookie */
endCookie:

	if (!AllowOnlyCookie) { /* Authorize by login */
		char *username, *password;
		char *authStr;

		Log(LOG_LEVEL_DEBUG, "LOGIN AUTH");

		char *authorization;
		if (HTTPFindHeader("Authorization: ", Buff, &authorization, NULL, NULL)) {
			/* Resolve username:password from authorization header */ {
				char *authStrb64 = strstr(authorization, "Basic ") + (sizeof(char) * 6);

				Log(LOG_LEVEL_DEBUG, "LOGIN AUTH B64 %s", authStrb64);

				if ((size_t)authStrb64 == (sizeof(char) * 6)) {
					free(authorization);
					Log(LOG_LEVEL_DEBUG, "LOGIN AUTH B64 DROP");
					goto end;
				}

				size_t trash;
				if (!Base64Decode(authStrb64, (unsigned char**)(&authStr), &trash)) {
					free(authorization);
					Log(LOG_LEVEL_DEBUG, "LOGIN AUTH B64 DROP");
					goto end;
				}
				free(authorization);

				char *delimiterIndex = strchr(authStr, ':');

				if (delimiterIndex == NULL) {
					free(authStr);
					Log(LOG_LEVEL_DEBUG, "LOGIN AUTH STR DROP");
					goto end;
				}

				password = delimiterIndex + 1;
				*delimiterIndex = 0x00;
				username = authStr;
			}

			pthread_mutex_lock(&AuthLocalLock); {
				for (size_t x = 0; x < AuthLocalCount; x++) {
					if (strcmp(AuthLocalList[x]->username, username) != 0) {
						Log(LOG_LEVEL_DEBUG, "LOGIN AUTH UNAME %s vs %s", AuthLocalList[x]->username, username);
						continue;
					}

					char *saltb64;
					uint8_t *salt;
					size_t saltLen;
					char *firstDelimiter = strchr(AuthLocalList[x]->password, '$');
					char *secondDelimiter = strchr(firstDelimiter + 1, '$');

					size_t iterations = (size_t)atoll(AuthLocalList[x]->password);
					size_t saltb64Len = (secondDelimiter - (firstDelimiter + 1)) * (sizeof(char));

					saltb64 = malloc(saltb64Len + 1 /* NUL */); {
						memcpy(saltb64, firstDelimiter + 1, saltb64Len);
						saltb64[saltb64Len] = 0x00;
						Base64Decode(saltb64, &salt, &saltLen);
					} free(saltb64);

					char *pbkdf2 = PBKDF2_HMAC_SHA_512Ex(password, strlen(password), (char*)salt, saltLen, iterations); // TODO: Possible DoS, needs login limit
					free(salt);

					Log(LOG_LEVEL_DEBUG, "PBKDF2 CMP: %s vs %s", AuthLocalList[x]->password, pbkdf2);

					if (strcmp(AuthLocalList[x]->password, pbkdf2) == 0) {
						pthread_mutex_unlock(&AuthLocalLock);
						free(pbkdf2);

						IPv6Map *ip = GetIPFromHSock(Fd);

						pthread_mutex_lock(&AuthWebLock); {
							for (size_t x = 0; x < AuthWebCount; x++) {
								if (IPv6MapEqual(ip, AuthWebList[x]->ip)) {
									free(ip);
									free(authStr);

									if (AuthWebList[x]->expiry >= (size_t)(GetUnixTimestampMilliseconds() / 1000)) {
										AuthWebList[x]->expiry = (size_t)(GetUnixTimestampMilliseconds() / 1000) + AuthLoginExpiry;
										InterfaceInfo->user = AuthWebList[x]->username;
										pthread_mutex_unlock(&AuthWebLock);
										evbuffer_add(OutBuff, "HTTP/1.1 200 OK\r\nContent-Length: ", 33);
										return true;
									} else {
										AuthWebRemove(x);

										pthread_mutex_unlock(&AuthWebLock);
										goto end; // Auth expired
									}
								} else {
									if (AuthWebList[x]->expiry < (GetUnixTimestampMilliseconds() / 1000)) {
										AuthWebRemove(x);
									}
								}
							}

							if (AuthWebList == NULL)
								AuthWebList = malloc(++AuthWebCount * sizeof(*AuthWebList));

							AuthWebList[AuthWebCount - 1] = malloc(sizeof(AUTH_WEB));
							AuthWebList[AuthWebCount - 1]->expiry = (size_t)(GetUnixTimestampMilliseconds() / 1000) + AuthLoginExpiry;
							AuthWebList[AuthWebCount - 1]->username = malloc(strlen(username) + 1 /* NUL */);
							AuthWebList[AuthWebCount - 1]->ip = ip;
							strcpy(AuthWebList[AuthWebCount - 1]->username, username);
							InterfaceInfo->user = AuthWebList[AuthWebCount - 1]->username;

							free(authStr); // invalidates username and password from headers

							uint8_t randBytes[SIZE_RND_VERIFY];
							RAND_pseudo_bytes(randBytes, SIZE_RND_VERIFY);
							Base64Encode(randBytes, SIZE_RND_VERIFY, (char**)(&(AuthWebList[AuthWebCount - 1]->rndVerify)));

							evbuffer_add_printf(OutBuff, "HTTP/1.1 200 OK\r\nSet-Cookie: "AUTH_COOKIE"=%s\r\nContent-Length: ", AuthWebList[AuthWebCount - 1]->rndVerify);
						} pthread_mutex_unlock(&AuthWebLock);
						return true;
					} else {
						pthread_mutex_unlock(&AuthLocalLock);
						free(pbkdf2);
					}
					break;
				}
			} pthread_mutex_unlock(&AuthLocalLock);

			free(authStr);
		}
	} /* End authorize by login */

end:
	evbuffer_add_printf(OutBuff, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"%s\"\r\nContent-Length: 0\r\n\r\n", HTTP_AUTHORIZATION_REALM);
	return false;
}

void InterfaceHome(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();
	WEB_INTERFACE_INFO info;
	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_HOME)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(headers);
		evbuffer_free(body);
		return;
	}

	HTML_TEMPALTE_TABLE_INFO tableInfo;
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateHead, HtmlTemplateHeadSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateHome, HtmlTemplateHomeSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateFoot, HtmlTemplateFootSize, info, tableInfo);

	evbuffer_add_printf(headers, "%zu", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add(headers, "\r\nContent-Type: text/html\r\n\r\n", 29);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);

	evbuffer_free(headers);
	evbuffer_free(body);
}

void InterfaceProxies(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();
	WEB_INTERFACE_INFO info;
	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_PROXIES)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(headers);
		evbuffer_free(body);
		return;
	}


	HTML_TEMPALTE_TABLE_INFO tableInfo;
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateHead, HtmlTemplateHeadSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateProxies, HtmlTemplateProxiesSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateFoot, HtmlTemplateFootSize, info, tableInfo);

	evbuffer_add_printf(headers, "%zu", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add(headers, "\r\nContent-Type: text/html\r\n\r\n", 29);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);

	evbuffer_free(headers);
	evbuffer_free(body);
}

void InterfaceUncheckedProxies(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();

	WEB_INTERFACE_INFO info;
	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_UPROXIES)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(headers);
		evbuffer_free(body);
		return;
	}


	HTML_TEMPALTE_TABLE_INFO tableInfo;
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateHead, HtmlTemplateHeadSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateUProxies, HtmlTemplateUProxiesSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateFoot, HtmlTemplateFootSize, info, tableInfo);

	evbuffer_add_printf(headers, "%zu", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add(headers, "\r\nContent-Type: text/html\r\n\r\n", 29);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);

	evbuffer_free(headers);
	evbuffer_free(body);
}

void InterfaceProxySources(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();

	WEB_INTERFACE_INFO info;
	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_PRXSRC)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(headers);
		evbuffer_free(body);
		return;
	}


	HTML_TEMPALTE_TABLE_INFO tableInfo;
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateHead, HtmlTemplateHeadSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateProxySources, HtmlTemplateProxySourcesSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateFoot, HtmlTemplateFootSize, info, tableInfo);

	evbuffer_add_printf(headers, "%zu", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add(headers, "\r\nContent-Type: text/html\r\n\r\n", 29);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);

	evbuffer_free(headers);
	evbuffer_free(body);
}

void InterfaceStats(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();

	WEB_INTERFACE_INFO info;
	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_STATS)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(headers);
		evbuffer_free(body);
		return;
	}


	HTML_TEMPALTE_TABLE_INFO tableInfo;
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateHead, HtmlTemplateHeadSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateStats, HtmlTemplateStatsSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateFoot, HtmlTemplateFootSize, info, tableInfo);

	evbuffer_add_printf(headers, "%zu", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add(headers, "\r\nContent-Type: text/html\r\n\r\n", 29);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);

	evbuffer_free(headers);
	evbuffer_free(body);
}

static PROXY *GetProxyFromUidBuff(char *Buff)
{
	char *uidStart = strstr(Buff, "?uid=");
	if (uidStart == NULL)
		return NULL;

	char *uidEnd = strchr(uidStart, '&');
	if (uidEnd == NULL) {
		uidEnd = strchr(uidStart, ' ');
		if (uidEnd == NULL)
			return NULL;
	}

	*uidEnd = 0x00;

	uint8_t *ident;
	size_t len;
	if (!Base64Decode(uidStart + 5, &ident, &len) || len != PROXY_IDENTIFIER_LEN)
		return NULL;

	PROXY *ret = GetProxyByIdentifier(ident);
	free(ident);
	return ret;
}

void InterfaceProxyRecheck(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	WEB_INTERFACE_INFO info;

	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_RECHECK)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(headers);
		return;
	}

	PROXY *proxy = GetProxyFromUidBuff(Buff);

	if (proxy == NULL) {
		bufferevent_write(BuffEvent, "HTTP/1.1 404 Not found\r\nContent-Length: 15\r\n\r\nProxy not found", 61);

		evbuffer_free(headers);
		return;
	}
	if (proxy->rechecking) {
		bufferevent_write(BuffEvent, "HTTP/1.1 403 Forbidden\r\nContent-Length: 18\r\n\r\nAlready rechecking", 64);

		evbuffer_free(headers);
		return;
	}

	struct evbuffer *body = evbuffer_new();

	HTML_TEMPALTE_TABLE_INFO tableInfo;
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateHead, HtmlTemplateHeadSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	tableInfo.tableObject = proxy;
	HtmlTemplateBufferInsert(body, HtmlTemplateCheck, HtmlTemplateCheckSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateFoot, HtmlTemplateFootSize, info, tableInfo);

	evbuffer_add_printf(headers, "%zu", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add(headers, "\r\nContent-Type: text/html\r\n\r\n", 29);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);

	evbuffer_free(headers);
	evbuffer_free(body);
}

void InterfaceRawSpamhausZen(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	WEB_INTERFACE_INFO info;

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(headers);
		BufferEventFreeOnWrite(BuffEvent);
		return;
	}

	PROXY *proxy = GetProxyFromUidBuff(Buff);

	if (proxy == NULL) {
		bufferevent_write(BuffEvent, "HTTP/1.1 404 Not found\r\nContent-Length: 15\r\n\r\nProxy not found", 61);

		evbuffer_free(headers);
		BufferEventFreeOnWrite(BuffEvent);
		return;
	}

	evbuffer_add_printf(headers, "%d", 3); // To Content-Length
	evbuffer_add(headers, "\r\nContent-Type: text/html\r\n\r\n", 29);

	bufferevent_write_buffer(BuffEvent, headers);
	SpamhausZENAsync(proxy->ip, BuffEvent);

	evbuffer_free(headers);
}

void InterfaceRawHttpBL(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	WEB_INTERFACE_INFO info;

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(headers);
		BufferEventFreeOnWrite(BuffEvent);
		return;
	}

	bufferevent_write_buffer(BuffEvent, headers);
	evbuffer_free(headers);

	PROXY *proxy = GetProxyFromUidBuff(Buff);

	if (proxy == NULL) {
		bufferevent_write(BuffEvent, "HTTP/1.1 404 Not found\r\nContent-Length: 15\r\n\r\nProxy not found", 61);

		BufferEventFreeOnWrite(BuffEvent);
		return;
	}

	HTTP_BLAsync(proxy->ip, HttpBLAccessKey, BuffEvent);
}

void InterfaceRawReverseDNS(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();
	WEB_INTERFACE_INFO info;

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(body);
		evbuffer_free(headers);
		return;
	}

	PROXY *proxy = GetProxyFromUidBuff(Buff);

	if (proxy == NULL) {
		bufferevent_write(BuffEvent, "HTTP/1.1 404 Not found\r\nContent-Length: 15\r\n\r\nProxy not found", 61);

		evbuffer_free(body);
		evbuffer_free(headers);
		return;
	}

	char *rDNS = ReverseDNS(proxy->ip);
	if (rDNS == NULL) {
		evbuffer_add(headers, "3", 1); // To Content-Length
		evbuffer_add(body, "N/A", 3);
	} else {
		evbuffer_add_printf(headers, "%zu", strlen(rDNS)); // To Content-Length
		evbuffer_add_reference(body, rDNS, strlen(rDNS), (evbuffer_ref_cleanup_cb)free, rDNS);
	}

	evbuffer_add(headers, "\r\nContent-Type: text/html\r\n\r\n", 29);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);

	evbuffer_free(headers);
	evbuffer_free(body);
}

static void InterfaceRawRecheckStage2(UNCHECKED_PROXY *UProxy)
{
	Log(LOG_LEVEL_DEBUG, "Rechecked proxy");

	struct bufferevent *buffEvent = (struct bufferevent*)UProxy->singleCheckCallbackExtraData;

	if (!UProxy->checkSuccess) {
		Log(LOG_LEVEL_DEBUG, "Proxy NULL");
		bufferevent_write(buffEvent, "20\r\nContent-Type: text/html\r\n\r\n{ \"success\": false }", 51);
		Log(LOG_LEVEL_DEBUG, "BuffEvent free %p", buffEvent);
		BufferEventFreeOnWrite(buffEvent);
		return;
	}

	PROXY *proxy = UProxy->associatedProxy;

	struct evbuffer *http = evbuffer_new();
	struct evbuffer *body = evbuffer_new();
	char anon;
	if (proxy->anonymity == ANONYMITY_TRANSPARENT)
		anon = 't';
	else if (proxy->anonymity == ANONYMITY_ANONYMOUS)
		anon = 'a';
	else if (proxy->anonymity == ANONYMITY_MAX)
		anon = 'm';
	else
		anon = 'n';

	char *identifierb64;
	Base64Encode(proxy->identifier, PROXY_IDENTIFIER_LEN, &identifierb64); {
		char *liveSinceTime = FormatTime(proxy->liveSinceMs); {
			char *lastCheckedTime = FormatTime(proxy->lastCheckedMs); {
				evbuffer_add_printf(body, "{ \"success\": true, \"anonymity\": \"%c\", \"httpTimeoutMs\": %"PRIu64", \"timeoutMs\": %"PRIu64", \"liveSince\": \"%s\", \"lastChecked\": \"%s\", \"retries\": %"PRIu8", \"successfulChecks\": %"PRIu32", \"failedChecks\": %"PRIu32", \"uid\": \"%s\" }", anon, proxy->httpTimeoutMs, proxy->timeoutMs, liveSinceTime, lastCheckedTime, proxy->retries, proxy->successfulChecks, proxy->failedChecks, identifierb64);
			} free(lastCheckedTime);
		} free(liveSinceTime);
	} free(identifierb64);
	evbuffer_add_printf(http, "%zu", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add(http, "\r\nContent-Type: text/html\r\n\r\n", 29);
	bufferevent_write_buffer(buffEvent, http);
	bufferevent_write_buffer(buffEvent, body);
	evbuffer_free(http);
	evbuffer_free(body);

	BufferEventFreeOnWrite(buffEvent);
	return;
}

void InterfaceRawRecheck(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	WEB_INTERFACE_INFO info;

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(headers);
		BufferEventFreeOnWrite(BuffEvent);
		return;
	}

	PROXY *proxy = GetProxyFromUidBuff(Buff);

	if (proxy == NULL) {
		bufferevent_write(BuffEvent, "HTTP/1.1 404 Not found\r\nContent-Length: 15\r\n\r\nProxy not found", 61);

		evbuffer_free(headers);
		BufferEventFreeOnWrite(BuffEvent);
		return;
	}
	if (proxy->rechecking) {
		bufferevent_write(BuffEvent, "HTTP/1.1 403 Forbidden\r\nContent-Length: 18\r\n\r\nAlready rechecking", 64);

		evbuffer_free(headers);
		BufferEventFreeOnWrite(BuffEvent);
		return;
	}

	Recheck(proxy, InterfaceRawRecheckStage2, BuffEvent);

	bufferevent_write_buffer(BuffEvent, headers);
	evbuffer_free(headers);
}

void InterfaceRawUProxyAdd(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();
	WEB_INTERFACE_INFO info;
	IPv6Map *ip;
	ssize_t port;
	PROXY_TYPE type;
	char *offset = &(Buff[8]);

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(headers);
		evbuffer_free(body);
		BufferEventFreeOnWrite(BuffEvent);
		return;
	}

	if (Buff[0] == 'G') {
		char *newLine = strchr(offset, '\n');
		/* IP */ {
			char *ipStart = strstr(offset, "?ip=");
			if (ipStart == NULL) {
				evbuffer_add(body, "Missing ip parameter", 20);
				goto error;
			}
			ipStart += 4;

			if (newLine <= ipStart) {
				evbuffer_add(body, "Malformed request", 17);
				goto error;
			}

			char *ipEnd = strchr(ipStart, '&');
			if (ipEnd == NULL) {
				evbuffer_add(body, "Malformed request", 17);
				goto error;
			}
			char *ipRaw = malloc((ipEnd - ipStart) / sizeof(char) + 1); {
				memcpy(ipRaw, ipStart, ipEnd - ipStart);
				ipRaw[ipEnd - ipStart] = 0x00;

				ip = StringToIPv6Map(ipRaw);
				if (ip == NULL) {
					evbuffer_add(body, "Malformed IP", 12);
					free(ipRaw);
					goto error;
				}
			} free(ipRaw);
			offset = ipEnd;
		} /* End IP */
		/* Port */ {
			char *portStart = strstr(offset, "&port=");
			if (portStart == NULL) {
				evbuffer_add(body, "Missing port parameter", 22);
				goto error;
			}
			portStart += 6;

			if (newLine <= portStart) {
				evbuffer_add(body, "Malformed request", 17);
				goto error;
			}

			port = atoi(portStart);
			if (port > UINT16_MAX) {
				evbuffer_add(body, "Malformed port", 14);
				goto error;
			}
			offset = strstr(portStart, "&");
			if (offset == NULL) {
				evbuffer_add(body, "Malformed request", 17);
				goto error;
			}
		} /* End port */
		/* Type */ {
			char *typeStart = strstr(offset, "&type=");
			if (typeStart == NULL) {
				evbuffer_add(body, "Missing type parameter", 22);
				goto error;
			}
			typeStart += 6;

			if (newLine <= typeStart) {
				evbuffer_add(body, "Malformed request", 17);
				goto error;
			}

			type = atoi(typeStart);
			if (type > PROXY_TYPE_ALL || type <= 0) {
				evbuffer_add(body, "Malformed type", 14);
				goto error;
			}
		} /* end type */

		UProxyAdd(AllocUProxy(ip, (uint16_t)port, type, NULL, NULL));

		evbuffer_add(body, "OK", 2);
		evbuffer_add_printf(headers, "%zu", evbuffer_get_length(body)); // To Content-Length
		evbuffer_add(headers, "\r\nContent-Type: text/html\r\n\r\n", 29);
		bufferevent_write_buffer(BuffEvent, headers);
		bufferevent_write_buffer(BuffEvent, body);
		evbuffer_free(headers);
		evbuffer_free(body);
		BufferEventFreeOnWrite(BuffEvent);
		return;
	} else {
		char *rawLen;
		if (!HTTPFindHeader("Content-Length: ", Buff, &rawLen, NULL, NULL)) {
			evbuffer_add(body, "Invalid request", 15);
			goto error;
		}

		uint64_t len = atoll(rawLen);
		Log(LOG_LEVEL_DEBUG, "Len: %d", len);
		if (len == 0 || len > 5242880) {
			// 5MB
			evbuffer_add(body, "Invalid request", 15);
			goto error;
		}
		uint64_t origLen = strlen(Buff);
		Log(LOG_LEVEL_DEBUG, "origLen: %d", origLen);

		char *content = strstr(Buff, "\r\n\r\n") + (4);
		if ((size_t)content == 4) {
			content = strstr(Buff, "\n\n") + (2);
			if ((size_t)content == 2) {
				evbuffer_add(body, "Invalid request", 15);
				goto error;
			}
		}

		uint64_t packetContentLen = origLen - (content - Buff);
		Log(LOG_LEVEL_DEBUG, "packetContentLen: %d", packetContentLen);
		Log(LOG_LEVEL_DEBUG, "Buff: %s", Buff);
		if (len < packetContentLen) {
			evbuffer_add(body, "Invalid request", 15);
			goto error;
		} else if (len > packetContentLen) {
			char *buffCopy = malloc((origLen + len) + 1);
			memcpy(buffCopy, Buff, origLen + 1);
			
			UPROXY_ADD_PROCESS_POST_PARAMS *params = malloc(sizeof(UPROXY_ADD_PROCESS_POST_PARAMS));
			params->Buff = buffCopy;
			params->ReceivedAllData = false;
			params->BuffLen = origLen;
			
			bufferevent_setwatermark(BuffEvent, EV_READ, (size_t)(len), (size_t)(len)); // Read exactly len
			bufferevent_setcb(BuffEvent, (bufferevent_data_cb)InterfaceRawUProxyAddProcessPost, NULL, NULL, params);
			
			evbuffer_free(headers);
			evbuffer_free(body);
			return;
		} else {
			UPROXY_ADD_PROCESS_POST_PARAMS *params = malloc(sizeof(UPROXY_ADD_PROCESS_POST_PARAMS));
			params->Buff = Buff;
			params->ReceivedAllData = true;
			// BuffLen not used
			InterfaceRawUProxyAddProcessPost(BuffEvent, params);
		}
	}
	goto ok;
error:
	evbuffer_drain(headers, evbuffer_get_length(headers));
	evbuffer_add(headers, "HTTP/1.1 403 Forbidden\r\nContent-Length: ", 40);
ok:
	evbuffer_add_printf(headers, "%zu", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add(headers, "\r\nContent-Type: text/html\r\n\r\n", 29);
	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);
	BufferEventFreeOnWrite(BuffEvent);
	evbuffer_free(headers);
	evbuffer_free(body);
	return;
}

void InterfaceRawUProxyAddProcessPost(struct bufferevent *BuffEvent, UPROXY_ADD_PROCESS_POST_PARAMS *Params)
{
	char *Buff = Params->Buff;
	bool ReceivedAllData = Params->ReceivedAllData;
	
	if (!ReceivedAllData) {
		struct evbuffer *evBuff = bufferevent_get_input(BuffEvent);
		size_t len = evbuffer_get_length(evBuff);
		
		evbuffer_copyout(evBuff, Buff + Params->BuffLen, len);
		Buff[Params->BuffLen + len] = 0x00;
	}
	
	char *content = strstr(Buff, "\r\n\r\n") + 4;
	if ((size_t)content == 4) {
		content = strstr(Buff, "\n\n") + 2;
		if ((size_t)content == 2) {
			goto end;
		}
	}
	// uint64_t contentLen = (content - Buff) / sizeof(char);

	char *tokSave = NULL;
	char *pch = strtok_r(content, "\n", &tokSave);
	size_t added = 0, total = 0;
	PROXY_TYPE curType = PROXY_TYPE_HTTP;
	while (pch != NULL) {
		if (pch[0] == '\0') {
			pch = strtok_r(NULL, "\n", &tokSave);
			continue;
		}

		added += AddProxyHarvesterFormat(pch, &curType);
		total++;

		pch = strtok_r(NULL, "\n", &tokSave);
	}
	
	Log(LOG_LEVEL_SUCCESS, "Added %llu (%llu new) proxies from the interface\n", total, added);

	evbuffer_add_printf(bufferevent_get_output(BuffEvent), "HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n%.4s%.4s", (char*)(&added), (char*)(&total));
	
end:
	if (!ReceivedAllData)
		free(Buff);
	free(Params);
	
	BufferEventFreeOnWrite(BuffEvent);
}

void InterfaceTools(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();

	WEB_INTERFACE_INFO info;
	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_TOOLS)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(headers);
		evbuffer_free(body);
		return;
	}

	HTML_TEMPALTE_TABLE_INFO tableInfo;
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateHead, HtmlTemplateHeadSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateTools, HtmlTemplateToolsSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateFoot, HtmlTemplateFootSize, info, tableInfo);

	evbuffer_add_printf(headers, "%zu", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add(headers, "\r\nContent-Type: text/html\r\n\r\n", 29);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);

	evbuffer_free(headers);
	evbuffer_free(body);
}

static bool InterfaceRawGetCustomPageStage2(UNCHECKED_PROXY *UProxy, UPROXY_CUSTOM_PAGE_STAGE Stage)
{
	Log(LOG_LEVEL_DEBUG, "CustomPage stage 2");
	struct bufferevent *buffEvent = (struct bufferevent*)UProxy->singleCheckCallbackExtraData;

	if (!UProxy->checkSuccess) {
		bufferevent_write(buffEvent, "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 24\r\nContent-Type: text/html\r\n\r\nProxy connection failure", 101);
		Log(LOG_LEVEL_DEBUG, "BuffEvent free %p", buffEvent);
		BufferEventFreeOnWrite(buffEvent);
		return false;
	}

	if (Stage == UPROXY_CUSTOM_PAGE_STAGE_INITIAL_PACKET) {
		bufferevent_write(buffEvent, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: Chunked\r\n\r\n", 72);

		struct evbuffer *head = evbuffer_new(); {
			HTML_TEMPALTE_TABLE_INFO tableInfo;
			memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
			tableInfo.tableObject = 0;
			WEB_INTERFACE_INFO info;

			for (size_t x = 0;x < InterfacePagesSize;x++) {
				if (InterfacePages[x].page == INTERFACE_PAGE_CPAGE_RAW)
					info.currentPage = &(InterfacePages[x]);
			}

			info.user = NULL;
			HtmlTemplateBufferInsert(head, HtmlTemplateCPageRaw, HtmlTemplateCPageRawSize, info, tableInfo);
			Log(LOG_LEVEL_DEBUG, "Head len: %d", evbuffer_get_length(head));

			evbuffer_add_printf(bufferevent_get_output(buffEvent), "%zx\r\n", evbuffer_get_length(head));
			bufferevent_write_buffer(buffEvent, head);
			bufferevent_write(buffEvent, "\r\n", 2);
		} evbuffer_free(head);
	}

	size_t len = evbuffer_get_length(bufferevent_get_input(UProxy->assocBufferEvent));

	char* data = malloc(len + 1); {
		data[len] = 0x00;
		bufferevent_read(UProxy->assocBufferEvent, data, len);
		StrReplaceOrig(&data, "<", "&lt;");
		StrReplaceOrig(&data, ">", "&gt;");

		len = strlen(data);
		evbuffer_add_printf(bufferevent_get_output(buffEvent), "%zx\r\n", len);
		bufferevent_write(buffEvent, data, len);
	} free(data);
	bufferevent_write(buffEvent, "\r\n", 2);

	pthread_mutex_unlock(&(UProxy->processing));

	if (Stage == UPROXY_CUSTOM_PAGE_STAGE_END) {
		struct evbuffer *foot = evbuffer_new(); {
			HTML_TEMPALTE_TABLE_INFO tableInfo;
			memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
			tableInfo.tableObject = (void*)1;
			WEB_INTERFACE_INFO info;

			for (size_t x = 0;x < InterfacePagesSize;x++) {
				if (InterfacePages[x].page == INTERFACE_PAGE_CPAGE_RAW)
					info.currentPage = &(InterfacePages[x]);
			}

			info.user = NULL;
			HtmlTemplateBufferInsert(foot, HtmlTemplateCPageRaw, HtmlTemplateCPageRawSize, info, tableInfo);

			evbuffer_add_printf(bufferevent_get_output(buffEvent), "%zu\r\n", evbuffer_get_length(foot));
			bufferevent_write_buffer(buffEvent, foot);
			bufferevent_write(buffEvent, "\r\n0\r\n\r\n", 7);
		} evbuffer_free(foot);

		Log(LOG_LEVEL_DEBUG, "BuffEvent free %p", buffEvent);

		BufferEventFreeOnWrite(buffEvent);
	}
	return true;
}

static bool InterfaceRawGetCustomPageStage2Render(UNCHECKED_PROXY *UProxy, UPROXY_CUSTOM_PAGE_STAGE Stage)
{
	Log(LOG_LEVEL_DEBUG, "CustomPage stage 2 (render)");
	struct bufferevent *buffEvent = (struct bufferevent*)UProxy->singleCheckCallbackExtraData;
	Log(LOG_LEVEL_DEBUG, "CPAGE %p", buffEvent);

	if (!UProxy->checkSuccess) {
		bufferevent_write(buffEvent, "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 24\r\nContent-Type: text/html\r\n\r\nProxy connection failure", 101);
		Log(LOG_LEVEL_DEBUG, "BuffEvent free %p", buffEvent);
		BufferEventFreeOnWrite(buffEvent);
		return false;
	}

	bufferevent_write_buffer(buffEvent, bufferevent_get_input(UProxy->assocBufferEvent));
	pthread_mutex_unlock(&(UProxy->processing));

	if (Stage == UPROXY_CUSTOM_PAGE_STAGE_END) {
		Log(LOG_LEVEL_DEBUG, "BuffEvent free %p", buffEvent);

		BufferEventFreeOnWrite(buffEvent);
	}
	return true;
}

void InterfaceRawGetCustomPage(struct bufferevent *BuffEvent, char *Buff, bool Render)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();
	WEB_INTERFACE_INFO info;

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(body);
		evbuffer_free(headers);
		BufferEventFreeOnWrite(BuffEvent);
		return;
	}

	char *newLine = strchr(Buff, '\n');

	PROXY *proxy = GetProxyFromUidBuff(Buff);

	if (proxy == NULL) {
		bufferevent_write(BuffEvent, "HTTP/1.1 404 Not found\r\nContent-Length: 15\r\n\r\nProxy not found", 61);

		evbuffer_free(body);
		evbuffer_free(headers);
		BufferEventFreeOnWrite(BuffEvent);
		return;
	}

	char *pageStart = strstr(Buff + (strlen(Buff) + 1), "page="); // That's because GetProxyFromUidBuff puts 0x00 at & or \x20 in path (& in this situation, if page= exists). Search page= at one character from 0x00
	if (pageStart == NULL || pageStart >= newLine) {
		evbuffer_add(body, "Missing page parameter", 22);
		goto fail;
	}

	char *pageEnd = strchr(pageStart, ' ');
	if (pageEnd == NULL) {
		pageEnd = strchr(pageStart, '&');
		if (pageEnd == NULL) {
			evbuffer_add(body, "Malformed request", 17);
			goto fail;
		}
	}

	*pageEnd = 0x00;

	char *postStart = strstr(Buff + (strlen(Buff) + 1), "postData=");

	if (postStart >= newLine)
		postStart = NULL;

	if (postStart != NULL) {
		char *postEnd = strchr(postStart, ' ');
		if (postEnd == NULL) {
			postEnd = strchr(postStart, '&');
			if (postEnd == NULL) {
				evbuffer_add(body, "Malformed request", 17);
				goto fail;
			}
		}
		postStart += sizeof(char) * 9;
		*postEnd = 0x00;

		char *tag = NULL;
		while ((tag = strchr(postStart, '%')) != NULL) {
			char ascii;
			char *tagEnd = tag + 3;
			char end = *tagEnd; {
				ascii = (char)strtol(tag + 1, NULL, 16);
			} *tagEnd = end;

			*tag = ascii;
			char *temp = malloc(strlen(tagEnd) + 1); {
				strcpy(temp, tagEnd);
				strcpy(tag + 1, temp);
			} free(temp);
			// Can't use StrReplaceOrig because tag isn't the original pointer, so realloc fails
		}
		if (strlen(postStart + sizeof(char) * 9) < 1) {
			evbuffer_add(body, "Malformed request", 17);
			goto fail;
		}
	}

	PageRequest(proxy,
				Render ? InterfaceRawGetCustomPageStage2Render : InterfaceRawGetCustomPageStage2,
				pageStart + (sizeof(char) * 5),
				(size_t)postStart != (sizeof(char) * 9) ? postStart : NULL,
				true,
				BuffEvent);

	evbuffer_free(headers);
	evbuffer_free(body);

	return;
fail:
	evbuffer_add_printf(headers, "%zu", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add(headers, "\r\nContent-Type: text/html\r\n\r\n", 29);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);

	evbuffer_free(headers);
	evbuffer_free(body);
	BufferEventFreeOnWrite(BuffEvent);
}

void InterfaceRawMultiRequest(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();
	WEB_INTERFACE_INFO info;

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(body);
		evbuffer_free(headers);
		bufferevent_free(BuffEvent);
		return;
	}

	char *newLine = strchr(Buff, '\n');

	char *postStart = strstr(Buff, "postData=");

	if (postStart == NULL || postStart >= newLine) {
		postStart = NULL;
	}

	char *postEnd = NULL;

	if (postStart != NULL) {
		postEnd = strchr(postStart, '&');
		if (postEnd == NULL) {
			evbuffer_add(body, "Malformed request", 17);
			goto fail;
		}
		postStart += sizeof(char) * 9;
		*postEnd = 0x00;

		char *tag = NULL;
		while ((tag = strchr(postStart, '%')) != NULL) {
			char ascii;
			char *tagEnd = tag + 3;
			char end = *tagEnd; {
				ascii = (char)strtol(tag + 1, NULL, 16);
			} *tagEnd = end;

			*tag = ascii;
			char *temp = malloc(strlen(tagEnd) + 1); {
				strcpy(temp, tagEnd);
				strcpy(tag + 1, temp);
			} free(temp);
			// Can't use StrReplaceOrig because tag isn't the original pointer, so realloc fails
		}
		if (strlen(postStart + sizeof(char) * 9) < 1) {
			evbuffer_add(body, "Malformed request", 17);
			goto fail;
		}
	}

	char *pageStart = strstr(postEnd == NULL ? Buff : postEnd + sizeof(char), "page=");
	if (pageStart == NULL || pageStart >= newLine) {
		evbuffer_add(body, "Missing page parameter", 22);
		goto fail;
	}

	char *pageEnd = strchr(pageStart, ' ');
	if (pageEnd == NULL) {
		evbuffer_add(body, "Malformed request", 17);
		goto fail;
	}

	*pageEnd = 0x00;

	pthread_mutex_lock(&LockCheckedProxies); {
		for (size_t x = 0;x < SizeCheckedProxies;x++)
			PageRequest(CheckedProxies[x], NULL, pageStart + (sizeof(char) * 5), (size_t)postStart != (sizeof(char) * 9) ? postStart : NULL, false,	BuffEvent);
	} pthread_mutex_unlock(&LockCheckedProxies);

	evbuffer_free(headers);
	evbuffer_free(body);

	return;
fail:
	evbuffer_add_printf(headers, "%zu", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add(headers, "\r\nContent-Type: text/html\r\n\r\n", 29);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);

	evbuffer_free(headers);
	evbuffer_free(body);
}

void InterfaceSettings(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();

	WEB_INTERFACE_INFO info;
	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_SETTINGS)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(headers);
		evbuffer_free(body);
		return;
	}

	HTML_TEMPALTE_TABLE_INFO tableInfo;
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateHead, HtmlTemplateHeadSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateSettings, HtmlTemplateSettingsSize, info, tableInfo);
	memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
	HtmlTemplateBufferInsert(body, HtmlTemplateFoot, HtmlTemplateFootSize, info, tableInfo);

	evbuffer_add_printf(headers, "%zu", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add(headers, "\r\nContent-Type: text/html\r\n\r\n", 29);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);

	evbuffer_free(headers);
	evbuffer_free(body);
}

void InterfaceHtmlTemplatesReload(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();

	WEB_INTERFACE_INFO info;

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(headers);
		return;
	}

	pthread_mutex_lock(&AuthWebLock); {
		InterfaceInit();
		HtmlTemplateLoadAll(); // These two must be called in this order
		HtmlTemplateMimeTypesInit(); // These two must be called in this order
	} pthread_mutex_unlock(&AuthWebLock);

	evbuffer_add(headers, "8\r\nContent-Type: text/plain\r\n\r\nReloaded", 39);

	bufferevent_write_buffer(BuffEvent, headers);

	evbuffer_free(headers);
}

void InterfaceRawGetAllProxies(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();
	WEB_INTERFACE_INFO info;

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);

		evbuffer_free(headers);
		bufferevent_free(BuffEvent);
		return;
	}

	pthread_mutex_lock(&LockCheckedProxies); {
		for (size_t x = 0;x < SizeCheckedProxies;x++) {
			char *identifierb64;
			Base64Encode(CheckedProxies[x]->identifier, PROXY_IDENTIFIER_LEN, &identifierb64); {
				evbuffer_add(body, identifierb64, strlen(identifierb64));
				evbuffer_add(body, "\n", 1);
			} free(identifierb64);
		}
	} pthread_mutex_unlock(&LockCheckedProxies);

	evbuffer_add_printf(headers, "%zx\r\nContent-Type: text/plain\r\n\r\n", evbuffer_get_length(body));

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);

	evbuffer_free(headers);
	evbuffer_free(body);
}
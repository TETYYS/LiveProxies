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
#include <assert.h>
#include "Server.h"
#include "Harvester.h"

static char *strnstr(char *Haystack, char *Needle, size_t Size)
{
	if (Size == 0)
		return Haystack;
	size_t needleLength = strlen(Needle);
	assert(Size >= needleLength);
	for (size_t x = 0;x < Size - needleLength;x++) {
		if (strncmp(&(Haystack[x]), Needle, needleLength) == 0)
			return &(Haystack[x]);
	}
	return 0;
}

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
	InterfacePages[6].name = "Raw Spamhaus ZEN output";
	InterfacePages[6].page = INTERFACE_PAGE_SPAMHAUS;
	InterfacePages[7].name = "Raw Reverse DNS output";
	InterfacePages[7].page = INTERFACE_PAGE_RDNS;
	InterfacePages[8].name = "Raw proxy check output";
	InterfacePages[8].page = INTERFACE_PAGE_CHECK;
}

static bool AuthVerify(char *Buff, struct evbuffer *OutBuff, int Fd, INTERFACE_INFO *InterfaceInfo, bool AllowOnlyCookie)
{
	InterfaceInfo->user = NULL;
	if (AuthLocalList == NULL)
		goto end;

	if (!AllowOnlyCookie) { /* Authorize by login */
		char *username, *password;
		char *authStr;

		char *authorization;
		if (ServerFindHeader("Authorization: ", Buff, &authorization, NULL, NULL)) {
			/* Resolve username:password from authorization header */ {
				char *authStrb64 = strstr(authorization, "Basic ") + (sizeof(char) * 6);

				if ((size_t)authStrb64 == (sizeof(char) * 6)) {
					free(authorization);
					goto end;
				}

				size_t trash;
				if (!Base64Decode(authStrb64, (unsigned char**)(&authStr), &trash)) {
					free(authorization);
					goto end;
				}
				free(authorization);

				char *delimiterIndex = strchr(authStr, ':');

				if (delimiterIndex == NULL) {
					free(authStr);
					goto end;
				}

				password = delimiterIndex + (1 * sizeof(char));
				*delimiterIndex = 0x00;
				username = authStr;
			}

			pthread_mutex_lock(&AuthLocalLock); {
				for (size_t x = 0; x < AuthLocalCount; x++) {
					if (strcmp(AuthLocalList[x]->username, username) != 0)
						continue;

					char *saltb64;
					uint8_t *salt;
					size_t saltLen;
					char *firstDelimiter = strchr(AuthLocalList[x]->password, '$');
					char *secondDelimiter = strchr(firstDelimiter + (1 * sizeof(char)), '$');

					size_t iterations = atoll(AuthLocalList[x]->password);
					size_t saltb64Len = (secondDelimiter - (firstDelimiter + 1)) * (sizeof(char));

					saltb64 = malloc(saltb64Len + 1 /* NUL */); {
						memcpy(saltb64, firstDelimiter + (1 * sizeof(char)), saltb64Len);
						saltb64[saltb64Len] = 0x00;
						Base64Decode(saltb64, &salt, &saltLen);
					} free(saltb64);

					char *pbkdf2 = PBKDF2_HMAC_SHA_512Ex(password, strlen(password), salt, saltLen, iterations); // TODO: Possible DoS, needs login limit
					free(salt);

					if (strcmp(AuthLocalList[x]->password, pbkdf2) == 0) {
						free(pbkdf2);

						IPv6Map *ip = GetIPFromHSock(Fd);

						pthread_mutex_lock(&AuthWebLock); {
							for (size_t x = 0; x < AuthWebCount; x++) {
								if (IPv6MapCompare(ip, AuthWebList[x]->ip)) {
									free(ip);
									free(authStr);

									if (AuthWebList[x]->expiry > (GetUnixTimestampMilliseconds() / 1000)) {
										pthread_mutex_unlock(&AuthLocalLock);
										pthread_mutex_unlock(&AuthWebLock);
										evbuffer_add_reference(OutBuff, "HTTP/1.1 200 OK\r\nContent-Length: ", 33 * sizeof(char), NULL, NULL);
										InterfaceInfo->user = AuthWebList[x]->username;
										return true;
									} else {
										free(AuthWebList[x]->username);
										free(AuthWebList[x]->rndVerify);
										free(AuthWebList[x]->ip);
										free(AuthWebList[x]);
										AuthWebList[x] = AuthWebList[AuthWebCount];

										pthread_mutex_unlock(&AuthLocalLock);
										pthread_mutex_unlock(&AuthWebLock);
										goto end; // Auth expired
									}
								}
							}

							if (AuthWebList == NULL)
								AuthWebList = malloc(++AuthWebCount * sizeof(AuthWebList));

							AuthWebList[AuthWebCount - 1] = malloc(sizeof(AUTH_WEB));
							AuthWebList[AuthWebCount - 1]->expiry = (GetUnixTimestampMilliseconds() / 1000) + AuthLoginExpiry;
							AuthWebList[AuthWebCount - 1]->username = malloc(strlen(username) + 1 /* NUL */);
							AuthWebList[AuthWebCount - 1]->ip = ip;
							strcpy(AuthWebList[AuthWebCount - 1]->username, username);
							InterfaceInfo->user = AuthWebList[AuthWebCount - 1]->username;

							free(authStr); // invalidates username and password from headers

							uint8_t randBytes[64];
							RAND_pseudo_bytes(randBytes, 64);
							size_t b64VerifyLen = Base64Encode(randBytes, 64, &(AuthWebList[AuthWebCount - 1]->rndVerify));

							evbuffer_add_printf(OutBuff, "HTTP/1.1 200 OK\r\nSet-Cookie: LPAuth=%s\r\nContent-Length: ", AuthWebList[AuthWebCount - 1]->rndVerify);
						} pthread_mutex_unlock(&AuthWebLock);

						pthread_mutex_unlock(&AuthLocalLock);
						return true;
					} else
						free(pbkdf2);
				}
			} pthread_mutex_unlock(&AuthLocalLock);

			free(authStr);
		}
	} /* End authorize by login */

	/* Authorize by cookie */ {
		if (AuthWebList == NULL)
			goto end;

		char *cookie;

		if (!ServerFindHeader("Cookie: ", Buff, &cookie, NULL, NULL))
			goto end;

		char *lpAuth; // not this is not long pointer
		char *cookieLpAuth = strstr(cookie, "LPAuth");
		if (cookieLpAuth == NULL)
			goto end;

		char *cookieDelimiter = strchr(cookieLpAuth, '=');
		if (cookieDelimiter == NULL)
			goto end;

		*cookieDelimiter = 0x00;
		lpAuth = cookieDelimiter + 1;
		char *nextCookie = strchr(lpAuth, ';');
		if (nextCookie != NULL)
			nextCookie = 0x00;

		pthread_mutex_lock(&AuthWebLock); {
			for (size_t x = 0; x < AuthWebCount; x++) {
				if (strcmp(AuthWebList[x]->rndVerify, lpAuth) != 0)
					continue;
				if (AuthWebList[x]->expiry > (GetUnixTimestampMilliseconds() / 1000)) {
					free(cookie);
					pthread_mutex_unlock(&AuthWebLock);
					if (!AllowOnlyCookie)
						evbuffer_add_reference(OutBuff, "HTTP/1.1 200 OK\r\nContent-Length: ", 33 * sizeof(char), NULL, NULL);
					InterfaceInfo->user = AuthWebList[x]->username;
					return true;
				} else {
					free(cookie);
					free(AuthWebList[x]->username);
					free(AuthWebList[x]->rndVerify);
					free(AuthWebList[x]->ip);
					free(AuthWebList[x]);
					AuthWebList[x] = AuthWebList[AuthWebCount];
					pthread_mutex_unlock(&AuthWebLock);
					goto end; // Auth token expired
				}
			}
		}
	} /* End authorize by cookie */

end:
	evbuffer_add_printf(OutBuff, "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"%s\"\r\nContent-Length: 0\r\n\r\n", HTTP_AUTHORIZATION_REALM);
	return false;
}

static char IntBlock3(size_t Max, size_t In)
{
	if (In <= Max / 3)
		return 'g';
	if (In <= Max / 3 * 2)
		return 'y';
	else
		return 'r';
}

void InterfaceHome(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();
	INTERFACE_INFO info;
	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_HOME)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

		evbuffer_free(headers);
		evbuffer_free(body);
		return;
	}

	if (HtmlTemplateUseStock) {
		evbuffer_add_printf(body, "<html><head><title>LiveProxies %s interface: Home</title></head><body><a href=\"/iface\">Checked proxies</a> <a href=\"/ifaceu\">Unchecked proxies</a></body></html>", VERSION);
	} else {
		HTML_TEMPALTE_TABLE_INFO tableInfo;
		memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
		HtmlTemplateBufferInsert(body, HtmlTemplateHead, HtmlTemplateHeadSize, info, tableInfo);
		memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
		HtmlTemplateBufferInsert(body, HtmlTemplateHome, HtmlTemplateHomeSize, info, tableInfo);
		memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
		HtmlTemplateBufferInsert(body, HtmlTemplateFoot, HtmlTemplateFootSize, info, tableInfo);
	}

	evbuffer_add_printf(headers, "%d", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add_reference(headers, "\r\nContent-Type: text/html\r\n\r\n", 29 * sizeof(char), NULL, NULL);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);
	bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

	evbuffer_free(headers);
	evbuffer_free(body);
}

void InterfaceProxies(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();
	INTERFACE_INFO info;
	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_PROXIES)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

		evbuffer_free(headers);
		evbuffer_free(body);
		return;
	}

	if (HtmlTemplateUseStock) {
		evbuffer_add_printf(body, "<html><head><title>LiveProxies %s interface: Checked proxies</title><style>table{border-collapse:collapse;border:1px solid}\ntd{padding:10px 5px;border:1px solid}\nth{padding:10px 5px;border:1px solid}\ntr .s{background-color:#c0c0c0}\ntr .r{background-color:red}\ntr .y{background-color:GoldenRod}\ntr .g{background-color:green}</style></head><body>", VERSION);

		pthread_mutex_lock(&LockCheckedProxies); {
			evbuffer_add_printf(body, "<center>Checked proxies: %d, currently checking: %d</center><br /><table><tbody><tr><th>IP:Port</th><th>Type</th><th>Country</th><th>Anonymity</th><th>Connection latency (ms)</th><th>HTTP/S latency (ms)</th><th>Live since</th><th>Last checked</th><th>Retries</th><th>Successful checks</th><th>Failed checks</th><th>Full check</th></tr>", SizeCheckedProxies, CurrentlyChecking);

			for (size_t x = 0; x < SizeCheckedProxies; x++) {
				evbuffer_add_reference(body, "<tr>", 4 * sizeof(char), NULL, NULL);

				char *ip = IPv6MapToString2(CheckedProxies[x]->ip); {
					evbuffer_add_printf(body, "<td>%s:%d</td>", ip, CheckedProxies[x]->port);
				} free(ip);
				evbuffer_add_printf(body, "<td>%s</td>", ProxyGetTypeString(CheckedProxies[x]->type));
				evbuffer_add_printf(body, "<td>%s</td>", CheckedProxies[x]->country);

				if (CheckedProxies[x]->anonymity == ANONYMITY_MAX)
					evbuffer_add_reference(body, "<td class=\"g\">Max</td>", 22 * sizeof(char), NULL, NULL);
				else if (CheckedProxies[x]->anonymity == ANONYMITY_ANONYMOUS)
					evbuffer_add_reference(body, "<td class=\"y\">Anonymous</td>", 28 * sizeof(char), NULL, NULL);
				else if (CheckedProxies[x]->anonymity == ANONYMITY_TRANSPARENT)
					evbuffer_add_reference(body, "<td class=\"r\">Transparent</td>", 30 * sizeof(char), NULL, NULL);
				else
					evbuffer_add_reference(body, "<td class=\"n\">N/A</td>", 23 * sizeof(char), NULL, NULL);

				evbuffer_add_printf(body, "<td class=\"%c\">%d</td>", IntBlock3(GlobalTimeout, CheckedProxies[x]->timeoutMs), CheckedProxies[x]->timeoutMs);

				evbuffer_add_printf(body, "<td class=\"%c\">%d</td>", IntBlock3(GlobalTimeout, CheckedProxies[x]->httpTimeoutMs), CheckedProxies[x]->httpTimeoutMs);

				char *time = FormatTime(CheckedProxies[x]->liveSinceMs); {
					evbuffer_add_printf(body, "<td>%s</td>", time);
				} free(time);
				time = FormatTime(CheckedProxies[x]->lastCheckedMs); {
					evbuffer_add_printf(body, "<td>%s</td>", time);
				} free(time);

				evbuffer_add_printf(body, "<td class=\"%c\">%d</td>", IntBlock3(AcceptableSequentialFails, CheckedProxies[x]->retries), CheckedProxies[x]->retries);

				evbuffer_add_printf(body, "<td>%d</td>", CheckedProxies[x]->successfulChecks);
				evbuffer_add_printf(body, "<td>%d</td>", CheckedProxies[x]->failedChecks);

				uint8_t sid[IPV6_SIZE + sizeof(uint16_t) + sizeof(PROXY_TYPE)];
				memcpy(sid, CheckedProxies[x]->ip->Data, IPV6_SIZE);
				*((uint16_t*)(sid + IPV6_SIZE)) = CheckedProxies[x]->port;
				*((PROXY_TYPE*)(sid + IPV6_SIZE + sizeof(uint16_t))) = CheckedProxies[x]->type;

				char *sidb64;
				Base64Encode(sid, IPV6_SIZE + sizeof(uint16_t) + sizeof(PROXY_TYPE), &sidb64); {
					evbuffer_add_printf(body, "<td><a href=\"/recheck?sid=%s\">Check</a></td>", sidb64);
				} free(sidb64);
			}
		} pthread_mutex_unlock(&LockCheckedProxies);

		evbuffer_add_reference(body, "</body></html>\n", 15 * sizeof(char), NULL, NULL);
	} else {
		HTML_TEMPALTE_TABLE_INFO tableInfo;
		memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
		HtmlTemplateBufferInsert(body, HtmlTemplateHead, HtmlTemplateHeadSize, info, tableInfo);
		memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
		HtmlTemplateBufferInsert(body, HtmlTemplateProxies, HtmlTemplateProxiesSize, info, tableInfo);
		memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
		HtmlTemplateBufferInsert(body, HtmlTemplateFoot, HtmlTemplateFootSize, info, tableInfo);
	}

	evbuffer_add_printf(headers, "%d", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add_reference(headers, "\r\nContent-Type: text/html\r\n\r\n", 29 * sizeof(char), NULL, NULL);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);
	bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

	evbuffer_free(headers);
	evbuffer_free(body);
}

void InterfaceUncheckedProxies(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();

	INTERFACE_INFO info;
	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_UPROXIES)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

		evbuffer_free(headers);
		evbuffer_free(body);
		return;
	}

	if (HtmlTemplateUseStock) {
		evbuffer_add_printf(body, "<html><head><title>LiveProxies %s interface: Unchecked proxies</title><style>table{border-collapse:collapse;border:1px solid}\ntd{padding:10px 5px;border:1px solid}\nth{padding:10px 5px;border:1px solid}\ntr .s{background-color:#c0c0c0}\ntr .r{background-color:red}\ntr .y{background-color:GoldenRod}\ntr .g{background-color:green}\nspan#check {display:inline-block;width: 16px;height: 16px;background-image: url('data:image/jpg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAkGBwgHBgkIBwgKCgkLDRYPDQwMDRsUFRAWIB0iIiAdHx8kKDQsJCYxJx8fLT0tMTU3Ojo6Iys/RD84QzQ5Ojf/2wBDAQoKCg0MDRoPDxo3JR8lNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzf/wAARCAAQABADASIAAhEBAxEB/8QAFwAAAwEAAAAAAAAAAAAAAAAAAgUGB//EACgQAAIBAgQDCQAAAAAAAAAAAAECAwQFBhEhUQAyQRIUFSQxQmFisf/EABQBAQAAAAAAAAAAAAAAAAAAAAT/xAAcEQACAQUBAAAAAAAAAAAAAAABQQIAAxESIfD/2gAMAwEAAhEDEQA/ANhW9W5qual70iywglwxyAA5tTpp14n4sR192xHDS2dPJxMDOWUZFM9SxOoOwGu/UKeJ8H+J1S1duljp5mbOYOD2T9xl7v3cH1e2S0UtmoVpaRfl5G5pG3PBcX5z1lwBh+dExfnPU8AYfnX/2Q==');}\nspan#x {display:inline-block;width: 16px;height: 16px;background-image: url('data:image/jpg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBwEBAQEBAQEKCgELDRYPDQwMDRsUCQQKIB0iIiAdHx8kKDQsGBolJx8fLT0tMTU3Li4uIys/OD8sNyg5OisBCgoKDQwNGg8PGislEyUrNzc3Nzc3Nzc3Nzc3Nys3Nzc3NzcrKzcrKzc3Kys3Nzc3Kzc3NzcrKysrNys3Nys3N//AABEIABAAEAMBIgACEQEDEQH/xAAXAAADAQAAAAAAAAAAAAAAAAADBAYB/8QAIxAAAQIGAgIDAAAAAAAAAAAAAQIEBgcIESExEkIJIgMFFP/EABUBAQEAAAAAAAAAAAAAAAAAAAYE/8QAHhEAAAQHAAAAAAAAAAAAAAAAAhES8AABAxMxQYH/2gAMAwEAAhEDEQA/AKJ24rDpBrHi+YkcRkpU/wAkqJWo/iiNnfAA6pGsZQrfIKupZo8rqrar4gWYcqY94zXQb+pJYw8zvkEdknWcrOuIT6ietPIlXZX/AB9KWZEKH4o/T6qBBLP6FnfBB7JO8ZWd2CcYwY1/UHeQWBZYSxg4/JMpZsOIIZ/fM75JPVI3nKDq4ULxGJW0nCaQaUqWQ308Jso//9k=');}</style></head><body>", VERSION);

		pthread_mutex_lock(&LockUncheckedProxies); {
			evbuffer_add_printf(body, "<center>Unchecked proxies: %d, currently checking: %d</center><br /><table><tbody><tr><th>IP:Port</th><th>Type</th>\n<th>Currently checking</th><th>Retries</th><th>Rechecking</th></tr>", SizeUncheckedProxies, CurrentlyChecking);
			for (size_t x = 0; x < SizeUncheckedProxies; x++) {
				evbuffer_add_reference(body, "<tr>", 4 * sizeof(char), NULL, NULL);

				char *ip = IPv6MapToString2(UncheckedProxies[x]->ip); {
					evbuffer_add_printf(body, "<td>%s:%d</td>", ip, UncheckedProxies[x]->port);
				} free(ip);

				evbuffer_add_printf(body, "<td>%s</td>", ProxyGetTypeString(UncheckedProxies[x]->type));
				evbuffer_add_printf(body, "<td><span id=\"%s\"></span></td>", UncheckedProxies[x]->checking ? "check" : "x");

				evbuffer_add_printf(body, "<td class=\"%c\">%d</td>", IntBlock3(AcceptableSequentialFails, UncheckedProxies[x]->retries), UncheckedProxies[x]->retries);
				evbuffer_add_printf(body, "<td><span id=\"%s\"></span></td>", UncheckedProxies[x]->associatedProxy != NULL ? "check" : "x");

				evbuffer_add_reference(body, "</tr>", 5 * sizeof(char), NULL, NULL);
			}
		} pthread_mutex_unlock(&LockUncheckedProxies);

		evbuffer_add_reference(body, "</tbody></table></body></html>", 30 * sizeof(char), NULL, NULL);
	} else {
		HTML_TEMPALTE_TABLE_INFO tableInfo;
		memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
		HtmlTemplateBufferInsert(body, HtmlTemplateHead, HtmlTemplateHeadSize, info, tableInfo);
		memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
		HtmlTemplateBufferInsert(body, HtmlTemplateUProxies, HtmlTemplateUProxiesSize, info, tableInfo);
		memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
		HtmlTemplateBufferInsert(body, HtmlTemplateFoot, HtmlTemplateFootSize, info, tableInfo);
	}

	evbuffer_add_printf(headers, "%d", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add_reference(headers, "\r\nContent-Type: text/html\r\n\r\n", 29 * sizeof(char), NULL, NULL);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);
	bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

	evbuffer_free(headers);
	evbuffer_free(body);
}

void InterfaceProxySources(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();

	INTERFACE_INFO info;
	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_PRXSRC)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

		evbuffer_free(headers);
		evbuffer_free(body);
		return;
	}

	if (HtmlTemplateUseStock) {
		evbuffer_add_printf(body, "<html><head><title>LiveProxies %s interface: Proxy sources</title><style>table{border-collapse:collapse;border:1px solid}\ntd{padding:10px 5px;border:1px solid}\nth{padding:10px 5px;border:1px solid};}</style></head><body>", VERSION);

		pthread_mutex_lock(&LockHarvesterPrxsrcStats); {
			evbuffer_add_printf(body, "<table><tbody><tr><th>Name</th><th>New proxies</th>\n<th>Total proxies</th></tr>", SizeUncheckedProxies, CurrentlyChecking);
			for (size_t x = 0; x < SizeHarvesterPrxsrcStats; x++) {
				evbuffer_add_reference(body, "<tr>", 4 * sizeof(char), NULL, NULL);

				evbuffer_add_printf(body, "<td>%s</td>", HarvesterPrxsrcStats[x].name);
				evbuffer_add_printf(body, "<td>%d</td>", HarvesterPrxsrcStats[x].addedNew);
				evbuffer_add_printf(body, "<td>%d</td>", HarvesterPrxsrcStats[x].added);

				evbuffer_add_reference(body, "</tr>", 5 * sizeof(char), NULL, NULL);
			}
		} pthread_mutex_unlock(&LockHarvesterPrxsrcStats);

		evbuffer_add_reference(body, "</tbody></table></body></html>", 30 * sizeof(char), NULL, NULL);
	} else {
		HTML_TEMPALTE_TABLE_INFO tableInfo;
		memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
		HtmlTemplateBufferInsert(body, HtmlTemplateHead, HtmlTemplateHeadSize, info, tableInfo);
		memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
		HtmlTemplateBufferInsert(body, HtmlTemplateProxySources, HtmlTemplateProxySourcesSize, info, tableInfo);
		memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
		HtmlTemplateBufferInsert(body, HtmlTemplateFoot, HtmlTemplateFootSize, info, tableInfo);
	}

	evbuffer_add_printf(headers, "%d", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add_reference(headers, "\r\nContent-Type: text/html\r\n\r\n", 29 * sizeof(char), NULL, NULL);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);
	bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

	evbuffer_free(headers);
	evbuffer_free(body);
}

void InterfaceStats(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();

	INTERFACE_INFO info;
	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_STATS)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

		evbuffer_free(headers);
		evbuffer_free(body);
		return;
	}

	if (HtmlTemplateUseStock) {
		evbuffer_add_printf(body, "<html><head><title>LiveProxies %s interface: Statistics</title></head><body>Not available in stock version.</body></html>", VERSION);
	} else {
		HTML_TEMPALTE_TABLE_INFO tableInfo;
		memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
		HtmlTemplateBufferInsert(body, HtmlTemplateHead, HtmlTemplateHeadSize, info, tableInfo);
		memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
		HtmlTemplateBufferInsert(body, HtmlTemplateStats, HtmlTemplateStatsSize, info, tableInfo);
		memset(&tableInfo, 0, sizeof(HTML_TEMPALTE_TABLE_INFO));
		HtmlTemplateBufferInsert(body, HtmlTemplateFoot, HtmlTemplateFootSize, info, tableInfo);
	}

	evbuffer_add_printf(headers, "%d", evbuffer_get_length(body)); // To Content-Length
	evbuffer_add_reference(headers, "\r\nContent-Type: text/html\r\n\r\n", 29 * sizeof(char), NULL, NULL);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);
	bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

	evbuffer_free(headers);
	evbuffer_free(body);
}

static void InterfaceProxyRecheckStage2(UNCHECKED_PROXY *UProxy)
{
	Log(LOG_LEVEL_DEBUG, "Rechecked proxy");

	struct bufferevent *buffEvent = (struct bufferevent*)UProxy->singleCheckCallbackExtraData;

	if (!UProxy->checkSuccess) {
		Log(LOG_LEVEL_DEBUG, "Proxy NULL");
		bufferevent_write(buffEvent, "57\r\n<h3 style=\"text-align:center;color:red\"><span id=\"x\"></span> OFFLINE</h3></body></html>\r\n", 93);
		bufferevent_flush(buffEvent, EV_WRITE, BEV_FINISHED);
		bufferevent_free(buffEvent);
		return;
	}

	PROXY *Proxy = UProxy->associatedProxy;

	if (Proxy->anonymity == ANONYMITY_TRANSPARENT)
		bufferevent_write(buffEvent, "44\r\n<p style=\"color:red\"><span id=\"x\"></span> Anonimity: Transparent</p>\r\n", 74);
	else if (Proxy->anonymity == ANONYMITY_ANONYMOUS)
		bufferevent_write(buffEvent, "4b\r\n<p style=\"color:GoldenRod\"><span id=\"warn\"></span> Anonimity: Anonymous</p>\r\n", 81);
	else if (Proxy->anonymity == ANONYMITY_MAX)
		bufferevent_write(buffEvent, "42\r\n<p style=\"color:green\"><span id=\"check\"></span> Anonimity: Max</p>\r\n", 72);
	else
		bufferevent_write(buffEvent, "2a\r\n<p><span id=\"q\"></span> Anonimity: N/A</p>\r\n", 48);

	Log(LOG_LEVEL_DEBUG, "Sent anonimity");
	bufferevent_flush(buffEvent, EV_WRITE, BEV_FLUSH);
	char *rDNS = ReverseDNS(Proxy->ip); {
		SendChunkPrintf(buffEvent, "<p>Reverse DNS: %s</p>", rDNS);
	} free(rDNS);
	bufferevent_flush(buffEvent, EV_WRITE, BEV_FLUSH);
	Log(LOG_LEVEL_DEBUG, "Sent rDNS");

	SPAMHAUS_ZEN_ANSWER zen = SpamhausZEN(Proxy->ip);
	switch (zen) {
		case SBL:
			bufferevent_write(buffEvent, "b5\r\n<p style=\"color:red\"><span id=\"x\"></span> Spamhaus ZEN: <a href=\"http://www.spamhaus.org/sbl/\" target=\"_blank\"><img src=\"http://www.spamhaus.org/images/sbl_badge_hp.gif\" /></a></p>\r\n", 186);
			break;
		case CSS:
			bufferevent_write(buffEvent, "b5\r\n<p style=\"color:red\"><span id=\"x\"></span> Spamhaus ZEN: <a href=\"http://www.spamhaus.org/css/\" target=\"_blank\"><img src=\"http://www.spamhaus.org/images/css_badge_hp.gif\" /></a></p>\r\n", 186);
			break;
		case XBL:
			bufferevent_write(buffEvent, "b5\r\n<p style=\"color:red\"><span id=\"x\"></span> Spamhaus ZEN: <a href=\"http://www.spamhaus.org/xbl/\" target=\"_blank\"><img src=\"http://www.spamhaus.org/images/xbl_badge_hp.gif\" /></a></p>\r\n", 186);
			break;
		case PBL:
			bufferevent_write(buffEvent, "bd\r\n<p style=\"color:GoldenRod\"><span id=\"warn\"></span> Spamhaus ZEN: <a href=\"http://www.spamhaus.org/pbl/\" target=\"_blank\"><img src=\"http://www.spamhaus.org/images/pbl_badge_hp.gif\" /></a></p>\r\n", 195);
			break;
		default:
			bufferevent_write(buffEvent, "47\r\n<p style=\"color:green\"><span id=\"check\"></span> Spamhaus ZEN: CLEAN</p>\r\n", 77);
			break;
	}

	Log(LOG_LEVEL_DEBUG, "Sent Spamhaus ZEN");

	bufferevent_write(buffEvent, "14\r\n</div></body></html>\r\n0\r\n\r\n", 31);

	Log(LOG_LEVEL_DEBUG, "Recheck OK");

	bufferevent_flush(buffEvent, EV_WRITE, BEV_FINISHED);
	bufferevent_free(buffEvent);
	return;
}

static PROXY *GetProxyFromSid(char *Buff)
{
	PROXY *proxy = NULL;

	char *pathStart = strstr(Buff, "?sid=");
	if (pathStart == NULL)
		return NULL;

	char *pathEnd = strchr(pathStart, ' ');
	if (pathEnd == NULL)
		return NULL;

	*pathEnd = 0x00;

	uint8_t *sid;
	size_t len;
	if (!Base64Decode(pathStart + (5 * sizeof(char)), &sid, &len))
		return NULL;
	{
		if (len != IPV6_SIZE + sizeof(uint16_t) + sizeof(PROXY_TYPE)) {
			free(sid);
			return NULL;
		}

		pthread_mutex_lock(&LockCheckedProxies); {
			for (size_t x = 0;x < SizeCheckedProxies;x++) {
				if (memcmp(sid, CheckedProxies[x]->ip->Data, IPV6_SIZE) == 0 && *((uint16_t*)(sid + IPV6_SIZE)) == CheckedProxies[x]->port && *((PROXY_TYPE*)(sid + IPV6_SIZE + sizeof(uint16_t))) == CheckedProxies[x]->type) {
					proxy = CheckedProxies[x];
					break;
				}
			}
		} pthread_mutex_unlock(&LockCheckedProxies);
	} free(sid);

	return proxy;
}

void InterfaceProxyRecheck(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	INTERFACE_INFO info;

	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_RECHECK)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

		evbuffer_free(headers);
		return;
	}

	PROXY *proxy = GetProxyFromSid(Buff);

	if (HtmlTemplateUseStock) {
		if (proxy == NULL) {
			goto fail;
		}

		evbuffer_free(headers);

		bufferevent_write(BuffEvent, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n", 72 * sizeof(char));
		bufferevent_write(BuffEvent, "ac0\r\n<html><head><style type=\"text/css\">span#check {display:inline-block;width: 16px;height: 16px;background-image: url('data:image/jpg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAkGBwgHBgkIBwgKCgkLDRYPDQwMDRsUFRAWIB0iIiAdHx8kKDQsJCYxJx8fLT0tMTU3Ojo6Iys/RD84QzQ5Ojf/2wBDAQoKCg0MDRoPDxo3JR8lNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzf/wAARCAAQABADASIAAhEBAxEB/8QAFwAAAwEAAAAAAAAAAAAAAAAAAgUGB//EACgQAAIBAgQDCQAAAAAAAAAAAAECAwQFBhEhUQAyQRIUFSQxQmFisf/EABQBAQAAAAAAAAAAAAAAAAAAAAT/xAAcEQACAQUBAAAAAAAAAAAAAAABQQIAAxESIfD/2gAMAwEAAhEDEQA/ANhW9W5qual70iywglwxyAA5tTpp14n4sR192xHDS2dPJxMDOWUZFM9SxOoOwGu/UKeJ8H+J1S1duljp5mbOYOD2T9xl7v3cH1e2S0UtmoVpaRfl5G5pG3PBcX5z1lwBh+dExfnPU8AYfnX/2Q==');}\nspan#x {display:inline-block;width: 16px;height: 16px;background-image: url('data:image/jpg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBwEBAQEBAQEKCgELDRYPDQwMDRsUCQQKIB0iIiAdHx8kKDQsGBolJx8fLT0tMTU3Li4uIys/OD8sNyg5OisBCgoKDQwNGg8PGislEyUrNzc3Nzc3Nzc3Nzc3Nys3Nzc3NzcrKzcrKzc3Kys3Nzc3Kzc3NzcrKysrNys3Nys3N//AABEIABAAEAMBIgACEQEDEQH/xAAXAAADAQAAAAAAAAAAAAAAAAADBAYB/8QAIxAAAQIGAgIDAAAAAAAAAAAAAQIEBgcIESExEkIJIgMFFP/EABUBAQEAAAAAAAAAAAAAAAAAAAYE/8QAHhEAAAQHAAAAAAAAAAAAAAAAAhES8AABAxMxQYH/2gAMAwEAAhEDEQA/AKJ24rDpBrHi+YkcRkpU/wAkqJWo/iiNnfAA6pGsZQrfIKupZo8rqrar4gWYcqY94zXQb+pJYw8zvkEdknWcrOuIT6ietPIlXZX/AB9KWZEKH4o/T6qBBLP6FnfBB7JO8ZWd2CcYwY1/UHeQWBZYSxg4/JMpZsOIIZ/fM75JPVI3nKDq4ULxGJW0nCaQaUqWQ308Jso//9k=');}\nspan#warn {display:inline-block;width: 16px;height: 16px;background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAAsVBMVEX////mawj/7QD/5AC8RxLDSRP/6gDmfxD/6AD/5QDwnBP+5gn+3AX/8wD/8QD1t1f/+/T4yWn3wBD/4AD/2AD3uhD//vryrA/+1Afysmzncw/shQ3shxn92yb/4xf/9wDccg//2q7/0oD7wUj93Ib5txr+y3jLbjb/0o3935L8u0r/1qX/zGf6tSD95aX7vlL7uUH94Z7MViL+yQX603X5wSv/1Dn/1lL+y0X/0mX7vTjEy7M8AAAAl0lEQVQYlXWPyQ6CMAAFsQVa9sWyqSgoiIiCsuP/f5goCUuM7zaTuTyK+rNnuuT0kS1N6Cf3OceZn1zjeXCJonM4cXA60vTtFUxB1zFM245JWTVNntd1VQ5sWkVhex4htmV+hWYQcQ0hx0Fd+7DKixADhCQZCLzaC8WArCwhdJAA1pVeIFfgWAAAi+He3fXC2a7GbZzf2297mAwTcOhOqQAAAABJRU5ErkJggg==');}\nspan#q {display:inline-block;width: 16px;height: 16px;background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAAVFBMVEX////x8fFjnM3q6uoESoeIsNRXlMru7u719fV0ptHp8feArNLH0996nbzo6Oi8zNr1+PmXvd7Y3OIbWpFUg6tkjrKoxd660+rD2eyZtc2Tr8iewuBnn7peAAAAoklEQVQYlTVPWxLEIAiLiG9tte/t3v+ei3abD4aEIQFAMCciS2bGgyWFKwLxDGYZPHz/E3xDr0l43JnXD9CM7ItaNy5+Y1EoI12ovnBRN+8Vh4Gt8Kqj8O0RCRbwTnCsm/MQKoJy2hXetVNDqFBa65KlqL4ipl5PA3qYZolV08zrMqkRi9TEVoSpPocBob2nt/Q8Z+iMtcaTzDvJhqy8n3v/A+GkBwY6VTOCAAAAAElFTkSuQmCC');}</style></head><body><div style=\"width:700px;border: 1px solid #000;padding: 20px;display: block;margin-left: auto;margin-right: auto;\"><h2 style=\"text-align:center\">Checking \r\n", 2759);

		char *ip = IPv6MapToString2(proxy->ip); {
			SendChunkPrintf(BuffEvent, "%s:%d (%s)...</h2>", ip, proxy->port, ProxyGetTypeString(proxy->type));
		} free(ip);

		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FLUSH);

		Recheck(proxy, InterfaceProxyRecheckStage2, BuffEvent);

		return;
fail:
		evbuffer_add_printf(headers, "HTTP/1.1 %s\r\nContent-Length: %d\r\n\r\n", "404 Not found", 15);
		bufferevent_write_buffer(BuffEvent, headers);
		bufferevent_write(BuffEvent, "Proxy not found", 15);
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);
		bufferevent_free(BuffEvent);
		evbuffer_free(headers);
	} else {

		if (proxy == NULL) {
			bufferevent_write(BuffEvent, "HTTP/1.1 404 Not found\r\nContent-Length: 15\r\n\r\nProxy not found", 61 * sizeof(char));
			bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

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

		evbuffer_add_printf(headers, "%d", evbuffer_get_length(body)); // To Content-Length
		evbuffer_add_reference(headers, "\r\nContent-Type: text/html\r\n\r\n", 29 * sizeof(char), NULL, NULL);

		bufferevent_write_buffer(BuffEvent, headers);
		bufferevent_write_buffer(BuffEvent, body);
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

		evbuffer_free(headers);
		evbuffer_free(body);
	}
}

void InterfaceRawSpamhausZen(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();
	INTERFACE_INFO info;

	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_RECHECK)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

		evbuffer_free(body);
		evbuffer_free(headers);
		return;
	}

	PROXY *proxy = GetProxyFromSid(Buff);

	if (proxy == NULL) {
		bufferevent_write(BuffEvent, "HTTP/1.1 404 Not found\r\nContent-Length: 15\r\n\r\nProxy not found", 61 * sizeof(char));
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

		evbuffer_free(body);
		evbuffer_free(headers);
		return;
	}

	SPAMHAUS_ZEN_ANSWER zen = SpamhausZEN(proxy->ip);
	switch (zen) {
		case SBL:
			evbuffer_add_reference(body, "sbl", 3 * sizeof(char), NULL, NULL);
			break;
		case CSS:
			evbuffer_add_reference(body, "css", 3 * sizeof(char), NULL, NULL);
			break;
		case XBL:
			evbuffer_add_reference(body, "css", 3 * sizeof(char), NULL, NULL);
			break;
		case PBL:
			evbuffer_add_reference(body, "pbl", 3 * sizeof(char), NULL, NULL);
			break;
		default:
			evbuffer_add_reference(body, "cln", 3 * sizeof(char), NULL, NULL);
			break;
	}

	evbuffer_add_printf(headers, "%d", 3); // To Content-Length
	evbuffer_add_reference(headers, "\r\nContent-Type: text/html\r\n\r\n", 29 * sizeof(char), NULL, NULL);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);
	bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

	evbuffer_free(headers);
	evbuffer_free(body);
}

void InterfaceRawReverseDNS(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	struct evbuffer *body = evbuffer_new();
	INTERFACE_INFO info;

	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_RECHECK)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

		evbuffer_free(body);
		evbuffer_free(headers);
		return;
	}

	PROXY *proxy = GetProxyFromSid(Buff);

	if (proxy == NULL) {
		bufferevent_write(BuffEvent, "HTTP/1.1 404 Not found\r\nContent-Length: 15\r\n\r\nProxy not found", 61 * sizeof(char));
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

		evbuffer_free(body);
		evbuffer_free(headers);
		return;
	}

	char *rDNS = ReverseDNS(proxy->ip);
	evbuffer_add_printf(headers, "%d", strlen(rDNS)); // To Content-Length
	evbuffer_add_reference(body, rDNS, strlen(rDNS), free, rDNS);

	evbuffer_add_reference(headers, "\r\nContent-Type: text/html\r\n\r\n", 29 * sizeof(char), NULL, NULL);

	bufferevent_write_buffer(BuffEvent, headers);
	bufferevent_write_buffer(BuffEvent, body);
	bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

	evbuffer_free(headers);
	evbuffer_free(body);
}

static void InterfaceRawRecheckStage2(UNCHECKED_PROXY *UProxy)
{
	Log(LOG_LEVEL_DEBUG, "Rechecked proxy");

	struct bufferevent *buffEvent = (struct bufferevent*)UProxy->singleCheckCallbackExtraData;

	if (!UProxy->checkSuccess) {
		Log(LOG_LEVEL_DEBUG, "Proxy NULL");
		bufferevent_write(buffEvent, "o", 1 * sizeof(char));
		bufferevent_flush(buffEvent, EV_WRITE, BEV_FINISHED);
		bufferevent_free(buffEvent);
		return;
	}

	PROXY *Proxy = UProxy->associatedProxy;

	if (Proxy->anonymity == ANONYMITY_TRANSPARENT)
		bufferevent_write(buffEvent, "t", 1 * sizeof(char));
	else if (Proxy->anonymity == ANONYMITY_ANONYMOUS)
		bufferevent_write(buffEvent, "a", 1 * sizeof(char));
	else if (Proxy->anonymity == ANONYMITY_MAX)
		bufferevent_write(buffEvent, "m", 1 * sizeof(char));
	else
		bufferevent_write(buffEvent, "n", 1 * sizeof(char));

	Log(LOG_LEVEL_DEBUG, "Sent anonimity");
	Log(LOG_LEVEL_DEBUG, "Recheck OK");

	bufferevent_flush(buffEvent, EV_WRITE, BEV_FINISHED);
	bufferevent_free(buffEvent);
	return;
}

void InterfaceRawRecheck(struct bufferevent *BuffEvent, char *Buff)
{
	struct evbuffer *headers = evbuffer_new();
	INTERFACE_INFO info;

	for (size_t x = 0;x < InterfacePagesSize;x++) {
		if (InterfacePages[x].page == INTERFACE_PAGE_RECHECK)
			info.currentPage = &(InterfacePages[x]);
	}

	if (!AuthVerify(Buff, headers, bufferevent_getfd(BuffEvent), &info, false)) {
		bufferevent_write_buffer(BuffEvent, headers);
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

		evbuffer_free(headers);
		return;
	}

	PROXY *proxy = GetProxyFromSid(Buff);

	if (proxy == NULL) {
		bufferevent_write(BuffEvent, "HTTP/1.1 404 Not found\r\nContent-Length: 15\r\n\r\nProxy not found", 61 * sizeof(char));
		bufferevent_flush(BuffEvent, EV_WRITE, BEV_FINISHED);

		evbuffer_free(headers);
		return;
	}

	Recheck(proxy, InterfaceRawRecheckStage2, BuffEvent);
	evbuffer_add_printf(headers, "%d", 1 * sizeof(char)); // To Content-Length
	evbuffer_add_reference(headers, "\r\nContent-Type: text/html\r\n\r\n", 29 * sizeof(char), NULL, NULL);

	bufferevent_write_buffer(BuffEvent, headers);
	evbuffer_free(headers);
}
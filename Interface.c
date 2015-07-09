#include "Interface.h"
#include "ProxyLists.h"
#include "IPv6Map.h"
#include "Global.h"
#include "Logger.h"
#include "Config.h"
#include "Base64.h"
#include "PBKDF2.h"
#include <event2/buffer.h>
#include <stdlib.h>

bool AuthVerify(struct evhttp_request *evRequest) {
	if (AuthLocalList == NULL)
		return true; // Pass through all users if auth list is empty

	struct evkeyvalq *headers = evhttp_request_get_input_headers(evRequest);
	struct evkeyval *header;

	for (header = headers->tqh_first; header; header = header->next.tqe_next) {
		/* Authorize by login */ {
			char *username, *password;
			char *authStr;

			if (strcmp(header->key, "Authorization") != 0)
				continue;

			/* Resolve username:password from authorization header */ {
				char *authStrb64 = strstr(header->value, "Basic ") + (sizeof(char)* 6);
				if (authStrb64 == (sizeof(char)* 6))
					return false;

				size_t trash;
				if (!Base64Decode(authStrb64, &authStr, &trash))
					return false;


				char *delimiterIndex = strchr(authStr, ':');

				if (delimiterIndex == NULL) {
					free(authStr);
					return false;
				}

				password = delimiterIndex + (1 * sizeof(char));
				*delimiterIndex = 0x00; // Are we allowed to modify inputted headers by evhttp???
				username = authStr;
			}

			sem_wait(&AuthLocalLock); {
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

						sem_wait(&AuthWebLock); {
							char *sIp;
							uint16_t port;
							evhttp_connection_get_peer(evhttp_request_get_connection(evRequest), &sIp, &port);

							for (size_t x = 0; x < AuthWebCount; x++) {
								IPv6Map *ip = StringToIPv6Map(sIp); {
									if (IPv6MapCompare(ip, AuthWebList[x]->ip)) {
										free(ip);
										if (AuthWebList[x]->expiry >(GetUnixTimestampMilliseconds() / 1000)) {
											sem_post(&AuthLocalLock);
											sem_post(&AuthWebLock);
											return true;
										} else {
											free(AuthWebList[x]->username);
											free(AuthWebList[x]->rndVerify);
											free(AuthWebList[x]->ip);
											free(AuthWebList[x]);
											AuthWebList[x] = AuthWebList[AuthWebCount];

											sem_post(&AuthLocalLock);
											sem_post(&AuthWebLock);
											return false; // Auth expired
										}
									}
								} free(ip);
							}

							if (AuthWebList == NULL)
								AuthWebList = malloc(++AuthWebCount * sizeof(AuthWebList));

							AuthWebList[AuthWebCount - 1] = malloc(sizeof(AUTH_WEB));
							AuthWebList[AuthWebCount - 1]->expiry = (GetUnixTimestampMilliseconds() / 1000) + AuthLoginExpiry;
							AuthWebList[AuthWebCount - 1]->username = malloc(strlen(username) + 1 /* NUL */);
							AuthWebList[AuthWebCount - 1]->ip = StringToIPv6Map(sIp);
							strcpy(AuthWebList[AuthWebCount - 1]->username, username);

							free(authStr); // invalidates username and password from headers

							uint8_t randBytes[64];
							RAND_pseudo_bytes(randBytes, 64);
							size_t b64VerifyLen = Base64Encode(randBytes, 64, &(AuthWebList[AuthWebCount - 1]->rndVerify));

							char *cookieFormat = malloc(((7 + b64VerifyLen) * sizeof(char)) + 1 /* NUL */); {
								sprintf(cookieFormat, "LPAuth=%s", AuthWebList[AuthWebCount - 1]->rndVerify);
								evhttp_add_header(evhttp_request_get_output_headers(evRequest), "Set-Cookie", cookieFormat);
							} free(cookieFormat);
						} sem_post(&AuthWebLock);

						sem_post(&AuthLocalLock);
						return true;
					}
					else
						free(pbkdf2);
				}
			} sem_post(&AuthLocalLock);

			free(authStr);
		} /* End authorize by login */

		/* Authorize by cookie */ {
			if (AuthWebList == NULL)
				return false;
			if (strcmp(header->key, "Cookie") != 0)
				continue;

			char *lpAuth; // not this is not long pointer
			char *cookieLpAuth = strstr(header->value, "LPAuth");

			if (cookieLpAuth != NULL) {
				char *cookieDelimiter = strchr(cookieLpAuth, '=');
				if (cookieDelimiter == NULL)
					return false;

				cookieDelimiter = 0x00; // Are we allowed to modify inputted headers by evhttp???
				lpAuth = cookieDelimiter + 1;
				char *nextCookie = strchr(lpAuth, ';');
				if (nextCookie != NULL)
					nextCookie = 0x00; // Are we allowed to modify inputted headers by evhttp???

				sem_wait(&AuthWebLock); {
					for (size_t x = 0; x < AuthWebCount; x++) {
						if (strcmp(AuthWebList[x]->rndVerify, lpAuth) == 0) {
							if (AuthWebList[x]->expiry >(GetUnixTimestampMilliseconds() / 1000))
								return true;
							else {
								free(AuthWebList[x]->username);
								free(AuthWebList[x]->rndVerify);
								free(AuthWebList[x]->ip);
								free(AuthWebList[x]);
								AuthWebList[x] = AuthWebList[AuthWebCount];
								return false; // Auth token expired
							}
						}
					}
				} sem_post(&AuthWebLock);
			}
		} /* End authorize by cookie */
	}

	return false;
}

void InterfaceWeb(struct evhttp_request *evRequest, void *arg) {
	if (!AuthVerify(evRequest)) {
		evhttp_add_header(evhttp_request_get_output_headers(evRequest), "WWW-Authenticate", "Basic realm=\""HTTP_AUTHORIZATION_REALM"\"");
		struct evbuffer *buff = evbuffer_new(); {
			evbuffer_add_reference(buff, "Not Authorized", 14, NULL, NULL);
			evhttp_send_reply(evRequest, 401 /* Forbidden */, "Not Authorized", buff);
		} evbuffer_free(buff);
		return;
	}
	struct evbuffer *buff = evbuffer_new(); {
		evbuffer_add_printf(buff, "<html><head><title>LiveProxies %s interface: Checked proxies</title></head><body>", VERSION);

		sem_wait(&lockCheckedProxies); {
			evbuffer_add_printf(buff, "<center>Checked proxies: %d, currently checking: %d</center><br />", sizeUncheckedProxies, CurrentlyChecking);
			for (size_t x = 0; x < sizeCheckedProxies; x++) {
				char *ip = IPv6MapToString2(checkedProxies[x]->ip); {
					evbuffer_add_printf(buff, "Proxy %s:%d, country %s, timeout %d, HTTP timeout %d, anonimity %s<br />",
						ip,
						checkedProxies[x]->port,
						checkedProxies[x]->country,
						checkedProxies[x]->timeoutMs,
						checkedProxies[x]->httpTimeoutMs,
						(checkedProxies[x]->anonymity == ANONYMITY_TRANSPARENT ? "transparent" :
						(checkedProxies[x]->anonymity == ANONYMITY_ANONYMOUS ? "anonymous" : "max")));
				} free(ip);
			}
		} sem_post(&lockCheckedProxies);

		evbuffer_add_reference(buff, "</body></html>\n", 15, NULL, NULL);

		evhttp_send_reply(evRequest, HTTP_OK, "OK", buff);
	} evbuffer_free(buff);
}

static void IntBlock3(size_t In, size_t *Out1, size_t *Out2) {
	*Out1 = In / 3;
	*Out2 = (In / 3) * 2;
}

void InterfaceWebUnchecked(struct evhttp_request *evRequest, void *arg) {
	if (!AuthVerify(evRequest)) {
		evhttp_add_header(evhttp_request_get_output_headers(evRequest), "WWW-Authenticate", "Basic realm=\""HTTP_AUTHORIZATION_REALM"\"");
		struct evbuffer *buff = evbuffer_new(); {
			evbuffer_add_reference(buff, "Not Authorized", 14, NULL, NULL);
			evhttp_send_reply(evRequest, 401 /* Forbidden */, "Not Authorized", buff);
		} evbuffer_free(buff);
		return;
	}
	struct evbuffer *buff = evbuffer_new(); {
		evbuffer_add_printf(buff, "<html><head><title>LiveProxies %s interface: Unchecked proxies</title></head><body>", VERSION);

		sem_wait(&lockUncheckedProxies); {
			evbuffer_add_printf(buff, "<center>Unchecked proxies: %d, currently checking: %d</center><br />", sizeUncheckedProxies, CurrentlyChecking);
			for (size_t x = 0; x < sizeUncheckedProxies; x++) {
				int lockVal;
				sem_getvalue(&(uncheckedProxies[x]->processing), &lockVal);
				if (lockVal == LOCK_BLOCKED)
					evbuffer_add_reference(buff, "<font color=\"green\">", 20, NULL, NULL);
				else {
					size_t block[2];
					IntBlock3(AcceptableSequentialFails, &(block[0]), &(block[1]));
					if (uncheckedProxies[x]->retries < block[0])
						evbuffer_add_reference(buff, "<font color=\"green\">", 20, NULL, NULL);
					else if (uncheckedProxies[x]->retries > block[0] && uncheckedProxies[x]->retries < block[1])
						evbuffer_add_reference(buff, "<font color=\"yellow\">", 20, NULL, NULL);
					else
						evbuffer_add_reference(buff, "<font color=\"red\">", 17, NULL, NULL);
				}

				char *ip = IPv6MapToString2(uncheckedProxies[x]->ip); {
					evbuffer_add_printf(buff, "Proxy %s:%d, type->%s, checking->%d, retries->%d",
						ip,
						uncheckedProxies[x]->port,
						(uncheckedProxies[x]->type == PROXY_TYPE_HTTP ? "HTTP" :
						(uncheckedProxies[x]->type == PROXY_TYPE_SOCKS4 || uncheckedProxies[x]->type == PROXY_TYPE_SOCKS4A ? "SOCKS4" : "SOCKS5")),
						uncheckedProxies[x]->checking,
						uncheckedProxies[x]->retries);
				} free(ip);

				/*char timeBuff[21];
				memset(timeBuff, 0, 21);
				struct tm *timeinfo;
				time_t timeRaw;*/

				/*if (uncheckedProxies[x]->checking && uncheckedProxies[x]->requestTimeMs != 0) {
					/*timeRaw = uncheckedProxies[x]->requestTimeMs / 1000;

					Log(LOG_LEVEL_DEBUG, "WServer: time_t %d", timeRaw);

					timeinfo = localtime(&timeRaw);

					strftime(timeBuff, 20, "%F %H:%M:%S", timeinfo);

					//evbuffer_add_reference(buff, ", requestTime: ", 15, NULL, NULL);
					//evbuffer_add_reference(buff, timeBuff, 20, NULL, NULL);
					evbuffer_add_printf(buff, ", requestTime: %s", timeBuff);*
					}
					if (uncheckedProxies[x]->requestTimeHttpMs != 0) {
					/*timeRaw = uncheckedProxies[x]->requestTimeHttpMs / 1000;

					localtime_r(&timeRaw, timeinfo);

					strftime(timeBuff, 20, "%F %H:%M:%S", timeinfo);
					evbuffer_add_printf(buff, ", requestTimeHttp: %s", timeBuff);*
					}*/

				if (lockVal == LOCK_BLOCKED)
					evbuffer_add_reference(buff, " <b>PROCESSING</b>", 18, NULL, NULL);

				evbuffer_add_reference(buff, "</font><br />", 13, NULL, NULL);
			}
		} sem_post(&lockUncheckedProxies);

		evbuffer_add_reference(buff, "</body></html>\n", 15, NULL, NULL);

		evhttp_send_reply(evRequest, HTTP_OK, "OK", buff);
	} evbuffer_free(buff);
}
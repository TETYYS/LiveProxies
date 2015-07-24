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
#include <assert.h>

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

bool AuthVerify(evhtp_request_t *evRequest)
{
	if (AuthLocalList == NULL)
		return true; // Pass through all users if auth list is empty

	evhtp_kvs_t *headers = evRequest->headers_in;
	evhtp_kv_t *header;

	for (header = headers->tqh_first; header; header = header->next.tqe_next) {
		/* Authorize by login */ {
			char *username, *password;
			char *authStr;

			if (strncmp(header->key, "Authorization", header->klen) != 0)
				continue;

			/* Resolve username:password from authorization header */ {
				char *authStrb64 = strnstr(header->val, "Basic ", header->vlen) + (sizeof(char)* 6);
				if ((size_t)authStrb64 == (sizeof(char)* 6))
					return false;

				size_t trash;
				if (!Base64Decode(authStrb64, (unsigned char**)(&authStr), &trash))
					return false;


				char *delimiterIndex = strchr(authStr, ':');

				if (delimiterIndex == NULL) {
					free(authStr);
					return false;
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

						pthread_mutex_lock(&AuthWebLock); {
							uint16_t port;
							struct sockaddr *sa = evhtp_request_get_connection(evRequest)->saddr;
							char sIp[IPV6_STRING_SIZE];

							if (evutil_inet_ntop(AF_INET, &(sa->sa_data), sIp, IPV6_STRING_SIZE) == NULL)
								evutil_inet_ntop(AF_INET6, &(sa->sa_data), sIp, IPV6_STRING_SIZE);

							for (size_t x = 0; x < AuthWebCount; x++) {
								IPv6Map *ip = StringToIPv6Map(sIp); {
									if (IPv6MapCompare(ip, AuthWebList[x]->ip)) {
										free(ip);
										free(authStr);

										if (AuthWebList[x]->expiry >(GetUnixTimestampMilliseconds() / 1000)) {
											pthread_mutex_unlock(&AuthLocalLock);
											pthread_mutex_unlock(&AuthWebLock);
											return true;
										} else {
											free(AuthWebList[x]->username);
											free(AuthWebList[x]->rndVerify);
											free(AuthWebList[x]->ip);
											free(AuthWebList[x]);
											AuthWebList[x] = AuthWebList[AuthWebCount];

											pthread_mutex_unlock(&AuthLocalLock);
											pthread_mutex_unlock(&AuthWebLock);
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
								evhtp_headers_add_header(evRequest->headers_out, evhtp_header_new("Set-Cookie", cookieFormat, 0, 1));
							} free(cookieFormat);
						} pthread_mutex_unlock(&AuthWebLock);

						pthread_mutex_unlock(&AuthLocalLock);
						return true;
					} else
						free(pbkdf2);
				}
			} pthread_mutex_unlock(&AuthLocalLock);

			free(authStr);
		} /* End authorize by login */

		/* Authorize by cookie */ {
			if (AuthWebList == NULL)
				return false;
			if (strncmp(header->key, "Cookie", header->klen) != 0)
				continue;

			char *lpAuth; // not this is not long pointer
			char *cookieLpAuth = strnstr(header->val, "LPAuth", header->vlen);

			if (cookieLpAuth != NULL) {
				char *cookieDelimiter = strchr(cookieLpAuth, '=');
				if (cookieDelimiter == NULL)
					return false;

				cookieDelimiter = 0x00;
				lpAuth = cookieDelimiter + 1;
				char *nextCookie = strchr(lpAuth, ';');
				if (nextCookie != NULL)
					nextCookie = 0x00;

				pthread_mutex_lock(&AuthWebLock); {
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
				} pthread_mutex_unlock(&AuthWebLock);
			}
		} /* End authorize by cookie */
	}

	return false;
}

void InterfaceWeb(evhtp_request_t *evRequest, void *arg)
{
	if (!AuthVerify(evRequest)) {
		evhtp_headers_add_header(evRequest->headers_out, evhtp_header_new("WWW-Authenticate", "Basic realm=\""HTTP_AUTHORIZATION_REALM"\"", 0, 0));

		evbuffer_add_reference(evRequest->buffer_out, "Unauthorized", 12, NULL, NULL);
		evhtp_send_reply(evRequest, EVHTP_RES_UNAUTH);
		return;
	}

	evhtp_headers_add_header(evRequest->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
	evbuffer_add_printf(evRequest->buffer_out, "<html><head><title>LiveProxies %s interface: Checked proxies</title></head><body>", VERSION);

	pthread_mutex_lock(&lockCheckedProxies); {
		evbuffer_add_printf(evRequest->buffer_out, "<center>Checked proxies: %d, currently checking: %d</center><br />", sizeUncheckedProxies, CurrentlyChecking);
		for (size_t x = 0; x < sizeCheckedProxies; x++) {
			char *ip = IPv6MapToString2(checkedProxies[x]->ip); {
				evbuffer_add_printf(evRequest->buffer_out, "Proxy %s:%d, type %s, country %s, timeout %d, HTTP timeout %d, anonimity %s<br />",
					ip,
					checkedProxies[x]->port,
					ProxyGetTypeString(checkedProxies[x]->type),
					checkedProxies[x]->country,
					checkedProxies[x]->timeoutMs,
					checkedProxies[x]->httpTimeoutMs,
					(checkedProxies[x]->anonymity == ANONYMITY_TRANSPARENT ? "transparent" :
					(checkedProxies[x]->anonymity == ANONYMITY_ANONYMOUS ? "anonymous" : "max")));
			} free(ip);
		}
	} pthread_mutex_unlock(&lockCheckedProxies);

	evbuffer_add_reference(evRequest->buffer_out, "</body></html>\n", 15, NULL, NULL);

	evhtp_send_reply(evRequest, EVHTP_RES_OK);
}

static void IntBlock3(size_t In, size_t *Out1, size_t *Out2)
{
	*Out1 = In / 3;
	*Out2 = (In / 3) * 2;
}

void InterfaceWebUnchecked(evhtp_request_t *evRequest, void *arg)
{
	if (!AuthVerify(evRequest)) {
		evhtp_headers_add_header(evRequest->headers_out, evhtp_header_new("WWW-Authenticate", "Basic realm=\""HTTP_AUTHORIZATION_REALM"\"", 0, 0));

		evbuffer_add_reference(evRequest->buffer_out, "Unauthorized", 12, NULL, NULL);
		evhtp_send_reply(evRequest, EVHTP_RES_UNAUTH);
		return;
	}

	evhtp_headers_add_header(evRequest->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
	evbuffer_add_printf(evRequest->buffer_out, "<html><head><title>LiveProxies %s interface: Unchecked proxies</title></head><body>", VERSION);

	pthread_mutex_lock(&lockUncheckedProxies); {
		evbuffer_add_printf(evRequest->buffer_out, "<center>Unchecked proxies: %d, currently checking: %d</center><br />", sizeUncheckedProxies, CurrentlyChecking);
		for (size_t x = 0; x < sizeUncheckedProxies; x++) {
			size_t block[2];
			IntBlock3(AcceptableSequentialFails, &(block[0]), &(block[1]));
			if (uncheckedProxies[x]->retries < block[0])
				evbuffer_add_reference(evRequest->buffer_out, "<font color=\"green\">", 20, NULL, NULL);
			else if (uncheckedProxies[x]->retries > block[0] && uncheckedProxies[x]->retries < block[1])
				evbuffer_add_reference(evRequest->buffer_out, "<font color=\"yellow\">", 20, NULL, NULL);
			else
				evbuffer_add_reference(evRequest->buffer_out, "<font color=\"red\">", 17, NULL, NULL);

			char *ip = IPv6MapToString2(uncheckedProxies[x]->ip); {
				evbuffer_add_printf(evRequest->buffer_out, "Proxy %s:%d, type->%s, checking->%d, retries->%d",
					ip,
					uncheckedProxies[x]->port,
					ProxyGetTypeString(uncheckedProxies[x]->type),
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

			evbuffer_add_reference(evRequest->buffer_out, "</font><br />", 13, NULL, NULL);
		}
	} pthread_mutex_unlock(&lockUncheckedProxies);

	evbuffer_add_reference(evRequest->buffer_out, "</body></html>\n", 15, NULL, NULL);

	evhtp_send_reply(evRequest, EVHTP_RES_OK);
}

void WSocketServer()
{

}
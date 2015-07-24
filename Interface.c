#include "Interface.h"
#include "ProxyLists.h"
#include "IPv6Map.h"
#include "Global.h"
#include "Logger.h"
#include "Config.h"
#include "Base64.h"
#include "PBKDF2.h"
#include "SingleCheck.h"
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

static bool AuthVerify(evhtp_request_t *evRequest, bool AllowOnlyCookie)
{
	if (AuthLocalList == NULL)
		return true; // Pass through all users if auth list is empty

	evhtp_kvs_t *headers = evRequest->headers_in;
	evhtp_kv_t *header;

	for (header = headers->tqh_first; header; header = header->next.tqe_next) {
		if (!AllowOnlyCookie) { /* Authorize by login */
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

				*cookieDelimiter = 0x00;
				lpAuth = cookieDelimiter + 1;
				char *nextCookie = strchr(lpAuth, ';');
				if (nextCookie != NULL)
					nextCookie = 0x00;

				pthread_mutex_lock(&AuthWebLock); {
					for (size_t x = 0; x < AuthWebCount; x++) {
						if (strcmp(AuthWebList[x]->rndVerify, lpAuth) == 0) {
							if (AuthWebList[x]->expiry >(GetUnixTimestampMilliseconds() / 1000)) {
								pthread_mutex_unlock(&AuthWebLock);
								return true;
							} else {
								free(AuthWebList[x]->username);
								free(AuthWebList[x]->rndVerify);
								free(AuthWebList[x]->ip);
								free(AuthWebList[x]);
								AuthWebList[x] = AuthWebList[AuthWebCount];
								pthread_mutex_unlock(&AuthWebLock);
								return false; // Auth token expired
							}
						}
					}
				}
			}
		} /* End authorize by cookie */
	}

	return false;
}

static MEM_OUT char *FormatTime(uint64_t TimeMs)
{
	char *timeBuff = malloc(20 * sizeof(char)+1);
	memset(timeBuff, 0, 20 * sizeof(char)+1);
	struct tm *timeinfo;
	time_t timeRaw = TimeMs / 1000;

	timeinfo = localtime(&timeRaw);
	strftime(timeBuff, 20, "%F %H:%M:%S", timeinfo);

	return timeBuff;
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

void InterfaceWeb(evhtp_request_t *evRequest, void *arg)
{
	if (!AuthVerify(evRequest, false)) {
		evhtp_headers_add_header(evRequest->headers_out, evhtp_header_new("WWW-Authenticate", "Basic realm=\""HTTP_AUTHORIZATION_REALM"\"", 0, 0));

		evbuffer_add_reference(evRequest->buffer_out, "Unauthorized", 12, NULL, NULL);
		evhtp_send_reply(evRequest, EVHTP_RES_UNAUTH);
		return;
	}

	evhtp_headers_add_header(evRequest->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
	evbuffer_add_printf(evRequest->buffer_out, "<html><head><title>LiveProxies %s interface: Checked proxies</title><style>table{border-collapse:collapse;border:1px solid}\ntd{padding:10px 5px;border:1px solid}\nth{padding:10px 5px;border:1px solid}\ntr .s{background-color:#c0c0c0}\ntr .r{background-color:red}\ntr .y{background-color:GoldenRod}\ntr .g{background-color:green}</style></head><body>", VERSION);

	pthread_mutex_lock(&lockCheckedProxies); {
		evbuffer_add_printf(evRequest->buffer_out, "<center>Checked proxies: %d, currently checking: %d</center><br /><table><tbody><tr><th>IP:Port</th><th>Type</th><th>Country</th><th>Anonymity</th><th>Connection latency (ms)</th><th>HTTP/S latency (ms)</th><th>Live since</th><th>Last checked</th><th>Retries</th><th>Successful checks</th><th>Failed checks</th><th>Full check</th></tr>", sizeCheckedProxies, CurrentlyChecking);

		for (size_t x = 0; x < sizeCheckedProxies; x++) {
			evbuffer_add_reference(evRequest->buffer_out, "<tr>", 4, NULL, NULL);

			char *ip = IPv6MapToString2(checkedProxies[x]->ip); {
				evbuffer_add_printf(evRequest->buffer_out, "<td>%s:%d</td>", ip, checkedProxies[x]->port);
			} free(ip);
			evbuffer_add_printf(evRequest->buffer_out, "<td>%s</td>", ProxyGetTypeString(checkedProxies[x]->type));
			evbuffer_add_printf(evRequest->buffer_out, "<td>%s</td>", checkedProxies[x]->country);

			if (checkedProxies[x]->anonymity == ANONYMITY_MAX)
				evbuffer_add_reference(evRequest->buffer_out, "<td class=\"g\">Max</td>", 22, NULL, NULL);
			else if (checkedProxies[x]->anonymity == ANONYMITY_ANONYMOUS)
				evbuffer_add_reference(evRequest->buffer_out, "<td class=\"y\">Anonymous</td>", 28, NULL, NULL);
			else if (checkedProxies[x]->anonymity == ANONYMITY_TRANSPARENT)
				evbuffer_add_reference(evRequest->buffer_out, "<td class=\"r\">Transparent</td>", 30, NULL, NULL);
			else
				evbuffer_add_reference(evRequest->buffer_out, "<td class=\"n\">N/A</td>", 23, NULL, NULL);

			evbuffer_add_printf(evRequest->buffer_out, "<td class=\"%c\">%d</td>", IntBlock3(GlobalTimeout, checkedProxies[x]->timeoutMs), checkedProxies[x]->timeoutMs);

			evbuffer_add_printf(evRequest->buffer_out, "<td class=\"%c\">%d</td>", IntBlock3(GlobalTimeout, checkedProxies[x]->httpTimeoutMs), checkedProxies[x]->httpTimeoutMs);

			char *time = FormatTime(checkedProxies[x]->liveSinceMs); {
				evbuffer_add_printf(evRequest->buffer_out, "<td>%s</td>", time);
			} free(time);
			time = FormatTime(checkedProxies[x]->lastCheckedMs); {
				evbuffer_add_printf(evRequest->buffer_out, "<td>%s</td>", time);
			} free(time);

			evbuffer_add_printf(evRequest->buffer_out, "<td class=\"%c\">%d</td>", IntBlock3(AcceptableSequentialFails, checkedProxies[x]->retries), checkedProxies[x]->retries);

			evbuffer_add_printf(evRequest->buffer_out, "<td>%d</td>", checkedProxies[x]->successfulChecks);
			evbuffer_add_printf(evRequest->buffer_out, "<td>%d</td>", checkedProxies[x]->failedChecks);

			uint8_t sid[IPV6_SIZE + sizeof(uint16_t)+sizeof(PROXY_TYPE)];
			memcpy(sid, checkedProxies[x]->ip->Data, IPV6_SIZE);
			*((uint16_t*)(sid + IPV6_SIZE)) = checkedProxies[x]->port;
			*((PROXY_TYPE*)(sid + IPV6_SIZE + sizeof(uint16_t))) = checkedProxies[x]->type;

			char *sidb64;
			Base64Encode(sid, IPV6_SIZE + sizeof(uint16_t)+sizeof(PROXY_TYPE), &sidb64); {
				evbuffer_add_printf(evRequest->buffer_out, "<td><a href=\"/iface/check?sid=%s\">Check</a></td>", sidb64);
			} free(sidb64);
		}
	} pthread_mutex_unlock(&lockCheckedProxies);

	evbuffer_add_reference(evRequest->buffer_out, "</body></html>\n", 15, NULL, NULL);

	evhtp_send_reply(evRequest, EVHTP_RES_OK);
}

void InterfaceWebUnchecked(evhtp_request_t *evRequest, void *arg)
{
	if (!AuthVerify(evRequest, false)) {
		evhtp_headers_add_header(evRequest->headers_out, evhtp_header_new("WWW-Authenticate", "Basic realm=\""HTTP_AUTHORIZATION_REALM"\"", 0, 0));

		evbuffer_add_reference(evRequest->buffer_out, "Unauthorized", 12, NULL, NULL);
		evhtp_send_reply(evRequest, EVHTP_RES_UNAUTH);
		return;
	}

	evhtp_headers_add_header(evRequest->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));
	evbuffer_add_printf(evRequest->buffer_out, "<html><head><title>LiveProxies %s interface: Unchecked proxies</title><style>table{border-collapse:collapse;border:1px solid}\ntd{padding:10px 5px;border:1px solid}\nth{padding:10px 5px;border:1px solid}\ntr .s{background-color:#c0c0c0}\ntr .r{background-color:red}\ntr .y{background-color:GoldenRod}\ntr .g{background-color:green}\nspan#check {display:inline-block;width: 16px;height: 16px;background-image: url('data:image/jpg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAkGBwgHBgkIBwgKCgkLDRYPDQwMDRsUFRAWIB0iIiAdHx8kKDQsJCYxJx8fLT0tMTU3Ojo6Iys/RD84QzQ5Ojf/2wBDAQoKCg0MDRoPDxo3JR8lNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzf/wAARCAAQABADASIAAhEBAxEB/8QAFwAAAwEAAAAAAAAAAAAAAAAAAgUGB//EACgQAAIBAgQDCQAAAAAAAAAAAAECAwQFBhEhUQAyQRIUFSQxQmFisf/EABQBAQAAAAAAAAAAAAAAAAAAAAT/xAAcEQACAQUBAAAAAAAAAAAAAAABQQIAAxESIfD/2gAMAwEAAhEDEQA/ANhW9W5qual70iywglwxyAA5tTpp14n4sR192xHDS2dPJxMDOWUZFM9SxOoOwGu/UKeJ8H+J1S1duljp5mbOYOD2T9xl7v3cH1e2S0UtmoVpaRfl5G5pG3PBcX5z1lwBh+dExfnPU8AYfnX/2Q==');}\nspan#x {display:inline-block;width: 16px;height: 16px;background-image: url('data:image/jpg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBwEBAQEBAQEKCgELDRYPDQwMDRsUCQQKIB0iIiAdHx8kKDQsGBolJx8fLT0tMTU3Li4uIys/OD8sNyg5OisBCgoKDQwNGg8PGislEyUrNzc3Nzc3Nzc3Nzc3Nys3Nzc3NzcrKzcrKzc3Kys3Nzc3Kzc3NzcrKysrNys3Nys3N//AABEIABAAEAMBIgACEQEDEQH/xAAXAAADAQAAAAAAAAAAAAAAAAADBAYB/8QAIxAAAQIGAgIDAAAAAAAAAAAAAQIEBgcIESExEkIJIgMFFP/EABUBAQEAAAAAAAAAAAAAAAAAAAYE/8QAHhEAAAQHAAAAAAAAAAAAAAAAAhES8AABAxMxQYH/2gAMAwEAAhEDEQA/AKJ24rDpBrHi+YkcRkpU/wAkqJWo/iiNnfAA6pGsZQrfIKupZo8rqrar4gWYcqY94zXQb+pJYw8zvkEdknWcrOuIT6ietPIlXZX/AB9KWZEKH4o/T6qBBLP6FnfBB7JO8ZWd2CcYwY1/UHeQWBZYSxg4/JMpZsOIIZ/fM75JPVI3nKDq4ULxGJW0nCaQaUqWQ308Jso//9k=');}</style></head><body>", VERSION);

	pthread_mutex_lock(&lockUncheckedProxies); {
		evbuffer_add_printf(evRequest->buffer_out, "<center>Unchecked proxies: %d, currently checking: %d</center><br /><table><tbody><tr><th>IP:Port</th><th>Type</th>\n<th>Currently checking</th><th>Retries</th><th>Connection latency (ms)</th><th>HTTP/S latency (ms)</th><th>Rechecking</th></tr>", sizeUncheckedProxies, CurrentlyChecking);
		for (size_t x = 0; x < sizeUncheckedProxies; x++) {
			evbuffer_add_reference(evRequest->buffer_out, "<tr>", 4, NULL, NULL);

			char *ip = IPv6MapToString2(uncheckedProxies[x]->ip); {
				evbuffer_add_printf(evRequest->buffer_out, "<td>%s:%d</td>", ip, uncheckedProxies[x]);
			} free(ip);

			evbuffer_add_printf(evRequest->buffer_out, "<td>%s</td>", ProxyGetTypeString(uncheckedProxies[x]->type));
			evbuffer_add_printf(evRequest->buffer_out, "<td><span id=\"%s\"></span></td>", uncheckedProxies[x]->checking ? "check" : "x");

			evbuffer_add_printf(evRequest->buffer_out, "<td class=\"%c\">%d</td>", IntBlock3(AcceptableSequentialFails, uncheckedProxies[x]->retries), uncheckedProxies[x]->retries);
			evbuffer_add_printf(evRequest->buffer_out, "<td class=\"%c\">%d</td>", IntBlock3(AcceptableSequentialFails, uncheckedProxies[x]->requestTimeMs), uncheckedProxies[x]->requestTimeMs != 0 ? uncheckedProxies[x]->requestTimeMs : "N/A");
			evbuffer_add_printf(evRequest->buffer_out, "<td class=\"%c\">%d</td>", IntBlock3(AcceptableSequentialFails, uncheckedProxies[x]->requestTimeHttpMs), uncheckedProxies[x]->requestTimeHttpMs != 0 ? uncheckedProxies[x]->requestTimeHttpMs : "N/A");
			evbuffer_add_printf(evRequest->buffer_out, "<td><span id=\"%s\"></span></td>", uncheckedProxies[x]->associatedProxy != NULL ? "check" : "x");

			evbuffer_add_reference(evRequest->buffer_out, "</tr>", 5, NULL, NULL);
		}
	} pthread_mutex_unlock(&lockUncheckedProxies);

	evbuffer_add_reference(evRequest->buffer_out, "</tbody></table></body></html>", 30, NULL, NULL);

	evhtp_send_reply(evRequest, EVHTP_RES_OK);
}

void InterfaceProxyRecheck(evhtp_request_t *evRequest, void *arg)
{
	if (!AuthVerify(evRequest, true)) {
		evhtp_headers_add_header(evRequest->headers_out, evhtp_header_new("WWW-Authenticate", "Basic realm=\""HTTP_AUTHORIZATION_REALM"\"", 0, 0));

		evbuffer_add_reference(evRequest->buffer_out, "Unauthorized", 12, NULL, NULL);
		evhtp_send_reply(evRequest, EVHTP_RES_UNAUTH);
		return;
	}

	PROXY *proxy = NULL;

	char *sidb64 = evhtp_kv_find(evRequest->uri->query, "sid");

	if (sidb64 == NULL) {
		evhtp_send_reply(evRequest, EVHTP_RES_NACCEPTABLE);
		return;
	}

	uint8_t *sid;
	size_t len;
	Base64Decode(sidb64, &sid, &len); {
		if (len != IPV6_SIZE + sizeof(uint16_t) + sizeof(PROXY_TYPE)) {
			evhtp_send_reply(evRequest, EVHTP_RES_NACCEPTABLE);
			free(sid);
			return;
		}

		pthread_mutex_lock(&lockCheckedProxies); {
			for (size_t x = 0;x < sizeCheckedProxies;x++) {
				if (memcmp(sid, checkedProxies[x]->ip->Data, IPV6_SIZE) == 0 &&	*((uint16_t*)(sid + IPV6_SIZE)) == checkedProxies[x]->port && *((PROXY_TYPE*)(sid + IPV6_SIZE + sizeof(uint16_t))) == checkedProxies[x]->type) {
					proxy = checkedProxies[x];
					break;
				}
			}
		} pthread_mutex_unlock(&lockCheckedProxies);
	} free(sid);

	if (proxy == NULL) {
		evhtp_send_reply(evRequest, EVHTP_RES_NOTFOUND);
		return;
	}

	evhtp_headers_add_header(evRequest->headers_out, evhtp_header_new("Content-Type", "text/html", 0, 0));

	evhtp_send_reply_start(evRequest, EVHTP_RES_OK);

	struct evbuffer *buff = evbuffer_new(); {
		evbuffer_add_reference(buff, "<html><head><style type=\"text/css\">span#check {display:inline-block;width: 16px;height: 16px;background-image: url('data:image/jpg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAkGBwgHBgkIBwgKCgkLDRYPDQwMDRsUFRAWIB0iIiAdHx8kKDQsJCYxJx8fLT0tMTU3Ojo6Iys/RD84QzQ5Ojf/2wBDAQoKCg0MDRoPDxo3JR8lNzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzf/wAARCAAQABADASIAAhEBAxEB/8QAFwAAAwEAAAAAAAAAAAAAAAAAAgUGB//EACgQAAIBAgQDCQAAAAAAAAAAAAECAwQFBhEhUQAyQRIUFSQxQmFisf/EABQBAQAAAAAAAAAAAAAAAAAAAAT/xAAcEQACAQUBAAAAAAAAAAAAAAABQQIAAxESIfD/2gAMAwEAAhEDEQA/ANhW9W5qual70iywglwxyAA5tTpp14n4sR192xHDS2dPJxMDOWUZFM9SxOoOwGu/UKeJ8H+J1S1duljp5mbOYOD2T9xl7v3cH1e2S0UtmoVpaRfl5G5pG3PBcX5z1lwBh+dExfnPU8AYfnX/2Q==');}\nspan#x {display:inline-block;width: 16px;height: 16px;background-image: url('data:image/jpg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEAAkGBwEBAQEBAQEKCgELDRYPDQwMDRsUCQQKIB0iIiAdHx8kKDQsGBolJx8fLT0tMTU3Li4uIys/OD8sNyg5OisBCgoKDQwNGg8PGislEyUrNzc3Nzc3Nzc3Nzc3Nys3Nzc3NzcrKzcrKzc3Kys3Nzc3Kzc3NzcrKysrNys3Nys3N//AABEIABAAEAMBIgACEQEDEQH/xAAXAAADAQAAAAAAAAAAAAAAAAADBAYB/8QAIxAAAQIGAgIDAAAAAAAAAAAAAQIEBgcIESExEkIJIgMFFP/EABUBAQEAAAAAAAAAAAAAAAAAAAYE/8QAHhEAAAQHAAAAAAAAAAAAAAAAAhES8AABAxMxQYH/2gAMAwEAAhEDEQA/AKJ24rDpBrHi+YkcRkpU/wAkqJWo/iiNnfAA6pGsZQrfIKupZo8rqrar4gWYcqY94zXQb+pJYw8zvkEdknWcrOuIT6ietPIlXZX/AB9KWZEKH4o/T6qBBLP6FnfBB7JO8ZWd2CcYwY1/UHeQWBZYSxg4/JMpZsOIIZ/fM75JPVI3nKDq4ULxGJW0nCaQaUqWQ308Jso//9k=');}\nspan#warn {display:inline-block;width: 16px;height: 16px;background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAAsVBMVEX////mawj/7QD/5AC8RxLDSRP/6gDmfxD/6AD/5QDwnBP+5gn+3AX/8wD/8QD1t1f/+/T4yWn3wBD/4AD/2AD3uhD//vryrA/+1Afysmzncw/shQ3shxn92yb/4xf/9wDccg//2q7/0oD7wUj93Ib5txr+y3jLbjb/0o3935L8u0r/1qX/zGf6tSD95aX7vlL7uUH94Z7MViL+yQX603X5wSv/1Dn/1lL+y0X/0mX7vTjEy7M8AAAAl0lEQVQYlXWPyQ6CMAAFsQVa9sWyqSgoiIiCsuP/f5goCUuM7zaTuTyK+rNnuuT0kS1N6Cf3OceZn1zjeXCJonM4cXA60vTtFUxB1zFM245JWTVNntd1VQ5sWkVhex4htmV+hWYQcQ0hx0Fd+7DKixADhCQZCLzaC8WArCwhdJAA1pVeIFfgWAAAi+He3fXC2a7GbZzf2297mAwTcOhOqQAAAABJRU5ErkJggg==');}\nspan#q {display:inline-block;width: 16px;height: 16px;background-image: url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAMAAAAoLQ9TAAAAVFBMVEX////x8fFjnM3q6uoESoeIsNRXlMru7u719fV0ptHp8feArNLH0996nbzo6Oi8zNr1+PmXvd7Y3OIbWpFUg6tkjrKoxd660+rD2eyZtc2Tr8iewuBnn7peAAAAoklEQVQYlTVPWxLEIAiLiG9tte/t3v+ei3abD4aEIQFAMCciS2bGgyWFKwLxDGYZPHz/E3xDr0l43JnXD9CM7ItaNy5+Y1EoI12ovnBRN+8Vh4Gt8Kqj8O0RCRbwTnCsm/MQKoJy2hXetVNDqFBa65KlqL4ipl5PA3qYZolV08zrMqkRi9TEVoSpPocBob2nt/Q8Z+iMtcaTzDvJhqy8n3v/A+GkBwY6VTOCAAAAAElFTkSuQmCC');}</style></head><body><div style=\"width:700px;border: 1px solid #000;padding: 20px;display: block;margin-left: auto;margin-right: auto;\"><h2 style=\"text-align:center\">Checking ",
			2753, NULL, NULL);
		char *ip = IPv6MapToString2(proxy->ip); {
			evbuffer_add_printf(buff, "%s:%d (%s)...</h2>", ip, proxy->port, ProxyGetTypeString(proxy->type));
		} free(ip);

		evhtp_send_reply_body(evRequest, buff);

		proxy = Recheck(proxy);
		Log(LOG_LEVEL_DEBUG, "Rechecked proxy");
		if (proxy == NULL) {
			Log(LOG_LEVEL_DEBUG, "Proxy NULL");
			evbuffer_add_reference(buff, "<h3 style=\"text-align:center;color:red\"><span id=\"x\"></span> OFFLINE</h3></body></html>", 87, NULL, NULL);
			evhtp_send_reply_body(evRequest, buff);
			evhtp_send_reply_end(evRequest);
			evbuffer_free(buff);
			return;
		}

		if (proxy->anonymity == ANONYMITY_TRANSPARENT)
			evbuffer_add_reference(buff, "<p style=\"color:red\"><span id=\"x\"></span> Anonimity: Transparent</p>", 68, NULL, NULL);
		else if (proxy->anonymity == ANONYMITY_ANONYMOUS)
			evbuffer_add_reference(buff, "<p style=\"color:GoldenRod\"><span id=\"warn\"></span> Anonimity: Anonymous</p>", 75, NULL, NULL);
		else if (proxy->anonymity == ANONYMITY_MAX)
			evbuffer_add_reference(buff, "<p style=\"color:green\"><span id=\"check\"></span> Anonimity: Max</p>", 66, NULL, NULL);
		else
			evbuffer_add_reference(buff, "<p><span id=\"q\"></span> Anonimity: N/A</p>", 42, NULL, NULL);
		evhtp_send_reply_body(evRequest, buff);

		Log(LOG_LEVEL_DEBUG, "Sent anonimity");

		evbuffer_add_printf(buff, "<p>Reverse DNS: %s</p>", ReverseDNS(proxy->ip));
		evhtp_send_reply_body(evRequest, buff);

		Log(LOG_LEVEL_DEBUG, "Sent rDNS");

		SPAMHAUS_ZEN_ANSWER zen = SpamhausZEN(proxy->ip);
		switch (zen) {
			case SBL:
				evbuffer_add_reference(buff, "<p style=\"color:red\"><span id=\"x\"></span> Spamhaus ZEN: <a href=\"http://www.spamhaus.org/sbl/\" target=\"_blank\"><img src=\"http://www.spamhaus.org/images/sbl_badge_hp.gif\" /></a></p>", 180, NULL, NULL);
				break;
			case CSS:
				evbuffer_add_reference(buff, "<p style=\"color:red\"><span id=\"x\"></span> Spamhaus ZEN: <a href=\"http://www.spamhaus.org/css/\" target=\"_blank\"><img src=\"http://www.spamhaus.org/images/css_badge_hp.gif\" /></a></p>", 180, NULL, NULL);
				break;
			case XBL:
				evbuffer_add_reference(buff, "<p style=\"color:red\"><span id=\"x\"></span> Spamhaus ZEN: <a href=\"http://www.spamhaus.org/xbl/\" target=\"_blank\"><img src=\"http://www.spamhaus.org/images/xbl_badge_hp.gif\" /></a></p>", 180, NULL, NULL);
				break;
			case PBL:
				evbuffer_add_reference(buff, "<p style=\"color:GoldenRod\"><span id=\"warn\"></span> Spamhaus ZEN: <a href=\"http://www.spamhaus.org/pbl/\" target=\"_blank\"><img src=\"http://www.spamhaus.org/images/pbl_badge_hp.gif\" /></a></p>", 189, NULL, NULL);
				break;
			default:
				evbuffer_add_reference(buff, "<p style=\"color:green\"><span id=\"check\"></span> Spamhaus ZEN: CLEAN</p>", 71, NULL, NULL);
				break;
		}
		evhtp_send_reply_body(evRequest, buff);

		Log(LOG_LEVEL_DEBUG, "Sent Spamhaus ZEN");

		evbuffer_add_reference(buff, "</div></body></html>", 20, NULL, NULL);
		evhtp_send_reply_body(evRequest, buff);

		evhtp_send_reply_end(evRequest);

		Log(LOG_LEVEL_DEBUG, "Recheck OK");
	} evbuffer_free(buff);
}
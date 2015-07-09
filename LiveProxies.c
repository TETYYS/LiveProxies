#include "LiveProxies.h"
#include "WServer.h"
#include "ProxyRequest.h"
#include "GeoIP.h"
#include "ProxyLists.h"
#include "Logger.h"
#include "Global.h"
#include "IPv6Map.h"
#include "Harvester.h"
#include "ProxyRequest.h"
#include "Config.h"
#include "Interface.h"
#include <event2/event.h>
#include <evhttp.h>
#include <pcre.h>
#include <limits.h>
#include <evhttp.h>
#include <libconfig.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <math.h>

static char *StdinDynamic() {
	char *str;
	int ch;
	size_t len = 0;
	size_t size = 16;
	str = malloc(sizeof(char)* size);

	while (EOF != (ch = fgetc(stdin)) && ch != '\n'){
		str[len++] = ch;
		if (len == size) {
			str = realloc(str, sizeof(char)*(size += 16));
			if (!str)return str;
		}
	}
	str[len++] = '\0';

	return realloc(str, sizeof(char)* len);
}

int main(int argc, char** argv) {
	if (argc == 2) {
		printf("Enter username to use for interface:\n");
		char *uname = StdinDynamic();

		printf("Enter password to use for interface:\n");
		char *pbkdf2;
		char *passwd = StdinDynamic(); {
			pbkdf2 = PBKDF2_HMAC_SHA_512(passwd, strlen(passwd));
			memset(passwd, 0, strlen(passwd)); // safety!
		} free(passwd);

		char confirmation;
		do {
			printf("Save to global configuration? [Y/N]:\n");
			confirmation = fgetc(stdin);
		} while (confirmation != 'y' && confirmation != 'Y' && confirmation != 'n' && confirmation != 'N');

		config_t cfg;
		config_init(&cfg);

		bool globalWrite = false;
		if (confirmation == 'y' || confirmation == 'Y')
			globalWrite = true;

		if (globalWrite) {
			if (access("/etc/liveproxies/passwd.conf", F_OK) == -1)
				creat("/etc/liveproxies/passwd.conf", S_IRUSR | S_IWUSR);
			if (config_read_file(&cfg, "/etc/liveproxies/passwd.conf") == CONFIG_FALSE) {
				Log(LOG_LEVEL_ERROR, "Failed to open /etc/liveproxies/passwd.conf, exiting...");
				exit(EXIT_FAILURE);
			}
		}
		else {
			if (access("./passwd.conf", F_OK) == -1)
				creat("./passwd.conf", S_IRUSR | S_IWUSR);
			if (config_read_file(&cfg, "./passwd.conf") == CONFIG_FALSE) {
				Log(LOG_LEVEL_ERROR, "Failed to open ./passwd.conf, exiting...");
				exit(EXIT_FAILURE);
			}
		}

		config_setting_t *cfgRoot = config_root_setting(&cfg);
		config_setting_t *authBlock;

		if ((authBlock = config_setting_get_member(cfgRoot, "Auth")) == NULL)
			authBlock = config_setting_add(cfgRoot, "Auth", CONFIG_TYPE_ARRAY);

		config_setting_t *username = config_setting_add(authBlock, "username", CONFIG_TYPE_STRING);
		config_setting_t *password = config_setting_add(authBlock, "password", CONFIG_TYPE_STRING);
		config_setting_set_string(username, uname);
		config_setting_set_string(password, pbkdf2);

		if (globalWrite)
			config_write_file(&cfg, "/etc/liveproxies/passwd.conf");
		else
			config_write_file(&cfg, "./passwd.conf");

		return 0;
	}
	printf("LiveProxes "VERSION" started\n");

	levRequestBase = event_base_new();

	CurrentlyChecking = 0;
	sizeUncheckedProxies = 0;
	sizeCheckedProxies = 0;

	config_t cfg;
	config_init(&cfg);

	if (config_read_file(&cfg, "liveproxies.conf") == CONFIG_FALSE) {
		Log(LOG_LEVEL_DEBUG, "Failed to open liveproxies.conf in working directory, opening in global...: %s (line %d)", config_error_text(&cfg), config_error_line(&cfg));
	}

	if (config_read_file(&cfg, "/etc/liveproxies/liveproxies.conf") == CONFIG_FALSE) {
		Log(LOG_LEVEL_ERROR, "Failed to open /etc/liveproxies/liveproxies.conf: %s (line %d)", config_error_text(&cfg), config_error_line(&cfg));
		exit(EXIT_FAILURE);
	}

	config_setting_t *cfgRoot = config_root_setting(&cfg);

#define CONFIG_INT64(svar, var, default) if (config_setting_lookup_int64(cfgRoot, svar, &var) == CONFIG_FALSE) { var = default; Log(LOG_LEVEL_ERROR, "Failed to lookup %s, setting to %d...", svar, default); }

	CONFIG_INT64("SimultaneousChecks", SimultaneousChecks, 3000)
		CONFIG_INT64("CheckingInterval", CheckingInterval, 10000)
		CONFIG_INT64("RemoveThreadInterval", RemoveThreadInterval, 300000)
		CONFIG_INT64("GlobalTimeout", GlobalTimeout, 10000)
		CONFIG_INT64("AcceptableSequentialFails", AcceptableSequentialFails, 3)
		CONFIG_INT64("AuthLoginExpiry", AuthLoginExpiry, 10800)

#undef CONFIG_INT64

		if (config_setting_lookup_int(cfgRoot, "ServerPort", &ServerPort) == CONFIG_FALSE) {
			ServerPort = 8080; // 8080 default
			Log(LOG_LEVEL_ERROR, "Failed to lookup ServerPort, setting to 8080...");
		}
		else {
			if (ServerPort > 65535 || ServerPort < 1) {
				Log(LOG_LEVEL_ERROR, "Invalid ServerPort value, setting to 8080...");
				ServerPort = 8080; // 8080 default
			}
		}

		if (config_setting_lookup_string(cfgRoot, "HarvestersPath", &HarvestersPath) == CONFIG_FALSE) {
			Log(LOG_LEVEL_ERROR, "Failed to lookup HarvestersPath, setting to /etc/liveproxies/scripts/...");
			HarvestersPath = "/etc/liveproxies/scripts/";
		}

		if (config_setting_lookup_bool(cfgRoot, "DisableIPv6", &DisableIPv6) == CONFIG_FALSE) {
			Log(LOG_LEVEL_ERROR, "Failed to lookup DisableIPv6, setting to false...");
			DisableIPv6 = false;
		}

		char *globalIp;
		if (config_setting_lookup_string(cfgRoot, "GlobalIp", &globalIp) == CONFIG_FALSE) {
			Log(LOG_LEVEL_ERROR, "Failed to lookup GlobalIp, exiting...");
			exit(EXIT_FAILURE);
		}

		GlobalIp = StringToIPv6Map(globalIp);
		if (GlobalIp == NULL) {
			Log(LOG_LEVEL_ERROR, "Invalid GlobalIp value, exiting...");
			exit(EXIT_FAILURE);
		}
		if (GetIPType(GlobalIp) == IPV6 && DisableIPv6) {
			Log(LOG_LEVEL_ERROR, "Got IPv6 address at GlobalIp, but IPv6 is disabled (DisableIPv6 == true), exiting...");
			exit(EXIT_FAILURE);
		}

		/* Auth init */ {
			config_t cfg;
			config_init(&cfg);
			bool noAuth = false;
			AuthLocalList = NULL;
			AuthLocalCount = 0;

			if (config_read_file(&cfg, "passwd.conf") == CONFIG_FALSE) {
				Log(LOG_LEVEL_DEBUG, "Failed to open passwd.conf in working directory, opening in global...: %s (line %d)", config_error_text(&cfg), config_error_line(&cfg));
				noAuth = true;
			}

			if (noAuth) {
				if (config_read_file(&cfg, "/etc/liveproxies/passwd.conf") == CONFIG_FALSE)
					Log(LOG_LEVEL_DEBUG, "Failed to open /etc/liveproxies/passwd.conf: %s (line %d)", config_error_text(&cfg), config_error_line(&cfg));
				else
					noAuth = false;
			}

			if (!noAuth) {
				sem_init(&AuthLocalLock, false, LOCK_UNBLOCKED);
				config_setting_t *cfgRoot = config_root_setting(&cfg);
				size_t x = 0;
				config_setting_t *currentBlock;

				config_setting_t *Auth = config_setting_get_member(cfgRoot, "Auth");
				if (Auth != NULL) {
					while ((currentBlock = config_setting_get_elem(Auth, x)) != NULL) {
						if (x % 2 == 0) {
							if (AuthLocalList == NULL)
								AuthLocalList = malloc(++AuthLocalCount * sizeof(AuthLocalList));
							else
								AuthLocalList = realloc(AuthLocalList, ++AuthLocalCount * sizeof(AuthLocalList));

							AuthLocalList[AuthLocalCount - 1] = malloc(sizeof(AUTH_LOCAL));

							AuthLocalList[AuthLocalCount - 1]->username = config_setting_get_string(currentBlock);
						} else
							AuthLocalList[AuthLocalCount - 1]->password = config_setting_get_string(currentBlock);
						x++;
					}
				}
			}
			
		} /* End auth init */

		char *ip = IPv6MapToString2(GlobalIp); {
			RequestString = calloc((291 /* :^) */ + strlen(ip) + strlen(VERSION) + 1 + INTEGER_VISIBLE_SIZE(ServerPort)), sizeof(char));
			sprintf(RequestString,
				"GET /prxchk HTTP/1.1\n"
				"Host: %s:%d\n"
				"Connection: Close\n"
				"Cache-Control: max-age=0\n"
				"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n"
				"User-Agent: LiveProxies Proxy Checker %s (tetyys.com)\n"
				"DNT: 1\n"
				"Accept-Encoding: gzip, deflate, sdch\n"
				"Accept-Language: en-US,en;q=0.8\n"
				"LPKey: ", ip, ServerPort, VERSION);

			RequestHeaders = malloc(sizeof(struct evkeyvalq)); // HACK HACK
			RequestHeaders->tqh_first = NULL;
			RequestHeaders->tqh_last = &RequestHeaders->tqh_first;

			char *host = malloc(strlen(ip) + INTEGER_VISIBLE_SIZE(ServerPort) + 1); {
				sprintf(host, "%s:%d", ip, ServerPort);
				evhttp_add_header(RequestHeaders, "Host", host);
			} free(host);
		} free(ip);
		evhttp_add_header(RequestHeaders, "Connection", "Close");
		evhttp_add_header(RequestHeaders, "Cache-Control", "max-age=0");
		evhttp_add_header(RequestHeaders, "Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
		char *ua = malloc(39 + strlen(VERSION) + 1); {
			sprintf(ua, "LiveProxies Proxy Checker %s (tetyys.com)", VERSION);
			evhttp_add_header(RequestHeaders, "User-Agent", ua);
		} free(ua);
		evhttp_add_header(RequestHeaders, "DNT", "1");
		evhttp_add_header(RequestHeaders, "Accept-Encoding", "gzip, deflate, sdch");
		evhttp_add_header(RequestHeaders, "Accept-Language", "en-US,en;q=0.8");

		char *pcreError;
		int pcreErrorOffset;
		char *err;

		ipv6Regex = pcre_compile("(\\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:)))(%.+)?\\s*)", 0, &pcreError, &pcreErrorOffset, NULL); // 👌
		if (ipv6Regex == NULL) {
			Log(LOG_LEVEL_ERROR, "Couldn't compile PCRE IPv6 regex:\n%s at %d", pcreError, pcreErrorOffset);
			return EXIT_FAILURE;
		}
		ipv6RegexEx = pcre_study(ipv6Regex, 0, &err);
		if (err != NULL) {
			Log(LOG_LEVEL_ERROR, "Couldn't study PCRE IPv6 regex");
			return EXIT_FAILURE;
		}

		ipv4Regex = pcre_compile("(\\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\.|$)){4}\\b)", 0, &pcreError, &pcreErrorOffset, NULL); // 👌
		if (ipv4Regex == NULL) {
			Log(LOG_LEVEL_ERROR, "Couldn't compile PCRE IPv4 regex:\n%s at %d", pcreError, pcreErrorOffset);
			return EXIT_FAILURE;
		}
		ipv4RegexEx = pcre_study(ipv4Regex, 0, &err);
		if (err != NULL) {
			Log(LOG_LEVEL_ERROR, "Couldn't study PCRE IPv4 regex");
			return EXIT_FAILURE;
		}

		RAND_pseudo_bytes(&hashSalt, 64);

		sem_init(&lockUncheckedProxies, 0, LOCK_UNBLOCKED);
		sem_init(&lockCheckedProxies, 0, LOCK_UNBLOCKED);

		int status = pthread_create(&harvestThread, NULL, (void*)HarvestLoop, NULL);
		if (status != 0) {
			Log(LOG_LEVEL_ERROR, "HarvestLoop thread creation error, return code: %d\n", status);
			return status;
		}
		pthread_detach(harvestThread);
		Log(LOG_LEVEL_DEBUG, "Started harvest thread");

		status = pthread_create(&removeThread, NULL, (void*)RemoveThread, NULL);
		if (status != 0) {
			Log(LOG_LEVEL_ERROR, "RemoteThread thread creation error, return code: %d\n", status);
			return status;
		}
		pthread_detach(removeThread);
		Log(LOG_LEVEL_DEBUG, "Started remove thread");

		status = pthread_create(&checkThread, NULL, (void*)CheckLoop, NULL);
		if (status != 0) {
			Log(LOG_LEVEL_ERROR, "CheckLoop thread creation error, return code: %d\n", status);
			return status;
		}
		pthread_detach(checkThread);
		Log(LOG_LEVEL_DEBUG, "Started check thread");

		pthread_t serverBase;
		status = pthread_create(&serverBase, NULL, (void*)WServerBase, NULL);
		if (status != 0) {
			Log(LOG_LEVEL_ERROR, "WServerBase thread creation error, return code: %d\n", status);
			return status;
		}
		pthread_detach(serverBase);

		pthread_t requestBase;
		status = pthread_create(&requestBase, NULL, (void*)RequestBase, NULL);
		if (status != 0) {
			Log(LOG_LEVEL_ERROR, "RequestBase thread creation error, return code: %d\n", status);
			return status;
		}
		pthread_detach(requestBase);

		Log(LOG_LEVEL_SUCCESS, "Non-interactive mode active");

		for (;;)
			sleep(INT_MAX);
}

void RequestBase() {
	for (;;) {
		if (sizeUncheckedProxies > 0)
			event_base_dispatch(levRequestBase);
		usleep(10000);
	}
}

void CheckLoop() {
	Log(LOG_LEVEL_DEBUG, "CheckLoop: Start");
	for (;;) {
		size_t count = 0;
		UNCHECKED_PROXY **proxiesToCheck = NULL;

		Log(LOG_LEVEL_DEBUG, "CheckLoop: Waiting for UProxy list lock...");
		sem_wait(&lockUncheckedProxies); {
			Log(LOG_LEVEL_DEBUG, "CheckLoop: Looping through UProxies...");

			for (size_t x = 0; x < sizeUncheckedProxies; x++) {
				if (CurrentlyChecking > SimultaneousChecks)
					break;
				if (!(uncheckedProxies[x]->checking)) {
					if (proxiesToCheck == NULL)
						proxiesToCheck = malloc(sizeof(proxiesToCheck));
					else
						proxiesToCheck = realloc(proxiesToCheck, (count + 1) * sizeof(proxiesToCheck));
					proxiesToCheck[count++] = uncheckedProxies[x];
				}
				else
					Log(LOG_LEVEL_DEBUG, "CheckLoop: Proxy %d discard", x);
			}
		} sem_post(&lockUncheckedProxies);

		for (size_t x = 0; x < count; x++) {
			proxiesToCheck[x]->checking = true;
			Log(LOG_LEVEL_DEBUG, "CheckLoop: Proxy %d set checking", x);
			RequestAsync(proxiesToCheck[x]);
		}

		free(proxiesToCheck);
		count = 0;

		Log(LOG_LEVEL_DEBUG, "CheckLoop: Sleeping... (%d)", CurrentlyChecking);
		msleep(CheckingInterval);
	}
}
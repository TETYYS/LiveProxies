#define _GNU_SOURCE

#include "LiveProxies.h"
#include "ProxyRequest.h"
#include "GeoIP.h"
#include "ProxyLists.h"
#include "Logger.h"
#include "Global.h"
#include "IPv6Map.h"
#include "Harvester.h"
#include "Config.h"
#include "Interface.h"
#include "PBKDF2.h"
#include "Server.h"
#include "Stats.h"
#include "HtmlTemplate.h"
#include "Websocket.h"

#include <event2/event.h>
#include <event2/thread.h>
#include <event2/dns.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/conf.h>

#include <pcre.h>
#include <limits.h>
#include <libconfig.h>
#include <stdio.h>
#include <unistd.h>
#include <math.h>
#include <fcntl.h>
#include <pthread.h>
#include <assert.h>

#include <curl/curl.h>

static char *StdinDynamic()
{
	char *str;
	int ch;
	size_t len = 0;
	size_t size = 16;
	str = malloc(sizeof(char)* size);

	while (EOF != (ch = fgetc(stdin)) && ch != '\n') {
		str[len++] = ch;
		if (len == size) {
			str = realloc(str, sizeof(char)*(size += 16));
			if (!str)return str;
		}
	}
	str[len++] = '\0';

	return realloc(str, sizeof(char)* len);
}

static char *HostFormat(IPv6Map *Ip, uint16_t Port)
{
	char *ret = IPv6MapToString2(Ip);
	size_t len = strlen(ret);
	ret = realloc(ret, (sizeof(char)* (len + INTEGER_VISIBLE_SIZE(Port) + 1 /* : between ip and port */)) + 1 /* NUL */);
	char *hostFormat = malloc((sizeof(char)* len) + 1); {
		memcpy(hostFormat, ret, (sizeof(char)* len) + 1);
		sprintf(ret, "%s:%d", hostFormat, Port);
	} free(hostFormat);
	ret[len + 1 + (size_t)INTEGER_VISIBLE_SIZE(Port)] = 0x00;
	return ret;
}

static void EvLog(int Level, char *Format, va_list VA)
{
	Log(Level, Format, VA);
}

int main(int argc, char** argv)
{
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
		} else {
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
#if DEBUG
	#define MMDB_DEBUG 1
	printf("========================DEBUG========================\n");
	//evthread_enable_lock_debugging();
	//event_enable_debug_mode();
	//event_set_log_callback((event_log_cb)EvLog);
	//event_enable_debug_logging(EVENT_DBG_ALL);
#endif

	if (access("/etc/liveproxies/passwd.conf", F_OK) == -1 && access("./passwd.conf", F_OK) == -1)
		Log(LOG_LEVEL_WARNING, "No credentials present for interface pages. Access blocked by default.");

	curl_global_init(CURL_GLOBAL_ALL);
	evthread_use_pthreads();
	AuthWebList = NULL;
	pthread_mutex_init(&AuthWebLock, NULL);
	pthread_mutex_init(&WebSocketUnfinishedPacketsLock, NULL);
	pthread_mutex_init(&WebSocketSubscribedClientsLock, NULL);
	AuthWebCount = 0;
	levRequestBase = event_base_new();
	levRequestDNSBase = evdns_base_new(levRequestBase, 1);
	CurrentlyChecking = 0;
	SizeUncheckedProxies = 0;
	SizeCheckedProxies = 0;
	WebSocketUnfinishedPackets = NULL;
	WebSocketUnfinishedPacketsSize = 0;
	WebSocketSubscribedClients = NULL;
	WebSocketSubscribedClientsSize = 0;
	InterfaceInit();
	HtmlTemplateLoadAll(); // These two must be called in this order
	HtmlTemplateMimeTypesInit(); // These two must be called in this order

	int status = MMDB_open("/usr/local/share/GeoIP/GeoLite2-Country.mmdb", MMDB_MODE_MMAP, &GeoIPDB);

	if (status != MMDB_SUCCESS) {
		Log(LOG_LEVEL_ERROR, "Can't open GeoLite2 database /usr/local/share/GeoIP/GeoLite2-Country.mmdb - %s", MMDB_strerror(status));
		exit(1);
	}

	config_t cfg;
	config_init(&cfg);

	if (config_read_file(&cfg, "liveproxies.conf") == CONFIG_FALSE) {
		Log(LOG_LEVEL_DEBUG, "Failed to open liveproxies.conf in working directory, opening in global...: %s (line %d)", config_error_text(&cfg), config_error_line(&cfg));

		if (config_read_file(&cfg, "/etc/liveproxies/liveproxies.conf") == CONFIG_FALSE) {
			Log(LOG_LEVEL_ERROR, "Failed to open /etc/liveproxies/liveproxies.conf: %s (line %d)", config_error_text(&cfg), config_error_line(&cfg));
			exit(EXIT_FAILURE);
		}
	}

	config_setting_t *cfgRoot = config_root_setting(&cfg);

#define CONFIG_INT64(cfg, svar, var, default) if (config_setting_lookup_int64(cfg, svar, (long long*)(&var)) == CONFIG_FALSE) { var = default; Log(LOG_LEVEL_ERROR, "Failed to lookup %s, setting to %d...", svar, default); }
#define CONFIG_INT(cfg, svar, var, default) if (config_setting_lookup_int(cfg, svar, (int*)(&var)) == CONFIG_FALSE) { var = default; Log(LOG_LEVEL_ERROR, "Failed to lookup %s, setting to %d...", svar, default); }
#define CONFIG_STRING(cfg, svar, var, default) const char *val_##var; if (config_setting_lookup_string(cfg, svar, &(val_##var)) == CONFIG_FALSE) { var = default; Log(LOG_LEVEL_ERROR, "Failed to lookup %s, setting to %s...", svar, default); } else { var = malloc((strlen(val_##var) * sizeof(char)) + 1); strcpy(var, (val_##var)); }
#define CONFIG_BOOL(cfg, svar, var, default) if (config_setting_lookup_bool(cfg, svar, (int*)(&var)) == CONFIG_FALSE) { var = default; Log(LOG_LEVEL_ERROR, "Failed to lookup %s, setting to %d...", svar, default); }

	CONFIG_INT64(cfgRoot, "SimultaneousChecks", SimultaneousChecks, 3000)
	CONFIG_INT64(cfgRoot, "CheckingInterval", CheckingInterval, 10000)
	CONFIG_INT64(cfgRoot, "RemoveThreadInterval", RemoveThreadInterval, 300000)
	CONFIG_INT64(cfgRoot, "GlobalTimeout", GlobalTimeout, 10000)
	CONFIG_INT64(cfgRoot, "AcceptableSequentialFails", AcceptableSequentialFails, 3)
	CONFIG_INT64(cfgRoot, "AuthLoginExpiry", AuthLoginExpiry, 10800)
	CONFIG_INT64(cfgRoot, "ProxySourcesBacklog", ProxySourcesBacklog, 20)
	CONFIG_INT(cfgRoot, "ServerPort", ServerPort, 8084)
	CONFIG_INT(cfgRoot, "ServerPortUDP", ServerPortUDP, 8084)
	CONFIG_BOOL(cfgRoot, "EnableUDP", EnableUDP, true)
	CONFIG_STRING(cfgRoot, "HarvestersPath", HarvestersPath, "/etc/liveproxies/scripts/")
	CONFIG_STRING(cfgRoot, "HttpBLAccessKey", HttpBLAccessKey, "")

	CONFIG_STRING(cfgRoot, "RequestHeaderKey", RequestHeaderKey, "LPKey")
	CONFIG_STRING(cfgRoot, "RequestUA", RequestUA, "LiveProxies proxy checker {VERSION} (tetyys.com/liveproxies)")
	StrReplaceOrig(&RequestUA, "{VERSION}", VERSION);
	StrReplaceOrig(&RequestUA, "{KEY_NAME}", RequestHeaderKey);

	GlobalTimeoutTV.tv_sec = GlobalTimeout / 1000;
	GlobalTimeoutTV.tv_usec = (GlobalTimeout % 1000) * 1000;

	if (HttpBLAccessKey[0] == 0x00)
		Log(LOG_LEVEL_WARNING, "Project HoneyPot Http:BL access key is not present. Get one at www.projecthoneypot.org/httpbl_configure.php or Http:BL lookups will be disabled.");

	/* SSL */ {
		config_setting_t *sslGroup = config_setting_get_member(cfgRoot, "SSL");

		CONFIG_BOOL(sslGroup, "Enable", SSLEnabled, false)
		CONFIG_STRING(sslGroup, "Private", SSLPrivateKey, "/etc/liveproxies/private.key")
		CONFIG_STRING(sslGroup, "Public", SSLPublicKey, "/etc/liveproxies/public.cer")
		CONFIG_STRING(sslGroup, "CipherList", SSLCipherList, "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH")
		CONFIG_INT(sslGroup, "ServerPort", SSLServerPort, 8085)

		if (SSLEnabled) {
			SSL_load_error_strings();
			SSL_library_init();
			if (!RAND_poll()) {
				Log(LOG_LEVEL_ERROR, "RAND_poll, exiting...");
				exit(EXIT_FAILURE);
			}

			levServerSSL = SSL_CTX_new(SSLv23_server_method());
			SSL_CTX_set_session_cache_mode(levServerSSL, SSL_SESS_CACHE_OFF);

			SSL_CTX *CTX;
			X509 *cert = NULL;
			RSA *rsa = NULL;
			BIO *bio;
			uint8_t *certBuff;
			size_t size;

			FILE *hFile = fopen(SSLPublicKey, "r"); {
				if (hFile == NULL) {
					Log(LOG_LEVEL_ERROR, "Failed to read public key (1), exiting...");
					exit(EXIT_FAILURE);
				}
				fseek(hFile, 0, SEEK_END);
				size = ftell(hFile);
				fseek(hFile, 0, SEEK_SET);

				certBuff = malloc(size);
				fread(certBuff, size, 1, hFile);
			} fclose(hFile);

			bio = BIO_new_mem_buf(certBuff, size); {
				cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
				if (cert == NULL) {
					Log(LOG_LEVEL_ERROR, "Failed to read public key (2), exiting...");
					exit(EXIT_FAILURE);
				}

				if (!SSL_CTX_use_certificate(levServerSSL, cert) || !SSL_CTX_use_PrivateKey_file(levServerSSL, SSLPrivateKey, SSL_FILETYPE_PEM)) {
					Log(LOG_LEVEL_ERROR, "Failed to load public / private key, exiting...");
					exit(EXIT_FAILURE);
				}
				SSL_CTX_set_options(levServerSSL, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
				SSL_CTX_set_cipher_list(levServerSSL, SSLCipherList);

				uint8_t *buff;
				size_t len;
				SSLFingerPrint = malloc(EVP_MAX_MD_SIZE);
				unsigned int trash;
				X509_digest(cert, EVP_sha512(), SSLFingerPrint, &trash);
				Log(LOG_LEVEL_DEBUG, "SSL fingerprint: %128x", SSLFingerPrint);
			} BIO_free(bio);

			CONFIG_STRING(sslGroup, "RequestHeaders", RequestStringSSL, "CONNECT {HOST} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: {UA}\r\n\r\n")
			StrReplaceOrig(&RequestStringSSL, "{VERSION}", VERSION);
			StrReplaceOrig(&RequestStringSSL, "{UA}", RequestUA);
			StrReplaceOrig(&RequestStringSSL, "{KEY_NAME}", RequestHeaderKey);
		}
	} /* End SSL */

	/* Stats */	{
		config_setting_t *statsGroup = config_setting_get_member(cfgRoot, "Stats");
		CONFIG_INT(statsGroup, "CollectionInterval", StatsCollectionInterval, 10000)
		CONFIG_INT(statsGroup, "MaxItems", StatsMaxItems, 1000)
	} /* End stats */

	/* GlobalIP */ {
		const char *globalIp4 = NULL;
		const char *globalIp6 = NULL;
		config_setting_lookup_string(cfgRoot, "GlobalIp4", &globalIp4);
		config_setting_lookup_string(cfgRoot, "GlobalIp6", &globalIp6);
		if (globalIp4 == NULL && globalIp6 == NULL) {
			Log(LOG_LEVEL_ERROR, "Failed to lookup global IP address (GlobalIp4 or GlobalIp6)");
		}

		GlobalIp4 = NULL;
		if (globalIp4 != NULL) {
			GlobalIp4 = StringToIPv6Map((char*)globalIp4);

			if (GlobalIp4 == NULL) {
				Log(LOG_LEVEL_ERROR, "Invalid GlobalIp4 value, exiting...");
				exit(EXIT_FAILURE);
			}

			Host4 = HostFormat(GlobalIp4, ServerPort);
			if (SSLEnabled)
				Host4SSL = HostFormat(GlobalIp4, SSLServerPort);
		}

		GlobalIp6 = NULL;
		if (globalIp6 != NULL) {
			GlobalIp6 = StringToIPv6Map((char*)globalIp6);

			if (GlobalIp6 == NULL) {
				Log(LOG_LEVEL_ERROR, "Invalid GlobalIp6 value, exiting...");
				exit(EXIT_FAILURE);
			}

			Host6 = HostFormat(GlobalIp6, ServerPort);
			if (SSLEnabled)
				Host6SSL = HostFormat(GlobalIp6, SSLServerPort);
		}
	} /* End GlobalIP */

	CONFIG_STRING(cfgRoot, "RequestHeaders", RequestString,
		"GET {PAGE_PATH} HTTP/1.1\r\n"
		"Host: {HOST}\r\n"
		"Connection: Close\r\n"
		"Cache-Control: max-age=0\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
		"User-Agent: {UA}\r\n"
		"DNT: 1\r\n"
		"Accept-Encoding: gzip, deflate, sdch\r\n"
		"Accept-Language: en-US,en;q=0.8\r\n"
		"{KEY_NAME}: {KEY_VAL}")
	// Host and LPKey is injected upon request
	StrReplaceOrig(&RequestString, "{VERSION}", VERSION);
	StrReplaceOrig(&RequestString, "{UA}", RequestUA);
	StrReplaceOrig(&RequestString, "{KEY_NAME}", RequestHeaderKey);
	RequestStringLen = strlen(RequestString);

	config_destroy(&cfg);

#undef CONFIG_INT64
#undef CONFIG_INT
#undef CONFIG_BOOL
#undef CONFIG_STRING

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
			pthread_mutex_init(&AuthLocalLock, NULL);
			config_setting_t *cfgRoot = config_root_setting(&cfg);
			size_t x = 0;
			config_setting_t *currentBlock;

			config_setting_t *Auth = config_setting_get_member(cfgRoot, "Auth");
			if (Auth != NULL) {
				while ((currentBlock = config_setting_get_elem(Auth, x)) != NULL) {
					const char *val = config_setting_get_string(currentBlock);
					if (x % 2 == 0) {
						if (AuthLocalList == NULL)
							AuthLocalList = malloc(++AuthLocalCount * sizeof(AuthLocalList));
						else
							AuthLocalList = realloc(AuthLocalList, ++AuthLocalCount * sizeof(AuthLocalList));

						AuthLocalList[AuthLocalCount - 1] = malloc(sizeof(AUTH_LOCAL));

						AuthLocalList[AuthLocalCount - 1]->username = malloc((strlen(val) * sizeof(char)) + 1);
						strcpy((char*)AuthLocalList[AuthLocalCount - 1]->username, val);
					} else {
						AuthLocalList[AuthLocalCount - 1]->password = malloc((strlen(val) * sizeof(char)) + 1);
						strcpy((char*)AuthLocalList[AuthLocalCount - 1]->password, val);
					}
					x++;
				}
			}
			config_destroy(&cfg);
		}
	} /* End auth init */

	const char *pcreError;
	int pcreErrorOffset;
	const char *err;

	ipv6Regex = pcre_compile("\\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}))|:)))(%.+)?\\s*", 0, &pcreError, &pcreErrorOffset, NULL); // 👌
	if (ipv6Regex == NULL) {
		Log(LOG_LEVEL_ERROR, "Couldn't compile PCRE IPv6 regex:\n%s at %d", pcreError, pcreErrorOffset);
		return EXIT_FAILURE;
	}
	ipv6RegexEx = pcre_study(ipv6Regex, 0, &err);
	if (err != NULL) {
		Log(LOG_LEVEL_ERROR, "Couldn't study PCRE IPv6 regex");
		return EXIT_FAILURE;
	}

	ipv4Regex = pcre_compile("(\\b(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(\\.(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)){3}\\b)", 0, &pcreError, &pcreErrorOffset, NULL); // 👌
	if (ipv4Regex == NULL) {
		Log(LOG_LEVEL_ERROR, "Couldn't compile PCRE IPv4 regex:\n%s at %d", pcreError, pcreErrorOffset);
		return EXIT_FAILURE;
	}
	ipv4RegexEx = pcre_study(ipv4Regex, 0, &err);
	if (err != NULL) {
		Log(LOG_LEVEL_ERROR, "Couldn't study PCRE IPv4 regex");
		return EXIT_FAILURE;
	}

	RAND_pseudo_bytes((unsigned char*)(&hashSalt), 64);

	pthread_mutex_init(&LockUncheckedProxies, NULL);
	pthread_mutex_init(&LockCheckedProxies, NULL);
	pthread_mutex_init(&LockStatsHarvesterPrxsrc, NULL);
	pthread_mutex_init(&LockStatsProxyCount, NULL);

#define THREAD_START(var, fx, name) pthread_t var; status = pthread_create(&var, NULL, (void*)fx, NULL); if (status != 0) { Log(LOG_LEVEL_ERROR, name" creation error, code %d", status); return status; } pthread_setname_np(var, name); pthread_detach(var);

	THREAD_START(serverBase, ServerBase, "Server base")
	THREAD_START(serverBaseSSL, ServerBaseSSL, "Server base SSL")

	if (EnableUDP) {
		if (GlobalIp4 != NULL)
			ServerUDP4();
		if (GlobalIp6 != NULL)
			ServerUDP6();
	}

	THREAD_START(harvestThread, HarvestLoop, "Harvest thread")
	THREAD_START(removeThread, RemoveThread, "Removal thread")
	THREAD_START(checkThread, CheckLoop, "Check thread")
	THREAD_START(requestBase, RequestBase, "Request base")
	THREAD_START(statsThread, StatsCollection, "Stats thread")

	Log(LOG_LEVEL_SUCCESS, "Non-interactive mode active");

	for (;;) {
		sleep(INT_MAX); // gdb is flipping out when we exit main thread
		ERR_free_strings();
		EVP_cleanup();
		CONF_modules_finish();
		CONF_modules_free();
		CONF_modules_unload(1);
		CRYPTO_cleanup_all_ex_data();
		exit(0);
		/*FILE *hF = fopen("events.txt", "w+"); {
			//Log(LOG_LEVEL_DEBUG, "Dumping events...");
			event_base_dump_events(levRequestBase, hF);
		} fclose(hF);*/
	}
}

void RequestBase()
{
	if (SSLEnabled) {
		RequestBaseSSLCTX = SSL_CTX_new(SSLv23_client_method());
		SSL_CTX_set_session_cache_mode(RequestBaseSSLCTX, SSL_SESS_CACHE_OFF);
	}

	for (;;) {
		if (CurrentlyChecking > 0)
			event_base_dispatch(levRequestBase);
		usleep(10000);
	}
}

void CheckLoop()
{
	Log(LOG_LEVEL_DEBUG, "CheckLoop: Start");
	for (;;) {
		size_t count = 0;
		UNCHECKED_PROXY **proxiesToCheck = NULL;

		Log(LOG_LEVEL_DEBUG, "CheckLoop: Waiting for UProxy list lock...");
		pthread_mutex_lock(&LockUncheckedProxies); {
			Log(LOG_LEVEL_DEBUG, "CheckLoop: Looping through UProxies...");

			for (uint64_t x = 0; x < SizeUncheckedProxies; x++) {
				if (CurrentlyChecking > SimultaneousChecks)
					break;
				if (!(UncheckedProxies[x]->checking) && UncheckedProxies[x]->singleCheckCallback == NULL) {
					if (proxiesToCheck == NULL)
						proxiesToCheck = malloc(sizeof(proxiesToCheck));
					else
						proxiesToCheck = realloc(proxiesToCheck, (count + 1) * sizeof(proxiesToCheck));
					proxiesToCheck[count++] = UncheckedProxies[x];
				} else
					Log(LOG_LEVEL_DEBUG, "CheckLoop: Proxy %d discard", x);
			}
		} pthread_mutex_unlock(&LockUncheckedProxies);

		for (size_t x = 0; x < count; x++) {
			Log(LOG_LEVEL_DEBUG, "CheckLoop: Proxy %d set checking", x);
			proxiesToCheck[x]->targetIPv4 = GlobalIp4;
			proxiesToCheck[x]->targetIPv6 = GlobalIp6;
			proxiesToCheck[x]->targetPort = proxiesToCheck[x]->type == PROXY_TYPE_SOCKS5_WITH_UDP ? ServerPortUDP : (ProxyIsSSL(proxiesToCheck[x]->type) ? SSLServerPort : ServerPort);
			RequestAsync(proxiesToCheck[x]);
		}

		free(proxiesToCheck);
		count = 0;

		Log(LOG_LEVEL_DEBUG, "CheckLoop: Sleeping... (%d)", CurrentlyChecking);
		msleep(CheckingInterval);
	}
}
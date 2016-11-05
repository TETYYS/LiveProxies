#define _GNU_SOURCE

#include "LiveProxies.h"
#include "ProxyRequest.h"
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
#ifdef __linux__
#include <unistd.h>
#elif defined _WIN32 || defined _WIN64
#include <shlwapi.h>
#include <windows.h>
#endif
#include <math.h>
#include <fcntl.h>
#include "CPH_Threads.h"

#include <curl/curl.h>
#include <maxminddb.h>

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

#ifdef LIBEV_DEBUG
static void EvLog(int Level, char *Format, va_list VA)
{
	Log(Level, Format, VA);
}
#endif

int main(int argc, char** argv)
{
#if defined _WIN32 || defined _WIN64
	WinAppData = getenv("AppData");
#endif

	if (argc == 2 && strcmp(argv[1], "passwd") == 0) {
		printf("Enter username to use for interface:\n");
		char *uname = StdinDynamic();

		printf("Enter password to use for interface:\n");
		char *pbkdf2;
		char *passwd = StdinDynamic(); {
			pbkdf2 = PBKDF2_HMAC_SHA_512(passwd, strlen(passwd));
#ifdef __linux__
			memset(passwd, 0, strlen(passwd)); // safety!
			*(volatile char *)passwd = *(volatile char *)passwd;
#elif defined _WIN32 || defined _WIN64
			SecureZeroMemory(passwd, strlen(passwd));
#endif
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

		char *path;

		if (globalWrite) {
#ifdef __linux__
			path = "/etc/liveproxies/passwd.conf";
#elif defined _WIN32 || defined _WIN64
			path = malloc(strlen(WinAppData) + 29 + 1);
			strcpy(path, WinAppData);
			strcat(path, "\\liveproxies\\passwd.conf");
#endif
		} else {
#ifdef __linux__
			path = "./passwd.conf";
#elif defined _WIN32 || defined _WIN64
			path = ".\\passwd.conf";
#endif
		}

#ifdef __linux__
		if (access(path, F_OK) == -1)
			creat(path, S_IRUSR | S_IWUSR);
#elif defined _WIN32 || defined _WIN64
		if (!PathFileExists(path)) {
			HANDLE hFile = CreateFile(path, FILE_READ_DATA, FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
			if (hFile != INVALID_HANDLE_VALUE) {
				CloseHandle(hFile);
			}
		}
#endif

		config_setting_t *cfgRoot = config_root_setting(&cfg);
		config_setting_t *authBlock;

		if ((authBlock = config_setting_get_member(cfgRoot, "Auth")) == NULL)
			authBlock = config_setting_add(cfgRoot, "Auth", CONFIG_TYPE_ARRAY);

		config_setting_t *username = config_setting_add(authBlock, "username", CONFIG_TYPE_STRING);
		config_setting_t *password = config_setting_add(authBlock, "password", CONFIG_TYPE_STRING);
		config_setting_set_string(username, uname);
		config_setting_set_string(password, pbkdf2);

		config_write_file(&cfg, path);

		if (globalWrite) {
#if defined _WIN32 || defined _WIN64
			free(path);
#endif
		}

		return 0;
	}

	//

	printf("LiveProxes "VERSION" started\n");
#if DEBUG
#define MMDB_DEBUG 0
	printf("========================DEBUG========================\n");
#ifdef EXTENDED_DEBUG
	evthread_enable_lock_debugging();
	event_enable_debug_mode();
	event_set_log_callback((event_log_cb)EvLog);
	event_enable_debug_logging(EVENT_DBG_ALL);
#endif
#endif

#if defined _WIN32 || defined _WIN64
	int res;
	WSADATA wsaData;

	if ((res = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0) {
		Log(LOG_LEVEL_ERROR, "WSAStartup failed: %d\n", res);
		return res;
}
#endif

	char *globalPath, *localPath;

	curl_global_init(CURL_GLOBAL_ALL);

#if __linux__
	evthread_use_pthreads();
#elif defined _WIN32 || defined _WIN64
	evthread_use_windows_threads();
#endif
	AuthWebList = NULL;

	pthread_mutex_init(&AuthWebLock, NULL);
	pthread_mutex_init(&WebSocketUnfinishedPacketsLock, NULL);
	pthread_mutex_init(&WebSocketSubscribedClientsLock, NULL);
	pthread_mutex_init(&LockUncheckedProxies, NULL);
	pthread_mutex_init(&LockCheckedProxies, NULL);
	pthread_mutex_init(&LockStatsHarvesterPrxsrc, NULL);
	pthread_mutex_init(&LockStatsProxyCount, NULL);

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

#ifdef __linux__
	globalPath = "/usr/local/share/GeoIP/GeoLite2-Country.mmdb";
	localPath = "./GeoLite2-Country.mmdb";
#elif defined _WIN32 || defined _WIN64
	globalPath = malloc(strlen(WinAppData) + 34 + 1);
	strcpy(globalPath, WinAppData);
	strcat(globalPath, "\\liveproxies\\GeoLite2-Country.mmdb");
	localPath = ".\\GeoLite2-Country.mmdb";
#endif
	int status = MMDB_open(globalPath, MMDB_MODE_MMAP, &GeoIPDB);

	if (status != MMDB_SUCCESS) {
		Log(LOG_LEVEL_ERROR, "Can't open GeoLite2 database in global path (%s) (%s), opening in local...", globalPath, MMDB_strerror(status));

		status = MMDB_open(localPath, MMDB_MODE_MMAP, &GeoIPDB);
		if (status != MMDB_SUCCESS) {
			Log(LOG_LEVEL_ERROR, "Can't open GeoLite2 database %s - %s", localPath, MMDB_strerror(status));
			exit(1);
		}
	}

#if defined _WIN32 || defined _WIN64
	free(globalPath);
#endif


	config_t cfg;
	config_init(&cfg);

#ifdef __linux__
	globalPath = "/etc/liveproxies/liveproxies.conf";
#elif defined _WIN32 || defined _WIN64
	globalPath = malloc(strlen(WinAppData) + 29 + 1);
	strcpy(globalPath, WinAppData);
	strcat(globalPath, "\\liveproxies\\liveproxies.conf");
#endif
#ifdef __linux__
	localPath = "./liveproxies.conf";
#elif defined _WIN32 || defined _WIN64
	localPath = ".\\liveproxies.conf";
#endif

	if (config_read_file(&cfg, localPath) == CONFIG_FALSE) {
		Log(LOG_LEVEL_DEBUG, "Failed to open %s in working directory, opening in global...: %s (line %d)", localPath, config_error_text(&cfg), config_error_line(&cfg));

		if (config_read_file(&cfg, globalPath) == CONFIG_FALSE) {
			Log(LOG_LEVEL_ERROR, "Failed to open in global path: %s (line %d)", globalPath, config_error_text(&cfg), config_error_line(&cfg));
			exit(EXIT_FAILURE);
		}
	}

#if defined _WIN32 || defined _WIN64
	free(globalPath);
#endif

	config_setting_t *cfgRoot = config_root_setting(&cfg);

#define CONFIG_INT64(cfg, svar, var, default) if (config_setting_lookup_int64(cfg, svar, (long long*)(&var)) == CONFIG_FALSE) { var = default; Log(LOG_LEVEL_ERROR, "Failed to lookup %s, setting to %d...", svar, default); }
#define CONFIG_INT(cfg, svar, var, default) if (config_setting_lookup_int(cfg, svar, (int*)(&var)) == CONFIG_FALSE) { var = default; Log(LOG_LEVEL_ERROR, "Failed to lookup %s, setting to %d...", svar, default); }
#define CONFIG_STRING(cfg, svar, var, default) const char *val_##var; if (config_setting_lookup_string(cfg, svar, &(val_##var)) == CONFIG_FALSE) { var = malloc(strlen(default) + 1); strcpy(var, default); Log(LOG_LEVEL_ERROR, "Failed to lookup %s, setting to %s...", svar, default); } else { var = malloc(strlen(val_##var) + 1); strcpy(var, (val_##var)); }
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
	CONFIG_BOOL(cfgRoot, "SOCKS5ResolveDomainsRemotely", SOCKS5ResolveDomainsRemotely, false)
	CONFIG_STRING(cfgRoot, "HarvestersPath", HarvestersPath, "/etc/liveproxies/scripts/")
	CONFIG_STRING(cfgRoot, "HttpBLAccessKey", HttpBLAccessKey, "")
	CONFIG_STRING(cfgRoot, "Hostname", GlobalHostname, "")
	if (*GlobalHostname == '\0') {
		free(GlobalHostname);
		GlobalHostname = NULL;
	}

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
		CONFIG_STRING(sslGroup, "CipherList", SSLCipherList, "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4")
		CONFIG_INT(sslGroup, "ServerPort", SSLServerPort, 8085)

		if (SSLEnabled) {
			SSL_library_init();
			OpenSSL_add_ssl_algorithms();
			OpenSSL_add_all_algorithms();
			SSL_load_error_strings();
			ERR_load_crypto_strings();
			if (!RAND_poll()) {
				Log(LOG_LEVEL_ERROR, "RAND_poll, exiting...");
				exit(EXIT_FAILURE);
			}

			levServerSSL = SSL_CTX_new(TLSv1_2_server_method());
			SSL_CTX_set_verify(levServerSSL, SSL_VERIFY_PEER, SSLVerifyCallback);

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
				X509 *cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
				if (cert == NULL) {
					Log(LOG_LEVEL_ERROR, "Failed to read public key (2), exiting...");
					exit(EXIT_FAILURE);
				}
				
				SSLFingerPrint = malloc(EVP_MAX_MD_SIZE);
				unsigned int trash;
				X509_digest(cert, EVP_sha512(), SSLFingerPrint, &trash);
				
				X509_free(cert);
				
				Log(LOG_LEVEL_DEBUG, "SSL fingerprint: %128x", SSLFingerPrint);
			} BIO_free(bio);
			free(certBuff);
			
			if (!SSL_CTX_use_certificate_chain_file(levServerSSL, SSLPublicKey) || !SSL_CTX_use_PrivateKey_file(levServerSSL, SSLPrivateKey, SSL_FILETYPE_PEM)) {
				Log(LOG_LEVEL_ERROR, "Failed to load public / private key, exiting...");
				exit(EXIT_FAILURE);
			}
			SSL_CTX_set_options(levServerSSL, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
			SSL_CTX_set_cipher_list(levServerSSL, SSLCipherList);

			CONFIG_STRING(sslGroup, "RequestHeaders", RequestStringSSL, "CONNECT {HOST} HTTP/1.1\r\nHost: {HOST}\r\nUser-Agent: {UA}\r\n\r\n")
			StrReplaceOrig(&RequestStringSSL, "{VERSION}", VERSION);
			StrReplaceOrig(&RequestStringSSL, "{UA}", RequestUA);
			StrReplaceOrig(&RequestStringSSL, "{KEY_NAME}", RequestHeaderKey);
		}
	} /* End SSL */

	/* Stats */ {
		config_setting_t *statsGroup = config_setting_get_member(cfgRoot, "Stats");
		CONFIG_INT(statsGroup, "CollectionInterval", StatsCollectionInterval, 10000)
		CONFIG_INT(statsGroup, "MaxItems", StatsMaxItems, 1000)
	} /* End stats */

	/* Websockets */ {
		config_setting_t *websocketsGroup = config_setting_get_member(cfgRoot, "Websockets");
		CONFIG_INT(websocketsGroup, "PingInterval", WSPingInterval, 5000)
		CONFIG_INT(websocketsGroup, "MessageInterval", WSMessageInterval, 700)
		
	} /* End websockets*/
	
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
		
		HostHostnameSSL = NULL;
		if (GlobalHostname != NULL) {
			size_t hostnameLen = strlen(GlobalHostname);
			HostHostnameSSL = malloc((sizeof(char)* (hostnameLen + INTEGER_VISIBLE_SIZE(SSLServerPort) + 1 /* : between ip and port */)) + 1 /* NUL */);
			sprintf(HostHostnameSSL, "%s:%d", GlobalHostname, SSLServerPort);
		}
	} /* End GlobalIP */

	CONFIG_STRING(cfgRoot, "POSTRequest", POSTRequestString,
		"POST {PAGE_PATH} HTTP/1.1\r\n"
		"Host: {HOST}\r\n"
		"Connection: Close\r\n"
		"Cache-Control: max-age=0\r\n"
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
		"User-Agent: {UA}\r\n"
		"DNT: 1\r\n"
		"Accept-Encoding: gzip, deflate, sdch\r\n"
		"Accept-Language: en-US,en;q=0.8\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Content-Length: {DATA_LEN}\r\n"
		"{KEY_NAME}: {KEY_VAL}\r\n\r\n"
		"{POST_DATA}")
	// Host, LPKey, DataLen and PostData is injected upon request
	StrReplaceOrig(&POSTRequestString, "{VERSION}", VERSION);
	StrReplaceOrig(&POSTRequestString, "{UA}", RequestUA);
	StrReplaceOrig(&POSTRequestString, "{KEY_NAME}", RequestHeaderKey);
	POSTRequestStringLen = strlen(POSTRequestString);

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
		bool authExists = true;
		AuthLocalList = NULL;
		AuthLocalCount = 0;

#ifdef __linux__
		globalPath = "/etc/liveproxies/passwd.conf";
#elif defined _WIN32 || defined _WIN64
		globalPath = malloc(strlen(WinAppData) + 29 + 1);
		strcpy(globalPath, WinAppData);
		strcat(globalPath, "\\liveproxies\\passwd.conf");
#endif
#ifdef __linux__
		localPath = "./passwd.conf";
#elif defined _WIN32 || defined _WIN64
		localPath = ".\\passwd.conf";
#endif

		if (config_read_file(&cfg, localPath) == CONFIG_FALSE) {
			Log(LOG_LEVEL_DEBUG, "Failed to open %s in working directory, opening in global...: %s (line %d)", localPath, config_error_text(&cfg), config_error_line(&cfg));
			authExists = false;
		}

		if (!authExists) {
			if (config_read_file(&cfg, globalPath) == CONFIG_FALSE)
				Log(LOG_LEVEL_DEBUG, "Failed to open %s: %s (line %d)", globalPath, config_error_text(&cfg), config_error_line(&cfg));
			else
				authExists = true;
		}

#if defined _WIN32 || defined _WIN64
		free(globalPath);
#endif

		if (authExists) {
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

						AuthLocalList[AuthLocalCount - 1]->username = malloc(strlen(val) + 1);
						strcpy((char*)AuthLocalList[AuthLocalCount - 1]->username, val);
						Log(LOG_LEVEL_DEBUG, "Added user %s", AuthLocalList[AuthLocalCount - 1]->username);
					} else {
						AuthLocalList[AuthLocalCount - 1]->password = malloc(strlen(val) + 1);
						strcpy((char*)AuthLocalList[AuthLocalCount - 1]->password, val);
					}
					x++;
				}
			} else {
				Log(LOG_LEVEL_ERROR, "No credentials present for interface pages. Access blocked by default. (2)");
			}
			config_destroy(&cfg);
		} else {
			Log(LOG_LEVEL_ERROR, "No credentials present for interface pages. Access blocked by default.");
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
#ifdef __linux__
		sleep(INT_MAX); // gdb is flipping out when we exit main thread
#elif defined _WIN32 || defined _WIN64
		Sleep(INT_MAX);
#endif
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
		RequestBaseSSLCTX = SSL_CTX_new(TLSv1_2_client_method());
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
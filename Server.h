#pragma once

#include <pcre.h>
#include <openssl/ssl.h>
#include <maxminddb.h>

MMDB_s GeoIPDB;
pcre *ipv6Regex;
pcre_extra *ipv6RegexEx;
pcre *ipv4Regex;
pcre_extra *ipv4RegexEx;

struct event_base *levServerBase;
struct evconnlistener *levServerList4;
struct evconnlistener *levServerList6;

SSL_CTX *levServerSSL;

struct event_base *levServerBaseSSL;
struct evconnlistener *levServerListSSL4;
struct evconnlistener *levServerListSSL6;

void ServerBase();
void ServerBaseSSL();
void ServerUDP6();
void ServerUDP4();

void ServerRead(struct bufferevent *BuffEvent, void *Ctx);
void ServerEvent(struct bufferevent *BuffEvent, short Event, void *Ctx);

int SSLVerifyCallback(int preverify_ok, X509_STORE_CTX *ctx);
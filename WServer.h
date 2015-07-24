#pragma once

#include <evhtp.h>
#include <pcre.h>
#include <stdbool.h>
#include <openssl/ssl.h>
#include "GeoIP.h"

GeoIP *GeoIPDB;
GeoIP *GeoIPDB6;
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

void GenericCb(evhtp_request_t *evRequest, void *arg);
void WServerBase();
void WServerBaseSSL();
void WServerUDP6();
void WServerUDP4();
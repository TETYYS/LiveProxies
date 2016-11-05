#pragma once

#include "tadns.h"
#include <stdbool.h>

typedef struct _DNS_LOOKUP_ASYNC_EX {
	void *object;
	struct event *evDNS;
	struct dns *dnsCtx;
	bool resolveDone;
	dns_callback_t fxDone;
	void *fxFreed;
	bool ipv6;
} DNS_LOOKUP_ASYNC_EX;

typedef void(*FxDnsFreed)(struct _DNS_LOOKUP_ASYNC_EX*);


typedef enum _DNS_RR_TYPE {
	DNS_RR_TYPE_A = 1, //			a host address
	DNS_RR_TYPE_NS = 2, //			an authoritative name server
	DNS_RR_TYPE_MD = 3, //			a mail destination (OBSOLETE - use MX)
	DNS_RR_TYPE_MF = 4, //			a mail forwarder (OBSOLETE - use MX)
	DNS_RR_TYPE_CNAME = 5, //		the canonical name for an alias
	DNS_RR_TYPE_SOA = 6, //			marks the start of a zone of authority
	DNS_RR_TYPE_MB = 7, //			a mailbox domain name (EXPERIMENTAL)
	DNS_RR_TYPE_MG = 8, //			a mail group member (EXPERIMENTAL)
	DNS_RR_TYPE_MR = 9, //			a mail rename domain name (EXPERIMENTAL)
	DNS_RR_TYPE_NULL = 10, //		a null RR (EXPERIMENTAL)
	DNS_RR_TYPE_WKS = 11, //		a well known service description
	DNS_RR_TYPE_PTR = 12, //		a domain name pointer
	DNS_RR_TYPE_HINFO = 13, //		host information
	DNS_RR_TYPE_MINFO = 14, //		mailbox or mail list information
	DNS_RR_TYPE_MX = 15, //			mail exchange
	DNS_RR_TYPE_TXT = 16, //		text strings
	DNS_RR_TYPE_RP = 17, //			for Responsible Person
	DNS_RR_TYPE_AFSDB = 18, //		for AFS Data Base location
	DNS_RR_TYPE_X25 = 19, //		for X.25 PSDN address
	DNS_RR_TYPE_ISDN = 20, //		for ISDN address
	DNS_RR_TYPE_RT = 21, //			for Route Through
	DNS_RR_TYPE_NSAP = 22, //		for NSAP address, NSAP style A record
	DNS_RR_TYPE_NSAP_PTR = 23, //	for domain name pointer, NSAP style
	DNS_RR_TYPE_SIG = 24, //		for security signature
	DNS_RR_TYPE_KEY = 25, //		for security key
	DNS_RR_TYPE_PX = 26, //			X.400 mail mapping information
	DNS_RR_TYPE_GPOS = 27, //		Geographical Position
	DNS_RR_TYPE_AAAA = 28, //		IP6 Address
	DNS_RR_TYPE_LOC = 29, //		Location Information
	DNS_RR_TYPE_NXT = 30, //		Next Domain (OBSOLETE)
	DNS_RR_TYPE_EID = 31, //		Endpoint Identifier
	DNS_RR_TYPE_NIMLOC = 32, //		Nimrod Locator
	DNS_RR_TYPE_SRV = 33, //		Server Selection
	DNS_RR_TYPE_ATMA = 34, //		ATM Address
	DNS_RR_TYPE_NAPTR = 35, //		Naming Authority Pointer
	DNS_RR_TYPE_KX = 36, //			Key Exchanger
	DNS_RR_TYPE_CERT = 37, //		CERT
	DNS_RR_TYPE_A6 = 38, //			A6 (OBSOLETE - use AAAA)
	DNS_RR_TYPE_DNAME = 39, //		DNAME
	DNS_RR_TYPE_SINK = 40, //		SINK
	DNS_RR_TYPE_OPT = 41, //		OPT
	DNS_RR_TYPE_APL = 42, //		APL
	DNS_RR_TYPE_DS = 43, //			Delegation Signer
	DNS_RR_TYPE_SSHFP = 44, //		SSH Key Fingerprint
	DNS_RR_TYPE_IPSECKEY = 45, //	IPSECKEY
	DNS_RR_TYPE_RRSIG = 46, //		RRSIG
	DNS_RR_TYPE_NSEC = 47, //		NSEC
	DNS_RR_TYPE_DNSKEY = 48, //		DNSKEY
	DNS_RR_TYPE_DHCID = 49, //		DHCID
	DNS_RR_TYPE_NSEC3 = 50, //		NSEC3
	DNS_RR_TYPE_NSEC3PARAM = 51, //	NSEC3PARAM
	DNS_RR_TYPE_TLSA = 52, //		TLSA
	DNS_RR_TYPE_HIP = 55, //		Host Identity Protocol
	DNS_RR_TYPE_NINFO = 56, //		NINFO
	DNS_RR_TYPE_RKEY = 57, //		RKEY
	DNS_RR_TYPE_TALINK = 58, //		Trust Anchor LINK
	DNS_RR_TYPE_CDS = 59, //		Child DS
	DNS_RR_TYPE_CDNSKEY = 60, //	DNSKEY(s) the Child wants reflected in DS
	DNS_RR_TYPE_OPENPGPKEY = 61, //	OpenPGP Key
	DNS_RR_TYPE_CSYNC = 62, //		Child-To-Parent Synchronization
	DNS_RR_TYPE_SPF = 99, //		?
	DNS_RR_TYPE_UINFO = 100, //		?
	DNS_RR_TYPE_UID = 101, //		?
	DNS_RR_TYPE_GID = 102, //		?
	DNS_RR_TYPE_UNSPEC = 103, //	?
	DNS_RR_TYPE_NID = 104, //		?
	DNS_RR_TYPE_L32 = 105, //		?
	DNS_RR_TYPE_L64 = 106, //		?
	DNS_RR_TYPE_LP = 107, //		?
	DNS_RR_TYPE_EUI48 = 108, //		an EUI-48 address
	DNS_RR_TYPE_EUI64 = 109, //		an EUI-64 address
	DNS_RR_TYPE_TKEY = 249, //		Transaction Key
	DNS_RR_TYPE_TSIG = 250, //		Transaction Signature
	DNS_RR_TYPE_IXFR = 251, //		incremental transfer
	DNS_RR_TYPE_AXFR = 252, //		transfer of an entire zone
	DNS_RR_TYPE_MAILB = 253, //		mailbox-related RRs (MB, MG or MR)
	DNS_RR_TYPE_MAILA = 254, //		mail agent RRs (OBSOLETE - see MX)
	DNS_RR_TYPE_URI = 256, //		URI
	DNS_RR_TYPE_CAA = 257, //		Certification Authority Restriction
	DNS_RR_TYPE_TA = 32768, //		DNSSEC Trust Authorities
	DNS_RR_TYPE_DLV = 32769, //		DNSSEC Lookaside Validation
	DNS_RR_TYPE_Reserved = 65535, //?
} DNS_RR_TYPE;

typedef enum _DNS_CLASS {
	DNS_CLASS_RESERVED = 0,
	DNS_CLASS_INTERNET = 1,
	DNS_CLASS_UNASSIGNED = 2,
	DNS_CLASS_CHAOS = 3,
	DNS_CLASS_HESIOD = 4,
	DNS_CLASS_NONE = 254,
	DNS_CLASS_ANY = 255
} DNS_CLASS;

void HTTP_BLAsyncStage2		(struct dns_cb_data *data);
void SpamhausZENAsyncStage2	(struct dns_cb_data *data);
void ProxyDNSResolved		(struct dns_cb_data *data);

DNS_LOOKUP_ASYNC_EX *DNSResolveAsync(void *Ex, char *Domain, bool IPv6, dns_callback_t fxDone, FxDnsFreed fxFreed);
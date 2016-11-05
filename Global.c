#include "Global.h"
#include "Logger.h"
#include "ProxyRequest.h"
#include "IPv6Map.h"
#ifdef __linux__
	#include <sys/time.h>
#elif defined _WIN32 || defined _WIN64
	#include <windows.h>
#endif
#include <stddef.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

double GetUnixTimestampMilliseconds()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec + (tv.tv_usec / 1000000.0)) * 1000.0;
}

char *GetHost(IP_TYPE Preffered, bool SSL)
{
	char *host4 = (SSL ? Host4SSL : Host4);
	char *host6 = (SSL ? Host6SSL : Host6);

	if (host4 != NULL && host6 != NULL)
		return Preffered == IPV4 ? host4 : host6;
	if (host4 == NULL)
		return host6;
	else
		return host4;
}

MEM_OUT char *FormatTime(uint64_t TimeMs)
{
	char *timeBuff = zalloc(20 + 1);

	struct tm *timeinfo;
	time_t timeRaw = TimeMs / 1000;

	timeinfo = localtime(&timeRaw);
	strftime(timeBuff, 20, "%Y-%m-%d %H:%M:%S", timeinfo);

	return timeBuff;
}

bool MemEqual(void *A, void *B, size_t Size)
{
	return memcmp(A, B, Size) == 0;
}

char *StrReplaceToNew(char *In, char *Search, char *Replace)
{
	char *ret;
	char *search = strstr(In, Search);
	size_t lSideLen = search - In;

	if (search == NULL || Replace[0] == '\0')
		return NULL;

	size_t searchLen = strlen(Search);
	size_t origLen = strlen(In);
	size_t replaceLen = strlen(Replace);

	ret = malloc((origLen - searchLen + replaceLen) * (sizeof(char) + 1));

	// Copy left side
	if (search != In)
		memcpy(ret, In, lSideLen);

	// Copy replacement
	memcpy(ret + lSideLen, Replace, replaceLen);

	// Copy right side
	if (search + (searchLen) != (In + origLen)) {
		memcpy(ret + lSideLen + replaceLen,
			   search + searchLen,
			   In + (origLen) - search - searchLen);
	}
	ret[(origLen - searchLen + replaceLen)] = L'\0';

	if (strstr(ret, Search) != NULL)
		StrReplaceOrig(&ret, Search, Replace);

	return ret;
}

bool StrReplaceOrig(char **In, char *Search, char *Replace)
{
	char *search = strstr(*In, Search);
	if (search == NULL)
		return false;

	size_t searchOffset = search - *In;

	size_t searchLen = strlen(Search);
	size_t origLen = strlen(*In);
	size_t replaceLen = strlen(Replace);

	size_t origToReplaceEndLen = (origLen - searchLen + replaceLen);

	if (replaceLen > searchLen) {
		*In = realloc(*In, origToReplaceEndLen + 1);
		search = strstr(*In, Search); // Re-search string

		char *rightSide = search + searchLen;
		size_t rightSideLen = ((*In + origLen) - rightSide);

		memmove(search + replaceLen, rightSide, rightSideLen);
		memcpy(*In + searchOffset, Replace, replaceLen);
		(*In)[origToReplaceEndLen] = '\0';
	} else if (replaceLen == searchLen)
		memcpy(*In + searchOffset, Replace, replaceLen);
	else if (replaceLen < searchLen) {
		char *rightSide = search + searchLen;
		size_t rightSideLen = ((*In + origLen) - rightSide);

		memmove(search + replaceLen, rightSide, rightSideLen);
		*In = realloc(*In, origToReplaceEndLen * (sizeof(char) + 1));

		memcpy(*In + searchOffset, Replace, replaceLen);
		(*In)[origToReplaceEndLen] = '\0';
	}

	if (strstr(*In, Search) != NULL)
		StrReplaceOrig(In, Search, Replace);

	return true;
}

MEM_OUT bool HTTPFindHeader(char *In, char *Buff, char **Out, char **StartIndex, char **EndIndex)
{
	char *valIndex = Buff;

	size_t searchIndex = 0, inLen = strlen(In);

	do {
		valIndex = strstr(Buff + searchIndex, In);
		if (valIndex == NULL)
			return false;
		if (valIndex == Buff || *(valIndex - 1) != '\n')
			searchIndex = (size_t)valIndex + inLen;
		else
			break;
	} while (1);

	char *valEnd = strstr(valIndex + inLen, "\r\n");
	if (valEnd == NULL) {
		valEnd = strchr(valIndex + inLen, '\n');
		if (valEnd == NULL)
			return false;
	}

	char *valIndexEnd = valIndex + inLen;
	size_t valLen = valEnd - valIndexEnd;

	*Out = malloc(valLen + 1);
	memcpy(*Out, valIndexEnd, valLen);
	(*Out)[valLen] = 0x00;

	if (StartIndex != NULL)
		*StartIndex = valIndex;
	if (EndIndex != NULL)
		*EndIndex = valEnd;

	return true;
}

void BufferEventFreeOnWrite(struct bufferevent *In)
{
	if (evbuffer_get_length(bufferevent_get_output(In)))
		bufferevent_setcb(In, NULL, (bufferevent_data_cb)bufferevent_free, (bufferevent_event_cb)bufferevent_free, NULL);
	else
		bufferevent_free(In);
}
#include "Global.h"
#include "Logger.h"
#include "ProxyRequest.h"
#include "IPv6Map.h"
#include <sys/time.h>
#include <stddef.h>
#include <assert.h>

double GetUnixTimestampMilliseconds()
{
	struct timeval tv;
	assert(gettimeofday(&tv, NULL) != -1);
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
	char *timeBuff = malloc(20 * sizeof(char) + 1);
	memset(timeBuff, 0, 20 * sizeof(char) + 1);
	struct tm *timeinfo;
	time_t timeRaw = TimeMs / 1000;

	timeinfo = localtime(&timeRaw);
	strftime(timeBuff, 20, "%F %H:%M:%S", timeinfo);

	return timeBuff;
}

bool MemEqual(void *A, void *B, size_t Size)
{
	while (--Size) {
		if (*((uint8_t*)A) != *((uint8_t*)B))
			return false;
		A++;
		B++;
	}
	return true;
}

char *StrReplaceToNew(char *In, char *Search, char *Replace)
{
	char *ret;
	char *searchOffset = strstr(In, Search);

	if (searchOffset == NULL || *Replace == 0x00)
		return NULL;

	size_t searchLen = strlen(Search);
	size_t origLen = strlen(In);
	size_t replaceLen = strlen(Replace);

	ret = malloc((origLen - searchLen + replaceLen) * sizeof(char) + 1);

	// Copy left side
	if (searchOffset != In)
		memcpy(ret, In, searchOffset - In);

	// Copy replacement
	memcpy(ret + (searchOffset - In), Replace, replaceLen * sizeof(char));

	// Copy right side
	if (searchOffset + (searchLen * sizeof(char)) != (In + (origLen * sizeof(char)))) {
		size_t replaceLenBytes = (replaceLen * sizeof(char));
		memcpy(ret + (searchOffset - In) + replaceLenBytes,
			   searchOffset + (searchLen * sizeof(char)),
			   In + (origLen * sizeof(char)) - searchOffset - (searchLen * sizeof(char)));
	}
	ret[(origLen - searchLen + replaceLen) * sizeof(char)] = 0x00;

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
		// In: Test test {TEST} test
		// Search: {TEST}
		// Replace:TEST!!!

		*In = realloc(*In, origToReplaceEndLen * sizeof(char) + 1); // Extend string to fit replacement
		//  -> Test test {TEST} testX

		char *rightSide = *In + searchOffset + (searchLen * sizeof(char));
		size_t rightSideLen = ((*In + (origLen * sizeof(char))) - rightSide) / sizeof(char);

		char cpyTemp[rightSideLen];
		memcpy(cpyTemp, rightSide, rightSideLen);
		memcpy(*In + searchOffset + (replaceLen * sizeof(char)), cpyTemp, rightSideLen);
		//  -> Test test {TEST}  test

		memcpy(*In + searchOffset, Replace, replaceLen * sizeof(char));
		(*In)[origToReplaceEndLen * sizeof(char)] = 0x00;
		//  -> Test test TEST!!! test
	} else if (replaceLen == searchLen) {
		// In: Test test {TEST} test
		// Search: {TEST}
		// Replace:TEST!!

		memcpy(*In + searchOffset, Replace, replaceLen * sizeof(char));
		//  -> Test test TEST!! test
	} else if (replaceLen < searchLen) {
		// In: Test test {TEST} test
		// Search: {TEST}
		// Replace:TEST!

		char *rightSide = *In + searchOffset + (searchLen * sizeof(char));
		size_t rightSideLen = ((*In + (origLen * sizeof(char))) - rightSide) / sizeof(char);

		char cpyTemp[rightSideLen];
		memcpy(cpyTemp, rightSide, rightSideLen);
		memcpy(*In + searchOffset + (replaceLen * sizeof(char)), cpyTemp, rightSideLen);
		//  -> Test test {TEST testt

		*In = realloc(*In, origToReplaceEndLen * sizeof(char) + 1); // Shorten string to make RAM happy
		//  -> Test test {TEST test

		memcpy(*In + searchOffset, Replace, replaceLen * sizeof(char));
		(*In)[origToReplaceEndLen * sizeof(char)] = 0x00;
		//  -> Test test TEST! test
	} else {
		// what
		assert(false);
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
#include "Logger.h"
#include <stdarg.h>
#include <stdio.h>

#define DEBUG 1

void _Log(char *File, int Line, LOG_LEVEL Level, const char *Format, ...)
{
	if (Level == LOG_LEVEL_DEBUG) {
#if !DEBUG
		return;
#endif
	}

	va_list args;
	va_start(args, Format);

	switch (Level) {
		case LOG_LEVEL_SUCCESS: {
			printf("[OK] ");
			break;
		}
		case LOG_LEVEL_ERROR: {
			printf("[ERROR] ");
			break;
		}
		case LOG_LEVEL_WARNING: {
			printf("[WARN] ");
			break;
		}
		case LOG_LEVEL_DEBUG: {
			printf("[DEBUG] (%s:%d) ", File, Line);
			break;
		}
	}

	vprintf(Format, args);
	va_end(args);
	printf("\n");
}
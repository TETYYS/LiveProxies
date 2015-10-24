#include "Logger.h"
#include "Global.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

void _Log(char *File, int Line, LOG_LEVEL Level, const char *Format, ...)
{
	if (Level == LOG_LEVEL_DEBUG) {
#ifndef DEBUG
		return;
#endif
	}

	char *time = FormatTime(GetUnixTimestampMilliseconds()); {
		switch (Level) {
			case LOG_LEVEL_SUCCESS: {
				printf("[OK]\t%s ", time);
				break;
			}
			case LOG_LEVEL_ERROR: {
				printf("[ERROR]\t%s ", time);
				break;
			}
			case LOG_LEVEL_WARNING: {
				printf("[WARN]\t%s ", time);
				break;
			}
			case LOG_LEVEL_DEBUG: {
				printf("[DEBUG]\t (%s:%d) %s ", File, Line, time);
				break;
			}
		}
	} free(time);

	va_list args;
	va_start(args, Format); {
		vprintf(Format, args);
	} va_end(args);
	printf("\n");
}
#pragma once

typedef enum _LOG_LEVEL {
	LOG_LEVEL_SUCCESS,
	LOG_LEVEL_ERROR,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_DEBUG
} LOG_LEVEL;

void Log(LOG_LEVEL Level, const char *Format, ...);
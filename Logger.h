#pragma once

typedef enum _LOG_LEVEL {
	LOG_LEVEL_SUCCESS,
	LOG_LEVEL_ERROR,
	LOG_LEVEL_WARNING,
	LOG_LEVEL_DEBUG
} LOG_LEVEL;

void _Log(char *File, int Line, LOG_LEVEL Level, const char *Format, ...);
#define Log(Level, Format, ...) _Log(__FILE__, __LINE__, Level, Format, ##__VA_ARGS__)
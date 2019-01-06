#ifndef _LOG_H_
#define _LOG_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#define LLOG_ERROR 1
#define LLOG_WARNING 2
#define LLOG_NOTICE 3
#define LLOG_INFO 4
#define LLOG_DEBUG 5

#define LLOG_DISPLAY_LEVEL LLOG_DEBUG

/* expands to the first argument */
#define FIRST(...) FIRST_HELPER(__VA_ARGS__, throwaway)
#define FIRST_HELPER(first, ...) first

#ifdef __cplusplus
extern "C" {
#endif

// #define LLOG(level, ...) ((level <= LLOG_DISPLAY_LEVEL) && fprintf(stderr, "[%s]%.0s: " FIRST(__VA_ARGS__) "\n", llog_level_names[level], __VA_ARGS__))
#define LLOG(level, ...) LLog_log(level, __VA_ARGS__)

void LLog_log(int level, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif // _LOG_H_

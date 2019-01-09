#include <string.h>
#include <base/llog.h>

static char *llog_level_names[] = { NULL, "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG" };
void LLog_log(int level, const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);

  if (level <= LLOG_DISPLAY_LEVEL) {
    fprintf(stderr, "[%s]: ", llog_level_names[level]);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
  }

  va_end(ap);
}

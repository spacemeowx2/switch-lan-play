#include <base/llog.h>

void rt_assert(int val, const char *exp)
{
    if (!val) {
        LLOG(LLOG_ERROR, "assert failed: %s", exp);
        exit(1);
    }
}

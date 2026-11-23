/*
 * Link-time hooks for the dynamic_enhanced executions (linked with -Wl,--wrap=realloc -Wl,--wrap=time).
 * Adapted from cs224proj/dynamic_enhanced/dyne/assets/inject_realloc.c.
 *
 * With no environment variable set, both wrappers forward to the real functions unchanged, so the
 * binary behaves like the plain ASan build (asan_lsan / asan_lsan_default runs use it that way).
 *
 * DYNENH_REALLOC_FAIL=1  the first realloc() that receives a non-NULL pointer returns NULL and
 *                        leaves the block untouched (a real realloc failure).  realloc(NULL, n) is
 *                        passed through, so a first allocation done with realloc keeps its meaning.
 *                        The injection is reported on fd 2 with write(2) (no allocation).
 * DYNENH_TIME=<n>        time() returns n, so srand(time(NULL)) gets a fixed, chosen seed.
 *
 * __real_realloc resolves to the ASan interceptor, so LSan still tracks the abandoned block.
 */
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

void *__real_realloc(void *, size_t);
time_t __real_time(time_t *);

static int injected = 0;

void *__wrap_realloc(void *ptr, size_t size)
{
    if (!injected && ptr != NULL && getenv("DYNENH_REALLOC_FAIL") != NULL) {
        injected = 1;
        (void)write(2, "[dynenh] injected realloc failure\n", 34);
        return NULL;
    }
    return __real_realloc(ptr, size);
}

time_t __wrap_time(time_t *t)
{
    const char *fixed = getenv("DYNENH_TIME");
    if (fixed == NULL) {
        return __real_time(t);
    }
    time_t value = (time_t)atol(fixed);
    if (t != NULL) {
        *t = value;
    }
    return value;
}

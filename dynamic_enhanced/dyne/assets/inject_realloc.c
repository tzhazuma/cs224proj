/*
 * Link-time fault injection for realloc().
 *
 * The binary is linked with -Wl,--wrap=realloc, so every call to realloc()
 * from the unit's translation units is redirected here.  The wrapper:
 *   - logs each call to fd 2 with write(2), so the log itself cannot allocate
 *     through malloc/realloc;
 *   - fails the first call that receives a non-NULL pointer when
 *     DYNENH_REALLOC_FAIL_NONNULL=1, returning NULL without touching the
 *     original block.  A NULL-argument realloc is passed through: failing it
 *     would only short-circuit the unit's allocation instead of exercising
 *     the "reallocation of an existing block failed" path.
 *
 * __real_realloc resolves to the sanitizer interceptor in ASan builds, so the
 * allocator bookkeeping stays consistent and LSan can see the abandoned block.
 */

#include <stdlib.h>
#include <unistd.h>

void *__real_realloc(void *, size_t);

static long call_count = 0;
static int injected = 0;

static void emit_hex(const char *prefix, unsigned long value, const char *suffix)
{
    char buf[192];
    int n = 0;
    const char *p;
    for (p = prefix; *p != '\0'; ++p) {
        buf[n++] = *p;
    }
    char digits[24];
    int d = 0;
    if (value == 0) {
        digits[d++] = '0';
    }
    while (value > 0 && d < (int)sizeof(digits)) {
        digits[d++] = (char)('0' + (value % 10));
        value /= 10;
    }
    while (d > 0) {
        buf[n++] = digits[--d];
    }
    for (p = suffix; *p != '\0'; ++p) {
        buf[n++] = *p;
    }
    buf[n++] = '\n';
    (void)write(2, buf, (size_t)n);
}

void *__wrap_realloc(void *ptr, size_t size)
{
    call_count += 1;
    emit_hex("[dynenh] realloc #", (unsigned long)call_count, "");
    if (ptr == NULL) {
        (void)write(2, "[dynenh] realloc ptr=NULL\n", 26);
    } else {
        (void)write(2, "[dynenh] realloc ptr=nonnull\n", 29);
    }
    if (!injected && ptr != NULL && getenv("DYNENH_REALLOC_FAIL_NONNULL") != NULL) {
        injected = 1;
        emit_hex("[dynenh] injected NULL at call ", (unsigned long)call_count, "");
        return NULL;
    }
    return __real_realloc(ptr, size);
}

/*
 * L4-D gold-label hooks (linked with -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc,--wrap=free,
 * --wrap=strdup,--wrap=wcsdup,--wrap=time; C++ units also link l4d_trace_new.cpp).
 *
 * Every allocation / release done by the program is written to the file named by $L4D_TRACE, one event per line,
 * with the raw return addresses of the call stack (backtrace(); the binary is linked -no-pie, so gold.py can
 * symbolize them with addr2line):
 *   A <id> <kind> | <addr> <addr> ...        new block <id> (kind malloc|calloc|realloc|strdup|wcsdup|new|new[])
 *   F <id> <kind> | ...                       block <id> released (free|delete|delete[]|realloc)
 *   R <old> <new> | ...                       successful realloc of a tracked block: <old> released, <new> allocated
 *   I <old> | ...                             injected realloc failure on block <old> (returns NULL, block untouched)
 *   U <kind> | ...                            release of a pointer that is not a tracked block (e.g. Juliet's
 *                                             variant-12 free of an ALLOCA buffer); it is NOT passed to the real
 *                                             free, so the run continues instead of aborting in glibc
 * Environment:
 *   L4D_TIME=<n>          time() returns n (fixes srand(time(NULL)); same convention as data/dynamic/inject.c)
 *   L4D_FAIL_REALLOC=<k>  the k-th realloc() of a non-NULL pointer returns NULL and leaves the block untouched
 */
#define _GNU_SOURCE
#include <execinfo.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void __real_free(void *);
char *__real_strdup(const char *);
wchar_t *__real_wcsdup(const wchar_t *);
time_t __real_time(time_t *);

#define TABLE 65536
#define DEPTH 24
static void *keys[TABLE];
static long ids[TABLE];
static long next_id = 1;
static int trace_fd = -2;
static long realloc_count = 0;
static int busy = 0;

static size_t slot(void *p)
{
    uintptr_t h = (uintptr_t)p;
    h ^= h >> 17;
    h *= 0x9E3779B97F4A7C15ull;
    return (size_t)(h >> 7) & (TABLE - 1);
}

static long table_put(void *p)
{
    size_t i = slot(p);
    while (keys[i] != NULL && keys[i] != (void *)1) {
        i = (i + 1) & (TABLE - 1);
    }
    keys[i] = p;
    ids[i] = next_id++;
    return ids[i];
}

static long table_take(void *p)
{
    size_t i = slot(p);
    while (keys[i] != NULL) {
        if (keys[i] == p) {
            keys[i] = (void *)1; /* tombstone */
            return ids[i];
        }
        i = (i + 1) & (TABLE - 1);
    }
    return 0;
}

static long table_find(void *p)
{
    size_t i = slot(p);
    while (keys[i] != NULL) {
        if (keys[i] == p) {
            return ids[i];
        }
        i = (i + 1) & (TABLE - 1);
    }
    return 0;
}

static void emit(const char *head)
{
    if (trace_fd == -2) {
        const char *path = getenv("L4D_TRACE");
        trace_fd = path ? open(path, O_WRONLY | O_CREAT | O_APPEND, 0644) : -1;
    }
    if (trace_fd < 0) {
        return;
    }
    char buf[1024];
    void *frames[DEPTH];
    int n = backtrace(frames, DEPTH);
    int len = snprintf(buf, sizeof buf, "%s |", head);
    for (int i = 1; i < n && len < (int)sizeof buf - 24; i++) { /* frame 0 is emit() */
        len += snprintf(buf + len, sizeof buf - len, " %lx", (unsigned long)(uintptr_t)frames[i]);
    }
    buf[len++] = '\n';
    (void)write(trace_fd, buf, len);
}

__attribute__((constructor)) static void l4d_init(void)
{
    void *frames[2];
    busy = 1;
    backtrace(frames, 2); /* loads the unwinder before the program runs */
    busy = 0;
}

void *l4d_raw_malloc(size_t n) { return __real_malloc(n); }
void l4d_raw_free(void *p) { __real_free(p); }

void l4d_alloc_event(void *p, const char *kind)
{
    if (p == NULL || busy) {
        return;
    }
    busy = 1;
    char head[96];
    snprintf(head, sizeof head, "A %ld %s", table_put(p), kind);
    emit(head);
    busy = 0;
}

/* returns 1 if p is a tracked block (caller then releases it for real) */
int l4d_release_event(void *p, const char *kind)
{
    if (p == NULL) {
        return 0;
    }
    if (busy) {
        return table_take(p) != 0;
    }
    busy = 1;
    char head[96];
    long id = table_take(p);
    if (id) {
        snprintf(head, sizeof head, "F %ld %s", id, kind);
    } else {
        snprintf(head, sizeof head, "U %s", kind);
    }
    emit(head);
    busy = 0;
    return id != 0;
}

void *__wrap_malloc(size_t n)
{
    void *p = __real_malloc(n);
    l4d_alloc_event(p, "malloc");
    return p;
}

void *__wrap_calloc(size_t a, size_t b)
{
    void *p = __real_calloc(a, b);
    l4d_alloc_event(p, "calloc");
    return p;
}

char *__wrap_strdup(const char *s)
{
    char *p = __real_strdup(s);
    l4d_alloc_event(p, "strdup");
    return p;
}

wchar_t *__wrap_wcsdup(const wchar_t *s)
{
    wchar_t *p = __real_wcsdup(s);
    l4d_alloc_event(p, "wcsdup");
    return p;
}

void __wrap_free(void *p)
{
    if (l4d_release_event(p, "free")) {
        __real_free(p);
    }
}

void *__wrap_realloc(void *p, size_t n)
{
    if (p == NULL) {
        void *q = __real_realloc(NULL, n);
        l4d_alloc_event(q, "realloc");
        return q;
    }
    if (busy) {
        return __real_realloc(p, n);
    }
    char head[96];
    long old = table_find(p);
    realloc_count++;
    const char *fail = getenv("L4D_FAIL_REALLOC");
    if (fail != NULL && atol(fail) == realloc_count) {
        busy = 1;
        snprintf(head, sizeof head, "I %ld", old);
        emit(head);
        busy = 0;
        return NULL;
    }
    void *q = __real_realloc(p, n);
    if (q == NULL) {
        return NULL;
    }
    busy = 1;
    if (old) {
        table_take(p);
    }
    snprintf(head, sizeof head, "R %ld %ld", old, table_put(q));
    emit(head);
    busy = 0;
    return q;
}

time_t __wrap_time(time_t *t)
{
    const char *fixed = getenv("L4D_TIME");
    if (fixed == NULL) {
        return __real_time(t);
    }
    time_t value = (time_t)atol(fixed);
    if (t != NULL) {
        *t = value;
    }
    return value;
}

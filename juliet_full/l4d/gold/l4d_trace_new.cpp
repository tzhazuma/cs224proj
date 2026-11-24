// Global operator new/new[]/delete/delete[] replacements for the L4-D gold trace (see l4d_trace.c).
// Blocks come from the real malloc, so they never appear twice in the trace; releases of untracked pointers
// are logged (U) and not passed to free.
#include <cstddef>
#include <new>

extern "C" {
void *l4d_raw_malloc(std::size_t n);
void l4d_raw_free(void *p);
void l4d_alloc_event(void *p, const char *kind);
int l4d_release_event(void *p, const char *kind);
}

static void *take(std::size_t n, const char *kind)
{
    void *p = l4d_raw_malloc(n ? n : 1);
    if (p == nullptr) {
        throw std::bad_alloc();
    }
    l4d_alloc_event(p, kind);
    return p;
}

static void *take_nothrow(std::size_t n, const char *kind) noexcept
{
    void *p = l4d_raw_malloc(n ? n : 1);
    l4d_alloc_event(p, kind);
    return p;
}

static void give(void *p, const char *kind) noexcept
{
    if (l4d_release_event(p, kind)) {
        l4d_raw_free(p);
    }
}

void *operator new(std::size_t n) { return take(n, "new"); }
void *operator new[](std::size_t n) { return take(n, "new[]"); }
void *operator new(std::size_t n, const std::nothrow_t &) noexcept { return take_nothrow(n, "new"); }
void *operator new[](std::size_t n, const std::nothrow_t &) noexcept { return take_nothrow(n, "new[]"); }
void operator delete(void *p) noexcept { give(p, "delete"); }
void operator delete[](void *p) noexcept { give(p, "delete[]"); }
void operator delete(void *p, std::size_t) noexcept { give(p, "delete"); }
void operator delete[](void *p, std::size_t) noexcept { give(p, "delete[]"); }
void operator delete(void *p, const std::nothrow_t &) noexcept { give(p, "delete"); }
void operator delete[](void *p, const std::nothrow_t &) noexcept { give(p, "delete[]"); }

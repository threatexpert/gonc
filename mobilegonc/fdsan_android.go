//go:build android

package mobilegonc

/*
#include <dlfcn.h>
#include <stdint.h>

typedef uint64_t (*fn_get_owner_tag)(int);
typedef void     (*fn_exchange_owner_tag)(int, uint64_t, uint64_t);

static fn_get_owner_tag      g_get_owner_tag      = (fn_get_owner_tag)0;
static fn_exchange_owner_tag g_exchange_owner_tag = (fn_exchange_owner_tag)0;
static int                   g_fdsan_init         = 0;

// init_fdsan_funcs loads android_fdsan_* via dlsym (available API 29+).
// Safe to call multiple times; the race on g_fdsan_init is benign because
// dlsym is idempotent and we only set pointers, never free them.
static void init_fdsan_funcs(void) {
    if (g_fdsan_init) return;
    g_fdsan_init = 1;
    g_get_owner_tag      = (fn_get_owner_tag)(uintptr_t)
                           dlsym(RTLD_DEFAULT, "android_fdsan_get_owner_tag");
    g_exchange_owner_tag = (fn_exchange_owner_tag)(uintptr_t)
                           dlsym(RTLD_DEFAULT, "android_fdsan_exchange_owner_tag");
}

// clear_fdsan_tag removes the ownership tag that Android's detachFd() leaves
// on a file descriptor without closing it. After this call, raw unix.Close()
// on the fd is fdsan-safe (tag is 0, leaving no dangling ownership record when the
// kernel recycles the fd number for GPU fence objects).
static void clear_fdsan_tag(int fd) {
    init_fdsan_funcs();
    if (!g_get_owner_tag || !g_exchange_owner_tag) return;
    uint64_t tag = g_get_owner_tag(fd);
    if (tag != 0) {
        g_exchange_owner_tag(fd, tag, 0);
    }
}
*/
import "C"

func clearFdsanTag(fd int) {
	C.clear_fdsan_tag(C.int(fd))
}

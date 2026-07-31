/* fixture 2 的外部侧：保存 + 晚调，但注销**真的**清空槽位。
 *
 * Q1  MayRetain
 * Q3  MayInvokeAfterReturn
 * Q4' ClearsOnAllPaths —— fixture_unregister 在唯一一条路径上把两个槽位都写回 NULL，
 *     此后 fixture_fire 不可能再取到那个回调。
 *
 * 与 retain_late_invoke_leaky.c 的差别只有 fixture_unregister 的实现。Rust 侧完全相同。
 */

#include <stddef.h>

typedef void (*fixture_callback)(void *);

static fixture_callback g_callback = NULL;
static void *g_user_data = NULL;

void fixture_register(fixture_callback callback, void *user_data) {
    g_callback = callback;
    g_user_data = user_data;
}

void fixture_unregister(void) {
    g_callback = NULL;
    g_user_data = NULL;
}

void fixture_fire(void) {
    if (g_callback) {
        g_callback(g_user_data);
    }
}

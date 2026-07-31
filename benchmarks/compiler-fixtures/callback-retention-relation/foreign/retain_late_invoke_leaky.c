/* fixture 3 的外部侧：保存 + 晚调，注销**没清干净**。
 *
 * Q1  MayRetain
 * Q3  MayInvokeAfterReturn
 * Q4' MayLeaveSlotPopulated —— 注册时把回调同时写进了两个槽位（一个「当前」、一个
 *     「派发缓存」），而 fixture_unregister 只清了前者。fixture_fire 在主槽位为空时
 *     回退到缓存槽位，于是注销之后回调仍然可能被调用。
 *
 * 这是「guard 被击穿」的形状：Rust 侧的 Registration guard 忠实地在 drop 时调用了
 * 注销，但那次注销没有真的解除注册。**Rust 侧看不见这一点**——它只能看到 Drop 里
 * 调了一个 extern 函数。
 *
 * 与 retain_late_invoke_clearing.c 的差别只有槽位数量与 fixture_unregister 的实现。
 * Rust 侧完全相同。
 */

#include <stddef.h>

typedef void (*fixture_callback)(void *);

static fixture_callback g_callback = NULL;
static void *g_user_data = NULL;

/* 派发缓存：注册时一并写入，注销时被遗漏。 */
static fixture_callback g_cached_callback = NULL;
static void *g_cached_user_data = NULL;

void fixture_register(fixture_callback callback, void *user_data) {
    g_callback = callback;
    g_user_data = user_data;
    g_cached_callback = callback;
    g_cached_user_data = user_data;
}

void fixture_unregister(void) {
    /* 只清了主槽位。缓存槽位仍然持有同一个回调指针。 */
    g_callback = NULL;
    g_user_data = NULL;
}

void fixture_fire(void) {
    if (g_callback) {
        g_callback(g_user_data);
    } else if (g_cached_callback) {
        g_cached_callback(g_cached_user_data);
    }
}

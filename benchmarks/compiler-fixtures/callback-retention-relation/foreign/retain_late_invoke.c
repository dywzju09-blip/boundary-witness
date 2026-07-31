/* fixture 1 与 fixture 4 的外部侧：保存 + 晚调，没有注销。
 *
 * Q1 MayRetain            —— 回调与 user data 被写进跨调用存活的全局槽位
 * Q3 MayInvokeAfterReturn —— fixture_fire 在 fixture_register 返回之后才调用它
 * Q4' 不适用              —— 本 stub 不提供注销
 */

#include <stddef.h>

typedef void (*fixture_callback)(void *);

static fixture_callback g_callback = NULL;
static void *g_user_data = NULL;

void fixture_register(fixture_callback callback, void *user_data) {
    g_callback = callback;
    g_user_data = user_data;
}

/* 由外部组件在稍后某个时刻调用——注册那次调用早已返回。 */
void fixture_fire(void) {
    if (g_callback) {
        g_callback(g_user_data);
    }
}

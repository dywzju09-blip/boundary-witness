/* 负对照与非空性检查用的外部侧：只同步调用，从不保存。
 *
 * Q1  NoRetain              —— 回调指针没有到达任何跨调用存活的存储
 * Q3  SynchronousInvokeOnly —— 只在 fixture_register 内部调用一次
 * Q4' 不适用
 *
 * 无论 Rust 侧的 bound 多松，这个外部实现都不会让安全客户端触发释放后使用。
 * 把它换给 fixture 1 或 fixture 3 时，判定必须翻转为相容——这是判定器接了外部侧
 * 证据的证明。
 */

#include <stddef.h>

typedef void (*fixture_callback)(void *);

void fixture_register(fixture_callback callback, void *user_data) {
    if (callback) {
        callback(user_data);
    }
    /* 返回前不保存任何指针。 */
}

void fixture_unregister(void) {
    /* 没有槽位可清。 */
}

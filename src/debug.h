#ifndef DEBUG_H
#define DEBUG_H

/*
 * debug.h — 调试输出宏封装
 * 级别:
 *   LEVEL_NONE = 0  无调试信息
 *   LEVEL_BASIC = 1 仅输出时间、序号、客户端IP、查询域名 (-d)
 *   LEVEL_VERBOSE = 2 输出冗长调试信息 (-dd)
 */

#include <stdio.h>
#include <time.h>

/* 调试级别 */
typedef enum {
    DEBUG_NONE    = 0,
    DEBUG_BASIC   = 1,
    DEBUG_VERBOSE = 2
} debug_level_t;

/* 全局调试级别 (在 main.c 中定义) */
extern debug_level_t g_debug_level;

/* 获取当前时间字符串 (线程不安全，仅用于调试输出) */
static inline const char *debug_timestamp(void) {
    static char buf[32];
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(buf, sizeof(buf), "%H:%M:%S", tm);
    return buf;
}

/* 调试宏: 仅在级别>=要求时输出 */
#define DEBUG_PRINTF(level, fmt, ...)                                   \
    do {                                                                \
        if (g_debug_level >= (level)) {                                 \
            fprintf(stderr, "[%s] " fmt "\n",                           \
                    debug_timestamp(), ##__VA_ARGS__);                  \
        }                                                               \
    } while (0)

/* 级别1: 基本信息 */
#define DEBUG_BASIC(fmt, ...)    DEBUG_PRINTF(DEBUG_BASIC, fmt, ##__VA_ARGS__)

/* 级别2: 详细信息 */
#define DEBUG_VERBOSE(fmt, ...)  DEBUG_PRINTF(DEBUG_VERBOSE, fmt, ##__VA_ARGS__)

/* 错误输出 (总是显示) */
#define DEBUG_ERROR(fmt, ...)                                           \
    do {                                                                \
        fprintf(stderr, "[ERROR] [%s] " fmt "\n",                      \
                debug_timestamp(), ##__VA_ARGS__);                      \
    } while (0)

#endif /* DEBUG_H */

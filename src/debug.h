#ifndef DEBUG_H
#define DEBUG_H

/*
 * debug.h — 调试输出封装
 *
 * 提供分级调试输出，不调试时零 CPU 开销
 * 级别: 0 = 无, 1 = 基本信息 (-d), 2 = 详细调试 (-dd)
 *
 * 调试级别 1：输出时间坐标、序号、客户端 IP、查询域名
 * 调试级别 2：更详细的报文转储
 */

#include <stdio.h>
#include <time.h>
#include <stdint.h>

/* 调试级别 */
#define DEBUG_LEVEL_NONE    0
#define DEBUG_LEVEL_BASIC   1
#define DEBUG_LEVEL_VERBOSE 2

/* 全局调试级别 (在 debug.c 中定义) */
extern int g_debug_level;
extern int g_query_seq;  /* 递增查询序号 */

/* 获取当前时间字符串 */
const char *debug_timestamp(void);

/* 十六进制转储 (-dd 级别使用) */
void dump_hex(FILE *fp, const uint8_t *data, int len);

/*
 * DEBUG(level, fmt, ...) — 按级别输出调试信息
 *
 * 用法:
 *   DEBUG(1, "query from %s for %s", ip_str, domain);
 *   DEBUG(2, "Raw packet (%d bytes):", len);
 *   dump_hex(stderr, packet, len);   // -dd 级别
 */
#define DEBUG(level, fmt, ...)                                          \
    do {                                                                \
        if (g_debug_level >= (level)) {                                 \
            fprintf(stderr, "[%s] [%d] " fmt "\n",                      \
                    debug_timestamp(), g_query_seq, ##__VA_ARGS__);      \
            fflush(stderr);                                             \
        }                                                               \
    } while (0)

/* 错误输出 (总是显示) */
#define DEBUG_ERROR(fmt, ...)                                           \
    do {                                                                \
        fprintf(stderr, "[ERROR] [%s] " fmt "\n",                       \
                debug_timestamp(), ##__VA_ARGS__);                      \
        fflush(stderr);                                                 \
    } while (0)

#endif /* DEBUG_H */

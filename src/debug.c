#include "debug.h"

/*
 * debug.c — 调试输出实现
 */

int g_debug_level = 0;      /* 默认关闭调试 */
int g_query_seq = 0;        /* 递增查询序号 */

const char *debug_timestamp(void) {
    static char buf[32];
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(buf, sizeof(buf), "%H:%M:%S", tm);
    return buf;
}

void dump_hex(FILE *fp, const uint8_t *data, int len) {
    if (!fp || !data || len <= 0) return;

    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) {
            fprintf(fp, "%04x: ", i);
        }
        fprintf(fp, "%02x ", data[i]);
        if (i % 16 == 15 || i == len - 1) {
            fprintf(fp, "\n");
        }
    }
}

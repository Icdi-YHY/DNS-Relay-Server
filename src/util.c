#include "util.h"
#include "platform.h"

#include <string.h>

/*
 * util.c — 工具函数实现
 */

int encode_domain_name(uint8_t *buf, const char *domain) {
    if (!buf || !domain) return -1;

    const char *p = domain;
    const char *dot;
    size_t total = 0;

    while (*p) {
        if (*p == '.') { p++; continue; }

        dot = strchr(p, '.');
        size_t seg_len = dot ? (size_t)(dot - p) : strlen(p);

        if (seg_len > 63) return -1;

        buf[total++] = (uint8_t)seg_len;
        memcpy(buf + total, p, seg_len);
        total += seg_len;

        p = dot ? dot + 1 : p + seg_len;
    }

    buf[total++] = 0;  /* 根标签 */
    return (int)total;
}

const char *decode_domain_name(const uint8_t *msg, int msg_len,
                               int *offset, char *out) {
    if (!msg || !offset || !out) return NULL;

    int pos = *offset;
    int out_pos = 0;
    int jumped = 0;

    while (pos < msg_len && msg[pos] != 0) {
        if ((msg[pos] & 0xC0) == 0xC0) {
            /* 压缩指针 */
            if (pos + 1 >= msg_len) return NULL;
            int ptr = ((msg[pos] & 0x3F) << 8) | msg[pos + 1];
            if (ptr >= msg_len) return NULL;

            if (!jumped) {
                *offset = pos + 2;
                jumped = 1;
            }
            pos = ptr;
            continue;
        }

        int len = msg[pos++];
        if (pos + len > msg_len) return NULL;

        if (len > 0) {
            if (out_pos > 0) out[out_pos++] = '.';
            memcpy(out + out_pos, msg + pos, len);
            out_pos += len;
        }
        pos += len;
    }

    out[out_pos] = '\0';

    if (!jumped)
        *offset = pos + 1;  /* +1 for root label */

    return out;
}

uint32_t ip_str_to_int(const char *ip_str) {
    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) == 1)
        return addr.s_addr;
    return 0;
}

const char *ip_int_to_str(uint32_t ip, char *buf) {
    struct in_addr addr;
    addr.s_addr = ip;
    inet_ntop(AF_INET, &addr, buf, 16);
    return buf;
}

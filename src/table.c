#include "table.h"
#include "debug.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

/*
 * table.c — 域名-IP 对照表哈希表实现
 *
 * 哈希函数: djb2 变体，对域名计算哈希
 */

/* djb2 哈希算法 */
static unsigned long hash_str(const char *str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++)) {
        /* 域名不区分大小写，统一转小写 */
        hash = ((hash << 5) + hash) + tolower(c);
    }

    return hash % TABLE_HASH_SIZE;
}

void table_init(table_t *tbl) {
    if (!tbl) return;
    memset(tbl, 0, sizeof(table_t));
}

int table_load_file(table_t *tbl, const char *filename) {
    if (!tbl || !filename)
        return -1;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        DEBUG_ERROR("无法打开对照表文件: %s", filename);
        return -1;
    }

    tbl->filename = strdup(filename);
    char line[1024];
    size_t count = 0;

    while (fgets(line, sizeof(line), fp)) {
        char *p = line;

        /* 跳过前导空白 */
        while (*p && isspace((unsigned char)*p)) p++;

        /* 跳过空行和注释 */
        if (*p == '\0' || *p == '\n' || *p == '#')
            continue;

        /* 解析 IP 地址 */
        char ip_str[64];
        int ip_len = 0;
        while (*p && !isspace((unsigned char)*p) && ip_len < 63)
            ip_str[ip_len++] = *p++;
        ip_str[ip_len] = '\0';

        if (ip_len == 0)
            continue;

        /* 跳过空白到域名 */
        while (*p && isspace((unsigned char)*p)) p++;

        /* 解析域名 */
        char domain[256];
        int dom_len = 0;
        while (*p && !isspace((unsigned char)*p) && *p != '\n' && *p != '\r' && dom_len < 255)
            domain[dom_len++] = *p++;
        domain[dom_len] = '\0';

        if (dom_len == 0)
            continue;

        /* 转换 IP 地址 */
        struct in_addr addr;
        if (inet_pton(AF_INET, ip_str, &addr) != 1) {
            DEBUG_VERBOSE("跳过无效IP: %s (域名: %s)", ip_str, domain);
            continue;
        }

        /* 添加到哈希表 */
        unsigned long idx = hash_str(domain);
        table_entry_t *entry = (table_entry_t *)malloc(sizeof(table_entry_t));
        if (!entry) {
            DEBUG_ERROR("内存分配失败");
            fclose(fp);
            return -1;
        }

        entry->domain = strdup(domain);
        entry->ip_addr = addr.s_addr;  /* 已经是网络字节序 */
        entry->next = tbl->buckets[idx];
        tbl->buckets[idx] = entry;
        count++;
    }

    fclose(fp);
    tbl->count = count;
    DEBUG_BASIC("加载了 %zu 条域名-IP 记录", count);
    return (int)count;
}

int table_lookup(const table_t *tbl, const char *domain, uint32_t *ip_addr) {
    if (!tbl || !domain || !ip_addr)
        return 0;

    unsigned long idx = hash_str(domain);

    for (table_entry_t *e = tbl->buckets[idx]; e; e = e->next) {
#ifdef PLATFORM_WIN
        if (_stricmp(e->domain, domain) == 0) {
#else
        if (strcasecmp(e->domain, domain) == 0) {
#endif
            *ip_addr = e->ip_addr;
            return 1;
        }
    }

    return 0;
}

void table_destroy(table_t *tbl) {
    if (!tbl) return;

    for (size_t i = 0; i < TABLE_HASH_SIZE; i++) {
        table_entry_t *e = tbl->buckets[i];
        while (e) {
            table_entry_t *next = e->next;
            free(e->domain);
            free(e);
            e = next;
        }
        tbl->buckets[i] = NULL;
    }

    free(tbl->filename);
    tbl->filename = NULL;
    tbl->count = 0;
}

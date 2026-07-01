#include "dns_table.h"
#include "debug.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

/*
 * dns_table.c — 域名对照表哈希表实现
 *
 * 哈希函数: DJB2 算法（对域名不区分大小写）
 */

/* DJB2 哈希算法 */
static unsigned long hash_string(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;  /* hash * 33 + c */
    return hash;
}

int dns_table_init(DNSTable *t, int size) {
    if (!t || size <= 0) return -1;

    t->buckets = (TableEntry **)calloc((size_t)size, sizeof(TableEntry *));
    if (!t->buckets) return -1;

    t->size = size;
    t->count = 0;
    return 0;
}

int dns_table_load(DNSTable *t, const char *filename) {
    if (!t || !filename) return -1;

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        DEBUG_ERROR("无法打开对照表文件: %s", filename);
        return -1;
    }

    char line[1024];
    int load_count = 0;

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

        if (ip_len == 0) continue;

        /* 跳过空白到域名 */
        while (*p && isspace((unsigned char)*p)) p++;

        /* 解析域名 */
        char domain[256];
        int dom_len = 0;
        while (*p && !isspace((unsigned char)*p) && *p != '\n' && *p != '\r'
               && dom_len < 255)
            domain[dom_len++] = *p++;
        domain[dom_len] = '\0';

        if (dom_len == 0) continue;

        /* 转换 IP 地址 */
        struct in_addr addr;
        if (inet_pton(AF_INET, ip_str, &addr) != 1) {
            DEBUG(2, "跳过无效IP: %s (域名: %s)", ip_str, domain);
            continue;
        }

        /* 添加到哈希表 */
        unsigned long idx = hash_string(domain) % (unsigned long)t->size;
        TableEntry *entry = (TableEntry *)malloc(sizeof(TableEntry));
        if (!entry) {
            DEBUG_ERROR("内存分配失败");
            fclose(fp);
            return -1;
        }

        strncpy(entry->domain, domain, sizeof(entry->domain) - 1);
        entry->domain[sizeof(entry->domain) - 1] = '\0';
        entry->ip = addr.s_addr;  /* 已经是网络字节序 */
        entry->next = t->buckets[idx];
        t->buckets[idx] = entry;
        load_count++;
    }

    fclose(fp);
    t->count = (size_t)load_count;
    DEBUG(1, "加载了 %d 条域名-IP 记录", load_count);
    return load_count;
}

int dns_table_lookup_all(DNSTable *t, const char *domain, uint32_t *ips, int max_ips) {
    if (!t || !domain || !ips || max_ips <= 0) return 0;

    unsigned long idx = hash_string(domain) % (unsigned long)t->size;
    int count = 0;

    for (TableEntry *e = t->buckets[idx]; e; e = e->next) {
#ifdef PLATFORM_WIN
        if (_stricmp(e->domain, domain) == 0) {
#else
        if (strcasecmp(e->domain, domain) == 0) {
#endif
            if (e->ip == 0) return -1;  /* 拦截优先 */
            if (count < max_ips) {
                ips[count++] = e->ip;
            }
        }
    }

    return count;
}

int dns_table_lookup(DNSTable *t, const char *domain, uint32_t *ip) {
    if (!t || !domain || !ip) return 0;

    unsigned long idx = hash_string(domain) % (unsigned long)t->size;

    for (TableEntry *e = t->buckets[idx]; e; e = e->next) {
#ifdef PLATFORM_WIN
        if (_stricmp(e->domain, domain) == 0) {
#else
        if (strcasecmp(e->domain, domain) == 0) {
#endif
            *ip = e->ip;
            return 1;
        }
    }

    return 0;
}

int dns_table_add(DNSTable *t, const char *domain, uint32_t ip, int ttl) {
    if (!t || !domain) return -1;

    (void)ttl;  /* 统一管理过期，暂不使用 per-entry TTL */

    unsigned long idx = hash_string(domain) % (unsigned long)t->size;

    /* 先检查是否已存在，存在则更新 IP */
    for (TableEntry *e = t->buckets[idx]; e; e = e->next) {
#ifdef PLATFORM_WIN
        if (_stricmp(e->domain, domain) == 0) {
#else
        if (strcasecmp(e->domain, domain) == 0) {
#endif
            e->ip = ip;
            return 0;
        }
    }

    /* 不存在则创建新条目 */
    TableEntry *entry = (TableEntry *)malloc(sizeof(TableEntry));
    if (!entry) return -1;

    strncpy(entry->domain, domain, sizeof(entry->domain) - 1);
    entry->domain[sizeof(entry->domain) - 1] = '\0';
    entry->ip = ip;
    entry->next = t->buckets[idx];
    t->buckets[idx] = entry;
    t->count++;

    return 0;
}

void dns_table_destroy(DNSTable *t) {
    if (!t || !t->buckets) return;

    for (int i = 0; i < t->size; i++) {
        TableEntry *e = t->buckets[i];
        while (e) {
            TableEntry *next = e->next;
            free(e);
            e = next;
        }
        t->buckets[i] = NULL;
    }

    free(t->buckets);
    t->buckets = NULL;
    t->count = 0;
    t->size = 0;
}

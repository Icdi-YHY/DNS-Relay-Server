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
 * 支持记录类型: A, AAAA, CNAME, MX, NS, PTR
 */

/* DJB2 哈希算法 */
static unsigned long hash_string(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

/* 识别类型前缀 */
static int parse_type(const char *s, int *type) {
    if (!s || !type) return 0;
         if (strcasecmp(s, "AAAA") == 0) { *type = 28; return 1; }
    else if (strcasecmp(s, "CNAME") == 0) { *type = 5;  return 1; }
    else if (strcasecmp(s, "MX") == 0)    { *type = 15; return 1; }
    else if (strcasecmp(s, "NS") == 0)    { *type = 2;  return 1; }
    else if (strcasecmp(s, "PTR") == 0)   { *type = 12; return 1; }
    return 0;  /* 不是类型前缀，当成 A 记录处理 */
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
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '\0' || *p == '\n' || *p == '#') continue;

        /* 读第一个 token */
        char token1[64];
        int t1_len = 0;
        while (*p && !isspace((unsigned char)*p) && t1_len < 63)
            token1[t1_len++] = *p++;
        token1[t1_len] = '\0';
        if (t1_len == 0) continue;

        /* 跳过空白 */
        while (*p && isspace((unsigned char)*p)) p++;

        /* 读第二个 token */
        char token2[256];
        int t2_len = 0;
        while (*p && !isspace((unsigned char)*p) && *p != '\n' && *p != '\r' && t2_len < 255)
            token2[t2_len++] = *p++;
        token2[t2_len] = '\0';

        /* 跳过空白 */
        while (*p && isspace((unsigned char)*p)) p++;

        /* 读第三个 token（如果有） */
        char token3[256];
        int t3_len = 0;
        while (*p && !isspace((unsigned char)*p) && *p != '\n' && *p != '\r' && t3_len < 255)
            token3[t3_len++] = *p++;
        token3[t3_len] = '\0';

        int entry_type = 1;  /* 默认 A 记录 */
        uint32_t ip = 0;
        char data[256] = "";
        char domain[256] = "";
        int has_type_prefix = parse_type(token1, &entry_type);

        if (has_type_prefix) {
            /* 格式: TYPE VALUE DOMAIN */
            strcpy(domain, token3);
            if (entry_type == 1 || entry_type == 28) {
                /* A/AAAA: token2 是 IP 地址 */
                strcpy(data, token2);
            } else {
                /* CNAME/MX/NS/PTR: token2 是目标域名 */
                strncpy(data, token2, sizeof(data) - 1);
                data[sizeof(data) - 1] = '\0';
            }
        } else {
            /* 传统格式: IP DOMAIN（A 记录）或 0.0.0.0 DOMAIN（拦截） */
            strcpy(domain, token2);
            strcpy(data, token1);
        }

        if (domain[0] == '\0') continue;

        /* 对于 A 记录，把 IP 转成二进制 */
        if (entry_type == 1) {
            struct in_addr addr;
            if (inet_pton(AF_INET, data, &addr) == 1) {
                ip = addr.s_addr;
            } else {
                DEBUG(2, "跳过无效IP: %s (域名: %s)", data, domain);
                continue;
            }
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
        entry->type = entry_type;
        entry->ip = ip;
        strncpy(entry->data, data, sizeof(entry->data) - 1);
        entry->data[sizeof(entry->data) - 1] = '\0';
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
            if (e->type == 1) {
                if (e->ip == 0) return -1;  /* 拦截 */
                if (count < max_ips) ips[count++] = e->ip;
            }
        }
    }
    return count;
}

int dns_table_lookup_type(DNSTable *t, const char *domain,
                          int *type, uint32_t *ip,
                          char *data, int data_len) {
    if (!t || !domain || !type) return 0;
    unsigned long idx = hash_string(domain) % (unsigned long)t->size;

    for (TableEntry *e = t->buckets[idx]; e; e = e->next) {
#ifdef PLATFORM_WIN
        if (_stricmp(e->domain, domain) == 0) {
#else
        if (strcasecmp(e->domain, domain) == 0) {
#endif
            *type = e->type;
            if (ip) *ip = e->ip;
            if (data && data_len > 0) {
                strncpy(data, e->data, (size_t)data_len - 1);
                data[data_len - 1] = '\0';
            }
            return 1;
        }
    }
    return 0;
}

int dns_table_lookup(DNSTable *t, const char *domain, uint32_t *ip) {
    int type;
    return dns_table_lookup_type(t, domain, &type, ip, NULL, 0);
}

int dns_table_add(DNSTable *t, const char *domain, uint32_t ip, int ttl) {
    if (!t || !domain) return -1;
    (void)ttl;
    unsigned long idx = hash_string(domain) % (unsigned long)t->size;

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

    TableEntry *entry = (TableEntry *)malloc(sizeof(TableEntry));
    if (!entry) return -1;
    strncpy(entry->domain, domain, sizeof(entry->domain) - 1);
    entry->domain[sizeof(entry->domain) - 1] = '\0';
    entry->type = 1;
    entry->ip = ip;
    entry->data[0] = '\0';
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

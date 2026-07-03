#include "dns_cache.h"
#include "debug.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/*
 * dns_cache.c — DNS 缓存实现
 *
 * 缓存完整的 DNS 响应报文，支持 TTL 过期自动清理
 */

/* DJB2 哈希算法（不区分大小写） */
static unsigned long cache_hash(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + tolower(c);
    return hash;
}

int dns_cache_init(DNSCache *c, int size) {
    if (!c || size <= 0) return -1;

    c->buckets = (CacheEntry **)calloc((size_t)size, sizeof(CacheEntry *));
    if (!c->buckets) return -1;

    c->size = size;
    c->count = 0;
    return 0;
}

int dns_cache_put(DNSCache *c, const char *domain,
                  const uint8_t *response, int len, int ttl) {
    if (!c || !domain || !response || len <= 0) return -1;

    /* 允许 TTL 为 0（不缓存），否则按用户设置 */
    if (ttl < 0) ttl = 0;

    time_t expire = time(NULL) + ttl;
    unsigned long idx = cache_hash(domain) % (unsigned long)c->size;

    /* 检查是否已存在（更新） */
    for (CacheEntry *e = c->buckets[idx]; e; e = e->next) {
#ifdef PLATFORM_WIN
        if (_stricmp(e->domain, domain) == 0) {
#else
        if (strcasecmp(e->domain, domain) == 0) {
#endif
            /* 更新已有条目 */
            free(e->response);
            e->response = (uint8_t *)malloc((size_t)len);
            if (!e->response) return -1;
            memcpy(e->response, response, (size_t)len);
            e->response_len = len;
            e->expiry_time = expire;
            return 0;
        }
    }

    /* 创建新条目 */
    CacheEntry *entry = (CacheEntry *)malloc(sizeof(CacheEntry));
    if (!entry) return -1;

    strncpy(entry->domain, domain, sizeof(entry->domain) - 1);
    entry->domain[sizeof(entry->domain) - 1] = '\0';

    entry->response = (uint8_t *)malloc((size_t)len);
    if (!entry->response) {
        free(entry);
        return -1;
    }
    memcpy(entry->response, response, (size_t)len);
    entry->response_len = len;
    entry->expiry_time = expire;

    /* 头插法 */
    entry->next = c->buckets[idx];
    c->buckets[idx] = entry;
    c->count++;

    DEBUG(2, "缓存: %s (%d 字节, TTL=%ds)", domain, len, ttl);
    return 0;
}

CacheEntry *dns_cache_get(DNSCache *c, const char *domain) {
    if (!c || !domain) return NULL;

    unsigned long idx = cache_hash(domain) % (unsigned long)c->size;
    time_t now = time(NULL);

    for (CacheEntry *e = c->buckets[idx]; e; e = e->next) {
#ifdef PLATFORM_WIN
        if (_stricmp(e->domain, domain) == 0) {
#else
        if (strcasecmp(e->domain, domain) == 0) {
#endif
            if (now >= e->expiry_time) {
                /* 已过期，根据策略可以惰性删除，这里返回 NULL */
                return NULL;
            }
            return e;  /* 命中，返回完整缓存条目 */
        }
    }

    return NULL;  /* 未命中 */
}

void dns_cache_evict_expired(DNSCache *c) {
    if (!c || !c->buckets) return;

    time_t now = time(NULL);
    int cleaned = 0;

    for (int i = 0; i < c->size; i++) {
        CacheEntry **pp = &c->buckets[i];

        while (*pp) {
            CacheEntry *e = *pp;

            if (now >= e->expiry_time) {
                /* 从链表中移除 */
                *pp = e->next;
                free(e->response);
                free(e);
                cleaned++;
                c->count--;
            } else {
                pp = &e->next;
            }
        }
    }

    if (cleaned > 0) {
        DEBUG(2, "缓存清理: 移除了 %d 个过期条目", cleaned);
    }
}

void dns_cache_destroy(DNSCache *c) {
    if (!c || !c->buckets) return;

    for (int i = 0; i < c->size; i++) {
        CacheEntry *e = c->buckets[i];
        while (e) {
            CacheEntry *next = e->next;
            free(e->response);
            free(e);
            e = next;
        }
        c->buckets[i] = NULL;
    }

    free(c->buckets);
    c->buckets = NULL;
    c->count = 0;
    c->size = 0;
}

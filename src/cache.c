#include "cache.h"
#include "debug.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

/*
 * cache.c — 动态缓存实现
 *
 * 使用哈希表 (djb2) + 链表解决碰撞
 * 支持 TTL 过期和 LRU 淘汰 (超出 max_entries 时)
 */

/* djb2 哈希 (与 table.c 保持一致) */
static unsigned long cache_hash(const char *str) {
    unsigned long hash = 5381;
    int c;

    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + tolower(c);
    }

    return hash % CACHE_HASH_SIZE;
}

void cache_init(dns_cache_t *cache, size_t max_entries) {
    if (!cache) return;
    memset(cache, 0, sizeof(dns_cache_t));
    cache->max_entries = max_entries > 0 ? max_entries : 10000;
}

void cache_put(dns_cache_t *cache, const char *domain,
               uint32_t ip_addr, uint32_t ttl) {
    if (!cache || !domain)
        return;

    /* TTL 最小为 60 秒，避免频繁查询 */
    if (ttl < 60)
        ttl = 60;

    time_t expire = time(NULL) + ttl;
    unsigned long idx = cache_hash(domain);

    /* 检查是否已存在 (更新) */
    for (cache_entry_t *e = cache->buckets[idx]; e; e = e->next) {
#ifdef PLATFORM_WIN
        if (_stricmp(e->domain, domain) == 0) {
#else
        if (strcasecmp(e->domain, domain) == 0) {
#endif
            e->ip_addr = ip_addr;
            e->expire_time = expire;
            e->status = (ip_addr == 0) ? CACHE_NEGATIVE : CACHE_VALID;
            return;  /* 更新成功 */
        }
    }

    /* 淘汰检查: 如果缓存满了，清理过期条目 */
    if (cache->max_entries > 0 && cache->count >= cache->max_entries) {
        cache_cleanup(cache);
        /* 如果还是满了，先不缓存 */
        if (cache->count >= cache->max_entries)
            return;
    }

    /* 创建新条目 */
    cache_entry_t *entry = (cache_entry_t *)malloc(sizeof(cache_entry_t));
    if (!entry)
        return;

    strncpy(entry->domain, domain, sizeof(entry->domain) - 1);
    entry->domain[sizeof(entry->domain) - 1] = '\0';
    entry->ip_addr = ip_addr;
    entry->expire_time = expire;
    entry->status = (ip_addr == 0) ? CACHE_NEGATIVE : CACHE_VALID;
    entry->next = cache->buckets[idx];
    cache->buckets[idx] = entry;
    cache->count++;

    DEBUG_VERBOSE("缓存: %s -> %s (TTL=%us)",
                  domain,
                  ip_addr == 0 ? "NXDOMAIN" : "IP",
                  ttl);
}

int cache_get(dns_cache_t *cache, const char *domain, uint32_t *ip_addr) {
    if (!cache || !domain || !ip_addr)
        return 0;

    unsigned long idx = cache_hash(domain);
    time_t now = time(NULL);

    for (cache_entry_t *e = cache->buckets[idx]; e; e = e->next) {
#ifdef PLATFORM_WIN
        if (_stricmp(e->domain, domain) == 0) {
#else
        if (strcasecmp(e->domain, domain) == 0) {
#endif
            if (now >= e->expire_time) {
                e->status = CACHE_EXPIRED;
                return 0;  /* 已过期 */
            }

            *ip_addr = e->ip_addr;
            return 1;  /* 命中 */
        }
    }

    return 0;  /* 未命中 */
}

size_t cache_cleanup(dns_cache_t *cache) {
    if (!cache) return 0;

    time_t now = time(NULL);
    size_t cleaned = 0;

    for (size_t i = 0; i < CACHE_HASH_SIZE; i++) {
        cache_entry_t **pp = &cache->buckets[i];

        while (*pp) {
            cache_entry_t *e = *pp;

            if (now >= e->expire_time) {
                /* 从链表中移除 */
                *pp = e->next;
                free(e);
                cleaned++;
                cache->count--;
            } else {
                pp = &e->next;
            }
        }
    }

    if (cleaned > 0) {
        DEBUG_VERBOSE("缓存清理: 移除了 %zu 个过期条目", cleaned);
    }

    return cleaned;
}

void cache_destroy(dns_cache_t *cache) {
    if (!cache) return;

    for (size_t i = 0; i < CACHE_HASH_SIZE; i++) {
        cache_entry_t *e = cache->buckets[i];
        while (e) {
            cache_entry_t *next = e->next;
            free(e);
            e = next;
        }
        cache->buckets[i] = NULL;
    }

    cache->count = 0;
}

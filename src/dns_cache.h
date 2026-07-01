#ifndef DNS_CACHE_H
#define DNS_CACHE_H

/*
 * dns_cache.h — DNS 缓存管理接口
 *
 * 缓存从外部 DNS 服务器查询到的结果（完整响应报文）
 * 支持 TTL 过期（参照 DNS 响应中的 TTL 字段）
 */

#include "platform.h"

/* 一条缓存记录 */
typedef struct CacheEntry {
    char   domain[256];          /* 域名 */
    uint8_t *response;           /* 缓存的完整响应报文 */
    int     response_len;        /* 响应长度 */
    time_t  expiry_time;         /* 过期时间（绝对时间） */
    struct CacheEntry *next;     /* 哈希链 */
} CacheEntry;

/* 缓存结构 */
typedef struct {
    CacheEntry **buckets;        /* 哈希桶数组 */
    int         size;            /* 桶数量 */
    int         count;           /* 条目总数 */
} DNSCache;

/**
 * dns_cache_init - 初始化缓存
 * @c: 缓存指针
 * @size: 哈希桶数量
 * @return: 成功返回 0
 */
int dns_cache_init(DNSCache *c, int size);

/**
 * dns_cache_put - 存入一条缓存记录
 * @c: 缓存指针
 * @domain: 域名
 * @response: 完整的 DNS 响应报文
 * @len: 响应报文长度
 * @ttl: 生存时间（秒）
 * @return: 成功返回 0
 */
int dns_cache_put(DNSCache *c, const char *domain,
                  const uint8_t *response, int len, int ttl);

/**
 * dns_cache_get - 查询缓存
 * @c: 缓存指针
 * @domain: 域名
 * @return: 找到返回 CacheEntry 指针（自动检查过期），未找到返回 NULL
 */
CacheEntry *dns_cache_get(DNSCache *c, const char *domain);

/**
 * dns_cache_evict_expired - 清理所有过期条目
 * @c: 缓存指针
 */
void dns_cache_evict_expired(DNSCache *c);

/**
 * dns_cache_destroy - 释放缓存
 * @c: 缓存指针
 */
void dns_cache_destroy(DNSCache *c);

#endif /* DNS_CACHE_H */

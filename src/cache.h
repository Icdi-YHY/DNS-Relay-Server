#ifndef CACHE_H
#define CACHE_H

/*
 * cache.h — DNS 动态缓存模块
 * 缓存从中继响应中获取的 A 记录，减少对上游 DNS 的请求
 * 支持 TTL 过期自动清理
 */

#include "platform.h"

/* 缓存哈希表大小 */
#define CACHE_HASH_SIZE 1021

/* 缓存条目状态 */
typedef enum {
    CACHE_VALID,       /* 有效 */
    CACHE_EXPIRED,     /* 已过期 */
    CACHE_NEGATIVE     /* 否定缓存 (NXDOMAIN)，短时间有效 */
} cache_status_t;

/* 一条缓存记录 */
typedef struct cache_entry {
    char    domain[256];           /* 域名 */
    uint32_t ip_addr;              /* IP 地址 (网络字节序)，0 表示 NXDOMAIN */
    time_t  expire_time;           /* 过期绝对时间 */
    cache_status_t status;         /* 状态 */
    struct cache_entry *next;      /* 哈希碰撞链表 */
} cache_entry_t;

/* 缓存上下文 */
typedef struct {
    cache_entry_t *buckets[CACHE_HASH_SIZE];
    size_t count;                  /* 当前有效缓存条目数 */
    size_t max_entries;            /* 最大条目数 (超出后淘汰) */
} dns_cache_t;

/**
 * cache_init - 初始化缓存
 * @cache: 缓存指针
 * @max_entries: 最大条目数 (0 表示无限制)
 */
void cache_init(dns_cache_t *cache, size_t max_entries);

/**
 * cache_put - 向缓存中存入一条记录
 * @cache: 缓存指针
 * @domain: 域名
 * @ip_addr: IP 地址 (网络字节序)，0 表示 NXDOMAIN
 * @ttl: 生存时间 (秒)
 */
void cache_put(dns_cache_t *cache, const char *domain,
               uint32_t ip_addr, uint32_t ttl);

/**
 * cache_get - 从缓存中查找域名
 * @cache: 缓存指针
 * @domain: 域名
 * @ip_addr: 输出，IP 地址 (网络字节序)
 * @return: 找到返回 1，未找到或已过期返回 0
 */
int cache_get(dns_cache_t *cache, const char *domain, uint32_t *ip_addr);

/**
 * cache_cleanup - 清理所有过期条目
 * @cache: 缓存指针
 * @return: 清理的条目数
 */
size_t cache_cleanup(dns_cache_t *cache);

/**
 * cache_destroy - 销毁缓存，释放所有内存
 * @cache: 缓存指针
 */
void cache_destroy(dns_cache_t *cache);

#endif /* CACHE_H */

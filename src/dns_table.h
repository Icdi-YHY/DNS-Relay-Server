#ifndef DNS_TABLE_H
#define DNS_TABLE_H

/*
 * dns_table.h — 域名对照表管理接口
 *
 * 读取 "域名-IP 地址" 对照表文件，构建内存哈希表（链地址法）
 * 提供高效的域名查询接口
 * 判断查询结果是 0.0.0.0（拦截）还是有效 IP
 */

#include "platform.h"

/* 一条对照表记录 */
typedef struct TableEntry {
    char   domain[256];       /* 域名 */
    int    type;              /* DNS 记录类型 (A=1, AAAA=28, CNAME=5, MX=15, NS=2, PTR=12) */
    uint32_t ip;              /* A 记录的 IP 地址（网络字节序），0.0.0.0 表示拦截 */
    char   data[256];         /* CNAME/MX/NS/PTR 的目标值 */
    struct TableEntry *next;  /* 链表指针（链地址法解决哈希冲突） */
} TableEntry;

/* 对照表结构 */
typedef struct {
    TableEntry **buckets;     /* 哈希桶数组 */
    int         size;         /* 桶数量 */
    int         count;        /* 条目总数 */
} DNSTable;

/**
 * dns_table_init - 初始化哈希表
 * @t: 对照表指针
 * @size: 哈希桶数量
 * @return: 成功返回 0
 */
int dns_table_init(DNSTable *t, int size);

/**
 * dns_table_load - 从文件加载对照表
 * @t: 对照表指针
 * @filename: 文件名
 * @return: 成功返回加载的记录数，失败返回 -1
 *
 * 文件格式:
 *   # 注释行（可选）
 *   0.0.0.0 ad1.sina.com.cn    ← 不良网站拦截
 *   123.127.134.10 www.bupt.cn  ← 直接返回 IP
 *
 * 每行格式: <IP 地址> <域名>
 */
int dns_table_load(DNSTable *t, const char *filename);

/**
 * dns_table_lookup - 查询域名对应的 IP 地址
 * @t: 对照表指针
 * @domain: 域名
 * @ip: 输出参数，IP 地址（网络字节序）
 * @return: 0=未命中, 1=命中
 *
 * 命中时，若 *ip == 0 表示该域名被拦截（0.0.0.0）
 * 未命中时需要中继到外部 DNS
 */
int dns_table_lookup(DNSTable *t, const char *domain, uint32_t *ip);

/**
 * dns_table_lookup_all - 查询域名对应的所有 IP 地址
 * @t: 对照表指针
 * @domain: 域名
 * @ips: 输出数组，存放所有 IP 地址（网络字节序）
 * @max_ips: ips 数组容量
 * @return: 找到的 IP 数量
 *
 * 返回 0 表示未命中；返回 -1 表示命中但含 0.0.0.0（拦截）
 */
int dns_table_lookup_all(DNSTable *t, const char *domain, uint32_t *ips, int max_ips);

/**
 * dns_table_lookup_type - 查询域名的记录类型和目标值
 * @t: 对照表指针
 * @domain: 域名
 * @type: 输出参数，记录类型
 * @ip: 输出参数，A 记录的 IP（网络字节序）
 * @data: 输出参数，CNAME/MX/NS/PTR 的目标值
 * @data_len: data 缓冲区大小
 * @return: 0=未命中, 1=命中
 */
int dns_table_lookup_type(DNSTable *t, const char *domain,
                          int *type, uint32_t *ip,
                          char *data, int data_len);

/**
 * dns_table_add - 添加条目（用于缓存更新）
 * @t: 对照表指针
 * @domain: 域名
 * @ip: IP 地址（网络字节序）
 * @ttl: TTL（实现中可忽略，统一管理过期）
 * @return: 成功返回 0
 */
int dns_table_add(DNSTable *t, const char *domain, uint32_t ip, int ttl);

/**
 * dns_table_destroy - 释放哈希表
 * @t: 对照表指针
 */
void dns_table_destroy(DNSTable *t);

#endif /* DNS_TABLE_H */

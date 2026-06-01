#ifndef TABLE_H
#define TABLE_H

/*
 * table.h — 域名-IP 对照表模块
 * 从 dnsrelay.txt 文件中加载，提供快速域名查找
 * 使用哈希表实现，期望 O(1) 查找
 */

#include "platform.h"

/* 哈希表大小 (质数，减少碰撞) */
#define TABLE_HASH_SIZE 8191

/* 一条对照表记录 */
typedef struct table_entry {
    char *domain;                 /* 域名 (如 "www.bupt.edu.cn") */
    uint32_t ip_addr;             /* IP 地址 (网络字节序) */
    struct table_entry *next;     /* 链表指针 (处理哈希碰撞) */
} table_entry_t;

/* 对照表结构 */
typedef struct {
    table_entry_t *buckets[TABLE_HASH_SIZE];  /* 哈希桶 */
    size_t count;                             /* 记录总数 */
    char *filename;                           /* 加载的文件名 */
} table_t;

/**
 * table_init - 初始化对照表
 * @tbl: 对照表指针
 */
void table_init(table_t *tbl);

/**
 * table_load_file - 从文件加载对照表
 * @tbl: 对照表指针
 * @filename: 文件名
 * @return: 成功返回加载的记录数，失败返回 -1
 *
 * 文件格式: 每行为 "IP_ADDRESS DOMAIN_NAME"
 *   - 0.0.0.0 example.com   → 拦截
 *   - 1.2.3.4 example.com   → 正常解析
 *   - # 开头的行为注释
 *   - 空行跳过
 */
int table_load_file(table_t *tbl, const char *filename);

/**
 * table_lookup - 查找域名对应的 IP 地址
 * @tbl: 对照表指针
 * @domain: 域名 (点分格式)
 * @ip_addr: 输出参数，IP 地址 (网络字节序)
 * @return: 找到返回 1，未找到返回 0
 *
 * 注意: 返回 1 时，若 ip_addr == 0 表示拦截 (0.0.0.0)
 *       返回 0 时，ip_addr 值无效 (需要中继)
 */
int table_lookup(const table_t *tbl, const char *domain, uint32_t *ip_addr);

/**
 * table_destroy - 销毁对照表，释放所有内存
 * @tbl: 对照表指针
 */
void table_destroy(table_t *tbl);

#endif /* TABLE_H */

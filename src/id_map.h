#ifndef ID_MAP_H
#define ID_MAP_H

/*
 * id_map.h — ID 转换表接口
 *
 * 管理客户端原始 Transaction ID 与转发 ID 的映射关系
 * 支持多客户端并发查询
 * 收到外部 DNS 响应时，通过转发 ID 查到原始客户端和原始 ID
 */

#include "platform.h"

/* ID 映射条目 */
typedef struct {
    uint16_t    orig_id;          /* 客户端的原始 ID */
    uint16_t    relay_id;         /* 中继转发用的 ID */
    struct sockaddr_in client_addr; /* 客户端地址（区分不同客户端） */
    time_t      send_time;        /* 发送时间（用于超时判断） */
    int         in_use;           /* 是否正在使用 */
} IDMapEntry;

/* ID 映射表 */
typedef struct {
    IDMapEntry *entries;          /* 动态数组 */
    int         capacity;         /* 容量 */
    int         count;            /* 当前使用数 */
    uint16_t    next_relay_id;    /* 下一个可用转发 ID */
} IDMap;

/**
 * id_map_init - 初始化 ID 表
 * @m: ID 映射表指针
 * @capacity: 最大并发查询数
 * @return: 成功返回 0
 */
int id_map_init(IDMap *m, int capacity);

/**
 * id_map_alloc - 分配转发 ID，记录映射
 * @m: ID 映射表指针
 * @orig_id: 客户端的原始 ID
 * @client: 客户端地址
 * @relay_id: 输出，分配的转发 ID
 * @return: 成功返回 0，表满返回 -1
 */
int id_map_alloc(IDMap *m, uint16_t orig_id,
                 struct sockaddr_in *client, uint16_t *relay_id);

/**
 * id_map_lookup - 根据转发 ID 查找原始信息
 * @m: ID 映射表指针
 * @relay_id: 转发 ID
 * @orig_id: 输出，原始客户端 ID
 * @client: 输出，客户端地址
 * @return: 成功返回 0，未找到返回 -1
 */
int id_map_lookup(IDMap *m, uint16_t relay_id,
                  uint16_t *orig_id, struct sockaddr_in *client);

/**
 * id_map_free - 释放 ID 映射项
 * @m: ID 映射表指针
 * @relay_id: 要释放的转发 ID
 */
void id_map_free(IDMap *m, uint16_t relay_id);

/**
 * id_map_cleanup - 清理超时的映射项
 * @m: ID 映射表指针
 * @timeout: 超时秒数
 */
void id_map_cleanup(IDMap *m, time_t timeout);

/**
 * id_map_destroy - 释放 ID 映射表
 * @m: ID 映射表指针
 */
void id_map_destroy(IDMap *m);

#endif /* ID_MAP_H */

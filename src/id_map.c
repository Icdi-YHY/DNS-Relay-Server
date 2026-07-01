#include "id_map.h"
#include "debug.h"
#include <string.h>
#include <stdlib.h>

/*
 * id_map.c — ID 转换表实现
 *
 * 每个并发查询分配一个唯一的 relay_id，记录 orig_id → relay_id 映射
 * 收到上游响应时，用 relay_id 查找对应的客户端和原始 ID
 */

int id_map_init(IDMap *m, int capacity) {
    if (!m || capacity <= 0) return -1;

    m->entries = (IDMapEntry *)calloc((size_t)capacity, sizeof(IDMapEntry));
    if (!m->entries) return -1;

    m->capacity = capacity;
    m->count = 0;
    m->next_relay_id = 1;
    return 0;
}

int id_map_alloc(IDMap *m, uint16_t orig_id,
                 struct sockaddr_in *client, uint16_t *relay_id) {
    if (!m || !client || !relay_id) return -1;

    /* 找空闲槽位 */
    int slot = -1;
    for (int i = 0; i < m->capacity; i++) {
        if (!m->entries[i].in_use) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        DEBUG(2, "ID 映射表已满，丢弃查询 (ID=%u)", orig_id);
        return -1;
    }

    /* 分配 relay_id（避免 0，0 表示无效） */
    uint16_t new_id;
    int conflict;
    do {
        conflict = 0;
        new_id = m->next_relay_id++;
        if (m->next_relay_id == 0) m->next_relay_id = 1;

        /* 检查是否与现有条目冲突 */
        for (int i = 0; i < m->capacity; i++) {
            if (m->entries[i].in_use && m->entries[i].relay_id == new_id) {
                conflict = 1;
                break;
            }
        }
    } while (conflict);

    /* 记录映射 */
    m->entries[slot].orig_id = orig_id;
    m->entries[slot].relay_id = new_id;
    memcpy(&m->entries[slot].client_addr, client, sizeof(*client));
    m->entries[slot].send_time = time(NULL);
    m->entries[slot].in_use = 1;
    m->count++;

    *relay_id = new_id;
    return 0;
}

int id_map_lookup(IDMap *m, uint16_t relay_id,
                  uint16_t *orig_id, struct sockaddr_in *client) {
    if (!m) return -1;

    for (int i = 0; i < m->capacity; i++) {
        if (m->entries[i].in_use && m->entries[i].relay_id == relay_id) {
            if (orig_id) *orig_id = m->entries[i].orig_id;
            if (client)  memcpy(client, &m->entries[i].client_addr,
                                sizeof(m->entries[i].client_addr));
            return 0;
        }
    }

    return -1;  /* 未找到 */
}

void id_map_free(IDMap *m, uint16_t relay_id) {
    if (!m) return;

    for (int i = 0; i < m->capacity; i++) {
        if (m->entries[i].in_use && m->entries[i].relay_id == relay_id) {
            m->entries[i].in_use = 0;
            m->count--;
            return;
        }
    }
}

void id_map_cleanup(IDMap *m, time_t timeout) {
    if (!m) return;

    time_t now = time(NULL);
    int cleaned = 0;

    for (int i = 0; i < m->capacity; i++) {
        if (m->entries[i].in_use) {
            if (difftime(now, m->entries[i].send_time) >= (double)timeout) {
                DEBUG(2, "ID 映射超时: orig_id=%u, relay_id=%u",
                      m->entries[i].orig_id, m->entries[i].relay_id);
                m->entries[i].in_use = 0;
                m->count--;
                cleaned++;
            }
        }
    }

    if (cleaned > 0) {
        DEBUG(2, "ID 映射清理: 移除了 %d 个超时条目", cleaned);
    }
}

void id_map_destroy(IDMap *m) {
    if (!m) return;
    free(m->entries);
    m->entries = NULL;
    m->capacity = 0;
    m->count = 0;
}

#ifndef DNS_RELAY_H
#define DNS_RELAY_H

/*
 * dns_relay.h — DNS 中继转发接口
 *
 * 当本地对照表未命中时，将查询转发给外部 DNS 服务器
 * 接收外部 DNS 的响应，还原 ID 后转给客户端
 * 将成功查询结果写入缓存（由主流程完成）
 */

#include "platform.h"
#include "id_map.h"

/**
 * relay_forward - 修改 ID 后转发查询给外部 DNS
 * @sock: UDP socket（用于发送）
 * @dns_server: 外部 DNS 服务器地址
 * @query: 客户端原始查询报文
 * @qlen: 查询报文长度
 * @client_addr: 客户端地址（用于 ID 映射记录）
 * @map: ID 映射表
 * @return: 成功返回分配的 relay_id，失败返回 -1
 *
 * 流程:
 * 1. 从查询中提取原始 ID
 * 2. 调用 id_map_alloc 分配 relay_id（记录客户端映射）
 * 3. 构造转发报文（替换 ID 为 relay_id）
 * 4. 通过 sock 发送给外部 DNS
 */
int relay_forward(socket_t sock, struct sockaddr_in *dns_server,
                  const uint8_t *query, int qlen,
                  struct sockaddr_in *client_addr, IDMap *map);

#endif /* DNS_RELAY_H */

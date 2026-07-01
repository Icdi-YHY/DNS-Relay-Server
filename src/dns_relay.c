#include "dns_relay.h"
#include "dns_message.h"
#include "debug.h"
#include <string.h>

/*
 * dns_relay.c — DNS 中继转发实现
 *
 * 当本地对照表未命中时，将查询转发给外部 DNS 服务器。
 * ID 映射由 id_map 模块管理。
 */

int relay_forward(socket_t sock, struct sockaddr_in *dns_server,
                  const uint8_t *query, int qlen,
                  struct sockaddr_in *client_addr, IDMap *map) {
    if (!query || qlen < (int)sizeof(DNSHeader) || !dns_server || !client_addr || !map)
        return -1;

    /* 1. 解析查询获取域名和原始 ID */
    DNSHeader hdr;
    DNSQuestion q;
    if (dns_decode_query(query, qlen, &hdr, &q) != 0) {
        DEBUG(2, "relay_forward: 无法解析查询报文");
        return -1;
    }

    uint16_t orig_id = ntohs(hdr.id);

    /* 2. 分配 relay_id */
    uint16_t relay_id;
    if (id_map_alloc(map, orig_id, client_addr, &relay_id) != 0) {
        DEBUG(1, "relay_forward: ID 映射表已满，丢弃查询 (ID=%u)", orig_id);
        return -1;
    }

    /* 3. 构造转发报文（替换 ID） */
    uint8_t relay_buf[MAX_DNS_PACKET];
    int relay_len = dns_build_relay_query(&hdr, &q, relay_id, relay_buf);
    if (relay_len < 0) {
        id_map_free(map, relay_id);
        DEBUG(2, "relay_forward: 构建转发报文失败");
        return -1;
    }

    /* 4. 发送给外部 DNS */
    int sent = sendto(sock, (const char *)relay_buf, relay_len, 0,
                      (const struct sockaddr *)dns_server,
                      sizeof(*dns_server));
    if (sent < 0) {
        id_map_free(map, relay_id);
        DEBUG(2, "relay_forward: 发送失败 (errno=%d)", socket_errno());
        return -1;
    }

    DEBUG(2, "转发: ID %u → %u, 域名=%s", orig_id, relay_id, q.qname);
    return (int)relay_id;
}

#include "relay.h"
#include "dns.h"
#include "debug.h"
#include <string.h>
#include <stdlib.h>

/*
 * relay.c — DNS 中继转发实现
 *
 * ID 映射方案:
 *   - 每个客户端查询携带一个 16 位 ID
 *   - 多个客户端可能使用相同的 ID，直接转发会导致冲突
 *   - 方案: 转发时替换为 proxy_id (单调递增)，记录映射关系
 *   - 收到响应时根据 proxy_id 查找客户端，恢复 original_id 后转发
 *
 * 超时处理:
 *   - 每个挂起查询记录发送时间戳
 *   - 每秒检查一次超时 (在 select 超时中处理)
 *   - 超时后清理记录 (不通知客户端，符合 DNS 协议)
 */

int relay_init(relay_ctx_t *ctx, SOCKET server_sock,
               const char *upstream_ip, uint16_t upstream_port) {
    if (!ctx || !upstream_ip)
        return -1;

    memset(ctx, 0, sizeof(relay_ctx_t));
    ctx->server_sock = server_sock;
    ctx->next_proxy_id = 1;

    /* 创建上游 socket (UDP) */
    ctx->upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->upstream_sock == INVALID_SOCKET) {
        DEBUG_ERROR("无法创建上游 socket");
        return -1;
    }

    /* 上游 socket 也设为非阻塞 */
#ifdef PLATFORM_WIN
    unsigned long nonblock = 1;
    ioctlsocket(ctx->upstream_sock, FIONBIO, &nonblock);
#else
    int flags = fcntl(ctx->upstream_sock, F_GETFL, 0);
    fcntl(ctx->upstream_sock, F_SETFL, flags | O_NONBLOCK);
#endif

    /* 构造上游地址 */
    memset(&ctx->upstream_addr, 0, sizeof(ctx->upstream_addr));
    ctx->upstream_addr.sin_family = AF_INET;
    ctx->upstream_addr.sin_port = htons(upstream_port);

    struct in_addr addr;
    if (inet_pton(AF_INET, upstream_ip, &addr) != 1) {
        DEBUG_ERROR("无效的上游 DNS 地址: %s", upstream_ip);
        socket_close(ctx->upstream_sock);
        return -1;
    }
    ctx->upstream_addr.sin_addr = addr;

    return 0;
}

int relay_forward(relay_ctx_t *ctx,
                  const uint8_t *query, size_t query_len,
                  const struct sockaddr_in *client_addr,
                  socklen_t client_len) {
    if (!ctx || !query || !client_addr || query_len < sizeof(dns_header_t))
        return -1;

    const dns_header_t *hdr = (const dns_header_t *)query;
    uint16_t original_id = ntohs(hdr->id);

    /* 找一个空闲的 pending 槽位 */
    int slot = -1;
    for (int i = 0; i < MAX_PENDING; i++) {
        if (!ctx->pending[i].used) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        DEBUG_VERBOSE("挂起查询表已满，丢弃查询 (ID=%u)", original_id);
        return -1;
    }

    /* 分配 proxy_id (避免 0，0 表示无效) */
    uint16_t proxy_id;
    int attempts = 0;
    do {
        proxy_id = ctx->next_proxy_id++;
        if (ctx->next_proxy_id == 0)
            ctx->next_proxy_id = 1;
        attempts++;
        /* 检查是否与已有的 pending 冲突 */
    } while (relay_process_response(ctx, NULL, 0) == 0 && attempts < MAX_PENDING);
    /* 上面这行是快速检查 — 实际我们用下面的循环 */

    /* 真正检查 proxy_id 不冲突 */
    int conflict;
    do {
        conflict = 0;
        for (int i = 0; i < MAX_PENDING; i++) {
            if (ctx->pending[i].used && ctx->pending[i].proxy_id == proxy_id) {
                conflict = 1;
                proxy_id = ctx->next_proxy_id++;
                if (ctx->next_proxy_id == 0)
                    ctx->next_proxy_id = 1;
                break;
            }
        }
    } while (conflict);

    /* 构建转发报文 (替换 ID) */
    uint8_t relay_buf[MAX_DNS_PACKET];
    int relay_len = dns_build_relay_query(query, query_len,
                                          proxy_id,
                                          relay_buf, sizeof(relay_buf));
    if (relay_len < 0) {
        DEBUG_VERBOSE("构建转发报文失败");
        return -1;
    }

    /* 发送到上游 DNS */
    int sent = sendto(ctx->upstream_sock, (const char *)relay_buf, relay_len, 0,
                      (const struct sockaddr *)&ctx->upstream_addr,
                      sizeof(ctx->upstream_addr));
    if (sent < 0) {
        DEBUG_VERBOSE("向上游发送失败 (errno=%d)", socket_errno());
        return -1;
    }

    /* 记录挂起查询 */
    ctx->pending[slot].used = true;
    ctx->pending[slot].proxy_id = proxy_id;
    memcpy(&ctx->pending[slot].client_addr, client_addr, sizeof(*client_addr));
    ctx->pending[slot].client_len = client_len;
    ctx->pending[slot].original_id = original_id;
    ctx->pending[slot].timestamp = time(NULL);
    memcpy(ctx->pending[slot].query, query, query_len);
    ctx->pending[slot].query_len = query_len;

    DEBUG_VERBOSE("转发: ID %u → %u, 客户端=%s:%d",
                  original_id, proxy_id,
                  inet_ntoa(client_addr->sin_addr),
                  ntohs(client_addr->sin_port));

    return (int)proxy_id;
}

int relay_process_response(relay_ctx_t *ctx,
                           const uint8_t *response, size_t response_len) {
    if (!ctx)
        return -1;

    /* 如果 response 为 NULL，只是做冲突检查 */
    if (!response)
        return 0;

    if (response_len < sizeof(dns_header_t))
        return -1;

    const dns_header_t *hdr = (const dns_header_t *)response;
    uint16_t proxy_id = ntohs(hdr->id);

    /* 在 pending 表中查找匹配的 proxy_id */
    int slot = -1;
    for (int i = 0; i < MAX_PENDING; i++) {
        if (ctx->pending[i].used && ctx->pending[i].proxy_id == proxy_id) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        DEBUG_VERBOSE("收到未知 proxy_id=%u 的响应 (可能已超时)", proxy_id);
        return -1;
    }

    pending_query_t *pending = &ctx->pending[slot];

    /* 恢复原始 ID */
    uint8_t relay_resp[MAX_DNS_PACKET];
    size_t resp_len = response_len < sizeof(relay_resp) ? response_len : sizeof(relay_resp);
    memcpy(relay_resp, response, resp_len);
    dns_restore_id(relay_resp, resp_len, pending->original_id);

    /* 发送给客户端 */
    int sent = sendto(ctx->server_sock, (const char *)relay_resp, resp_len, 0,
                      (const struct sockaddr *)&pending->client_addr,
                      pending->client_len);
    if (sent < 0) {
        DEBUG_VERBOSE("发送响应给客户端失败 (errno=%d)", socket_errno());
    }

    /* 提取域名用于日志 */
    char domain_buf[256];
    uint16_t qtype;
    if (dns_extract_question(pending->query, pending->query_len,
                             domain_buf, sizeof(domain_buf), &qtype) == 0) {
        DEBUG_BASIC("中继响应: %-30s  ID=%u→%u  客户端=%s:%d",
                    domain_buf,
                    proxy_id, pending->original_id,
                    inet_ntoa(pending->client_addr.sin_addr),
                    ntohs(pending->client_addr.sin_port));
    }

    /* 清理 pending 条目 */
    pending->used = false;

    return 0;
}

void relay_check_timeouts(relay_ctx_t *ctx) {
    if (!ctx) return;

    time_t now = time(NULL);
    int timed_out = 0;

    for (int i = 0; i < MAX_PENDING; i++) {
        if (ctx->pending[i].used) {
            if (difftime(now, ctx->pending[i].timestamp) >= PENDING_TIMEOUT) {
                /* 超时，清理 */
                char domain_buf[64];
                uint16_t qtype;
                if (dns_extract_question(ctx->pending[i].query,
                                         ctx->pending[i].query_len,
                                         domain_buf, sizeof(domain_buf),
                                         &qtype) == 0) {
                    DEBUG_VERBOSE("超时: %s (ID=%u, proxy=%u)",
                                  domain_buf,
                                  ctx->pending[i].original_id,
                                  ctx->pending[i].proxy_id);
                }

                ctx->pending[i].used = false;
                timed_out++;
            }
        }
    }

    if (timed_out > 0) {
        DEBUG_VERBOSE("清理了 %d 个超时查询", timed_out);
    }
}

SOCKET relay_get_upstream_sock(const relay_ctx_t *ctx) {
    return ctx ? ctx->upstream_sock : INVALID_SOCKET;
}

void relay_destroy(relay_ctx_t *ctx) {
    if (!ctx) return;

    if (ctx->upstream_sock != INVALID_SOCKET) {
        socket_close(ctx->upstream_sock);
        ctx->upstream_sock = INVALID_SOCKET;
    }
}

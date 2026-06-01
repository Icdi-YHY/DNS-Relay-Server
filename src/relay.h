#ifndef RELAY_H
#define RELAY_H

/*
 * relay.h — DNS 中继转发模块
 * 处理未命中本地表的 DNS 查询转发到上游服务器
 * 支持多客户端并发查询时的 ID 映射
 */

#include "platform.h"

/* 最大并发挂起查询数 */
#define MAX_PENDING 1024

/* 挂起查询超时时间 (秒) */
#define PENDING_TIMEOUT 5

/* 一条挂起的转发查询记录 */
typedef struct {
    bool    used;                        /* 条目是否被使用 */
    uint16_t proxy_id;                   /* 分配给该查询的代理 ID */
    struct sockaddr_in client_addr;      /* 客户端地址 */
    socklen_t client_len;                /* 客户端地址长度 */
    uint16_t original_id;                /* 客户端原始查询 ID */
    time_t  timestamp;                   /* 发送时间戳 (用于超时检测) */
    uint8_t query[MAX_DNS_PACKET];       /* 原始客户端查询 */
    size_t  query_len;                   /* 原始查询长度 */
} pending_query_t;

/* 中继模块上下文 */
typedef struct {
    SOCKET  server_sock;                 /* 服务器 socket (监听客户端) */
    SOCKET  upstream_sock;               /* 上游 socket (与外部 DNS 通信) */
    struct sockaddr_in upstream_addr;    /* 上游 DNS 地址 */
    pending_query_t pending[MAX_PENDING]; /* 挂起查询表 */
    uint16_t next_proxy_id;              /* 下一个可用的代理 ID */
} relay_ctx_t;

/**
 * relay_init - 初始化中继模块
 * @ctx: 中继上下文
 * @server_sock: 服务器 socket (用于发送响应给客户端)
 * @upstream_ip: 上游 DNS IP 字符串
 * @upstream_port: 上游 DNS 端口
 * @return: 成功 0，失败 -1
 */
int relay_init(relay_ctx_t *ctx, SOCKET server_sock,
               const char *upstream_ip, uint16_t upstream_port);

/**
 * relay_forward - 转发查询到上游 DNS 服务器
 * @ctx: 中继上下文
 * @query: 客户端原始查询报文
 * @query_len: 查询报文长度
 * @client_addr: 客户端地址
 * @client_len: 客户端地址长度
 * @return: 成功返回分配的 proxy_id，失败返回 -1
 *
 * 分配新 ID，记录客户端映射，向上游发送查询
 */
int relay_forward(relay_ctx_t *ctx,
                  const uint8_t *query, size_t query_len,
                  const struct sockaddr_in *client_addr,
                  socklen_t client_len);

/**
 * relay_process_response - 处理来自上游 DNS 的响应
 * @ctx: 中继上下文
 * @response: 上游返回的响应报文
 * @response_len: 响应报文长度
 * @return: 成功 0 (已转发给客户端)，无匹配 -1
 *
 * 根据 proxy_id 查找对应的客户端，恢复原始 ID 并发送响应
 */
int relay_process_response(relay_ctx_t *ctx,
                           const uint8_t *response, size_t response_len);

/**
 * relay_check_timeouts - 检查超时的挂起查询并清理
 * @ctx: 中继上下文
 *
 * 超时的查询不会给客户端发任何消息 (超时透明传递)
 */
void relay_check_timeouts(relay_ctx_t *ctx);

/**
 * relay_get_upstream_sock - 获取上游 socket 描述符
 * @ctx: 中继上下文
 * @return: 上游 socket
 */
SOCKET relay_get_upstream_sock(const relay_ctx_t *ctx);

/**
 * relay_destroy - 清理中继模块
 * @ctx: 中继上下文
 */
void relay_destroy(relay_ctx_t *ctx);

#endif /* RELAY_H */

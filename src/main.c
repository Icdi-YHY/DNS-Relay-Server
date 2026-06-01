#include "platform.h"
#include "dns.h"
#include "table.h"
#include "relay.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * main.c — DNS 中继服务器主程序
 *
 * 事件驱动模型 (select)，单线程处理所有客户端并发查询
 * 同时监听两个 socket:
 *   - server_sock: 接收客户端 DNS 查询 (端口 53)
 *   - upstream_sock: 接收上游 DNS 服务器响应
 */

/* ========== 全局变量 ========== */
debug_level_t g_debug_level = DEBUG_NONE;

/* 默认配置 */
#define DEFAULT_DNS_SERVER  "202.106.0.20"
#define DEFAULT_TABLE_FILE  "dnsrelay.txt"

/* ========== 配置 ========== */
typedef struct {
    char    upstream_ip[64];       /* 上游 DNS 服务器 IP */
    uint16_t upstream_port;        /* 上游 DNS 服务器端口 (通常 53) */
    char    table_file[256];       /* 对照表文件路径 */
    table_t table;                 /* 域名-IP 对照表 */
    relay_ctx_t relay;             /* 中继转发模块 */
    SOCKET  server_sock;           /* 监听 socket (UDP 53) */
} config_t;

/* ========== 函数声明 ========== */
static int parse_args(config_t *cfg, int argc, char *argv[]);
static int init_server(config_t *cfg);
static void handle_client_query(config_t *cfg, const uint8_t *query,
                                 size_t query_len,
                                 const struct sockaddr_in *client_addr,
                                 socklen_t client_len);
static void handle_upstream_response(config_t *cfg,
                                      const uint8_t *resp, size_t resp_len);

/* ========== 主函数 ========== */
int main(int argc, char *argv[]) {
    config_t cfg;
    int ret;

    /* 1. 初始化 socket 库 (仅 Windows 需要) */
    if (socket_init() != 0) {
        fprintf(stderr, "Socket 初始化失败\n");
        return 1;
    }

    /* 2. 解析命令行参数 */
    memset(&cfg, 0, sizeof(cfg));
    cfg.upstream_port = 53;
    if (parse_args(&cfg, argc, argv) != 0) {
        fprintf(stderr, "用法: dnsrelay [-d|-dd] [dns-server-ipaddr] [filename]\n");
        socket_cleanup();
        return 1;
    }

    /* 3. 加载对照表 */
    table_init(&cfg.table);
    if (table_load_file(&cfg.table, cfg.table_file) < 0) {
        DEBUG_ERROR("加载对照表失败: %s", cfg.table_file);
        socket_cleanup();
        return 1;
    }

    /* 4. 初始化服务器 (创建 + bind server_sock) */
    if (init_server(&cfg) != 0) {
        DEBUG_ERROR("服务器初始化失败");
        table_destroy(&cfg.table);
        socket_cleanup();
        return 1;
    }

    /* 5. 初始化中继模块 (创建 upstream_sock) */
    if (relay_init(&cfg.relay, cfg.server_sock,
                   cfg.upstream_ip, cfg.upstream_port) != 0) {
        DEBUG_ERROR("中继模块初始化失败");
        socket_close(cfg.server_sock);
        table_destroy(&cfg.table);
        socket_cleanup();
        return 1;
    }

    DEBUG_BASIC("DNS 中继服务器启动");
    DEBUG_BASIC("监听端口: %d", DNS_PORT);
    DEBUG_BASIC("上游 DNS: %s:%d", cfg.upstream_ip, cfg.upstream_port);
    DEBUG_BASIC("对照表: %s (%zu 条记录)", cfg.table_file, cfg.table.count);

    /* 6. 事件循环 (select 多路复用) */
    fd_set read_fds;
    struct timeval tv;
    uint8_t buffer[MAX_DNS_PACKET];
    struct sockaddr_in from_addr;
    socklen_t from_len;
    SOCKET upstream_sock = relay_get_upstream_sock(&cfg.relay);
    int max_fd = (int)(cfg.server_sock > upstream_sock
                       ? cfg.server_sock : upstream_sock) + 1;

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(cfg.server_sock, &read_fds);
        FD_SET(upstream_sock, &read_fds);

        /* 设置 select 超时 (1秒，用于定期检查挂起查询超时) */
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        ret = select(max_fd, &read_fds, NULL, NULL, &tv);
        if (ret < 0) {
#ifdef PLATFORM_WIN
            if (socket_errno() == WSAEINTR)
                continue;
#else
            if (errno == EINTR)
                continue;
#endif
            DEBUG_ERROR("select() 失败: errno=%d", socket_errno());
            break;
        }

        if (ret == 0) {
            /* 超时: 检查挂起查询超时 */
            relay_check_timeouts(&cfg.relay);
            continue;
        }

        /* --- 来自客户端的 DNS 查询 (端口 53) --- */
        if (FD_ISSET(cfg.server_sock, &read_fds)) {
            from_len = sizeof(from_addr);
            int n = recvfrom(cfg.server_sock, (char *)buffer, sizeof(buffer), 0,
                             (struct sockaddr *)&from_addr, &from_len);
            if (n < 0) {
                DEBUG_ERROR("recvfrom(server_sock) 失败: errno=%d", socket_errno());
                continue;
            }

            if ((size_t)n < sizeof(dns_header_t))
                continue;

            handle_client_query(&cfg, buffer, (size_t)n, &from_addr, from_len);
        }

        /* --- 来自上游 DNS 的响应 --- */
        if (FD_ISSET(upstream_sock, &read_fds)) {
            from_len = sizeof(from_addr);
            int n = recvfrom(upstream_sock, (char *)buffer, sizeof(buffer), 0,
                             (struct sockaddr *)&from_addr, &from_len);
            if (n < 0) {
                DEBUG_ERROR("recvfrom(upstream_sock) 失败: errno=%d", socket_errno());
                continue;
            }

            if ((size_t)n < sizeof(dns_header_t))
                continue;

            handle_upstream_response(&cfg, buffer, (size_t)n);
        }
    }

    /* 清理 */
    relay_destroy(&cfg.relay);
    socket_close(cfg.server_sock);
    table_destroy(&cfg.table);
    socket_cleanup();
    DEBUG_BASIC("DNS 中继服务器关闭");
    return 0;
}

/* ========== 参数解析 ========== */
static int parse_args(config_t *cfg, int argc, char *argv[]) {
    int i = 1;

    /* 默认值 */
    strcpy(cfg->upstream_ip, DEFAULT_DNS_SERVER);
    strcpy(cfg->table_file, DEFAULT_TABLE_FILE);

    while (i < argc) {
        if (strcmp(argv[i], "-d") == 0) {
            g_debug_level = DEBUG_BASIC;
            i++;
        } else if (strcmp(argv[i], "-dd") == 0) {
            g_debug_level = DEBUG_VERBOSE;
            i++;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "未知选项: %s\n", argv[i]);
            return -1;
        } else {
            /* 第一个非选项参数是 DNS 服务器地址 */
            if (strlen(argv[i]) < sizeof(cfg->upstream_ip)) {
                strcpy(cfg->upstream_ip, argv[i]);
                i++;
            } else {
                return -1;
            }

            /* 第二个非选项参数是对照表文件 */
            if (i < argc && argv[i][0] != '-') {
                if (strlen(argv[i]) < sizeof(cfg->table_file)) {
                    strcpy(cfg->table_file, argv[i]);
                    i++;
                } else {
                    return -1;
                }
            }
        }
    }

    return 0;
}

/* ========== 服务器初始化 ========== */
static int init_server(config_t *cfg) {
    /* 创建 UDP socket */
    cfg->server_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (cfg->server_sock == INVALID_SOCKET) {
        DEBUG_ERROR("socket() 创建失败");
        return -1;
    }

    /* 设置非阻塞模式 */
#ifdef PLATFORM_WIN
    unsigned long nonblock = 1;
    if (ioctlsocket(cfg->server_sock, FIONBIO, &nonblock) != 0) {
        DEBUG_ERROR("ioctlsocket() 失败");
        return -1;
    }
#else
    int flags = fcntl(cfg->server_sock, F_GETFL, 0);
    if (flags < 0 || fcntl(cfg->server_sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        DEBUG_ERROR("fcntl() 失败");
        return -1;
    }
#endif

    /* 允许地址重用 */
    int reuse = 1;
    setsockopt(cfg->server_sock, SOL_SOCKET, SO_REUSEADDR,
               (const char *)&reuse, sizeof(reuse));

    /* 绑定端口 53 */
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(DNS_PORT);

    if (bind(cfg->server_sock, (struct sockaddr *)&server_addr,
             sizeof(server_addr)) < 0) {
        DEBUG_ERROR("bind() 失败 (端口 %d 可能被占用)", DNS_PORT);
        socket_close(cfg->server_sock);
        cfg->server_sock = INVALID_SOCKET;
        return -1;
    }

    return 0;
}

/* ========== 客户端查询处理 ========== */
static void handle_client_query(config_t *cfg, const uint8_t *query,
                                 size_t query_len,
                                 const struct sockaddr_in *client_addr,
                                 socklen_t client_len) {
    char domain[256];
    uint16_t qtype;
    uint8_t response[MAX_DNS_PACKET];

    /* 提取查询域名 */
    if (dns_extract_question(query, query_len, domain, sizeof(domain), &qtype) < 0) {
        DEBUG_VERBOSE("无法解析 DNS 查询报文 (长度=%zu)", query_len);
        return;
    }

    /* 显示客户端信息 */
    char client_ip[64];
    inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, sizeof(client_ip));
    DEBUG_BASIC("查询: %-30s 类型=%3u  客户端=%-15s",
                domain, qtype, client_ip);

    /* 本地表查找 */
    uint32_t ip_addr;
    if (table_lookup(&cfg->table, domain, &ip_addr)) {
        /* 命中本地表 */
        if (ip_addr == 0) {
            /* 0.0.0.0 → 返回 NXDOMAIN (域名不存在) */
            int resp_len = dns_build_response(query, query_len,
                                              response, sizeof(response),
                                              0, 0);
            if (resp_len > 0) {
                sendto(cfg->server_sock, (const char *)response, resp_len, 0,
                       (const struct sockaddr *)client_addr, client_len);
                DEBUG_BASIC("→ 拦截 (NXDOMAIN): %s", domain);
            }
        } else {
            /* 返回本地 IP */
            int resp_len = dns_build_response(query, query_len,
                                              response, sizeof(response),
                                              ip_addr, 3600);
            if (resp_len > 0) {
                sendto(cfg->server_sock, (const char *)response, resp_len, 0,
                       (const struct sockaddr *)client_addr, client_len);
                char ip_str[64];
                inet_ntop(AF_INET, &ip_addr, ip_str, sizeof(ip_str));
                DEBUG_BASIC("→ 本地解析: %s -> %s", domain, ip_str);
            }
        }
    } else {
        /* 未命中本地表 → 中继到上游 DNS */
        DEBUG_VERBOSE("→ 中继: %s (ID转换中...)", domain);
        relay_forward(&cfg->relay, query, query_len,
                      client_addr, client_len);
    }
}

/* ========== 上游响应处理 ========== */
static void handle_upstream_response(config_t *cfg,
                                      const uint8_t *resp, size_t resp_len) {
    const dns_header_t *hdr = (const dns_header_t *)resp;

    /* 只处理响应报文 */
    if (DNS_GET_QR(hdr) != 1) {
        DEBUG_VERBOSE("忽略上游非响应报文");
        return;
    }

    DEBUG_VERBOSE("收到上游响应 (ID=%u, %zu 字节)",
                  ntohs(hdr->id), resp_len);

    relay_process_response(&cfg->relay, resp, resp_len);
}

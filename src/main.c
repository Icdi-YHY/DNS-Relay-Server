/*
 * main.c — DNS 中继服务器主程序
 *
 * 事件驱动模型 (select)，单线程处理所有客户端并发查询
 * 单 UDP socket 架构：一个 socket 绑定 53 端口，
 * 同时接收客户端请求和外部 DNS 响应，通过源地址区分。
 */

#include "platform.h"
#include "dns_message.h"
#include "dns_table.h"
#include "dns_cache.h"
#include "dns_relay.h"
#include "id_map.h"
#include "debug.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========== 默认配置 ========== */
#define DEFAULT_DNS_SERVER  "202.106.0.20"
#define DEFAULT_TABLE_FILE  "dnsrelay.txt"
#define DEFAULT_TABLE_SIZE  8191   /* 对照表哈希桶数 */
#define DEFAULT_CACHE_SIZE  1021   /* 缓存哈希桶数 */
#define DEFAULT_ID_MAP_SIZE 1024   /* 最大并发查询数 */
#define PENDING_TIMEOUT     5      /* 超时秒数 */
#define DEFAULT_CACHE_TTL   60     /* 默认缓存 TTL（秒） */

/* ========== 全局配置 ========== */
typedef struct {
    char        dns_server[64];      /* 外部 DNS 服务器 IP */
    int         dns_port;            /* 外部 DNS 端口 */
    char        table_path[256];     /* 对照表路径 */
    socket_t    sock;                /* 监听 socket（唯一） */
    struct sockaddr_in server_addr;  /* 本机绑定地址 */
    struct sockaddr_in dns_addr;     /* 外部 DNS 地址 */

    DNSTable    table;               /* 静态对照表 */
    DNSCache    cache;               /* 动态缓存 */
    IDMap       id_map;              /* ID 映射表 */
    int         cache_ttl;           /* 缓存 TTL（秒），0=使用上游值 */
} GlobalState;

/* ========== 函数声明 ========== */
static int parse_args(GlobalState *state, int argc, char *argv[]);
static int init_server(GlobalState *state);
static void handle_client_query(GlobalState *state,
                                 const uint8_t *query, int qlen,
                                 const struct sockaddr_in *client_addr);
static void handle_upstream_response(GlobalState *state,
                                      const uint8_t *resp, int resp_len);

/* ========== 主函数 ========== */
int main(int argc, char *argv[]) {
    GlobalState state;
    int ret;

    /* 设置控制台 UTF-8 输出 (Windows) */
#ifdef PLATFORM_WIN
    SetConsoleOutputCP(CP_UTF8);
#endif

    /* 设置 stderr 无缓冲，每行立即输出 */
    setvbuf(stderr, NULL, _IONBF, 0);

    /* 1. 初始化 socket 库 */
    if (socket_init() != 0) {
        fprintf(stderr, "Socket 初始化失败\n");
        return 1;
    }

    /* 2. 解析命令行参数 */
    memset(&state, 0, sizeof(state));
    state.dns_port = DNS_PORT;
    state.cache_ttl = 0;  /* 0 = 使用上游 DNS 的 TTL */
    if (parse_args(&state, argc, argv) != 0) {
        fprintf(stderr, "用法: dnsrelay [-d|-dd] [-ttl N] [dns-server-ipaddr] [filename]\n");
        socket_cleanup();
        return 1;
    }

    /* 3. 加载对照表 */
    if (dns_table_init(&state.table, DEFAULT_TABLE_SIZE) != 0) {
        DEBUG_ERROR("对照表初始化失败");
        socket_cleanup();
        return 1;
    }
    if (dns_table_load(&state.table, state.table_path) < 0) {
        DEBUG_ERROR("加载对照表失败: %s", state.table_path);
        dns_table_destroy(&state.table);
        socket_cleanup();
        return 1;
    }

    /* 4. 初始化服务器 (创建 + bind) */
    if (init_server(&state) != 0) {
        DEBUG_ERROR("服务器初始化失败");
        dns_table_destroy(&state.table);
        socket_cleanup();
        return 1;
    }

    /* 5. 初始化缓存 */
    if (dns_cache_init(&state.cache, DEFAULT_CACHE_SIZE) != 0) {
        DEBUG_ERROR("缓存初始化失败");
        close_socket(state.sock);
        dns_table_destroy(&state.table);
        socket_cleanup();
        return 1;
    }

    /* 6. 初始化 ID 映射表 */
    if (id_map_init(&state.id_map, DEFAULT_ID_MAP_SIZE) != 0) {
        DEBUG_ERROR("ID 映射表初始化失败");
        dns_cache_destroy(&state.cache);
        close_socket(state.sock);
        dns_table_destroy(&state.table);
        socket_cleanup();
        return 1;
    }

    /* 7. 输出启动信息 */
    DEBUG(1, "DNS 中继服务器启动");
    DEBUG(1, "监听端口: %d", DNS_PORT);
    DEBUG(1, "上游 DNS: %s:%d", state.dns_server, state.dns_port);
    DEBUG(1, "对照表: %s (%d 条记录)", state.table_path, state.table.count);

    /* ========== 事件循环 (select) ========== */
    fd_set read_fds;
    struct timeval tv;
    uint8_t buffer[MAX_DNS_PACKET];
    struct sockaddr_in from_addr;
    socklen_t from_len;

    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(state.sock, &read_fds);

        /* select 超时 1 秒，用于定期检查超时 */
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        ret = select((int)(state.sock + 1), &read_fds, NULL, NULL, &tv);
        if (ret < 0) {
#ifdef PLATFORM_WIN
            if (socket_errno() == WSAEINTR) continue;
#else
            if (errno == EINTR) continue;
#endif
            DEBUG_ERROR("select() 失败: errno=%d", socket_errno());
            break;
        }

        if (ret == 0) {
            /* 超时: 清理过期缓存和 ID 映射 */
            id_map_cleanup(&state.id_map, PENDING_TIMEOUT);
            dns_cache_evict_expired(&state.cache);
            continue;
        }

        /* --- 收到数据 --- */
        if (FD_ISSET(state.sock, &read_fds)) {
            from_len = sizeof(from_addr);
            int n = recvfrom(state.sock, (char *)buffer, sizeof(buffer), 0,
                             (struct sockaddr *)&from_addr, &from_len);
            if (n < 0) {
                DEBUG(2, "recvfrom 失败: errno=%d", socket_errno());
                continue;
            }

            if (n < (int)sizeof(DNSHeader))
                continue;

            /*
             * 通过源地址区分：
             *   - 源地址 == 上游 DNS 地址 → 上游响应
             *   - 否则 → 客户端查询
             */
            if (from_addr.sin_addr.s_addr == state.dns_addr.sin_addr.s_addr &&
                from_addr.sin_port == state.dns_addr.sin_port) {
                /* 来自上游 DNS 的响应 */
                handle_upstream_response(&state, buffer, n);
            } else {
                /* 来自客户端的 DNS 查询 */
                handle_client_query(&state, buffer, n, &from_addr);
            }
        }
    }

    /* 清理 */
    id_map_destroy(&state.id_map);
    dns_cache_destroy(&state.cache);
    close_socket(state.sock);
    dns_table_destroy(&state.table);
    socket_cleanup();
    DEBUG(1, "DNS 中继服务器关闭");
    return 0;
}

/* ========== 参数解析 ========== */
static int parse_args(GlobalState *state, int argc, char *argv[]) {
    int i = 1;

    /* 默认值 */
    strcpy(state->dns_server, DEFAULT_DNS_SERVER);
    strcpy(state->table_path, DEFAULT_TABLE_FILE);

    while (i < argc) {
        if (strcmp(argv[i], "-d") == 0) {
            g_debug_level = DEBUG_LEVEL_BASIC;
            i++;
        } else if (strcmp(argv[i], "-dd") == 0) {
            g_debug_level = DEBUG_LEVEL_VERBOSE;
            i++;
        } else if (strcmp(argv[i], "-ttl") == 0 && i + 1 < argc) {
            int ttl = atoi(argv[++i]);
            if (ttl > 0) state->cache_ttl = ttl;
            i++;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "未知选项: %s\n", argv[i]);
            return -1;
        } else {
            /* 第一个非选项参数是 DNS 服务器地址 */
            if (strlen(argv[i]) < sizeof(state->dns_server)) {
                strcpy(state->dns_server, argv[i]);
                i++;
            } else {
                return -1;
            }

            /* 第二个非选项参数是对照表文件 */
            if (i < argc && argv[i][0] != '-') {
                if (strlen(argv[i]) < sizeof(state->table_path)) {
                    strcpy(state->table_path, argv[i]);
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
static int init_server(GlobalState *state) {
    /* 创建 UDP socket */
    state->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (state->sock == INVALID_SOCKET) {
        DEBUG_ERROR("socket() 创建失败");
        return -1;
    }

    /* 设置非阻塞模式 */
#ifdef PLATFORM_WIN
    unsigned long nonblock = 1;
    if (ioctlsocket(state->sock, FIONBIO, &nonblock) != 0) {
        DEBUG_ERROR("ioctlsocket() 失败");
        return -1;
    }
#else
    int flags = fcntl(state->sock, F_GETFL, 0);
    if (flags < 0 || fcntl(state->sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        DEBUG_ERROR("fcntl() 失败");
        return -1;
    }
#endif

    /* 允许地址重用 */
    int reuse = 1;
    setsockopt(state->sock, SOL_SOCKET, SO_REUSEADDR,
               (const char *)&reuse, sizeof(reuse));

    /* 绑定端口 53 */
    memset(&state->server_addr, 0, sizeof(state->server_addr));
    state->server_addr.sin_family = AF_INET;
    state->server_addr.sin_addr.s_addr = INADDR_ANY;
    state->server_addr.sin_port = htons(DNS_PORT);

    if (bind(state->sock, (struct sockaddr *)&state->server_addr,
             sizeof(state->server_addr)) < 0) {
        DEBUG_ERROR("bind() 失败 (端口 %d 可能被占用)", DNS_PORT);
        close_socket(state->sock);
        state->sock = INVALID_SOCKET;
        return -1;
    }

    /* 构造上游 DNS 地址 */
    memset(&state->dns_addr, 0, sizeof(state->dns_addr));
    state->dns_addr.sin_family = AF_INET;
    state->dns_addr.sin_port = htons((uint16_t)state->dns_port);

    struct in_addr addr;
    if (inet_pton(AF_INET, state->dns_server, &addr) != 1) {
        DEBUG_ERROR("无效的上游 DNS 地址: %s", state->dns_server);
        close_socket(state->sock);
        state->sock = INVALID_SOCKET;
        return -1;
    }
    state->dns_addr.sin_addr = addr;

    return 0;
}

/* ========== 客户端查询处理 ========== */
static void handle_client_query(GlobalState *state,
                                 const uint8_t *query, int qlen,
                                 const struct sockaddr_in *client_addr) {
    DNSHeader hdr;
    DNSQuestion q;
    uint8_t response[MAX_DNS_PACKET];
    char client_ip[64];

    g_query_seq++;  /* 递增查询序号 */

    /* 解析查询报文 */
    if (dns_decode_query(query, qlen, &hdr, &q) != 0) {
        DEBUG(2, "无法解析 DNS 查询报文 (长度=%d)", qlen);
        return;
    }

    /* 获取客户端 IP 字符串 */
    inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, sizeof(client_ip));
    DEBUG(1, "查询: %-30s 类型=%3u  客户端=%-15s", q.qname, q.qtype, client_ip);

    /* 1. 检查缓存（动态缓存的中继结果，存完整响应报文） */
    char cache_key[300];
    snprintf(cache_key, sizeof(cache_key), "%s|%u", q.qname, q.qtype);
    DEBUG(2, "缓存查询: %s (类型=%u)", q.qname, q.qtype);
    CacheEntry *ce = dns_cache_get(&state->cache, cache_key);
    if (ce) {
        DEBUG(2, "缓存命中: %s (类型=%u)", q.qname, q.qtype);
        /* 缓存命中，用当前查询的问题段 + 缓存的 Answer 段构造响应 */
        /* 避免问题段编码不一致导致客户端报 Question section mismatch */
        uint8_t cached_resp[MAX_DNS_PACKET];
        /* 复制头部 */
        memcpy(cached_resp, ce->response, sizeof(DNSHeader));
        DNSHeader *chdr = (DNSHeader *)cached_resp;
        chdr->id = hdr.id;  /* 匹配当前查询 */
        size_t cpos = sizeof(DNSHeader);

        /* 重新写 Question 段（用当前查询的域名） */
        int qname_len = dns_encode_name(cached_resp + cpos, q.qname);
        if (qname_len > 0) {
            cpos += qname_len;
            *(uint16_t *)(cached_resp + cpos) = htons(q.qtype);
            cpos += 2;
            *(uint16_t *)(cached_resp + cpos) = htons(q.qclass);
            cpos += 2;
        }

        /* 复制缓存的 Answer 段 */
        /* 跳过原响应中的 Question 段，定位到 Answer */
        const DNSHeader *ce_hdr = (const DNSHeader *)ce->response;
        uint16_t ce_qdcount = ntohs(ce_hdr->qdcount);
        const uint8_t *ce_body = ce->response + sizeof(DNSHeader);
        int ce_body_len = ce->response_len - (int)sizeof(DNSHeader);
        /* 跳过原 Question 段 */
        const uint8_t *ce_p = ce_body;
        const uint8_t *ce_end = ce_body + ce_body_len;
        for (uint16_t i = 0; i < ce_qdcount && ce_p < ce_end; i++) {
            ce_p = dns_skip_name(ce_p, ce_end);
            if (!ce_p) break;
            ce_p += 4;  /* QTYPE + QCLASS */
        }
        /* ce_p 现在指向 Answer 段开头 */
        int answer_len = (int)(ce_end - ce_p);
        if (answer_len > 0 && (int)(cpos + answer_len) < MAX_DNS_PACKET) {
            memcpy(cached_resp + cpos, ce_p, answer_len);
        }

        int total_len = (int)(cpos + (answer_len > 0 ? answer_len : 0));
        sendto(state->sock, (const char *)cached_resp, total_len, 0,
               (const struct sockaddr *)client_addr, sizeof(*client_addr));
        DEBUG(1, "→ 缓存命中: %s", q.qname);
        return;
    }

    /* 2. 检查本地对照表（支持多类型 + 一域名多 IP） */
    {
        int table_type;
        uint32_t table_ip;
        char table_data[256];
        int found = dns_table_lookup_type(&state->table, q.qname,
                                          &table_type, &table_ip,
                                          table_data, sizeof(table_data));

        if (found && table_type == 1 && table_ip == 0) {
            /* 不良网站拦截 (0.0.0.0 → NXDOMAIN) */
            int resp_len = dns_build_response_multi(&hdr, &q, 1, NULL, 0, NULL, 1, response, NULL, 0);
            if (resp_len > 0) {
                sendto(state->sock, (const char *)response, resp_len, 0,
                       (const struct sockaddr *)client_addr, sizeof(*client_addr));
                DEBUG(1, "→ 拦截 (NXDOMAIN): %s", q.qname);
            }
            return;
        }

        if (found && table_type == 1) {
            /* A 记录：查全部 IP */
            uint32_t ips[16];
            int ip_count = dns_table_lookup_all(&state->table, q.qname, ips, 16);
            if (ip_count > 0) {
                int resp_len = dns_build_response_multi(&hdr, &q, 1, ips, ip_count, NULL, 0, response, NULL, 0);
                if (resp_len > 0) {
                    sendto(state->sock, (const char *)response, resp_len, 0,
                           (const struct sockaddr *)client_addr, sizeof(*client_addr));
                    char ip_str[64];
                    DEBUG(1, "→ 本地解析: %s -> %s (共%d个IP, 类型=A)",
                          q.qname, ip_int_to_str(ips[0], ip_str), ip_count);
                }
                return;
            }
        }

        if (found && table_type != 1) {
            /* 非 A 记录（AAAA / CNAME / MX / NS / PTR） */
            static const char *type_names[29] = {NULL};
            if (!type_names[1]) {
                type_names[1] = "A"; type_names[2] = "NS"; type_names[5] = "CNAME";
                type_names[12] = "PTR"; type_names[15] = "MX"; type_names[28] = "AAAA";
            }
            const char *tname = (table_type >= 1 && table_type <= 28)
                                ? type_names[table_type] : "?";
            if (!tname) tname = "?";

            /* CNAME 额外返回目标域名的 A 记录 */
            uint32_t extra_ips[16];
            int extra_ip_count = 0;
            if (table_type == 5) {
                extra_ip_count = dns_table_lookup_all(&state->table,
                                    table_data, extra_ips, 16);
                if (extra_ip_count < 0) extra_ip_count = 0;
            }
            /* 类型不匹配时返回空应答（不报错，但无记录） */
            int type_matches = (q.qtype == (uint16_t)table_type) ||
                               (table_type == 5 && q.qtype == 1);
            int resp_len;
            if (!type_matches && table_type != 5) {
                resp_len = dns_build_response_multi(&hdr, &q, table_type, NULL, 0,
                                                     NULL, 0, response, NULL, 0);
            } else {
                resp_len = dns_build_response_multi(&hdr, &q, table_type, NULL, 0,
                                                     table_data, 0, response,
                                                     extra_ips, extra_ip_count);
            }
            if (resp_len > 0) {
                sendto(state->sock, (const char *)response, resp_len, 0,
                       (const struct sockaddr *)client_addr, sizeof(*client_addr));
                if (table_type == 5 && extra_ip_count > 0) {
                    DEBUG(1, "→ 本地解析: %s -> %s (类型=%s, 附带%d个IP)",
                          q.qname, table_data, tname, extra_ip_count);
                } else {
                    DEBUG(1, "→ 本地解析: %s -> %s (类型=%s)",
                          q.qname, table_data, tname);
                }
            }
            return;
        }
    }

    /* 3. 未命中 → 中继到上游 DNS */
    DEBUG(1, "→ 中继: %s (ID转换中...)", q.qname);
    relay_forward(state->sock, &state->dns_addr,
                  query, qlen,
                  (struct sockaddr_in *)client_addr, &state->id_map);
}

/* ========== 上游响应处理 ========== */
static void handle_upstream_response(GlobalState *state,
                                      const uint8_t *resp, int resp_len) {
    const DNSHeader *hdr = (const DNSHeader *)resp;

    /* 只处理响应报文 */
    if (DNS_GET_QR(hdr) != 1) {
        DEBUG(2, "忽略上游非响应报文");
        return;
    }

    DEBUG(2, "收到上游响应 (ID=%u, %d 字节, RCODE=%u)",
          ntohs(hdr->id), resp_len, DNS_GET_RCODE(hdr));

    /* 查 ID 映射表，找到原始客户端 */
    uint16_t relay_id = ntohs(hdr->id);
    uint16_t orig_id;
    struct sockaddr_in client_addr;

    if (id_map_lookup(&state->id_map, relay_id, &orig_id, &client_addr) != 0) {
        DEBUG(2, "收到未知 relay_id=%u 的响应 (可能已超时)", relay_id);
        return;
    }

    /* 复制响应报文并恢复原始 ID */
    uint8_t relay_resp[MAX_DNS_PACKET];
    int copy_len = resp_len < (int)sizeof(relay_resp) ? resp_len : (int)sizeof(relay_resp);
    memcpy(relay_resp, resp, (size_t)copy_len);
    dns_restore_id(relay_resp, (size_t)copy_len, orig_id);

    /* 发送给客户端 */
    sendto(state->sock, (const char *)relay_resp, copy_len, 0,
           (const struct sockaddr *)&client_addr, sizeof(client_addr));

    /* 释放 ID 映射条目 */
    id_map_free(&state->id_map, relay_id);

    /* 提取域名用于日志 */
    {
        DNSHeader tmp_hdr;
        DNSQuestion tmp_q;
        if (dns_decode_query(resp, resp_len, &tmp_hdr, &tmp_q) == 0) {
            DEBUG(1, "中继响应: %-30s  ID=%u→%u  客户端=%s:%d",
                   tmp_q.qname,
                   relay_id, orig_id,
                   inet_ntoa(client_addr.sin_addr),
                   ntohs(client_addr.sin_port));

            /* 缓存响应报文供后续使用 */
            if (DNS_GET_RCODE(hdr) == DNS_RCODE_NOERROR) {
                int cache_ttl = state->cache_ttl;
                if (cache_ttl <= 0) {
                    /* 未指定 TTL，从上游响应提取（所有类型） */
                    cache_ttl = dns_extract_ttl(resp, (size_t)resp_len);
                    if (cache_ttl <= 0) cache_ttl = 60;
                }
                char ck[300];
                snprintf(ck, sizeof(ck), "%s|%u", tmp_q.qname, tmp_q.qtype);
                dns_cache_put(&state->cache, ck,
                              relay_resp, copy_len, cache_ttl);
                DEBUG(1, "→ 已缓存: %s (类型=%u, TTL=%us)", tmp_q.qname, tmp_q.qtype, cache_ttl);
            } else {
                DEBUG(1, "→ 未缓存(RCODE=%u): %s",
                      DNS_GET_RCODE(hdr), tmp_q.qname);
            }
        }
    }
}

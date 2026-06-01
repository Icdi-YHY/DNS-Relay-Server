#ifndef DNS_H
#define DNS_H

/*
 * dns.h — DNS 协议结构体定义 (RFC 1035 §4.1)
 *
 * 所有多字节整数均为网络字节序 (Big-Endian)
 * 使用 #pragma pack(1) 确保结构体紧凑对齐
 */

#include "platform.h"

#ifdef _MSC_VER
    #pragma pack(push, 1)
    #define PACKED
#else
    #define PACKED __attribute__((packed))
#endif

/* ========== DNS 报文头部 (12 字节) ========== */
typedef struct PACKED {
    uint16_t id;         /* 查询标识符 */

    /* Flags (网络字节序，注意位操作) */
    uint16_t flags;

    uint16_t qdcount;    /* 问题数 */
    uint16_t ancount;    /* 回答数 */
    uint16_t nscount;    /* 权威记录数 */
    uint16_t arcount;    /* 附加记录数 */
} dns_header_t;

/* ========== Flag 位域操作宏 ========== */
/* QR: 0=查询, 1=响应 */
#define DNS_QR_MASK      0x8000
#define DNS_QR_QUERY     0x0000
#define DNS_QR_RESPONSE  0x8000
#define DNS_GET_QR(h)    (((h)->flags & DNS_QR_MASK) >> 15)

/* OPCODE: 0=标准查询, 1=反向查询, 2=服务器状态 */
#define DNS_OPCODE_MASK  0x7800
#define DNS_OPCODE_STD   0x0000
#define DNS_GET_OPCODE(h) (((h)->flags & DNS_OPCODE_MASK) >> 11)
#define DNS_SET_OPCODE(h, v) do { \
    (h)->flags = ((h)->flags & ~DNS_OPCODE_MASK) | ((v) << 11); \
} while (0)

/* AA: 权威回答 */
#define DNS_AA_MASK      0x0400
#define DNS_SET_AA(h, v) do { \
    (h)->flags = ((h)->flags & ~DNS_AA_MASK) | ((v) ? DNS_AA_MASK : 0); \
} while (0)

/* TC: 截断 */
#define DNS_TC_MASK      0x0200
#define DNS_GET_TC(h)    (((h)->flags & DNS_TC_MASK) >> 9)

/* RD: 期望递归 */
#define DNS_RD_MASK      0x0100
#define DNS_GET_RD(h)    (((h)->flags & DNS_RD_MASK) >> 8)
#define DNS_SET_RD(h, v) do { \
    (h)->flags = ((h)->flags & ~DNS_RD_MASK) | ((v) ? DNS_RD_MASK : 0); \
} while (0)

/* RA: 递归可用 */
#define DNS_RA_MASK      0x0080
#define DNS_SET_RA(h, v) do { \
    (h)->flags = ((h)->flags & ~DNS_RA_MASK) | ((v) ? DNS_RA_MASK : 0); \
} while (0)

/* RCODE: 响应码 */
#define DNS_RCODE_MASK   0x000F
#define DNS_RCODE_NOERROR   0
#define DNS_RCODE_FORMERR   1
#define DNS_RCODE_SERVFAIL  2
#define DNS_RCODE_NXDOMAIN  3
#define DNS_RCODE_REFUSED   5
#define DNS_GET_RCODE(h) (((h)->flags & DNS_RCODE_MASK))
#define DNS_SET_RCODE(h, v) do { \
    (h)->flags = ((h)->flags & ~DNS_RCODE_MASK) | ((v) & DNS_RCODE_MASK); \
} while (0)

/* ========== 查询类型和类别常量 ========== */
/* QTYPE */
#define DNS_TYPE_A       1    /* IPv4 地址 */
#define DNS_TYPE_NS      2    /* 域名服务器 */
#define DNS_TYPE_CNAME   5    /* 别名 */
#define DNS_TYPE_MX      15   /* 邮件交换 */
#define DNS_TYPE_AAAA    28   /* IPv6 地址 */
#define DNS_TYPE_PTR     12   /* 反向查询 */
#define DNS_TYPE_ANY     255  /* 任意 */

/* QCLASS */
#define DNS_CLASS_IN     1    /* Internet */

/* ========== 资源记录 (Answer/Authority/Additional 共用) ========== */
/* 注意: NAME 字段使用压缩指针或长度前缀，不能直接作为结构体成员 */
typedef struct PACKED {
    uint16_t type;      /* A, AAAA, MX, CNAME, ... */
    uint16_t cls;       /* IN */
    uint32_t ttl;       /* 生存时间 (秒) */
    uint16_t rdlength;  /* RDLENGTH */
    /* uint8_t rdata[rdlength]; 紧随其后 */
} dns_rr_t;

/* ========== 域名编解码函数 ========== */

/**
 * dns_encode_name - 将点分域名编码为 DNS 长度前缀格式
 * @dst: 目标缓冲区
 * @dst_len: 目标缓冲区大小
 * @name: 点分域名 (如 "www.bupt.edu.cn")
 * @return: 编码后字节数，失败返回 -1
 *
 * 编码结果: 3www5bupt3edu2cn0
 */
int dns_encode_name(uint8_t *dst, size_t dst_len, const char *name);

/**
 * dns_decode_name - 将 DNS 长度前缀域名解码为点分字符串
 * @dst: 目标缓冲区
 * @dst_len: 目标缓冲区大小
 * @src: DNS 报文中的域名起始位置
 * @msg: DNS 报文起始位置 (用于解引用压缩指针)
 * @msg_len: DNS 报文总长度
 * @return: 解析消耗的字节数 (含压缩指针跳转)，失败返回 -1
 *
 * 支持 DNS 名称压缩 (0xC0 指针, RFC 1035 §4.1.4)
 */
int dns_decode_name(char *dst, size_t dst_len,
                    const uint8_t *src,
                    const uint8_t *msg, size_t msg_len);

/**
 * dns_skip_name - 跳过 DNS 报文中的一个域名 (不解码)
 * @p: 域名起始位置
 * @end: 报文结束位置
 * @return: 跳过后的位置，格式错误返回 NULL
 */
const uint8_t *dns_skip_name(const uint8_t *p, const uint8_t *end);

/**
 * dns_build_response - 根据查询报文构建响应报文
 * @query: 原始查询报文
 * @query_len: 查询报文长度
 * @response: 输出缓冲区
 * @resp_len: 输出缓冲区大小
 * @ip_addr: 要返回的 IP 地址 (网络字节序)
 *          如果为 0，返回 NXDOMAIN (域名不存在)
 * @ttl: TTL 值
 * @return: 响应报文长度，失败返回 -1
 */
int dns_build_response(const uint8_t *query, size_t query_len,
                       uint8_t *response, size_t resp_len,
                       uint32_t ip_addr, uint32_t ttl);

/**
 * dns_extract_question - 从查询报文中提取域名
 * @query: 查询报文
 * @query_len: 报文长度
 * @domain: 输出缓冲区，存放提取的域名
 * @domain_len: 输出缓冲区大小
 * @qtype: 输出，查询类型
 * @return: 成功返回 0，失败返回 -1
 */
int dns_extract_question(const uint8_t *query, size_t query_len,
                         char *domain, size_t domain_len,
                         uint16_t *qtype);

/**
 * dns_build_relay_query - 构建转发到上游 DNS 的查询报文
 * @query: 原始客户端查询
 * @query_len: 原始查询长度
 * @new_id: 新的查询 ID
 * @out: 输出缓冲区
 * @out_len: 输出缓冲区大小
 * @return: 转发报文长度，失败返回 -1
 */
int dns_build_relay_query(const uint8_t *query, size_t query_len,
                          uint16_t new_id,
                          uint8_t *out, size_t out_len);

/**
 * dns_restore_id - 将上游 DNS 响应中的 ID 恢复为原始客户端 ID
 * @response: 上游 DNS 响应报文 (会被修改)
 * @response_len: 报文长度
 * @original_id: 原始客户端 ID
 * @return: 成功返回 0
 */
int dns_restore_id(uint8_t *response, size_t response_len,
                   uint16_t original_id);

/**
 * dns_copy_response - 完整复制一份 DNS 响应报文
 * @src: 源报文 (可以是查询或响应)
 * @src_len: 源报文长度
 * @dst: 目标缓冲区
 * @dst_len: 目标缓冲区大小
 * @return: 复制后的报文长度，失败返回 -1
 *
 * 将查询报文转为响应报文 (设置 QR=1) 并追加 Answer 段
 */
int dns_copy_header(uint8_t *dst, size_t dst_len,
                    const uint8_t *src, size_t src_len);

/**
 * dns_extract_a_record - 从 DNS 响应中提取第一个 A 记录 IP
 * @response: DNS 响应报文
 * @resp_len: 响应报文长度
 * @domain: 输出，查询的域名 (可选)
 * @domain_len: 域名缓冲区大小
 * @ip_addr: 输出，A 记录的 IP 地址 (网络字节序)
 * @ttl: 输出，TTL 值 (可选)
 * @return: 成功返回 1，无 A 记录返回 0，失败返回 -1
 */
int dns_extract_a_record(const uint8_t *response, size_t resp_len,
                          char *domain, size_t domain_len,
                          uint32_t *ip_addr, uint32_t *ttl);

#ifdef _MSC_VER
    #pragma pack(pop)
#endif

#endif /* DNS_H */

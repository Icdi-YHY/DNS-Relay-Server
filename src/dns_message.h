#ifndef DNS_MESSAGE_H
#define DNS_MESSAGE_H

/*
 * dns_message.h — DNS 报文编解码接口 (RFC 1035 §4.1)
 *
 * 所有多字节整数均为网络字节序 (Big-Endian)
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
    uint16_t id;         /* Transaction ID */
    uint16_t flags;      /* QR|OPCODE|AA|TC|RD|RA|Z|RCODE */
    uint16_t qdcount;    /* Question 数 */
    uint16_t ancount;    /* Answer 数 */
    uint16_t nscount;    /* Authority 数 */
    uint16_t arcount;    /* Additional 数 */
} DNSHeader;

/* ========== 解析后的查询信息 ========== */
typedef struct {
    char     qname[256];   /* 解码后的域名 */
    uint16_t qtype;        /* 查询类型 (A=1, AAAA=28, MX=15, CNAME=5, PTR=12) */
    uint16_t qclass;       /* 查询类别 (IN=1) */
} DNSQuestion;

/* ========== Header 标志位常量 ========== */
#define DNS_QR_MASK      0x8000
#define DNS_QR_QUERY     0x0000
#define DNS_QR_RESPONSE  0x8000

#define DNS_OPCODE_MASK  0x7800
#define DNS_OPCODE_STD   0x0000

#define DNS_AA_MASK      0x0400
#define DNS_TC_MASK      0x0200
#define DNS_RD_MASK      0x0100
#define DNS_RA_MASK      0x0080
#define DNS_RCODE_MASK   0x000F

#define DNS_RCODE_NOERROR   0
#define DNS_RCODE_FORMERR   1
#define DNS_RCODE_SERVFAIL  2
#define DNS_RCODE_NXDOMAIN  3
#define DNS_RCODE_REFUSED   5

#define DNS_GET_FLAGS(h)    ntohs((h)->flags)
#define DNS_GET_QR(h)       ((DNS_GET_FLAGS(h) & DNS_QR_MASK) >> 15)
#define DNS_GET_OPCODE(h)   ((DNS_GET_FLAGS(h) & DNS_OPCODE_MASK) >> 11)
#define DNS_GET_RD(h)       ((DNS_GET_FLAGS(h) & DNS_RD_MASK) >> 8)
#define DNS_GET_RCODE(h)    (DNS_GET_FLAGS(h) & DNS_RCODE_MASK)
#define DNS_SET_RD(h, v)    do { \
    uint16_t _f = ntohs((h)->flags); \
    _f = (_f & ~DNS_RD_MASK) | ((v) ? DNS_RD_MASK : 0); \
    (h)->flags = htons(_f); \
} while (0)
#define DNS_SET_RA(h, v)    do { \
    uint16_t _f = ntohs((h)->flags); \
    _f = (_f & ~DNS_RA_MASK) | ((v) ? DNS_RA_MASK : 0); \
    (h)->flags = htons(_f); \
} while (0)
#define DNS_SET_RCODE(h, v) do { \
    uint16_t _f = ntohs((h)->flags); \
    _f = (_f & ~DNS_RCODE_MASK) | ((v) & DNS_RCODE_MASK); \
    (h)->flags = htons(_f); \
} while (0)

/* ========== QTYPE / QCLASS 常量 ========== */
#define DNS_TYPE_A       1    /* IPv4 主机地址 */
#define DNS_TYPE_NS      2    /* 权威名字服务器 */
#define DNS_TYPE_CNAME   5    /* 别名规范名 */
#define DNS_TYPE_MX      15   /* 邮件交换 */
#define DNS_TYPE_AAAA    28   /* IPv6 主机地址 */
#define DNS_TYPE_PTR     12   /* 指针记录（反向查询） */
#define DNS_TYPE_ANY     255  /* 任意类型 */

#define DNS_CLASS_IN     1    /* Internet */

/* ========== 资源记录结构 (Answer/Authority/Additional) ========== */
/* NAME 字段使用压缩指针或长度前缀，不在结构体中 */
typedef struct PACKED {
    uint16_t type;      /* A, AAAA, MX, CNAME, ... */
    uint16_t cls;       /* IN */
    uint32_t ttl;       /* 生存时间 (秒) */
    uint16_t rdlength;  /* RDATA 长度 */
    /* uint8_t rdata[rdlength]; 紧随其后 */
} DNSResourceRecord;

/* ========== 关键接口 ========== */

/**
 * dns_decode_query - 解码请求报文，提取 Header 和 Question
 * @raw: 原始 DNS 报文
 * @len: 报文长度
 * @hdr: 输出，解析后的头部
 * @q: 输出，解析后的查询信息（域名、类型等）
 * @return: 成功返回 0，失败返回 -1
 */
int dns_decode_query(const uint8_t *raw, int len,
                     DNSHeader *hdr, DNSQuestion *q);

/**
 * dns_encode_name - 将点分域名编码为 DNS 标签格式
 * @buf: 输出缓冲区
 * @name: 点分域名 (如 "www.bupt.edu.cn")
 * @return: 编码后字节数，失败返回 -1
 *
 * "www.bupt.edu.cn" → \x03www\x05bupt\x03edu\x02cn\x00
 */
int dns_encode_name(uint8_t *buf, const char *name);

/**
 * dns_decode_name - 解码 DNS 域名（支持压缩指针）
 * @raw: DNS 报文起始位置
 * @rawlen: 报文总长度
 * @offset: 输入时指向域名起始偏移，输出时指向域名结束后的位置
 * @out: 输出缓冲区，存放点分字符串
 * @return: 成功返回 out，失败返回 NULL
 *
 * 支持 DNS 名称压缩指针 (0xC0, RFC 1035 §4.1.4)
 */
const char *dns_decode_name(const uint8_t *raw, int rawlen,
                            int *offset, char *out);

/**
 * dns_build_response - 构造响应报文
 * @req_hdr: 原始查询的 Header
 * @q: 原始查询的 Question
 * @ip: 要返回的 IP 地址（网络字节序），仅在 nxdomain==0 时使用
 * @nxdomain: 非 0 时返回 NXDOMAIN（域名不存在）
 * @out: 输出缓冲区
 * @return: 响应报文长度，失败返回 -1
 *
 * 当 nxdomain=1 时，返回 RCODE=3，无 Answer 段（不良网站拦截）
 * 当 nxdomain=0 且 ip≠0 时，返回 A 记录（本地解析）
 */
int dns_build_response(const DNSHeader *req_hdr, const DNSQuestion *q,
                       uint32_t ip, int nxdomain, uint8_t *out);

/**
 * dns_build_response_multi - 构造含多个 A 记录的响应报文
 * @req_hdr: 原始查询的 Header
 * @q: 原始查询的 Question
 * @ips: IP 地址数组（网络字节序）
 * @ip_count: IP 地址数量
 * @nxdomain: 非 0 时返回 NXDOMAIN（拦截）
 * @out: 输出缓冲区
 * @return: 响应报文长度，失败返回 -1
 *
 * 一个域名对应多个 IP 时使用此函数，Answer 段写入多条 A 记录
 */
int dns_build_response_multi(const DNSHeader *req_hdr, const DNSQuestion *q,
                              int rr_type, const uint32_t *ips, int ip_count,
                              const char *rdata_str,
                              int nxdomain, uint8_t *out,
                              const uint32_t *extra_ips, int extra_ip_count);

/**
 * dns_build_relay_query - 构造转发给外部 DNS 的查询报文
 * @orig_hdr: 原始查询的 Header
 * @q: 原始查询的 Question
 * @new_id: 新的查询 ID（使用中继分配的 proxy_id）
 * @out: 输出缓冲区
 * @return: 转发报文长度，失败返回 -1
 */
int dns_build_relay_query(const DNSHeader *orig_hdr, const DNSQuestion *q,
                          uint16_t new_id, uint8_t *out);

/**
 * dns_restore_id - 将上游 DNS 响应中的 ID 恢复为原始客户端 ID
 * @response: 上游 DNS 响应报文（会被修改）
 * @response_len: 报文长度
 * @original_id: 原始客户端 ID
 * @return: 成功返回 0
 */
int dns_restore_id(uint8_t *response, size_t response_len,
                   uint16_t original_id);

/**
 * dns_extract_a_record - 从 DNS 响应中提取第一条 A 记录
 * @response: DNS 响应报文
 * @resp_len: 响应报文长度
 * @domain: 输出，查询的域名（可选，可为 NULL）
 * @domain_len: 域名缓冲区大小
 * @ip_addr: 输出，A 记录的 IP 地址（网络字节序）
 * @ttl: 输出，TTL 值（可选，可为 NULL）
 * @return: 成功提取返回 1，无 A 记录返回 0，解析失败返回 -1
 */
int dns_extract_a_record(const uint8_t *response, size_t resp_len,
                         char *domain, size_t domain_len,
                         uint32_t *ip_addr, uint32_t *ttl);

#ifdef _MSC_VER
    #pragma pack(pop)
#endif

#endif /* DNS_MESSAGE_H */

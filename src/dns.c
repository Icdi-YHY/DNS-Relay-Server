#include "dns.h"
#include "debug.h"
#include <string.h>
#include <stdio.h>

/*
 * dns.c — DNS 报文解析/构建实现 (RFC 1035 §4)
 */

int dns_encode_name(uint8_t *dst, size_t dst_len, const char *name) {
    if (!dst || !dst_len || !name)
        return -1;

    size_t total = 0;
    const char *p = name;
    const char *dot;
    size_t seg_len;

    while (*p) {
        /* 跳过开头的点 */
        if (*p == '.') {
            p++;
            continue;
        }

        /* 找到下一个点或末尾 */
        dot = strchr(p, '.');
        if (dot)
            seg_len = (size_t)(dot - p);
        else
            seg_len = strlen(p);

        if (seg_len > 63)
            return -1;  /* 标签长度超限 */

        if (total + 1 + seg_len + 1 > dst_len)
            return -1;  /* 缓冲区不足 */

        dst[total++] = (uint8_t)seg_len;
        memcpy(dst + total, p, seg_len);
        total += seg_len;

        p = dot ? dot + 1 : p + seg_len;
    }

    /* 根标签 (0) */
    if (total + 1 > dst_len)
        return -1;
    dst[total++] = 0;

    return (int)total;
}

int dns_decode_name(char *dst, size_t dst_len,
                     const uint8_t *src,
                     const uint8_t *msg, size_t msg_len) {
    if (!dst || !dst_len || !src || !msg || !msg_len)
        return -1;

    size_t total = 0;
    size_t consumed = 0;
    int jumped = 0;
    const uint8_t *p = src;

    while (*p != 0) {
        if ((*p & 0xC0) == 0xC0) {
            /* 压缩指针: 高2位为11，后14位为偏移 */
            if ((size_t)(p + 1 - msg) >= msg_len)
                return -1;

            uint16_t offset = ((*p & 0x3F) << 8) | *(p + 1);
            if (offset >= msg_len)
                return -1;

            if (!jumped) {
                consumed = (size_t)(p + 2 - src);
                jumped = 1;
            }
            p = msg + offset;
            continue;
        }

        /* 普通标签 */
        uint8_t len = *p;
        p++;
        if ((size_t)(p + len - msg) > msg_len)
            return -1;

        if (len > 0) {
            if (total + 1 + len >= dst_len)
                return -1;

            if (total > 0)
                dst[total++] = '.';
            memcpy(dst + total, p, len);
            total += len;
        }
        p += len;
    }

    dst[total] = '\0';

    if (!jumped)
        consumed = (size_t)(p + 1 - src);  /* +1 for root label */

    return (int)consumed;
}

const uint8_t *dns_skip_name(const uint8_t *p, const uint8_t *end) {
    if (!p || !end || p >= end)
        return NULL;

    while (*p != 0) {
        if (*p & 0xC0) {
            /* 压缩指针，占2字节 */
            if (p + 2 > end)
                return NULL;
            return p + 2;
        }
        uint8_t len = *p;
        p++;
        if (p + len > end)
            return NULL;
        p += len;
    }
    /* 跳过根标签 */
    return p + 1;
}

int dns_extract_question(const uint8_t *query, size_t query_len,
                          char *domain, size_t domain_len,
                          uint16_t *qtype) {
    if (!query || query_len < sizeof(dns_header_t))
        return -1;

    const dns_header_t *hdr = (const dns_header_t *)query;
    uint16_t qdcount = ntohs(hdr->qdcount);

    if (qdcount == 0)
        return -1;

    /* 跳过头部到 Question 段 */
    const uint8_t *p = query + sizeof(dns_header_t);
    const uint8_t *end = query + query_len;

    /* 解码 QNAME */
    int ret = dns_decode_name(domain, domain_len, p, query, query_len);
    if (ret < 0)
        return -1;

    p += ret;

    /* 读取 QTYPE 和 QCLASS */
    if (p + 4 > end)
        return -1;

    if (qtype)
        *qtype = ntohs(*(const uint16_t *)p);

    return 0;
}

int dns_build_response(const uint8_t *query, size_t query_len,
                        uint8_t *response, size_t resp_len,
                        uint32_t ip_addr, uint32_t ttl) {
    if (!query || !response || query_len < sizeof(dns_header_t))
        return -1;

    const dns_header_t *q_hdr = (const dns_header_t *)query;
    size_t pos = 0;

    /* 1. 复制并修改头部 */
    if (pos + sizeof(dns_header_t) > resp_len)
        return -1;

    dns_header_t *r_hdr = (dns_header_t *)response;
    memcpy(r_hdr, q_hdr, sizeof(dns_header_t));

    r_hdr->flags = htons(
        DNS_QR_RESPONSE |                        /* 标记为响应 */
        (ntohs(q_hdr->flags) & DNS_RD_MASK) |     /* 继承 RD */
        DNS_RA_MASK |                             /* 递归可用 */
        (ip_addr == 0 ? DNS_RCODE_NXDOMAIN : DNS_RCODE_NOERROR) << 0
    );
    r_hdr->ancount = htons(ip_addr != 0 ? 1 : 0);
    r_hdr->nscount = 0;
    r_hdr->arcount = 0;
    pos += sizeof(dns_header_t);

    /* 2. 复制 Question 段 */
    const uint8_t *q_body = query + sizeof(dns_header_t);
    size_t q_body_len = query_len - sizeof(dns_header_t);

    /* 找到 Question 段的结束位置 (QNAME + QTYPE + QCLASS) */
    const uint8_t *q_end = dns_skip_name(q_body, q_body + q_body_len);
    if (!q_end)
        return -1;

    size_t question_len = (size_t)(q_end + 4 - q_body);  /* +4 for QTYPE+QCLASS */
    if (pos + question_len > resp_len)
        return -1;

    memcpy(response + pos, q_body, question_len);
    pos += question_len;

    /* 3. 如果是 NXDOMAIN，不需要 Answer 段 */
    if (ip_addr == 0)
        return (int)pos;

    /* 4. 构建 Answer RR (名称使用压缩指针指向 Question 中的域名) */
    /*    DNS 名称压缩: 指针指向 Question 段中的 QNAME，偏移 = sizeof(dns_header_t) */
    uint16_t name_ptr = htons(0xC000 | sizeof(dns_header_t));

    if (pos + 2 + sizeof(dns_rr_t) + 4 > resp_len)
        return -1;

    /* 名称指针 */
    memcpy(response + pos, &name_ptr, 2);
    pos += 2;

    /* RR 固定部分 */
    dns_rr_t rr;
    rr.type = htons(DNS_TYPE_A);
    rr.cls  = htons(DNS_CLASS_IN);
    rr.ttl  = htonl(ttl);
    rr.rdlength = htons(4);
    memcpy(response + pos, &rr, sizeof(dns_rr_t));
    pos += sizeof(dns_rr_t);

    /* RDATA: IP 地址 (网络字节序) */
    memcpy(response + pos, &ip_addr, 4);
    pos += 4;

    return (int)pos;
}

int dns_build_relay_query(const uint8_t *query, size_t query_len,
                           uint16_t new_id,
                           uint8_t *out, size_t out_len) {
    if (!query || !out || query_len < sizeof(dns_header_t) || query_len > out_len)
        return -1;

    memcpy(out, query, query_len);
    dns_header_t *hdr = (dns_header_t *)out;
    hdr->id = htons(new_id);

    return (int)query_len;
}

int dns_restore_id(uint8_t *response, size_t response_len,
                    uint16_t original_id) {
    if (!response || response_len < sizeof(dns_header_t))
        return -1;

    dns_header_t *hdr = (dns_header_t *)response;
    hdr->id = htons(original_id);
    return 0;
}

int dns_extract_a_record(const uint8_t *response, size_t resp_len,
                          char *domain, size_t domain_len,
                          uint32_t *ip_addr, uint32_t *ttl) {
    if (!response || resp_len < sizeof(dns_header_t))
        return -1;

    const dns_header_t *hdr = (const dns_header_t *)response;

    /* 必须是响应报文且无错误 */
    if (DNS_GET_QR(hdr) != 1)
        return -1;

    if (DNS_GET_RCODE(hdr) != DNS_RCODE_NOERROR)
        return 0;  /* 有错误，无 A 记录可提取 */

    uint16_t qdcount = ntohs(hdr->qdcount);
    uint16_t ancount = ntohs(hdr->ancount);

    if (qdcount == 0 || ancount == 0)
        return 0;

    const uint8_t *p = response + sizeof(dns_header_t);
    const uint8_t *end = response + resp_len;

    /* 跳过 Question 段 */
    for (uint16_t i = 0; i < qdcount; i++) {
        p = dns_skip_name(p, end);
        if (!p || p + 4 > end)
            return -1;
        p += 4;  /* 跳过 QTYPE (2) + QCLASS (2) */
    }

    /* 解析第一个 Answer */
    if (p >= end)
        return -1;

    /* Answer NAME (可能用压缩指针) */
    const uint8_t *name_start = p;
    p = dns_skip_name(p, end);
    if (!p || p + sizeof(dns_rr_t) > end)
        return -1;

    /* 如有需要，提取域名 */
    if (domain && domain_len > 0) {
        dns_decode_name(domain, domain_len, name_start, response, resp_len);
    }

    const dns_rr_t *rr = (const dns_rr_t *)p;
    uint16_t type = ntohs(rr->type);
    uint16_t rdlength = ntohs(rr->rdlength);

    if (type != DNS_TYPE_A)
        return 0;  /* 不是 A 记录 */

    if (rdlength != 4)
        return 0;  /* IPv4 地址必须是 4 字节 */

    if (ttl)
        *ttl = ntohl(rr->ttl);

    p += sizeof(dns_rr_t);
    if (p + 4 > end)
        return -1;

    if (ip_addr)
        *ip_addr = *(const uint32_t *)p;

    return 1;  /* 成功提取 */
}

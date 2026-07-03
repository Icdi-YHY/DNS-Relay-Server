#include "dns_message.h"
#include "debug.h"
#include <string.h>
#include <stdio.h>

/*
 * dns_message.c — DNS 报文解析/构建实现 (RFC 1035 §4)
 */

/* ========== 内部工具函数 ========== */

/* 跳过报文中的一个域名（不解码），返回跳过后的位置 */
static const uint8_t *skip_name(const uint8_t *p, const uint8_t *end) {
    if (!p || !end || p >= end) return NULL;

    while (*p != 0) {
        if (*p & 0xC0) {
            if (p + 2 > end) return NULL;
            return p + 2;
        }
        uint8_t len = *p;
        p++;
        if (p + len > end) return NULL;
        p += len;
    }
    return p + 1;
}

/* ========== 公开接口 ========== */

int dns_encode_name(uint8_t *buf, const char *name) {
    if (!buf || !name) return -1;

    size_t total = 0;
    const char *p = name;
    const char *dot;
    size_t seg_len;

    while (*p) {
        if (*p == '.') { p++; continue; }

        dot = strchr(p, '.');
        seg_len = dot ? (size_t)(dot - p) : strlen(p);

        if (seg_len > 63) return -1;

        buf[total++] = (uint8_t)seg_len;
        memcpy(buf + total, p, seg_len);
        total += seg_len;

        p = dot ? dot + 1 : p + seg_len;
    }

    buf[total++] = 0;  /* 根标签 */
    return (int)total;
}

const char *dns_decode_name(const uint8_t *raw, int rawlen,
                            int *offset, char *out) {
    if (!raw || !offset || !out) return NULL;

    int pos = *offset;
    int out_pos = 0;
    int jumped = 0;

    while (pos < rawlen && raw[pos] != 0) {
        if ((raw[pos] & 0xC0) == 0xC0) {
            /* 压缩指针 */
            if (pos + 1 >= rawlen) return NULL;
            int ptr = ((raw[pos] & 0x3F) << 8) | raw[pos + 1];
            if (ptr >= rawlen) return NULL;

            if (!jumped) {
                *offset = pos + 2;
                jumped = 1;
            }
            pos = ptr;
            continue;
        }

        /* 普通标签 */
        int len = raw[pos++];
        if (pos + len > rawlen) return NULL;

        if (len > 0) {
            if (out_pos > 0) out[out_pos++] = '.';
            memcpy(out + out_pos, raw + pos, len);
            out_pos += len;
        }
        pos += len;
    }

    out[out_pos] = '\0';

    if (!jumped)
        *offset = pos + 1;  /* +1 for root label (0x00) */

    return out;
}

int dns_decode_query(const uint8_t *raw, int len,
                     DNSHeader *hdr, DNSQuestion *q) {
    if (!raw || len < (int)sizeof(DNSHeader) || !hdr || !q)
        return -1;

    /* 复制头部 */
    memcpy(hdr, raw, sizeof(DNSHeader));

    if (ntohs(hdr->qdcount) == 0)
        return -1;

    /* 跳过头部到 Question 段 */
    int offset = sizeof(DNSHeader);

    /* 解码 QNAME */
    if (!dns_decode_name(raw, len, &offset, q->qname))
        return -1;

    /* 读取 QTYPE 和 QCLASS */
    if (offset + 4 > len)
        return -1;

    q->qtype  = ntohs(*(const uint16_t *)(raw + offset));
    q->qclass = ntohs(*(const uint16_t *)(raw + offset + 2));

    return 0;
}

int dns_build_response(const DNSHeader *req_hdr, const DNSQuestion *q,
                       uint32_t ip, int nxdomain, uint8_t *out) {
    if (!req_hdr || !q || !out)
        return -1;

    DNSHeader *r_hdr = (DNSHeader *)out;
    size_t pos = 0;

    /* 1. 构建响应头部 */
    if (pos + sizeof(DNSHeader) > 512) return -1;

    memset(r_hdr, 0, sizeof(DNSHeader));
    r_hdr->id      = req_hdr->id;
    r_hdr->flags   = htons(DNS_QR_RESPONSE | DNS_RA_MASK |
                           (ntohs(req_hdr->flags) & DNS_RD_MASK) |
                           (nxdomain ? DNS_RCODE_NXDOMAIN : DNS_RCODE_NOERROR));
    r_hdr->qdcount = htons(1);
    r_hdr->ancount = htons(nxdomain ? 0 : 1);
    r_hdr->nscount = 0;
    r_hdr->arcount = 0;
    pos += sizeof(DNSHeader);

    /* 2. 复制 Question 段 */
    int qname_len = dns_encode_name((uint8_t *)out + pos, q->qname);
    if (qname_len < 0) return -1;
    pos += qname_len;

    if (pos + 4 > 512) return -1;
    *(uint16_t *)(out + pos) = htons(q->qtype);
    pos += 2;
    *(uint16_t *)(out + pos) = htons(q->qclass);
    pos += 2;

    /* 3. 如果是 NXDOMAIN，不需要 Answer 段 */
    if (nxdomain)
        return (int)pos;

    /* 4. 构建 Answer 段 */
    /* NAME 使用压缩指针指向 Question 段中的域名 */
    uint16_t name_ptr = htons(0xC000 | sizeof(DNSHeader));

    if (pos + 2 + sizeof(DNSResourceRecord) + 4 > 512) return -1;

    /* 名称指针 */
    memcpy(out + pos, &name_ptr, 2);
    pos += 2;

    /* RR 固定部分 */
    DNSResourceRecord rr;
    rr.type     = htons(DNS_TYPE_A);
    rr.cls      = htons(DNS_CLASS_IN);
    rr.ttl      = htonl(nxdomain ? 0 : 3600);
    rr.rdlength = htons(4);
    memcpy(out + pos, &rr, sizeof(DNSResourceRecord));
    pos += sizeof(DNSResourceRecord);

    /* RDATA: IP 地址 (网络字节序) */
    memcpy(out + pos, &ip, 4);
    pos += 4;

    return (int)pos;
}

int dns_build_response_multi(const DNSHeader *req_hdr, const DNSQuestion *q,
                              int rr_type, const uint32_t *ips, int ip_count,
                              const char *rdata_str,
                              int nxdomain, uint8_t *out,
                              const uint32_t *extra_ips, int extra_ip_count) {
    if (!req_hdr || !q || !out) return -1;

    int ancount = 0;
    if (!nxdomain) {
        if (rr_type == 1) ancount = ip_count > 0 ? ip_count : 0;
        else ancount = (rdata_str && rdata_str[0]) ? 1 : 0;
    }

    DNSHeader *r_hdr = (DNSHeader *)out;
    size_t pos = 0;

    /* 1. 构建响应头部 */
    if (pos + sizeof(DNSHeader) > 512) return -1;
    memset(r_hdr, 0, sizeof(DNSHeader));
    r_hdr->id      = req_hdr->id;
    r_hdr->flags   = htons(DNS_QR_RESPONSE | DNS_RA_MASK |
                           (ntohs(req_hdr->flags) & DNS_RD_MASK) |
                           (nxdomain ? DNS_RCODE_NXDOMAIN : DNS_RCODE_NOERROR));
    r_hdr->qdcount = htons(1);
    r_hdr->ancount = htons((uint16_t)ancount);
    r_hdr->nscount = 0;
    r_hdr->arcount = 0;
    pos += sizeof(DNSHeader);

    /* 2. 写 Question 段 */
    int qname_len = dns_encode_name((uint8_t *)out + pos, q->qname);
    if (qname_len < 0) return -1;
    pos += qname_len;
    if (pos + 4 > 512) return -1;
    *(uint16_t *)(out + pos) = htons(q->qtype);
    pos += 2;
    *(uint16_t *)(out + pos) = htons(q->qclass);
    pos += 2;

    /* 3. NXDOMAIN 则无 Answer 段 */
    if (nxdomain || ancount == 0)
        return (int)pos;

    /* 4. 写 Answer 段 */
    uint16_t name_ptr = htons(0xC000 | sizeof(DNSHeader));

    if (rr_type == 1) {
        /* A 记录：多条 IPv4 地址 */
        for (int i = 0; i < ip_count; i++) {
            if (pos + 2 + sizeof(DNSResourceRecord) + 4 > 512) break;
            memcpy(out + pos, &name_ptr, 2); pos += 2;
            DNSResourceRecord rr;
            rr.type     = htons(DNS_TYPE_A);
            rr.cls      = htons(DNS_CLASS_IN);
            rr.ttl      = htonl(3600);
            rr.rdlength = htons(4);
            memcpy(out + pos, &rr, sizeof(DNSResourceRecord)); pos += sizeof(DNSResourceRecord);
            memcpy(out + pos, &ips[i], 4); pos += 4;
        }
    } else if (rr_type == 28 && rdata_str) {
        /* AAAA 记录：16 字节 IPv6 地址 */
        struct in6_addr addr6;
        if (inet_pton(AF_INET6, rdata_str, &addr6) == 1) {
            if (pos + 2 + sizeof(DNSResourceRecord) + 16 > 512) return (int)pos;
            memcpy(out + pos, &name_ptr, 2); pos += 2;
            DNSResourceRecord rr;
            rr.type     = htons(DNS_TYPE_AAAA);
            rr.cls      = htons(DNS_CLASS_IN);
            rr.ttl      = htonl(3600);
            rr.rdlength = htons(16);
            memcpy(out + pos, &rr, sizeof(DNSResourceRecord)); pos += sizeof(DNSResourceRecord);
            memcpy(out + pos, &addr6, 16); pos += 16;
        }
    } else if ((rr_type == 5 || rr_type == 2 || rr_type == 12) && rdata_str) {
        /* CNAME / NS / PTR 记录：目标域名 */
        uint8_t target_enc[256];
        int target_len = dns_encode_name(target_enc, rdata_str);
        if (target_len > 0) {
            /* 记下 CNAME RDATA 的起始位置（供后面的 A 记录压缩指针使用） */
            uint16_t cname_rdata_pos = (uint16_t)(pos + 2 + sizeof(DNSResourceRecord));

            if (pos + 2 + sizeof(DNSResourceRecord) + (size_t)target_len > 512) return (int)pos;
            memcpy(out + pos, &name_ptr, 2); pos += 2;
            DNSResourceRecord rr;
            rr.type     = htons((uint16_t)rr_type);
            rr.cls      = htons(DNS_CLASS_IN);
            rr.ttl      = htonl(3600);
            rr.rdlength = htons((uint16_t)target_len);
            memcpy(out + pos, &rr, sizeof(DNSResourceRecord)); pos += sizeof(DNSResourceRecord);
            memcpy(out + pos, target_enc, (size_t)target_len); pos += (size_t)target_len;

            /* CNAME 同时返回目标域名的 A 记录 */
            if (rr_type == 5 && extra_ips && extra_ip_count > 0) {
                for (int ei = 0; ei < extra_ip_count; ei++) {
                    if (pos + 2 + sizeof(DNSResourceRecord) + 4 > 512) break;
                    /* 名称压缩指针指向 CNAME RDATA 中的目标域名 */
                    uint16_t canon_ptr = htons(0xC000 | cname_rdata_pos);
                    memcpy(out + pos, &canon_ptr, 2); pos += 2;
                    DNSResourceRecord arr;
                    arr.type     = htons(DNS_TYPE_A);
                    arr.cls      = htons(DNS_CLASS_IN);
                    arr.ttl      = htonl(3600);
                    arr.rdlength = htons(4);
                    memcpy(out + pos, &arr, sizeof(DNSResourceRecord)); pos += sizeof(DNSResourceRecord);
                    memcpy(out + pos, &extra_ips[ei], 4); pos += 4;
                    ancount++;
                }
                /* 更新 ANCOUNT */
                r_hdr->ancount = htons((uint16_t)ancount);
            }
        }
    } else if (rr_type == 15 && rdata_str) {
        /* MX 记录：2 字节优先级 + 目标域名 */
        char mx_domain[256];
        strncpy(mx_domain, rdata_str, sizeof(mx_domain) - 1);
        mx_domain[sizeof(mx_domain) - 1] = '\0';

        uint8_t target_enc[256];
        int target_len = dns_encode_name(target_enc, mx_domain);
        if (target_len > 0) {
            if (pos + 2 + sizeof(DNSResourceRecord) + 2 + (size_t)target_len > 512) return (int)pos;
            memcpy(out + pos, &name_ptr, 2); pos += 2;
            DNSResourceRecord rr;
            rr.type     = htons(DNS_TYPE_MX);
            rr.cls      = htons(DNS_CLASS_IN);
            rr.ttl      = htonl(3600);
            rr.rdlength = htons((uint16_t)(2 + target_len));
            memcpy(out + pos, &rr, sizeof(DNSResourceRecord)); pos += sizeof(DNSResourceRecord);
            *(uint16_t *)(out + pos) = htons(10); pos += 2;  /* preference = 10 */
            memcpy(out + pos, target_enc, (size_t)target_len); pos += (size_t)target_len;
        }
    }

    return (int)pos;
}

int dns_build_relay_query(const DNSHeader *orig_hdr, const DNSQuestion *q,
                          uint16_t new_id, uint8_t *out) {
    if (!orig_hdr || !q || !out)
        return -1;

    size_t pos = 0;

    /* 1. 构建头部 (只改 ID) */
    if (pos + sizeof(DNSHeader) > 512) return -1;

    DNSHeader *hdr = (DNSHeader *)out;
    memcpy(hdr, orig_hdr, sizeof(DNSHeader));
    hdr->id = htons(new_id);
    hdr->qdcount = htons(1);
    pos += sizeof(DNSHeader);

    /* 2. 写 Question 段 */
    int qname_len = dns_encode_name((uint8_t *)out + pos, q->qname);
    if (qname_len < 0) return -1;
    pos += qname_len;

    if (pos + 4 > 512) return -1;
    *(uint16_t *)(out + pos) = htons(q->qtype);
    pos += 2;
    *(uint16_t *)(out + pos) = htons(q->qclass);
    pos += 2;

    return (int)pos;
}

int dns_restore_id(uint8_t *response, size_t response_len,
                   uint16_t original_id) {
    if (!response || response_len < sizeof(DNSHeader))
        return -1;

    DNSHeader *hdr = (DNSHeader *)response;
    hdr->id = htons(original_id);
    return 0;
}

int dns_extract_a_record(const uint8_t *response, size_t resp_len,
                         char *domain, size_t domain_len,
                         uint32_t *ip_addr, uint32_t *ttl) {
    if (!response || resp_len < sizeof(DNSHeader))
        return -1;

    const DNSHeader *hdr = (const DNSHeader *)response;

    if (DNS_GET_QR(hdr) != 1)
        return -1;

    if (DNS_GET_RCODE(hdr) != DNS_RCODE_NOERROR)
        return 0;

    uint16_t qdcount = ntohs(hdr->qdcount);
    uint16_t ancount = ntohs(hdr->ancount);

    if (qdcount == 0 || ancount == 0)
        return 0;

    const uint8_t *p = response + sizeof(DNSHeader);
    const uint8_t *end = response + resp_len;

    /* 跳过 Question 段 */
    for (uint16_t i = 0; i < qdcount; i++) {
        p = skip_name(p, end);
        if (!p || p + 4 > end) return -1;
        p += 4;
    }

    /* 解析第一个 Answer */
    if (p >= end) return -1;

    const uint8_t *name_start = p;
    p = skip_name(p, end);
    if (!p || p + sizeof(DNSResourceRecord) > end) return -1;

    /* 提取域名 */
    if (domain && domain_len > 0) {
        int offset = (int)(name_start - response);
        dns_decode_name(response, (int)resp_len, &offset, domain);
    }

    const DNSResourceRecord *rr = (const DNSResourceRecord *)p;
    uint16_t type = ntohs(rr->type);
    uint16_t rdlength = ntohs(rr->rdlength);

    if (type != DNS_TYPE_A) return 0;
    if (rdlength != 4) return 0;

    if (ttl) *ttl = ntohl(rr->ttl);

    p += sizeof(DNSResourceRecord);
    if (p + 4 > end) return -1;

    if (ip_addr) *ip_addr = *(const uint32_t *)p;

    return 1;
}

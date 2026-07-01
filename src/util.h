#ifndef UTIL_H
#define UTIL_H

/*
 * util.h — 工具函数接口
 *
 * 域名编码/解码工具、字节序转换封装、IP 地址字符串与二进制互转
 */

#include <stdint.h>

/**
 * encode_domain_name - 将点分域名编码为 DNS 标签格式
 * @buf: 输出缓冲区
 * @domain: 点分域名 (如 "www.example.com")
 * @return: 编码后字节数，失败返回 -1
 *
 * 将 "www.example.com" 编码为 \x03www\x07example\x03com\x00
 */
int encode_domain_name(uint8_t *buf, const char *domain);

/**
 * decode_domain_name - 解码 DNS 域名（支持压缩指针）
 * @msg: DNS 报文起始位置
 * @msg_len: 报文总长度
 * @offset: 输入时指向域名起始偏移，输出时指向域名结束后的位置
 * @out: 输出缓冲区，存放点分字符串
 * @return: 成功返回 out，失败返回 NULL
 *
 * 支持 DNS 名称压缩指针 (0xC0, RFC 1035 §4.1.4)
 */
const char *decode_domain_name(const uint8_t *msg, int msg_len,
                               int *offset, char *out);

/**
 * ip_str_to_int - IP 字符串转网络字节序整数
 * @ip_str: 点分 IP 字符串 (如 "192.168.1.1")
 * @return: 网络字节序的 32 位 IP 地址，失败返回 0
 */
uint32_t ip_str_to_int(const char *ip_str);

/**
 * ip_int_to_str - IP 整数转点分字符串
 * @ip: 网络字节序的 32 位 IP 地址
 * @buf: 输出缓冲区 (至少 16 字节)
 * @return: 指向 buf 的指针
 */
const char *ip_int_to_str(uint32_t ip, char *buf);

#endif /* UTIL_H */

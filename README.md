# DNS-Relay-Server

**计算机网络课程设计** — C语言实现 DNS 中继服务器

## 功能概述

DNS 中继服务器（DNS Relay Server）是位于客户端与外部 DNS 服务器之间的中间层，
具有三种核心功能：

| 功能 | 说明 |
|------|------|
| **DNS 服务器** | 从本地"域名-IP 地址"对照表中查找，命中则直接返回 IP |
| **不良网站拦截** | 表中 IP 为 `0.0.0.0` 时，返回 NXDOMAIN (域名不存在) |
| **DNS 中继** | 未命中时，向外部 DNS 服务器转发查询并返回结果 |

## 协议标准

- **RFC 1035** — DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
- 基于 UDP 协议，监听端口 53
- 支持 DNS 名称压缩指针 (0xC0)

## 项目结构

```
dnsrelay/
├── src/
│   ├── main.c       — 入口、参数解析、UDP 事件循环
│   ├── dns.h        — DNS 协议结构体及编解码函数声明
│   ├── dns.c        — DNS 报文解析/构建实现
│   ├── table.h      — 域名-IP 对照表接口
│   ├── table.c      — 哈希表实现，支持文件加载与快速查找
│   ├── relay.h      — 中继转发模块接口
│   ├── relay.c      — 外部 DNS 通信 + ID 映射
│   ├── cache.h      — 动态缓存接口
│   ├── cache.c      — 缓存实现
│   ├── platform.h   — 平台抽象层 (Win/Linux)
│   └── debug.h      — 调试输出宏
├── dnsrelay.txt     — 默认域名-IP 对照表
├── Makefile         — 构建系统
└── README.md        — 本文件
```

## 构建方法

### 使用 GCC (Linux / MinGW)

```bash
make
```

### 使用 MSVC (Windows Visual Studio)

```bash
nmake /f NMakefile
```

或直接在 Visual Studio 中创建项目并添加 `src/` 下的源文件。

## 使用方法

### 命令行语法

```
dnsrelay [-d|-dd] [dns-server-ipaddr] [filename]
```

### 参数说明

| 参数 | 说明 |
|------|------|
| `-d` | 调试级别 1（输出时间、序号、客户端IP、查询域名） |
| `-dd` | 调试级别 2（输出详细调试信息） |
| `dns-server-ipaddr` | 外部 DNS 服务器 IP（默认 `202.106.0.20`） |
| `filename` | 域名-IP 对照表文件路径（默认 `dnsrelay.txt`） |

### 示例

```bash
# 无调试输出，使用默认外部 DNS 和默认对照表
dnsrelay

# 调试级别 1，指定外部 DNS 和对账表
dnsrelay -d 192.168.0.1 c:\dns-table.txt

# 调试级别 2，仅指定外部 DNS
dnsrelay -dd 202.99.96.68
```

### 系统配置与运行

1. 使用 `ipconfig /all` 记下当前 DNS 服务器地址
2. 将本机 DNS 设为 `127.0.0.1`
3. 运行 `dnsrelay` 程序，指定外部 DNS 为步骤 1 记下的地址
4. 正常使用 `ping`、`nslookup`、浏览器等功能验证

### 相关命令

```bash
nslookup www.bupt.edu.cn    # 查询域名 IP
nslookup                     # 交互式查询
ipconfig /displaydns         # 查看 DNS 缓存
ipconfig /flushdns           # 清空 DNS 缓存
```

## 状态

> 🚧 项目开发中...

| 阶段 | 状态 |
|------|------|
| Phase 1: 项目骨架 + DNS 协议定义 | ✅ 已完成 |
| Phase 2: 对照表 + 本地 DNS 解析 | ✅ 已完成 |
| Phase 3: DNS 中继 + ID 映射 + 并发 | ✅ 已完成 |
| Phase 4: 动态缓存 + 功能扩展 | ✅ 已完成 |
| Phase 5: 文档完善 + 最终测试 | ⏳ 待开始 |

## 参考资料

- RFC 1035: Domain Names - Implementation and Specification
- TCP/IP 网络互连技术 卷3, Douglas E. Comer, 清华大学出版社

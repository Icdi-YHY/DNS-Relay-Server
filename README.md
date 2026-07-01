# DNS-Relay-Server

**北京邮电大学 — 项目式课程阶段2（计算机网络课程设计）**

**C语言实现的 DNS 中继服务器**：本地域名解析 + 不良网站拦截 + 外部DNS转发

---

## 目录

1. [功能概述](#功能概述)
2. [系统架构](#系统架构)
3. [协议标准](#协议标准)
4. [项目结构](#项目结构)
5. [构建方法](#构建方法)
6. [使用方法](#使用方法)
7. [运行测试](#运行测试)
8. [模块设计](#模块设计)
9. [开发阶段](#开发阶段)
10. [参考资料](#参考资料)

---

## 功能概述

DNS 中继服务器是位于客户端与外部 DNS 服务器之间的中间层，具有三种核心功能：

| 场景 | 检索结果 | 行为 | 功能 |
|------|---------|------|------|
| **Case 1** | 命中普通 IP 地址 | 向客户端返回该 IP | **DNS 服务器** |
| **Case 2** | 命中 `0.0.0.0` | 返回 NXDOMAIN（域名不存在报错） | **不良网站拦截** |
| **Case 3** | 本地未命中 | 向外部 DNS 服务器转发查询，结果返回给客户端 | **DNS 中继** |

### 高级特性

- **多客户端并发**：`select()` 事件驱动，单线程处理所有并发查询
- **ID 映射**：自动转换客户端与上游之间的 DNS 查询 ID，避免冲突
- **动态缓存**：自动缓存中继结果，遵循 DNS TTL，减少上游请求
- **超时处理**：5 秒超时自动清理挂起查询
- **跨平台**：支持 Windows 和 Linux

---

## 系统架构

```
┌──────────┐     DNS 查询 (UDP 53)     ┌────────────────┐     DNS 转发      ┌──────────────┐
│ 客户端 A  │ ──────────────────────────▶ │                │ ────────────────▶ │   上游 DNS   │
└──────────┘                             │  DNS 中继服务器  │                  │  (8.8.8.8)   │
┌──────────┐     DNS 查询 (UDP 53)     │                │                  └──────────────┘
│ 客户端 B  │ ──────────────────────────▶ │  127.0.0.1:53  │
└──────────┘                             │                │
                                         │  查询处理流程:   │
                                         │  ① 缓存 →       │
                                         │  ② 本地表 →     │
                                         │  ③ 中继转发     │
                                         └────────────────┘
```

### 查询处理流程

```
客户端 DNS 查询
        │
        ▼
  ┌──────────┐  命中   ┌────────────┐
  │ ① 缓存   │ ──────▶ │ 返回结果给  │
  │  检查    │         │   客户端    │
  └──────────┘         └────────────┘
        │ 未命中
        ▼
  ┌──────────┐  命中   ┌────────────┐
  │ ② 本地   │ ──────▶ │ 返回结果给  │
  │  对照表  │         │   客户端    │
  └──────────┘         └────────────┘
        │ 未命中
        ▼
  ┌──────────┐         ┌────────────┐
  │ ③ 中继   │ ──────▶ │ 转发到上游  │
  │  转发    │         │   DNS      │
  └──────────┘         └─────┬──────┘
                             │ 收到响应
                             ▼
                      ┌────────────┐
                      │ 缓存结果 +  │
                      │ 返回给客户端 │
                      └────────────┘
```

---

## 协议标准

- **RFC 1035** — DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
- 基于 UDP 协议，监听端口 53
- 支持 DNS 名称压缩指针 (0xC0, RFC 1035 §4.1.4)
- 支持查询类型：A (IPv4)、AAAA (IPv6)、MX、CNAME、PTR、ANY

---

## 项目结构

```
dnsrelay/
├── src/
│   ├── main.c             入口、参数解析、UDP 事件循环
│   ├── platform.h/c       平台抽象层 (Windows/Linux socket 封装)
│   ├── debug.h/c          调试输出 (级别 0/1/2, 带递增序号)
│   ├── util.h/c           工具函数 (域名编解码/IP 转换)
│   ├── dns_message.h/c    DNS 协议结构体及报文编解码 (RFC 1035 §4.1)
│   ├── dns_table.h/c      域名-IP 对照表 (哈希表, 支持文件加载与 O(1) 查找)
│   ├── dns_cache.h/c      动态缓存 (完整响应报文, TTL 过期自动清理)
│   ├── id_map.h/c         ID 转换表 (管理并发查询的 ID 映射)
│   └── dns_relay.h/c      中继转发 (转发到外部 DNS, 依赖 id_map 模块)
├── dnsrelay.txt           默认域名-IP 对照表 (909 条记录)
├── Makefile               构建系统 (支持 GCC/MinGW)
└── README.md              本文件
```

### 模块职责与耦合

| 模块 | 职责 | 依赖 | 抽象程度 |
|------|------|------|---------|
| `platform.h/c` | Socket 初始化/清理/关闭 | 无 | ⭐⭐⭐ |
| `debug.h/c` | 分级调试输出宏 + 递增序号 + 十六进制转储 | 无 | ⭐⭐⭐ |
| `util.h/c` | 域名编解码/IP 地址转换工具 | `platform.h` | ⭐⭐⭐ |
| `dns_message.h/c` | DNS 报文编解码 (Header + Question) | `platform.h` | ⭐⭐⭐ |
| `dns_table.h/c` | 域名-IP 哈希表 (含动态添加) | `platform.h` | ⭐⭐⭐ |
| `dns_cache.h/c` | TTL 动态缓存 (存完整响应报文) | `platform.h`, `debug.h` | ⭐⭐⭐ |
| `id_map.h/c` | ID 转换表 (独立管理并发查询 ID 映射) | `platform.h`, `debug.h` | ⭐⭐⭐ |
| `dns_relay.h/c` | 中继转发 (转发到外部 DNS) | `dns_message.h`, `id_map.h` | ⭐⭐⭐ |
| `main.c` | 入口、select 事件循环、业务流程 | 所有模块 | ⭐ |

---

## 构建方法

### 使用 GCC (MinGW / Linux)

```bash
# 编译
gcc -Wall -Wextra -std=c99 -O2 -I src -o dnsrelay.exe \
    src/main.c src/platform.c src/debug.c src/util.c \
    src/dns_message.c src/dns_table.c src/dns_cache.c \
    src/id_map.c src/dns_relay.c \
    -lws2_32

# 或使用 Makefile
make
```

### 使用 MSVC (Visual Studio)

```
cl /Wall /std:c11 /O2 /I src src/main.c src/platform.c src/debug.c src/util.c src/dns_message.c src/dns_table.c src/dns_cache.c src/id_map.c src/dns_relay.c /link ws2_32.lib
```

### 使用 Makefile（推荐）

```bash
make        # 编译
make clean  # 清理
```

---

## 使用方法

### 命令行语法

```
dnsrelay [-d|-dd] [dns-server-ipaddr] [filename]
```

### 参数说明

| 参数 | 说明 |
|------|------|
| `-d` | 调试级别 1：输出时间戳、客户端 IP、查询域名 |
| `-dd` | 调试级别 2：输出详细调试信息（报文内容、ID映射等） |
| `dns-server-ipaddr` | 外部 DNS 服务器 IP（默认 `202.106.0.20`） |
| `filename` | 域名-IP 对照表文件路径（默认 `dnsrelay.txt`） |

### 示例

```bash
# 无调试输出，使用默认外部 DNS 和默认对照表
dnsrelay

# 调试级别 1，指定外部 DNS（8.8.8.8）和对照表
dnsrelay -d 8.8.8.8 dnsrelay.txt

# 调试级别 2，仅指定外部 DNS
dnsrelay -dd 202.99.96.68
```

---

## 运行测试

### 测试环境准备

1. 使用 `ipconfig /all` 记下当前 DNS 服务器地址（例如 `10.3.9.45`）
2. 将本机 DNS 设为 `127.0.0.1`（网络适配器属性 → IPv4 → DNS）
3. 运行 dnsrelay 程序，指定外部 DNS 为步骤 1 记下的地址：

```bash
dnsrelay -d 10.3.9.45 dnsrelay.txt
```

### 测试用例

#### 测试 1：本地解析功能（命中对照表）

对照表中有 `www.bupt.cn → 123.127.134.10`

```bash
nslookup www.bupt.cn
```
期望结果：返回 IP `123.127.134.10`

#### 测试 2：不良网站拦截（命中 0.0.0.0）

对照表中有 `ad1.sina.com.cn → 0.0.0.0`

```bash
nslookup ad1.sina.com.cn
```
期望结果：返回 "DNS request timed out" 或 NXDOMAIN

#### 测试 3：中继功能（未命中本地表）

```bash
nslookup www.baidu.com
```
期望结果：返回正确 IP（由上游 DNS 解析）

#### 测试 4：并发查询

```bash
nslookup www.bupt.edu.cn
nslookup www.google.com
nslookup www.baidu.com
```
期望结果：所有查询均能正确解析

### 调试命令

```bash
nslookup www.bupt.edu.cn     # 查询域名 IP
nslookup                      # 交互式查询
ipconfig /displaydns          # 查看 DNS 缓存
ipconfig /flushdns            # 清空 DNS 缓存
```

---

## 模块设计

### DNS 报文结构 (dns.h/c)

严格按照 RFC 1035 §4.1 实现：

- **Header** (12 字节): ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
- **Question**: QNAME (长度前缀格式), QTYPE, QCLASS
- **Resource Record**: NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA

关键函数：
- `dns_encode_name` / `dns_decode_name` — 域名编解码（支持压缩指针）
- `dns_build_response` — 构建响应报文（成功/NXDOMAIN）
- `dns_extract_question` — 解析查询域名和类型
- `dns_extract_a_record` — 从响应中提取 A 记录

### 域名-IP 对照表 (table.h/c)

- **数据结构**：哈希表 (djb2 算法)，8191 个桶，链地址法解决碰撞
- **文件格式**：每行 `IP_ADDRESS DOMAIN_NAME`，`#` 注释，空行跳过
- **查找**：O(1) 平均时间复杂度

### 中继转发 (relay.h/c)

- **双 Socket 设计**：server_sock 接客户端，upstream_sock 接上游 DNS
- **ID 映射**：每个并发查询分配唯一 proxy_id，记录 `proxy_id → (client, original_id)` 映射
- **超时管理**：5 秒超时自动清理，不阻塞客户端
- **并发模型**：`select()` 同时监控两个 socket，零忙等待

### 动态缓存 (cache.h/c)

- **数据结构**：哈希表 (djb2)，1021 个桶
- **TTL 管理**：缓存上游 DNS 响应中的 TTL，过期自动清理（最小保留 60 秒）
- **否定缓存**：NXDOMAIN 结果也缓存，避免重复查询不存在的域名
- **上限**：5000 条，超出时淘汰过期条目

### 平台抽象 (platform.h)

- 将 Windows (`winsock2.h`) 和 POSIX (`sys/socket.h`) 差异集中封装
- 提供统一接口：`socket_init()`、`socket_cleanup()`、`socket_close()`
- 核心代码使用抽象接口，条件编译只在平台层出现

### 调试输出 (debug.h)

- 三级控制：`NONE`（无）、`BASIC`（基本信息）、`VERBOSE`（详细信息）
- 通过 `-d` / `-dd` 命令行参数控制
- 宏封装：不在主流程中插入条件判断

---

## 开发阶段

| 阶段 | 内容 | 状态 |
|------|------|------|
| Phase 1 | 项目骨架 + DNS 协议结构体定义 + 构建系统 | ✅ 已完成 |
| Phase 2 | 对照表模块 + DNS 报文解析 + 本地查询响应 | ✅ 已完成 |
| Phase 3 | DNS 中继 + ID 映射 + select 并发 + 超时处理 | ✅ 已完成 |
| Phase 4 | 动态缓存 + A 记录提取 + 三层查询体系 | ✅ 已完成 |
| Phase 5 | 文档完善 + 最终测试 | ✅ 已完成 |

---

## 参考资料

- **RFC 1035**: Domain Names - Implementation and Specification
- **RFC 1034**: Domain Names - Concepts and Facilities
- **TCP/IP 网络互连技术 卷3**, Douglas E. Comer, 清华大学出版社, 1999
- **WireShark**: https://www.wireshark.org/ — 协议分析工具

---

*北京邮电大学 网络工程专业 — 项目式课程阶段2*

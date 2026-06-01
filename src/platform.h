#ifndef PLATFORM_H
#define PLATFORM_H

/*
 * platform.h — 平台抽象层
 * 将 Windows/Linux 平台差异集中在这里，核心代码调用抽象接口
 */

/* ========== 平台检测 ========== */
#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__)
    #define PLATFORM_WIN 1
#elif defined(__linux__) || defined(__unix__) || defined(__APPLE__)
    #define PLATFORM_POSIX 1
#else
    #error "Unsupported platform"
#endif

/* ========== Socket 头文件 ========== */
#ifdef PLATFORM_WIN
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <windows.h>
    #include <ws2tcpip.h>
    /* Windows: 链接时自动引用 ws2_32.lib */
    #ifdef _MSC_VER
        #pragma comment(lib, "ws2_32.lib")
    #endif

    /* Windows 下 socket 初始化/清理 */
    static inline int socket_init(void) {
        WSADATA wsa;
        return WSAStartup(MAKEWORD(2, 2), &wsa);
    }
    static inline void socket_cleanup(void) {
        WSACleanup();
    }

    /* Windows 下 close 用 closesocket */
    #define socket_close(s)  closesocket(s)
    #define socket_errno()   WSAGetLastError()
    #define SOCKET_EWOULDBLOCK WSAEWOULDBLOCK
    #define SOCKET_ETIMEDOUT   WSAETIMEDOUT
#else
    /* POSIX (Linux / macOS) */
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <sys/select.h>
    #include <sys/time.h>

    /* POSIX 下 socket 初始化为空操作 */
    static inline int socket_init(void)  { return 0; }
    static inline void socket_cleanup(void) {}

    #define socket_close(s)  close(s)
    #define socket_errno()   errno
    #define SOCKET_EWOULDBLOCK EWOULDBLOCK
    #define SOCKET_ETIMEDOUT   ETIMEDOUT

    /* Windows SOCKET 类型在 POSIX 下就是 int */
    typedef int SOCKET;
    #define INVALID_SOCKET (-1)
    #define SOCKET_ERROR   (-1)
#endif

/* ========== 通用类型别名 ========== */
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ========== DNS 协议常量 ========== */
#define DNS_PORT            53      /* DNS 服务器端口 */
#define MAX_DNS_PACKET      512     /* DNS 报文最大长度 (RFC 1035) */
#define DNS_DEFAULT_TIMEOUT_MS  3000   /* 等待外部 DNS 响应的超时时间 (ms) */
#define DNS_MAX_PENDING         1024   /* 最大并发挂起查询数 */

#endif /* PLATFORM_H */

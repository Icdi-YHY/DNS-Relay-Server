#include "platform.h"

/*
 * platform.c — 平台抽象层实现
 *
 * 将 Windows/Linux 网络初始化差异封装在 .c 文件中
 */

#ifdef PLATFORM_WIN

int socket_init(void) {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa);
}

void socket_cleanup(void) {
    WSACleanup();
}

#else /* POSIX */

int socket_init(void) {
    return 0;  /* POSIX 无需初始化 */
}

void socket_cleanup(void) {
    /* POSIX 无需清理 */
}

#endif

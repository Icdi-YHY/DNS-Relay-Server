#
# Makefile — DNS 中继服务器构建系统
# 支持: Windows (MinGW/MSVC) 和 Linux
#

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LDFLAGS =

# 源文件
SRC = src/main.c src/dns.c src/table.c src/relay.c src/cache.c
OBJ = $(SRC:.c=.o)
TARGET = dnsrelay

# 平台检测
ifeq ($(OS),Windows_NT)
    # Windows
    ifeq ($(findstring mingw,$(shell $(CC) -dumpmachine)),mingw)
        # MinGW
        CFLAGS += -D_WIN32_WINNT=0x0600
    else
        # MSVC via CL
        CC = cl
        CFLAGS = /Wall /std:c11 /O2 /nologo
        OBJ = $(SRC:.c=.obj)
        TARGET = dnsrelay.exe
    endif
    # Windows 需要链接 ws2_32
    ifneq ($(CC),cl)
        LDFLAGS += -lws2_32
    endif
else
    # Linux / macOS
    CFLAGS += -D_DEFAULT_SOURCE
endif

.PHONY: all clean run

all: $(TARGET)

# 链接
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 编译规则
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.obj: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJ) $(TARGET)
ifeq ($(OS),Windows_NT)
	-del /Q $(OBJ) $(TARGET) 2>nul || echo done
endif

run: $(TARGET)
	./$(TARGET)

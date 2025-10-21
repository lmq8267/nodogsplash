
CC?=gcc
CFLAGS?=-O2 -g -Wall
CFLAGS+=-Isrc
#CFLAGS+=-Wall -Wwrite-strings -pedantic -std=gnu99
LDFLAGS+=-pthread
LDLIBS=-lmicrohttpd

STRIP?=strip
ENABLE_STATE_FILE ?= yes

NDS_OBJS=src/auth.o src/client_list.o src/commandline.o src/conf.o \
	src/debug.o src/fw_iptables.o src/path.o src/main.o src/http_microhttpd.o src/http_microhttpd_utils.o \
	src/ndsctl_thread.o src/safe.o src/tc.o src/util.o src/template.o

ifeq (yes,$(ENABLE_STATE_FILE))
CFLAGS += -DWITH_STATE_FILE
LDLIBS += -ljson-c
NDS_OBJS += src/state_file.o
endif

# 定义颜色变量
RED = \033[31m
GREEN = \033[32m
YELLOW = \033[33m
BLUE = \033[34m
RESET = \033[0m

# 输出函数
define print_step
	@echo "$(1)$(2)$(RESET)"
endef

.PHONY: clean all 

all: clean nodogsplash ndsctl

%.o : %.c
	$(call print_step, $(BLUE), 编译目标文件 $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

nodogsplash: $(NDS_OBJS) $(LIBHTTPD_OBJS)
	$(call print_step, $(GREEN), 链接 nodogsplash 可执行文件)
	$(CC) $(LDFLAGS) -o nodogsplash $+ $(LDLIBS)
	$(call print_step, $(YELLOW), 去除调试信息 nodogsplash)
	$(STRIP) nodogsplash

ndsctl: src/ndsctl.o
	$(call print_step, $(GREEN), 链接 ndsctl 可执行文件)
	$(CC) $(LDFLAGS) -o ndsctl $+ $(LDLIBS)
	$(call print_step, $(YELLOW), 去除调试信息 ndsctl)
	$(STRIP) ndsctl

clean:
	$(call print_step, $(RED), 清理生成文件)
	rm -f nodogsplash ndsctl src/*.o
	rm -rf dist

install:
ifeq (yes,$(STRIP))
	strip nodogsplash
	strip ndsctl
endif
	mkdir -p $(DESTDIR)/usr/bin/
	cp ndsctl $(DESTDIR)/usr/bin/
	cp nodogsplash $(DESTDIR)/usr/bin/
	mkdir -p $(DESTDIR)/etc/nodogsplash/htdocs/images
	cp resources/nodogsplash.conf $(DESTDIR)/etc/nodogsplash/
	cp resources/splash.html $(DESTDIR)/etc/nodogsplash/htdocs/
	cp resources/splash.css $(DESTDIR)/etc/nodogsplash/htdocs/
	cp resources/status.html $(DESTDIR)/etc/nodogsplash/htdocs/
	cp resources/splash.jpg $(DESTDIR)/etc/nodogsplash/htdocs/images/

tests:
	$(MAKE) -C ./tests tests

checkastyle:
	@command -v astyle >/dev/null 2>&1 || \
	{ echo >&2 "We need 'astyle' but it's not installed. Aborting."; exit 1; }

checkstyle: checkastyle
	@if astyle \
		--dry-run \
		--lineend=linux \
		--suffix=none \
		--style=kr \
		--indent=force-tab \
		--formatted --recursive "src/*.c" "src/*.h" | grep -q -i formatted ; then \
			echo Please fix formatting or run fixstyle ; false ; else \
			echo Style looks ok. ; fi

fixstyle: checkastyle
	@echo "\033[1;34mChecking style ...\033[00m"
	@if astyle \
		--dry-run \
		--lineend=linux \
		--suffix=none \
		--style=kr \
		--indent=force-tab \
		--formatted --recursive "src/*.c" "src/*.h" | grep -q -i formatted ; then \
			echo "\033[1;33mPrevious files have been corrected\033[00m" ; else \
			echo "\033[0;32mAll files are ok\033[00m" ; fi

DEBVERSION=$(shell dpkg-parsechangelog | awk -F'[ -]' '/^Version/{print($$2); exit;}' )
deb: clean
	mkdir -p dist/nodogsplash-$(DEBVERSION)
	tar --exclude dist --exclude ".git*" -cf - . | (cd dist/nodogsplash-$(DEBVERSION) && tar xf -)
	cd dist && tar cjf nodogsplash_$(DEBVERSION).orig.tar.bz2 nodogsplash-$(DEBVERSION) && cd -
	cd dist/nodogsplash-$(DEBVERSION) && dpkg-buildpackage -us -uc && cd -
	rm -rf dist/nodogsplash-$(DEBVERSION)

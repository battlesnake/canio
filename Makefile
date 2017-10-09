MAKEFLAGS := -rR
cansys_demo = cansys_server_demo cansys_client_demo
progs = cancat canpty $(cansys_demo)

CC := gcc
LD = $(CC)

ifeq ($(target),)
machine := $(shell uname -m)
ifeq ($(machine),x86_64)
target=pc
else
target=am335x
endif
endif

ifeq ($(target),pc)
CROSS_COMPILE ?=
CFLAGS ?= -march=native -mtune=native -flto
configured = y
endif

ifeq ($(target),am335x)
CROSS_COMPILE = arm-linux-gnueabihf-
CFLAGS = -march=armv7-a -mtune=cortex-a8 -mfpu=neon
configured = y
endif

ifneq ($(configured),y)
$(error Unknown target: $(target))
endif

CFLAGS += -O2 -Wall -Wextra -Wno-parentheses -Werror -std=gnu11 -fdata-sections -ffunction-sections -Wl,--gc-sections -pipe

.PHONY: all
all: $(progs)
	size -d $(progs)

.PHONY: clean
clean:
	rm -f -- $(progs) *.o

$(progs): %: %.o canio.o terminal.o reactor.o
	$(CROSS_COMPILE)$(LD) $(CFLAGS) -o $@ $^ -lutil

$(cansys_demo): cansys_%_demo: cansys_%.o args.o

%.o: %.c $(wildcard *.h)
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -c -std=gnu11 -o $@ $<

.PHONY: config
config:
	ip link set can0 down
	ip link set can0 up txqueuelen 1000000 type can triple-sampling on bitrate 1000000

.PHONY: virtual
virtual:
	modprobe vcan
	ip link add dev can0 type vcan
	ip link set dev can0 up

.PHONY: install
install: $(progs)
	cp -t /usr/bin $^

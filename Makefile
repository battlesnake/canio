cansys_demo = cansys_server_demo cansys_client_demo
progs = cancat canpty $(cansys_demo)

CFLAGS := -O2 -march=native -mtune=native -Wall -Wextra -Wno-parentheses -Werror -std=gnu11 -flto -fdata-sections -ffunction-sections -Wl,--gc-sections -pipe

.PHONY: all
all: $(progs)
	size -d $(progs)

.PHONY: clean
clean:
	rm -f -- $(progs) *.o

$(progs): %: %.o canio.o terminal.o reactor.o
	$(CC) $(CFLAGS) -o $@ $^ -lutil

$(cansys_demo): cansys_%_demo: cansys_%.o args.o

%.o: %.c $(wildcard *.h)
	$(CC) $(CFLAGS) -c -std=gnu11 -o $@ $<

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

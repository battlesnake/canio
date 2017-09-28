progs = cancat canpty

.PHONY: all
all: $(progs)

.PHONY: clean
clean:
	rm -f -- $(progs) *.o

$(progs): %: %.o canio.o
	$(CC) $(CFLAGS) -o $@ $^ -lutil

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

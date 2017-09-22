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

config:
	ip link set can0 down
	ip link set can0 up type can triple-sampling on bitrate 1000000 txqueuelen 10000

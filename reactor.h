#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct reactor;

#define _REACTOR_REACTION(name) int name (__attribute__((unused)) struct reactor *reactor, __attribute__((unused)) void *ctx, __attribute__((unused)) void *arg, __attribute__((unused)) int fd)
#define REACTOR_REACTION(name) static _REACTOR_REACTION(name)

typedef _REACTOR_REACTION(reactor_reaction);

struct reactor_fd
{
	int fd;
	reactor_reaction *read;
	reactor_reaction *write;
	reactor_reaction *error;
	void *arg;
};

struct reactor
{
	size_t capacity;
	size_t count;
	struct reactor_fd *rfd;
	void *ctx;
	bool ended;
	int code;
};

int reactor_init(struct reactor *inst, size_t capacity, void *ctx);
void reactor_free(struct reactor *inst);

int reactor_bind(struct reactor *inst, int fd, void *arg, reactor_reaction *read, reactor_reaction *write, reactor_reaction *error);

int reactor_cycle(struct reactor *inst, int ms);
int reactor_loop(struct reactor *inst, int *code);

void reactor_end(struct reactor *inst, int code);
bool reactor_ended(struct reactor *inst, int *code);

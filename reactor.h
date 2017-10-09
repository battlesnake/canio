#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * This class encapsulates an event-loop for event-driven IO.
 *
 * One binds file descriptors to the reactor, with optional read/write/error
 * handling callbacks.
 *
 * The event loop uses poll(2).
 *
 *  * If a descriptor is in error state, then if an error callback is bound then
 *    it will be called - otherwise the event loop will exit (if no handler).
 *
 *  * If a descriptor with a read callback is readable, then the read callback
 *    will be called.
 *
 *  * If a descriptor with a write callback is writeable then the write callback
 *    will be called.
 *
 *  * If a handler returns non-zero, the event-loop will exit, returning -1.
 *    reactor_ended will return false.
 *
 *  * If reactor_end is called (from within a callback only) then the event-loop
 *    will exit, returning zero.  The exit code passed to reactor_end will be
 *    accessible via reactor_ended (which will return true).
 *
 * The reactor has a global context pointer which is passed to all callbacks.
 * Each bound file-descriptor may also have a local context pointer which is
 * also passed to callbacks for events occurring on that descriptor.
 */

struct reactor;

#define _REACTOR_REACTION(name) int name (__attribute__((unused)) struct reactor *reactor, __attribute__((unused)) void *ctx, __attribute__((unused)) void *arg, __attribute__((unused)) int fd)
/* Useful macro for defining callbacks */
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

/* Run one cycle of the loop (with timeout), returns zero on success */
int reactor_cycle(struct reactor *inst, int ms);

/*
 * Run the event loop until error (returns -1) or until a callback calls
 * reactor_end (returns zero)
 */
int reactor_loop(struct reactor *inst, int *code);

/*
 * Call from a callback to gracefully end the event-loop
 */
void reactor_end(struct reactor *inst, int code);

/*
 * Returns whether the even-loop ended gracefully, and returns the exit code ih
 * such a case
 */
bool reactor_ended(struct reactor *inst, int *code);

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <fcntl.h>
#include <poll.h>

#include "reactor.h"

int reactor_init(struct reactor *inst, size_t capacity, void *ctx)
{
	memset(inst, 0, sizeof(*inst));
	capacity++;
	inst->capacity = capacity;
	inst->rfd = malloc(capacity * sizeof(*inst->rfd));
	if (!inst->rfd) {
		errno = ENOMEM;
		return -1;
	}
	inst->ctx = ctx;
	return 0;
}

void reactor_free(struct reactor *inst)
{
	free(inst->rfd);
	inst->rfd = NULL;
}

int reactor_bind(struct reactor *inst, int fd, void *arg, reactor_reaction *read, reactor_reaction *write, reactor_reaction *error)
{
	if (fd == -1) {
		return 0;
	}
	if (inst->count == inst->capacity) {
		errno = ENOSPC;
		return -1;
	}
	struct reactor_fd *rfd = &inst->rfd[inst->count];
	rfd->fd = fd;
	rfd->read = read;
	rfd->write = write;
	rfd->error = error;
	rfd->arg = arg;
	int prev = fcntl(fd, F_GETFL);
	if (prev == -1) {
		return -1;
	}
	if (fcntl(fd, F_SETFL, prev | O_NONBLOCK) == -1) {
		return -1;
	}
	inst->count++;
	return 0;
}

int reactor_cycle(struct reactor *inst, int timeout)
{
	struct pollfd pfds[inst->count];
	for (size_t i = 0; i < inst->count; i++) {
		const struct reactor_fd *rfd = &inst->rfd[i];
		struct pollfd *pfd = &pfds[i];
		pfd->fd = rfd->fd;
		pfd->events = 0;
		pfd->events |= rfd->read ? POLLIN : 0;
		pfd->events |= rfd->write ? POLLOUT : 0;
	}
	int ret = poll(pfds, inst->count, timeout);
	if (ret < 0) {
		goto fail;
	}
	if (ret == 0) {
		errno = ETIMEDOUT;
		goto fail;
	}
	/* Error */
	for (size_t i = 0; i < inst->count; i++) {
		const struct reactor_fd *rfd = &inst->rfd[i];
		struct pollfd *pfd = &pfds[i];
		if (pfd->revents & POLLERR) {
			errno = EIO;
			if (!rfd->error || rfd->error(inst, inst->ctx, rfd->arg, rfd->fd)) {
				goto fail;
			}
		}
		if (inst->ended) {
			goto done;
		}
	}
	/* Read */
	for (size_t i = 0; i < inst->count; i++) {
		const struct reactor_fd *rfd = &inst->rfd[i];
		struct pollfd *pfd = &pfds[i];
		errno = 0;
		if (pfd->revents & POLLIN && rfd->read(inst, inst->ctx, rfd->arg, rfd->fd)) {
			goto fail;
		}
		if (inst->ended) {
			goto done;
		}
	}
	/* Write */
	for (size_t i = 0; i < inst->count; i++) {
		const struct reactor_fd *rfd = &inst->rfd[i];
		struct pollfd *pfd = &pfds[i];
		errno = 0;
		if (pfd->revents & POLLOUT && rfd->write(inst, inst->ctx, rfd->arg, rfd->fd)) {
			goto fail;
		}
		if (inst->ended) {
			goto done;
		}
	}

	ret = 0;
	goto done;

fail:
	ret = -1;

done:
	return ret;
}

int reactor_loop(struct reactor *inst, int *code)
{
	while (!reactor_ended(inst, code)) {
		if (reactor_cycle(inst, inst->shutting_down ? 0 : -1)) {
			return inst->shutting_down && errno == ETIMEDOUT ? 0 : -1;
		}
	}
	return 0;
}

void reactor_shutdown(struct reactor *inst, int code)
{
	inst->shutting_down = true;
	inst->code = code;
}

void reactor_end(struct reactor *inst, int code)
{
	inst->ended = true;
	inst->code = code;
}

bool reactor_ended(struct reactor *inst, int *code)
{
	if (inst->ended && code) {
		*code = inst->code;
	}
	return inst->ended;
}

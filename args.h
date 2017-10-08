#pragma once
#include <stddef.h>
#include <inttypes.h>
#include "log.h"

#define MAXARGS 10
#define MAXARGL 100
typedef char arg_list[MAXARGS][MAXARGL];

struct arg_builder
{
	size_t argl;
	size_t argc;
	arg_list args;
};

enum args_char_action
{
	aca_continue,
	aca_run,
	aca_error
};

void args_reset(struct arg_builder *args);
enum args_char_action args_char(struct arg_builder *args, char c);

enum cli_command_result
{
	ccr_success,
	ccr_syntax,
	ccr_fail
};

#define _CLI_COMMAND_HANDLER(name) enum cli_command_result name (__attribute__((unused)) const struct arg_builder *args, __attribute__((unused)) void *ctx)
#define CLI_COMMAND_HANDLER(name) static _CLI_COMMAND_HANDLER(name)

typedef _CLI_COMMAND_HANDLER(cli_command_handler);

struct cli_command
{
	const char *command;
	const char *description;
	const char *syntax;
	size_t min_args;
	size_t max_args;
	cli_command_handler *handler;
};

const struct cli_command *find_command(const struct cli_command *commands, ssize_t ncommands, const char *command);

enum cli_command_result args_execute(const struct arg_builder *args, void *ctx, const struct cli_command *commands, ssize_t ncommands);

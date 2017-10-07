#include "args.h"

void args_reset(struct arg_builder *args)
{
	args->argl = 0;
	args->argc = 0;
	args->args[0][0] = 0;
}

enum args_char_action args_char(struct arg_builder *args, char c)
{
	if (c == '\r' || c == '\n') {
		if (args->argl > 0) {
			args->argl = 0;
			args->argc++;
		}
		return aca_run;
	} else if (c < 32) {
		error("Invalid character: 0x%02hhx", c);
		return aca_error;
	} else if (c == '\t' || c == ' ') {
		if (args->argl > 0) {
			args->argc++;
			args->argl = 0;
		}
		if (args->argc == MAXARGS) {
			error("Too many arguments");
			return aca_error;
		}
		return aca_continue;
	} else {
		if (args->argl == MAXARGL) {
			error("Argument too long");
			return aca_error;
		}
		args->args[args->argc][args->argl] = c;
		args->argl++;
		args->args[args->argc][args->argl] = 0;
		return aca_continue;
	}
}

const struct cli_command *find_command(const struct cli_command *commands, ssize_t ncommands, const char *command)
{
	for (ssize_t i = 0; ncommands >= 0 && i < ncommands || ncommands == -1 && commands[i].command; i++) {
		if (strcmp(commands[i].command, command) == 0) {
			return &commands[i];
		}
	}
	return NULL;
}

enum cli_command_result args_execute(const struct arg_builder *args, void *ctx, const struct cli_command *commands, ssize_t ncommands)
{
	if (!args->argc) {
		return ccr_syntax;
	}
	const struct cli_command *cmd = find_command(commands, ncommands, args->args[0]);
	if (cmd == NULL) {
		error("Invalid command");
		return ccr_syntax;
	}
	if (args->argc < cmd->min_args) {
		error("Insufficient arguments");
		return ccr_syntax;
	}
	if (args->argc > cmd->max_args) {
		error("Too many arguments");
		return ccr_syntax;
	}
	if (!cmd->handler) {
		error("Command not bound");
		return ccr_fail;
	}
	return cmd->handler(args, ctx);
}

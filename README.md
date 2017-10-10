canio
=====

The `-n <node>` flag specifies the node ID.

The `-m` flag specifies master mode, in which case the node ID specifies the ID of the target node.

The `-i` flag specifies the name of the CAN interface, e.g. can0.


cancat
======

Use like cat / netcat / tcpcat to provide simple stdio over CAN.

Example:

    # Node A
    ./cancat -m -n 10 -i can0
    # Node B
    ./cancat -n 10 -i can0
    # Now STDIN of node A appears on node B, STDOUT of node B appears on node A.

You can exit `cancat` by issuing `SIGINT` with `Ctrl+C`, unless in super-master mode:

Using `-M` (super-master mode) instead of / in addition to `-m` will cause `SIGINT` (Ctrl+C) and `SIGTSTP` (Ctrl+Z) to be forwarded to the remote via the control channel, rather than affecting the local `cancat` instance.  `SIGQUIT` (`Ctrl+\`) still ends `cancat`.

Using `-q` will suppress logging of commands received via the control channel (`cancat` does not handle these commands, but it can log them with the `-v` verbose option specified).

If piping data into a `cancat` master, do not use super-master mode.  Using it would result in certain control characters in the piped input being translated to signals for the remote instead of being sent verbatim.


canpty
======

Use to run a program locally in a PTY and make it available via cancat on the remote.

Example:

    # Node A
    ./canpty -n 2 -i can0 -- /bin/bash -i
    # Node B
    ./cancat -m -n 2 -i can0
    # Now node A is running an interactive bash shell and node B can access it via CAN.


virtual can
===========

Run `sudo make virtual` to create a virtual CAN interface called can0 for testing (uses `vcan` kernel module).


cansys
======

I'll document this properly later.

Basically it's a protocol for node discovery and administration, with a CLI client provided, and also an example server (which mocks a system).

It supports:

 * ident - get name of remote node.

 * ping - can be used to calculate RTT for remote node.

 * reboot - request remote node to reboot.

 * uptime - query remote node's uptime.

 * register read/write - read+write handlers are injected so registers do not need to be backed by storage.

 * heartbeats - periodic "I'm alive" notifications, interval can be set by client.

The mock server provided starts with uptime of zero and resets it (in addition to the heartbeat interval) on reboot.
The registers in the mock server are all read/write and persist over mocked "reboots" although there is no requirement for registers to behave this way.

The example client will ring the terminal bell (which may flash your screen or make some beep sound) on each heartbeat received.

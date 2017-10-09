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
Using `-M` instead of `-m` for master mode will cause `SIGINT` (Ctrl+C) and `SIGTSTP` (Ctrl+Z) to be forwarded to the remote via the control channel, rather than affecting the local `cancat` instance.  `SIGQUIT` still ends `cancat`.
Using `-q` will suppress logging of commands received via the control channel (`cancat` does not handle these commands, it only logs them).

canpty
======

Use to run a program locally in a PTY and make it available via cancat on the remote.

Example:

    # Node A
    ./canpty -n 2 -i can0 -- /bin/bash -i
    # Node B
    ./cancat -m -n 2 -i can0
    # Now node A is running an interactive bash shell and node B can access it via CAN.

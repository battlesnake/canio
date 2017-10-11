^Z SIGSTOP: Alternate between stopping/continueing like zsh.
SIGCHLD is sent on stop/resume I think, so we need to handle that rather than just quitting on SIGCHLD.
We can use that to track what state the child process is in so we know whether ^Z does TSTP or CONT.

Merge cancat and canpty into one program with extra argument (-t/-T like ssh) and ssh-like default (`isatty(STDIN_FILENO)`?) to determine whether to allocate pty.

canpty: option to send STDERR over can descriptor #2.

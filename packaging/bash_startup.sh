#!/bin/bash
# Disable builtins that bypass seccomp policy enforcement
enable -n kill      # Signal sending
enable -n enable    # Prevent re-enabling
enable -n ulimit    # Resource limits
enable -n umask     # File permission mask
enable -n builtin   # Force builtin bypass
enable -n command   # Function/alias bypass

# nexus-ephemera-ipc-os

Peer identity checks for the `nexus-ephemera` 0.2.0 daemon.

On Unix the crate reads the current UID. On Windows it reads the named-pipe client PID and the server PID, compares each token's user SID with the current user, and can replace the pipe DACL with one allow ACE for that user. A missing PID, a PID of zero, a SID mismatch, or a DACL that is not that single ACE fails closed. This is not mTLS. A privileged local administrator is outside this check.

The main `nexus-ephemera` crate does not contain these syscalls.

# nexus-ephemera-ipc-os

Peer identity checks for the `nexus-ephemera` 0.2.0 daemon.

On Unix the crate reads the current UID. On Windows it reads the named-pipe client PID and the server PID, compares each token's user SID with the current user, and creates a pipe DACL for that user plus its exact package SID when running in an AppContainer. The mandatory label matches the process integrity level. Missing identity, SID mismatch, unexpected ACE trustees or permissions, and label mismatches fail closed. This is not mTLS. A privileged local administrator is outside this check.

The main `nexus-ephemera` crate does not contain these syscalls.

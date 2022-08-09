//go:build darwin

package common

import (
	"syscall"
)

// LockMemory locks current and future pages in memory to protect secret keys from being swapped out to disk.
// It's possible (and strongly recommended) to deploy Wormhole such that keys are only ever
// stored in memory and never touch the disk. This is a privileged operation and requires CAP_IPC_LOCK.
func LockMemory() {
	// do nothing
}

// SetRestrictiveUmask masks the group and world bits. This ensures that key material
// and sockets we create aren't accidentally group- or world-readable.
func SetRestrictiveUmask() {
	syscall.Umask(0077) // cannot fail
}

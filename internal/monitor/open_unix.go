//go:build unix

package monitor

import (
	"os"
	"syscall"
)

// A monitored pathname may change after enumeration. Refuse final symlinks
// and avoid blocking indefinitely if an attacker substitutes a FIFO.
const fileOpenFlags = os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK

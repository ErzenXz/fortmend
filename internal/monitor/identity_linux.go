//go:build linux

package monitor

import (
	"fmt"
	"os"
	"syscall"
)

func fileIdentity(info os.FileInfo) string {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d:%d:%d", stat.Dev, stat.Ino, stat.Ctim.Sec, stat.Ctim.Nsec)
	}
	return ""
}

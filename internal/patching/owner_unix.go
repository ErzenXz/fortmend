//go:build !windows

package patching

import (
	"fmt"
	"os"
	"syscall"
)

func secureOwner(st os.FileInfo, path string, testing bool) error {
	// Injected identity is used only by package tests on macOS fixtures.
	if testing {
		return nil
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || st.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("patch state ancestor must be root owned and not group/world writable: %s", path)
	}
	return nil
}

func lockState(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another security patch operation is running: %w", err)
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

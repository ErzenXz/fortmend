package protection

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ErzenXz/fortmend/internal/model"
)

// ValidateRootPath rejects writable/symlinked policy and state ancestry before
// any privileged runtime is started.
func ValidateRootPath(path string, directory bool) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("absolute root-owned path required")
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if st.Mode()&os.ModeSymlink != 0 || st.Mode().Perm()&0022 != 0 || !rootOwned(st) {
			return fmt.Errorf("unsafe root policy/state path %s", p)
		}
		if p == filepath.Clean(path) && !directory {
			if !st.Mode().IsRegular() {
				return fmt.Errorf("policy must be a regular file")
			}
		} else if !st.IsDir() {
			return fmt.Errorf("state ancestry must be directories")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return nil
}

type EventLog struct {
	Path     string
	MaxBytes int64
	mu       sync.Mutex
}

func (l *EventLog) Append(ctx context.Context, e model.SecurityEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	max := l.MaxBytes
	if max <= 0 {
		max = 16 * 1024 * 1024
	}
	if int64(len(data)) > max {
		return fmt.Errorf("event exceeds log bound")
	}
	if st, err := os.Lstat(l.Path); err == nil {
		if !st.Mode().IsRegular() {
			return fmt.Errorf("event log is not a regular file")
		}
		if st.Size()+int64(len(data)) > max {
			if err := os.Rename(l.Path, l.Path+".previous"); err != nil {
				return err
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(l.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

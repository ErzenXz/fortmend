//go:build !linux && !darwin

package protection

import (
	"fmt"
	"os"
)

func rootOwned(os.FileInfo) bool { return false }
func AcquireLock(string) (func(), error) {
	return nil, fmt.Errorf("Linux protection lock unavailable on this platform")
}

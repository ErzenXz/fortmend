//go:build !linux && !darwin

package codexapp

import "os"

func rootOwned(os.FileInfo) bool { return false }

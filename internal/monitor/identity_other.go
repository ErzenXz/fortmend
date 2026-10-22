//go:build !linux && !darwin

package monitor

import "os"

func fileIdentity(os.FileInfo) string { return "" }

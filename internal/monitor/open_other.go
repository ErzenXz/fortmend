//go:build !unix

package monitor

import "os"

const fileOpenFlags = os.O_RDONLY

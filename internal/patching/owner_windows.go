//go:build windows

package patching

import (
	"errors"
	"os"
)

func secureOwner(os.FileInfo, string, bool) error { return errors.New("patching requires Linux") }

func lockState(string) (func(), error) { return nil, errors.New("patching requires Linux") }

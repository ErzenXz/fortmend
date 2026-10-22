//go:build !linux && !darwin

package codexapp

import "os/exec"

func isolateProcess(*exec.Cmd) {}

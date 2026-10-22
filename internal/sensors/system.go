package sensors

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// SystemRunner uses only host administration binaries from fixed system paths,
// a clean environment and bounded output. It never invokes a shell.
type SystemRunner struct{}
type boundedOutput struct {
	data  []byte
	limit int
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > b.limit {
		return 0, fmt.Errorf("command output exceeds bound")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}
func (SystemRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !filepath.IsAbs(name) {
		if strings.ContainsAny(name, "/\\") {
			return nil, fmt.Errorf("invalid system tool name")
		}
		found := ""
		for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
			p := filepath.Join(dir, name)
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0111 != 0 {
				found = p
				break
			}
		}
		if found == "" {
			return nil, fmt.Errorf("system tool unavailable: %s", name)
		}
		name = found
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C.UTF-8", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"}
	cmd.WaitDelay = 2 * time.Second
	out := &boundedOutput{limit: 16 * 1024 * 1024}
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	return out.data, err
}

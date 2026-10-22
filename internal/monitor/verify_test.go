package monitor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyWebshellAbsentBoundedAndSafe(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, content string
		wantErr       bool
	}{
		{"safe.php", "<?php echo 'healthy';", false},
		{"direct.php", "<?php system($_GET['cmd']);", true},
		{"obfuscated.php", "<?php eval(base64_decode('YWJj'));", true},
	} {
		path := filepath.Join(root, test.name)
		if err := os.WriteFile(path, []byte(test.content), 0600); err != nil {
			t.Fatal(err)
		}
		if err := VerifyWebshellAbsent(path); (err != nil) != test.wantErr || (test.wantErr && !errors.Is(err, ErrWebshellPresent)) {
			t.Errorf("%s verification: %v", test.name, err)
		}
	}
	if err := VerifyWebshellAbsent(filepath.Join(root, "absent.php")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWebshellAbsent(filepath.Join(root, "missing-dir", "absent.php")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWebshellAbsent("relative.php"); err == nil {
		t.Fatal("relative path accepted")
	}
	if err := os.Symlink(filepath.Join(root, "safe.php"), filepath.Join(root, "linked.php")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWebshellAbsent(filepath.Join(root, "linked.php")); err == nil {
		t.Fatal("leaf symlink accepted")
	}
	if err := os.Symlink(root, filepath.Join(root, "ancestor")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWebshellAbsent(filepath.Join(root, "ancestor", "safe.php")); err == nil {
		t.Fatal("ancestor symlink accepted")
	}
	dir := filepath.Join(root, "directory.php")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWebshellAbsent(dir); err == nil {
		t.Fatal("nonregular file accepted")
	}
	large := filepath.Join(root, "large.php")
	if err := os.WriteFile(large, make([]byte, (1<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyWebshellAbsent(large); err == nil {
		t.Fatal("oversize file accepted")
	}
}

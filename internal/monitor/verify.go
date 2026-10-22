package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ErrWebshellPresent means a known indicator remains, as distinct from a
// collection failure that prevented verification.
var ErrWebshellPresent = errors.New("webshell indicator remains at original path")

// VerifyWebshellAbsent checks the original path without following symlinks or
// executing PHP. A missing file or stable PHP without the known indicators
// passes; this does not establish that the service or host is uncompromised.
func VerifyWebshellAbsent(path string) error {
	parent, leaf, err := verificationParent(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer parent.Close()
	f, err := parent.OpenFile(leaf, fileOpenFlags, 0)
	if errors.Is(err, os.ErrNotExist) {
		return verifyParentCurrent(parent, path)
	}
	if err != nil {
		return fmt.Errorf("open original webshell path safely: %w", err)
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() {
		return errors.New("webshell verification refuses nonregular files")
	}
	if before.Size() > 1<<20 {
		return errors.New("webshell verification exceeds 1 MiB limit")
	}
	content, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(content) > 1<<20 {
		return errors.New("webshell verification file grew beyond limit")
	}
	digest := sha256.Sum256(content)
	contentHash := hex.EncodeToString(digest[:])
	after, err := f.Stat()
	if err != nil {
		return err
	}
	if OccurrenceID(path, contentHash, before) != OccurrenceID(path, contentHash, after) {
		return errors.New("webshell verification file changed during read")
	}
	current, err := parent.Lstat(leaf)
	if err != nil {
		return err
	}
	if current.Mode()&os.ModeSymlink != 0 || !os.SameFile(after, current) || OccurrenceID(path, contentHash, after) != OccurrenceID(path, contentHash, current) {
		return errors.New("webshell verification pathname changed during read")
	}
	if err := verifyParentCurrent(parent, path); err != nil {
		return err
	}
	if signature, _ := MatchWebshell(content); signature != "" {
		return fmt.Errorf("%w: %s", ErrWebshellPresent, signature)
	}
	return nil
}

// Anchor each directory component, compare the opened directory identity to
// its nofollow metadata, and constrain subsequent operations to that root.
func verificationParent(path string) (*os.Root, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) {
		return nil, "", errors.New("webshell verification requires a clean absolute file path")
	}
	root, err := os.OpenRoot(string(filepath.Separator))
	if err != nil {
		return nil, "", err
	}
	components := strings.Split(strings.TrimPrefix(filepath.Dir(path), string(filepath.Separator)), string(filepath.Separator))
	if len(components) > 128 {
		root.Close()
		return nil, "", errors.New("webshell verification directory depth exceeds limit")
	}
	for _, component := range components {
		if component == "" {
			continue
		}
		before, err := root.Lstat(component)
		if err != nil {
			root.Close()
			return nil, "", err
		}
		if !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
			root.Close()
			return nil, "", errors.New("webshell verification refuses symlink or non-directory ancestors")
		}
		next, err := root.OpenRoot(component)
		if err != nil {
			root.Close()
			return nil, "", err
		}
		opened, err := next.Stat(".")
		root.Close()
		if err != nil {
			next.Close()
			return nil, "", err
		}
		if !os.SameFile(before, opened) {
			next.Close()
			return nil, "", errors.New("webshell verification ancestor changed while opening")
		}
		root = next
	}
	return root, filepath.Base(path), nil
}

func verifyParentCurrent(parent *os.Root, path string) error {
	fresh, _, err := verificationParent(path)
	if err != nil {
		return fmt.Errorf("webshell verification parent changed: %w", err)
	}
	defer fresh.Close()
	anchored, err := parent.Stat(".")
	if err != nil {
		return err
	}
	current, err := fresh.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(anchored, current) {
		return errors.New("webshell verification parent directory was replaced")
	}
	return nil
}

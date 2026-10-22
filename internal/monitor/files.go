package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/sensors"
)

var directRequestExec = regexp.MustCompile(`(?is)(?:^|[^a-z0-9_$>:])(?:eval|system|passthru|shell_exec|exec)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`)
var decodedRequestEval = regexp.MustCompile(`(?is)(?:^|[^a-z0-9_$>:])eval\s*\(\s*(?:base64_decode|gzinflate)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[`)
var encodedEval = regexp.MustCompile(`(?is)\beval\s*\(\s*(?:base64_decode|gzinflate)\s*\(`)
var persistenceCommand = regexp.MustCompile(`(?is)(?:curl|wget)\b[^\n]{0,500}\|\s*(?:/bin/)?(?:ba)?sh\b|(?:/dev/tcp/|\bnc\s+[^\n]*\s-e\s|\bbash\s+-i\b)`)

// MatchWebshell reports code-level indicators, not a malware-family verdict.
// Even direct request execution can occur in deliberately unsafe test code.
// Callers must retain a recovery copy and verify any authorized remediation.
func MatchWebshell(content []byte) (signature string, confidence float64) {
	if !strings.Contains(strings.ToLower(string(content)), "<?") {
		return "", 0
	}
	content = phpExecutable(content)
	if directRequestExec.Match(content) {
		return "php-request-command-execution", .99
	}
	if decodedRequestEval.Match(content) {
		return "php-request-decoded-eval", .99
	}
	if encodedEval.Match(content) {
		return "php-obfuscated-eval", .85
	}
	return "", 0
}

// Strip comments, quoted strings and non-PHP markup before matching. Heredocs
// are deliberately excluded from high confidence matching until fully parsed.
func phpExecutable(content []byte) []byte {
	out := make([]byte, len(content))
	for i := range out {
		out[i] = ' '
	}
	inside := false
	for i := 0; i < len(content); {
		if !inside {
			phpTag := i+5 < len(content) && strings.EqualFold(string(content[i:i+5]), "<?php") && (content[i+5] == ' ' || content[i+5] == '\n' || content[i+5] == '\t' || content[i+5] == '\r')
			shortEcho := i+3 <= len(content) && string(content[i:i+3]) == "<?="
			if phpTag || shortEcho {
				inside = true
				if phpTag {
					i += 5
				} else {
					i += 3
				}
				continue
			}
			i++
			continue
		}
		if i+2 <= len(content) && string(content[i:i+2]) == "?>" {
			inside = false
			i += 2
			continue
		}
		if i+3 <= len(content) && string(content[i:i+3]) == "<<<" {
			return nil
		}
		if content[i] == '\'' || content[i] == '"' || content[i] == '`' {
			quote := content[i]
			i++
			for i < len(content) {
				if content[i] == '\\' {
					i += 2
					continue
				}
				if content[i] == quote {
					i++
					break
				}
				i++
			}
			continue
		}
		if content[i] == '#' || (i+2 <= len(content) && string(content[i:i+2]) == "//") {
			for i < len(content) && content[i] != '\n' {
				i++
			}
			continue
		}
		if i+2 <= len(content) && string(content[i:i+2]) == "/*" {
			i += 2
			for i+2 <= len(content) && string(content[i:i+2]) != "*/" {
				i++
			}
			i += 2
			continue
		}
		out[i] = content[i]
		i++
	}
	return out
}

func (m *Monitor) files(ctx context.Context, s *diskState, emit func(sensors.Observation) error) error {
	next := map[string]string{}
	nextOccurrences := map[string]string{}
	visited := 0
	var total int64
	type scope struct {
		path        string
		persistence bool
	}
	scopes := make([]scope, 0, len(m.config.WebRoots)+len(m.config.PersistencePaths))
	for _, p := range m.config.WebRoots {
		scopes = append(scopes, scope{p, false})
	}
	for _, p := range m.config.PersistencePaths {
		scopes = append(scopes, scope{p, true})
	}
	for _, sc := range scopes {
		if err := ctx.Err(); err != nil {
			return err
		}
		absolute, err := filepath.Abs(sc.path)
		if err != nil {
			return err
		}
		absolute = filepath.Clean(absolute)
		if absolute == string(filepath.Separator) {
			return errors.New("monitor refuses unscoped filesystem root")
		}
		info, err := os.Lstat(absolute)
		if errors.Is(err, os.ErrNotExist) && sc.persistence {
			continue
		}
		if err != nil {
			return fmt.Errorf("monitor scope %s: %w", absolute, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("monitor scope must not be symlink: %s", absolute)
		}
		rootPath := absolute
		first := "."
		if !info.IsDir() {
			rootPath = filepath.Dir(absolute)
			first = filepath.Base(absolute)
		}
		root, err := os.OpenRoot(rootPath)
		if err != nil {
			return err
		}
		err = walkScoped(root, first, 0, func(rel string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			visited++
			if visited > 8192 {
				return errors.New("monitor entry limit exceeded; narrow configured roots")
			}
			if d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !sc.persistence {
				ext := strings.ToLower(filepath.Ext(d.Name()))
				if ext != ".php" && ext != ".phtml" && ext != ".php3" && ext != ".php5" && ext != ".inc" {
					return nil
				}
			}
			fi, err := d.Info()
			if err != nil {
				return err
			}
			if !fi.Mode().IsRegular() {
				return nil
			}
			if fi.Size() > 1<<20 {
				return fmt.Errorf("monitored file exceeds 1 MiB limit: %s", filepath.Join(rootPath, rel))
			}
			total += fi.Size()
			if total > 32<<20 {
				return errors.New("monitor scan exceeds 32 MiB limit; narrow configured roots")
			}
			// OpenRoot confines symlink races to the configured root. Stat after
			// opening also refuses a replaced non-regular file.
			f, err := root.OpenFile(rel, fileOpenFlags, 0)
			if err != nil {
				return err
			}
			stat, err := f.Stat()
			if err != nil {
				f.Close()
				return err
			}
			if !stat.Mode().IsRegular() {
				f.Close()
				return errors.New("monitored file changed type")
			}
			content, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
			afterRead, statErr := f.Stat()
			f.Close()
			if err != nil {
				return err
			}
			if statErr != nil {
				return statErr
			}
			if len(content) > 1<<20 {
				return errors.New("monitored file grew beyond limit")
			}
			path := filepath.Join(rootPath, rel)
			digest := sha256.Sum256(content)
			hash := hex.EncodeToString(digest[:])
			occurrence := OccurrenceID(path, hash, afterRead)
			if occurrence != OccurrenceID(path, hash, stat) {
				return errors.New("monitored file changed while reading; retry required")
			}
			next[path] = hash
			nextOccurrences[path] = occurrence
			if old, ok := s.Files[path]; ok && old == hash && s.FileOccurrences[path] == occurrence {
				return nil
			}
			attrs := map[string]string{"path": path, "sha256": hash, "change": "created", "occurrenceId": occurrence}
			if old, ok := s.Files[path]; ok {
				attrs["change"] = "modified"
				attrs["previousSha256"] = old
			}
			if !sc.persistence {
				sig, confidence := MatchWebshell(content)
				if sig != "" {
					attrs["signature"] = sig
					attrs["quarantineEligible"] = "false"
					if confidence >= .99 {
						attrs["quarantineEligible"] = "true"
					}
					if err := emit(sensors.Observation{Kind: "webshell.suspicious", Severity: model.SeverityHigh, Confidence: confidence, DetectorIDs: []string{"aegis:" + sig}, Attributes: attrs}); err != nil {
						return err
					}
				}
				if s.Baseline {
					return emit(sensors.Observation{Kind: "file.modified", Severity: model.SeverityInfo, Confidence: 1, DetectorIDs: []string{"aegis:webroot-integrity"}, Attributes: attrs})
				}
			} else {
				suspicious := persistenceCommand.Match(content)
				if suspicious || s.Baseline {
					attrs["indicator"] = "persistence-content-change"
					severity := model.SeverityMedium
					confidence := .6
					if suspicious {
						attrs["indicator"] = "reverse-shell-or-download-execution"
						severity = model.SeverityHigh
						confidence = .95
					}
					return emit(sensors.Observation{Kind: "persistence.suspicious", Severity: severity, Confidence: confidence, DetectorIDs: []string{"aegis:persistence-integrity"}, Attributes: attrs})
				}
			}
			return nil
		})
		root.Close()
		if err != nil {
			return fmt.Errorf("scan %s: %w", absolute, err)
		}
	}
	for path, hash := range s.Files {
		if _, ok := next[path]; !ok {
			if err := emit(sensors.Observation{Kind: "file.modified", Severity: model.SeverityMedium, Confidence: 1, DetectorIDs: []string{"aegis:integrity-deletion"}, Attributes: map[string]string{"path": path, "previousSha256": hash, "change": "deleted"}}); err != nil {
				return err
			}
		}
	}
	s.Files = next
	s.FileOccurrences = nextOccurrences
	s.Baseline = true
	return m.save(s)
}

// Read directories incrementally: fs.WalkDir materializes every directory
// entry before applying a caller's limit, which is unsafe in attacker-writable
// webroots containing millions of entries.
func walkScoped(root *os.Root, path string, depth int, visit fs.WalkDirFunc) error {
	if depth > 64 {
		return errors.New("monitor directory depth limit exceeded")
	}
	info, err := root.Lstat(path)
	if err != nil {
		return visit(path, nil, err)
	}
	entry := fs.FileInfoToDirEntry(info)
	if err := visit(path, entry, nil); err != nil {
		return err
	}
	if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
		return nil
	}
	dir, err := root.OpenFile(path, fileOpenFlags, 0)
	if err != nil {
		return err
	}
	defer dir.Close()
	opened, err := dir.Stat()
	if err != nil {
		return err
	}
	if !opened.IsDir() {
		return errors.New("monitored directory changed type")
	}
	for {
		entries, readErr := dir.ReadDir(64)
		for _, child := range entries {
			if err := walkScoped(root, filepath.Join(path, child.Name()), depth+1, visit); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

//go:build linux

package remediation

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ErzenXz/fortmend/internal/model"
	"github.com/ErzenXz/fortmend/internal/monitor"
	"github.com/ErzenXz/fortmend/internal/sensors"
	"golang.org/x/sys/unix"
)

type receipt struct {
	Version      int       `json:"version"`
	Path         string    `json:"path"`
	SHA256       string    `json:"sha256"`
	Signature    string    `json:"signature"`
	OccurrenceID string    `json:"occurrenceId,omitempty"`
	EventID      string    `json:"eventId,omitempty"`
	Status       string    `json:"status"`
	At           time.Time `json:"at"`
	Device       uint64    `json:"device"`
	Inode        uint64    `json:"inode"`
	OriginalMode uint32    `json:"originalMode"`
	OriginalUID  uint32    `json:"originalUid"`
	OriginalGID  uint32    `json:"originalGid"`
}

func actionKey(event model.SecurityEvent, path string) string {
	identity := event.Attributes["occurrenceId"]
	if identity == "" {
		identity = event.ID
	}
	return digest([]byte(identity + "\x00" + path + "\x00" + event.Attributes["sha256"]))
}

func successObservation(path, quarantinePath string, r receipt) sensors.Observation {
	return sensors.Observation{Kind: "remediation.quarantined", Severity: model.SeverityHigh, Confidence: 1, DetectorIDs: []string{"fortmend:verified-webshell-quarantine"}, Attributes: map[string]string{"path": path, "sha256": r.SHA256, "signature": r.Signature, "occurrenceId": r.OccurrenceID, "quarantinePath": quarantinePath, "receiptPath": filepath.Join(filepath.Dir(quarantinePath), "receipt.json"), "status": "contained", "hostClean": "false", "verification": "source-absent-and-evidence-hash-matched"}}
}

// Resume a durable receipt after a duplicate delivery or a process crash
// between the move and its final receipt update. This never removes a new file
// which has since appeared at the original path.
func (q *Quarantine) resume(event model.SecurityEvent, path string, parent int) (sensors.Observation, error) {
	dir := filepath.Join(q.StateDir, "quarantine", actionKey(event, path))
	fd, err := openDirectory(dir, false)
	if err != nil {
		return sensors.Observation{}, err
	}
	defer unix.Close(fd)
	if err := ownedPrivate(fd); err != nil {
		return sensors.Observation{}, err
	}
	n, err := unix.Openat(fd, "receipt.json", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return sensors.Observation{}, err
	}
	f := os.NewFile(uintptr(n), "receipt.json")
	b, err := io.ReadAll(io.LimitReader(f, 16385))
	f.Close()
	if err != nil {
		return sensors.Observation{}, err
	}
	if len(b) > 16384 {
		return sensors.Observation{}, errors.New("quarantine receipt exceeds limit")
	}
	var r receipt
	if err := json.Unmarshal(b, &r); err != nil {
		return sensors.Observation{}, err
	}
	if r.Path != path || r.SHA256 != event.Attributes["sha256"] || r.Signature != event.Attributes["signature"] || r.OccurrenceID != event.Attributes["occurrenceId"] || (r.Status != "quarantined" && r.Status != "prepared") {
		return sensors.Observation{}, errors.New("prior receipt does not match event")
	}
	n, err = unix.Openat(fd, "payload", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return sensors.Observation{}, err
	}
	payload := os.NewFile(uintptr(n), "payload")
	defer payload.Close()
	var st unix.Stat_t
	if err := unix.Fstat(n, &st); err != nil {
		return sensors.Observation{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Ino != r.Inode || uint64(st.Dev) != r.Device {
		return sensors.Observation{}, errors.New("prior quarantine payload identity mismatch")
	}
	content, err := readFile(payload)
	if err != nil {
		return sensors.Observation{}, err
	}
	if digest(content) != r.SHA256 {
		return sensors.Observation{}, errors.New("prior quarantine payload hash mismatch")
	}
	if err := unix.Fstatat(parent, filepath.Base(path), &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return sensors.Observation{}, errors.New("target path reappeared; prior receipt does not authorize removal")
	}
	if err := unix.Fchown(n, 0, 0); err != nil {
		return sensors.Observation{}, err
	}
	if err := unix.Fchmod(n, 0600); err != nil {
		return sensors.Observation{}, err
	}
	if err := payload.Sync(); err != nil {
		return sensors.Observation{}, err
	}
	if r.Status != "quarantined" {
		r.Status = "quarantined"
		if err := writeReceipt(fd, r); err != nil {
			return sensors.Observation{}, err
		}
	}
	return successObservation(path, filepath.Join(dir, "payload"), r), nil
}

// openDirectory walks every component without following symlinks. New state
// components are created owner-only, directly relative to the verified FD.
func openDirectory(path string, create bool) (int, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && create {
			if err = unix.Mkdirat(fd, part, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				unix.Close(fd)
				return -1, err
			}
			next, err = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("open directory component %s: %w", part, err)
		}
		fd = next
	}
	return fd, nil
}
func ownedPrivate(fd int) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Uid != 0 || st.Mode&0077 != 0 {
		return errors.New("quarantine directory must be root-owned and owner-only")
	}
	return nil
}
func readFile(f *os.File) ([]byte, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("quarantine file exceeds 1 MiB")
	}
	return b, nil
}
func digest(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func writeReceipt(fd int, r receipt) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := ".receipt-" + hex.EncodeToString(nonce[:])
	n, err := unix.Openat(fd, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(fd, temporary, 0)
	f := os.NewFile(uintptr(n), temporary)
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := unix.Renameat(fd, temporary, fd, "receipt.json"); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func (q *Quarantine) apply(ctx context.Context, event model.SecurityEvent, path string) (sensors.Observation, error) {
	if os.Geteuid() != 0 {
		return sensors.Observation{}, errors.New("quarantine requires the root service identity")
	}
	parent, err := openDirectory(filepath.Dir(path), false)
	if err != nil {
		return sensors.Observation{}, err
	}
	defer unix.Close(parent)
	leaf := filepath.Base(path)
	n, err := unix.Openat(parent, leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return q.resume(event, path, parent)
		}
		return sensors.Observation{}, err
	}
	f := os.NewFile(uintptr(n), path)
	defer f.Close()
	var original unix.Stat_t
	if err := unix.Fstat(n, &original); err != nil {
		return sensors.Observation{}, err
	}
	if original.Mode&unix.S_IFMT != unix.S_IFREG || original.Nlink != 1 {
		return sensors.Observation{}, errors.New("quarantine refuses nonregular or multiply linked files")
	}
	content, err := readFile(f)
	if err != nil {
		return sensors.Observation{}, err
	}
	signature, confidence := monitor.MatchWebshell(content)
	if digest(content) != event.Attributes["sha256"] || signature != event.Attributes["signature"] || confidence < .99 {
		return sensors.Observation{}, errors.New("quarantine evidence changed or no longer independently matches")
	}
	if expected := event.Attributes["occurrenceId"]; expected != "" {
		info, err := f.Stat()
		if err != nil {
			return sensors.Observation{}, err
		}
		if monitor.OccurrenceID(path, event.Attributes["sha256"], info) != expected {
			return sensors.Observation{}, errors.New("quarantine occurrence changed; delayed event cannot authorize a new file version")
		}
	}
	state, err := openDirectory(q.StateDir, true)
	if err != nil {
		return sensors.Observation{}, err
	}
	defer unix.Close(state)
	if err := ownedPrivate(state); err != nil {
		return sensors.Observation{}, err
	}
	if err := unix.Mkdirat(state, "quarantine", 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return sensors.Observation{}, err
	}
	quarantine, err := unix.Openat(state, "quarantine", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return sensors.Observation{}, err
	}
	defer unix.Close(quarantine)
	if err := ownedPrivate(quarantine); err != nil {
		return sensors.Observation{}, err
	}
	var qstat unix.Stat_t
	if err := unix.Fstat(quarantine, &qstat); err != nil {
		return sensors.Observation{}, err
	}
	if qstat.Dev != original.Dev {
		return sensors.Observation{}, errors.New("quarantine must be on the same filesystem as the webroot; target unchanged")
	}
	action := actionKey(event, path)
	if err := unix.Mkdirat(quarantine, action, 0700); err != nil {
		return sensors.Observation{}, err
	}
	actionFD, err := unix.Openat(quarantine, action, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return sensors.Observation{}, err
	}
	defer unix.Close(actionFD)
	r := receipt{Version: 1, Path: path, SHA256: event.Attributes["sha256"], Signature: signature, OccurrenceID: event.Attributes["occurrenceId"], EventID: event.ID, Status: "prepared", At: time.Now().UTC(), Device: uint64(original.Dev), Inode: original.Ino, OriginalMode: original.Mode, OriginalUID: original.Uid, OriginalGID: original.Gid}
	if err := writeReceipt(actionFD, r); err != nil {
		return sensors.Observation{}, err
	}
	if err := unix.Fsync(quarantine); err != nil {
		return sensors.Observation{}, err
	}
	var current unix.Stat_t
	if err := unix.Fstatat(parent, leaf, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return sensors.Observation{}, err
	}
	if current.Ino != original.Ino || current.Dev != original.Dev || current.Nlink != 1 {
		return sensors.Observation{}, errors.New("target changed before containment; target unchanged")
	}
	if expected := event.Attributes["occurrenceId"]; expected != "" {
		info, err := f.Stat()
		if err != nil {
			return sensors.Observation{}, err
		}
		if monitor.OccurrenceID(path, event.Attributes["sha256"], info) != expected {
			return sensors.Observation{}, errors.New("quarantine occurrence changed before move; target unchanged")
		}
	}
	if err := ctx.Err(); err != nil {
		return sensors.Observation{}, err
	}
	if q.beforeMove != nil {
		q.beforeMove()
	}
	if err := unix.Renameat2(parent, leaf, actionFD, "payload", unix.RENAME_NOREPLACE); err != nil {
		return sensors.Observation{}, fmt.Errorf("atomic quarantine move failed; target unchanged: %w", err)
	}
	quarantinePath := filepath.Join(q.StateDir, "quarantine", action, "payload")
	// Linux cannot atomically compare an inode and rename its pathname. Verify
	// the moved inode immediately, restoring without overwrite on any race.
	metadataModified := false
	failure := func(cause error) (sensors.Observation, error) {
		r.Status = "needs_review"
		if metadataModified {
			cause = errors.Join(cause, unix.Fchown(n, int(original.Uid), int(original.Gid)), unix.Fchmod(n, original.Mode&07777))
		}
		restoreErr := unix.Renameat2(actionFD, "payload", parent, leaf, unix.RENAME_NOREPLACE)
		if restoreErr == nil {
			r.Status = "restored_after_verification_failure"
		}
		receiptErr := writeReceipt(actionFD, r)
		return sensors.Observation{Kind: "remediation.quarantine_failed", Severity: model.SeverityCritical, Confidence: 1, DetectorIDs: []string{"fortmend:quarantine-verification"}, Attributes: map[string]string{"path": path, "quarantinePath": quarantinePath, "status": r.Status, "hostClean": "false"}}, errors.Join(cause, restoreErr, receiptErr)
	}
	var moved unix.Stat_t
	if err := unix.Fstatat(actionFD, "payload", &moved, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return failure(err)
	}
	if moved.Ino != original.Ino || moved.Dev != original.Dev || moved.Nlink != 1 {
		return failure(errors.New("moved target identity changed during containment"))
	}
	content, err = readFile(f)
	if err != nil {
		return failure(err)
	}
	if digest(content) != r.SHA256 {
		return failure(errors.New("moved payload digest changed during containment"))
	}
	if err := unix.Fstatat(parent, leaf, &current, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return failure(errors.New("webroot path still exists after containment"))
	}
	currentParent, err := openDirectory(filepath.Dir(path), false)
	if err != nil {
		return failure(fmt.Errorf("webroot parent path changed: %w", err))
	}
	var anchoredDir, pathnameDir unix.Stat_t
	parentErr := errors.Join(unix.Fstat(parent, &anchoredDir), unix.Fstat(currentParent, &pathnameDir))
	unix.Close(currentParent)
	if parentErr != nil {
		return failure(parentErr)
	}
	if anchoredDir.Ino != pathnameDir.Ino || anchoredDir.Dev != pathnameDir.Dev {
		return failure(errors.New("webroot parent directory was replaced during containment"))
	}
	metadataModified = true
	if err := unix.Fchown(n, 0, 0); err != nil {
		return failure(err)
	}
	if err := unix.Fchmod(n, 0600); err != nil {
		return failure(err)
	}
	if err := f.Sync(); err != nil {
		return failure(err)
	}
	if err := unix.Fsync(parent); err != nil {
		return failure(err)
	}
	r.Status = "quarantined"
	if err := writeReceipt(actionFD, r); err != nil {
		return failure(err)
	}
	return successObservation(path, quarantinePath, r), nil
}

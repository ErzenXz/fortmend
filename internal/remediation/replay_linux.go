//go:build linux

package remediation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/sensors"
	"golang.org/x/sys/unix"
)

type deliveryMarker struct {
	ReceiptSHA256 string    `json:"receiptSha256"`
	DeliveredAt   time.Time `json:"deliveredAt"`
}

func readPrivate(fd int, name string, limit int64) ([]byte, error) {
	n, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(n), name)
	defer f.Close()
	var before, after unix.Stat_t
	if err := unix.Fstat(n, &before); err != nil {
		return nil, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 || before.Uid != 0 || before.Mode&0077 != 0 {
		return nil, errors.New("quarantine metadata must be a private root-owned regular file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("quarantine metadata exceeds limit")
	}
	if err := unix.Fstat(n, &after); err != nil {
		return nil, err
	}
	if before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, errors.New("quarantine metadata changed during read")
	}
	return b, nil
}

func writeDelivery(fd int, hash string) error {
	b, err := json.Marshal(deliveryMarker{hash, time.Now().UTC()})
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	name := ".delivery-" + hex.EncodeToString(nonce[:])
	n, err := unix.Openat(fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(fd, name, 0)
	f := os.NewFile(uintptr(n), name)
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
	if err := unix.Renameat(fd, name, fd, "delivery.json"); err != nil {
		return err
	}
	return unix.Fsync(fd)
}

func (q *Quarantine) replay(ctx context.Context, emit func(sensors.Observation) error) error {
	if os.Geteuid() != 0 {
		return errors.New("quarantine replay requires root")
	}
	if !filepath.IsAbs(q.StateDir) || filepath.Clean(q.StateDir) != q.StateDir {
		return errors.New("quarantine replay requires a clean absolute state directory")
	}
	switch q.StateDir {
	case "/", "/etc", "/usr", "/var", "/tmp", "/home":
		return errors.New("quarantine replay refuses broad state directory")
	}
	state, err := openDirectory(q.StateDir, false)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(state)
	if err := ownedPrivate(state); err != nil {
		return err
	}
	fd, err := unix.Openat(state, "quarantine", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), "quarantine")
	defer dir.Close()
	if err := ownedPrivate(fd); err != nil {
		return err
	}
	count := 0
	var bytesRead int64
	for {
		entries, readErr := dir.ReadDir(64)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			count++
			if count > 4096 {
				return errors.New("quarantine receipt limit4096 exceeded; archive delivered evidence before continuing")
			}
			key := entry.Name()
			decoded, err := hex.DecodeString(key)
			if err != nil || len(decoded) != 32 || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return errors.New("unexpected non-action entry in quarantine directory")
			}
			action, err := unix.Openat(fd, key, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			err = q.replayAction(ctx, action, key, &bytesRead, emit)
			unix.Close(action)
			if err != nil {
				return fmt.Errorf("replay quarantine action %s: %w", key, err)
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

func (q *Quarantine) replayAction(ctx context.Context, fd int, key string, bytesRead *int64, emit func(sensors.Observation) error) error {
	if err := ownedPrivate(fd); err != nil {
		return err
	}
	data, err := readPrivate(fd, "receipt.json", 16<<10)
	if err != nil {
		return err
	}
	var r receipt
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	if r.Version != 1 {
		return errors.New("unknown quarantine receipt version")
	}
	event := model.SecurityEvent{ID: r.EventID, Kind: "webshell.suspicious", Confidence: .99, Attributes: map[string]string{"path": r.Path, "sha256": r.SHA256, "signature": r.Signature, "occurrenceId": r.OccurrenceID, "quarantineEligible": "true"}}
	if _, err := q.validate(event); err != nil {
		return err
	}
	if (r.EventID != "" || r.OccurrenceID != "") && actionKey(event, r.Path) != key {
		return errors.New("receipt action identity mismatch")
	}
	marker, err := readPrivate(fd, "delivery.json", 4096)
	if err == nil {
		var delivered deliveryMarker
		if err := json.Unmarshal(marker, &delivered); err != nil {
			return err
		}
		if delivered.ReceiptSHA256 == digest(data) {
			return nil
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	path := filepath.Join(q.StateDir, "quarantine", key, "payload")
	var observation sensors.Observation
	switch r.Status {
	case "quarantined", "prepared":
		n, err := unix.Openat(fd, "payload", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && r.Status == "prepared" {
			return nil
		}
		if err != nil {
			return err
		}
		payload := os.NewFile(uintptr(n), "payload")
		defer payload.Close()
		var st unix.Stat_t
		if err := unix.Fstat(n, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Ino != r.Inode || uint64(st.Dev) != r.Device {
			return errors.New("receipt payload identity mismatch")
		}
		*bytesRead += st.Size
		if *bytesRead > 32<<20 {
			return errors.New("quarantine replay exceeds32MiB per poll; remaining receipts will retry")
		}
		content, err := readFile(payload)
		if err != nil {
			return err
		}
		if digest(content) != r.SHA256 {
			return errors.New("receipt payload digest mismatch")
		}
		if err := unix.Fchown(n, 0, 0); err != nil {
			return err
		}
		if err := unix.Fchmod(n, 0600); err != nil {
			return err
		}
		if err := payload.Sync(); err != nil {
			return err
		}
		parent, err := openDirectory(filepath.Dir(r.Path), false)
		absent := errors.Is(err, unix.ENOENT)
		if err != nil && !absent {
			return err
		}
		if err == nil {
			var source unix.Stat_t
			statErr := unix.Fstatat(parent, filepath.Base(r.Path), &source, unix.AT_SYMLINK_NOFOLLOW)
			unix.Close(parent)
			absent = errors.Is(statErr, unix.ENOENT)
			if statErr != nil && !absent {
				return statErr
			}
		}
		if absent {
			if r.Status == "prepared" {
				r.Status = "quarantined"
				if err := writeReceipt(fd, r); err != nil {
					return err
				}
				data, err = readPrivate(fd, "receipt.json", 16<<10)
				if err != nil {
					return err
				}
			}
			observation = successObservation(r.Path, path, r)
		} else {
			observation = replayedFailure(r, path, "source_reappeared")
		}
	case "needs_review", "restored_after_verification_failure":
		observation = replayedFailure(r, path, r.Status)
	default:
		return errors.New("unknown quarantine receipt status")
	}
	observation.Attributes["replayed"] = "true"
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := emit(observation); err != nil {
		return err
	}
	return writeDelivery(fd, digest(data))
}

func replayedFailure(r receipt, path, status string) sensors.Observation {
	return sensors.Observation{Kind: "remediation.quarantine_failed", Severity: model.SeverityCritical, Confidence: 1, DetectorIDs: []string{"aegis:quarantine-receipt-recovery"}, Attributes: map[string]string{"path": r.Path, "sha256": r.SHA256, "signature": r.Signature, "occurrenceId": r.OccurrenceID, "quarantinePath": path, "status": status, "hostClean": "false"}}
}

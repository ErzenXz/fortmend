package protection

import (
	"context"
	"encoding/json"
	"github.com/ErzenXz/aegis/internal/sensors"
	"os"
	"path/filepath"
)

// A response receipt may outlive the detected file. Stage its normalized result
// before queue delivery so a full/offline queue cannot lose containment status.
func (r *Runtime) saveResponse(ctx context.Context, o sensors.Observation) error {
	r.responseMu.Lock()
	defer r.responseMu.Unlock()
	if err := r.flushResponseLocked(ctx); err != nil {
		return err
	}
	data, err := json.Marshal(o)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(r.StateDir, ".response-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(f.Name(), filepath.Join(r.StateDir, "response-outbox.json")); err != nil {
		return err
	}
	return r.flushResponseLocked(ctx)
}
func (r *Runtime) flushResponse(ctx context.Context) error {
	r.responseMu.Lock()
	defer r.responseMu.Unlock()
	return r.flushResponseLocked(ctx)
}
func (r *Runtime) flushResponseLocked(ctx context.Context) error {
	path := filepath.Join(r.StateDir, "response-outbox.json")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var o sensors.Observation
	if err := json.Unmarshal(data, &o); err != nil {
		return err
	}
	if err := r.emit(ctx, "quarantine", o); err != nil {
		return err
	}
	return os.Remove(path)
}

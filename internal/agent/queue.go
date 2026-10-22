package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/ErzenXz/aegis/internal/model"
)

type Queue struct {
	path     string
	maxBytes int64
	mu       sync.Mutex
	drainMu  sync.Mutex
	events   []model.SecurityEvent
	bytes    int64
}

func OpenQueue(path string, maxBytes int64) (*Queue, error) {
	if maxBytes <= 0 {
		return nil, fmt.Errorf("queue size must be positive")
	}
	queue := &Queue{path: path, maxBytes: maxBytes}
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return queue, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		var event model.SecurityEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("decode offline queue: %w", err)
		}
		queue.events = append(queue.events, event)
		encoded, err := json.Marshal(event)
		if err != nil {
			return nil, err
		}
		queue.bytes += int64(len(encoded) + 1)
	}
	return queue, scanner.Err()
}

func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.events)
}

func (q *Queue) Push(event model.SecurityEvent) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if q.bytes+int64(len(payload)) > q.maxBytes {
		return fmt.Errorf("offline queue capacity exhausted; event was not accepted")
	}
	// Appending one durable record avoids rewriting the entire backlog for every
	// CVE observation in a large inventory. Compaction happens during delivery.
	if err := os.MkdirAll(filepath.Dir(q.path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(q.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(payload); err == nil {
		err = f.Sync()
	}
	if err != nil {
		_ = f.Truncate(st.Size())
		_ = f.Sync()
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	q.events = append(q.events, event)
	q.bytes += int64(len(payload))
	return nil
}

func (q *Queue) Drain(ctx context.Context, send func(context.Context, model.SecurityEvent) error) error {
	q.drainMu.Lock()
	defer q.drainMu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q.mu.Lock()
		if len(q.events) == 0 {
			q.mu.Unlock()
			return nil
		}
		event := q.events[0]
		q.mu.Unlock()
		// Network delivery must never hold the collection lock.
		if err := send(ctx, event); err != nil {
			return err
		}
		q.mu.Lock()
		previous := q.events
		previousBytes := q.bytes
		q.events = q.events[1:]
		payload, _ := json.Marshal(event)
		q.bytes -= int64(len(payload) + 1)
		if err := q.persist(); err != nil {
			q.events = previous
			q.bytes = previousBytes
			q.mu.Unlock()
			return err
		}
		q.mu.Unlock()
	}
}

func (q *Queue) persist() error {
	if err := os.MkdirAll(filepath.Dir(q.path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(q.path), ".aegis-events-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	encoder := json.NewEncoder(temporary)
	for _, event := range q.events {
		if err := encoder.Encode(event); err != nil {
			temporary.Close()
			return err
		}
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, q.path)
}

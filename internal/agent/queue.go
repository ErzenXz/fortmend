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
	events   []model.SecurityEvent
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
	q.events = append(q.events, event)
	for q.encodedSize() > q.maxBytes && len(q.events) > 1 {
		q.events = q.events[1:]
	}
	if q.encodedSize() > q.maxBytes {
		q.events = q.events[:0]
		return fmt.Errorf("event exceeds offline queue capacity")
	}
	return q.persist()
}

func (q *Queue) Drain(ctx context.Context, send func(context.Context, model.SecurityEvent) error) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	for len(q.events) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := send(ctx, q.events[0]); err != nil {
			return err
		}
		q.events = q.events[1:]
		if err := q.persist(); err != nil {
			return err
		}
	}
	return nil
}

func (q *Queue) encodedSize() int64 {
	var size int64
	for _, event := range q.events {
		payload, _ := json.Marshal(event)
		size += int64(len(payload) + 1)
	}
	return size
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

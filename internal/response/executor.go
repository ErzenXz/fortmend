package response

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/ErzenXz/fortmend/internal/model"
)

const (
	minimumObservation = 24 * time.Hour
	minimumConfidence  = 0.95
)

type Adapter interface {
	Apply(context.Context, model.ActionSpec) (model.RollbackPlan, error)
	Rollback(context.Context, model.RollbackPlan) error
}

type HealthVerifier interface {
	Verify(context.Context, model.ActionSpec) error
}

type Option func(*Executor)

func WithHealthVerifier(verifier HealthVerifier) Option {
	return func(executor *Executor) { executor.verifier = verifier }
}

type StaticReadiness struct {
	EnrolledAt       time.Time
	TelemetryHealthy bool
	RecoveryByAction map[model.ActionKind]bool
}

type Executor struct {
	adapter   Adapter
	verifier  HealthVerifier
	readiness StaticReadiness
	mu        sync.Mutex
	receipts  map[string]model.ActionReceipt
}

func NewExecutor(adapter Adapter, readiness StaticReadiness, options ...Option) *Executor {
	executor := &Executor{adapter: adapter, readiness: readiness, receipts: make(map[string]model.ActionReceipt)}
	for _, option := range options {
		option(executor)
	}
	return executor
}

// Execute is the privileged response module's only interface. Policy
// admission happens before the adapter can observe an action.
func (e *Executor) Execute(ctx context.Context, request model.ResponseRequest) model.ActionReceipt {
	e.mu.Lock()
	defer e.mu.Unlock()
	if previous, ok := e.receipts[request.Action.IdempotencyKey]; ok {
		return previous
	}
	receipt := model.ActionReceipt{
		SchemaVersion:  model.SchemaVersion,
		DeviceID:       request.DeviceID,
		IdempotencyKey: request.Action.IdempotencyKey,
		Status:         model.ActionRejected,
	}
	reject := func(reason string) model.ActionReceipt {
		receipt.Reason = reason
		if request.Action.IdempotencyKey != "" {
			e.receipts[request.Action.IdempotencyKey] = receipt
		}
		return receipt
	}
	if request.Action.IdempotencyKey == "" {
		return reject("idempotency key required")
	}
	if !request.Finding.Deterministic {
		return reject("deterministic evidence required")
	}
	if request.Finding.Confidence < minimumConfidence {
		return reject("confidence below 0.95")
	}
	if time.Since(e.readiness.EnrolledAt) < minimumObservation {
		return reject("24 hour observation period not complete")
	}
	if !e.readiness.TelemetryHealthy {
		return reject("telemetry health check failed")
	}
	if !e.readiness.RecoveryByAction[request.Action.Kind] {
		return reject("recovery capability not verified")
	}
	rollback, err := e.adapter.Apply(ctx, request.Action)
	if err != nil {
		receipt.Status = model.ActionFailed
		receipt.Reason = fmt.Sprintf("apply failed: %v", err)
		e.receipts[request.Action.IdempotencyKey] = receipt
		return receipt
	}
	receipt.Status = model.ActionApplied
	receipt.AppliedAt = time.Now().UTC()
	receipt.Rollback = &rollback
	if e.verifier != nil {
		if err := e.verifier.Verify(ctx, request.Action); err != nil {
			receipt.Reason = fmt.Sprintf("post-action health check failed: %v", err)
			if rollbackErr := e.adapter.Rollback(ctx, rollback); rollbackErr != nil {
				receipt.Status = model.ActionFailed
				receipt.Reason += fmt.Sprintf("; rollback failed: %v", rollbackErr)
			} else {
				receipt.Status = model.ActionRolledBack
			}
		}
	}
	e.receipts[request.Action.IdempotencyKey] = receipt
	return receipt
}

package response_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/response"
)

type recordingAdapter struct {
	applied    int
	rolledBack int
}

func (a *recordingAdapter) Apply(context.Context, model.ActionSpec) (model.RollbackPlan, error) {
	a.applied++
	return model.RollbackPlan{Kind: "noop"}, nil
}

func (a *recordingAdapter) Rollback(context.Context, model.RollbackPlan) error {
	a.rolledBack++
	return nil
}

type unhealthyVerifier struct{}

func (unhealthyVerifier) Verify(context.Context, model.ActionSpec) error {
	return errors.New("management channel unavailable")
}

func TestAIOnlyProposalCannotAuthorizePrivilegedAction(t *testing.T) {
	adapter := &recordingAdapter{}
	executor := response.NewExecutor(adapter, response.StaticReadiness{
		EnrolledAt:       time.Now().Add(-48 * time.Hour),
		TelemetryHealthy: true,
		RecoveryByAction: map[model.ActionKind]bool{model.ActionKillProcess: true},
	})

	receipt := executor.Execute(context.Background(), model.ResponseRequest{
		DeviceID: "device-1",
		Finding: model.Finding{
			ID:            "finding-1",
			Confidence:    1,
			Deterministic: false,
		},
		Action: model.ActionSpec{
			Kind:           model.ActionKillProcess,
			IdempotencyKey: "case-1:kill:42",
			Parameters:     map[string]string{"pid": "42"},
		},
	})

	if receipt.Status != model.ActionRejected || receipt.Reason != "deterministic evidence required" {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
	if adapter.applied != 0 {
		t.Fatal("rejected action reached privileged adapter")
	}
}

func TestFailedPostActionHealthCheckRollsBackAndRemainsIdempotent(t *testing.T) {
	adapter := &recordingAdapter{}
	executor := response.NewExecutor(adapter, response.StaticReadiness{
		EnrolledAt:       time.Now().Add(-48 * time.Hour),
		TelemetryHealthy: true,
		RecoveryByAction: map[model.ActionKind]bool{model.ActionIsolateHost: true},
	}, response.WithHealthVerifier(unhealthyVerifier{}))
	request := model.ResponseRequest{
		DeviceID: "device-1",
		Finding:  model.Finding{ID: "finding-1", Confidence: 0.99, Deterministic: true},
		Action:   model.ActionSpec{Kind: model.ActionIsolateHost, IdempotencyKey: "case-1:isolate"},
	}

	first := executor.Execute(context.Background(), request)
	second := executor.Execute(context.Background(), request)
	if first.Status != model.ActionRolledBack || first.Reason != "post-action health check failed: management channel unavailable" {
		t.Fatalf("unexpected first receipt: %#v", first)
	}
	if second.Status != first.Status || adapter.applied != 1 || adapter.rolledBack != 1 {
		t.Fatalf("idempotency failed: second=%#v applied=%d rolledBack=%d", second, adapter.applied, adapter.rolledBack)
	}
}

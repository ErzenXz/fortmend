package model

import "time"

const SchemaVersion = "fortmend.security/v1alpha1"

// SupportsSchema keeps previously persisted and enrolled preview data readable.
// Newly produced records always use SchemaVersion.
func SupportsSchema(version string) bool {
	return version == SchemaVersion || version == "aegis.security/v1alpha1"
}

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

type SecurityEvent struct {
	SchemaVersion string            `json:"schemaVersion"`
	ID            string            `json:"id"`
	DeviceID      string            `json:"deviceId"`
	ObservedAt    time.Time         `json:"observedAt"`
	Source        string            `json:"source"`
	Kind          string            `json:"kind"`
	Severity      Severity          `json:"severity"`
	Confidence    float64           `json:"confidence"`
	DetectorIDs   []string          `json:"detectorIds,omitempty"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

type Finding struct {
	SchemaVersion string    `json:"schemaVersion"`
	ID            string    `json:"id"`
	DeviceID      string    `json:"deviceId"`
	CreatedAt     time.Time `json:"createdAt"`
	Title         string    `json:"title"`
	Severity      Severity  `json:"severity"`
	Confidence    float64   `json:"confidence"`
	Deterministic bool      `json:"deterministic"`
	DetectorIDs   []string  `json:"detectorIds"`
	EventIDs      []string  `json:"eventIds"`
}

type ActionKind string

const (
	ActionKillProcess        ActionKind = "process.kill"
	ActionQuarantineFile     ActionKind = "file.quarantine"
	ActionDisablePersistence ActionKind = "persistence.disable"
	ActionBlockIndicator     ActionKind = "network.block_indicator"
	ActionIsolateHost        ActionKind = "network.isolate_host"
	ActionApplySecurityFix   ActionKind = "system.apply_security_update"
	ActionRotateCredential   ActionKind = "fortmend.rotate_credential"
	ActionDisableAccount     ActionKind = "account.disable_incident_created"
)

type ActionSpec struct {
	Kind           ActionKind        `json:"kind"`
	IdempotencyKey string            `json:"idempotencyKey"`
	LeaseSeconds   int               `json:"leaseSeconds,omitempty"`
	Parameters     map[string]string `json:"parameters,omitempty"`
}

type ResponseRequest struct {
	DeviceID string     `json:"deviceId"`
	Finding  Finding    `json:"finding"`
	Action   ActionSpec `json:"action"`
}

type RollbackPlan struct {
	Kind       string            `json:"kind"`
	Parameters map[string]string `json:"parameters,omitempty"`
}

type ActionStatus string

const (
	ActionRejected   ActionStatus = "rejected"
	ActionApplied    ActionStatus = "applied"
	ActionRolledBack ActionStatus = "rolled_back"
	ActionFailed     ActionStatus = "failed"
)

type ActionReceipt struct {
	SchemaVersion  string        `json:"schemaVersion"`
	DeviceID       string        `json:"deviceId"`
	IdempotencyKey string        `json:"idempotencyKey"`
	Status         ActionStatus  `json:"status"`
	Reason         string        `json:"reason,omitempty"`
	AppliedAt      time.Time     `json:"appliedAt,omitempty"`
	Rollback       *RollbackPlan `json:"rollback,omitempty"`
}

type AuditRecord struct {
	Sequence     int64     `json:"sequence"`
	RecordedAt   time.Time `json:"recordedAt"`
	Kind         string    `json:"kind"`
	ObjectID     string    `json:"objectId"`
	PreviousHash string    `json:"previousHash,omitempty"`
	Hash         string    `json:"hash"`
}

type Evidence struct {
	Kind        string            `json:"kind"`
	CollectedAt time.Time         `json:"collectedAt"`
	Summary     string            `json:"summary"`
	Attributes  map[string]string `json:"attributes,omitempty"`
	SHA256      string            `json:"sha256,omitempty"`
	Redacted    bool              `json:"redacted"`
}

type IncidentCase struct {
	SchemaVersion string     `json:"schemaVersion"`
	ID            string     `json:"id"`
	DeviceID      string     `json:"deviceId"`
	FindingIDs    []string   `json:"findingIds"`
	Evidence      []Evidence `json:"evidence"`
}

type CapabilityReport struct {
	SchemaVersion string            `json:"schemaVersion"`
	DeviceID      string            `json:"deviceId"`
	ObservedAt    time.Time         `json:"observedAt"`
	Platform      string            `json:"platform"`
	Capabilities  map[string]bool   `json:"capabilities"`
	Details       map[string]string `json:"details,omitempty"`
}

type ResponseProposal struct {
	SchemaVersion string       `json:"schemaVersion"`
	CaseID        string       `json:"caseId"`
	Summary       string       `json:"summary"`
	Actions       []ActionSpec `json:"actions"`
	Citations     []string     `json:"citations,omitempty"`
}

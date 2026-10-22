package model_test

import (
	"testing"

	"github.com/ErzenXz/fortmend/internal/model"
)

func TestLegacyAndCurrentEventSchemasRemainExplicit(t *testing.T) {
	for _, schema := range []string{"aegis.security/v1alpha1", "fortmend.security/v1alpha1"} {
		if !model.SupportsSchema(schema) {
			t.Errorf("rejected supported schema %q", schema)
		}
	}
	for _, schema := range []string{"", "aegis.security/v2", "fortmend.security/v2", "fortmend.update/v1alpha1"} {
		if model.SupportsSchema(schema) {
			t.Errorf("accepted unsupported schema %q", schema)
		}
	}
	if model.SchemaVersion != "fortmend.security/v1alpha1" {
		t.Fatalf("new event schema still uses legacy branding: %q", model.SchemaVersion)
	}
}

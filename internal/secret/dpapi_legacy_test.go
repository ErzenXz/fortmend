//go:build windows

package secret_test

import (
	"bytes"
	"testing"

	"github.com/ErzenXz/fortmend/internal/secret"
)

func TestLegacyDPAPIEnvelopeStillRequiresProtectedCiphertext(t *testing.T) {
	plaintext := []byte("disposable-test-device-key")
	sealed, err := secret.Seal(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	currentPrefix := []byte("fortmend-dpapi-v1\n")
	if !bytes.HasPrefix(sealed, currentPrefix) {
		t.Fatal("newly sealed secret does not use the Fortmend envelope")
	}
	legacyPrefix := []byte("aegis-dpapi-v1\n")
	legacy := append(append([]byte(nil), legacyPrefix...), sealed[len(currentPrefix):]...)
	opened, err := secret.Open(legacy)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("legacy envelope did not decrypt: %v", err)
	}
	for _, invalid := range [][]byte{legacyPrefix, append(append([]byte(nil), legacyPrefix...), plaintext...), append([]byte("unrecognized-v1\n"), sealed[len(currentPrefix):]...)} {
		if _, err := secret.Open(invalid); err == nil {
			t.Fatal("accepted an empty, plaintext, or unrecognized envelope")
		}
	}
	legacy[len(legacy)-1] ^= 0xff
	if _, err := secret.Open(legacy); err == nil {
		t.Fatal("accepted tampered DPAPI ciphertext")
	}
}

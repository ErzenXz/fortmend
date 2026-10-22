//go:build windows

package secret

import (
	"bytes"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var dpapiHeader = []byte("fortmend-dpapi-v1\n")

func Seal(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("cannot seal empty secret")
	}
	input := windows.DataBlob{Size: uint32(len(plaintext)), Data: &plaintext[0]}
	var output windows.DataBlob
	if err := windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, fmt.Errorf("DPAPI protect: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	ciphertext := append([]byte(nil), unsafe.Slice(output.Data, output.Size)...)
	return append(append([]byte(nil), dpapiHeader...), ciphertext...), nil
}

func Open(sealed []byte) ([]byte, error) {
	header := dpapiHeader
	if bytes.HasPrefix(sealed, []byte("aegis-dpapi-v1\n")) {
		header = []byte("aegis-dpapi-v1\n")
	}
	if !bytes.HasPrefix(sealed, header) || len(sealed) == len(header) {
		return nil, fmt.Errorf("secret is not protected by Fortmend DPAPI storage")
	}
	ciphertext := sealed[len(header):]
	input := windows.DataBlob{Size: uint32(len(ciphertext)), Data: &ciphertext[0]}
	var output windows.DataBlob
	if err := windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output); err != nil {
		return nil, fmt.Errorf("DPAPI unprotect: %w", err)
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(output.Data)))
	return append([]byte(nil), unsafe.Slice(output.Data, output.Size)...), nil
}

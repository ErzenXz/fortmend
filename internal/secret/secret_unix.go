//go:build !windows

package secret

func Seal(plaintext []byte) ([]byte, error) {
	return append([]byte(nil), plaintext...), nil
}

func Open(sealed []byte) ([]byte, error) {
	return append([]byte(nil), sealed...), nil
}

package monitor

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

// OccurrenceID identifies this version of an opened file independently of
// delivery retries. Linux includes inode/device and ctime, so recreated or
// rewritten identical content is a distinct occurrence even with restored mtime.
func OccurrenceID(path, digest string, info os.FileInfo) string {
	identity := fmt.Sprintf("%s\x00%s\x00%d\x00%d\x00%s", path, digest, info.Size(), info.ModTime().UnixNano(), fileIdentity(info))
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])
}

package awsctx

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// NewTraceID creates an X-Ray root identifier using the owning service's clock.
func NewTraceID(now time.Time) string {
	var random [12]byte
	_, _ = rand.Read(random[:])
	return fmt.Sprintf("1-%08x-%s", uint32(now.Unix()), hex.EncodeToString(random[:]))
}

package sdk

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Key returns a finding key for an automated finding: the first 16 hex
// characters of SHA-256 over parts joined with NUL bytes. rpt add --upsert
// matches keys, so the same check on the same scope must give the same key
// on every run. Recommended parts: the check or knowledge-base entry ID,
// then the finding's scope IDs sorted, so a finding keys the same whatever
// order its scope IDs come in. rpt itself never calls Key; it only compares
// the keys plugins set.
func Key(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(sum[:8])
}

package eventbridge

import (
	"regexp"
	"slices"
	"strings"
	"time"

	"stackd/internal/awsctx"
)

var traceRootPattern = regexp.MustCompile(`^1-[0-9a-fA-F]{8}-[0-9a-fA-F]{24}$`)
var traceParentPattern = regexp.MustCompile(`^[0-9a-fA-F]{16}$`)

// eventTraceHeader selects before parsing: an invalid entry header suppresses a
// valid HTTP header. X-Ray metadata is independent of event size, matching and
// customer JSON. Native normalization is captured in testdata/aws/eventbridge/trace.json.
func eventTraceHeader(entry string, present bool, transport string, now time.Time) string {
	header := transport
	if present {
		header = entry
	}
	if header == "" {
		return ""
	}
	var root, parent, sampled string
	var extra map[string]string
	for part := range strings.SplitSeq(header, ";") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		switch key {
		case "Root":
			root = ""
			if traceRootPattern.MatchString(value) {
				root = strings.ToLower(value)
			}
		case "Parent":
			// An invalid duplicate does not replace the last valid parent.
			if traceParentPattern.MatchString(value) {
				parent = value
			}
		case "Sampled":
			sampled = ""
			if value == "0" || value == "1" || value == "?" {
				sampled = value
			}
		default:
			if extra == nil {
				extra = make(map[string]string)
			}
			extra[key] = value
		}
	}
	// Native unsampled headers acquire a root even if it was absent/invalid.
	// Sampled and deferred headers without a valid root are instead discarded.
	if root == "" {
		if sampled != "0" {
			return ""
		}
		root = awsctx.NewTraceID(now)
	}
	// X-Ray's sampled-parent admission is stricter than its unsampled parser.
	if sampled == "1" && parent != strings.ToLower(parent) {
		return ""
	}
	var out strings.Builder
	out.Grow(len(header))
	out.WriteString("Root=")
	out.WriteString(root)
	if parent != "" {
		out.WriteString(";Parent=")
		out.WriteString(parent)
	}
	if sampled != "" {
		out.WriteString(";Sampled=")
		out.WriteString(sampled)
	}
	keys := make([]string, 0, len(extra))
	for key := range extra {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		out.WriteByte(';')
		out.WriteString(key)
		out.WriteByte('=')
		out.WriteString(extra[key])
	}
	return out.String()
}

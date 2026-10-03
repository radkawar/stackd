package sns

import (
	"regexp"
	"strings"
)

var traceRootPattern = regexp.MustCompile(`^1-[0-9a-fA-F]{8}-[0-9a-fA-F]{24}$`)
var traceParentPattern = regexp.MustCompile(`^[0-9a-fA-F]{16}$`)

// passThroughTraceHeader follows SNS transport admission, not EventBridge's
// TraceHeader field. Native SNS strips whitespace/extensions and uses the last
// repeated field. Malformed tracing never rejects an otherwise valid message.
func passThroughTraceHeader(header string) string {
	var root, parent, sampled string
	for field := range strings.SplitSeq(header, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok {
			continue
		}
		switch name {
		case "Root":
			root = value
		case "Parent":
			parent = value
		case "Sampled":
			sampled = value
		}
	}
	if !traceRootPattern.MatchString(root) || !traceParentPattern.MatchString(parent) || sampled != "0" && sampled != "1" {
		return ""
	}
	return "Root=" + root + ";Parent=" + parent + ";Sampled=" + sampled
}

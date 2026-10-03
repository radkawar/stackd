package awsapi

import (
	"testing"
)

func TestModeledPatternDialect(t *testing.T) {
	// CloudTrail PartitionKeyName/PartitionKeyType publish this scalar range
	// with a UTF-16 pair at each supplementary-plane endpoint.
	const scalarRange = `^[\u0020-\uD7FF\uE000-\uFFFD\uD800\uDC00-\uDBFF\uDFFF\t]*$`
	for _, tt := range []struct {
		pattern, value string
		want           bool
	}{
		{`^[a-z0-9]([a-z0-9]|-(?!-)){1,61}[a-z0-9]$`, "my-account", true},
		{`^[a-z0-9]([a-z0-9]|-(?!-)){1,61}[a-z0-9]$`, "my--account", false},
		{`^[\u0009\u000A\u000D\u0020-\u007E\u00A1-\u00FF]+$`, "hello\nworld", true},
		{`^[\p{L}\p{Z}\p{N}_.:/=+\-@]*$`, "équipe:日本", true},
		{`^[\u10000-\u10FFFF]+$`, "𐀀", true},
		{`^[\u10000-\u10FFFF]+$`, "a", false},
		{scalarRange, "\U00010000", true},
		{scalarRange, "😀", true},
		{scalarRange, "\U0010FFFF", true},
		{scalarRange, "\uD7FF\uE000\uFFFD", true},
		{scalarRange, "\uFFFE", false},
		{scalarRange, " \t", true},
		{scalarRange, "\x00", false},
		{scalarRange, "\x1f", false},
		{scalarRange, "a\nb", false},
		{`^\uD83D\uDE00+$`, "😀😀", true},
		{`^\ud83d\ude00$`, "😀", true},
		{`^\\uD83D\\uDE00$`, `\uD83D\uDE00`, true},
		{`^\\uD83D\\uDE00$`, "😀", false},
		{`^\\\uD83D\uDE00$`, `\😀`, true},
		{`^\\u0041$`, `\u0041`, true},
		{`^\\u0041$`, "A", false},
		{`^\u{1F600}$`, "😀", true},
		{`^\p{Print}+$`, "stackd-aas-missing !~", true},
		{`^\p{Print}+$`, "a\tb", false},
		{`^\p{Print}+$`, "\x7f", false},
		{`^\p{Print}+$`, "é", false},
		{`^[\p{Print}\t]+$`, " \t~", true},
		{`^[^\p{Print}]+$`, "\x1f\x7fé", true},
		{`^[^\p{Print}]+$`, " ", false},
		{`^\P{Print}+$`, "\x1f\x7f😀", true},
		{`^[\P{Print}]+$`, "~", false},
		{`^\[\p{Print}\]$`, "[a]", true},
		{`^\\p\{Print\}$`, `\p{Print}`, true},
		{`^\p{ASCII}+$`, "\x00A\x7f", true},
		{`^\p{ASCII}+$`, "é", false},
		{`^[\p{ASCII}]+$`, "\t\nA", true},
		{`^[^\p{ASCII}]+$`, "é😀", true},
		{`^\P{ASCII}+$`, "A", false},
		{`^\\p\{ASCII\}$`, `\p{ASCII}`, true},
	} {
		got, err := matchPattern(tt.pattern, tt.value)
		if err != nil || got != tt.want {
			t.Errorf("matchPattern(%q,%q)=(%v,%v), want %v", tt.pattern, tt.value, got, err, tt.want)
		}
	}
}

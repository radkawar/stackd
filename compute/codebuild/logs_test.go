package codebuild

import "testing"

func TestLogsDoNotLeakSecretAcrossPollingBoundaries(t *testing.T) {
	secret := "sensitive-value"
	first, consumed := redactLogs([]byte("before sensitive-"), []string{secret}, true)
	if string(first) != "before " || consumed != 7 {
		t.Fatalf("published partial secret: %q, consumed %d", first, consumed)
	}
	second, consumed := redactLogs([]byte("sensitive-value after\n"), []string{secret}, true)
	if string(second) != "*** after\n" || consumed != 22 {
		t.Fatalf("incorrect resumed secret masking: %q, consumed %d", second, consumed)
	}
}
func TestLogsHoldOverlappingSecretBeforeAdvancingOffset(t *testing.T) {
	data, consumed := redactLogs([]byte("prefix abcd"), []string{"abcd", "cde"}, true)
	if string(data) != "prefix " || consumed != 7 {
		t.Fatalf("split overlapping secret: %q, consumed %d", data, consumed)
	}
	final, consumed := redactLogs([]byte("abcd"), []string{"abcd", "cde"}, false)
	if string(final) != "***" || consumed != 4 {
		t.Fatalf("incorrect final masking: %q, consumed %d", final, consumed)
	}
}
func TestLogsFlushNonsecretPrefixWhenProcessExits(t *testing.T) {
	output, consumed := redactLogs([]byte("value=sens"), []string{"sensitive"}, false)
	if string(output) != "value=sens" || consumed != 10 {
		t.Fatalf("discarded final nonsecret bytes: %q, consumed %d", output, consumed)
	}
}

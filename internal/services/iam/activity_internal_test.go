package iam

import "testing"

func TestActivityCredentialARNDoesNotAllocate(t *testing.T) {
	scope := Scope{Partition: "aws", AccountID: "123456789012"}
	for _, test := range []struct {
		name string
		arn  string
		want string
	}{
		{"user", "arn:aws:iam::123456789012:user/path/original", "arn:aws:iam::123456789012:user/"},
		{"renamed user", "arn:aws:iam::123456789012:user/new-path/renamed", "arn:aws:iam::123456789012:user/"},
		{"role", "arn:aws:iam::123456789012:role/report-reader", "arn:aws:iam::123456789012:role/report-reader"},
		{"role path containing user", "arn:aws:iam::123456789012:role/path:user/name", "arn:aws:iam::123456789012:role/path:user/name"},
		{"session", "arn:aws:sts::123456789012:assumed-role/report-reader/example-session", "arn:aws:sts::123456789012:assumed-role/report-reader/example-session"},
		{"foreign account", "arn:aws:iam::999999999999:user/name", "arn:aws:iam::999999999999:user/name"},
		{"foreign partition", "arn:aws-cn:iam::123456789012:user/name", "arn:aws-cn:iam::123456789012:user/name"},
		{"absent issuer", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			var got string
			allocations := testing.AllocsPerRun(100, func() { got = activityCredentialARN(scope, test.arn) })
			if got != test.want || allocations != 0 {
				t.Fatalf("normalization = %q (%g allocations), want %q without allocations", got, allocations, test.want)
			}
		})
	}
}

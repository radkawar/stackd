package iam

import "testing"

func TestTOTPMatchesRFC6238SHA1Vectors(t *testing.T) {
	for _, tc := range []struct {
		seconds int64
		want    string
	}{{59, "287082"}, {1111111109, "081804"}, {1111111111, "050471"}, {1234567890, "005924"}, {2000000000, "279037"}, {20000000000, "353130"}} {
		if got := totp([]byte("12345678901234567890"), tc.seconds/30); got != tc.want {
			t.Fatalf("time=%d code=%s want=%s", tc.seconds, got, tc.want)
		}
	}
}

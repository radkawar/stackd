package gateway

import "testing"

func TestRemoteIP(t *testing.T) {
	for _, tc := range []struct{ peer, want string }{
		{"192.0.2.1:12345", "192.0.2.1"},
		{"[2001:db8::1]:12345", "2001:db8::1"},
		{"[::ffff:192.0.2.1]:12345", "192.0.2.1"},
		{"[fe80::1%eth0]:12345", "fe80::1"},
		{"", ""},
		{"unix-socket", ""},
		{"example.com:12345", ""},
	} {
		t.Run(tc.peer, func(t *testing.T) {
			if got := remoteIP(tc.peer); got != tc.want {
				t.Fatalf("remoteIP(%q) = %q; want %q", tc.peer, got, tc.want)
			}
		})
	}
}

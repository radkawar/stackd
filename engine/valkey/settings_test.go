package valkey

import (
	"strings"
	"testing"
)

func TestAccessStringsCannotOverrideCredentialAuthority(t *testing.T) {
	for _, access := range []string{"on ~* +@all nopass", "on ~* +@all >replacement", "on ~* +@all #" + strings.Repeat("a", 64), "on ~* +@all\nuser default on nopass +@all"} {
		if err := ValidateUsers([]User{{Name: "reader", AccessString: access, PasswordHashes: []string{strings.Repeat("b", 64)}}}); err == nil {
			t.Fatalf("credential override was admitted: %q", access)
		}
	}
	for _, users := range [][]User{{{Name: controllerUser, AccessString: "on ~* +@all", NoPassword: true}}, {{Name: "reader", AccessString: "on ~* +@read", NoPassword: true}, {Name: "reader", AccessString: "on ~* +@all", NoPassword: true}}} {
		if err := ValidateUsers(users); err == nil {
			t.Fatal("reserved/duplicate ACL authority was admitted")
		}
	}
}
func TestParametersCannotDisableDurabilityOrAuthentication(t *testing.T) {
	for _, name := range []string{"appendonly", "appendfsync", "requirepass", "aclfile", "bind", "port", "dir", "dbfilename", "protected-mode"} {
		if err := ValidateParameters(map[string]string{name: "no"}); err == nil {
			t.Fatalf("unsafe parameter %s was admitted", name)
		}
	}
}

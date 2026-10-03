package mq

import (
	service "stackd/internal/services/mq"
	"strings"
	"testing"
)

func TestPendingUsersDoNotChangeEffectiveAuthentication(t *testing.T) {
	broker := service.BrokerRecord{Users: []service.UserRecord{
		{Username: "current", Password: "current-password-123", ConsoleAccess: true, PendingChange: "UPDATE", PendingPassword: "pending-password-456", PendingConsoleAccess: false},
		{Username: "new-user", PendingChange: "CREATE", PendingPassword: "new-password-789", PendingConsoleAccess: true},
		{Username: "deleting", Password: "deleting-password-123", ConsoleAccess: true, PendingChange: "DELETE"},
		{Username: "granting", Password: "granting-password-123", PendingChange: "UPDATE", PendingConsoleAccess: true},
	}}
	users, err := effectiveActiveMQUsers(broker, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 3 || users[0].Username != "current" || users[0].Password != "current-password-123" || users[1].Username != "deleting" {
		t.Fatal("pending metadata changed effective native authentication")
	}
	realm := string(activeMQConsoleRealm(users))
	if !strings.Contains(realm, "current: ") || !strings.Contains(realm, "deleting: ") || strings.Contains(realm, "new-user: ") || strings.Contains(realm, "granting: ") {
		t.Fatal("pending metadata changed effective console authority")
	}
	if !strings.Contains(realm, jettyPassword("current-password-123")) || strings.Contains(realm, jettyPassword("pending-password-456")) {
		t.Fatal("pending password changed console authentication")
	}
	broker.Users = []service.UserRecord{}
	broker.Username, broker.Password = "legacy", "legacy-password-123"
	users, err = effectiveActiveMQUsers(broker, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 0 {
		t.Fatal("explicit deny-all resurrected legacy credentials")
	}
	if len(activeMQConsoleRealm(users)) != 0 {
		t.Fatal("explicit deny-all retained a console login")
	}
}

func TestConsolePasswordMatchesInstalledJettyEncoding(t *testing.T) {
	// Vector produced by the pinned image's native Password utility. Includes
	// leading/trailing spaces, a property escape, punctuation and UTF-8.
	password := "  abc\\def#é雪!?  "
	want := "OBF:11tr11tr1ktd1f40U0joqU0iajU0jxlU0k2xU0kar130fU12liU0xglU1a3oU0uosU0xnn1f0e1krh11tr11tr"
	if got := jettyPassword(password); got != want {
		t.Fatalf("credential cannot round-trip through native Jetty: %q", got)
	}
}

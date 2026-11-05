package glue

import (
	"errors"
	"testing"

	"stackd/internal/awswire"
	"stackd/internal/services/glue/icebergmeta"
)

func TestFederatedRESTTypedErrorsPreserveSuccessfulNil(t *testing.T) {
	var successful *awswire.Error
	if err := federatedNamespaceError(successful); err != nil {
		t.Fatalf("successful namespace command became an error interface: %#v", err)
	}
	if err := federationError(successful); err != nil {
		t.Fatalf("successful table command became an error interface: %#v", err)
	}
	for _, test := range []struct {
		code, kind string
		status     int
	}{
		{"EntityNotFoundException", "NoSuchNamespaceException", 404},
		{"ConcurrentModificationException", "NamespaceNotEmptyException", 409},
	} {
		err := federatedNamespaceError(&awswire.Error{Code: test.code, Message: "actual owner failure", StatusCode: test.status})
		var native *icebergmeta.Error
		if !errors.As(err, &native) || native.Type != test.kind || native.Code != test.status {
			t.Fatalf("namespace failure %s was lost: %v", test.code, err)
		}
	}
	denied := &awswire.Error{Code: "AccessDeniedException", Message: "current IAM denial", StatusCode: 403}
	if err := federatedNamespaceError(denied); err != denied {
		t.Fatalf("actual authorization error was changed: %v", err)
	}
}

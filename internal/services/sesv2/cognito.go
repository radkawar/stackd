package sesv2

import (
	"context"
	"strings"
)

// ValidateCognitoIdentity resolves a same-account SES sender for the pool owner.
// Public Cognito setup owns role-creation admission; execution uses its current
// service-linked-role session through ordinary SendEmail authorization.
func (s *Service) ValidateCognitoIdentity(ctx context.Context, scope Scope, sourceARN, from, configuration string) error {
	return s.repository.View(ctx, func(r Reader) error {
		prefix := ResourceKey{Scope: scope}.ARN("identity")
		if !strings.HasPrefix(sourceARN, prefix) {
			return bad("Cognito SourceArn must name an SES identity in the pool account and Region.")
		}
		id, e := r.Identity(ResourceKey{scope, strings.TrimPrefix(sourceARN, prefix)})
		if e != nil {
			return e
		}
		if !id.Verified {
			return rejectedIdentity(id.Key.Name, scope.Region)
		}
		address, e := parseAddress(from)
		if e != nil {
			return e
		}
		if address.Address != id.Key.Name {
			return bad("Cognito From must match its verified email identity.")
		}
		if configuration != "" {
			_, e = r.ConfigurationSet(ResourceKey{scope, configuration})
			return e
		}
		return nil
	})
}

// QueueCognitoDefault is an internal managed-mail boundary, separate from public
// SES sending authority and sandbox restrictions. It cannot select another sender.
func (s *Service) QueueCognitoDefault(ctx context.Context, scope Scope, to, subject, text string) error {
	e := s.repository.Update(ctx, func(tx Transaction) error {
		_, e := s.acceptManaged(tx, scope, "no-reply@verificationemail.com", to, subject, text, "COGNITO_DEFAULT")
		return e
	})
	if e == nil {
		s.jobs.Wake()
	}
	return e
}

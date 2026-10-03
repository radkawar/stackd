package account

import "context"

// InitializeMemberContact copies the management account's current primary
// contact when Organizations creates a member, replacing only FullName with
// the new account's name. Alternate contacts are not inherited. The context
// must join the enclosing account/role publication transaction.
func (s *Service) InitializeMemberContact(ctx context.Context, partition, managementID, memberID, name string) error {
	return s.repository.Update(ctx, func(writer Writer) error {
		contact, found, err := writer.Contact(Scope{partition, managementID})
		if err != nil || !found {
			return err
		}
		contact.FullName = name
		return writer.PutContact(Scope{partition, memberID}, contact)
	})
}

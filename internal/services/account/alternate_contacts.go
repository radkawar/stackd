package account

import (
	"context"
	"strings"

	api "stackd/internal/awsapi/account"
	"stackd/internal/awsctx"
)

func (s *Service) getAlternateContact(ctx context.Context, in api.GetAlternateContactInput) (any, error) {
	var output *api.GetAlternateContactOutput
	err := s.repository.View(ctx, func(reader Reader) error {
		ctx, instant := reader.Context(), s.clock.Now().UTC()
		kind := value(in.AlternateContactType)
		target, err := s.authorize(ctx, "GetAlternateContact", value(in.AccountId), map[string][]string{"account:AlternateContactTypes": {kind}}, instant)
		if err != nil {
			return err
		}
		contact, found, err := reader.AlternateContact(AlternateContactKey{Scope{awsctx.FromContext(ctx).Partition, target}, ContactType(kind)})
		if err != nil {
			return err
		}
		if !found {
			return failure("ResourceNotFoundException", "No contact of the inputted alternate contact type found.", 404)
		}
		output = &api.GetAlternateContactOutput{AlternateContact: &api.AlternateContact{
			AlternateContactType: in.AlternateContactType, Name: ptr(api.Name(contact.Name)), Title: ptr(api.Title(contact.Title)), EmailAddress: ptr(api.EmailAddress(contact.EmailAddress)), PhoneNumber: ptr(api.PhoneNumber(contact.PhoneNumber)),
		}}
		return nil
	})
	return output, err
}

func (s *Service) putAlternateContact(ctx context.Context, in api.PutAlternateContactInput) (any, error) {
	err := s.repository.Update(ctx, func(writer Writer) error {
		ctx, instant := writer.Context(), s.clock.Now().UTC()
		kind := value(in.AlternateContactType)
		target, err := s.authorize(ctx, "PutAlternateContact", value(in.AccountId), map[string][]string{"account:AlternateContactTypes": {kind}}, instant)
		if err != nil {
			return err
		}
		// AWS strips surrounding email whitespace, preserving its case and all
		// whitespace in the other fields. See testdata/aws/account/contacts.json.
		contact := AlternateContact{Name: value(in.Name), Title: value(in.Title), EmailAddress: strings.TrimSpace(value(in.EmailAddress)), PhoneNumber: value(in.PhoneNumber)}
		if err := writer.PutAlternateContact(AlternateContactKey{Scope{awsctx.FromContext(ctx).Partition, target}, ContactType(kind)}, contact); err != nil {
			return err
		}
		return s.recordAPICall(ctx, "PutAlternateContact", &in, &api.PutAlternateContactOutput{}, nil)
	})
	return &api.PutAlternateContactOutput{}, err
}

func (s *Service) deleteAlternateContact(ctx context.Context, in api.DeleteAlternateContactInput) (any, error) {
	err := s.repository.Update(ctx, func(writer Writer) error {
		ctx, instant := writer.Context(), s.clock.Now().UTC()
		kind := value(in.AlternateContactType)
		target, err := s.authorize(ctx, "DeleteAlternateContact", value(in.AccountId), map[string][]string{"account:AlternateContactTypes": {kind}}, instant)
		if err != nil {
			return err
		}
		key := AlternateContactKey{Scope{awsctx.FromContext(ctx).Partition, target}, ContactType(kind)}
		_, found, err := writer.AlternateContact(key)
		if err != nil {
			return err
		}
		if !found {
			return failure("ResourceNotFoundException", "No contact of the inputted alternate contact type found.", 404)
		}
		if err := writer.DeleteAlternateContact(key); err != nil {
			return err
		}
		return s.recordAPICall(ctx, "DeleteAlternateContact", &in, &api.DeleteAlternateContactOutput{}, nil)
	})
	return &api.DeleteAlternateContactOutput{}, err
}

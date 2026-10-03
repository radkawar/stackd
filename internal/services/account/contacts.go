package account

import (
	"context"
	"strings"

	api "stackd/internal/awsapi/account"
	"stackd/internal/awsctx"
)

func (s *Service) getContactInformation(ctx context.Context, in api.GetContactInformationInput) (any, error) {
	var output *api.GetContactInformationOutput
	err := s.repository.View(ctx, func(reader Reader) error {
		ctx, instant := reader.Context(), s.clock.Now().UTC()
		target, err := s.authorize(ctx, "GetContactInformation", value(in.AccountId), nil, instant)
		if err != nil {
			return err
		}
		contact, found, err := reader.Contact(Scope{awsctx.FromContext(ctx).Partition, target})
		if err != nil {
			return err
		}
		if !found {
			return failure("ResourceNotFoundException", "No contact information found.", 404)
		}
		output = &api.GetContactInformationOutput{ContactInformation: contactOutput(contact)}
		return nil
	})
	return output, err
}

func (s *Service) putContactInformation(ctx context.Context, in api.PutContactInformationInput) (any, error) {
	// TODO: Comeback complete primary-contact country/address validation, remaining field normalization and partition/bootstrap initialization conformance against AWS.
	err := s.repository.Update(ctx, func(writer Writer) error {
		ctx, instant := writer.Context(), s.clock.Now().UTC()
		target, err := s.authorize(ctx, "PutContactInformation", value(in.AccountId), nil, instant)
		if err != nil {
			return err
		}
		c := in.ContactInformation
		contact := ContactInformation{
			FullName:     strings.TrimSpace(value(c.FullName)),
			AddressLine1: strings.TrimSpace(value(c.AddressLine1)), AddressLine2: value(c.AddressLine2), AddressLine3: value(c.AddressLine3),
			City: strings.TrimSpace(value(c.City)), StateOrRegion: strings.TrimSpace(value(c.StateOrRegion)), DistrictOrCounty: value(c.DistrictOrCounty),
			PostalCode: strings.TrimSpace(value(c.PostalCode)), CountryCode: strings.ToUpper(value(c.CountryCode)),
			PhoneNumber: strings.TrimSpace(value(c.PhoneNumber)), CompanyName: value(c.CompanyName), WebsiteURL: value(c.WebsiteUrl),
		}
		// Wire validation checks the supplied strings. Normalization must not
		// turn a supplied field into an empty stored value.
		type field struct{ name, value string }
		fields := []field{{"FullName", contact.FullName}, {"AddressLine1", contact.AddressLine1}, {"City", contact.City}, {"PostalCode", contact.PostalCode}}
		if c.StateOrRegion != nil {
			fields = append(fields, field{"StateOrRegion", contact.StateOrRegion})
		}
		for _, f := range fields {
			if f.value == "" {
				return failure("ValidationException", "the argument "+f.name+" can not be empty", 400)
			}
		}
		if err := writer.PutContact(Scope{awsctx.FromContext(ctx).Partition, target}, contact); err != nil {
			return err
		}
		return s.recordAPICall(ctx, "PutContactInformation", &in, &api.PutContactInformationOutput{}, nil)
	})
	return &api.PutContactInformationOutput{}, err
}

func contactOutput(c ContactInformation) *api.ContactInformation {
	return &api.ContactInformation{
		FullName:     ptr(api.FullName(c.FullName)),
		AddressLine1: ptr(api.AddressLine(c.AddressLine1)), AddressLine2: optional(api.AddressLine(c.AddressLine2)), AddressLine3: optional(api.AddressLine(c.AddressLine3)),
		City: ptr(api.City(c.City)), StateOrRegion: optional(api.StateOrRegion(c.StateOrRegion)), DistrictOrCounty: optional(api.DistrictOrCounty(c.DistrictOrCounty)),
		PostalCode: ptr(api.PostalCode(c.PostalCode)), CountryCode: ptr(api.CountryCode(c.CountryCode)),
		PhoneNumber: ptr(api.ContactInformationPhoneNumber(c.PhoneNumber)), CompanyName: optional(api.CompanyName(c.CompanyName)), WebsiteUrl: optional(api.WebsiteUrl(c.WebsiteURL)),
	}
}

func optional[T ~string](s T) *T {
	if s == "" {
		return nil
	}
	return &s
}

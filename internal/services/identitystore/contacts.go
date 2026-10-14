package identitystore

import api "stackd/internal/awsapi/identitystore"

// Contact lists are whole-attribute replacements. A null AttributeValue removes
// a list; a supplied list must have exactly one item, as in CreateUser.
func domainAddresses(values api.Addresses) ([]Address, error) {
	if values == nil {
		return nil, nil
	}
	if len(values) != 1 {
		return nil, bad("Addresses must contain exactly one item.")
	}
	v := values[0]
	for _, field := range []*api.SensitiveStringType{v.Country, v.Formatted, v.Locality, v.PostalCode, v.Region, v.StreetAddress, v.Type} {
		if field != nil && (value(field) == "" || !validOptionalText(value(field))) {
			return nil, bad("Invalid address attribute value.")
		}
	}
	return []Address{{Country: value(v.Country), Formatted: value(v.Formatted), Locality: value(v.Locality), PostalCode: value(v.PostalCode), Region: value(v.Region), StreetAddress: value(v.StreetAddress), Type: value(v.Type), Primary: v.Primary != nil && bool(*v.Primary)}}, nil
}

func domainPhoneNumbers(values api.PhoneNumbers) ([]PhoneNumber, error) {
	if values == nil {
		return nil, nil
	}
	if len(values) != 1 {
		return nil, bad("PhoneNumbers must contain exactly one item.")
	}
	v := values[0]
	for _, field := range []*api.SensitiveStringType{v.Value, v.Type} {
		if field != nil && (value(field) == "" || !validOptionalText(value(field))) {
			return nil, bad("Invalid phone number attribute value.")
		}
	}
	return []PhoneNumber{{Value: value(v.Value), Type: value(v.Type), Primary: v.Primary != nil && bool(*v.Primary)}}, nil
}

package account

// Scope identifies global Account state independently of the request region.
type Scope struct{ Partition, AccountID string }

// ContactInformation owns the account's primary contact. Required fields are
// nonempty after generated input validation. Empty optional fields mean absent;
// the API model rejects present empty strings for every contact member.
type ContactInformation struct {
	FullName, AddressLine1, City, PostalCode, CountryCode, PhoneNumber                   string
	AddressLine2, AddressLine3, StateOrRegion, DistrictOrCounty, CompanyName, WebsiteURL string
}

type ContactType string

// AlternateContact is the complete replaceable contact for one account/type.
// The type is part of its storage key rather than a mutable record property.
type AlternateContact struct{ Name, Title, EmailAddress, PhoneNumber string }

type AlternateContactKey struct {
	Scope Scope
	Type  ContactType
}

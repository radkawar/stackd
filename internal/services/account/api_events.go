package account

import (
	"context"
	"errors"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/journal"
)

// The native GetRegionOptStatus capture preserves RegionName. The documented
// alternate-contact events use lower camel case instead; casing is not a
// service-wide rule. Other operations use the documented Account convention.
// All outputs are suppressed, including contact and primary-email values.
func accountProjection(operation string) (apievents.Projection, bool) {
	p := apievents.Projection{Category: journal.CategoryManagement}
	switch operation {
	case "GetRegionOptStatus":
		p.ReadOnly = true
		p.Request.Fields = accountRegionStatusFields
	case "GetAccountInformation", "GetAlternateContact", "GetContactInformation", "GetGovCloudAccountInformation", "GetPrimaryEmail", "GetPrimaryEmailUpdateStatus", "ListRegions":
		p.ReadOnly = true
	case "PutAlternateContact":
		// Official example 2 logs these fields despite their sensitive models.
		// PhoneNumber, although required by the API, is absent from that record.
		p.Request.Fields = accountAlternateContactFields
	case "EnableRegion", "DisableRegion", "PutAccountName", "DeleteAlternateContact", "PutContactInformation", "StartPrimaryEmailUpdate", "AcceptPrimaryEmailUpdate":
	default:
		return p, false
	}
	// Unobserved sensitive values retain the shared safe omission, rather than
	// extrapolating the alternate-contact example to account names/addresses.
	// OTP is credential material and never suitable for an audit document.
	return p, true
}

var accountRegionStatusFields = map[string]awsapi.FieldProjection{
	"RegionName": {Name: "RegionName"},
}

var accountAlternateContactFields = map[string]awsapi.FieldProjection{
	"Name":         {Mode: awsapi.IncludeField},
	"EmailAddress": {Mode: awsapi.IncludeField},
	"Title":        {Mode: awsapi.IncludeField},
}

func accountError(err error) *awswire.Error {
	var apiErr *awswire.Error
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return failure("InternalServerException", "Account storage or authorization is unavailable.", 500)
}

func (s *Service) recordAPICall(ctx context.Context, name string, input, output any, apiErr *awswire.Error) error {
	if s.apiEvents == nil {
		return nil
	}
	projection, known := accountProjection(name)
	if !known {
		return nil
	}
	model, _ := awscatalog.LookupService("account")
	operation, known := model.Operation(name)
	if !known {
		return nil
	}
	call, err := projection.Call(model, operation, input, output, apiErr)
	if err != nil {
		return err
	}
	m := awsctx.FromContext(ctx)
	// The available native record and documented examples are caller-account
	// records. AccountId remains a request target, not an asserted audit recipient
	// or an invented resource ARN for management/delegated access.
	return s.apiEvents.Record(ctx, journal.Envelope{At: s.clock.Now().UTC(), Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}, call)
}

// RecordRequestError records only known generated operations, without consulting
// or serializing the failed HTTP body. It runs after any resource rollback.
func (s *Service) RecordRequestError(ctx context.Context, decoded awsapi.DecodedRequest, apiErr *awswire.Error) error {
	return s.recordAPICall(ctx, string(decoded.Operation.Name), decoded.Input, nil, apiErr)
}

package lambda

import (
	"context"
	"encoding/json"

	api "stackd/internal/awsapi/lambda"
	"stackd/internal/awswire"
)

// FilterEncryption uses current KMS authority, outside Lambda transactions.
// Protect runs as the configuring caller; Unprotect runs as the caller for API
// retrieval, or the regional Lambda principal for source processing.
type FilterEncryption interface {
	Resolve(context.Context, EventSourceMappingKey, string) (string, *awswire.Error)
	Protect(context.Context, EventSourceMappingRecord, string, []byte) (*EncryptedMappingFilters, *awswire.Error)
	Unprotect(context.Context, EventSourceMappingRecord, bool) ([]byte, *awswire.Error)
}

func (s *Service) mappingFilters(ctx context.Context, v EventSourceMappingRecord, processing bool) ([]string, *awswire.Error) {
	encrypted := v.Settings.EncryptedFilters
	if encrypted == nil {
		return v.Settings.Filters, nil
	}
	if s.filterEncryption == nil {
		return nil, unsupported("No event source filter encryption provider is configured.")
	}
	plain, wire := s.filterEncryption.Unprotect(ctx, v, processing)
	if wire != nil {
		return nil, wire
	}
	defer clear(plain)
	var filters []string
	if err := json.Unmarshal(plain, &filters); err != nil {
		return nil, failure("ServiceException", "Invalid encrypted filter criteria.", 500)
	}
	return filters, nil
}

// prepareMappingFilters returns the transient plaintext response separately from
// retained settings. Replacing filters does not require decrypting the old value.
func (s *Service) prepareMappingFilters(ctx context.Context, old EventSourceMappingRecord, function FunctionReference, settings EventSourceMappingSettings, in *api.UpdateEventSourceMappingInput) (EventSourceMappingSettings, []string, *awswire.Error, *awswire.Error) {
	changed := in.FilterCriteria != nil || in.KMSKeyArn != nil || in.FunctionName != nil || function != old.Function
	if !changed {
		filters, wire := s.mappingFilters(ctx, old, false)
		return settings, filters, wire, nil
	}
	filters := settings.Filters
	if in.FilterCriteria == nil && old.Settings.EncryptedFilters != nil {
		var wire *awswire.Error
		filters, wire = s.mappingFilters(ctx, old, false)
		if wire != nil {
			return settings, nil, nil, mappingParameter(filterDecryptionMessage(wire))
		}
	}
	keyARN := settings.KMSKeyARN
	if in.KMSKeyArn != nil {
		keyARN = value(in.KMSKeyArn)
	}
	if len(filters) == 0 {
		keyARN = ""
	}
	settings.KMSKeyARN, settings.EncryptedFilters = keyARN, nil
	settings.Filters = filters
	if keyARN == "" {
		return settings, filters, nil, nil
	}
	if s.filterEncryption == nil {
		return settings, nil, nil, unsupported("No event source filter encryption provider is configured.")
	}
	resolved, wire := s.filterEncryption.Resolve(ctx, old.Key, keyARN)
	if wire != nil {
		return settings, nil, nil, mappingParameter(wire.Message)
	}
	settings.KMSKeyARN = resolved
	proposed := old
	proposed.Function, proposed.Settings = function, settings
	plain, err := json.Marshal(filters)
	if err != nil {
		return settings, nil, nil, wireError(err)
	}
	defer clear(plain)
	encrypted, wire := s.filterEncryption.Protect(ctx, proposed, resolved, plain)
	if wire != nil {
		return settings, nil, nil, mappingParameter(wire.Message)
	}
	settings.EncryptedFilters = encrypted
	settings.Filters = nil
	return settings, filters, nil, nil
}

func filterDecryptionMessage(wire *awswire.Error) string {
	reason := "Lambda was unable to decrypt your filter criteria. Please check your KMS key settings."
	switch wire.Code {
	case "AccessDeniedException":
		reason = "Lambda was unable to decrypt your filter criteria because the KMS access was denied. Please check your KMS permissions."
	case "DisabledException":
		reason = "Lambda was unable to decrypt your filter criteria because the KMS key used is disabled. Please check your KMS key settings."
	}
	return reason + " KMS Exception: " + wire.Code + " KMS Message: " + wire.Message
}

func mappingFilterResponse(out *api.EventSourceMappingConfiguration, filters []string, wire *awswire.Error) {
	out.FilterCriteria = nil
	if wire != nil {
		out.FilterCriteriaError = &api.FilterCriteriaError{ErrorCode: new(api.FilterCriteriaErrorCode(wire.Code)), Message: new(api.FilterCriteriaErrorMessage(filterDecryptionMessage(wire)))}
		return
	}
	if len(filters) > 0 {
		out.FilterCriteria = &api.FilterCriteria{Filters: api.FilterList{}}
		for _, pattern := range filters {
			out.FilterCriteria.Filters = append(out.FilterCriteria.Filters, api.Filter{Pattern: new(api.Pattern(pattern))})
		}
	}
}

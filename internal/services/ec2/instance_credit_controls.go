package ec2

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	native "stackd/compute/ec2"
	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/ec2"
	"stackd/internal/awswire"
)

// InstanceCreditModificationRecord retains the typed idempotency contract, not
// usage history. A replay cannot apply an old mode over an intervening change.
type InstanceCreditModificationKey struct {
	Scope Scope
	Token string
}
type InstanceCreditModification struct{ InstanceID, Mode string }
type InstanceCreditModificationRecord struct {
	Key            InstanceCreditModificationKey
	Specifications []InstanceCreditModification
	Result         api.ModifyInstanceCreditSpecificationResult
}

func registerInstanceCredits(s *Service) {
	register(s, "GetDefaultCreditSpecification", s.getDefaultCreditSpecification)
	register(s, "ModifyDefaultCreditSpecification", s.modifyDefaultCreditSpecification)
	register(s, "DescribeInstanceCreditSpecifications", s.describeInstanceCreditSpecifications)
	register(s, "ModifyInstanceCreditSpecification", s.modifyInstanceCreditSpecification)
	command := s.operations["ModifyInstanceCreditSpecification"]
	s.operations["ModifyInstanceCreditSpecification"] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[api.ModifyInstanceCreditSpecificationRequest](ctx)
		if !ok || boolValue(in.DryRun) {
			return command(ctx)
		}
		s.instanceWorkMu.Lock()
		defer s.instanceWorkMu.Unlock()
		var targets []InstanceRecord
		err := s.repository.View(ctx, func(tx Reader) error {
			_, records, replay, err := s.creditModificationPlan(tx.Context(), tx, in)
			if !replay {
				targets = records
			}
			return err
		})
		// The registered command owns authorization/validation rejection and its
		// journal projection. Do not pause a VMM for a rejected or replayed request.
		if err != nil || len(targets) == 0 {
			return command(ctx)
		}
		paused := make(map[ResourceKey]native.Instance, len(targets))
		for _, record := range targets {
			requested := creditRequestedMode(in, record.Key.ID)
			if instanceState(record) != "running" || record.Credits.Mode == requested {
				continue
			}
			handle, effectErr := s.creditInstanceHandle(ctx, record)
			if effectErr == nil {
				var status native.Status
				status, effectErr = handle.Inspect(ctx)
				if effectErr == nil && status.State != native.Running && status.State != native.Paused {
					effectErr = failure("IncorrectInstanceState", "The native instance is not running.")
				}
				if effectErr == nil {
					effectErr = handle.Pause(ctx)
					if effectErr == nil {
						paused[record.Key] = handle
						_, effectErr = s.pollInstanceCredits(ctx, record.Key, handle)
					}
				}
			}
			if effectErr == nil {
				effectErr = s.repository.View(ctx, func(tx Reader) error { var err error; record, err = tx.Instance(record.Key); return err })
				if effectErr == nil {
					changeInstanceCreditMode(&record, requested)
					effectErr = applyInstanceCreditQuota(ctx, handle, record)
				}
			}
			if effectErr != nil {
				for key, handle := range paused {
					effectErr = errors.Join(effectErr, s.resumeCreditModification(ctx, key, handle))
				}
				return nil, s.creditModificationFailure(ctx, in, effectErr)
			}
		}
		out, rejected := command(ctx)
		// Config acceptance and its audit are committed. A failed native resume does
		// not undo the accepted credit setting; the existing instance observation
		// deadline retries the paused VMM under that setting.
		for key, handle := range paused {
			if err := s.resumeCreditModification(ctx, key, handle); err != nil {
				if rejected != nil {
					rejected = wireError(errors.Join(rejected, err))
				}
			}
		}
		return out, rejected
	}
}

func (s *Service) creditModificationFailure(ctx context.Context, in *api.ModifyInstanceCreditSpecificationRequest, cause error) *awswire.Error {
	rejected := wireError(cause)
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	if s.recorder != nil {
		var err error
		completion, err = apievents.Reserve(completion)
		if err != nil {
			return wireError(err)
		}
	}
	if err := s.repository.Update(completion, func(tx Transaction) error {
		return s.recordCall(tx.Context(), "ModifyInstanceCreditSpecification", in, nil, rejected)
	}); err != nil {
		return wireError(err)
	}
	return rejected
}

func validateCreditFamily(value *api.UnlimitedSupportedInstanceFamily) (string, error) {
	if value == nil {
		return "", failure("MissingParameter", "The request must include the InstanceFamily parameter. Add the required parameter and retry the request.")
	}
	family := strings.ToLower(str(value))
	if family == "" {
		return "", failure("InvalidParameterValue", "The value (  ) for the parameter InstanceFamily is invalid. Change the value and try again.")
	}
	if !supportedCreditFamily(family) {
		return "", failure("InvalidInstanceFamily", "The "+family+" instance family does not support an implemented Unlimited credit specification.")
	}
	return family, nil
}

func creditDefaultResponse(family, mode string) *api.InstanceFamilyCreditSpecification {
	return &api.InstanceFamilyCreditSpecification{InstanceFamily: new(api.UnlimitedSupportedInstanceFamily(family)), CpuCredits: new(api.String(mode))}
}

func (s *Service) getDefaultCreditSpecification(ctx context.Context, tx Transaction, in *api.GetDefaultCreditSpecificationRequest) (*api.GetDefaultCreditSpecificationResult, error) {
	if err := s.authorize(ctx, "GetDefaultCreditSpecification", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	family, err := validateCreditFamily(in.InstanceFamily)
	if err != nil {
		return nil, err
	}
	record, err := tx.InstanceCreditDefault(scopeFor(ctx), family)
	if errors.Is(err, ErrNotFound) {
		record = InstanceCreditDefaultRecord{Scope: scopeFor(ctx), Family: family, Mode: defaultInstanceCreditMode(family)}
	} else if err != nil {
		return nil, err
	}
	return &api.GetDefaultCreditSpecificationResult{InstanceFamilyCreditSpecification: creditDefaultResponse(family, record.Mode)}, nil
}

func (s *Service) modifyDefaultCreditSpecification(ctx context.Context, tx Transaction, in *api.ModifyDefaultCreditSpecificationRequest) (*api.ModifyDefaultCreditSpecificationResult, error) {
	if err := s.authorize(ctx, "ModifyDefaultCreditSpecification", "", "*", nil); err != nil {
		return nil, err
	}
	// Native DryRun performs authorization before validating family or mode.
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	family, err := validateCreditFamily(in.InstanceFamily)
	if err != nil {
		return nil, err
	}
	if in.CpuCredits == nil {
		return nil, failure("MissingParameter", "The request must include the CpuCredits parameter.")
	}
	mode := str(in.CpuCredits)
	if err := validateCreditMode(mode); err != nil {
		return nil, err
	}
	record, err := tx.InstanceCreditDefault(scopeFor(ctx), family)
	if errors.Is(err, ErrNotFound) {
		record = InstanceCreditDefaultRecord{Scope: scopeFor(ctx), Family: family, Mode: defaultInstanceCreditMode(family)}
	} else if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	record.Changes = creditWindow(record.Changes, now)
	if record.Mode != mode {
		if len(record.Changes) >= 4 || (len(record.Changes) != 0 && now.Before(record.Changes[len(record.Changes)-1].Add(5*time.Minute))) {
			return nil, failure("RequestLimitExceeded", "The default credit specification can be modified once per five minutes and four times per 24 hours.")
		}
		record.Mode = mode
		record.Changes = append(record.Changes, now)
		if err := tx.PutInstanceCreditDefault(record); err != nil {
			return nil, err
		}
	}
	return &api.ModifyDefaultCreditSpecificationResult{InstanceFamilyCreditSpecification: creditDefaultResponse(family, record.Mode)}, nil
}

func (s *Service) describeInstanceCreditSpecifications(ctx context.Context, tx Transaction, in *api.DescribeInstanceCreditSpecificationsRequest) (*api.DescribeInstanceCreditSpecificationsResult, error) {
	if err := s.authorize(ctx, "DescribeInstanceCreditSpecifications", "", "*", nil); err != nil {
		return nil, err
	}
	if err := dryRun(in.DryRun); err != nil {
		return nil, err
	}
	if len(in.InstanceIds) > 1000 {
		return nil, failure("InvalidParameterValue", "At most 1000 instance IDs may be specified.")
	}
	if in.MaxResults != nil && len(in.InstanceIds) > 0 {
		return nil, failure("InvalidParameterCombination", "The parameter instancesSet cannot be used with the parameter maxResults")
	}
	if in.MaxResults != nil && (*in.MaxResults < 5 || *in.MaxResults > 1000) {
		return nil, failure("InvalidRequest", "MaxResults must be between 5 and 1000.")
	}
	for _, filter := range in.Filters {
		if str(filter.Name) != "instance-id" {
			return nil, failure("InvalidRequest", "The filter '"+str(filter.Name)+"' is invalid")
		}
	}
	records, err := tx.Instances(scopeFor(ctx))
	if err != nil {
		return nil, err
	}
	for _, id := range in.InstanceIds {
		if _, err := loadInstance(ctx, tx, string(id)); err != nil {
			return nil, err
		}
	}
	items := make([]pageItem, 0, len(records))
	modes := make(map[string]string, len(records))
	for _, record := range records {
		if len(in.InstanceIds) == 0 && record.Credits.Mode != "unlimited" {
			continue
		}
		mode := record.Credits.Mode
		if mode == "" {
			mode = "standard"
		}
		items = append(items, pageItem{ID: record.Key.ID, Fields: map[string][]string{"instance-id": {record.Key.ID}}})
		modes[record.Key.ID] = mode
	}
	ids, next, err := selectPage(ctx, "DescribeInstanceCreditSpecifications", stringsOf(in.InstanceIds), in.Filters, maxResults(in.MaxResults), in.NextToken, items)
	if err != nil {
		return nil, err
	}
	out := &api.DescribeInstanceCreditSpecificationsResult{InstanceCreditSpecifications: api.InstanceCreditSpecificationList{}, NextToken: next}
	for _, id := range ids {
		out.InstanceCreditSpecifications = append(out.InstanceCreditSpecifications, api.InstanceCreditSpecification{InstanceId: new(api.String(id)), CpuCredits: new(api.String(modes[id]))})
	}
	return out, nil
}

func creditRequestedMode(in *api.ModifyInstanceCreditSpecificationRequest, id string) string {
	for _, specification := range in.InstanceCreditSpecifications {
		if str(specification.InstanceId) == id {
			return str(specification.CpuCredits)
		}
	}
	return ""
}

func canonicalCreditModification(in *api.ModifyInstanceCreditSpecificationRequest) ([]InstanceCreditModification, error) {
	if len(in.InstanceCreditSpecifications) == 0 {
		return nil, failure("MissingParameter", "The request must contain at least one instance credit specification.")
	}
	specifications := make([]InstanceCreditModification, 0, len(in.InstanceCreditSpecifications))
	for _, specification := range in.InstanceCreditSpecifications {
		specifications = append(specifications, InstanceCreditModification{InstanceID: str(specification.InstanceId), Mode: str(specification.CpuCredits)})
	}
	slices.SortFunc(specifications, func(a, b InstanceCreditModification) int { return strings.Compare(a.InstanceID, b.InstanceID) })
	for index := 1; index < len(specifications); index++ {
		if specifications[index].InstanceID == specifications[index-1].InstanceID && specifications[index].Mode != specifications[index-1].Mode {
			return nil, failure("InvalidParameterCombination", "Conflicting credit specifications for one instance.")
		}
	}
	return slices.Compact(specifications), nil
}

func creditModificationFailureItem(id, code, message string) api.UnsuccessfulInstanceCreditSpecificationItem {
	return api.UnsuccessfulInstanceCreditSpecificationItem{InstanceId: new(api.String(id)), Error: &api.UnsuccessfulInstanceCreditSpecificationItemError{Code: new(api.UnsuccessfulInstanceCreditSpecificationErrorCode(code)), Message: new(api.String(message))}}
}

func (s *Service) authorizeInstanceCreditModification(ctx context.Context, id string, record *InstanceRecord) error {
	conditions := map[string][]string{"ec2:InstanceID": {id}}
	var tags api.TagList
	if record != nil && record.Key.ID != "" {
		tags = record.Data.Tags
		conditions["ec2:InstanceType"] = []string{str(record.Data.InstanceType)}
		if record.Data.Placement != nil {
			conditions["ec2:AvailabilityZone"] = []string{str(record.Data.Placement.AvailabilityZone)}
		}
	}
	return s.authorizeWith(ctx, "ModifyInstanceCreditSpecification", "instance", id, tags, conditions)
}

// creditModificationPlan applies whole-request validation/IAM before any native
// effects. Native per-instance failures remain in the modeled unsuccessful set.
func (s *Service) creditModificationPlan(ctx context.Context, tx Reader, in *api.ModifyInstanceCreditSpecificationRequest) (*api.ModifyInstanceCreditSpecificationResult, []InstanceRecord, bool, error) {
	if boolValue(in.DryRun) {
		if len(in.InstanceCreditSpecifications) == 0 {
			if err := s.authorize(ctx, "ModifyInstanceCreditSpecification", "", "*", nil); err != nil {
				return nil, nil, false, err
			}
		}
		for _, specification := range in.InstanceCreditSpecifications {
			id := str(specification.InstanceId)
			record, err := tx.Instance(key(ctx, id))
			if err != nil && !errors.Is(err, ErrNotFound) {
				return nil, nil, false, err
			}
			if err := s.authorizeInstanceCreditModification(ctx, id, &record); err != nil {
				return nil, nil, false, err
			}
		}
		return nil, nil, false, dryRun(in.DryRun)
	}
	specifications, err := canonicalCreditModification(in)
	if err != nil {
		return nil, nil, false, err
	}
	if len(str(in.ClientToken)) > 64 {
		return nil, nil, false, failure("InvalidParameterValue", "ClientToken must not exceed 64 characters.")
	}
	out := &api.ModifyInstanceCreditSpecificationResult{SuccessfulInstanceCreditSpecifications: api.SuccessfulInstanceCreditSpecificationSet{}, UnsuccessfulInstanceCreditSpecifications: api.UnsuccessfulInstanceCreditSpecificationSet{}}
	records := make([]InstanceRecord, 0, len(specifications))
	for _, specification := range specifications {
		record, err := loadInstance(ctx, tx, specification.InstanceID)
		if err != nil {
			var rejected *awswire.Error
			if !errors.As(err, &rejected) {
				return nil, nil, false, err
			}
			if err := s.authorizeInstanceCreditModification(ctx, specification.InstanceID, nil); err != nil {
				return nil, nil, false, err
			}
			out.UnsuccessfulInstanceCreditSpecifications = append(out.UnsuccessfulInstanceCreditSpecifications, creditModificationFailureItem(specification.InstanceID, rejected.Code, rejected.Message))
			continue
		}
		if err := s.authorizeInstanceCreditModification(ctx, record.Key.ID, &record); err != nil {
			return nil, nil, false, err
		}
		if specification.Mode != "standard" && specification.Mode != "unlimited" {
			out.UnsuccessfulInstanceCreditSpecifications = append(out.UnsuccessfulInstanceCreditSpecifications, creditModificationFailureItem(record.Key.ID, "InvalidCpuCredits.Malformed", "The CpuCredit parameter for instance ID "+record.Key.ID+" requires a value of either standard or unlimited. Change the value and try again."))
			continue
		}
		if !instanceHasCPUCredits(record) {
			out.UnsuccessfulInstanceCreditSpecifications = append(out.UnsuccessfulInstanceCreditSpecifications, creditModificationFailureItem(record.Key.ID, "InstanceCreditSpecification.NotSupported", "The instance does not support CPU credit specifications."))
			continue
		}
		// Native owned fixtures also accept changes on a retained terminated
		// tombstone, even though the API overview mentions running/stopped only.
		if state := instanceState(record); state != "running" && state != "stopped" && state != "terminated" {
			out.UnsuccessfulInstanceCreditSpecifications = append(out.UnsuccessfulInstanceCreditSpecifications, creditModificationFailureItem(record.Key.ID, "IncorrectInstanceState", "The instance cannot change its CPU credit specification in its current state."))
			continue
		}
		out.SuccessfulInstanceCreditSpecifications = append(out.SuccessfulInstanceCreditSpecifications, api.SuccessfulInstanceCreditSpecificationItem{InstanceId: new(api.String(record.Key.ID))})
		records = append(records, record)
	}
	if token := str(in.ClientToken); token != "" {
		previous, err := tx.InstanceCreditModification(InstanceCreditModificationKey{Scope: scopeFor(ctx), Token: token})
		if err == nil {
			if !slices.Equal(previous.Specifications, specifications) {
				return nil, nil, false, failure("IdempotentParameterMismatch", "Parameters differ from the previous request with this ClientToken.")
			}
			result := api.CloneModifyInstanceCreditSpecificationResult(previous.Result)
			return &result, nil, true, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return nil, nil, false, err
		}
	}
	return out, records, false, nil
}

func (s *Service) modifyInstanceCreditSpecification(ctx context.Context, tx Transaction, in *api.ModifyInstanceCreditSpecificationRequest) (*api.ModifyInstanceCreditSpecificationResult, error) {
	out, records, replay, err := s.creditModificationPlan(ctx, tx, in)
	if err != nil || replay {
		return out, err
	}
	for _, record := range records {
		mode := creditRequestedMode(in, record.Key.ID)
		if mode == record.Credits.Mode {
			continue
		}
		charged := changeInstanceCreditMode(&record, mode)
		if instanceState(record) == "running" {
			scheduleInstanceObservation(&record, s.clock.Now())
		}
		if instanceState(record) == "running" || charged != 0 {
			if err := s.recordInstanceCreditSample(ctx, &record, 0, charged, charged != 0); err != nil {
				return nil, err
			}
		}
		if err := tx.PutInstance(record); err != nil {
			return nil, err
		}
	}
	if token := str(in.ClientToken); token != "" {
		specifications, _ := canonicalCreditModification(in)
		if err := tx.PutInstanceCreditModification(InstanceCreditModificationRecord{Key: InstanceCreditModificationKey{Scope: scopeFor(ctx), Token: token}, Specifications: specifications, Result: *out}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

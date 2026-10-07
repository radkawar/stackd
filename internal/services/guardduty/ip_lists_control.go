package guardduty

import (
	"context"
	"errors"
	"maps"
	"regexp"
	"slices"
	"time"
	"unicode/utf8"

	"stackd/internal/apievents"
	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/guardduty"
	"stackd/internal/awswire"
)

var ipListNamePattern = regexp.MustCompile(`^[a-zA-Z0-9\s_-]+$`)
var ipListOwnerPattern = regexp.MustCompile(`^[0-9]{12}$`)

// A recovery deadline outlives the bounded synchronous read and completion.
// ACTIVE lists have no deadline: object changes require explicit reactivation.
const ipListRecoveryDelay = time.Minute
const ipListReadTimeout = 30 * time.Second

func registerIPLists(s *Service) {
	registerIPSets(s)
	registerThreatIntelSets(s)
}

func ipListARN(sc Scope, detector string, kind IPListKind, id string) string {
	return detectorARN(sc, detector) + "/" + string(kind) + "/" + id
}

// Unlike ordinary registration, source failures must commit ERROR and the
// rejected API outcome together. The admission transaction journals its source
// intent through the service-owned IAM policy mutation; no success is recorded
// until the external read and parsing have actually completed.
func registerIPListMutation[I, O any](s *Service, name string, admit func(Transaction, *I) (*O, *IPList, error)) {
	s.operations[name] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServerErrorException", "Missing generated input", 500)
		}
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		var out *O
		var pending *IPList
		err = s.repository.Attempt(ctx, func(tx Transaction) error {
			var err error
			out, pending, err = admit(tx, in)
			if err != nil {
				return err
			}
			if pending == nil {
				return s.recordCall(tx.Context(), name, in, out, nil)
			}
			return nil
		})
		if err != nil {
			return nil, s.rejectIPListCall(ctx, name, in, err)
		}
		if pending == nil {
			s.jobs.Wake()
			return out, nil
		}
		ranges, rejected := s.readIPList(ctx, *pending)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		err = s.repository.Attempt(completion, func(tx Transaction) error {
			if err := completeIPList(tx, *pending, ranges, rejected); err != nil {
				return err
			}
			if rejected != nil {
				return s.recordCall(tx.Context(), name, in, nil, rejected)
			}
			return s.recordCall(tx.Context(), name, in, out, nil)
		})
		s.jobs.Wake()
		if err != nil {
			return nil, s.rejectIPListCall(completion, name, in, err)
		}
		if rejected != nil {
			return nil, rejected
		}
		return out, nil
	}
}

func (s *Service) rejectIPListCall(ctx context.Context, name string, in any, err error) *awswire.Error {
	rejected := wireError(err)
	completion, cancel := apievents.CompletionContext(ctx)
	defer cancel()
	var dependency interface{ RecordRejection(context.Context) error }
	if errors.As(err, &dependency) {
		if err := dependency.RecordRejection(completion); err != nil {
			return wireError(err)
		}
	}
	if err := s.recordCall(completion, name, in, nil, rejected); err != nil {
		return wireError(err)
	}
	return rejected
}

func (s *Service) readIPList(ctx context.Context, v IPList) ([]IPRange, *awswire.Error) {
	if s.ipLists == nil {
		return nil, failure("InternalServerErrorException", "GuardDuty IP list source is unavailable", 500)
	}
	ctx, cancel := context.WithTimeout(ctx, ipListReadTimeout)
	defer cancel()
	content, err := s.ipLists.Read(ctx, v)
	if err != nil {
		return nil, wireError(err)
	}
	limit := 2000
	if v.Kind == ThreatIPList {
		limit = 250000
	}
	ranges, err := parseIPList(v.Format, content, limit)
	if err != nil {
		return nil, invalid(err.Error())
	}
	return ranges, nil
}

func completeIPList(tx Transaction, pending IPList, ranges []IPRange, rejected *awswire.Error) error {
	v, err := tx.IPList(pending.Scope, pending.DetectorID, pending.Kind, pending.ID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if v.Version != pending.Version || v.Status != "ACTIVATING" || !v.Due.Equal(pending.Due) {
		return nil
	}
	v.Status, v.Due = "ACTIVE", time.Time{}
	if rejected != nil {
		v.Status = "ERROR"
		ranges = nil
	}
	if err := tx.ReplaceIPRanges(v.Scope, v.DetectorID, v.Kind, v.ID, ranges); err != nil {
		return err
	}
	return tx.PutIPList(v)
}

func (s *Service) loadIPList(r Reader, detector string, kind IPListKind, id, action string) (IPList, error) {
	sc := scopeFor(r.Context())
	v, err := r.IPList(sc, detector, kind, id)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return v, err
	}
	if e := s.authorize(r.Context(), action, ipListARN(sc, detector, kind, id), v.Tags, nil, nil); e != nil {
		return v, e
	}
	if err != nil {
		return v, missingIPList()
	}
	if err := checkCloudFormationOwnership(r.Context(), v.CFNOwnership); err != nil {
		return v, err
	}
	return v, nil
}

func missingIPList() error {
	return invalid("The request is rejected since no such resource found.")
}
func invalidIPListInput() error {
	// Native legacy endpoints return this modeled code with HTTP 400.
	return failure("InternalServerErrorException", "The request is rejected because an invalid or out-of-range value is specified as an input parameter.", 400)
}
func validateIPListOwner(owner *api.AccountId) error {
	if owner != nil && !ipListOwnerPattern.MatchString(string(*owner)) {
		return invalid("The request failed because the 'accountId' was formatted incorrectly.")
	}
	return nil
}
func validateIPListLocation(location string) error {
	if location == "" || utf8.RuneCountInString(location) > 300 {
		return invalid("The request is rejected because the parameter ipSetLocation has an invalid value.")
	}
	// The source adapter owns S3 URI parsing, not this lifecycle owner.
	return nil
}

type ipListCreate struct {
	Kind                                            IPListKind
	DetectorID, Name, Format, Location, ClientToken string
	Owner                                           *api.AccountId
	Activate                                        *api.Boolean
	Tags                                            api.TagMap
}

func (s *Service) createIPList(tx Transaction, in ipListCreate, action string) (IPList, *IPList, error) {
	sc := scopeFor(tx.Context())
	tags := stringTags(in.Tags)
	keys := slices.Sorted(maps.Keys(tags))
	if err := s.authorize(tx.Context(), action, "*", nil, tags, keys); err != nil {
		return IPList{}, nil, err
	}
	if _, err := tx.Detector(sc, in.DetectorID); err != nil {
		return IPList{}, nil, err
	}
	if in.Activate == nil {
		return IPList{}, nil, invalid("The request is rejected because the JSON could not be processed.")
	}
	if !ipListNamePattern.MatchString(in.Name) || utf8.RuneCountInString(in.Name) > 300 {
		param := "ipSetName"
		if in.Kind == ThreatIPList {
			param = "threatIntelSetName"
		}
		return IPList{}, nil, invalid("The request is rejected because the parameter " + param + " has an invalid value.")
	}
	switch in.Format {
	case "TXT", "STIX", "OTX_CSV", "ALIEN_VAULT", "PROOF_POINT", "FIRE_EYE":
	default:
		return IPList{}, nil, invalid("The request is rejected because the JSON could not be processed.")
	}
	if err := validateIPListLocation(in.Location); err != nil {
		return IPList{}, nil, err
	}
	if err := validateIPListOwner(in.Owner); err != nil {
		return IPList{}, nil, err
	}
	if len(in.ClientToken) > 64 {
		return IPList{}, nil, invalid("ClientToken exceeds 64 characters")
	}
	if err := validateTags(tags); err != nil {
		return IPList{}, nil, err
	}
	all, err := tx.IPLists(sc, in.DetectorID)
	if err != nil {
		return IPList{}, nil, err
	}
	count := 0
	for _, existing := range all {
		if existing.Kind != in.Kind || existing.Status == "DELETED" {
			continue
		}
		count++
		if existing.Name != in.Name {
			continue
		}
		if len(tags) > 0 {
			if err := s.authorize(tx.Context(), "TagResource", existing.ARN, existing.Tags, tags, keys); err != nil {
				return IPList{}, nil, err
			}
		}
		if in.ClientToken != "" && existing.ClientToken == in.ClientToken {
			if err := checkCloudFormationOwnership(tx.Context(), existing.CFNOwnership); err != nil {
				return IPList{}, nil, err
			}
			return existing, nil, nil
		}
		return IPList{}, nil, invalid("An IP list with this name already exists")
	}
	quota := 1
	if in.Kind == ThreatIPList {
		quota = 6
	}
	if count >= quota {
		return IPList{}, nil, failure("InternalServerErrorException", "The request is rejected because it’s an attempt to create resources beyond the current AWS account limits.", 400)
	}
	v := IPList{Scope: sc, DetectorID: in.DetectorID, Kind: in.Kind, ID: newID(), Name: in.Name, Format: in.Format, Location: in.Location, ExpectedBucketOwner: value(in.Owner), ClientToken: in.ClientToken, Tags: tags, Status: "INACTIVE", Version: 1}
	v.CFNOwnership = creationOwnership(tx.Context())
	v.ARN = ipListARN(sc, v.DetectorID, v.Kind, v.ID)
	if len(tags) > 0 {
		if err := s.authorize(tx.Context(), "TagResource", v.ARN, nil, tags, keys); err != nil {
			return IPList{}, nil, err
		}
	}
	if s.ipLists == nil {
		return IPList{}, nil, failure("InternalServerErrorException", "GuardDuty IP list source is unavailable", 500)
	}
	if bool(*in.Activate) {
		v.Status, v.Due = "ACTIVATING", s.clock.Now().Add(ipListRecoveryDelay)
	}
	if err := s.ipLists.PutPolicy(tx.Context(), v); err != nil {
		return IPList{}, nil, err
	}
	if err := tx.PutIPList(v); err != nil {
		return IPList{}, nil, err
	}
	if v.Status == "ACTIVATING" {
		return v, &v, nil
	}
	return v, nil, nil
}

type ipListUpdate struct {
	Kind           IPListKind
	DetectorID, ID string
	Name           *api.Name
	Location       *api.Location
	Owner          *api.AccountId
	Activate       *api.Boolean
}

func (s *Service) updateIPList(tx Transaction, in ipListUpdate, action string) (*IPList, error) {
	v, err := s.loadIPList(tx, in.DetectorID, in.Kind, in.ID, action)
	if err != nil {
		return nil, err
	}
	if v.Status == "DELETED" {
		return nil, missingIPList()
	}
	if in.Name != nil {
		// Native Update accepts a 301-character name despite the model's 300
		// bound; keep the observed character validation without truncation.
		if !ipListNamePattern.MatchString(string(*in.Name)) {
			return nil, invalidIPListInput()
		}
		all, err := tx.IPLists(v.Scope, v.DetectorID)
		if err != nil {
			return nil, err
		}
		for _, other := range all {
			if other.Kind == v.Kind && other.ID != v.ID && other.Status != "DELETED" && other.Name == string(*in.Name) {
				return nil, invalid("An IP list with this name already exists")
			}
		}
		v.Name = string(*in.Name)
	}
	if in.Location != nil {
		if err := validateIPListLocation(string(*in.Location)); err != nil {
			return nil, err
		}
		v.Location = string(*in.Location)
	}
	if err := validateIPListOwner(in.Owner); err != nil {
		return nil, err
	}
	if in.Owner != nil {
		v.ExpectedBucketOwner = string(*in.Owner)
	}
	activate := in.Activate != nil && bool(*in.Activate)
	if in.Name == nil && in.Location == nil && in.Owner == nil && in.Activate == nil {
		return nil, nil
	}
	if activate {
		v.Status, v.Due = "ACTIVATING", s.clock.Now().Add(ipListRecoveryDelay)
	} else if in.Activate != nil || (v.Status == "ACTIVATING" && (in.Location != nil || in.Owner != nil)) {
		v.Status, v.Due = "INACTIVE", time.Time{}
	}
	if in.Activate != nil || in.Location != nil || in.Owner != nil {
		v.Version++
	}
	if activate || in.Location != nil || in.Owner != nil {
		if s.ipLists == nil {
			return nil, failure("InternalServerErrorException", "GuardDuty IP list source is unavailable", 500)
		}
		if err := s.ipLists.PutPolicy(tx.Context(), v); err != nil {
			return nil, err
		}
	}
	if err := tx.PutIPList(v); err != nil {
		return nil, err
	}
	if activate {
		return &v, nil
	}
	return nil, nil
}

func (s *Service) deleteIPList(tx Transaction, detector string, kind IPListKind, id, action string) error {
	v, err := s.loadIPList(tx, detector, kind, id, action)
	if err != nil {
		return err
	}
	if v.Status == "DELETED" {
		return missingIPList()
	}
	if s.ipLists == nil {
		return failure("InternalServerErrorException", "GuardDuty IP list source is unavailable", 500)
	}
	if err := s.ipLists.DeletePolicy(tx.Context(), v); err != nil {
		return err
	}
	v.Status, v.Due, v.Tags = "DELETED", time.Time{}, map[string]string{}
	v.Version++
	if err := tx.ReplaceIPRanges(v.Scope, v.DetectorID, v.Kind, v.ID, nil); err != nil {
		return err
	}
	return tx.PutIPList(v)
}

func (s *Service) listIPLists(tx Transaction, detector string, kind IPListKind, action string, maxResults *api.MaxResults, token string) ([]api.String, string, error) {
	if err := s.authorize(tx.Context(), action, "*", nil, nil, nil); err != nil {
		return nil, "", err
	}
	sc := scopeFor(tx.Context())
	if _, err := tx.Detector(sc, detector); err != nil {
		return nil, "", err
	}
	if maxResults != nil && (*maxResults < 1 || *maxResults > 50) {
		return nil, "", invalid("The request is rejected because the parameter maxResults is out-of-bounds.")
	}
	cursorKind := string(kind) + ":" + detector
	limit, after, err := page(tx.Context(), cursorKind, maxResults, token)
	if err != nil {
		return nil, "", invalidIPListInput()
	}
	all, err := tx.IPLists(sc, detector)
	if err != nil {
		return nil, "", err
	}
	ids := make([]api.String, 0, min(limit, len(all)))
	for _, v := range all {
		if v.Kind != kind || v.Status == "DELETED" || v.ID <= after {
			continue
		}
		if len(ids) == limit {
			return ids, pageToken(tx.Context(), cursorKind, string(ids[len(ids)-1])), nil
		}
		ids = append(ids, api.String(v.ID))
	}
	return ids, "", nil
}

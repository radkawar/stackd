package ebs

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"stackd/clock"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/scheduler"
	"stackd/internal/services/ec2"
)

const BlockSize = 512 * 1024

// CompletionDelay and ReadinessDelay deliberately separate EC2 completion from
// EBS direct readability. They are deterministic emulator timing, not AWS SLAs.
const CompletionDelay = time.Second
const ReadinessDelay = 5 * time.Second

// CountValidationDelay is an emulator policy, not an inferred native timer.
const CountValidationDelay = 10 * time.Minute

// DeletionDelay models bounded direct-plane visibility after EC2 deletion.
const DeletionDelay = 5 * time.Second

// SharingDelay publishes private grants and revocations on the direct plane.
// Native propagation is asynchronous; this duration is a local clock policy.
const SharingDelay = 5 * time.Second

// BlockTokenLifetime follows the captured nonempty-list expiry advertisement;
// native rejection after natural expiration has not been measured.
const BlockTokenLifetime = 585000 * time.Second

type Config struct {
	Repository            Repository
	Authorizer            authorization.Authorizer
	Recorder              apievents.Recorder
	Clock                 clock.Clock
	Keys                  DataKeys
	EC2Keys               EC2DataKeys
	Policies              SnapshotPolicies
	Images                ImageReferences
	Events                NotificationPublisher
	InstanceKeys          InstanceDataKeys
	Attachments           InstanceAttachments
	NativeDisks           NativeDisks
	NativeVolumeDirectory string
}
type Service struct {
	repository            Repository
	authorizer            authorization.Authorizer
	recorder              apievents.Recorder
	clock                 clock.Clock
	keys                  DataKeys
	ec2Keys               EC2DataKeys
	policies              SnapshotPolicies
	images                ImageReferences
	events                NotificationPublisher
	jobs                  *scheduler.Driver
	admission             snapshotAdmission
	operations            map[string]func(context.Context) (any, *awswire.Error)
	instanceKeys          InstanceDataKeys
	attachments           InstanceAttachments
	nativeDisks           NativeDisks
	nativeVolumeDirectory string
	nativeWorkMu          sync.Mutex
}

func New(c Config) *Service {
	if c.Clock == nil {
		c.Clock = clock.Real{}
	}
	if c.Repository == nil {
		c.Repository = NewMemoryRepository(nil)
	}
	if c.Authorizer == nil {
		c.Authorizer = authorization.NewWithClock(nil, nil, c.Clock)
	}
	s := &Service{repository: c.Repository, authorizer: c.Authorizer, recorder: c.Recorder, clock: c.Clock, keys: c.Keys, ec2Keys: c.EC2Keys, policies: c.Policies, images: c.Images, events: c.Events, operations: map[string]func(context.Context) (any, *awswire.Error){}}
	s.instanceKeys, s.attachments, s.nativeDisks = c.InstanceKeys, c.Attachments, c.NativeDisks
	s.nativeVolumeDirectory = c.NativeVolumeDirectory
	s.jobs = scheduler.New(c.Clock, snapshotJobs{s})
	register(s, "StartSnapshot", s.startSnapshot)
	register(s, "PutSnapshotBlock", s.putSnapshotBlock)
	register(s, "CompleteSnapshot", s.completeSnapshot)
	register(s, "ListSnapshotBlocks", s.listSnapshotBlocks)
	register(s, "ListChangedBlocks", s.listChangedBlocks)
	register(s, "GetSnapshotBlock", s.getSnapshotBlock)
	return s
}
func (s *Service) Operations() []string {
	out := make([]string, 0, len(s.operations))
	for op := range s.operations {
		out = append(out, op)
	}
	slices.Sort(out)
	return out
}
func (s *Service) JobDriver() *scheduler.Driver { return s.jobs }
func (s *Service) Close() error                 { s.jobs.Close(); return nil }
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	model, _ := awscatalog.LookupService("ebs")
	request, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.RESTJSONError(w, r, &model, failure("InternalServerException", "Missing generated request binding.", "", 500))
		return
	}
	out, rejected := s.ExecuteCommand(r.Context(), request)
	if rejected != nil {
		awswire.RESTJSONError(w, r, &model, rejected)
		return
	}
	response, err := awsapi.EncodeHTTPResponse(model, request.Operation, out)
	if err != nil {
		awswire.RESTJSONError(w, r, &model, wireError(err))
		return
	}
	for k, v := range response.Header {
		w.Header()[k] = v
	}
	w.Header().Set("X-Amzn-Requestid", awsctx.FromContext(r.Context()).RequestID)
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(response.Body)
}
func (s *Service) ExecuteCommand(ctx context.Context, request awsapi.DecodedRequest) (any, *awswire.Error) {
	ctx = awsapi.WithDecodedRequest(ctx, request)
	fn, ok := s.operations[string(request.Operation.Name)]
	if !ok {
		return nil, failure("UnknownOperationException", "Unknown EBS operation.", "", 400)
	}
	return fn(ctx)
}
func register[I, O any](s *Service, action string, fn func(Transaction, *I) (*O, error)) {
	s.operations[action] = func(ctx context.Context) (any, *awswire.Error) {
		in, ok := awsapi.Input[I](ctx)
		if !ok {
			return nil, failure("InternalServerException", "Missing generated request binding.", "", 500)
		}
		ctx = ec2.WithSnapshotAudit(ctx)
		ctx, err := apievents.Reserve(ctx)
		if err != nil {
			return nil, wireError(err)
		}
		// Expired work is independent of the current request's success or rejection.
		if err = s.advance(ctx); err != nil {
			return nil, wireError(err)
		}
		ctx, outcomes := apievents.RetainOutcomes(ctx)
		var out *O
		if rejected := s.admitAccount(ctx, action); rejected != nil {
			err = rejected
		} else {
			err = s.repository.Attempt(ctx, func(tx Transaction) error {
				var err error
				out, err = fn(tx, in)
				if err != nil {
					return err
				}
				return s.recordCall(tx.Context(), action, in, out, nil)
			})
		}
		if err == nil {
			s.jobs.Wake()
			return out, nil
		}
		rejected := wireError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		err = s.repository.Update(completion, func(tx Transaction) error {
			if err := outcomes.Record(tx.Context()); err != nil {
				return err
			}
			return s.recordCall(tx.Context(), action, in, nil, rejected)
		})
		if err != nil {
			return nil, wireError(err)
		}
		return nil, rejected
	}
}
func (s *Service) RecordRequestError(ctx context.Context, request awsapi.DecodedRequest, rejected *awswire.Error) error {
	return s.recordCall(ctx, string(request.Operation.Name), request.Input, nil, rejected)
}
func (*Service) RequestError(action string, err error) *awswire.Error {
	var validation *awsapi.ValidationError
	if action == "PutSnapshotBlock" && errors.As(err, &validation) && validation.Constraint == "enum" {
		return invalid("INVALID_PARAMETER_VALUE", err.Error())
	}
	return failure("ValidationException", err.Error(), "", 400)
}
func failure(code, message, reason string, status int) *awswire.Error {
	return &awswire.Error{Code: code, Message: message, Reason: reason, StatusCode: status}
}
func invalid(reason, message string) *awswire.Error {
	return failure("ValidationException", message, reason, 400)
}
func wireError(err error) *awswire.Error {
	var wire *awswire.Error
	if errors.As(err, &wire) {
		if wire.Code == "AccessDenied" {
			return failure("AccessDeniedException", wire.Message, "", 403)
		}
		return wire
	}
	return failure("InternalServerException", "Unable to access EBS snapshot state.", "", 500)
}
func scopeFor(ctx context.Context) Scope {
	m := awsctx.FromContext(ctx)
	return Scope{m.Partition, m.AccountID, m.Region}
}
func value[T ~string](p *T) string {
	if p == nil {
		return ""
	}
	return string(*p)
}
func number[T ~int32 | ~int64](p *T) int64 {
	if p == nil {
		return 0
	}
	return int64(*p)
}
func snapshotARN(k SnapshotKey) string {
	return "arn:" + k.Partition + ":ec2:" + k.Region + "::snapshot/" + k.ID
}
func missing(id string) *awswire.Error {
	return failure("ResourceNotFoundException", "The snapshot '"+id+"' does not exist.", "SNAPSHOT_NOT_FOUND", 404)
}

// snapshotRecord resolves lifecycle visibility without granting operation access.
// Parent creation must authorize this source before rejecting foreign ownership.
func (s *Service) snapshotRecord(r Reader, id string) (SnapshotRecord, error) {
	scope := scopeFor(r.Context())
	v, err := r.RegionalSnapshot(scope.Partition, scope.Region, id)
	if errors.Is(err, ErrNotFound) {
		return SnapshotRecord{}, missing(id)
	}
	if err != nil {
		return SnapshotRecord{}, err
	}
	s.observeSnapshot(r.Context(), v)
	if v.Deleted && (v.DeleteAt.IsZero() || !v.DeleteAt.After(s.clock.Now())) {
		return SnapshotRecord{}, missing(id)
	}
	return v, nil
}
func (s *Service) snapshot(r Reader, id string, readable bool) (SnapshotRecord, error) {
	v, err := s.snapshotRecord(r, id)
	if err != nil {
		return SnapshotRecord{}, err
	}
	if readable && !v.Readable {
		return SnapshotRecord{}, missing(id)
	}
	scope := scopeFor(r.Context())
	if v.Key.AccountID != scope.AccountID {
		if !readable {
			return SnapshotRecord{}, missing(id)
		}
		if v.Public {
			return SnapshotRecord{}, invalid("INVALID_SNAPSHOT_ID", "Public snapshots are not supported")
		}
		share, ok := snapshotShare(v, scope.AccountID)
		if !ok || !share.Readable {
			return SnapshotRecord{}, missing(id)
		}
		v.Tags, err = r.SharedTags(SharedTagsKey{Snapshot: v.Key, AccountID: scope.AccountID})
		if err != nil {
			return SnapshotRecord{}, err
		}
	}
	return v, nil
}
func (s *Service) authorizationRequest(ctx context.Context, namespace, action string, v SnapshotRecord, conditions map[string][]string) authorization.Request {
	// Request conditions may be shared by creation and parent authorization;
	// each resource gets only its own authoritative tags.
	conditions = maps.Clone(conditions)
	if conditions == nil {
		conditions = map[string][]string{}
	}
	resource := "*"
	if v.Key.ID != "" {
		resource = snapshotARN(v.Key)
		for k, t := range v.Tags {
			conditions["aws:ResourceTag/"+k] = []string{t}
			if namespace == "ec2" {
				conditions["ec2:ResourceTag/"+k] = []string{t}
			}
		}
		if namespace == "ec2" && !v.Created.IsZero() {
			conditions["ec2:Owner"] = []string{v.Key.AccountID}
			conditions["ec2:Encrypted"] = []string{strconv.FormatBool(v.KMSKeyARN != "")}
			conditions["ec2:VolumeSize"] = []string{strconv.FormatInt(v.VolumeSize, 10)}
			conditions["ec2:SnapshotID"] = []string{v.Key.ID}
			conditions["ec2:SnapshotTime"] = []string{v.Created.UTC().Format(time.RFC3339)}
			parentVolume := "arn:" + v.Key.Partition + ":ec2:" + v.Key.Region + ":" + v.Key.AccountID + ":volume/vol-ffffffff"
			if v.Volume != nil {
				parentVolume = volumeARN(v.Volume.Source)
			}
			conditions["ec2:ParentVolume"] = []string{parentVolume}
		}
	}
	if namespace == "ec2" {
		conditions["ec2:Region"] = []string{scopeFor(ctx).Region}
	}
	// Foreign data/tag callers have already passed their service visibility
	// gate. Ownership-only controls and parent creation admit IAM first, then
	// enforce ownership; this grant never bypasses that gate or caller restrictions.
	foreign := v.Key.AccountID != "" && v.Key.AccountID != scopeFor(ctx).AccountID
	now := s.clock.Now()
	// EC2's decoded native authorization context makes batch permission keys
	// multivalued only when distinct values remain. The service-wide catalog
	// calls them scalar; plain StringEquals must not match a multi-account batch.
	var contextTypes map[string]string
	if namespace == "ec2" && action == "ModifySnapshotAttribute" {
		for _, key := range []string{"ec2:Add/userId", "ec2:Remove/userId", "ec2:Add/group", "ec2:Remove/group"} {
			if len(conditions[key]) > 1 {
				if contextTypes == nil {
					contextTypes = make(map[string]string)
				}
				contextTypes[key] = "stringList"
			}
		}
	}
	return authorization.Request{Action: namespace + ":" + action, ResourceARN: resource, ResourceAccountID: v.Key.AccountID, ResourceAccountGrant: foreign, Context: conditions, ContextTypes: contextTypes, EvaluationTime: &now}
}
func (s *Service) authorize(ctx context.Context, namespace, action string, v SnapshotRecord, conditions map[string][]string) error {
	if rejected := s.authorizer.Authorize(ctx, s.authorizationRequest(ctx, namespace, action, v, conditions)); rejected != nil {
		return rejected
	}
	return nil
}

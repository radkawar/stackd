package eks

import (
	"context"
	"errors"
	"net/http"

	native "stackd/compute/eks"
	"stackd/internal/apievents"
	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	authapi "stackd/internal/awsapi/eksauth"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	"stackd/journal"
)

// PodIdentityAuth is the generated EKS Auth frontend sharing the EKS association
// repository, current node membership, authorization and STS credential owner.
type PodIdentityAuth struct{ service *Service }

func (s *Service) PodIdentityAuth() *PodIdentityAuth { return &PodIdentityAuth{service: s} }
func (*PodIdentityAuth) Operations() []string        { return []string{"AssumeRoleForPodIdentity"} }
func (*PodIdentityAuth) RequestError(_ string, err error) *awswire.Error {
	return failure("InvalidParameterException", err.Error(), 400)
}
func (p *PodIdentityAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d, ok := awsapi.FromContext(r.Context())
	if !ok {
		awswire.JSONError(w, r, failure("InternalServerException", "Missing generated request.", 500))
		return
	}
	out, rejected := p.ExecuteCommand(r.Context(), d)
	if rejected != nil {
		awswire.JSONError(w, r, rejected)
		return
	}
	model, _ := awscatalog.LookupService("eksauth")
	body, err := awsapi.EncodeResponse(model, d.Operation, out)
	if err != nil {
		awswire.JSONError(w, r, podAuthError(err))
		return
	}
	awswire.WriteJSONBytes(w, r, body)
}
func (p *PodIdentityAuth) ExecuteCommand(ctx context.Context, d awsapi.DecodedRequest) (any, *awswire.Error) {
	in, ok := d.Input.(*authapi.AssumeRoleForPodIdentityRequest)
	if !ok || string(d.Operation.Name) != "AssumeRoleForPodIdentity" {
		return nil, failure("InvalidRequestException", "Unsupported EKS Auth request.", 400)
	}
	return p.service.exchangePodIdentity(awsapi.WithDecodedRequest(ctx, d), in)
}
func (p *PodIdentityAuth) RecordRequestError(ctx context.Context, d awsapi.DecodedRequest, e *awswire.Error) error {
	return p.service.recordPodIdentityAuth(ctx, d.Input, nil, e)
}
func (s *Service) recordPodIdentityAuth(ctx context.Context, in, out any, rejected *awswire.Error) error {
	if s.recorder == nil {
		return nil
	}
	model, ok := awscatalog.LookupService("eksauth")
	if !ok {
		return errors.New("EKS Auth generated model is unavailable")
	}
	op, ok := model.Operation("AssumeRoleForPodIdentity")
	if !ok {
		return errors.New("EKS Auth generated operation is unavailable")
	}
	call, err := (apievents.Projection{Category: journal.CategoryManagement, ReadOnly: true}).Call(model, op, in, out, rejected)
	if err != nil {
		return err
	}
	call.EventID = apievents.EventID(ctx)
	sc := scopeFor(ctx)
	return s.recorder.Record(ctx, journal.Envelope{At: s.clock.Now(), Partition: sc.Partition, AccountID: sc.AccountID, Region: sc.Region}, call)
}
func podAuthError(err error) *awswire.Error {
	var rejected *awswire.Error
	if errors.As(err, &rejected) {
		if rejected.Code == "AccessDenied" || rejected.Code == "AccessDeniedException" {
			return failure("AccessDeniedException", rejected.Message, 400)
		}
		return rejected
	}
	if errors.Is(err, ErrNotFound) {
		return failure("ResourceNotFoundException", "The requested cluster or pod identity association does not exist.", 404)
	}
	if errors.Is(err, native.ErrPodIdentityTokenExpired) {
		return failure("ExpiredTokenException", "The Kubernetes service account token has expired.", 400)
	}
	if errors.Is(err, native.ErrPodIdentityToken) {
		return failure("InvalidTokenException", "The token is not a current pod-bound service account token for this cluster and audience.", 400)
	}
	return failure("InternalServerException", "Unable to obtain pod identity credentials.", 500)
}
func (s *Service) authorizePodIdentityNode(ctx context.Context, c Cluster, subject native.PodIdentitySubject) error {
	role, id, err := s.PodIdentityNodeRole(ctx, c.Key, subject.NodeName, subject.NodeUID)
	if err != nil {
		return err
	}
	caller, callerID := principalIdentity(awsctx.FromContext(ctx))
	if caller != role || callerID != id {
		return failure("AccessDeniedException", "The caller is not the current IAM role of the pod's node.", 400)
	}
	return s.authorizePodIdentityCluster(ctx, c)
}
func (s *Service) authorizePodIdentityCluster(ctx context.Context, c Cluster) error {
	now := s.clock.Now()
	conditions := map[string][]string{}
	for key, value := range c.Tags {
		conditions["aws:ResourceTag/"+key] = []string{value}
	}
	if rejected := s.authorizer.Authorize(ctx, authorization.Request{Action: "eks-auth:AssumeRoleForPodIdentity", ResourceARN: c.Key.ARN(), Context: conditions, EvaluationTime: &now}); rejected != nil {
		return rejected
	}
	return nil
}
func (s *Service) exchangePodIdentity(ctx context.Context, in *authapi.AssumeRoleForPodIdentityRequest) (*authapi.AssumeRoleForPodIdentityResponse, *awswire.Error) {
	ctx, err := apievents.Reserve(ctx)
	if err != nil {
		return nil, podAuthError(err)
	}
	ctx, outcomes := apievents.RetainOutcomes(ctx)
	fail := func(err error) (*authapi.AssumeRoleForPodIdentityResponse, *awswire.Error) {
		rejected := podAuthError(err)
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if e := outcomes.Record(completion); e != nil {
			return nil, podAuthError(e)
		}
		if e := s.recordPodIdentityAuth(completion, in, nil, rejected); e != nil {
			return nil, podAuthError(e)
		}
		return nil, rejected
	}
	if value(in.ClusterName) == "" || value(in.Token) == "" {
		return fail(invalid("clusterName and token are required."))
	}
	key := Key{scopeFor(ctx), value(in.ClusterName)}
	var snapshot Cluster
	err = s.repository.View(ctx, func(r Reader) error {
		var e error
		snapshot, e = r.Cluster(key)
		if e != nil {
			return e
		}
		if snapshot.Status != "ACTIVE" && snapshot.Status != "UPDATING" {
			return failure("InvalidRequestException", "Cluster is unavailable.", 400)
		}
		return s.authorizePodIdentityCluster(r.Context(), snapshot)
	})
	if err != nil {
		return fail(err)
	}
	runtime, ok := s.runtime.(native.PodIdentityRuntime)
	if !ok {
		return fail(failure("ServiceUnavailableException", "The selected runtime cannot verify Kubernetes pod identity tokens.", 503))
	}
	subject, err := runtime.ReviewPodIdentityToken(ctx, snapshot.ID, value(in.Token))
	if err != nil {
		return fail(err)
	}
	if in.EksNodeName != nil && value(in.EksNodeName) != subject.NodeName || in.InstanceId != nil && value(in.InstanceId) != subject.InstanceID || in.Zone != nil && value(in.Zone) != subject.Zone {
		return fail(failure("InvalidTokenException", "The supplied node identity does not match the pod's current node.", 400))
	}
	var credential identity.Credential
	var association PodIdentityAssociation
	var out *authapi.AssumeRoleForPodIdentityResponse
	err = s.repository.Attempt(ctx, func(tx Transaction) error {
		current, e := tx.Cluster(key)
		if e != nil {
			return e
		}
		if current.ID != snapshot.ID {
			return ErrNotFound
		}
		if current.Status != "ACTIVE" && current.Status != "UPDATING" {
			return failure("InvalidRequestException", "Cluster is unavailable.", 400)
		}
		all, e := tx.PodIdentityAssociations(key)
		if e != nil {
			return e
		}
		found := false
		for _, a := range all {
			if a.ClusterID == current.ID && a.Namespace == subject.Namespace && a.ServiceAccount == subject.ServiceAccount {
				association = a
				found = true
				break
			}
		}
		if !found {
			return ErrNotFound
		}
		if s.podIdentityRoles == nil {
			return failure("ServiceUnavailableException", "Pod identity role authority is not configured.", 503)
		}
		callctx := tx.Context()
		if e = s.authorizePodIdentityNode(callctx, current, subject); e != nil {
			return e
		}
		if s.principals == nil {
			return errors.New("IAM principal owner is unavailable")
		}
		id, e := s.principals.ResolvePrincipal(callctx, association.RoleARN)
		if e != nil || id != association.RoleID {
			return failure("AccessDeniedException", "The association IAM role was deleted or replaced.", 403)
		}
		if association.TargetRoleARN != "" {
			id, e = s.principals.ResolvePrincipal(callctx, association.TargetRoleARN)
			if e != nil || id != association.TargetRoleID {
				return failure("AccessDeniedException", "The association target IAM role was deleted or replaced.", 403)
			}
		}
		credential, e = s.podIdentityRoles.AssumePodIdentity(callctx, PodIdentitySession{Association: association, PodName: subject.PodName, PodUID: subject.PodUID})
		if e != nil {
			return e
		}
		out = podIdentityAuthAPI(association, credential)
		return s.recordPodIdentityAuth(callctx, in, out, nil)
	})
	if err != nil {
		return fail(err)
	}
	return out, nil
}
func podIdentityAuthAPI(a PodIdentityAssociation, c identity.Credential) *authapi.AssumeRoleForPodIdentityResponse {
	return &authapi.AssumeRoleForPodIdentityResponse{Audience: new(authapi.String(native.PodIdentityAudience)), AssumedRoleUser: &authapi.AssumedRoleUser{Arn: new(authapi.String(c.PrincipalARN)), AssumeRoleId: new(authapi.String(c.PrincipalID))}, Credentials: &authapi.Credentials{AccessKeyId: new(authapi.String(c.AccessKeyID)), SecretAccessKey: new(authapi.String(c.SecretAccessKey)), SessionToken: new(authapi.String(c.SessionToken)), Expiration: &c.Expiration}, PodIdentityAssociation: &authapi.PodIdentityAssociation{AssociationArn: new(authapi.String(a.ARN())), AssociationId: new(authapi.String(a.ID))}, Subject: &authapi.Subject{Namespace: new(authapi.String(a.Namespace)), ServiceAccount: new(authapi.String(a.ServiceAccount))}}
}

// PodIdentityHandler supplies live association admission to the owned webhook.
// Credentials are exchanged only at the SigV4-authenticated EKS Auth frontend.
func (s *Service) PodIdentityHandler(key Key, id string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := awsctx.WithMetadata(r.Context(), awsctx.Metadata{Partition: key.Partition, AccountID: key.AccountID, Region: key.Region})
		switch r.URL.Path {
		case "/association":
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			found := false
			err := s.repository.View(ctx, func(reader Reader) error {
				c, e := reader.Cluster(key)
				if e != nil {
					return e
				}
				if c.ID != id {
					return ErrNotFound
				}
				if c.Status != "ACTIVE" && c.Status != "UPDATING" {
					return failure("ServiceUnavailableException", "Cluster is unavailable.", 503)
				}
				all, e := reader.PodIdentityAssociations(key)
				if e != nil {
					return e
				}
				for _, a := range all {
					if a.ClusterID == id && a.Namespace == r.URL.Query().Get("namespace") && a.ServiceAccount == r.URL.Query().Get("serviceAccount") {
						found = true
						break
					}
				}
				return nil
			})
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if !found {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	})
}

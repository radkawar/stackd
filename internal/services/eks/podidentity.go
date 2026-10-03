package eks

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/eks"
	"stackd/internal/identity"
)

// PodIdentityAssociation binds a cluster incarnation and Kubernetes service account
// to an immutable IAM role. Tokens and credentials are never association state.
type PodIdentityAssociation struct {
	Key                                          Key
	ID, ClusterID, Namespace, ServiceAccount     string
	RoleARN, RoleID, TargetRoleARN, TargetRoleID string
	ExternalID, OwnerARN, Policy                 string
	DisableSessionTags                           bool
	Tags                                         map[string]string
	Created, Modified                            time.Time
	ClientToken                                  string
}

func (a PodIdentityAssociation) ARN() string {
	return "arn:" + a.Key.Partition + ":eks:" + a.Key.Region + ":" + a.Key.AccountID + ":podidentityassociation/" + a.Key.Name + "/" + a.ID
}

type PodIdentityReader interface {
	PodIdentityAssociation(Key, string) (PodIdentityAssociation, error)
	PodIdentityAssociations(Key) ([]PodIdentityAssociation, error)
}
type PodIdentityTransaction interface {
	PodIdentityReader
	PutPodIdentityAssociation(PodIdentityAssociation) error
	DeletePodIdentityAssociation(Key, string) error
}
type PodIdentitySession struct {
	Association     PodIdentityAssociation
	PodName, PodUID string
}

// PodIdentityRoles delegates all credential ownership to IAM/STS.
type PodIdentityRoles interface {
	AssumePodIdentity(context.Context, PodIdentitySession) (identity.Credential, error)
}

func registerPodIdentity(s *Service) {
	register(s, "CreatePodIdentityAssociation", s.createPodIdentityAssociation)
	register(s, "DescribePodIdentityAssociation", s.describePodIdentityAssociation)
	register(s, "ListPodIdentityAssociations", s.listPodIdentityAssociations)
	register(s, "UpdatePodIdentityAssociation", s.updatePodIdentityAssociation)
	register(s, "DeletePodIdentityAssociation", s.deletePodIdentityAssociation)
}

var podNamespacePattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
var podServiceAccountPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

func (s *Service) validatePodIdentity(ctx context.Context, a *PodIdentityAssociation, passRole bool) error {
	if len(a.Namespace) > 63 || !podNamespacePattern.MatchString(a.Namespace) || len(a.ServiceAccount) > 253 || !podServiceAccountPattern.MatchString(a.ServiceAccount) {
		return invalid("namespace and serviceAccount must be valid Kubernetes names.")
	}
	if !podRoleARN(a.RoleARN, a.Key.Partition, a.Key.AccountID) {
		return invalid("roleArn must identify an IAM role in the cluster account and partition.")
	}
	if a.TargetRoleARN != "" && !podRoleARN(a.TargetRoleARN, a.Key.Partition, "") {
		return invalid("targetRoleArn must identify an IAM role in the cluster partition.")
	}
	if a.Policy != "" {
		if !a.DisableSessionTags {
			return invalid("disableSessionTags must be true when policy is supplied.")
		}
		if utf8.RuneCountInString(a.Policy) > 2048 {
			return invalid("Session policy exceeds 2048 characters.")
		}
		if _, err := policy.ParseSession([]byte(a.Policy)); err != nil {
			return invalid("Invalid session policy: " + err.Error())
		}
	}
	if err := validateTags(a.Tags); err != nil {
		return err
	}
	if s.principals == nil {
		return unsupported("IAM principal authority is not configured.")
	}
	if passRole {
		now := s.clock.Now()
		if err := s.authorizer.Authorize(ctx, authorization.Request{Action: "iam:PassRole", ResourceARN: a.RoleARN, Context: map[string][]string{"iam:PassedToService": {"pods.eks.amazonaws.com"}, "iam:AssociatedResourceArn": {a.Key.ARN()}}, EvaluationTime: &now}); err != nil {
			return err
		}
	}
	id, err := s.principals.ResolvePrincipal(ctx, a.RoleARN)
	if err != nil {
		return invalid("The specified IAM role does not exist.")
	}
	if a.RoleID != "" && a.RoleID != id {
		return invalid("The association IAM role was replaced; explicitly update roleArn to authorize the new role.")
	}
	a.RoleID = id
	if a.TargetRoleARN != "" {
		id, err = s.principals.ResolvePrincipal(ctx, a.TargetRoleARN)
		if err != nil {
			return invalid("The specified target IAM role does not exist.")
		}
		if a.TargetRoleID != "" && a.TargetRoleID != id {
			return invalid("The association target IAM role was replaced; explicitly update targetRoleArn to authorize the new role.")
		}
		a.TargetRoleID = id
	}
	a.ExternalID = a.Key.Region + "/" + a.Key.AccountID + "/" + a.Key.Name + "/" + a.Namespace + "/" + a.ServiceAccount
	return nil
}
func podRoleARN(arn, partition, account string) bool {
	p := strings.SplitN(arn, ":", 6)
	return len(p) == 6 && p[0] == "arn" && p[1] == partition && p[2] == "iam" && p[3] == "" && len(p[4]) == 12 && (account == "" || account == p[4]) && strings.HasPrefix(p[5], "role/") && len(p[5]) > 5 && !strings.HasPrefix(p[5], "role/aws-service-role/")
}
func (s *Service) createPodIdentityAssociation(ctx context.Context, tx Transaction, in *api.CreatePodIdentityAssociationRequest) (*api.CreatePodIdentityAssociationResponse, error) {
	key := Key{scopeFor(ctx), value(in.ClusterName)}
	c, err := tx.Cluster(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if errors.Is(err, ErrNotFound) {
		c.Key = key
	}
	if e := s.authorize(ctx, c, "CreatePodIdentityAssociation", tagConditions(tagsFromAPI(in.Tags))); e != nil {
		return nil, e
	}
	if err != nil {
		return nil, err
	}
	if c.Status != "ACTIVE" {
		return nil, failure("ResourceInUseException", "Cluster is not active.", 409)
	}
	if in.ClientRequestToken != nil && (len(value(in.ClientRequestToken)) < 33 || len(value(in.ClientRequestToken)) > 126) {
		return nil, invalid("The client request token parameter must be between 33 and 126 characters.")
	}
	store := tx
	token := value(in.ClientRequestToken)
	all, err := store.PodIdentityAssociations(key)
	if err != nil {
		return nil, err
	}
	duplicate := false
	for _, old := range all {
		if token != "" && old.ClientToken == token {
			return &api.CreatePodIdentityAssociationResponse{Association: podIdentityAPI(old)}, nil
		}
		if old.Namespace == value(in.Namespace) && old.ServiceAccount == value(in.ServiceAccount) {
			duplicate = true
		}
	}
	if duplicate {
		return nil, failure("ResourceInUseException", "A pod identity association already exists for this service account.", 409)
	}
	a := PodIdentityAssociation{Key: key, ClusterID: c.ID, ID: "a-" + strings.ReplaceAll(uuid.NewString(), "-", "")[:17], Namespace: value(in.Namespace), ServiceAccount: value(in.ServiceAccount), RoleARN: value(in.RoleArn), TargetRoleARN: value(in.TargetRoleArn), Policy: value(in.Policy), Tags: tagsFromAPI(in.Tags), ClientToken: token, Created: s.clock.Now(), Modified: s.clock.Now()}
	if in.DisableSessionTags != nil {
		a.DisableSessionTags = bool(*in.DisableSessionTags)
	}
	if err = s.validatePodIdentity(ctx, &a, true); err != nil {
		return nil, err
	}
	if err = store.PutPodIdentityAssociation(a); err != nil {
		return nil, err
	}
	return &api.CreatePodIdentityAssociationResponse{Association: podIdentityAPI(a)}, nil
}
func (s *Service) podIdentityForAction(ctx context.Context, tx Reader, name, id, action string, active bool) (PodIdentityAssociation, error) {
	key := Key{scopeFor(ctx), name}
	c, err := tx.Cluster(key)
	if err != nil {
		return PodIdentityAssociation{}, err
	}
	a, err := tx.PodIdentityAssociation(key, id)
	if err != nil {
		return a, err
	}
	if err = s.authorizeResource(ctx, a.ARN(), a.Tags, action, nil); err != nil {
		return a, err
	}
	if a.ClusterID != c.ID {
		return a, ErrNotFound
	}
	if active && c.Status != "ACTIVE" {
		return a, failure("ResourceInUseException", "Cluster is not active.", 409)
	}
	return a, nil
}
func (s *Service) describePodIdentityAssociation(ctx context.Context, tx Transaction, in *api.DescribePodIdentityAssociationRequest) (*api.DescribePodIdentityAssociationResponse, error) {
	a, err := s.podIdentityForAction(ctx, tx, value(in.ClusterName), value(in.AssociationId), "DescribePodIdentityAssociation", false)
	if err != nil {
		return nil, err
	}
	return &api.DescribePodIdentityAssociationResponse{Association: podIdentityAPI(a)}, nil
}
func (s *Service) updatePodIdentityAssociation(ctx context.Context, tx Transaction, in *api.UpdatePodIdentityAssociationRequest) (*api.UpdatePodIdentityAssociationResponse, error) {
	a, err := s.podIdentityForAction(ctx, tx, value(in.ClusterName), value(in.AssociationId), "UpdatePodIdentityAssociation", true)
	if err != nil {
		return nil, err
	}
	if a.OwnerARN != "" {
		return nil, unsupported("An add-on owned association must be updated through its add-on.")
	}
	if in.ClientRequestToken != nil && (len(value(in.ClientRequestToken)) < 33 || len(value(in.ClientRequestToken)) > 126) {
		return nil, invalid("The client request token parameter must be between 33 and 126 characters.")
	}
	if in.RoleArn != nil {
		a.RoleARN = value(in.RoleArn)
		a.RoleID = ""
	}
	if in.TargetRoleArn != nil {
		a.TargetRoleARN = value(in.TargetRoleArn)
		a.TargetRoleID = ""
	}
	if in.Policy != nil {
		a.Policy = value(in.Policy)
	}
	if in.DisableSessionTags != nil {
		a.DisableSessionTags = bool(*in.DisableSessionTags)
	}
	if err = s.validatePodIdentity(ctx, &a, in.RoleArn != nil); err != nil {
		return nil, err
	}
	a.Modified = s.clock.Now()
	if err = tx.PutPodIdentityAssociation(a); err != nil {
		return nil, err
	}
	return &api.UpdatePodIdentityAssociationResponse{Association: podIdentityAPI(a)}, nil
}
func (s *Service) deletePodIdentityAssociation(ctx context.Context, tx Transaction, in *api.DeletePodIdentityAssociationRequest) (*api.DeletePodIdentityAssociationResponse, error) {
	a, err := s.podIdentityForAction(ctx, tx, value(in.ClusterName), value(in.AssociationId), "DeletePodIdentityAssociation", true)
	if err != nil {
		return nil, err
	}
	if a.OwnerARN != "" {
		return nil, unsupported("An add-on owned association must be deleted through its add-on.")
	}
	if err = tx.DeletePodIdentityAssociation(a.Key, a.ID); err != nil {
		return nil, err
	}
	a.Modified = s.clock.Now()
	return &api.DeletePodIdentityAssociationResponse{Association: podIdentityAPI(a)}, nil
}
func (s *Service) listPodIdentityAssociations(ctx context.Context, tx Transaction, in *api.ListPodIdentityAssociationsRequest) (*api.ListPodIdentityAssociationsResponse, error) {
	c, err := s.load(ctx, tx, value(in.ClusterName), "ListPodIdentityAssociations")
	if err != nil {
		return nil, err
	}
	all, err := tx.PodIdentityAssociations(c.Key)
	if err != nil {
		return nil, err
	}
	names := []string{}
	byID := make(map[string]PodIdentityAssociation, len(all))
	for _, a := range all {
		if a.ClusterID != c.ID || in.Namespace != nil && a.Namespace != value(in.Namespace) || in.ServiceAccount != nil && a.ServiceAccount != value(in.ServiceAccount) {
			continue
		}
		names = append(names, a.ID)
		byID[a.ID] = a
	}
	page, next, err := pageStrings(names, value(in.NextToken), pageLimit(in.MaxResults), c.Key.ARN()+"/"+c.ID+"/podidentities/"+value(in.Namespace)+"/"+value(in.ServiceAccount))
	if err != nil {
		return nil, err
	}
	out := &api.ListPodIdentityAssociationsResponse{Associations: api.PodIdentityAssociationSummaries{}, NextToken: next}
	for _, id := range page {
		a := byID[id]
		v := podIdentityAPI(a)
		out.Associations = append(out.Associations, api.PodIdentityAssociationSummary{AssociationArn: v.AssociationArn, AssociationId: v.AssociationId, ClusterName: v.ClusterName, Namespace: v.Namespace, ServiceAccount: v.ServiceAccount, OwnerArn: v.OwnerArn})
	}
	return out, nil
}
func podIdentityAPI(a PodIdentityAssociation) *api.PodIdentityAssociation {
	out := &api.PodIdentityAssociation{AssociationArn: new(api.String(a.ARN())), AssociationId: new(api.String(a.ID)), ClusterName: new(api.String(a.Key.Name)), Namespace: new(api.String(a.Namespace)), ServiceAccount: new(api.String(a.ServiceAccount)), RoleArn: new(api.String(a.RoleARN)), DisableSessionTags: new(api.BoxedBoolean(a.DisableSessionTags)), CreatedAt: &a.Created, ModifiedAt: &a.Modified, Tags: tagsToAPI(a.Tags)}
	if a.TargetRoleARN != "" {
		out.TargetRoleArn = new(api.String(a.TargetRoleARN))
		out.ExternalId = new(api.String(a.ExternalID))
	}
	if a.OwnerARN != "" {
		out.OwnerArn = new(api.String(a.OwnerARN))
	}
	if a.Policy != "" {
		out.Policy = new(api.String(a.Policy))
	}
	return out
}

package integrations

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"slices"
	"time"

	"stackd/internal/authorization"
	"stackd/internal/awsapi"
	stsapi "stackd/internal/awsapi/sts"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
	eksservice "stackd/internal/services/eks"
)

// EKSPodIdentityRoles uses ordinary ServiceRoles and STS assumptions. It never
// invents access keys or keeps a second session store for Kubernetes workloads.
type EKSPodIdentityRoles struct {
	Roles ServiceRoles
	STS   interface {
		ExecuteCommand(context.Context, awsapi.DecodedRequest) (any, *awswire.Error)
	}
}

func (a EKSPodIdentityRoles) AssumePodIdentity(ctx context.Context, request eksservice.PodIdentitySession) (identity.Credential, error) {
	association := request.Association
	spec := identity.RoleSessionSpec{Role: identity.Principal{ID: association.RoleID}, SessionName: podIdentitySessionName(association.Key.Name, request.PodName), Duration: 6 * time.Hour}
	if !association.DisableSessionTags {
		spec.Tags = map[string]string{"eks-cluster-arn": association.Key.ARN(), "eks-cluster-name": association.Key.Name, "kubernetes-namespace": association.Namespace, "kubernetes-service-account": association.ServiceAccount, "kubernetes-pod-name": request.PodName, "kubernetes-pod-uid": request.PodUID}
		for key := range spec.Tags {
			spec.TransitiveTagKeys = append(spec.TransitiveTagKeys, key)
		}
		slices.Sort(spec.TransitiveTagKeys)
	}
	if association.TargetRoleARN == "" && association.Policy != "" {
		spec.Policies = []string{association.Policy}
		spec.HasSessionPolicy = true
	}
	roles := a.Roles
	if len(spec.Tags) != 0 && roles.Authorizer != nil {
		roles.Authorizer = podIdentityTrust{Authorizer: roles.Authorizer, tags: spec.Tags, keys: spec.TransitiveTagKeys}
	}
	credential, rejected := roles.assume(ctx, awsctx.ServicePrincipal{Name: "pods.eks.amazonaws.com", SourceARN: association.Key.ARN(), Type: "AWSService"}, association.RoleARN, spec, "")
	if rejected != nil {
		return identity.Credential{}, rejected
	}
	if association.TargetRoleARN == "" {
		return credential, nil
	}
	if a.STS == nil || a.Roles.Credentials == nil {
		return identity.Credential{}, errors.New("STS role chaining owner is unavailable")
	}
	callctx, rejected := serviceRoleRequestContext(ctx, credential, association.Key.Region, "pods.eks.amazonaws.com")
	if rejected != nil {
		return identity.Credential{}, rejected
	}
	input := &stsapi.AssumeRoleInput{RoleArn: new(stsapi.ArnType(association.TargetRoleARN)), RoleSessionName: new(stsapi.RoleSessionNameType(spec.SessionName)), DurationSeconds: new(stsapi.RoleDurationSecondsType(3600)), ExternalId: new(stsapi.ExternalIdType(association.ExternalID))}
	// The ordinary STS owner inherits the six transitive tags from the first
	// session. Re-supplying them would correctly reject a transitive-tag override.
	if association.Policy != "" {
		input.Policy = new(stsapi.UnrestrictedSessionPolicyDocumentType(association.Policy))
	}
	model, _ := awscatalog.LookupService("sts")
	op, _ := model.Operation("AssumeRole")
	output, rejected := a.STS.ExecuteCommand(callctx, awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: input})
	if rejected != nil {
		return identity.Credential{}, rejected
	}
	result, ok := output.(*stsapi.AssumeRoleOutput)
	if !ok || result.Credentials == nil || result.Credentials.AccessKeyId == nil {
		return identity.Credential{}, errors.New("STS returned an invalid pod identity session")
	}
	final, err := a.Roles.Credentials.Resolve(callctx, string(*result.Credentials.AccessKeyId))
	if err != nil {
		return identity.Credential{}, err
	}
	if final.IssuerID != association.TargetRoleID || final.IssuerARN != association.TargetRoleARN {
		return identity.Credential{}, errors.New("STS target role incarnation changed")
	}
	return final, nil
}

// Pod Identity trust evaluates the tags being issued, not the node's principal
// tags. Both permissions run within ServiceRoles' current-role transaction, with
// the same trust policy and evaluation time. Ordinary STS owns the chained hop.
type podIdentityTrust struct {
	authorization.Authorizer
	tags map[string]string
	keys []string
}

func (a podIdentityTrust) Authorize(ctx context.Context, request authorization.Request) *awswire.Error {
	for key, value := range a.tags {
		request.Context["aws:requesttag/"+key] = []string{value}
	}
	request.Context["aws:tagkeys"] = a.keys
	request.Context["sts:transitivetagkeys"] = a.keys
	if rejected := a.Authorizer.Authorize(ctx, request); rejected != nil {
		return rejected
	}
	request.Action = "sts:TagSession"
	return a.Authorizer.Authorize(ctx, request)
}

func podIdentitySessionName(cluster, pod string) string {
	// Each exchange creates a distinct STS session, even for the same live pod.
	suffix := uuid.NewString()
	prefix := "eks-" + cluster + "-" + pod
	if len(prefix) > 63-len(suffix) {
		prefix = prefix[:63-len(suffix)]
	}
	return prefix + "-" + suffix
}

var _ eksservice.PodIdentityRoles = EKSPodIdentityRoles{}

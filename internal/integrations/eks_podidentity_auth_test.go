package integrations

import (
	"context"
	"testing"
	"time"

	native "stackd/compute/eks"
	"stackd/internal/awsapi"
	authapi "stackd/internal/awsapi/eksauth"
	"stackd/internal/awscatalog"
	"stackd/internal/awsctx"
	"stackd/internal/identity"
	eks "stackd/internal/services/eks"
	"stackd/internal/services/iam"
)

// The runtime fixture represents an already-reviewed, live pod-bound token.
// EKS association/node lookup, IAM trust and STS credentials remain real owners.
type podIdentityTokenFixture struct {
	native.Runtime
	clusterID string
	subject   native.PodIdentitySubject
	review    func(context.Context) error
}

func (r *podIdentityTokenFixture) ReviewPodIdentityToken(ctx context.Context, id, token string) (native.PodIdentitySubject, error) {
	if id != r.clusterID || token != "current-pod-bound-token" {
		return native.PodIdentitySubject{}, native.ErrPodIdentityToken
	}
	if r.review != nil {
		if err := r.review(ctx); err != nil {
			return native.PodIdentitySubject{}, err
		}
	}
	return r.subject, nil
}

type podIdentityWorkerFixture struct {
	eks.NodegroupCompute
	observation eks.NodegroupObservation
}

func (w podIdentityWorkerFixture) Observe(context.Context, eks.Nodegroup) (eks.NodegroupObservation, error) {
	return w.observation, nil
}

func TestEKSPodIdentityCredentialsAcrossControlPlaneUpdates(t *testing.T) {
	for _, transition := range []string{"updating before review", "updating during review", "deleting during review", "replaced during review", "association removed during review"} {
		t.Run(transition, func(t *testing.T) {
			f := newPodIdentityRoleFixture(t, "memory")
			association := f.request.Association
			key := association.Key
			cluster := eks.Cluster{Key: key, ID: association.ClusterID, Status: "ACTIVE"}
			repository := f.commands
			nodeRole := iam.Role{Arn: "arn:aws:iam::123456789012:role/node", RoleId: "AROAPODNODE", RoleName: "node", MaxSessionDuration: 3600,
				AssumeRolePolicyDocument: podIdentityTrustPolicy(t, "Service", "ec2.amazonaws.com", []string{"sts:AssumeRole"}, nil),
				IdentityPolicies:         iam.IdentityPolicies{Inline: map[string]string{"eks-auth": `{"Statement":{"Effect":"Allow","Action":"eks-auth:AssumeRoleForPodIdentity","Resource":"` + key.ARN() + `"}}`}}}
			f.putRole(t, nodeRole)
			nodeCredential, rejected := f.adapter.Roles.assume(f.ctx, awsctx.ServicePrincipal{Name: "ec2.amazonaws.com", SourceARN: "arn:aws:ec2:us-east-1:123456789012:instance/i-podnode", Type: "AWSService"}, nodeRole.Arn, identity.RoleSessionSpec{SessionName: "pod-node", Duration: 12 * time.Hour}, "")
			if rejected != nil {
				t.Fatal(rejected)
			}
			metadata, err := identity.RequestMetadata(nodeCredential, nodeCredential.AccessKeyID, key.Region, "pod-exchange")
			if err != nil {
				t.Fatal(err)
			}
			ctx := awsctx.WithMetadata(f.ctx, metadata)
			worker := eks.NodegroupWorker{NodeName: "node-a", NodeUID: "node-incarnation", InstanceID: "i-podnode", PrivateIP: "10.0.0.2", LifecycleState: "InService", Ready: true}
			group := eks.Nodegroup{Key: eks.NodegroupKey{Cluster: key, Name: "workers"}, ID: "group-incarnation", ClusterID: cluster.ID, Status: "ACTIVE", NodeRoleARN: nodeRole.Arn, NodeRoleID: nodeRole.RoleId, Workers: []eks.NodegroupWorker{worker}}
			if err := repository.Update(ctx, func(tx eks.Transaction) error {
				if err := tx.PutCluster(cluster); err != nil {
					return err
				}
				if err := tx.PutNodegroup(group); err != nil {
					return err
				}
				return tx.PutPodIdentityAssociation(association)
			}); err != nil {
				t.Fatal(err)
			}
			runtime := &podIdentityTokenFixture{clusterID: cluster.ID, subject: native.PodIdentitySubject{Namespace: association.Namespace, ServiceAccount: association.ServiceAccount, PodName: f.request.PodName, PodUID: f.request.PodUID, NodeName: worker.NodeName, NodeUID: worker.NodeUID}}
			service := eks.New(eks.Config{Repository: repository, Clock: f.clock, Runtime: runtime, Principals: EKSPrincipals{IAM: f.owner}, Authorizer: f.adapter.Roles.Authorizer, PodIdentityRoles: f.adapter, Nodegroups: podIdentityWorkerFixture{observation: eks.NodegroupObservation{Workers: []eks.NodegroupWorker{worker}}}})
			t.Cleanup(func() { _ = service.Close() })
			model, _ := awscatalog.LookupService("eksauth")
			op, _ := model.Operation("AssumeRoleForPodIdentity")
			request := awsapi.DecodedRequest{Operation: op, Protocol: model.Protocol, Input: &authapi.AssumeRoleForPodIdentityRequest{ClusterName: new(authapi.ClusterName(key.Name)), Token: new(authapi.JwtToken("current-pod-bound-token"))}}
			output, rejected := service.PodIdentityAuth().ExecuteCommand(ctx, request)
			if rejected != nil {
				t.Fatal(rejected)
			}
			first := output.(*authapi.AssumeRoleForPodIdentityResponse)
			firstKey := string(*first.Credentials.AccessKeyId)
			change := func(ctx context.Context) error {
				return repository.Update(ctx, func(tx eks.Transaction) error {
					current, err := tx.Cluster(key)
					if err != nil {
						return err
					}
					switch transition {
					case "deleting during review":
						current.Status = "DELETING"
					case "replaced during review":
						current.ID = "replacement-cluster"
					case "association removed during review":
						return tx.DeletePodIdentityAssociation(key, association.ID)
					default:
						current.Status = "UPDATING"
					}
					return tx.PutCluster(current)
				})
			}
			if transition == "updating before review" {
				if err := change(ctx); err != nil {
					t.Fatal(err)
				}
			} else {
				runtime.review = change
			}
			if err := f.clock.Advance(5 * time.Hour); err != nil {
				t.Fatal(err)
			}
			output, rejected = service.PodIdentityAuth().ExecuteCommand(ctx, request)
			switch transition {
			case "deleting during review":
				if rejected == nil || rejected.Code != "InvalidRequestException" {
					t.Fatalf("deleting cluster refreshed credentials: %v", rejected)
				}
			case "replaced during review", "association removed during review":
				if rejected == nil || rejected.Code != "ResourceNotFoundException" {
					t.Fatalf("stale pod association refreshed credentials: %v", rejected)
				}
			default:
				if rejected != nil {
					t.Fatalf("control-plane update blocked pod refresh: %v", rejected)
				}
				refreshed := output.(*authapi.AssumeRoleForPodIdentityResponse)
				newKey := string(*refreshed.Credentials.AccessKeyId)
				if newKey == firstKey || !refreshed.Credentials.Expiration.After(*first.Credentials.Expiration) {
					t.Fatal("pod refresh reused the expiring session")
				}
				retained, err := f.adapter.Roles.Credentials.Resolve(ctx, newKey)
				if err != nil {
					t.Fatal(err)
				}
				f.requireCredential(t, retained, f.role, false)
				if _, err := f.adapter.Roles.Credentials.Resolve(ctx, firstKey); err != nil {
					t.Fatalf("control-plane update revoked the existing session: %v", err)
				}
			}
		})
	}
}

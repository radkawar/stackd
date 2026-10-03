package integrations

import (
	"testing"
	"time"

	"stackd/internal/awsctx"
	"stackd/internal/identity"
	"stackd/internal/services/iam"
)

func TestTaggedServiceRoleTrustAndImmutableRelationship(t *testing.T) {
	f := newLambdaRoleFixture(t)
	const cluster = "arn:aws:eks:us-east-1:123456789012:cluster/workloads"
	source := awsctx.ServicePrincipal{Name: "pods.eks.amazonaws.com", SourceARN: cluster, Type: "AWSService"}
	session := identity.RoleSessionSpec{Role: identity.Principal{ID: f.role.RoleId}, SessionName: "pod", Duration: 6 * time.Hour, Tags: map[string]string{"kubernetes-namespace": "payments"}, TransitiveTagKeys: []string{"kubernetes-namespace"}}
	assume := func() (identity.Credential, error) {
		credential, rejected := f.adapter.ServiceRoles.assume(f.ctx, source, f.role.Arn, session, "")
		if rejected != nil {
			return credential, rejected
		}
		return credential, nil
	}
	setTrust := func(actions string) {
		f.role.AssumeRolePolicyDocument = `{"Statement":{"Effect":"Allow","Principal":{"Service":"pods.eks.amazonaws.com"},"Action":` + actions + `,"Condition":{"ArnEquals":{"aws:SourceArn":"` + cluster + `"},"StringEquals":{"aws:RequestTag/kubernetes-namespace":"payments"},"ForAllValues:StringEquals":{"aws:TagKeys":["kubernetes-namespace"],"sts:TransitiveTagKeys":["kubernetes-namespace"]}}}}`
		f.update(t, func(tx iam.WriteTx) error { return tx.PutRole(f.scope, f.role) })
	}
	setTrust(`"sts:AssumeRole"`)
	if credential, err := assume(); err == nil || credential.AccessKeyID != "" {
		t.Fatal("AssumeRole-only trust issued a tagged session", err)
	}
	setTrust(`["sts:AssumeRole","sts:TagSession"]`)
	credential, err := assume()
	if err != nil {
		t.Fatal(err)
	}
	retained, err := f.adapter.Credentials.Resolve(f.ctx, credential.AccessKeyID)
	if err != nil || retained.SessionTags["kubernetes-namespace"] != "payments" || len(retained.TransitiveTagKeys) != 1 || retained.TransitiveTagKeys[0] != "kubernetes-namespace" || retained.Expiration.Sub(retained.CreateDate) != 6*time.Hour {
		t.Fatalf("tagged service session lost retained authority or service duration: %+v, %v", retained, err)
	}
	session.Tags["kubernetes-namespace"] = "other"
	if credential, err := assume(); err == nil || credential.AccessKeyID != "" {
		t.Fatal("request-tag condition did not deny the other namespace", err)
	}
	session.Tags["kubernetes-namespace"] = "payments"
	f.role.RoleId = "AROARECREATED"
	setTrust(`["sts:AssumeRole","sts:TagSession"]`)
	if credential, err := assume(); err == nil || credential.AccessKeyID != "" {
		t.Fatal("recreated role inherited a relationship to the deleted role identity", err)
	}
}

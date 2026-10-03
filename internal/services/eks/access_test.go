package eks_test

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/eks"
	"stackd/internal/services/eks"
)

func TestAccessUpdateReplayCannotResurrectRevokedGroups(t *testing.T) {
	client, repository, _ := sdkFixture(t)
	key := eks.Key{Scope: eks.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "access-replay"}
	principal := "arn:aws:iam::111111111111:user/developer"
	if e := repository.Update(t.Context(), func(tx eks.Transaction) error {
		if e := tx.PutCluster(eks.Cluster{Key: key, ID: "incarnation", Status: "ACTIVE", AuthenticationMode: "API"}); e != nil {
			return e
		}
		return tx.PutAccessEntry(eks.AccessEntry{Key: key, ID: "entry-incarnation", PrincipalARN: principal, PrincipalID: "immutable-user", Username: principal, Type: "STANDARD", Created: time.Unix(1, 0)})
	}); e != nil {
		t.Fatal(e)
	}
	grant := &sdk.UpdateAccessEntryInput{ClusterName: aws.String(key.Name), PrincipalArn: aws.String(principal), KubernetesGroups: []string{"developers"}, ClientRequestToken: aws.String("grant-before-revocation")}
	if _, e := client.UpdateAccessEntry(t.Context(), grant); e != nil {
		t.Fatal(e)
	}
	if _, e := client.UpdateAccessEntry(t.Context(), &sdk.UpdateAccessEntryInput{ClusterName: aws.String(key.Name), PrincipalArn: aws.String(principal), KubernetesGroups: []string{}, ClientRequestToken: aws.String("revocation")}); e != nil {
		t.Fatal(e)
	}
	if _, e := client.UpdateAccessEntry(t.Context(), grant); e != nil {
		t.Fatal(e)
	}
	result, e := client.DescribeAccessEntry(t.Context(), &sdk.DescribeAccessEntryInput{ClusterName: aws.String(key.Name), PrincipalArn: aws.String(principal)})
	if e != nil {
		t.Fatal(e)
	}
	if len(result.AccessEntry.KubernetesGroups) != 0 {
		t.Fatalf("old grant replay resurrected groups: %v", result.AccessEntry.KubernetesGroups)
	}
	grant.KubernetesGroups = []string{"administrators"}
	if _, e = client.UpdateAccessEntry(t.Context(), grant); e == nil {
		t.Fatal("same token admitted different authority")
	}
}

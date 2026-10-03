package eks_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	sdk "github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/smithy-go"
	api "stackd/internal/awsapi/eks"
	"stackd/internal/awscatalog"
	"stackd/internal/gateway"
	"stackd/internal/services/eks"
)

func sdkFixture(t *testing.T) (*sdk.Client, *eks.MemoryRepository, string) {
	t.Helper()
	repository := eks.NewMemoryRepository(nil)
	service := eks.New(eks.Config{Repository: repository})
	t.Cleanup(func() { _ = service.Close() })
	model, _ := awscatalog.LookupService("eks")
	registry := &gateway.Registry{}
	if e := registry.Register(gateway.Service{Name: "eks", SigningName: "eks", Protocol: gateway.RestJSON, Model: &model, Provider: service, Decode: api.DecodeRequest}); e != nil {
		t.Fatal(e)
	}
	handler, e := gateway.New(registry, gateway.Config{AccountID: "111111111111"})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return sdk.NewFromConfig(aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("test", "test", "")}, func(o *sdk.Options) { o.BaseEndpoint = aws.String(server.URL) }), repository, server.URL
}
func TestSDKControlFixtureAndScopedPagination(t *testing.T) {
	client, repository, endpoint := sdkFixture(t)
	var fixture struct {
		SupportedPolicyNames []string `json:"supportedPolicyNames"`
		NativeObservations   struct {
			DescribeCluster struct{ Name, ErrorCode string }
		}
	}
	b, e := os.ReadFile("../../../testdata/aws/eks/control_kernel.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &fixture); e != nil {
		t.Fatal(e)
	}
	paginator := sdk.NewListAccessPoliciesPaginator(client, &sdk.ListAccessPoliciesInput{MaxResults: aws.Int32(1)})
	var names []string
	for paginator.HasMorePages() {
		p, e := paginator.NextPage(t.Context())
		if e != nil {
			t.Fatal(e)
		}
		for _, policy := range p.AccessPolicies {
			names = append(names, aws.ToString(policy.Name))
		}
	}
	if !reflect.DeepEqual(names, fixture.SupportedPolicyNames) {
		t.Fatalf("policy catalog = %v", names)
	}
	_, e = client.DescribeCluster(t.Context(), &sdk.DescribeClusterInput{Name: aws.String(fixture.NativeObservations.DescribeCluster.Name)})
	var apiError smithy.APIError
	if !errors.As(e, &apiError) || apiError.ErrorCode() != fixture.NativeObservations.DescribeCluster.ErrorCode {
		t.Fatalf("native absent cluster contract: %v", e)
	}
	scopes := []eks.Scope{{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, {Partition: "aws", AccountID: "222222222222", Region: "us-east-1"}, {Partition: "aws", AccountID: "111111111111", Region: "us-west-2"}}
	e = repository.Update(t.Context(), func(tx eks.Transaction) error {
		for _, scope := range scopes {
			for _, name := range []string{"alpha", "bravo", "charlie"} {
				if e := tx.PutCluster(eks.Cluster{Key: eks.Key{Scope: scope, Name: name}, ID: scope.Region + scope.AccountID + name, Status: "ACTIVE", KubernetesVersion: "1.33", Created: time.Unix(123, 0), Tags: map[string]string{"scope": scope.Region + scope.AccountID}}); e != nil {
					return e
				}
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	first, e := client.ListClusters(t.Context(), &sdk.ListClustersInput{MaxResults: aws.Int32(2)})
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(first.Clusters, []string{"alpha", "bravo"}) || first.NextToken == nil {
		t.Fatalf("first page: %#v", first)
	}
	second, e := client.ListClusters(t.Context(), &sdk.ListClustersInput{MaxResults: aws.Int32(2), NextToken: first.NextToken})
	if e != nil || !reflect.DeepEqual(second.Clusters, []string{"charlie"}) || second.NextToken != nil {
		t.Fatalf("second page: %#v %v", second, e)
	}
	regional := sdk.NewFromConfig(aws.Config{Region: "us-west-2", Credentials: credentials.NewStaticCredentialsProvider("test", "test", "")}, func(o *sdk.Options) { o.BaseEndpoint = aws.String(endpoint) })
	_, e = regional.ListClusters(t.Context(), &sdk.ListClustersInput{NextToken: first.NextToken})
	if !errors.As(e, &apiError) || apiError.ErrorCode() != "InvalidParameterException" {
		t.Fatalf("cross-region cursor accepted: %v", e)
	}
	arn := "arn:aws:eks:us-east-1:111111111111:cluster/alpha"
	if _, e = client.TagResource(t.Context(), &sdk.TagResourceInput{ResourceArn: aws.String(arn), Tags: map[string]string{"owner": "changed"}}); e != nil {
		t.Fatal(e)
	}
	e = repository.View(context.Background(), func(tx eks.Reader) error {
		foreign, e := tx.Cluster(eks.Key{Scope: scopes[1], Name: "alpha"})
		if e != nil {
			return e
		}
		if foreign.Tags["owner"] != "" {
			t.Fatal("tag mutation crossed account")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

func TestChildTagsRejectReplacedResourceARN(t *testing.T) {
	key := eks.Key{Scope: eks.Scope{Partition: "aws", AccountID: "111111111111", Region: "us-east-1"}, Name: "tag-owner"}
	for _, kind := range []string{"nodegroup", "addon", "fargateprofile", "podidentityassociation"} {
		t.Run(kind, func(t *testing.T) {
			client, repository, _ := sdkFixture(t)
			var oldARN, currentARN string
			put := func(id string) error {
				return repository.Update(t.Context(), func(tx eks.Transaction) error {
					if err := tx.PutCluster(eks.Cluster{Key: key, ID: "cluster-incarnation", Status: "ACTIVE"}); err != nil {
						return err
					}
					tags := map[string]string{"owner": id}
					switch kind {
					case "nodegroup":
						n := eks.Nodegroup{Key: eks.NodegroupKey{Cluster: key, Name: "workers"}, ID: id, Tags: tags}
						currentARN = n.Key.ARN(id)
						return tx.PutNodegroup(n)
					case "addon":
						a := eks.Addon{Key: key, Name: "coredns", ID: id, Tags: tags}
						currentARN = a.ARN()
						return tx.PutAddon(a)
					case "fargateprofile":
						p := eks.FargateProfile{Key: key, Name: "selected-pods", ID: id, Tags: tags}
						currentARN = p.ARN()
						return tx.PutFargateProfile(p)
					default:
						if err := tx.DeletePodIdentityAssociation(key, "old-incarnation"); err != nil {
							return err
						}
						a := eks.PodIdentityAssociation{Key: key, ID: id, Namespace: "workloads", ServiceAccount: "application", Tags: tags}
						currentARN = a.ARN()
						return tx.PutPodIdentityAssociation(a)
					}
				})
			}
			if err := put("old-incarnation"); err != nil {
				t.Fatal(err)
			}
			oldARN = currentARN
			if err := put("new-incarnation"); err != nil {
				t.Fatal(err)
			}
			_, err := client.TagResource(t.Context(), &sdk.TagResourceInput{ResourceArn: aws.String(oldARN), Tags: map[string]string{"owner": "stale-caller"}})
			if err == nil {
				t.Fatalf("stale resource ARN accepted: %v", err)
			}
			_, err = client.UntagResource(t.Context(), &sdk.UntagResourceInput{ResourceArn: aws.String(oldARN), TagKeys: []string{"owner"}})
			if err == nil {
				t.Fatalf("stale resource ARN removed replacement tags: %v", err)
			}
			tags, err := client.ListTagsForResource(t.Context(), &sdk.ListTagsForResourceInput{ResourceArn: aws.String(currentARN)})
			if err != nil || !reflect.DeepEqual(tags.Tags, map[string]string{"owner": "new-incarnation"}) {
				t.Fatalf("replacement tags changed: %#v %v", tags, err)
			}
			if _, err := client.TagResource(t.Context(), &sdk.TagResourceInput{ResourceArn: aws.String(currentARN), Tags: map[string]string{"purpose": "current"}}); err != nil {
				t.Fatal(err)
			}
			tags, err = client.ListTagsForResource(t.Context(), &sdk.ListTagsForResourceInput{ResourceArn: aws.String(currentARN)})
			if err != nil || !reflect.DeepEqual(tags.Tags, map[string]string{"owner": "new-incarnation", "purpose": "current"}) {
				t.Fatalf("current resource tags were not persisted: %#v %v", tags, err)
			}
		})
	}
}

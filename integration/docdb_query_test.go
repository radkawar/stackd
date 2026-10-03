package stackd_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	docdbsdk "github.com/aws/aws-sdk-go-v2/service/docdb"
	rdssdk "github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"stackd"
	"stackd/storage"
	docdbstore "stackd/storage/docdb"
	rdsstore "stackd/storage/rds"
)

// Native clients share the RDS endpoint: neither user-agent nor an invented
// service hostname can select a private list or a different identifier owner.
func TestDocumentDBSharedQueryUnionAndOwnerRouting(t *testing.T) {
	backend := storage.NewMemory()
	account := "123456789012"
	created := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	expected := []string{}
	for i := range 24 {
		name := fmt.Sprintf("shared-%02d", i)
		expected = append(expected, name)
		if i%2 == 0 {
			e := backend.DocumentDB.Update(t.Context(), func(tx docdbstore.Transaction) error {
				return tx.PutCluster(docdbstore.Cluster{Key: docdbstore.Key{Scope: docdbstore.Scope{Partition: "aws", AccountID: account, Region: "us-east-1"}, Kind: "cluster", Name: name}, RuntimeID: name, EngineVersion: "5.0", Status: "creating", Created: created, Version: 1})
			})
			if e != nil {
				t.Fatal(e)
			}
		} else {
			e := backend.RDS.Update(t.Context(), func(tx rdsstore.Transaction) error {
				return tx.PutDatabase(rdsstore.Database{Key: rdsstore.Key{Scope: rdsstore.Scope{Partition: "aws", AccountID: account, Region: "us-east-1"}, Kind: "cluster", Name: name}, RuntimeID: name, Engine: "aurora-postgresql", EngineVersion: "17.11", Status: "creating", Created: created, Version: 1})
			})
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	cloud, server := startPublicCloud(t, stackd.Config{AccountID: account, Storage: backend})
	defer cloud.Close()
	defer server.Close()
	credentials := credentials.NewStaticCredentialsProvider("test", "test", "")
	rds := rdssdk.New(rdssdk.Options{BaseEndpoint: aws.String(server.URL), Region: "us-east-1", Credentials: credentials, RetryMaxAttempts: 1})
	docdb := docdbsdk.New(docdbsdk.Options{BaseEndpoint: aws.String(server.URL), Region: "us-east-1", Credentials: credentials, RetryMaxAttempts: 1})
	page, e := rds.DescribeDBClusters(t.Context(), &rdssdk.DescribeDBClustersInput{MaxRecords: aws.Int32(20)})
	if e != nil {
		t.Fatal(e)
	}
	if len(page.DBClusters) != 20 || page.Marker == nil {
		t.Fatalf("shared first page: %d marker=%v", len(page.DBClusters), page.Marker)
	}
	names := []string{}
	for _, v := range page.DBClusters {
		names = append(names, aws.ToString(v.DBClusterIdentifier))
	}
	// The next request comes from the other official SDK, proving one public
	// pagination namespace rather than private owner markers.
	next, e := docdb.DescribeDBClusters(t.Context(), &docdbsdk.DescribeDBClustersInput{MaxRecords: aws.Int32(20), Marker: page.Marker})
	if e != nil {
		t.Fatal(e)
	}
	for _, v := range next.DBClusters {
		names = append(names, aws.ToString(v.DBClusterIdentifier))
	}
	if !slices.Equal(names, expected) || next.Marker != nil {
		t.Fatalf("shared pagination lost or duplicated owners: %v marker=%v", names, next.Marker)
	}
	filtered, e := rds.DescribeDBClusters(t.Context(), &rdssdk.DescribeDBClustersInput{Filters: []rdstypes.Filter{{Name: aws.String("engine"), Values: []string{"docdb"}}}})
	if e != nil {
		t.Fatal(e)
	}
	if len(filtered.DBClusters) != 12 {
		t.Fatalf("engine filter lost DocumentDB rows: %d", len(filtered.DBClusters))
	}
	for _, v := range filtered.DBClusters {
		if aws.ToString(v.Engine) != "docdb" {
			t.Fatalf("engine filter returned %q", aws.ToString(v.Engine))
		}
	}
	named, e := docdb.DescribeDBClusters(t.Context(), &docdbsdk.DescribeDBClustersInput{DBClusterIdentifier: aws.String("shared-00")})
	if e != nil {
		t.Fatal(e)
	}
	if len(named.DBClusters) != 1 || aws.ToString(named.DBClusters[0].Engine) != "docdb" {
		t.Fatalf("wrong authoritative engine: %#v", named.DBClusters)
	}
	_, e = rds.ModifyDBCluster(t.Context(), &rdssdk.ModifyDBClusterInput{DBClusterIdentifier: aws.String("shared-00"), EnableHttpEndpoint: aws.Bool(true)})
	assertAPIError(t, e, "InvalidParameterCombination")
	_, e = docdb.ModifyDBCluster(t.Context(), &docdbsdk.ModifyDBClusterInput{DBClusterIdentifier: aws.String("shared-00"), DeletionProtection: aws.Bool(true)})
	if e != nil {
		t.Fatal(e)
	}
	namedRDS, e := rds.DescribeDBClusters(t.Context(), &rdssdk.DescribeDBClustersInput{DBClusterIdentifier: aws.String("shared-00")})
	if e != nil {
		t.Fatal(e)
	}
	if !aws.ToBool(namedRDS.DBClusters[0].DeletionProtection) {
		t.Fatal("mutation did not reach authoritative DocumentDB owner")
	}
}

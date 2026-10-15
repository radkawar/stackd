package stackd_test

import (
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	docdbsdk "github.com/aws/aws-sdk-go-v2/service/docdb"
	rdssdk "github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"stackd"
)

func globalRDS(c cloudClients, region, key, secret string) *rdssdk.Client {
	return rdssdk.New(rdssdk.Options{BaseEndpoint: aws.String(c.server.URL), Region: region, Credentials: credentials.NewStaticCredentialsProvider(key, secret, ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func globalDocDB(c cloudClients, region, key string) *docdbsdk.Client {
	return docdbsdk.New(docdbsdk.Options{BaseEndpoint: aws.String(c.server.URL), Region: region, Credentials: credentials.NewStaticCredentialsProvider(key, "test", ""), HTTPClient: c.server.Client(), RetryMaxAttempts: 1})
}

func TestGlobalClusterSDKRetainedEmptyLifecycle(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			c, reopen := retainedCloud(t, backend, stackd.Config{})
			rds := globalRDS(c, "us-east-1", "test", "test")
			doc := globalDocDB(c, "us-west-2", "test")
			absent, err := doc.DescribeGlobalClusters(t.Context(), &docdbsdk.DescribeGlobalClustersInput{})
			if err != nil || len(absent.GlobalClusters) != 0 || absent.Marker != nil {
				t.Fatalf("initial absence: %#v %v", absent, err)
			}
			_, err = rds.DescribeGlobalClusters(t.Context(), &rdssdk.DescribeGlobalClustersInput{GlobalClusterIdentifier: aws.String("missing")})
			assertAPIError(t, err, "GlobalClusterNotFoundFault")
			created, err := rds.CreateGlobalCluster(t.Context(), &rdssdk.CreateGlobalClusterInput{GlobalClusterIdentifier: aws.String("Owned-Aurora"), Engine: aws.String("aurora-postgresql"), EngineVersion: aws.String("16.6"), DatabaseName: aws.String("configuration"), StorageEncrypted: aws.Bool(true), DeletionProtection: aws.Bool(true), Tags: []rdstypes.Tag{{Key: aws.String("owner"), Value: aws.String("team")}}})
			if err != nil {
				t.Fatal(err)
			}
			arn := "arn:aws:rds::000000000000:global-cluster:owned-aurora"
			id := aws.ToString(created.GlobalCluster.GlobalClusterResourceId)
			if aws.ToString(created.GlobalCluster.GlobalClusterArn) != arn || id == "" || len(created.GlobalCluster.GlobalClusterMembers) != 0 || created.GlobalCluster.Endpoint != nil || aws.ToString(created.GlobalCluster.Status) != "available" {
				t.Fatalf("global metadata fabricated topology: %#v", created.GlobalCluster)
			}
			_, err = doc.CreateGlobalCluster(t.Context(), &docdbsdk.CreateGlobalClusterInput{GlobalClusterIdentifier: aws.String("owned-documents"), Engine: aws.String("docdb"), EngineVersion: aws.String("5.0")})
			if err != nil {
				t.Fatal(err)
			}
			// The SDK cannot select a private global namespace on the shared wire.
			listed, err := doc.DescribeGlobalClusters(t.Context(), &docdbsdk.DescribeGlobalClustersInput{})
			if err != nil || len(listed.GlobalClusters) != 2 {
				t.Fatalf("shared real owner list: %#v %v", listed, err)
			}
			_, err = doc.CreateGlobalCluster(t.Context(), &docdbsdk.CreateGlobalClusterInput{GlobalClusterIdentifier: aws.String("OWNED-AURORA"), Engine: aws.String("docdb")})
			assertAPIError(t, err, "GlobalClusterAlreadyExistsFault")
			for _, isolated := range []*rdssdk.Client{globalRDS(c, "eu-west-1", "111111111111", "test"), globalRDS(c, "cn-north-1", "test", "test")} {
				list, err := isolated.DescribeGlobalClusters(t.Context(), &rdssdk.DescribeGlobalClustersInput{})
				if err != nil || len(list.GlobalClusters) != 0 {
					t.Fatalf("global namespace crossed account/partition: %#v %v", list, err)
				}
				_, err = isolated.DescribeGlobalClusters(t.Context(), &rdssdk.DescribeGlobalClustersInput{GlobalClusterIdentifier: aws.String(arn)})
				assertAPIError(t, err, "GlobalClusterNotFoundFault")
			}
			for _, filter := range []rdstypes.Filter{{Name: aws.String("region"), Values: []string{"us-east-1"}}, {Name: aws.String("db-cluster-id"), Values: []string{"owned-aurora", arn}}} {
				list, err := rds.DescribeGlobalClusters(t.Context(), &rdssdk.DescribeGlobalClustersInput{Filters: []rdstypes.Filter{filter}})
				if err != nil || len(list.GlobalClusters) != 0 {
					t.Fatalf("empty global metadata acquired a regional member: %#v %v", list, err)
				}
			}
			_, err = doc.DeleteGlobalCluster(t.Context(), &docdbsdk.DeleteGlobalClusterInput{GlobalClusterIdentifier: aws.String("owned-aurora")})
			assertAPIError(t, err, "InvalidGlobalClusterStateFault")
			_, err = rds.ModifyGlobalCluster(t.Context(), &rdssdk.ModifyGlobalClusterInput{GlobalClusterIdentifier: aws.String(arn), NewGlobalClusterIdentifier: aws.String("renamed-aurora"), DeletionProtection: aws.Bool(false)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = doc.ModifyGlobalCluster(t.Context(), &docdbsdk.ModifyGlobalClusterInput{GlobalClusterIdentifier: aws.String("owned-documents"), DeletionProtection: aws.Bool(true)})
			if err != nil {
				t.Fatal(err)
			}
			c = reopen()
			rds = globalRDS(c, "ap-southeast-2", "test", "test")
			doc = globalDocDB(c, "eu-west-1", "test")
			_, err = rds.DescribeGlobalClusters(t.Context(), &rdssdk.DescribeGlobalClustersInput{GlobalClusterIdentifier: aws.String("owned-aurora")})
			assertAPIError(t, err, "GlobalClusterNotFoundFault")
			retained, err := rds.DescribeGlobalClusters(t.Context(), &rdssdk.DescribeGlobalClustersInput{GlobalClusterIdentifier: aws.String("RENAMED-AURORA")})
			if err != nil || len(retained.GlobalClusters) != 1 {
				t.Fatalf("reopen/global lookup: %#v %v", retained, err)
			}
			v := retained.GlobalClusters[0]
			if aws.ToString(v.GlobalClusterResourceId) != id || aws.ToString(v.DatabaseName) != "configuration" || !aws.ToBool(v.StorageEncrypted) || aws.ToBool(v.DeletionProtection) || aws.ToString(v.EngineVersion) != "16.6" || len(v.TagList) != 1 || len(v.GlobalClusterMembers) != 0 || v.Endpoint != nil {
				t.Fatalf("retained metadata changed or claimed a data plane: %#v", v)
			}
			_, err = rds.AddTagsToResource(t.Context(), &rdssdk.AddTagsToResourceInput{ResourceName: v.GlobalClusterArn, Tags: []rdstypes.Tag{{Key: aws.String("owner"), Value: aws.String("changed")}}})
			if err != nil {
				t.Fatal(err)
			}
			tags, err := doc.ListTagsForResource(t.Context(), &docdbsdk.ListTagsForResourceInput{ResourceName: v.GlobalClusterArn})
			if err != nil || len(tags.TagList) != 1 || aws.ToString(tags.TagList[0].Value) != "changed" {
				t.Fatalf("global tag owner: %#v %v", tags, err)
			}
			_, err = rds.RemoveTagsFromResource(t.Context(), &rdssdk.RemoveTagsFromResourceInput{ResourceName: v.GlobalClusterArn, TagKeys: []string{"owner"}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = rds.DeleteGlobalCluster(t.Context(), &rdssdk.DeleteGlobalClusterInput{GlobalClusterIdentifier: aws.String("renamed-aurora")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = doc.ModifyGlobalCluster(t.Context(), &docdbsdk.ModifyGlobalClusterInput{GlobalClusterIdentifier: aws.String("owned-documents"), DeletionProtection: aws.Bool(false)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = doc.DeleteGlobalCluster(t.Context(), &docdbsdk.DeleteGlobalClusterInput{GlobalClusterIdentifier: aws.String("owned-documents")})
			if err != nil {
				t.Fatal(err)
			}
			_, err = rds.DeleteGlobalCluster(t.Context(), &rdssdk.DeleteGlobalClusterInput{GlobalClusterIdentifier: aws.String("renamed-aurora")})
			assertAPIError(t, err, "GlobalClusterNotFoundFault")
			reused, err := rds.CreateGlobalCluster(t.Context(), &rdssdk.CreateGlobalClusterInput{GlobalClusterIdentifier: aws.String("renamed-aurora"), Engine: aws.String("aurora-mysql"), EngineVersion: aws.String("8.0.mysql_aurora.3.09.0")})
			if err != nil {
				t.Fatal(err)
			}
			if aws.ToString(reused.GlobalCluster.GlobalClusterResourceId) == id || len(reused.GlobalCluster.TagList) != 0 || aws.ToBool(reused.GlobalCluster.StorageEncrypted) {
				t.Fatalf("name reuse inherited incarnation: %#v", reused.GlobalCluster)
			}
			if _, err = rds.DeleteGlobalCluster(t.Context(), &rdssdk.DeleteGlobalClusterInput{GlobalClusterIdentifier: aws.String("renamed-aurora")}); err != nil {
				t.Fatal(err)
			}
			absent, err = doc.DescribeGlobalClusters(t.Context(), &docdbsdk.DescribeGlobalClustersInput{})
			if err != nil || len(absent.GlobalClusters) != 0 {
				t.Fatalf("owned namespace not empty after deletes: %#v %v", absent, err)
			}
		})
	}
}

func TestGlobalClusterSDKPaginationAndReplicationBoundary(t *testing.T) {
	c := newCloudClients(t)
	rds := globalRDS(c, "us-east-1", "test", "test")
	doc := globalDocDB(c, "us-west-2", "test")
	for i := range 23 {
		_, err := doc.CreateGlobalCluster(t.Context(), &docdbsdk.CreateGlobalClusterInput{GlobalClusterIdentifier: aws.String(fmt.Sprintf("global-%02d", i)), Engine: aws.String("docdb")})
		if err != nil {
			t.Fatal(err)
		}
	}
	page, err := rds.DescribeGlobalClusters(t.Context(), &rdssdk.DescribeGlobalClustersInput{MaxRecords: aws.Int32(20)})
	if err != nil || len(page.GlobalClusters) != 20 || page.Marker == nil {
		t.Fatalf("global first page: %#v %v", page, err)
	}
	next, err := doc.DescribeGlobalClusters(t.Context(), &docdbsdk.DescribeGlobalClustersInput{Marker: page.Marker, MaxRecords: aws.Int32(20)})
	if err != nil || len(next.GlobalClusters) != 3 || next.Marker != nil || aws.ToString(next.GlobalClusters[0].GlobalClusterIdentifier) != "global-20" {
		t.Fatalf("cross-region/SDK global continuation: %#v %v", next, err)
	}
	_, err = globalRDS(c, "us-east-1", "111111111111", "test").DescribeGlobalClusters(t.Context(), &rdssdk.DescribeGlobalClustersInput{Marker: page.Marker})
	assertAPIError(t, err, "InvalidParameterValue")
	_, err = rds.DescribeGlobalClusters(t.Context(), &rdssdk.DescribeGlobalClustersInput{Marker: aws.String("not-a-marker")})
	assertAPIError(t, err, "InvalidParameterValue")
	_, err = rds.DescribeGlobalClusters(t.Context(), &rdssdk.DescribeGlobalClustersInput{MaxRecords: aws.Int32(19)})
	assertAPIError(t, err, "InvalidParameterValue")
	_, err = rds.DescribeGlobalClusters(t.Context(), &rdssdk.DescribeGlobalClustersInput{Filters: []rdstypes.Filter{{Name: aws.String("engine"), Values: []string{"docdb"}}}})
	assertAPIError(t, err, "InvalidParameterCombination")
	_, err = rds.DescribeGlobalClusters(t.Context(), &rdssdk.DescribeGlobalClustersInput{Filters: []rdstypes.Filter{{Name: aws.String("region")}}})
	if err == nil {
		t.Fatal("official SDK accepted a filter missing its required Values")
	}
	_, err = rds.CreateGlobalCluster(t.Context(), &rdssdk.CreateGlobalClusterInput{GlobalClusterIdentifier: aws.String("source-rejected"), SourceDBClusterIdentifier: aws.String("arn:aws:rds:us-east-1:000000000000:cluster:source")})
	assertAPIError(t, err, "InvalidParameterCombination")
	_, err = rds.RemoveFromGlobalCluster(t.Context(), &rdssdk.RemoveFromGlobalClusterInput{GlobalClusterIdentifier: aws.String("global-00"), DbClusterIdentifier: aws.String("source")})
	assertAPIError(t, err, "InvalidParameterCombination")
	_, err = rds.FailoverGlobalCluster(t.Context(), &rdssdk.FailoverGlobalClusterInput{GlobalClusterIdentifier: aws.String("global-00"), TargetDbClusterIdentifier: aws.String("source")})
	assertAPIError(t, err, "InvalidParameterCombination")
	_, err = rds.SwitchoverGlobalCluster(t.Context(), &rdssdk.SwitchoverGlobalClusterInput{GlobalClusterIdentifier: aws.String("global-00"), TargetDbClusterIdentifier: aws.String("source")})
	assertAPIError(t, err, "InvalidParameterCombination")
	_, err = doc.CreateDBCluster(t.Context(), &docdbsdk.CreateDBClusterInput{DBClusterIdentifier: aws.String("rejected-member"), GlobalClusterIdentifier: aws.String("global-00"), Engine: aws.String("docdb"), MasterUsername: aws.String("owner"), MasterUserPassword: aws.String("owned-password")})
	assertAPIError(t, err, "InvalidParameterCombination")
	_, err = rds.CreateDBCluster(t.Context(), &rdssdk.CreateDBClusterInput{DBClusterIdentifier: aws.String("rejected-member"), GlobalClusterIdentifier: aws.String("global-00"), Engine: aws.String("aurora-postgresql"), MasterUsername: aws.String("owner"), MasterUserPassword: aws.String("owned-password")})
	assertAPIError(t, err, "InvalidParameterCombination")
	_, err = rds.ModifyGlobalCluster(t.Context(), &rdssdk.ModifyGlobalClusterInput{GlobalClusterIdentifier: aws.String("global-00"), NewGlobalClusterIdentifier: aws.String("must-not-rename"), DeletionProtection: aws.Bool(true), EngineVersion: aws.String("8.0")})
	assertAPIError(t, err, "InvalidParameterCombination")
	_, err = rds.ModifyGlobalCluster(t.Context(), &rdssdk.ModifyGlobalClusterInput{GlobalClusterIdentifier: aws.String("global-00"), NewGlobalClusterIdentifier: aws.String("global-01"), DeletionProtection: aws.Bool(true)})
	assertAPIError(t, err, "GlobalClusterAlreadyExistsFault")
	unchanged, err := doc.DescribeGlobalClusters(t.Context(), &docdbsdk.DescribeGlobalClustersInput{GlobalClusterIdentifier: aws.String("global-00")})
	if err != nil || len(unchanged.GlobalClusters) != 1 || aws.ToBool(unchanged.GlobalClusters[0].DeletionProtection) || len(unchanged.GlobalClusters[0].GlobalClusterMembers) != 0 {
		t.Fatalf("rejected mutations changed metadata: %#v %v", unchanged, err)
	}
	all, err := rds.DescribeGlobalClusters(t.Context(), &rdssdk.DescribeGlobalClustersInput{})
	if err != nil || len(all.GlobalClusters) != 23 {
		t.Fatalf("rejected create retained state: %#v %v", all, err)
	}
	for _, v := range all.GlobalClusters {
		if _, err = rds.DeleteGlobalCluster(t.Context(), &rdssdk.DeleteGlobalClusterInput{GlobalClusterIdentifier: v.GlobalClusterIdentifier}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGlobalClusterSDKCurrentIAMAndTags(t *testing.T) {
	c := newCloudClients(t)
	root := c.iam("test", "test", "")
	_, key, secret := c.user(t, "test", "global-owner")
	client := globalRDS(c, "us-east-1", key, secret)
	arn := "arn:aws:rds::000000000000:global-cluster:iam-global"
	policy := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"rds:CreateGlobalCluster","Resource":%q,"Condition":{"StringEquals":{"aws:RequestTag/owner":"team"}}},{"Effect":"Allow","Action":["rds:DescribeGlobalClusters","rds:ModifyGlobalCluster","rds:DeleteGlobalCluster"],"Resource":%q,"Condition":{"StringEquals":{"aws:ResourceTag/owner":"team"}}}]}`, arn, arn)
	putUserPolicy(t, root, "global-owner", policy)
	_, err := client.CreateGlobalCluster(t.Context(), &rdssdk.CreateGlobalClusterInput{GlobalClusterIdentifier: aws.String("iam-global"), Engine: aws.String("docdb")})
	assertAPIError(t, err, "AccessDenied")
	_, err = client.CreateGlobalCluster(t.Context(), &rdssdk.CreateGlobalClusterInput{GlobalClusterIdentifier: aws.String("iam-global"), Engine: aws.String("docdb"), Tags: []rdstypes.Tag{{Key: aws.String("owner"), Value: aws.String("team")}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.DescribeGlobalClusters(t.Context(), &rdssdk.DescribeGlobalClustersInput{GlobalClusterIdentifier: aws.String("iam-global")}); err != nil {
		t.Fatal(err)
	}
	putUserPolicy(t, root, "global-owner", `{"Statement":{"Effect":"Deny","Action":"rds:*","Resource":"*"}}`)
	_, err = client.ModifyGlobalCluster(t.Context(), &rdssdk.ModifyGlobalClusterInput{GlobalClusterIdentifier: aws.String("iam-global"), DeletionProtection: aws.Bool(true)})
	assertAPIError(t, err, "AccessDenied")
	_, err = client.DeleteGlobalCluster(t.Context(), &rdssdk.DeleteGlobalClusterInput{GlobalClusterIdentifier: aws.String("iam-global")})
	assertAPIError(t, err, "AccessDenied")
	putUserPolicy(t, root, "global-owner", policy)
	rootRDS := globalRDS(c, "us-west-2", "test", "test")
	_, err = rootRDS.AddTagsToResource(t.Context(), &rdssdk.AddTagsToResourceInput{ResourceName: aws.String(arn), Tags: []rdstypes.Tag{{Key: aws.String("owner"), Value: aws.String("other")}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DeleteGlobalCluster(t.Context(), &rdssdk.DeleteGlobalClusterInput{GlobalClusterIdentifier: aws.String("iam-global")})
	assertAPIError(t, err, "AccessDenied")
	if _, err = rootRDS.DeleteGlobalCluster(t.Context(), &rdssdk.DeleteGlobalClusterInput{GlobalClusterIdentifier: aws.String("iam-global")}); err != nil {
		t.Fatalf("denied IAM mutation changed protection: %v", err)
	}
}

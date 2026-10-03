// Command docdb_sdk_smoke checks decoded controls and modeled native error cases
// against a running stackd endpoint. It does not provision or mutate resources.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/docdb"
	"github.com/aws/aws-sdk-go-v2/service/docdb/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"os"
	"time"
)

func run() error {
	endpoint := flag.String("endpoint", "", "explicit local endpoint")
	cluster := flag.String("cluster", "", "owned available cluster identifier")
	flag.Parse()
	if *endpoint == "" || *cluster == "" {
		return errors.New("endpoint and cluster are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	client := docdb.New(docdb.Options{Region: "us-east-1", BaseEndpoint: endpoint, Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), RetryMaxAttempts: 1})
	clusters, e := client.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{DBClusterIdentifier: cluster})
	if e != nil {
		return e
	}
	if len(clusters.DBClusters) != 1 {
		return fmt.Errorf("unexpected cluster count %d", len(clusters.DBClusters))
	}
	row := clusters.DBClusters[0]
	if aws.ToString(row.DBClusterIdentifier) != *cluster || aws.ToString(row.Engine) != "docdb" || aws.ToString(row.Status) != "available" || aws.ToString(row.Endpoint) == "" || aws.ToInt32(row.Port) == 0 {
		return fmt.Errorf("decoded cluster missing ready endpoint: %#v", row)
	}
	if len(row.DBClusterMembers) != 1 || !aws.ToBool(row.DBClusterMembers[0].IsClusterWriter) {
		return errors.New("decoded writer identity missing")
	}
	instance, e := client.DescribeDBInstances(ctx, &docdb.DescribeDBInstancesInput{DBInstanceIdentifier: row.DBClusterMembers[0].DBInstanceIdentifier})
	if e != nil {
		return e
	}
	if len(instance.DBInstances) != 1 || aws.ToString(instance.DBInstances[0].DBClusterIdentifier) != *cluster {
		return errors.New("decoded instance cluster association changed")
	}
	tags, e := client.ListTagsForResource(ctx, &docdb.ListTagsForResourceInput{ResourceName: row.DBClusterArn})
	if e != nil {
		return e
	}
	owned := false
	for _, tag := range tags.TagList {
		if aws.ToString(tag.Key) == "owner" && aws.ToString(tag.Value) != "" {
			owned = true
		}
	}
	if !owned {
		return errors.New("decoded resource tags missing")
	}
	relational := rds.New(rds.Options{Region: "us-east-1", BaseEndpoint: endpoint, Credentials: credentials.NewStaticCredentialsProvider("test", "test", ""), RetryMaxAttempts: 1})
	shared, e := relational.DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{Filters: []rdstypes.Filter{{Name: aws.String("engine"), Values: []string{"docdb"}}}})
	if e != nil {
		return e
	}
	found := false
	for _, candidate := range shared.DBClusters {
		if aws.ToString(candidate.DBClusterArn) == aws.ToString(row.DBClusterArn) {
			found = true
		}
		if aws.ToString(candidate.Engine) != "docdb" {
			return errors.New("shared engine filter returned a relational engine")
		}
	}
	if !found {
		return errors.New("RDS SDK list omitted the authoritative DocumentDB owner")
	}
	missing := *cluster + "-absent"
	_, e = client.DescribeDBClusters(ctx, &docdb.DescribeDBClustersInput{DBClusterIdentifier: &missing})
	var absentCluster *types.DBClusterNotFoundFault
	if !errors.As(e, &absentCluster) {
		return fmt.Errorf("unmodeled absent cluster: %T %v", e, e)
	}
	_, e = client.DescribeDBInstances(ctx, &docdb.DescribeDBInstancesInput{DBInstanceIdentifier: &missing})
	var absentInstance *types.DBInstanceNotFoundFault
	if !errors.As(e, &absentInstance) {
		return fmt.Errorf("unmodeled absent instance: %T %v", e, e)
	}
	_, e = client.DescribeDBClusterSnapshots(ctx, &docdb.DescribeDBClusterSnapshotsInput{DBClusterSnapshotIdentifier: &missing})
	var absentSnapshot *types.DBClusterSnapshotNotFoundFault
	if !errors.As(e, &absentSnapshot) {
		return fmt.Errorf("unmodeled absent snapshot: %T %v", e, e)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"sdk": "aws-sdk-go-v2/service/docdb", "decoded_cluster": aws.ToString(row.DBClusterArn), "decoded_writer": aws.ToString(instance.DBInstances[0].DBInstanceIdentifier), "shared_rds_engine_filter": true, "modeled_errors": []string{absentCluster.ErrorCode(), absentInstance.ErrorCode(), absentSnapshot.ErrorCode()}})
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

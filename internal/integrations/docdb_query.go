package integrations

import (
	"context"
	"errors"
	"strings"

	"stackd/internal/awsapi"
	api "stackd/internal/awsapi/rds"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/services/docdb"
	"stackd/internal/services/rds"
)

// DocumentDBQuery composes the shared RDS Query endpoint. AWS uses the same
// signing name, endpoint and ARN namespace for both services. Routing uses the
// requested engine and current resource owner, never SDK user-agent or hostname.
// Projections are read from the owner inside the caller's shared transaction.
type DocumentDBQuery struct{ Documents *docdb.Service }

func (a DocumentDBQuery) ExecuteRDS(ctx context.Context, req awsapi.DecodedRequest) (any, bool, *awswire.Error) {
	engine, kind, reference, _, _ := documentRoute(req.Input)
	owned := engine == "docdb"
	if !owned && reference != "" {
		var e error
		owned, e = a.Documents.Owns(ctx, kind, reference)
		if e != nil {
			return nil, true, &awswire.Error{Code: "InternalFailure", Message: "Unable to resolve database resource owner.", StatusCode: 500}
		}
	}
	if !owned {
		return nil, false, nil
	}
	converted, e := documentDBCommand(req)
	if e != nil {
		rejected := &awswire.Error{Code: "InvalidParameterCombination", Message: e.Error(), StatusCode: 400}
		if err := a.Documents.RecordRequestError(ctx, req, rejected); err != nil {
			return nil, true, &awswire.Error{Code: "InternalFailure", Message: "Unable to record rejected database request.", StatusCode: 500}
		}
		return nil, true, rejected
	}
	out, rejected := a.Documents.ExecuteCommand(ctx, converted)
	if rejected != nil {
		return nil, true, rejected
	}
	output, e := documentDBOutput(string(req.Operation.Name), out)
	if e != nil {
		return nil, true, &awswire.Error{Code: "InternalFailure", Message: "Unable to project DocumentDB response.", StatusCode: 500}
	}
	return output, true, nil
}
func (a DocumentDBQuery) CheckCreate(ctx context.Context, input any) error {
	_, _, _, kind, name := documentRoute(input)
	if name == "" {
		return nil
	}
	owned, e := a.Documents.Owns(ctx, kind, name)
	if e != nil {
		return e
	}
	if owned {
		code := "DBClusterAlreadyExistsFault"
		if kind == "db" {
			code = "DBInstanceAlreadyExists"
		}
		if kind == "cluster-snapshot" {
			code = "DBClusterSnapshotAlreadyExistsFault"
		}
		return &awswire.Error{Code: code, Message: "The database identifier is already in use.", StatusCode: 400}
	}
	return nil
}
func (a DocumentDBQuery) Databases(ctx context.Context) ([]rds.Database, error) {
	return a.Documents.RDSDatabases(ctx)
}
func (a DocumentDBQuery) Snapshots(ctx context.Context) ([]rds.Snapshot, error) {
	return a.Documents.RDSSnapshots(ctx)
}
func (a DocumentDBQuery) CloudFormationRequestedPort(ctx context.Context, kind, name string) (int32, bool, error) {
	owned, err := a.Documents.Owns(ctx, kind, name)
	if err != nil || !owned {
		return 0, false, err
	}
	port, err := a.Documents.CloudFormationRequestedPort(ctx, kind, name)
	return port, true, err
}
func documentRoute(input any) (engine, kind, reference, createKind, createName string) {
	switch in := input.(type) {
	case *api.DescribeDBEngineVersionsInput:
		return stringValue(in.Engine), "", "", "", ""
	case *api.CreateDBClusterInput:
		return stringValue(in.Engine), "cluster", "", "cluster", stringValue(in.DBClusterIdentifier)
	case *api.CreateDBInstanceInput:
		return stringValue(in.Engine), "cluster", stringValue(in.DBClusterIdentifier), "db", stringValue(in.DBInstanceIdentifier)
	case *api.RestoreDBClusterFromSnapshotInput:
		return stringValue(in.Engine), "cluster-snapshot", stringValue(in.SnapshotIdentifier), "cluster", stringValue(in.DBClusterIdentifier)
	case *api.CreateDBClusterSnapshotInput:
		return "", "cluster", stringValue(in.DBClusterIdentifier), "cluster-snapshot", stringValue(in.DBClusterSnapshotIdentifier)
	case *api.DescribeDBClustersInput:
		return "", "cluster", stringValue(in.DBClusterIdentifier), "", ""
	case *api.ModifyDBClusterInput:
		return "", "cluster", stringValue(in.DBClusterIdentifier), "", ""
	case *api.DeleteDBClusterInput:
		return "", "cluster", stringValue(in.DBClusterIdentifier), "", ""
	case *api.StartDBClusterInput:
		return "", "cluster", stringValue(in.DBClusterIdentifier), "", ""
	case *api.StopDBClusterInput:
		return "", "cluster", stringValue(in.DBClusterIdentifier), "", ""
	case *api.DescribeDBInstancesInput:
		return "", "db", stringValue(in.DBInstanceIdentifier), "", ""
	case *api.ModifyDBInstanceInput:
		return "", "db", stringValue(in.DBInstanceIdentifier), "", ""
	case *api.DeleteDBInstanceInput:
		return "", "db", stringValue(in.DBInstanceIdentifier), "", ""
	case *api.RebootDBInstanceInput:
		return "", "db", stringValue(in.DBInstanceIdentifier), "", ""
	case *api.DescribeDBClusterSnapshotsInput:
		if in.DBClusterSnapshotIdentifier == nil && in.DBClusterIdentifier != nil {
			return "", "cluster", stringValue(in.DBClusterIdentifier), "", ""
		}
		return "", "cluster-snapshot", stringValue(in.DBClusterSnapshotIdentifier), "", ""
	case *api.DeleteDBClusterSnapshotInput:
		return "", "cluster-snapshot", stringValue(in.DBClusterSnapshotIdentifier), "", ""
	case *api.CreateDBClusterParameterGroupInput:
		if strings.HasPrefix(stringValue(in.DBParameterGroupFamily), "docdb") {
			return "docdb", "", "", "", ""
		}
	case *api.AddTagsToResourceInput:
		return "", "", stringValue(in.ResourceName), "", ""
	case *api.RemoveTagsFromResourceInput:
		return "", "", stringValue(in.ResourceName), "", ""
	case *api.ListTagsForResourceInput:
		return "", "", stringValue(in.ResourceName), "", ""
	}
	return "", "", "", "", ""
}
func stringValue[T ~string](v *T) string {
	if v == nil {
		return ""
	}
	return string(*v)
}

// RDSNames prevents two authoritative owners from allocating the same public
// identifier. The repository joins the creator's shared transaction; there is no
// separate name registry or resource-state copy.
type RDSNames struct{ Repository rds.Repository }

func (a RDSNames) Owns(ctx context.Context, kind, name string) (bool, error) {
	owned := false
	m := awsctx.FromContext(ctx)
	key := rds.Key{Scope: rds.Scope{Partition: m.Partition, AccountID: m.AccountID, Region: m.Region}, Kind: kind, Name: name}
	e := a.Repository.View(ctx, func(r rds.Reader) error {
		var e error
		if kind == "cluster-snapshot" {
			_, e = r.Snapshot(key)
		} else {
			_, e = r.Database(key)
		}
		if errors.Is(e, rds.ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		owned = true
		return nil
	})
	return owned, e
}

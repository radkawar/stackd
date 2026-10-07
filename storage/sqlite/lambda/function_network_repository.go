package lambda

import (
	"database/sql"
	"errors"

	domain "stackd/storage/lambda"
	"stackd/storage/sqlite/lambda/internal/sqlcgen"
)

func (r reader) functionNetwork(key domain.FunctionKey, pending bool, version uint64) (domain.FunctionNetworkConfiguration, string, error) {
	var out domain.FunctionNetworkConfiguration
	row, err := r.q.GetFunctionNetwork(r.ctx, sqlcgen.GetFunctionNetworkParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Pending: pending, Version: int64(version)})
	if errors.Is(err, sql.ErrNoRows) {
		return out, "", nil
	}
	if err != nil {
		return out, "", err
	}
	out.VPCID = row.VpcID
	members, err := r.q.ListFunctionNetworkMembers(r.ctx, sqlcgen.ListFunctionNetworkMembersParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Pending: pending, Version: int64(version)})
	if err != nil {
		return out, "", err
	}
	for _, member := range members {
		switch member.Kind {
		case "subnet":
			out.SubnetIDs = append(out.SubnetIDs, member.ResourceID)
		case "security-group":
			out.SecurityGroupIDs = append(out.SecurityGroupIDs, member.ResourceID)
		}
	}
	return out, row.Incarnation, nil
}

func (w writer) putFunctionNetwork(function domain.FunctionRecord, pending bool) error {
	key := function.Key
	if err := w.q.PutFunctionNetwork(w.ctx, sqlcgen.PutFunctionNetworkParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Pending: pending, Version: int64(function.Version), Incarnation: function.NetworkIncarnation, VpcID: function.VpcConfig.VPCID}); err != nil {
		return err
	}
	if err := w.q.DeleteFunctionNetworkMembers(w.ctx, sqlcgen.DeleteFunctionNetworkMembersParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Pending: pending, Version: int64(function.Version)}); err != nil {
		return err
	}
	for _, group := range []struct {
		kind string
		ids  []string
	}{{"subnet", function.VpcConfig.SubnetIDs}, {"security-group", function.VpcConfig.SecurityGroupIDs}} {
		for position, id := range group.ids {
			if err := w.q.PutFunctionNetworkMember(w.ctx, sqlcgen.PutFunctionNetworkMemberParams{Partition: key.Partition, Account: key.Account, Region: key.Region, FunctionName: key.Name, Pending: pending, Version: int64(function.Version), Kind: group.kind, Position: int64(position), ResourceID: id}); err != nil {
				return err
			}
		}
	}
	return nil
}

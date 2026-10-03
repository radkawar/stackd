package eks

import (
	"database/sql"
	"encoding/json"

	domain "stackd/internal/services/eks"
	"stackd/storage/sqlite/eks/internal/sqlcgen"
)

func (r reader) ClusterUpdate(k domain.Key, id string) (domain.Update, error) {
	row, err := r.q.GetUpdate(r.ctx, sqlcgen.GetUpdateParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name, ID: id})
	if err != nil {
		return domain.Update{}, missing(err)
	}
	return clusterUpdate(row)
}
func (r reader) ClusterUpdates(k domain.Key) ([]domain.Update, error) {
	rows, err := r.q.ListUpdates(r.ctx, sqlcgen.ListUpdatesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name})
	if err != nil {
		return nil, err
	}
	out := make([]domain.Update, 0, len(rows))
	for _, row := range rows {
		v, err := clusterUpdate(row)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
func clusterUpdate(row sqlcgen.EksUpdate) (domain.Update, error) {
	v := domain.Update{
		Key: domain.Key{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, Name: row.Name},
		ID:  row.ID, Type: row.Type, Status: row.Status, ErrorCode: row.ErrorCode, ErrorMessage: row.ErrorMessage,
		ClientToken: row.ClientToken, RequestHash: row.RequestHash, Created: readTime(row.Created),
		AuthenticationMode: row.AuthenticationMode, KubernetesVersion: row.KubernetesVersion,
		ResourceType: row.ResourceType, ResourceName: row.ResourceName,
	}
	if row.DeletionProtection.Valid {
		value := row.DeletionProtection.Int64 != 0
		v.DeletionProtection = &value
	}
	if err := json.Unmarshal([]byte(row.EnabledLogTypes), &v.EnabledLogTypes); err != nil {
		return domain.Update{}, err
	}
	if err := json.Unmarshal([]byte(row.ParamsJson), &v.Params); err != nil {
		return domain.Update{}, err
	}
	return v, nil
}
func (w writer) PutClusterUpdate(v domain.Update) error {
	protection := sql.NullInt64{}
	if v.DeletionProtection != nil {
		protection = sql.NullInt64{Int64: bit(*v.DeletionProtection), Valid: true}
	}
	logging, err := json.Marshal(v.EnabledLogTypes)
	if err != nil {
		return err
	}
	params, err := json.Marshal(v.Params)
	if err != nil {
		return err
	}
	k := v.Key
	return w.q.PutUpdate(w.ctx, sqlcgen.PutUpdateParams{
		Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, Name: k.Name,
		ID: v.ID, Type: v.Type, Status: v.Status, ErrorCode: v.ErrorCode, ErrorMessage: v.ErrorMessage,
		ClientToken: v.ClientToken, RequestHash: v.RequestHash, Created: timeValue(v.Created),
		DeletionProtection: protection, AuthenticationMode: v.AuthenticationMode, KubernetesVersion: v.KubernetesVersion,
		EnabledLogTypes: string(logging), ResourceType: v.ResourceType, ResourceName: v.ResourceName,
		ParamsJson: string(params),
	})
}

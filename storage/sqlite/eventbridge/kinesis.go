package eventbridge

import (
	"database/sql"

	api "stackd/internal/awsapi/eventbridge"
)

func decodeKinesisParameters(path sql.NullString) *api.KinesisParameters {
	if !path.Valid {
		return nil
	}
	value := api.TargetPartitionKeyPath(path.String)
	return &api.KinesisParameters{PartitionKeyPath: &value}
}

func encodeKinesisParameters(p *api.KinesisParameters) sql.NullString {
	if p == nil || p.PartitionKeyPath == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: string(*p.PartitionKeyPath), Valid: true}
}

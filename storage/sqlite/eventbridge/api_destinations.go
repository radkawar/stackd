package eventbridge

import (
	"database/sql"

	domain "stackd/storage/eventbridge"
	"stackd/storage/sqlite"
	"stackd/storage/sqlite/eventbridge/internal/sqlcgen"
)

func apiDestination(v sqlcgen.EventbridgeApiDestination) domain.APIDestinationRecord {
	out := domain.APIDestinationRecord{
		Key: domain.APIDestinationKey{Scope: domain.Scope{Partition: v.Partition, Account: v.Account, Region: v.Region}, Name: v.Name},
		ID:  v.ID, Description: v.Description, ConnectionARN: v.ConnectionArn, Endpoint: v.Endpoint, Method: v.Method,
		CFNOwner: v.CfnOwner,
		Rate:     int(v.Rate), Created: v.Created, Modified: v.Modified, RateCount: int(v.RateCount), Version: uint64(v.Version),
	}
	if v.RateWindow.Valid {
		out.RateWindow = v.RateWindow.Time
	}
	return out
}

func (r reader) APIDestination(k domain.APIDestinationKey) (domain.APIDestinationRecord, error) {
	v, err := r.q.GetAPIDestination(r.ctx, sqlcgen.GetAPIDestinationParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name})
	if err != nil {
		return domain.APIDestinationRecord{}, missing(err)
	}
	return apiDestination(v), nil
}

func (r reader) APIDestinations(scope domain.Scope) ([]domain.APIDestinationRecord, error) {
	rows, err := r.q.ListAPIDestinations(r.ctx, sqlcgen.ListAPIDestinationsParams{Partition: scope.Partition, Account: scope.Account, Region: scope.Region})
	if err != nil {
		return nil, err
	}
	out := make([]domain.APIDestinationRecord, 0, len(rows))
	for _, v := range rows {
		out = append(out, apiDestination(v))
	}
	return out, nil
}

func (w writer) PutAPIDestination(v domain.APIDestinationRecord) error {
	return w.q.PutAPIDestination(w.ctx, sqlcgen.PutAPIDestinationParams{
		Partition: v.Key.Partition, Account: v.Key.Account, Region: v.Key.Region, Name: v.Key.Name,
		ID: v.ID, Description: v.Description, ConnectionArn: v.ConnectionARN, Endpoint: v.Endpoint, Method: v.Method,
		CfnOwner: v.CFNOwner,
		Rate:     int64(v.Rate), Created: v.Created, Modified: v.Modified,
		RateWindow: sql.NullTime{Time: v.RateWindow, Valid: !v.RateWindow.IsZero()}, RateCount: int64(v.RateCount), Version: sqlite.Uint64(v.Version),
	})
}

func (w writer) DeleteAPIDestination(k domain.APIDestinationKey) error {
	return w.q.DeleteAPIDestination(w.ctx, sqlcgen.DeleteAPIDestinationParams{Partition: k.Partition, Account: k.Account, Region: k.Region, Name: k.Name})
}

package apigatewayv2

import (
	domain "stackd/internal/services/apigatewayv2"
	"stackd/storage/sqlite/apigatewayv2/internal/sqlcgen"
)

func rowRouteResponse(row sqlcgen.Apigatewayv2RouteResponse) domain.RouteResponseRecord {
	return domain.RouteResponseRecord{
		Key:     domain.ResourceKey{APIKey: domain.APIKey{Scope: domain.Scope{Partition: row.Partition, AccountID: row.AccountID, Region: row.Region}, ID: row.GatewayID}, ID: row.ID},
		RouteID: row.RouteID, ResponseKey: row.ResponseKey,
	}
}

func (r reader) RouteResponse(k domain.ResourceKey) (domain.RouteResponseRecord, error) {
	row, err := r.q.GetRouteResponse(r.ctx, sqlcgen.GetRouteResponseParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID})
	if err != nil {
		return domain.RouteResponseRecord{}, missing(err)
	}
	return rowRouteResponse(row), nil
}

func (r reader) RouteResponses(k domain.ResourceKey) ([]domain.RouteResponseRecord, error) {
	rows, err := r.q.ListRouteResponses(r.ctx, sqlcgen.ListRouteResponsesParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, RouteID: k.ID})
	if err != nil {
		return nil, err
	}
	out := make([]domain.RouteResponseRecord, len(rows))
	for i, row := range rows {
		out[i] = rowRouteResponse(row)
	}
	return out, nil
}

func (w writer) PutRouteResponse(v domain.RouteResponseRecord) error {
	k := v.Key
	return w.q.PutRouteResponse(w.ctx, sqlcgen.PutRouteResponseParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID, RouteID: v.RouteID, ResponseKey: v.ResponseKey})
}

func (w writer) DeleteRouteResponse(k domain.ResourceKey) error {
	return w.q.DeleteRouteResponse(w.ctx, sqlcgen.DeleteRouteResponseParams{Partition: k.Partition, AccountID: k.AccountID, Region: k.Region, GatewayID: k.APIKey.ID, ID: k.ID})
}

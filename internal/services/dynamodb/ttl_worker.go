package dynamodb

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	api "stackd/internal/awsapi/dynamodb"
)

// Expiry is asynchronous, as on AWS. The kernel owns its scan schedule; the
// native engine's host-clock TTL worker stays disabled.
const ttlScanInterval = time.Minute

func (s *Service) runTTL(ctx context.Context, tables []TableRecord) (time.Time, bool) {
	now := s.clock.Now()
	var next time.Time
	retry := false
	// One deterministic scanner originates a global-table expiry. Other Regions
	// receive an ordinary replicated delete, including its capacity charge and
	// absence of the original TTL service identity in their Streams records.
	owners := make(map[string]int)
	for i := range tables {
		group := tables[i].Replica.GroupID
		if group == "" {
			continue
		}
		owner, exists := owners[group]
		if !exists || compareTables(tables[i], tables[owner]) < 0 {
			owners[group] = i
		}
	}
	for i := range tables {
		table := &tables[i]
		if group := table.Replica.GroupID; group != "" && owners[group] != i {
			continue
		}
		due := table.TTLNextScan
		if !due.After(now) {
			if err := s.expireTTL(ctx, table, now); err != nil {
				if ctx.Err() != nil {
					return time.Time{}, false
				}
				slog.Error("DynamoDB TTL scan failed", "table", table.Key.ARN(), "error", err)
				retry = true
				continue
			}
			due = now.Add(ttlScanInterval)
			if err := s.repository.Update(ctx, func(tx Transaction) error {
				current, err := tx.Table(table.Key)
				if errors.Is(err, ErrNotFound) {
					return nil
				}
				if err != nil {
					return err
				}
				if current.PhysicalName != table.PhysicalName || !current.TTLChangedAt.Equal(table.TTLChangedAt) {
					return nil
				}
				current.TTLNextScan = due
				return tx.PutTable(current)
			}); err != nil {
				if ctx.Err() != nil {
					return time.Time{}, false
				}
				slog.Error("DynamoDB TTL schedule commit failed", "table", table.Key.ARN(), "error", err)
				retry = true
				continue
			}
		}
		if next.IsZero() || due.Before(next) {
			next = due
		}
	}
	return next, retry
}

func (s *Service) expireTTL(ctx context.Context, table *TableRecord, now time.Time) error {
	attribute := api.AttributeName(value(table.TTL.AttributeName))
	names := api.ExpressionAttributeNameMap{"#ttl": attribute}
	projection := []string{"#ttl"}
	for i, key := range table.Data.KeySchema {
		name := api.AttributeName(value(key.AttributeName))
		if name == attribute {
			continue
		}
		alias := "#key" + strconv.Itoa(i)
		names[api.ExpressionAttributeNameVariable(alias)] = name
		projection = append(projection, alias)
	}
	scan := api.ScanInput{
		TableName:                dataPhysical(table),
		ProjectionExpression:     new(api.ProjectionExpression(strings.Join(projection, ","))),
		ExpressionAttributeNames: names,
		// DynamoDB evaluates its own numeric and document types. Strings, malformed
		// TTL attributes, future timestamps and values over five years old are not
		// candidates. Only selected keys and TTL values leave the engine.
		FilterExpression: new(api.ConditionExpression("attribute_type(#ttl, :number) AND #ttl >= :oldest AND #ttl < :now")),
		ExpressionAttributeValues: api.ExpressionAttributeValueMap{
			":number": {S: new(api.StringAttributeValue("N"))},
			":oldest": {N: new(api.NumberAttributeValue(strconv.FormatInt(now.AddDate(-5, 0, 0).Unix(), 10)))},
			":now":    {N: new(api.NumberAttributeValue(strconv.FormatInt(now.Unix(), 10)))},
		},
	}
	for {
		var page api.ScanOutput
		if err := s.callEngine(ctx, table, "Scan", &scan, &page); err != nil {
			if engineCode(err, "ResourceNotFoundException") {
				return nil
			}
			return err
		}
		for _, item := range page.Items {
			key := make(api.Key, len(table.Data.KeySchema))
			for _, column := range table.Data.KeySchema {
				name := api.AttributeName(value(column.AttributeName))
				key[name] = item[name]
			}
			in := api.DeleteItemInput{
				TableName: scan.TableName, Key: key,
				// A customer can refresh the expiry after the scan. The native conditional
				// write, not a Go read/write race, decides whether this item is still due.
				ConditionExpression:       new(api.ConditionExpression("#ttl = :seen")),
				ExpressionAttributeNames:  api.ExpressionAttributeNameMap{"#ttl": attribute},
				ExpressionAttributeValues: api.ExpressionAttributeValueMap{":seen": item[attribute]},
			}
			if err := s.deleteTTLItem(ctx, table, &in); err != nil && !engineCode(err, "ConditionalCheckFailedException") {
				if engineCode(err, "ResourceNotFoundException") {
					return nil
				}
				return err
			}
		}
		if len(page.LastEvaluatedKey) == 0 {
			return nil
		}
		scan.ExclusiveStartKey = page.LastEvaluatedKey
	}
}

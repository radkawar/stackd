package dynamodb

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/google/uuid"
	api "stackd/internal/awsapi/dynamodb"
)

func (s *Service) updateReplicas(ctx context.Context, tx Transaction, table TableRecord, in *api.UpdateTableInput) (*TableRecord, error) {
	if err := transitionAvailable(table); err != nil {
		return nil, err
	}
	if len(in.ReplicaUpdates) == 0 {
		return nil, invalidTable("ReplicaUpdates must contain an action")
	}
	updates := make(map[string]api.ReplicationGroupUpdate, len(in.ReplicaUpdates))
	for _, update := range in.ReplicaUpdates {
		count, region := 0, ""
		if update.Create != nil {
			count++
			region = value(update.Create.RegionName)
		}
		if update.Update != nil {
			count++
			region = value(update.Update.RegionName)
		}
		if update.Delete != nil {
			count++
			region = value(update.Delete.RegionName)
		}
		if count != 1 {
			return nil, invalidTable("Each ReplicaUpdate must contain exactly one Create, Update, or Delete action")
		}
		if previous, found := updates[region]; found {
			if !reflect.DeepEqual(previous, update) {
				return nil, invalidTable("Conflicting replica updates for Region: " + region)
			}
			continue
		}
		updates[region] = update
		if err := s.replicaRegion(ctx, table.Key.Scope, region); err != nil {
			return nil, err
		}
		switch {
		case update.Create != nil:
			if region == table.Key.Region {
				return nil, invalidTable("Cannot create a replica in the source Region")
			}
			if table.Replica.GroupID == "" {
				table.Replica.GroupID = uuid.NewString()
			}
			if err := s.createReplica(ctx, tx, &table, *update.Create); err != nil {
				return nil, err
			}
			table.Replica.LastSourceAt = s.clock.Now()
		case update.Delete != nil:
			if region == table.Key.Region {
				return nil, invalidTable("Use DeleteTable to delete the current regional table")
			}
			peer, err := replicaMember(tx, &table, region)
			if err != nil {
				return nil, err
			}
			for _, action := range []string{"DeleteTableReplica", "DeleteTable"} {
				if err := s.authorizeTable(regionalContext(ctx, region), tx, peer.Key, action, "", nil); err != nil {
					return nil, err
				}
			}
			if err := replicaDeletable(&peer, s.clock.Now()); err != nil {
				return nil, err
			}
			peer.Data.TableStatus = new(api.TableStatusDELETING)
			if err := tx.PutTable(peer); err != nil {
				return nil, err
			}
		case update.Update != nil:
			peer, err := replicaMember(tx, &table, region)
			if err != nil {
				return nil, err
			}
			settings, err := replicaOverrideInput(&peer, *update.Update)
			if err != nil {
				return nil, err
			}
			peer.Replica.SettingsPending = peer.Key != table.Key
			changed, err := s.updateTableSettings(regionalContext(ctx, region), tx, peer, &settings)
			if err != nil {
				return nil, err
			}
			if peer.Key == table.Key {
				table = *changed
			}
		}
	}
	pending := api.CloneUpdateTableInput(*in)
	if table.PendingUpdate != nil {
		pending = api.CloneUpdateTableInput(*table.PendingUpdate)
		pending.ReplicaUpdates = api.CloneUpdateTableInput(*in).ReplicaUpdates
	}
	if table.Data.StreamSpecification == nil || table.Data.StreamSpecification.StreamEnabled == nil || !*table.Data.StreamSpecification.StreamEnabled {
		table.Data.StreamSpecification = &api.StreamSpecification{StreamEnabled: new(api.StreamEnabled(true)), StreamViewType: new(api.StreamViewTypeNEW_AND_OLD_IMAGES)}
		pending.StreamSpecification = table.Data.StreamSpecification
		if err := s.assignStreamIdentity(tx, &table); err != nil {
			return nil, err
		}
	}
	table.PendingUpdate, table.UpdateAcceptedAt = &pending, s.clock.Now()
	table.Data.TableStatus = new(api.TableStatusUPDATING)
	if err := tx.PutTable(table); err != nil {
		return nil, err
	}
	return &table, nil
}

func (s *Service) createReplica(ctx context.Context, tx Transaction, source *TableRecord, in api.CreateReplicationGroupMemberAction) error {
	region := value(in.RegionName)
	key := source.Key
	key.Region = region
	if _, err := tx.Table(key); err == nil {
		return invalidTable("A table already exists in replica Region: " + region)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	regional := regionalContext(ctx, region)
	// admitTable owns CreateTable authorization. These additional permissions
	// are required on the new regional ARN, not on the source table ARN.
	for _, action := range []string{"CreateTableReplica", "Query", "Scan", "UpdateItem", "PutItem", "GetItem", "DeleteItem", "BatchWriteItem"} {
		if err := s.authorizeTable(regional, tx, key, action, "", nil); err != nil {
			return err
		}
	}
	if err := s.roles.EnsureServiceLinkedRole(ctx, ReplicationServicePrincipal); err != nil {
		return err
	}
	create, err := replicaCreateInput(source, api.UpdateReplicationGroupMemberAction(in))
	if err != nil {
		return err
	}
	create.TableName = new(api.TableArn(key.ARN()))
	target, err := s.admitTable(regional, tx, &create, nil)
	if err != nil {
		return err
	}
	target.Replica.GroupID = source.Replica.GroupID
	target.TTL = source.TTL
	target.TTLChangedAt, target.TTLNextScan = source.TTLChangedAt, source.TTLNextScan
	target.Data.WarmThroughput = source.Data.WarmThroughput
	if err := tx.PutTable(*target); err != nil {
		return err
	}
	if err := s.prepareReplicaScaling(ctx, source, target); err != nil {
		return err
	}
	return tx.PutReplicaBootstrap(ReplicaBootstrap{Table: target.Key, Source: source.Key,
		SourceDatabaseID: source.DatabaseID, SourcePhysicalName: source.PhysicalName,
		SnapshotPhysicalName: "replica_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		KeySchema:            source.Data.KeySchema, AttributeDefinitions: source.Data.AttributeDefinitions})
}

func replicaMember(r Reader, source *TableRecord, region string) (TableRecord, error) {
	key := source.Key
	key.Region = region
	member, err := r.Table(key)
	if errors.Is(err, ErrNotFound) || err == nil && (source.Replica.GroupID == "" || member.Replica.GroupID != source.Replica.GroupID) {
		return TableRecord{}, invalidTable("The table has no replica in Region: " + region)
	}
	return member, err
}

func replicaDeletable(table *TableRecord, now time.Time) error {
	if err := transitionAvailable(*table); err != nil {
		return err
	}
	if table.Data.DeletionProtectionEnabled != nil && *table.Data.DeletionProtectionEnabled {
		return invalidTable("Resource cannot be deleted as it is currently protected against deletion. Disable deletion protection first.")
	}
	if table.Replica.GroupID != "" && !table.Replica.LastSourceAt.IsZero() && now.Before(table.Replica.LastSourceAt.Add(24*time.Hour)) {
		return invalidTable("Replica cannot be deleted because it has acted as a source region for new replica(s) being added to the table in the last 24 hours.")
	}
	return nil
}

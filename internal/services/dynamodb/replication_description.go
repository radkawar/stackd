package dynamodb

import api "stackd/internal/awsapi/dynamodb"

func (s *Service) describeReplicas(r Reader, table *TableRecord, out *api.TableDescription) error {
	out.Replicas, out.GlobalTableVersion, out.GlobalTableSettingsReplicationMode = nil, nil, nil
	if table.Replica.GroupID == "" {
		return nil
	}
	out.GlobalTableVersion = new(api.String("2019.11.21"))
	out.GlobalTableSettingsReplicationMode = new(api.GlobalTableSettingsReplicationModeENABLED_WITH_OVERRIDES)
	peers, err := r.ReplicaTables(table.Replica.GroupID)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		if peer.PhysicalName == table.PhysicalName {
			continue
		}
		status := api.ReplicaStatus(value(peer.Data.TableStatus))
		if peer.Replica.UnauthorizedAt != nil {
			status = api.ReplicaStatusREPLICATION_NOT_AUTHORIZED
		}
		description := api.ReplicaDescription{RegionName: new(api.RegionName(peer.Key.Region)), ReplicaStatus: &status,
			GlobalTableSettingsReplicationMode: new(api.GlobalTableSettingsReplicationModeENABLED_WITH_OVERRIDES), WarmThroughput: peer.Data.WarmThroughput}
		description.ProvisionedThroughputOverride = replicaReadOverride(table.Data.ProvisionedThroughput, peer.Data.ProvisionedThroughput)
		description.OnDemandThroughputOverride = replicaOnDemandOverride(table.Data.OnDemandThroughput, peer.Data.OnDemandThroughput)
		if replicaTableClass(&table.Data) != replicaTableClass(&peer.Data) {
			description.ReplicaTableClassSummary = peer.Data.TableClassSummary
		}
		for _, index := range peer.Data.GlobalSecondaryIndexes {
			entry := api.ReplicaGlobalSecondaryIndexDescription{IndexName: index.IndexName, WarmThroughput: index.WarmThroughput}
			for _, source := range table.Data.GlobalSecondaryIndexes {
				if value(source.IndexName) == value(index.IndexName) {
					entry.ProvisionedThroughputOverride = replicaReadOverride(source.ProvisionedThroughput, index.ProvisionedThroughput)
					entry.OnDemandThroughputOverride = replicaOnDemandOverride(source.OnDemandThroughput, index.OnDemandThroughput)
					break
				}
			}
			description.GlobalSecondaryIndexes = append(description.GlobalSecondaryIndexes, entry)
		}
		out.Replicas = append(out.Replicas, description)
	}
	return nil
}

func replicaReadOverride(source, peer *api.ProvisionedThroughputDescription) *api.ProvisionedThroughputOverride {
	if source == nil || peer == nil || source.ReadCapacityUnits == nil || peer.ReadCapacityUnits == nil || *source.ReadCapacityUnits == *peer.ReadCapacityUnits {
		return nil
	}
	return &api.ProvisionedThroughputOverride{ReadCapacityUnits: new(api.PositiveLongObject(*peer.ReadCapacityUnits))}
}

func replicaOnDemandOverride(source, peer *api.OnDemandThroughput) *api.OnDemandThroughputOverride {
	read := func(v *api.OnDemandThroughput) api.LongObject {
		if v == nil || v.MaxReadRequestUnits == nil {
			return -1
		}
		return *v.MaxReadRequestUnits
	}
	if read(source) == read(peer) {
		return nil
	}
	return &api.OnDemandThroughputOverride{MaxReadRequestUnits: new(read(peer))}
}

func replicaTableClass(table *api.TableDescription) string {
	if table.TableClassSummary == nil {
		return "STANDARD"
	}
	return value(table.TableClassSummary.TableClass)
}

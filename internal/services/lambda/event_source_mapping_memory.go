package lambda

import (
	"cmp"
	"maps"
	"slices"

	"stackd/storage/memory"
)

func cloneEventSourceMapping(v EventSourceMappingRecord) EventSourceMappingRecord {
	v.Tags = maps.Clone(v.Tags)
	v.Settings.Filters = slices.Clone(v.Settings.Filters)
	if encrypted := v.Settings.EncryptedFilters; encrypted != nil {
		v.Settings.EncryptedFilters = &EncryptedMappingFilters{Content: slices.Clone(encrypted.Content), DataKey: slices.Clone(encrypted.DataKey), FunctionARN: encrypted.FunctionARN, Format: encrypted.Format}
		v.Settings.Filters = nil
	}
	v.Settings.Metrics = slices.Clone(v.Settings.Metrics)
	if v.Settings.MaximumConcurrency != nil {
		v.Settings.MaximumConcurrency = new(*v.Settings.MaximumConcurrency)
	}
	if v.Settings.ProvisionedPollers != nil {
		v.Settings.ProvisionedPollers = new(*v.Settings.ProvisionedPollers)
	}
	if v.Settings.Stream != nil {
		v.Settings.Stream = new(*v.Settings.Stream)
	}
	if v.Settings.Kafka != nil {
		v.Settings.Kafka = new(*v.Settings.Kafka)
		v.Settings.Kafka.BootstrapServers = slices.Clone(v.Settings.Kafka.BootstrapServers)
		v.Settings.Kafka.Network.SubnetIDs = slices.Clone(v.Settings.Kafka.Network.SubnetIDs)
		v.Settings.Kafka.Network.SecurityGroupIDs = slices.Clone(v.Settings.Kafka.Network.SecurityGroupIDs)
	}
	if v.Settings.MQ != nil {
		v.Settings.MQ = new(*v.Settings.MQ)
	}
	if v.Settings.DocumentDB != nil {
		v.Settings.DocumentDB = cloneDocumentDBMappingSettings(v.Settings.DocumentDB)
	}
	return v
}

func (r memoryReader) EventSourceMapping(k EventSourceMappingKey) (v EventSourceMappingRecord, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	err = r.repository.mappings.View(r.Context(), func(rows *map[EventSourceMappingKey]EventSourceMappingRecord, _ *memory.Transaction) error {
		var ok bool
		v, ok = (*rows)[k]
		if !ok {
			return ErrNotFound
		}
		v = cloneEventSourceMapping(v)
		return nil
	})
	return
}

func (r memoryReader) EventSourceMappings(scope Scope) ([]EventSourceMappingRecord, error) {
	return r.eventSourceMappings(&scope)
}
func (r memoryReader) AllEventSourceMappings() ([]EventSourceMappingRecord, error) {
	return r.eventSourceMappings(nil)
}
func (r memoryReader) eventSourceMappings(scope *Scope) (out []EventSourceMappingRecord, err error) {
	if err = r.tx.Check(false); err != nil {
		return
	}
	out = []EventSourceMappingRecord{}
	err = r.repository.mappings.View(r.Context(), func(rows *map[EventSourceMappingKey]EventSourceMappingRecord, _ *memory.Transaction) error {
		for _, v := range *rows {
			if scope == nil || v.Key.Scope == *scope {
				out = append(out, cloneEventSourceMapping(v))
			}
		}
		return nil
	})
	slices.SortFunc(out, func(a, b EventSourceMappingRecord) int { return cmp.Compare(a.Key.ARN(), b.Key.ARN()) })
	return
}

func (w memoryWriter) PutEventSourceMapping(v EventSourceMappingRecord) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.mappings.Update(w.Context(), func(rows *map[EventSourceMappingKey]EventSourceMappingRecord, _ *memory.Transaction) error {
		if previous, ok := (*rows)[v.Key]; ok {
			v.LastProcessingResult = previous.LastProcessingResult
		}
		(*rows)[v.Key] = cloneEventSourceMapping(v)
		return nil
	})
}
func (w memoryWriter) DeleteEventSourceMapping(k EventSourceMappingKey) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	if err := w.repository.mappings.Update(w.Context(), func(rows *map[EventSourceMappingKey]EventSourceMappingRecord, _ *memory.Transaction) error {
		delete(*rows, k)
		return nil
	}); err != nil {
		return err
	}
	if err := w.DeleteDocumentDBCheckpoint(k); err != nil {
		return err
	}
	return w.repository.streamShards.Update(w.Context(), func(rows *map[StreamShardKey]StreamShardRecord, _ *memory.Transaction) error {
		for key := range *rows {
			if key.Mapping == k {
				delete(*rows, key)
			}
		}
		return nil
	})
}

func (w memoryWriter) SetEventSourceMappingProcessingResult(k EventSourceMappingKey, result string) error {
	if err := w.tx.Check(true); err != nil {
		return err
	}
	return w.repository.mappings.Update(w.Context(), func(rows *map[EventSourceMappingKey]EventSourceMappingRecord, _ *memory.Transaction) error {
		v, ok := (*rows)[k]
		if !ok {
			return ErrNotFound
		}
		v.LastProcessingResult = result
		(*rows)[k] = v
		return nil
	})
}

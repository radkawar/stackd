package eventbridge

import (
	"context"
	"errors"
	"strings"
	"time"

	"stackd/internal/authorization"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awswire"
)

func (s *Service) registerArchives() {
	register(s, "CreateArchive", s.createArchive)
	register(s, "DescribeArchive", s.describeArchive)
	register(s, "UpdateArchive", s.updateArchive)
	register(s, "ListArchives", s.listArchives)
	register(s, "DeleteArchive", s.deleteArchive)
}

func archiveSource(ctx context.Context, arn string) (BusKey, *awswire.Error) {
	scope := scopeFor(ctx)
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] != scope.Partition || parts[2] != "events" || parts[3] != scope.Region || parts[4] != scope.Account || !strings.HasPrefix(parts[5], "event-bus/") || strings.TrimPrefix(parts[5], "event-bus/") == "" {
		return BusKey{}, failure("ValidationException", "Parameter EventSourceArn is not valid. Reason: Must contain an event bus ARN in this account, partition and Region.")
	}
	return resolveBus(scope, arn, false)
}

// The default bus exists logically before any operation materializes it.
func archiveSourceBus(r Reader, source BusKey) (BusRecord, error) {
	bus, err := r.Bus(source)
	if errors.Is(err, ErrNotFound) {
		if source.Name == "default" {
			return BusRecord{Key: source}, nil
		}
		return BusRecord{}, failure("ResourceNotFoundException", "Event bus "+source.Name+" does not exist.")
	}
	return bus, err
}

func archiveNotFound(key ArchiveKey) *awswire.Error {
	return failure("ResourceNotFoundException", "Archive "+key.Name+" does not exist.")
}

func archiveConcurrent(key ArchiveKey) *awswire.Error {
	return failure("ConcurrentModificationException", "Archive "+key.Name+" was modified concurrently.")
}

func readArchive(r Reader, key ArchiveKey) (ArchiveRecord, error) {
	archive, err := r.Archive(key)
	if errors.Is(err, ErrNotFound) {
		return ArchiveRecord{}, archiveNotFound(key)
	}
	if err == nil {
		err = cloudFormationCheck(r.Context(), "Archive", archive.CFNOwner)
	}
	return archive, err
}

func (s *Service) authorizeArchive(r Reader, action string, key ArchiveKey) error {
	return s.authorize(r, action, key.ARN(), nil, nil, authorization.BoundPolicy{})
}

func archiveAbsent(r Reader, key ArchiveKey) error {
	_, err := r.Archive(key)
	if err == nil {
		return failure("ResourceAlreadyExistsException", "Archive "+key.Name+" already exists.")
	}
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

func checkArchiveSource(r Reader, archive ArchiveRecord, original BusRecord) error {
	current, err := archiveSourceBus(r, archive.Source)
	if err != nil {
		return err
	}
	if !original.Created.IsZero() && !current.Created.Equal(original.Created) {
		return archiveConcurrent(archive.Key)
	}
	return nil
}

func (s *Service) createArchive(ctx context.Context, in *api.CreateArchiveInput) (out *api.CreateArchiveOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "CreateArchive", in, &out, &rejected, false)
	source, wire := archiveSource(ctx, value(in.EventSourceArn))
	if wire != nil {
		return nil, wire
	}
	pattern, wire := archiveManagedPattern(value(in.EventPattern))
	if wire != nil {
		return nil, wire
	}
	archive := ArchiveRecord{Key: ArchiveKey{Scope: scopeFor(ctx), Name: value(in.ArchiveName)}, ID: identifier(), Source: source,
		Description: value(in.Description), KmsKeyIdentifier: value(in.KmsKeyIdentifier), State: "ENABLED", Version: 1}
	archive.CFNOwner = cloudFormationClaim(ctx, "Archive")
	if in.RetentionDays != nil {
		archive.RetentionDays = int32(*in.RetentionDays)
	}
	var bus BusRecord
	err := s.repository.View(ctx, func(r Reader) error {
		if err := s.authorizeArchive(r, "CreateArchive", archive.Key); err != nil {
			return err
		}
		var err error
		bus, err = archiveSourceBus(r, source)
		if err != nil {
			return err
		}
		if err := s.authorize(r, "CreateArchive", source.ARN(), bus.Tags, nil, bus.Policy); err != nil {
			return err
		}
		if err := archiveAbsent(r, archive.Key); err != nil {
			return err
		}
		return archiveRuleAvailable(r, archive)
	})
	if err != nil {
		return nil, wireError(err)
	}
	archive.KeyARN, wire = s.resolveArchiveKey(ctx, source, archive.KmsKeyIdentifier)
	if wire != nil {
		return nil, wire
	}
	archive.Pattern, wire = s.prepareArchivePayload(ctx, source, archive.KeyARN, []byte(value(in.EventPattern)))
	if wire != nil {
		return nil, wire
	}
	if archive.KeyARN != "" {
		// Native service DescribeKey denial leaves this targetless managed rule.
		// It is the real rule, not a separate staging ledger or an archive row.
		err = s.configUpdate(ctx, source, false, func(tx Transaction) error {
			if err := checkArchiveSource(tx, archive, bus); err != nil {
				return err
			}
			if err := archiveAbsent(tx, archive.Key); err != nil {
				return err
			}
			if err := archiveRuleAvailable(tx, archive); err != nil {
				return err
			}
			if _, err := s.bus(tx, source); err != nil {
				return err
			}
			return tx.PutRule(archiveRule(archive, pattern))
		})
		if err != nil {
			return nil, wireError(err)
		}
	}
	if wire := s.describeArchiveKey(ctx, source, archive.KeyARN); wire != nil {
		return nil, wire
	}
	err = s.configUpdate(ctx, source, false, func(tx Transaction) error {
		if err := checkArchiveSource(tx, archive, bus); err != nil {
			return err
		}
		if err := archiveAbsent(tx, archive.Key); err != nil {
			return err
		}
		if archive.KeyARN != "" {
			rule, err := tx.Rule(archiveRuleKey(archive))
			if errors.Is(err, ErrNotFound) || err == nil && rule.ArchiveID != archive.ID {
				return archiveConcurrent(archive.Key)
			}
			if err != nil {
				return err
			}
		}
		if _, err := s.bus(tx, source); err != nil {
			return err
		}
		archive.Created = s.clock.Now().Truncate(time.Second)
		if err := putArchiveRule(tx, archive, pattern); err != nil {
			return err
		}
		if err := tx.PutArchive(archive); err != nil {
			return err
		}
		out = &api.CreateArchiveOutput{ArchiveArn: str[api.ArchiveArn](archive.Key.ARN()), State: str[api.ArchiveState](archive.State), CreationTime: ptr(api.Timestamp(archive.Created))}
		return s.recordCall(tx.Context(), "CreateArchive", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}

func (s *Service) describeArchive(ctx context.Context, in *api.DescribeArchiveInput) (out *api.DescribeArchiveOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "DescribeArchive", in, &out, &rejected, true)
	key := ArchiveKey{Scope: scopeFor(ctx), Name: value(in.ArchiveName)}
	var archive ArchiveRecord
	err := s.repository.View(ctx, func(r Reader) error {
		if err := s.authorizeArchive(r, "DescribeArchive", key); err != nil {
			return err
		}
		var err error
		archive, err = readArchive(r, key)
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	out = &api.DescribeArchiveOutput{ArchiveArn: str[api.ArchiveArn](key.ARN()), ArchiveName: in.ArchiveName,
		EventSourceArn: str[api.EventBusArn](archive.Source.ARN()), State: str[api.ArchiveState](archive.State),
		RetentionDays: ptr(api.RetentionDays(archive.RetentionDays)), SizeBytes: ptr(api.Long(archive.SizeBytes)), EventCount: ptr(api.Long(archive.EventCount)), CreationTime: ptr(api.Timestamp(archive.Created))}
	if archive.Description != "" {
		out.Description = str[api.ArchiveDescription](archive.Description)
	}
	if archive.StateReason != "" {
		out.StateReason = str[api.ArchiveStateReason](archive.StateReason)
	}
	if archive.KmsKeyIdentifier != "" {
		out.KmsKeyIdentifier = str[api.KmsKeyIdentifier](archive.KmsKeyIdentifier)
	}
	if pattern, wire := s.openArchivePayload(ctx, archive.Source, archive.Pattern, "", archive.KeyARN); wire == nil && len(pattern) != 0 {
		out.EventPattern = str[api.EventPattern](string(pattern))
	}
	return out, nil
}

func (s *Service) updateArchive(ctx context.Context, in *api.UpdateArchiveInput) (out *api.UpdateArchiveOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "UpdateArchive", in, &out, &rejected, false)
	if in.Description == nil && in.EventPattern == nil && in.RetentionDays == nil && in.KmsKeyIdentifier == nil {
		return nil, failure("ValidationException", "At least one of EventPattern, RetentionDays, Description or KmsKeyIdentifier must be provided.")
	}
	key := ArchiveKey{Scope: scopeFor(ctx), Name: value(in.ArchiveName)}
	var archive ArchiveRecord
	var bus BusRecord
	err := s.repository.View(ctx, func(r Reader) error {
		if err := s.authorizeArchive(r, "UpdateArchive", key); err != nil {
			return err
		}
		var err error
		archive, err = readArchive(r, key)
		if err != nil {
			return err
		}
		bus, err = archiveSourceBus(r, archive.Source)
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	pattern := value(in.EventPattern)
	if in.EventPattern == nil {
		content, wire := s.openArchivePayload(ctx, archive.Source, archive.Pattern, "", archive.KeyARN)
		if wire != nil {
			if wire.StatusCode < 500 {
				return nil, failure("ValidationException", wire.Message)
			}
			return nil, wire
		}
		pattern = string(content)
	}
	managedPattern, wire := archiveManagedPattern(pattern)
	if wire != nil {
		return nil, wire
	}
	if !archive.MigrationDue.IsZero() {
		return nil, archiveConcurrent(key)
	}
	keyChanged := false
	if in.KmsKeyIdentifier != nil {
		resolved, wire := s.resolveArchiveKey(ctx, archive.Source, value(in.KmsKeyIdentifier))
		if wire != nil {
			return nil, wire
		}
		keyChanged = resolved != archive.KeyARN
		if keyChanged {
			archive.PreviousKeyARN, archive.PreviousKmsKeyIdentifier = archive.KeyARN, archive.KmsKeyIdentifier
		}
		archive.KeyARN = resolved
		if resolved != "" || !keyChanged {
			archive.KmsKeyIdentifier = value(in.KmsKeyIdentifier)
		}
	} else if archive.KeyARN != "" {
		if _, wire := s.resolveArchiveKey(ctx, archive.Source, archive.KeyARN); wire != nil {
			return nil, wire
		}
	}
	archive.Pattern, wire = s.prepareArchivePayload(ctx, archive.Source, archive.KeyARN, []byte(pattern))
	if wire != nil {
		return nil, wire
	}
	if wire := s.describeArchiveKey(ctx, archive.Source, archive.KeyARN); wire != nil {
		return nil, wire
	}
	if in.Description != nil {
		archive.Description = value(in.Description)
	}
	if in.RetentionDays != nil {
		archive.RetentionDays = int32(*in.RetentionDays)
	}
	err = s.configUpdate(ctx, archive.Source, false, func(tx Transaction) error {
		current, err := tx.Archive(key)
		if errors.Is(err, ErrNotFound) || err == nil && (current.ID != archive.ID || current.Version != archive.Version) {
			return archiveConcurrent(key)
		}
		if err != nil {
			return err
		}
		if err := checkArchiveSource(tx, archive, bus); err != nil {
			return err
		}
		if _, err := s.bus(tx, archive.Source); err != nil {
			return err
		}
		if err := putArchiveRule(tx, archive, managedPattern); err != nil {
			return err
		}
		if in.RetentionDays != nil && archive.RetentionDays != current.RetentionDays {
			if err := tx.UpdateArchiveEntryRetention(archive.ID, archive.RetentionDays); err != nil {
				return err
			}
		}
		archive.EventCount, archive.SizeBytes = current.EventCount, current.SizeBytes
		archive.State, archive.StateReason = "ENABLED", ""
		if keyChanged {
			archive.KeyVersion++
			archive.State = "UPDATING"
			archive.MigrationDue = s.clock.Now().Add(time.Second)
		}
		archive.Version++
		if err := tx.PutArchive(archive); err != nil {
			return err
		}
		out = &api.UpdateArchiveOutput{ArchiveArn: str[api.ArchiveArn](key.ARN()), State: str[api.ArchiveState](archive.State), CreationTime: ptr(api.Timestamp(archive.Created))}
		return s.recordCall(tx.Context(), "UpdateArchive", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}

func (s *Service) deleteArchive(ctx context.Context, in *api.DeleteArchiveInput) (out *api.DeleteArchiveOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "DeleteArchive", in, &out, &rejected, false)
	key := ArchiveKey{Scope: scopeFor(ctx), Name: value(in.ArchiveName)}
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.authorizeArchive(tx, "DeleteArchive", key); err != nil {
			return err
		}
		archive, err := readArchive(tx, key)
		if err != nil {
			return err
		}
		ruleKey := archiveRuleKey(archive)
		rule, err := tx.Rule(ruleKey)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err == nil && rule.ArchiveID == archive.ID {
			targets, err := tx.Targets(ruleKey)
			if err != nil {
				return err
			}
			for _, target := range targets {
				if err := tx.DeleteTarget(ruleKey, target.ID); err != nil {
					return err
				}
			}
			if err := tx.DeleteRule(ruleKey); err != nil {
				return err
			}
		}
		if err := tx.DeleteArchive(key); err != nil {
			return err
		}
		out = &api.DeleteArchiveOutput{}
		return s.recordCall(tx.Context(), "DeleteArchive", in, out, nil)
	})
	if err != nil {
		return nil, wireError(err)
	}
	s.jobs.Wake()
	return out, nil
}

func (s *Service) listArchives(ctx context.Context, in *api.ListArchivesInput) (out *api.ListArchivesOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "ListArchives", in, &out, &rejected, true)
	filters := 0
	if in.EventSourceArn != nil {
		filters++
	}
	if in.NamePrefix != nil {
		filters++
	}
	if in.State != nil {
		filters++
	}
	if filters > 1 {
		return nil, failure("ValidationException", "At most one filter is allowed for ListArchives. Use either : State, EventSourceArn, or NamePrefix.")
	}
	var source BusKey
	if in.EventSourceArn != nil {
		var wire *awswire.Error
		source, wire = archiveSource(ctx, value(in.EventSourceArn))
		if wire != nil {
			return nil, wire
		}
	}
	scope := scopeFor(ctx)
	var rows []ArchiveRecord
	err := s.repository.View(ctx, func(r Reader) error {
		if err := s.authorize(r, "ListArchives", "*", nil, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		if in.EventSourceArn != nil {
			if _, err := archiveSourceBus(r, source); err != nil {
				return err
			}
		}
		var err error
		rows, err = r.Archives(scope)
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	filtered := rows[:0]
	for _, archive := range rows {
		if !strings.HasPrefix(archive.Key.Name, value(in.NamePrefix)) || in.State != nil && archive.State != value(in.State) || in.EventSourceArn != nil && archive.Source != source {
			continue
		}
		filtered = append(filtered, archive)
	}
	collection := (ArchiveKey{Scope: scope}).ARN() + "/ListArchives/" + value(in.NamePrefix) + "/" + value(in.State) + "/" + value(in.EventSourceArn)
	rows, next, wire := page(filtered, func(archive ArchiveRecord) string { return archive.Key.Name }, collection, in.Limit, in.NextToken, "ValidationException")
	if wire != nil {
		return nil, wire
	}
	out = &api.ListArchivesOutput{Archives: api.ArchiveResponseList{}, NextToken: next}
	for _, archive := range rows {
		item := api.Archive{ArchiveName: str[api.ArchiveName](archive.Key.Name), EventSourceArn: str[api.EventBusArn](archive.Source.ARN()),
			State: str[api.ArchiveState](archive.State), RetentionDays: ptr(api.RetentionDays(archive.RetentionDays)),
			SizeBytes: ptr(api.Long(archive.SizeBytes)), EventCount: ptr(api.Long(archive.EventCount)), CreationTime: ptr(api.Timestamp(archive.Created))}
		if archive.StateReason != "" {
			item.StateReason = str[api.ArchiveStateReason](archive.StateReason)
		}
		out.Archives = append(out.Archives, item)
	}
	return out, nil
}

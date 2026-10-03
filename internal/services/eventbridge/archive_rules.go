package eventbridge

import (
	"encoding/json"
	"errors"

	"stackd/internal/awswire"
	"stackd/internal/services/eventbridge/eventpattern"
	"stackd/internal/services/eventbridge/inputtransform"
)

const archiveManagedBy = "prod.vhs.events.aws.internal"

func archiveRuleKey(archive ArchiveRecord) RuleKey {
	return RuleKey{Bus: archive.Source, Name: "Events-Archive-" + archive.Key.Name}
}

func disableManagedArchive(tx Transaction, rule RuleRecord) error {
	if rule.ArchiveID == "" {
		return nil
	}
	archive, err := tx.ArchiveByID(rule.ArchiveID)
	if errors.Is(err, ErrNotFound) {
		// Failed customer-key creation leaves a force-removable orphan rule.
		return nil
	}
	if err != nil {
		return err
	}
	archive.State = "DISABLED"
	archive.StateReason = "Managed rule for the archive was forcefully deleted."
	archive.Version++
	return tx.PutArchive(archive)
}

func archiveManagedPattern(pattern string) (string, *awswire.Error) {
	fields := map[string]json.RawMessage{}
	if pattern != "" {
		if _, err := eventpattern.Compile([]byte(pattern)); err != nil {
			return "", failure("InvalidEventPatternException", err.Error())
		}
		if err := json.Unmarshal([]byte(pattern), &fields); err != nil {
			return "", failure("InvalidEventPatternException", err.Error())
		}
	}
	fields["replay-name"] = json.RawMessage(`[{"exists":false}]`)
	encoded, err := json.Marshal(fields)
	if err != nil {
		return "", wireError(err)
	}
	return string(encoded), nil
}

func archiveRule(archive ArchiveRecord, pattern string) RuleRecord {
	return RuleRecord{Key: archiveRuleKey(archive), ManagedBy: archiveManagedBy, ArchiveID: archive.ID, Pattern: pattern,
		HasPattern: true, State: "ENABLED", CreatedBy: archive.Key.Account}
}

func archiveRuleAvailable(r Reader, archive ArchiveRecord) error {
	rule, err := r.Rule(archiveRuleKey(archive))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if rule.ArchiveID != archive.ID {
		return failure("ResourceAlreadyExistsException", "Rule "+rule.Key.Name+" already exists.")
	}
	return nil
}

func putArchiveRule(tx Transaction, archive ArchiveRecord, pattern string) error {
	if err := archiveRuleAvailable(tx, archive); err != nil {
		return err
	}
	rule := archiveRule(archive, pattern)
	if err := tx.PutRule(rule); err != nil {
		return err
	}
	target := TargetRecord{Rule: rule.Key, ID: rule.Key.Name,
		ARN:        "arn:" + archive.Key.Partition + ":events:" + archive.Key.Region + ":::",
		MaxRetries: 185, MaxAgeSeconds: 86400,
		Input: inputtransform.Definition{Transformer: &inputtransform.Transformer{
			InputPathsMap: map[string]string{},
			InputTemplate: `{"archive-arn": "` + archive.Key.ARN() + ":" + archive.ID + `","event": <aws.events.event.json>,"ingestion-time": <aws.events.event.ingestion-time>}`,
		}},
	}
	return tx.PutTarget(target)
}

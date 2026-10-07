package stepfunctions

import (
	"errors"
	"strconv"
	"time"
	"unicode/utf8"

	api "stackd/internal/awsapi/stepfunctions"
)

func validDescription(description string) error {
	if !utf8.ValidString(description) || utf8.RuneCountInString(description) > 256 {
		return invalid("description must contain at most 256 characters.")
	}
	return nil
}

func (s *Service) publishRevision(tx Transaction, machine *MachineRecord, description string, at time.Time) (VersionRecord, error) {
	versions, err := tx.Versions(machine.Key, machine.ID)
	if err != nil {
		return VersionRecord{}, err
	}
	for _, version := range versions {
		if version.RevisionID == machine.RevisionID {
			if err := cloudFormationCheck(tx.Context(), "StateMachineVersion", version.CFNOwner); err != nil {
				return VersionRecord{}, err
			}
			return version, nil
		}
	}
	if len(versions) >= 1000 {
		return VersionRecord{}, failure("ServiceQuotaExceededException", "The maximum number of state machine versions has been reached.", 400)
	}
	number := machine.NextVersion
	if number < 1 {
		number = 1
	}
	version := VersionRecord{Key: VersionKey{Machine: machine.Key, MachineID: machine.ID, Number: number}, RevisionID: machine.RevisionID, Created: at, Description: description}
	version.CFNOwner = cloudFormationClaim(tx.Context(), "StateMachineVersion")
	if err := tx.PutVersion(version); err != nil {
		return VersionRecord{}, err
	}
	if number == 1 {
		machine.FirstVersionDescription = description
	}
	machine.NextVersion, machine.Version = number+1, machine.Version+1
	if err := tx.PutMachine(*machine); err != nil {
		return VersionRecord{}, err
	}
	return version, nil
}

func (s *Service) publishStateMachineVersion(tx Transaction, in *api.PublishStateMachineVersionInput) (*api.PublishStateMachineVersionOutput, error) {
	machine, _, err := s.controlMachine(tx, value(in.StateMachineArn), "PublishStateMachineVersion", true, true)
	if err != nil {
		return nil, err
	}
	if owner := cloudFormationClaim(tx.Context(), "StateMachineVersion"); owner != "" {
		versions, err := tx.Versions(machine.Key, machine.ID)
		if err != nil {
			return nil, err
		}
		for _, version := range versions {
			if version.CFNOwner == owner {
				return &api.PublishStateMachineVersionOutput{CreationDate: controlTimestamp(version.Created), StateMachineVersionArn: new(api.Arn(version.Key.ARN()))}, nil
			}
		}
	}
	if err := validDescription(value(in.Description)); err != nil {
		return nil, err
	}
	revision, err := tx.Revision(RevisionKey{Scope: machine.Key.Scope, ID: machine.RevisionID})
	if err != nil {
		return nil, err
	}
	if in.RevisionId != nil && !(revision.Initial && value(in.RevisionId) == "INITIAL") && value(in.RevisionId) != revision.Key.ID {
		return nil, failure("ConflictException", "The requested revision is not the current state machine revision.", 400)
	}
	version, err := s.publishRevision(tx, &machine, value(in.Description), s.clock.Now().UTC())
	if err != nil {
		return nil, err
	}
	return &api.PublishStateMachineVersionOutput{CreationDate: controlTimestamp(version.Created), StateMachineVersionArn: new(api.Arn(version.Key.ARN()))}, nil
}

func (s *Service) deleteStateMachineVersion(tx Transaction, in *api.DeleteStateMachineVersionInput) (*api.DeleteStateMachineVersionOutput, error) {
	raw := value(in.StateMachineVersionArn)
	key, qualifier, err := machineReference(raw)
	if err != nil {
		return nil, err
	}
	number, ok := versionNumber(qualifier)
	if !ok {
		return nil, invalid("stateMachineVersionArn must be a version-qualified state machine ARN.")
	}
	machine, _, lookupErr := lookupMachine(tx, raw)
	if denied := s.authorize(tx, "DeleteStateMachineVersion", raw, machine.Tags, nil); denied != nil {
		return nil, denied
	}
	if lookupErr != nil {
		if machine.Key.Name != "" && (key.Scope != scopeFor(tx.Context()) || wireError(lookupErr).Code == "StateMachineDoesNotExist") {
			return &api.DeleteStateMachineVersionOutput{}, nil
		}
		return nil, lookupErr
	}
	version, err := tx.Version(VersionKey{Machine: key, MachineID: machine.ID, Number: number})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if err == nil {
		if err := cloudFormationCheck(tx.Context(), "StateMachineVersion", version.CFNOwner); err != nil {
			return nil, err
		}
	}
	aliases, err := tx.Aliases(key, machine.ID)
	if err != nil {
		return nil, err
	}
	for _, alias := range aliases {
		for _, route := range alias.Routes {
			if route.Version == number {
				return nil, failure("ConflictException", "Version to be deleted must not be referenced by an alias.", 400)
			}
		}
	}
	if err := tx.DeleteVersion(VersionKey{Machine: key, MachineID: machine.ID, Number: number}); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return &api.DeleteStateMachineVersionOutput{}, nil
}

func (s *Service) listStateMachineVersions(tx Transaction, in *api.ListStateMachineVersionsInput) (*api.ListStateMachineVersionsOutput, error) {
	machine, _, err := s.controlMachine(tx, value(in.StateMachineArn), "ListStateMachineVersions", true, false)
	if err != nil {
		return nil, err
	}
	collection := controlCollection(tx, "ListStateMachineVersions", machine.Key.ARN(), machine.ID)
	now := s.clock.Now()
	limit, after, err := controlPage(in.NextToken, in.MaxResults, collection, now)
	if err != nil {
		return nil, err
	}
	var last int64
	if after != "" {
		var ok bool
		last, ok = versionNumber(after)
		if !ok {
			return nil, failure("InvalidToken", "Invalid Token: 'Invalid token'", 400)
		}
	}
	versions, err := tx.Versions(machine.Key, machine.ID)
	if err != nil {
		return nil, err
	}
	out := &api.ListStateMachineVersionsOutput{StateMachineVersions: api.StateMachineVersionList{}}
	for _, version := range versions {
		if last != 0 && version.Key.Number >= last {
			continue
		}
		if len(out.StateMachineVersions) == limit {
			out.NextToken = controlNext(collection, after, now)
			break
		}
		out.StateMachineVersions = append(out.StateMachineVersions, api.StateMachineVersionListItem{CreationDate: controlTimestamp(version.Created), StateMachineVersionArn: new(api.LongArn(version.Key.ARN()))})
		after = strconv.FormatInt(version.Key.Number, 10)
	}
	return out, nil
}

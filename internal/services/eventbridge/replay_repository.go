package eventbridge

import "time"

// ReplayKey scopes replay names and their retained terminal history.
type ReplayKey struct {
	Scope
	Name string
}

func (k ReplayKey) ARN() string {
	return "arn:" + k.Partition + ":events:" + k.Region + ":" + k.Account + ":replay/" + k.Name
}

// ReplayRecord retains the selected archive incarnation, requested time window,
// rule filters and processing cursor. Targets and rule patterns are resolved
// when each replayed event enters the source bus, not when the replay is created.
// A zero Finished denotes active work; an empty Cursor.ID denotes no scanned
// archive event and therefore no EventLastReplayedTime.
type ReplayRecord struct {
	Key                    ReplayKey
	Archive                ArchiveKey
	ArchiveID              string
	Destination            BusKey
	Description            string
	FilterARNs             []string
	StartTime, EndTime     time.Time
	Started, Finished, Due time.Time
	Cursor                 ArchiveCursor
	State, StateReason     string
	Version                uint64
	RequestID, ActorARN    string
}

type ReplayReader interface {
	Replay(ReplayKey) (ReplayRecord, error)
	Replays(Scope) ([]ReplayRecord, error)
	NextReplay() (ReplayRecord, bool, error)
	NextReplayExpiration() (ReplayRecord, bool, error)
}

type ReplayWriter interface {
	PutReplay(ReplayRecord) error
	DeleteReplay(ReplayKey) error
}

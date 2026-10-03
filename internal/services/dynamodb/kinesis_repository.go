package dynamodb

import (
	"time"
)

// Each enable owns an immutable subscription identity. Retired subscriptions
// briefly drain independently, so changing controls cannot redirect accepted writes.
type KinesisDestination struct {
	ID               string
	Table            TableKey
	PhysicalName     string
	StreamARN        string
	Status           string
	Description      string
	Precision        string
	PendingPrecision string
	AdmissionFailure string
	Superseded       bool
	Due              time.Time
	CaptureUntil     time.Time
}

type KinesisConsumer struct {
	ID, StreamARN, Precision string
	CaptureUntil             time.Time
}

type KinesisDelivery struct {
	ID            string
	DestinationID string
	Table         TableKey
	StreamARN     string
	PartitionKey  string
	Data          []byte
	ParentEventID string
	Due           time.Time
	Attempts      int64
	LastError     string
}

type KinesisReader interface {
	KinesisDestinations() ([]KinesisDestination, error)
	KinesisDeliveries() ([]KinesisDelivery, error)
	NextKinesisDelivery() (string, time.Time, error)
	KinesisDelivery(string) (KinesisDelivery, error)
}

type KinesisWriter interface {
	PutKinesisDestination(KinesisDestination) error
	PutKinesisDelivery(KinesisDelivery) error
	DeleteKinesisDelivery(string) error
}

func kinesisConsumers(destinations []KinesisDestination, physical string) []KinesisConsumer {
	var out []KinesisConsumer
	for _, d := range destinations {
		if d.PhysicalName != physical {
			continue
		}
		if d.Status == "ACTIVE" || d.Status == "UPDATING" || d.Status == "DISABLING" || d.Status == "DISABLED" && !d.CaptureUntil.IsZero() {
			out = append(out, KinesisConsumer{ID: d.ID, StreamARN: d.StreamARN, Precision: d.Precision, CaptureUntil: d.CaptureUntil})
		}
	}
	return out
}

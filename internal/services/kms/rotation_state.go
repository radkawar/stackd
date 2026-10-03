package kms

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// AWS completes on-demand rotation in the background. The native capture took
// about 100 seconds; service time makes this modeled delay deterministic.
const onDemandRotationDelay = 2 * time.Minute

func generateSymmetricMaterial() KeyMaterialRecord {
	var id [32]byte
	_, _ = rand.Read(id[:])
	material := make([]byte, 32)
	_, _ = rand.Read(material)
	return KeyMaterialRecord{ID: hex.EncodeToString(id[:]), Material: material}
}

// advanceRotation applies due transitions in time order in the owning key
// transaction. All API and service consumers observe the same material history.
func advanceRotation(k *key, now time.Time) {
	// TODO: Comeback capture variable rotation completion/propagation and remaining automatic-rotation, quota/error precedence and partition conformance; current transitions use deterministic service time.
	for {
		due, kind := nextRotation(k)
		if due.IsZero() || now.Before(due) {
			return
		}
		material := generateSymmetricMaterial()
		material.RotationDate, material.RotationType = due, kind
		k.Materials = append(k.Materials, material)
		k.CurrentMaterialID = material.ID
		if kind == "ON_DEMAND" {
			k.Rotation.OnDemandStarted = time.Time{}
		} else {
			k.Rotation.Next = due.Add(time.Duration(k.Rotation.PeriodInDays) * 24 * time.Hour)
		}
	}
}

func nextRotation(k *key) (time.Time, string) {
	var due time.Time
	kind := "AUTOMATIC"
	if (k.Rotation.Enabled || k.manager == "AWS") && (k.state == "Enabled" || k.state == "Updating") {
		due = k.Rotation.Next
	}
	if !k.Rotation.OnDemandStarted.IsZero() {
		demand := k.Rotation.OnDemandStarted.Add(onDemandRotationDelay)
		if due.IsZero() || demand.Before(due) {
			due, kind = demand, "ON_DEMAND"
		}
	}
	return due, kind
}

// A disabled key skips missed automatic rotations. Re-enabling rotates once
// immediately when overdue, then starts a fresh period.
func resumeRotation(k *key, now time.Time) {
	if k.Origin == "EXTERNAL" {
		return // Shared import expiry and rotation are owned by advanceImported.
	}
	if k.Rotation.Enabled && !now.Before(k.Rotation.Next) {
		k.Rotation.Next = now
	}
	advanceRotation(k, now)
}

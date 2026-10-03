package eventbridge

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"stackd/internal/awsenvelope"
)

func TestBusEnvelopeAnonymizedRecovery(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/aws/eventbridge/bus_kms_envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	// This vector was locally re-sealed after account anonymization; it is not
	// unchanged native AWS ciphertext. The captured data key remains test material.
	var native struct {
		BusARN     string `json:"bus_arn"`
		KeyARN     string `json:"key_arn"`
		Ciphertext []byte `json:"ciphertext"`
		WrappedKey []byte `json:"wrapped_key"`
		DataKey    []byte `json:"data_key"`
		Plaintext  string `json:"plaintext"`
		Provenance string `json:"fixture_provenance"`
	}
	if err := json.Unmarshal(data, &native); err != nil {
		t.Fatal(err)
	}
	if native.Provenance != "Locally re-sealed account-anonymized derivative of an AWS capture; wrapped_key is a local fixture identifier, not a KMS ciphertext." {
		t.Fatal("missing local re-sealing provenance")
	}
	plain, err := awsenvelope.Open(native.DataKey, native.WrappedKey, native.KeyARN, map[string]string{"aws:events:event-bus:arn": native.BusARN}, native.Ciphertext)
	if err != nil || string(plain) != native.Plaintext {
		t.Fatalf("anonymized envelope recovery: %q %v", plain, err)
	}
	if _, err := awsenvelope.Open(native.DataKey, native.WrappedKey, native.KeyARN, map[string]string{"aws:events:event-bus:arn": native.BusARN + "-other"}, native.Ciphertext); err == nil {
		t.Fatal("ciphertext accepted for another bus")
	}
	corrupted := bytes.Clone(native.Ciphertext)
	corrupted[len(corrupted)-1] ^= 1
	if _, err := awsenvelope.Open(native.DataKey, native.WrappedKey, native.KeyARN, map[string]string{"aws:events:event-bus:arn": native.BusARN}, corrupted); err == nil {
		t.Fatal("corrupted anonymized ciphertext authenticated")
	}
	// Exercise the final-frame boundary and multiple regular frames, preserving
	// the exact customer bytes instead of unmarshalling and reserializing them.
	content := bytes.Repeat([]byte("customer event bytes\n"), awsenvelope.FrameLength)
	sealed, err := awsenvelope.Seal(native.DataKey, native.WrappedKey, native.KeyARN, map[string]string{"aws:events:event-bus:arn": native.BusARN}, content)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := awsenvelope.Open(native.DataKey, native.WrappedKey, native.KeyARN, map[string]string{"aws:events:event-bus:arn": native.BusARN}, sealed)
	if err != nil || !bytes.Equal(opened, content) {
		t.Fatalf("framed recovery: %v", err)
	}
}

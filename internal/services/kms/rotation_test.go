package kms

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkkms "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"

	"stackd/clock"
	"stackd/internal/awsctx"
)

func rotationStatus(t *testing.T, c *sdkkms.Client, id *string) *sdkkms.GetKeyRotationStatusOutput {
	t.Helper()
	out, err := c.GetKeyRotationStatus(t.Context(), &sdkkms.GetKeyRotationStatusInput{KeyId: id})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func rotationMaterials(t *testing.T, c *sdkkms.Client, id *string) []types.RotationsListEntry {
	t.Helper()
	out, err := c.ListKeyRotations(t.Context(), &sdkkms.ListKeyRotationsInput{KeyId: id, IncludeKeyMaterial: types.IncludeKeyMaterialAllKeyMaterial})
	if err != nil {
		t.Fatal(err)
	}
	return out.Rotations
}

func TestSDKRotationNativeEligibilityAndStates(t *testing.T) {
	capture := readCryptoCapture(t, "rotation")
	c := sdkClient(t, New(), rootMetadata("111111111111", "us-east-1", "aws"))
	k := createSDKKey(t, c)
	for i := range capture.Observations {
		row := &capture.Observations[i]
		row.Error.Message = strings.ReplaceAll(row.Error.Message, aws.ToString(capture.Keys[0].Arn), aws.ToString(k.Arn))
	}
	for _, row := range capture.Observations {
		if row.Case == "initial_status" {
			var native sdkkms.GetKeyRotationStatusOutput
			if err := json.Unmarshal(row.Output, &native); err != nil {
				t.Fatal(err)
			}
			out := rotationStatus(t, c, k.KeyId)
			if out.KeyRotationEnabled != native.KeyRotationEnabled || out.RotationPeriodInDays != nil || out.NextRotationDate != nil || out.OnDemandRotationStartDate != nil || aws.ToString(out.KeyId) != aws.ToString(k.Arn) {
				t.Fatal("initial rotation fields differ from AWS")
			}
		}
	}
	operations := map[string]func(*string) error{
		"get-key-rotation-status": func(id *string) error {
			_, err := c.GetKeyRotationStatus(t.Context(), &sdkkms.GetKeyRotationStatusInput{KeyId: id})
			return err
		},
		"list-key-rotations": func(id *string) error {
			_, err := c.ListKeyRotations(t.Context(), &sdkkms.ListKeyRotationsInput{KeyId: id})
			return err
		},
		"enable-key-rotation": func(id *string) error {
			_, err := c.EnableKeyRotation(t.Context(), &sdkkms.EnableKeyRotationInput{KeyId: id})
			return err
		},
		"disable-key-rotation": func(id *string) error {
			_, err := c.DisableKeyRotation(t.Context(), &sdkkms.DisableKeyRotationInput{KeyId: id})
			return err
		},
		"rotate-key-on-demand": func(id *string) error {
			_, err := c.RotateKeyOnDemand(t.Context(), &sdkkms.RotateKeyOnDemandInput{KeyId: id})
			return err
		},
	}
	for op, invoke := range operations {
		for _, alias := range []string{"alias/rotation", "arn:aws:kms:us-east-1:111111111111:alias/rotation"} {
			capture.requireError(t, invoke(&alias), "alias_"+op, "", "", "", true)
		}
	}
	for _, period := range []int32{89, 2561} {
		_, err := c.EnableKeyRotation(t.Context(), &sdkkms.EnableKeyRotationInput{KeyId: k.KeyId, RotationPeriodInDays: &period})
		requireCode(t, err, "ValidationException")
	}
	if _, err := c.EnableKeyRotation(t.Context(), &sdkkms.EnableKeyRotationInput{KeyId: k.KeyId, RotationPeriodInDays: aws.Int32(90)}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DisableKey(t.Context(), &sdkkms.DisableKeyInput{KeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	for op, invoke := range operations {
		err := invoke(k.KeyId)
		if op == "get-key-rotation-status" || op == "list-key-rotations" {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			capture.requireError(t, err, "disabled_"+op, "", "", "", true)
		}
	}
	if !rotationStatus(t, c, k.KeyId).KeyRotationEnabled {
		t.Fatal("disable-key lost automatic rotation configuration")
	}
	if _, err := c.ScheduleKeyDeletion(t.Context(), &sdkkms.ScheduleKeyDeletionInput{KeyId: k.KeyId, PendingWindowInDays: aws.Int32(7)}); err != nil {
		t.Fatal(err)
	}
	for op, invoke := range operations {
		err := invoke(k.KeyId)
		if op == "get-key-rotation-status" || op == "list-key-rotations" {
			if err != nil {
				t.Fatal(err)
			}
		} else {
			capture.requireError(t, err, "deleting_"+op, "", "", "", true)
		}
	}
	if out := rotationStatus(t, c, k.KeyId); out.KeyRotationEnabled || out.NextRotationDate != nil || out.RotationPeriodInDays != nil {
		t.Fatal("pending-deletion rotation fields differ from AWS")
	}
	if _, err := c.CancelKeyDeletion(t.Context(), &sdkkms.CancelKeyDeletionInput{KeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	if !rotationStatus(t, c, k.KeyId).KeyRotationEnabled {
		t.Fatal("cancel deletion did not restore rotation configuration")
	}
	hmac := createAsymmetricSDKKey(t, c, types.KeySpecHmac256, types.KeyUsageTypeGenerateVerifyMac)
	for op, invoke := range operations {
		err := invoke(hmac.KeyId)
		if op == "enable-key-rotation" || op == "rotate-key-on-demand" {
			capture.requireError(t, err, "hmac_"+op, "", "", "", true)
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSDKRotationRetainsCiphertextAndPendingWork(t *testing.T) {
	start := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	source := clock.NewManual(start)
	backend := NewMemoryStorage(nil)
	config := Config{Storage: backend, Clock: source}
	scope := rootMetadata("111111111111", "us-east-1", "aws")
	c := sdkClient(t, NewWithConfig(config), scope)
	k := createSDKKey(t, c)
	ec := map[string]string{"purpose": "rotation"}
	plaintext := []byte("survives rotation")
	before, err := c.Encrypt(t.Context(), &sdkkms.EncryptInput{KeyId: k.KeyId, Plaintext: plaintext, EncryptionContext: ec})
	if err != nil {
		t.Fatal(err)
	}
	data, err := c.GenerateDataKey(t.Context(), &sdkkms.GenerateDataKeyInput{KeyId: k.KeyId, KeySpec: types.DataKeySpecAes256})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.EnableKeyRotation(t.Context(), &sdkkms.EnableKeyRotationInput{KeyId: k.KeyId, RotationPeriodInDays: aws.Int32(90)}); err != nil {
		t.Fatal(err)
	}
	next := *rotationStatus(t, c, k.KeyId).NextRotationDate
	for range 2 {
		rotated, err := c.RotateKeyOnDemand(t.Context(), &sdkkms.RotateKeyOnDemandInput{KeyId: k.KeyId})
		if err != nil || aws.ToString(rotated.KeyId) != aws.ToString(k.Arn) {
			t.Fatal("on-demand acceptance", err)
		}
	}
	if out := rotationStatus(t, c, k.KeyId); out.OnDemandRotationStartDate == nil || !out.OnDemandRotationStartDate.Equal(start) || !out.NextRotationDate.Equal(next) {
		t.Fatal("pending rotation did not retain schedule/start")
	}
	if len(rotationMaterials(t, c, k.KeyId)) != 1 {
		t.Fatal("on-demand rotation completed synchronously")
	}
	// Replace the service while its job is pending; all job and material state
	// must belong to the caller-retained typed repository.
	c = sdkClient(t, NewWithConfig(config), scope)
	if err := source.Advance(2 * time.Minute); err != nil {
		t.Fatal(err)
	}
	materials := rotationMaterials(t, c, k.KeyId)
	if len(materials) != 2 || materials[0].RotationDate != nil || materials[0].KeyMaterialState != types.KeyMaterialStateNonCurrent || materials[1].RotationType != types.RotationTypeOnDemand || materials[1].KeyMaterialState != types.KeyMaterialStateCurrent || aws.ToString(materials[0].KeyMaterialId) == aws.ToString(materials[1].KeyMaterialId) {
		t.Fatal("incorrect retained material history")
	}
	if out := rotationStatus(t, c, k.KeyId); out.OnDemandRotationStartDate != nil || !out.NextRotationDate.Equal(next) {
		t.Fatal("completed rotation changed automatic schedule")
	}
	if err := backend.View(t.Context(), func(tx Reader) error {
		set, err := tx.KeySet(KeyOwner{Partition: "aws", AccountID: "111111111111"}, aws.ToString(k.KeyId))
		if err != nil {
			return err
		}
		for _, material := range set.Materials {
			clear(material.Material)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	old, err := c.Decrypt(t.Context(), &sdkkms.DecryptInput{CiphertextBlob: before.CiphertextBlob, EncryptionContext: ec})
	if err != nil || !bytes.Equal(old.Plaintext, plaintext) || aws.ToString(old.KeyMaterialId) != aws.ToString(materials[0].KeyMaterialId) {
		t.Fatal("old material decryption", err)
	}
	unwrapped, err := c.Decrypt(t.Context(), &sdkkms.DecryptInput{CiphertextBlob: data.CiphertextBlob})
	if err != nil || !bytes.Equal(unwrapped.Plaintext, data.Plaintext) || aws.ToString(unwrapped.KeyMaterialId) != aws.ToString(data.KeyMaterialId) {
		t.Fatal("retained data key", err)
	}
	wrapped, err := c.ReEncrypt(t.Context(), &sdkkms.ReEncryptInput{CiphertextBlob: before.CiphertextBlob, SourceEncryptionContext: ec, DestinationKeyId: k.KeyId, DestinationEncryptionContext: ec})
	if err != nil || aws.ToString(wrapped.SourceKeyMaterialId) != aws.ToString(materials[0].KeyMaterialId) || aws.ToString(wrapped.DestinationKeyMaterialId) != aws.ToString(materials[1].KeyMaterialId) {
		t.Fatal("same-key re-encryption must use current destination material", err)
	}
	current, err := c.Decrypt(t.Context(), &sdkkms.DecryptInput{CiphertextBlob: wrapped.CiphertextBlob, EncryptionContext: ec})
	if err != nil || !bytes.Equal(current.Plaintext, plaintext) {
		t.Fatal("re-encrypted ciphertext", err)
	}
	tampered := bytes.Replace(bytes.Clone(before.CiphertextBlob), []byte(aws.ToString(materials[0].KeyMaterialId)), []byte(aws.ToString(materials[1].KeyMaterialId)), 1)
	_, err = c.Decrypt(t.Context(), &sdkkms.DecryptInput{CiphertextBlob: tampered, EncryptionContext: ec})
	requireCode(t, err, "InvalidCiphertextException")
	first, err := c.ListKeyRotations(t.Context(), &sdkkms.ListKeyRotationsInput{KeyId: k.KeyId, IncludeKeyMaterial: types.IncludeKeyMaterialAllKeyMaterial, Limit: aws.Int32(1)})
	if err != nil || !first.Truncated || len(first.Rotations) != 1 {
		t.Fatal("first page", err)
	}
	second, err := c.ListKeyRotations(t.Context(), &sdkkms.ListKeyRotationsInput{KeyId: k.KeyId, Marker: first.NextMarker, Limit: aws.Int32(1)})
	if err != nil || second.Truncated || len(second.Rotations) != 1 || second.Rotations[0].RotationType != types.RotationTypeOnDemand {
		t.Fatal("rotation-only continuation", err)
	}
	other := createSDKKey(t, c)
	_, err = c.ListKeyRotations(t.Context(), &sdkkms.ListKeyRotationsInput{KeyId: other.KeyId, Marker: first.NextMarker})
	requireCode(t, err, "InvalidMarkerException")
	if _, err := c.RotateKeyOnDemand(t.Context(), &sdkkms.RotateKeyOnDemandInput{KeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DisableKey(t.Context(), &sdkkms.DisableKeyInput{KeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(2 * time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(rotationMaterials(t, c, k.KeyId)) != 3 || rotationStatus(t, c, k.KeyId).OnDemandRotationStartDate != nil {
		t.Fatal("accepted rotation must complete after disabling the key, as AWS captured")
	}
	_, err = c.Decrypt(t.Context(), &sdkkms.DecryptInput{CiphertextBlob: before.CiphertextBlob, EncryptionContext: ec})
	requireCode(t, err, "DisabledException")
	if _, err := c.EnableKey(t.Context(), &sdkkms.EnableKeyInput{KeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.RotateKeyOnDemand(t.Context(), &sdkkms.RotateKeyOnDemandInput{KeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ScheduleKeyDeletion(t.Context(), &sdkkms.ScheduleKeyDeletionInput{KeyId: k.KeyId, PendingWindowInDays: aws.Int32(7)}); err != nil {
		t.Fatal(err)
	}
	if out := rotationStatus(t, c, k.KeyId); out.KeyRotationEnabled || out.OnDemandRotationStartDate == nil {
		t.Fatal("pending deletion must retain accepted on-demand work")
	}
	if err := source.Advance(2 * time.Minute); err != nil {
		t.Fatal(err)
	}
	if len(rotationMaterials(t, c, k.KeyId)) != 4 || rotationStatus(t, c, k.KeyId).OnDemandRotationStartDate != nil {
		t.Fatal("accepted rotation did not finish during pending deletion")
	}
	if err := source.Advance(7 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	_, err = c.Decrypt(t.Context(), &sdkkms.DecryptInput{CiphertextBlob: before.CiphertextBlob, EncryptionContext: ec})
	requireCode(t, err, "NotFoundException")
}

func TestSDKAutomaticRotationSchedulesAndResume(t *testing.T) {
	start := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	source := clock.NewManual(start)
	c := sdkClient(t, NewWithConfig(Config{Clock: source}), rootMetadata("111111111111", "us-east-1", "aws"))
	k := createSDKKey(t, c)
	enable := func(period *int32) {
		t.Helper()
		if _, err := c.EnableKeyRotation(t.Context(), &sdkkms.EnableKeyRotationInput{KeyId: k.KeyId, RotationPeriodInDays: period}); err != nil {
			t.Fatal(err)
		}
	}
	enable(aws.Int32(90))
	next := *rotationStatus(t, c, k.KeyId).NextRotationDate
	if err := source.Advance(time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, period := range []*int32{nil, aws.Int32(90)} {
		enable(period)
		if out := rotationStatus(t, c, k.KeyId); !out.NextRotationDate.Equal(next) || aws.ToInt32(out.RotationPeriodInDays) != 90 {
			t.Fatal("repeated enable must preserve schedule")
		}
	}
	enable(aws.Int32(2560))
	if out := rotationStatus(t, c, k.KeyId); !out.NextRotationDate.Equal(source.Now().Add(2560 * 24 * time.Hour)) {
		t.Fatal("changed period did not reschedule")
	}
	if _, err := c.DisableKeyRotation(t.Context(), &sdkkms.DisableKeyRotationInput{KeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	enable(nil)
	if aws.ToInt32(rotationStatus(t, c, k.KeyId).RotationPeriodInDays) != 365 {
		t.Fatal("re-enabling without a period must default to 365 days")
	}
	if _, err := c.DisableKey(t.Context(), &sdkkms.DisableKeyInput{KeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(2 * 365 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	if len(rotationMaterials(t, c, k.KeyId)) != 1 {
		t.Fatal("disabled keys must not rotate automatically")
	}
	if _, err := c.EnableKey(t.Context(), &sdkkms.EnableKeyInput{KeyId: k.KeyId}); err != nil {
		t.Fatal(err)
	}
	materials := rotationMaterials(t, c, k.KeyId)
	if len(materials) != 2 || materials[1].RotationType != types.RotationTypeAutomatic || !materials[1].RotationDate.Equal(source.Now()) {
		t.Fatal("overdue key must rotate once on re-enable")
	}
	if err := source.Advance(2 * 365 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	if len(rotationMaterials(t, c, k.KeyId)) != 4 {
		t.Fatal("enabled key must retain each elapsed automatic rotation")
	}
}

func TestSDKRotationQuotaConflictsAndFailedCommit(t *testing.T) {
	source := clock.NewManual(time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC))
	backend := NewMemoryStorage(nil)
	scope := rootMetadata("111111111111", "us-east-1", "aws")
	c := sdkClient(t, NewWithConfig(Config{Storage: backend, Clock: source}), scope)
	k := createSDKKey(t, c)
	failing := sdkClient(t, NewWithConfig(Config{Storage: failWrites{Storage: backend}, Clock: source}), scope)
	_, err := failing.RotateKeyOnDemand(t.Context(), &sdkkms.RotateKeyOnDemandInput{KeyId: k.KeyId})
	requireCode(t, err, "KMSInternalException")
	if rotationStatus(t, c, k.KeyId).OnDemandRotationStartDate != nil {
		t.Fatal("failed transaction retained an accepted request")
	}
	for range 25 {
		if _, err := c.RotateKeyOnDemand(t.Context(), &sdkkms.RotateKeyOnDemandInput{KeyId: k.KeyId}); err != nil {
			t.Fatal(err)
		}
		if err := source.Advance(2 * time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	_, err = c.RotateKeyOnDemand(t.Context(), &sdkkms.RotateKeyOnDemandInput{KeyId: k.KeyId})
	requireCode(t, err, "LimitExceededException")
	if len(rotationMaterials(t, c, k.KeyId)) != 26 {
		t.Fatal("quota rejection lost completed history")
	}
	k = createSDKKey(t, c)
	if _, err := c.EnableKeyRotation(t.Context(), &sdkkms.EnableKeyRotationInput{KeyId: k.KeyId, RotationPeriodInDays: aws.Int32(90)}); err != nil {
		t.Fatal(err)
	}
	if err := source.Advance(90*24*time.Hour - 20*time.Minute); err != nil {
		t.Fatal(err)
	}
	_, err = c.RotateKeyOnDemand(t.Context(), &sdkkms.RotateKeyOnDemandInput{KeyId: k.KeyId})
	requireCode(t, err, "ConflictException")
	if err := source.Advance(20 * time.Minute); err != nil {
		t.Fatal(err)
	}
	_, err = failing.DescribeKey(t.Context(), &sdkkms.DescribeKeyInput{KeyId: k.KeyId})
	requireCode(t, err, "KMSInternalException")
	if len(rotationMaterials(t, c, k.KeyId)) != 2 {
		t.Fatal("rotation must recover exactly once after a failed material commit")
	}
}

func TestSDKManagedKeyAnnualRotationAndServiceDecryption(t *testing.T) {
	source := clock.NewManual(time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC))
	s := NewWithConfig(Config{Clock: source})
	scope := rootMetadata("111111111111", "us-east-1", "aws")
	root := awsctx.WithMetadata(t.Context(), scope)
	arn, keyErr := s.EnsureServiceKey(root, "sqs")
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	c := sdkClient(t, s, scope)
	// Fresh AWS-managed SQS keys report false with no schedule fields, while
	// their material is subject to AWS's documented fixed annual rotation.
	if out := rotationStatus(t, c, &arn); out.KeyRotationEnabled || out.RotationPeriodInDays != nil || out.NextRotationDate != nil {
		t.Fatal("managed key metadata differs from the native fresh-key capture")
	}
	_, err := c.EnableKeyRotation(t.Context(), &sdkkms.EnableKeyRotationInput{KeyId: &arn})
	requireCode(t, err, "AccessDeniedException")
	_, err = c.DisableKeyRotation(t.Context(), &sdkkms.DisableKeyRotationInput{KeyId: &arn})
	requireCode(t, err, "AccessDeniedException")
	_, err = c.RotateKeyOnDemand(t.Context(), &sdkkms.RotateKeyOnDemandInput{KeyId: &arn})
	requireCode(t, err, "AccessDeniedException")
	viaSQS := WithViaService(root, "sqs")
	context := map[string]string{"aws:sqs:queuearn": "arn:aws:sqs:us-east-1:111111111111:rotating"}
	plain, blob, _, keyErr := s.GenerateDataKey(viaSQS, arn, context)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	if err := source.Advance(365 * 24 * time.Hour); err != nil {
		t.Fatal(err)
	}
	decoded, _, keyErr := s.Decrypt(viaSQS, blob, context)
	if keyErr != nil || !bytes.Equal(decoded, plain) {
		t.Fatal("managed rotation lost a service data key", keyErr)
	}
	materials := rotationMaterials(t, c, &arn)
	if len(materials) != 2 || materials[1].RotationType != types.RotationTypeAutomatic {
		t.Fatal("managed annual rotation did not produce new material")
	}
}

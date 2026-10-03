package iam_test

import (
	"encoding/base32"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/internal/identity"
)

func TestIAMCredentialDefaultsAndPagination(t *testing.T) {
	f := newActivityFixture(t, nil, time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC))
	ctx := t.Context()
	var clients []*sdkiam.Client
	var firstKeys []identity.Credential
	for _, name := range []string{"first", "second"} {
		key := f.user(t, name)
		firstKeys = append(firstKeys, key)
		client := f.client("us-east-1", key)
		clients = append(clients, client)
		_, err := client.CreateAccessKey(ctx, &sdkiam.CreateAccessKeyInput{})
		requireCode(t, err, "AccessDenied")
		policy := `{"Statement":{"Effect":"Allow","Action":["iam:CreateAccessKey","iam:ListAccessKeys","iam:UpdateAccessKey","iam:DeleteAccessKey","iam:ListMFADevices"],"Resource":"` + key.PrincipalARN + `"}}`
		_, err = f.root.PutUserPolicy(ctx, &sdkiam.PutUserPolicyInput{UserName: &name, PolicyName: aws.String("own-credentials"), PolicyDocument: &policy})
		if err != nil {
			t.Fatal(err)
		}
		created, err := client.CreateAccessKey(ctx, &sdkiam.CreateAccessKeyInput{})
		if err != nil || aws.ToString(created.AccessKey.UserName) != name {
			t.Fatalf("implicit key owner = %+v, %v", created, err)
		}
		for i := range 2 {
			device, err := f.root.CreateVirtualMFADevice(ctx, &sdkiam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String(fmt.Sprintf("%s-%d", name, i))})
			if err != nil {
				t.Fatal(err)
			}
			seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(device.VirtualMFADevice.Base32StringSeed))
			if err != nil {
				t.Fatal(err)
			}
			step := f.clock.Now().Unix() / 30
			_, err = f.root.EnableMFADevice(ctx, &sdkiam.EnableMFADeviceInput{UserName: &name, SerialNumber: device.VirtualMFADevice.SerialNumber, AuthenticationCode1: aws.String(testMFAOTP(seed, step-1)), AuthenticationCode2: aws.String(testMFAOTP(seed, step))})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	keys, err := clients[0].ListAccessKeys(ctx, &sdkiam.ListAccessKeysInput{MaxItems: aws.Int32(1)})
	if err != nil || len(keys.AccessKeyMetadata) != 1 || !keys.IsTruncated {
		t.Fatalf("first key page = %+v, %v", keys, err)
	}
	for _, userName := range []*string{nil, aws.String("first")} {
		next, err := clients[0].ListAccessKeys(ctx, &sdkiam.ListAccessKeysInput{UserName: userName, Marker: keys.Marker})
		if err != nil || len(next.AccessKeyMetadata) != 1 || next.IsTruncated || aws.ToString(next.AccessKeyMetadata[0].UserName) != "first" || aws.ToString(next.AccessKeyMetadata[0].AccessKeyId) == aws.ToString(keys.AccessKeyMetadata[0].AccessKeyId) {
			t.Fatalf("implicit/explicit continuation = %+v, %v", next, err)
		}
	}
	_, err = clients[1].ListAccessKeys(ctx, &sdkiam.ListAccessKeysInput{Marker: keys.Marker})
	requireCode(t, err, "InvalidInput")
	_, err = clients[1].ListAccessKeys(ctx, &sdkiam.ListAccessKeysInput{UserName: aws.String("first"), Marker: keys.Marker})
	requireCode(t, err, "AccessDenied")
	devices, err := clients[0].ListMFADevices(ctx, &sdkiam.ListMFADevicesInput{MaxItems: aws.Int32(1)})
	if err != nil || len(devices.MFADevices) != 1 || !devices.IsTruncated {
		t.Fatalf("first MFA page = %+v, %v", devices, err)
	}
	next, err := clients[0].ListMFADevices(ctx, &sdkiam.ListMFADevicesInput{Marker: devices.Marker})
	if err != nil || len(next.MFADevices) != 1 || next.IsTruncated || aws.ToString(next.MFADevices[0].UserName) != "first" || aws.ToString(next.MFADevices[0].SerialNumber) == aws.ToString(devices.MFADevices[0].SerialNumber) {
		t.Fatalf("implicit MFA continuation = %+v, %v", next, err)
	}
	_, err = clients[1].ListMFADevices(ctx, &sdkiam.ListMFADevicesInput{Marker: devices.Marker})
	requireCode(t, err, "InvalidInput")
	// Implicit ownership must also reach mutations and the gateway's credential resolver.
	key := firstKeys[0].AccessKeyID
	_, err = clients[0].UpdateAccessKey(ctx, &sdkiam.UpdateAccessKeyInput{AccessKeyId: &key, Status: types.StatusTypeExpired})
	requireCode(t, err, "InvalidInput")
	_, err = clients[0].UpdateAccessKey(ctx, &sdkiam.UpdateAccessKeyInput{AccessKeyId: &key, Status: types.StatusTypeInactive})
	if err != nil {
		t.Fatal(err)
	}
	_, err = clients[0].ListAccessKeys(ctx, &sdkiam.ListAccessKeysInput{})
	requireCode(t, err, "InvalidClientTokenId")
	_, err = f.root.UpdateAccessKey(ctx, &sdkiam.UpdateAccessKeyInput{UserName: aws.String("first"), AccessKeyId: &key, Status: types.StatusTypeActive})
	if err != nil {
		t.Fatal(err)
	}
	_, err = clients[0].DeleteAccessKey(ctx, &sdkiam.DeleteAccessKeyInput{AccessKeyId: &key})
	if err != nil {
		t.Fatal(err)
	}
	_, err = clients[0].ListAccessKeys(ctx, &sdkiam.ListAccessKeysInput{})
	requireCode(t, err, "InvalidClientTokenId")
}

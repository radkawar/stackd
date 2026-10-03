package iam_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"image/png"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	sdkiam "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"stackd/clock"
	"stackd/internal/services/iam"
)

func testMFAOTP(seed []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, seed)
	mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1_000_000)
}

func TestVirtualMFALifecycleThroughSDK(t *testing.T) {
	source := clock.NewManual(time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC))
	service := iam.NewWithConfig(iam.Config{Clock: source})
	client := clientFor(t, service, "123456789012", "us-east-1")
	ctx := context.Background()
	user, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("mfa-user")})
	if err != nil {
		t.Fatal(err)
	}
	other, err := client.CreateUser(ctx, &sdkiam.CreateUserInput{UserName: aws.String("other-user")})
	if err != nil {
		t.Fatal(err)
	}
	created, err := client.CreateVirtualMFADevice(ctx, &sdkiam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String("phone"), Path: aws.String("/devices/"), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("security")}}})
	if err != nil {
		t.Fatal(err)
	}
	serial := aws.ToString(created.VirtualMFADevice.SerialNumber)
	if serial != "arn:aws:iam::123456789012:mfa/devices/phone" {
		t.Fatal(serial)
	}
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(created.VirtualMFADevice.Base32StringSeed))
	if err != nil || len(seed) != 20 {
		t.Fatalf("MFA seed decoding: %v", err)
	}
	if _, err := png.Decode(bytes.NewReader(created.VirtualMFADevice.QRCodePNG)); err != nil {
		t.Fatalf("not a real PNG QR code: %v", err)
	}
	step := source.Now().Unix() / 30
	_, err = client.EnableMFADevice(ctx, &sdkiam.EnableMFADeviceInput{UserName: user.User.UserName, SerialNumber: aws.String(serial), AuthenticationCode1: aws.String(testMFAOTP(seed, step-1)), AuthenticationCode2: aws.String(testMFAOTP(seed, step-1))})
	var invalid *types.InvalidAuthenticationCodeException
	if !errors.As(err, &invalid) {
		t.Fatalf("invalid code pair not a modeled error: %v", err)
	}
	_, err = client.EnableMFADevice(ctx, &sdkiam.EnableMFADeviceInput{UserName: user.User.UserName, SerialNumber: aws.String(serial), AuthenticationCode1: aws.String(testMFAOTP(seed, step-1)), AuthenticationCode2: aws.String(testMFAOTP(seed, step))})
	if err != nil {
		t.Fatal(err)
	}
	listed, err := client.ListMFADevices(ctx, &sdkiam.ListMFADevicesInput{UserName: user.User.UserName})
	if err != nil || len(listed.MFADevices) != 1 || listed.MFADevices[0].EnableDate == nil {
		t.Fatalf("MFA association: %+v %v", listed, err)
	}
	virtual, err := client.ListVirtualMFADevices(ctx, &sdkiam.ListVirtualMFADevicesInput{AssignmentStatus: types.AssignmentStatusTypeAssigned})
	if err != nil || len(virtual.VirtualMFADevices) != 1 {
		t.Fatalf("virtual listing: %+v %v", virtual, err)
	}
	if len(virtual.VirtualMFADevices[0].Base32StringSeed) != 0 || len(virtual.VirtualMFADevices[0].QRCodePNG) != 0 {
		t.Fatal("list exposed MFA seed")
	}
	source.Advance(10 * time.Second)
	if _, err := service.VerifyMFA(userContext(user.User, "aws"), serial, testMFAOTP(seed, step+1)); err != nil {
		t.Fatalf("STS verifier: %v", err)
	}
	if _, err := service.VerifyMFA(userContext(other.User, "aws"), serial, testMFAOTP(seed, step)); err == nil {
		t.Fatal("another IAM user used the device")
	}
	if _, err := service.VerifyMFA(userContext(user.User, "aws"), serial, testMFAOTP(seed, step-10)); err == nil {
		t.Fatal("expired MFA code accepted")
	}
	_, err = client.DeleteVirtualMFADevice(ctx, &sdkiam.DeleteVirtualMFADeviceInput{SerialNumber: aws.String(serial)})
	requireCode(t, err, "DeleteConflict")
	_, err = client.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: user.User.UserName})
	requireCode(t, err, "DeleteConflict")
	_, err = client.TagMFADevice(ctx, &sdkiam.TagMFADeviceInput{SerialNumber: aws.String(serial), Tags: []types.Tag{{Key: aws.String("team"), Value: aws.String("updated")}}})
	if err != nil {
		t.Fatal(err)
	}
	tags, err := client.ListMFADeviceTags(ctx, &sdkiam.ListMFADeviceTagsInput{SerialNumber: aws.String(serial)})
	if err != nil || len(tags.Tags) != 1 || aws.ToString(tags.Tags[0].Value) != "updated" {
		t.Fatalf("MFA tags: %+v %v", tags, err)
	}
	_, err = client.ResyncMFADevice(ctx, &sdkiam.ResyncMFADeviceInput{UserName: user.User.UserName, SerialNumber: aws.String(serial), AuthenticationCode1: aws.String(testMFAOTP(seed, step+9)), AuthenticationCode2: aws.String(testMFAOTP(seed, step+10))})
	if err != nil {
		t.Fatal(err)
	}
	source.Advance(10 * time.Second)
	if _, err := service.VerifyMFA(userContext(user.User, "aws"), serial, testMFAOTP(seed, step+11)); err != nil {
		t.Fatalf("resynchronized verifier: %v", err)
	}
	_, err = client.DeactivateMFADevice(ctx, &sdkiam.DeactivateMFADeviceInput{UserName: user.User.UserName, SerialNumber: aws.String(serial)})
	if err != nil {
		t.Fatal(err)
	}
	source.Advance(10 * time.Second)
	if _, err := service.VerifyMFA(userContext(user.User, "aws"), serial, testMFAOTP(seed, step+12)); err == nil {
		t.Fatal("deactivated device was accepted")
	}
	_, err = client.DeleteVirtualMFADevice(ctx, &sdkiam.DeleteVirtualMFADeviceInput{SerialNumber: aws.String(serial)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.DeleteUser(ctx, &sdkiam.DeleteUserInput{UserName: user.User.UserName})
	if err != nil {
		t.Fatal(err)
	}
}

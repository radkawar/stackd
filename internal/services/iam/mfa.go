package iam

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"net/url"
	"time"

	"github.com/skip2/go-qrcode"

	iamapi "stackd/internal/awsapi/iam"
	"stackd/internal/awsctx"
	"stackd/internal/awswire"
	"stackd/internal/identity"
)

func createVirtualMFADevice(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.CreateVirtualMFADeviceInput](ctx)
	if err != nil {
		return nil, err
	}
	name, path := inputString(in.VirtualMFADeviceName), defaultPath(inputString(in.Path))
	serial := resourceARN(m, "mfa", path, name)
	if len(serial) > 256 {
		return nil, invalid("The virtual MFA serial ARN exceeds 256 characters.")
	}
	if a.mfaDevices[serial] != nil {
		return nil, duplicate("virtual MFA device", name)
	}
	tags, err := inputTags(in.Tags, "MFADevice")
	if err != nil {
		return nil, err
	}
	seed := make([]byte, 20)
	if _, err := rand.Read(seed); err != nil {
		return nil, &awswire.Error{Code: "ServiceFailure", Message: "Unable to generate an MFA seed.", StatusCode: 500}
	}
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed)
	uri := url.URL{Scheme: "otpauth", Host: "totp", Path: "/Amazon Web Services:" + m.AccountID + ":" + name}
	parameters := url.Values{"secret": {encoded}, "issuer": {"Amazon Web Services"}}
	uri.RawQuery = parameters.Encode()
	png, encodeErr := qrcode.Encode(uri.String(), qrcode.Medium, 256)
	if encodeErr != nil {
		return nil, &awswire.Error{Code: "ServiceFailure", Message: "Unable to encode MFA QR code.", StatusCode: 500}
	}
	a.mfaDevices[serial] = &MFADevice{SerialNumber: serial, Binding: Propagated[MFABinding]{Value: MFABinding{Seed: string(seed)}}, Tags: tags}
	return &iamapi.CreateVirtualMFADeviceOutput{VirtualMFADevice: &iamapi.VirtualMFADevice{
		SerialNumber: wirePointer(iamapi.SerialNumberType(serial)), Base32StringSeed: []byte(encoded), QRCodePNG: png, Tags: wireTags(tags),
	}}, nil
}

func findMFADevice(a *account, serial string) (*MFADevice, *awswire.Error) {
	device := a.mfaDevices[serial]
	if device == nil {
		return nil, missing("virtual MFA device", serial)
	}
	return device, nil
}

func deleteVirtualMFADevice(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.DeleteVirtualMFADeviceInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	device, err := findMFADevice(a, inputString(in.SerialNumber))
	if err != nil {
		return nil, err
	}
	if device.Binding.Value.UserID != "" {
		return nil, conflict("Deactivate the virtual MFA device before deleting it.")
	}
	delete(a.mfaDevices, device.SerialNumber)
	return &iamapi.DeleteVirtualMFADeviceOutput{}, nil
}

func enableMFADevice(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.EnableMFADeviceInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	u, err := findUser(a, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	if err := requireMFASelfManagement(a, m, u.UserId); err != nil {
		return nil, err
	}
	device, err := findMFADevice(a, inputString(in.SerialNumber))
	if err != nil {
		return nil, err
	}
	if device.Binding.Value.UserID != "" {
		return nil, duplicate("MFA device association", device.SerialNumber)
	}
	count := 0
	for _, d := range a.mfaDevices {
		if d.Binding.Value.UserID == u.UserId {
			count++
		}
	}
	if count >= 8 {
		return nil, limit("An IAM user can have at most eight MFA devices.")
	}
	now := a.currentTime
	if err := synchronizeMFA(device, u.UserId, inputString(in.AuthenticationCode1), inputString(in.AuthenticationCode2), now); err != nil {
		return nil, err
	}
	device.EnableDate = now
	return &iamapi.EnableMFADeviceOutput{}, nil
}

func deactivateMFADevice(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.DeactivateMFADeviceInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	u, err := credentialPrincipal(a, m, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	if u.ID == m.AccountID && m.SessionType != string(identity.SessionTypeAssumeRoot) {
		return nil, &awswire.Error{Code: "InvalidUserType", Message: "Root MFA deactivation requires an AssumeRoot session.", StatusCode: 400}
	}
	if err := requireMFASelfManagement(a, m, u.ID); err != nil {
		return nil, err
	}
	device, err := findMFADevice(a, inputString(in.SerialNumber))
	if err != nil {
		return nil, err
	}
	if device.Binding.Value.UserID != u.ID {
		return nil, missing("MFA association", device.SerialNumber)
	}
	binding := device.Binding.Value
	binding.UserID = ""
	device.Binding.set(binding, a.currentTime)
	device.EnableDate = time.Time{}
	return &iamapi.DeactivateMFADeviceOutput{}, nil
}

// AWS requires an existing MFA-authenticated session when IAM users add or
// remove their own devices after enrollment, even if their policy allows it.
// Administrators managing another identity and AssumeRoot use their own rules.
func requireMFASelfManagement(a *account, m awsctx.Metadata, userID string) *awswire.Error {
	if userID != m.PrincipalID || userID == m.AccountID || m.MFAPresent {
		return nil
	}
	for _, device := range a.mfaDevices {
		if device.Binding.Value.UserID == userID {
			return &awswire.Error{Code: "AccessDenied", Message: "To complete this action, please ensure that you are authenticated with an MFA device that is enabled for this user.", StatusCode: 403}
		}
	}
	return nil
}

func resyncMFADevice(ctx context.Context, a *account, _ awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.ResyncMFADeviceInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	u, err := findUser(a, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	device, err := findMFADevice(a, inputString(in.SerialNumber))
	if err != nil {
		return nil, err
	}
	if device.Binding.Value.UserID != u.UserId {
		return nil, missing("MFA association", device.SerialNumber)
	}
	if err := synchronizeMFA(device, u.UserId, inputString(in.AuthenticationCode1), inputString(in.AuthenticationCode2), a.currentTime); err != nil {
		return nil, err
	}
	return &iamapi.ResyncMFADeviceOutput{}, nil
}

func listMFADevices(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, err := generatedIAMInput[iamapi.ListMFADevicesInput](ctx)
	if err != nil {
		return nil, err
	}
	u, err := credentialPrincipal(a, m, inputString(in.UserName))
	if err != nil {
		return nil, err
	}
	devices := make(iamapi.MfaDeviceListType, 0)
	for _, device := range a.mfaDevices {
		if device.Binding.Value.UserID == u.ID {
			devices = append(devices, iamapi.MFADevice{UserName: wirePointer(iamapi.UserNameType(u.UserName)), SerialNumber: wirePointer(iamapi.SerialNumberType(device.SerialNumber)), EnableDate: wirePointer(device.EnableDate)})
		}
	}
	selection := *in
	if in.UserName == nil && u.UserName != "" {
		selection.UserName = wirePointer(iamapi.ExistingUserNameType(u.UserName))
	}
	devices, paging, err := page(ctx, devices, func(d iamapi.MFADevice) string { return inputString(d.SerialNumber) }, m, &selection)
	return &iamapi.ListMFADevicesOutput{MFADevices: devices, IsTruncated: wirePointer(iamapi.BooleanType(paging.IsTruncated)), Marker: wireMarker(paging)}, err
}

func listVirtualMFADevices(ctx context.Context, a *account, m awsctx.Metadata) (any, *awswire.Error) {
	in, apiErr := generatedIAMInput[iamapi.ListVirtualMFADevicesInput](ctx)
	if apiErr != nil {
		return nil, apiErr
	}
	status := inputString(in.AssignmentStatus)
	devices := make(iamapi.VirtualMFADeviceListType, 0)
	for _, device := range a.mfaDevices {
		assigned := device.Binding.Value.UserID != ""
		if (status == "Assigned" && !assigned) || (status == "Unassigned" && assigned) {
			continue
		}
		wire := iamapi.VirtualMFADevice{SerialNumber: wirePointer(iamapi.SerialNumberType(device.SerialNumber))}
		if assigned {
			wire.EnableDate = &device.EnableDate
			for _, u := range a.users {
				if u.UserId == device.Binding.Value.UserID {
					wire.User = wireUser(u, false)
					break
				}
			}
		}
		devices = append(devices, wire)
	}
	devices, paging, err := page(ctx, devices, func(d iamapi.VirtualMFADevice) string { return inputString(d.SerialNumber) }, m, in)
	return &iamapi.ListVirtualMFADevicesOutput{VirtualMFADevices: devices, IsTruncated: wirePointer(iamapi.BooleanType(paging.IsTruncated)), Marker: wireMarker(paging)}, err
}

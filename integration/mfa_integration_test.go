package stackd_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"stackd"
	"stackd/clock"
)

func otpForTest(seed []byte, step int64) string {
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	h := hmac.New(sha1.New, seed)
	_, _ = h.Write(counter[:])
	digest := h.Sum(nil)
	offset := digest[len(digest)-1] & 15
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1_000_000)
}

func TestVirtualMFAEnforcesSTSAndIAMPermissions(t *testing.T) {
	ctx := context.Background()
	source := clock.NewManual(time.Date(2035, 2, 3, 4, 5, 0, 0, time.UTC))
	c := clockCloud(t, stackd.Config{Clock: source})
	root := c.iam("test", "test", "")
	arn, key, secret := c.user(t, "test", "mfa-user")
	putUserPolicy(t, root, "mfa-user", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"},"NumericLessThanEquals":{"aws:MultiFactorAuthAge":"60"}}}}`)
	device, err := root.CreateVirtualMFADevice(ctx, &iam.CreateVirtualMFADeviceInput{VirtualMFADeviceName: aws.String("user-device")})
	if err != nil {
		t.Fatal(err)
	}
	serial := device.VirtualMFADevice.SerialNumber
	seed, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(string(device.VirtualMFADevice.Base32StringSeed))
	if err != nil {
		t.Fatal(err)
	}
	step := source.Now().Unix() / 30
	if _, err := root.EnableMFADevice(ctx, &iam.EnableMFADeviceInput{UserName: aws.String("mfa-user"), SerialNumber: serial, AuthenticationCode1: aws.String(otpForTest(seed, step-1)), AuthenticationCode2: aws.String(otpForTest(seed, step))}); err != nil {
		t.Fatal(err)
	}
	caller := c.sts(key, secret, "")
	in := &sts.GetSessionTokenInput{SerialNumber: serial, TokenCode: aws.String(otpForTest(seed, step-10))}
	_, err = caller.GetSessionToken(ctx, in)
	assertAPIError(t, err, "AccessDenied")
	advanceClock(t, source, 30*time.Second)
	in.TokenCode = aws.String(otpForTest(seed, source.Now().Unix()/30))
	session, err := caller.GetSessionToken(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	token := session.Credentials
	mfaIAM := c.iam(aws.ToString(token.AccessKeyId), aws.ToString(token.SecretAccessKey), aws.ToString(token.SessionToken))
	if _, err := mfaIAM.ListUsers(ctx, &iam.ListUsersInput{}); err != nil {
		t.Fatal(err)
	}
	_, err = c.iam(key, secret, "").ListUsers(ctx, &iam.ListUsersInput{})
	assertAPIError(t, err, "AccessDenied")
	trust := fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":%q},"Action":"sts:AssumeRole","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}}`, arn)
	role, err := root.CreateRole(ctx, &iam.CreateRoleInput{RoleName: aws.String("mfa-role"), AssumeRolePolicyDocument: aws.String(trust)})
	if err != nil {
		t.Fatal(err)
	}
	assume := &sts.AssumeRoleInput{RoleArn: role.Role.Arn, RoleSessionName: aws.String("mfa-session")}
	_, err = caller.AssumeRole(ctx, assume)
	assertAPIError(t, err, "AccessDenied")
	assume.SerialNumber = serial
	advanceClock(t, source, 30*time.Second)
	assume.TokenCode = aws.String(otpForTest(seed, source.Now().Unix()/30))
	roleSession, err := caller.AssumeRole(ctx, assume)
	if err != nil {
		t.Fatal(err)
	}
	putRolePolicy(t, root, "mfa-role", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"iam:ListUsers","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}}`)
	roleToken := roleSession.Credentials
	_, err = c.iam(aws.ToString(roleToken.AccessKeyId), aws.ToString(roleToken.SecretAccessKey), aws.ToString(roleToken.SessionToken)).ListUsers(ctx, &iam.ListUsersInput{})
	assertAPIError(t, err, "AccessDenied")
	_, err = root.PutUserPolicy(ctx, &iam.PutUserPolicyInput{UserName: aws.String("mfa-user"), PolicyName: aws.String("sts"), PolicyDocument: aws.String(allow(`"sts:*"`, "*"))})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.sessionSTS(session.Credentials).GetAccessKeyInfo(ctx, &sts.GetAccessKeyInfoInput{AccessKeyId: aws.String(key)})
	assertAPIError(t, err, "AccessDenied")
	if _, err := root.DeactivateMFADevice(ctx, &iam.DeactivateMFADeviceInput{UserName: aws.String("mfa-user"), SerialNumber: serial}); err != nil {
		t.Fatal(err)
	}
	advanceClock(t, source, 10*time.Second)
	in.TokenCode = aws.String(otpForTest(seed, source.Now().Unix()/30+1))
	_, err = caller.GetSessionToken(ctx, in)
	assertAPIError(t, err, "AccessDenied")
	// Propagated deactivation prevents new MFA verification; an issued token keeps its
	// authenticated MFA context until expiration or permission changes.
	if _, err := mfaIAM.ListUsers(ctx, &iam.ListUsersInput{}); err != nil {
		t.Fatal(err)
	}
}

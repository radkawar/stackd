package awsenvelope

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"maps"
	"strings"
	"testing"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	wrapped := []byte("wrapped key")
	signer, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	for _, signed := range []bool{false, true} {
		for _, size := range []int{0, 1, FrameLength - 1, FrameLength, FrameLength + 1, 3 * FrameLength} {
			t.Run(fmt.Sprintf("signed=%t/size=%d", signed, size), func(t *testing.T) {
				plaintext := bytes.Repeat([]byte{0x71}, size)
				seal := Seal
				if signed {
					seal = signer.Seal
				}
				payload, err := seal(key, wrapped, "arn:key", map[string]string{"resource": "arn:resource"}, plaintext)
				if err != nil {
					t.Fatal(err)
				}
				context, err := EncryptionContext(payload, map[string]string{"resource": "arn:resource"})
				if err != nil || context["resource"] != "arn:resource" {
					t.Fatalf("context = %v, error = %v", context, err)
				}
				if signed {
					if len(context) != 2 || context[signingContextKey] != signer.PublicKey() || binary.BigEndian.Uint16(payload[1:]) != signedSuite {
						t.Fatalf("signed context = %v", context)
					}
					footer := len(payload) - 105
					if binary.BigEndian.Uint16(payload[footer:]) != 103 {
						t.Fatal("signature does not have SDK static length")
					}
					digest := sha512.Sum384(payload[:footer])
					if !ecdsa.VerifyASN1(&signer.key.PublicKey, digest[:], payload[footer+2:]) {
						t.Fatal("signature does not cover header and body")
					}
				} else if len(context) != 1 || binary.BigEndian.Uint16(payload[1:]) != unsignedSuite {
					t.Fatalf("unsigned context = %v", context)
				}
				got, err := Open(key, wrapped, "arn:key", map[string]string{"resource": "arn:resource"}, payload)
				if err != nil || !bytes.Equal(got, plaintext) {
					t.Fatalf("roundtrip mismatch: %v", err)
				}
			})
		}
	}
}

func TestEnvelopeBindsExactMultipleContexts(t *testing.T) {
	const sourceKey = "aws:lambda:EventSourceArn"
	const functionKey = "aws:lambda:FunctionArn"
	expected := map[string]string{
		sourceKey:   "arn:aws:sqs:us-east-1:123456789012:events",
		functionKey: "arn:aws:lambda:us-east-1:123456789012:function:processor",
	}
	original := maps.Clone(expected)
	key := bytes.Repeat([]byte{0x24}, 32)
	wrapped := []byte("wrapped key")
	plaintext := bytes.Repeat([]byte("private filter bytes"), FrameLength)
	signer, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	for _, signed := range []bool{false, true} {
		t.Run(fmt.Sprintf("signed=%t", signed), func(t *testing.T) {
			seal := Seal
			if signed {
				seal = signer.Seal
			}
			payload, err := seal(key, wrapped, "arn:key", expected, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			context, err := EncryptionContext(payload, expected)
			want := maps.Clone(original)
			if signed {
				want[signingContextKey] = signer.PublicKey()
			}
			if err != nil || !maps.Equal(context, want) || !maps.Equal(expected, original) {
				t.Fatalf("context = %v, expected input = %v, error = %v", context, expected, err)
			}
			// The extracted KMS context must not alias the caller's expectations.
			context[functionKey] = "other function"
			got, err := Open(key, wrapped, "arn:key", expected, payload)
			if err != nil || !bytes.Equal(got, plaintext) || !maps.Equal(expected, original) {
				t.Fatalf("multi-context recovery: %v", err)
			}
			for name, wrong := range map[string]map[string]string{
				"wrong source":     {sourceKey: expected[sourceKey] + "-other", functionKey: expected[functionKey]},
				"wrong function":   {sourceKey: expected[sourceKey], functionKey: expected[functionKey] + "-other"},
				"swapped values":   {sourceKey: expected[functionKey], functionKey: expected[sourceKey]},
				"missing source":   {functionKey: expected[functionKey]},
				"missing function": {sourceKey: expected[sourceKey]},
				"extra field":      {sourceKey: expected[sourceKey], functionKey: expected[functionKey], "mapping": "arn:mapping"},
				"reserved field":   {sourceKey: expected[sourceKey], functionKey: expected[functionKey], signingContextKey: signer.PublicKey()},
				"invalid UTF8":     {sourceKey: expected[sourceKey], functionKey: "\xff"},
			} {
				t.Run(name, func(t *testing.T) {
					if got, err := EncryptionContext(payload, wrong); err == nil || got != nil {
						t.Fatalf("accepted unexpected context: %v", got)
					}
					if got, err := Open(key, wrapped, "arn:key", wrong, payload); err == nil || got != nil {
						t.Fatalf("released plaintext for unexpected context: %x", got)
					}
				})
			}
			collision := maps.Clone(expected)
			collision[signingContextKey] = signer.PublicKey()
			if got, err := seal(key, wrapped, "arn:key", collision, plaintext); err == nil || got != nil {
				t.Fatal("caller supplied the reserved signing key")
			}
		})
	}
}

func TestEnvelopeRejectsTamperAndTruncation(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	wrapped := []byte("wrapped")
	signer, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	for _, signed := range []bool{false, true} {
		seal := Seal
		if signed {
			seal = signer.Seal
		}
		payload, err := seal(key, wrapped, "arn:key", map[string]string{"resource": "value"}, []byte("secret plaintext"))
		if err != nil {
			t.Fatal(err)
		}
		reject := func(label string, message []byte) {
			t.Helper()
			plaintext, err := Open(key, wrapped, "arn:key", map[string]string{"resource": "value"}, message)
			if err == nil || plaintext != nil {
				t.Fatalf("signed=%t %s released plaintext %x, error=%v", signed, label, plaintext, err)
			}
		}
		for i := range len(payload) {
			reject(fmt.Sprintf("truncated at %d", i), payload[:i])
			mutated := bytes.Clone(payload)
			mutated[i] ^= 1
			reject(fmt.Sprintf("tampered at %d", i), mutated)
		}
		reject("trailing bytes", append(bytes.Clone(payload), 0))
		for _, wrong := range []struct{ arn, name, value string }{
			{"other:key", "resource", "value"},
			{"arn:key", "other", "value"},
			{"arn:key", "resource", "other"},
		} {
			if got, err := Open(key, wrapped, wrong.arn, map[string]string{wrong.name: wrong.value}, payload); err == nil || got != nil {
				t.Fatal("accepted substituted resource or key ARN")
			}
		}
		if got, err := Open(bytes.Repeat([]byte{2}, 32), wrapped, "arn:key", map[string]string{"resource": "value"}, payload); err == nil || got != nil {
			t.Fatal("accepted wrong data key")
		}
		if got, err := Open(key, []byte("other"), "arn:key", map[string]string{"resource": "value"}, payload); err == nil || got != nil {
			t.Fatal("accepted substituted encrypted data key")
		}
	}
}

func TestEncryptionContextRejectsUnexpectedFields(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	const sourceKey = "aws:lambda:EventSourceArn"
	const functionKey = "aws:lambda:FunctionArn"
	expected := map[string]string{sourceKey: "source", functionKey: "function"}
	type pair struct{ key, value string }
	publicKey := pair{signingContextKey, signer.PublicKey()}
	source := pair{sourceKey, "source"}
	function := pair{functionKey, "function"}
	cases := map[string][]pair{
		"duplicate resource":    {publicKey, source, source},
		"duplicate signing key": {publicKey, publicKey, source},
		"unexpected field":      {publicKey, source, {"unexpected", "function"}},
		"substituted source":    {publicKey, {sourceKey, "other"}, function},
		"substituted function":  {publicKey, source, {functionKey, "other"}},
		"unsorted resources":    {publicKey, function, source},
		"unsorted signing key":  {source, publicKey, function},
		"missing public key":    {source, function},
		"missing source":        {publicKey, function},
		"missing function":      {publicKey, source},
		"malformed public key":  {{signingContextKey, strings.Repeat("A", 68)}, source, function},
		"invalid UTF8 key":      {publicKey, source, {"\xff", "function"}},
		"invalid UTF8 value":    {publicKey, source, {functionKey, "\xff"}},
		"extra field":           {publicKey, source, function, {"z", "x"}},
	}
	for name, pairs := range cases {
		t.Run(name, func(t *testing.T) {
			context := binary.BigEndian.AppendUint16(nil, uint16(len(pairs)))
			for _, pair := range pairs {
				context = appendBusField(context, []byte(pair.key))
				context = appendBusField(context, []byte(pair.value))
			}
			payload := append([]byte{2, 5, 0x78}, make([]byte, 32)...)
			payload = appendBusField(payload, context)
			if got, err := EncryptionContext(payload, expected); err == nil || got != nil {
				t.Fatalf("accepted malformed context %v", got)
			}
		})
	}
	for _, name := range []string{"a-resource", "z-resource"} {
		payload, err := signer.Seal(make([]byte, 32), []byte("wrapped"), "arn:key", map[string]string{name: "value"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := EncryptionContext(payload, map[string]string{name: "value"}); err != nil || got[name] != "value" || got[signingContextKey] != signer.PublicKey() {
			t.Fatalf("lexical ordering for %q: %v, %v", name, got, err)
		}
	}
}

func TestEnvelopeRejectsOutOfBoundsInputs(t *testing.T) {
	key := make([]byte, 32)
	payload, err := Seal(key, []byte("wrapped"), "arn:key", map[string]string{"resource": "value"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{0, 16, 24, 31, 33, 64} {
		wrong := make([]byte, size)
		if _, err := Seal(wrong, nil, "arn:key", map[string]string{"resource": "value"}, nil); err == nil {
			t.Fatalf("sealed with %d-byte data key", size)
		}
		if got, err := Open(wrong, []byte("wrapped"), "arn:key", map[string]string{"resource": "value"}, payload); err == nil || got != nil {
			t.Fatalf("opened with %d-byte data key", size)
		}
	}
	oversize := strings.Repeat("x", maxFieldLength+1)
	for _, input := range []struct {
		wrapped          []byte
		arn, name, value string
	}{
		{[]byte(oversize), "arn:key", "resource", "value"},
		{nil, oversize, "resource", "value"},
		{nil, "arn:key", oversize, "value"},
		{nil, "arn:key", "resource", oversize},
		{nil, "arn:key", "resource", strings.Repeat("x", maxFieldLength-6)},
		{nil, "arn:key", signingContextKey, "value"},
		{nil, "arn:key", "resource", "\xff"},
	} {
		if _, err := Seal(key, input.wrapped, input.arn, map[string]string{input.name: input.value}, nil); err == nil {
			t.Fatal("accepted invalid or overflowing field")
		}
	}
}

func TestEnvelopeBoundsCombinedContext(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	key, wrapped := make([]byte, 32), []byte("wrapped")
	for _, signed := range []bool{false, true} {
		t.Run(fmt.Sprintf("signed=%t", signed), func(t *testing.T) {
			seal := Seal
			size := maxFieldLength - 12 // count plus two one-byte keys and field lengths
			if signed {
				seal = signer.Seal
				size -= 4 + len(signingContextKey) + len(signer.PublicKey())
			}
			context := map[string]string{"a": strings.Repeat("x", size), "z": ""}
			payload, err := seal(key, wrapped, "arn:key", context, []byte("boundary"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := Open(key, wrapped, "arn:key", context, payload)
			if err != nil || string(got) != "boundary" {
				t.Fatalf("maximum context recovery: %q, %v", got, err)
			}
			context["z"] = "x"
			if got, err := seal(key, wrapped, "arn:key", context, nil); err == nil || got != nil {
				t.Fatal("accepted overflowing combined context")
			}
		})
	}
}

func TestSignedEnvelopeWithholdsEarlierFramesOnFailure(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	wrapped := []byte("wrapped")
	payload, err := signer.Seal(key, wrapped, "arn:key", map[string]string{"resource": "value"}, bytes.Repeat([]byte("secret"), FrameLength))
	if err != nil {
		t.Fatal(err)
	}
	footer := len(payload) - 105
	for _, offset := range []int{footer - 1, len(payload) - 1} {
		mutated := bytes.Clone(payload)
		mutated[offset] ^= 1
		if got, err := Open(key, wrapped, "arn:key", map[string]string{"resource": "value"}, mutated); err == nil || got != nil {
			t.Fatalf("released earlier frames after corruption at %d", offset)
		}
	}
	if got, err := Open(key, wrapped, "arn:key", map[string]string{"resource": "value"}, payload[:footer]); err == nil || got != nil {
		t.Fatal("released earlier frames without signature footer")
	}
}

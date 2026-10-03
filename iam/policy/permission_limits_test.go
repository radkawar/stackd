package policy

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
)

func TestPotentialActionsResourceByteLimits(t *testing.T) {
	const prefix = "arn:aws:s3:::bucket/"
	tests := []struct {
		name, key, template string
		keyBytes            int
		want                bool
	}{
		{"ASCII at bound", "abc", "?*", 3, true},
		{"ASCII over bound", "abcd", "?*", 3, false},
		{"two-byte character at bound", "é", "?*", 2, true},
		{"two-byte character over bound", "é", "?*", 1, false},
		{"three-byte character at bound", "界", "?*", 3, true},
		{"three-byte character over bound", "界", "?*", 2, false},
		{"surrogate pair at bound", "\U0001f9ed", "?*", 4, true},
		{"surrogate pair over bound", "\U0001f9ed", "?*", 3, false},
		{"surrogate pair needs two wildcard units", "\U0001f9ed", "?", 4, false},
		{"surrogate pair matches two wildcard units", "\U0001f9ed", "??", 4, true},
		{"nonempty template rejects empty key", "", "?*", 1, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			document := fmt.Sprintf(`{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":%q}}`, prefix+tt.key)
			summary, err := ParsePermissionSummary([]byte(document))
			if err != nil {
				t.Fatal(err)
			}
			actual, err := PotentialActionsWithResourceLimits(t.Context(), [][]*PermissionSummary{{summary}}, map[string][]string{"s3:GetObject": {prefix + tt.template}}, map[string]int{"s3:GetObject": len(prefix) + tt.keyBytes})
			var want []string
			if tt.want {
				want = []string{"s3:GetObject"}
			}
			if err != nil || !slices.Equal(actual, want) {
				t.Fatalf("actions=%v err=%v; want %v", actual, err, want)
			}
		})
	}
}

func TestPotentialActionsByteLimitDenyUnion(t *testing.T) {
	const prefix = "arn:aws:s3:::bucket/"
	summary, err := ParsePermissionSummary([]byte(`{"Statement":[
		{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/*"},
		{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket/a"},
		{"Effect":"Deny","Action":"s3:GetObject","NotResource":["arn:aws:s3:::bucket/a","arn:aws:s3:::bucket/abcd"]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	levels := [][]*PermissionSummary{{summary}}
	resources := map[string][]string{"s3:GetObject": {prefix + "?*"}}
	for _, tt := range []struct {
		keyBytes int
		want     []string
	}{{3, nil}, {4, []string{"s3:GetObject"}}} {
		actual, err := PotentialActionsWithResourceLimits(t.Context(), levels, resources, map[string]int{"s3:GetObject": len(prefix) + tt.keyBytes})
		if err != nil || !slices.Equal(actual, tt.want) {
			t.Fatalf("key bound=%d actions=%v err=%v; want %v", tt.keyBytes, actual, err, tt.want)
		}
	}
	if actual, err := PotentialActions(t.Context(), levels, resources); err != nil || !slices.Equal(actual, []string{"s3:GetObject"}) {
		t.Fatalf("unbounded report changed: actions=%v err=%v", actual, err)
	}
}

func TestPotentialActionsResourceBoundsAreActionSpecific(t *testing.T) {
	const prefix = "arn:aws:s3:::bucket/"
	summary, err := ParsePermissionSummary([]byte(`{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::bucket/é"}}`))
	if err != nil {
		t.Fatal(err)
	}
	levels := [][]*PermissionSummary{{summary}}
	resources := map[string][]string{"s3:GetObject": {prefix + "?*"}, "s3:PutObject": {prefix + "?*"}}
	limits := map[string]int{"s3:GetObject": len(prefix) + 1, "s3:PutObject": len(prefix) + 2}
	actual, err := PotentialActionsWithResourceLimits(t.Context(), levels, resources, limits)
	if err != nil || !slices.Equal(actual, []string{"s3:PutObject"}) {
		t.Fatalf("cached action-specific bound: actions=%v err=%v", actual, err)
	}
	for _, limits := range []map[string]int{nil, {"s3:GetObject": 0}} {
		actual, err := PotentialActionsWithResourceLimits(t.Context(), levels, resources, limits)
		if err != nil || !slices.Equal(actual, []string{"s3:GetObject", "s3:PutObject"}) {
			t.Fatalf("unbounded actions=%v err=%v", actual, err)
		}
	}
}

func TestPotentialActionsByteLimitCannotSkipUniverse(t *testing.T) {
	summary, err := ParsePermissionSummary([]byte(`{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`))
	if err != nil {
		t.Fatal(err)
	}
	resources := map[string][]string{"s3:GetObject": {"arn:aws:s3:::bucket/abc"}}
	for _, levels := range [][][]*PermissionSummary{nil, {{summary}}} {
		actual, err := PotentialActionsWithResourceLimits(t.Context(), levels, resources, map[string]int{"s3:GetObject": 1})
		if err != nil || len(actual) != 0 {
			t.Fatalf("unrestricted allow bypassed resource bound: actions=%v err=%v", actual, err)
		}
	}
	actual, err := PotentialActionsWithResourceLimits(t.Context(), nil, map[string][]string{"iam:ListUsers": nil}, map[string]int{"iam:ListUsers": 1})
	if err != nil || !slices.Equal(actual, []string{"iam:ListUsers"}) {
		t.Fatalf("global resource within one byte: actions=%v err=%v", actual, err)
	}
	if actual, err := PotentialActionsWithResourceLimits(t.Context(), nil, resources, map[string]int{"s3:GetObject": -1}); err == nil || actual != nil {
		t.Fatalf("negative byte bound: actions=%v err=%v", actual, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if actual, err := PotentialActionsWithResourceLimits(ctx, nil, resources, nil); !errors.Is(err, context.Canceled) || actual != nil {
		t.Fatalf("canceled bounded search: actions=%v err=%v", actual, err)
	}
}

func TestPermissionUTF8SurrogateValidity(t *testing.T) {
	if _, _, valid := permissionUTF8Step(0xdc00, false); valid {
		t.Fatal("accepted a low surrogate without its high half")
	}
	bytes, pending, valid := permissionUTF8Step(0xd800, false)
	if !valid || !pending || bytes != 4 {
		t.Fatalf("high surrogate must reserve four bytes and remain incomplete: bytes=%d pending=%v valid=%v", bytes, pending, valid)
	}
	if _, _, valid := permissionUTF8Step('a', pending); valid {
		t.Fatal("accepted an unterminated surrogate pair followed by ASCII")
	}
	bytes, pending, valid = permissionUTF8Step(0xdc00, pending)
	if !valid || pending || bytes != 0 {
		t.Fatalf("pair completion: bytes=%d pending=%v valid=%v", bytes, pending, valid)
	}
}

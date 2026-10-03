package eks

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestNativeAuditRetainsEffectiveIdentityAndOutcome(t *testing.T) {
	raw := json.RawMessage(`{"auditID":"native-id","stage":"ResponseComplete","verb":"create","requestURI":"/api/v1/namespaces/kube-system/pods/owned/exec?command=true","userAgent":"kubectl/1.33","user":{"username":"native-admin","uid":"actor-uid","groups":["system:masters"]},"impersonatedUser":{"username":"customer","uid":"customer-uid","groups":["customer-group"]},"sourceIPs":["192.0.2.7","10.0.0.2"],"stageTimestamp":"2031-01-02T03:04:05.123456Z","requestReceivedTimestamp":"2031-01-02T03:04:04Z","objectRef":{"resource":"pods","namespace":"kube-system","name":"owned","subresource":"exec","apiVersion":"v1"},"responseStatus":{"code":101},"requestObject":{"secret":"not-security-evidence"},"responseObject":{"token":"not-security-evidence"}}`)
	events, err := decodeKubernetesAudit([]json.RawMessage{raw})
	if err != nil {
		t.Fatal(err)
	}
	v := events[0]
	if v.UserName != "customer" || v.UserUID != "customer-uid" || v.ActorUserName != "native-admin" || !reflect.DeepEqual(v.Groups, []string{"customer-group"}) {
		t.Fatalf("wrong impersonated evidence: %+v", v)
	}
	if v.ResponseCode != 101 || v.Stage != "ResponseComplete" || v.Resource != "pods" || v.Subresource != "exec" || v.Namespace != "kube-system" || v.Name != "owned" || v.SourceIP != "192.0.2.7" || v.APIVersion != "v1" {
		t.Fatalf("native outcome changed: %+v", v)
	}
	want := time.Date(2031, 1, 2, 3, 4, 5, 123456000, time.UTC)
	if !v.NativeAt.Equal(want) {
		t.Fatalf("stage timestamp = %v", v.NativeAt)
	}
	// EKS owner, not webhook input, supplies AWS resource scope.
	if v.ClusterARN != "" || v.ClusterID != "" || v.ClusterName != "" {
		t.Fatalf("decoder invented scope: %+v", v)
	}
}

func TestNativeAuditInvalidBatchReturnsNoPartialEvents(t *testing.T) {
	valid := json.RawMessage(`{"auditID":"first","stage":"ResponseComplete","user":{"username":"system:anonymous","groups":["system:unauthenticated"]},"requestReceivedTimestamp":"2031-01-02T03:04:05Z","responseStatus":{"code":403}}`)
	events, err := decodeKubernetesAudit([]json.RawMessage{valid})
	if err != nil {
		t.Fatal(err)
	}
	if events[0].UserName != "system:anonymous" || events[0].ActorUserName != "system:anonymous" || events[0].ResponseCode != 403 || events[0].NativeAt.IsZero() {
		t.Fatalf("anonymous denial lost: %+v", events)
	}
	for _, invalid := range []json.RawMessage{json.RawMessage(`{"auditID":"missing-stage","stageTimestamp":"2031-01-02T03:04:05Z"}`), json.RawMessage(`{"auditID":"bad-date","stage":"ResponseComplete","stageTimestamp":"bad"}`), json.RawMessage(`{"stage":"ResponseComplete","stageTimestamp":"2031-01-02T03:04:05Z"}`)} {
		events, err := decodeKubernetesAudit([]json.RawMessage{valid, invalid})
		if err == nil || events != nil {
			t.Fatalf("partial malformed admission: %+v error=%v", events, err)
		}
	}
}

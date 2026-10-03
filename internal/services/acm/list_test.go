package acm_test

import (
	api "stackd/internal/awsapi/acm"
	"testing"
	"time"
)

func TestListFiltersPaginationAndServiceTimeStatus(t *testing.T) {
	s, c, _, _ := newService()
	ctx := owner("111111111111", "us-east-1")
	first := request(t, s, ctx, "first.example.test")
	advance(t, c, time.Second)
	second := request(t, s, ctx, "second.example.test")
	filtered := &api.ListCertificatesRequest{CertificateKeyPairOrigins: api.CertificateKeyPairOrigins{api.CertificateKeyPairOriginAWS_MANAGED}, Includes: &api.Filters{KeyTypes: api.KeyAlgorithmList{"EC_prime256v1"}}, MaxItems: new(api.MaxItems(1)), SortBy: new(api.SortByCREATED_AT), SortOrder: new(api.SortOrderASCENDING)}
	page := call[api.ListCertificatesResponse](t, s, ctx, "ListCertificates", filtered)
	if len(page.CertificateSummaryList) != 1 || *page.CertificateSummaryList[0].CertificateArn != *first || page.NextToken == nil || *page.CertificateSummaryList[0].CertificateKeyPairOrigin != api.CertificateKeyPairOriginAWS_MANAGED {
		t.Fatalf("first page mismatch: %#v", page)
	}
	next := *filtered
	next.NextToken = page.NextToken
	page2 := call[api.ListCertificatesResponse](t, s, ctx, "ListCertificates", &next)
	if len(page2.CertificateSummaryList) != 1 || *page2.CertificateSummaryList[0].CertificateArn != *second || page2.NextToken != nil {
		t.Fatalf("second page mismatch: %#v", page2)
	}
	rejection(t, s, owner("111111111111", "us-west-2"), "ListCertificates", &next, "InvalidArgsException")
	next.CertificateKeyPairOrigins = api.CertificateKeyPairOrigins{api.CertificateKeyPairOriginCUSTOMER_PROVIDED}
	rejection(t, s, ctx, "ListCertificates", &next, "InvalidArgsException")
	onlyImported := *filtered
	onlyImported.CertificateKeyPairOrigins = next.CertificateKeyPairOrigins
	imported := call[api.ListCertificatesResponse](t, s, ctx, "ListCertificates", &onlyImported)
	if len(imported.CertificateSummaryList) != 0 {
		t.Fatal("managed certs passed imported-origin filter")
	}
	rejection(t, s, ctx, "ListCertificates", &api.ListCertificatesRequest{SortBy: new(api.SortByCREATED_AT)}, "InvalidArgsException")
	advance(t, c, 72*time.Hour)
	timedOut := *filtered
	timedOut.MaxItems = new(api.MaxItems(10))
	timedOut.CertificateStatuses = api.CertificateStatuses{api.CertificateStatusVALIDATION_TIMED_OUT}
	expired := call[api.ListCertificatesResponse](t, s, ctx, "ListCertificates", &timedOut)
	if len(expired.CertificateSummaryList) != 2 || *expired.CertificateSummaryList[0].Status != api.CertificateStatusVALIDATION_TIMED_OUT || *expired.CertificateSummaryList[1].Status != api.CertificateStatusVALIDATION_TIMED_OUT {
		t.Fatal("list did not observe validation deadline without scheduler traffic")
	}
}

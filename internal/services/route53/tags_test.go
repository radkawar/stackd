package route53

import (
	"context"
	"errors"
	"fmt"
	"stackd/iam/policy"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/route53"
	"stackd/internal/awsctx"
	"testing"
)

func TestHostedZoneTagsIsolationAtomicityAndCurrentIAM(t *testing.T) {
	s, _ := testService(t)
	ctx := rootContext("111111111111")
	z := createZone(t, s, ctx, "tags.test", "tags")
	id := new(api.TagResourceId(value(z.HostedZone.Id)))
	kind := new(api.TagResourceTypeHostedzone)
	change := &api.ChangeTagsForResourceRequest{ResourceId: id, ResourceType: kind, AddTags: api.TagList{{Key: new(api.TagKey("Revision")), Value: new(api.TagValue("first"))}}}
	invoke[api.ChangeTagsForResourceResponse](t, s, ctx, "ChangeTagsForResource", change)
	read := &api.ListTagsForResourceRequest{ResourceId: id, ResourceType: kind}
	check := func(want string) {
		t.Helper()
		out := invoke[api.ListTagsForResourceResponse](t, s, ctx, "ListTagsForResource", read)
		if len(out.ResourceTagSet.Tags) != 1 || value(out.ResourceTagSet.Tags[0].Value) != want {
			t.Fatal(out.ResourceTagSet)
		}
	}
	check("first")
	change.AddTags[0].Value = new(api.TagValue("second"))
	abort := errors.New("abort tag transaction")
	if err := s.repository.Update(ctx, func(tx Transaction) error {
		invoke[api.ChangeTagsForResourceResponse](t, s, tx.Context(), "ChangeTagsForResource", change)
		return abort
	}); !errors.Is(err, abort) {
		t.Fatal(err)
	}
	check("first")
	change.AddTags = append(change.AddTags, api.Tag{Key: new(api.TagKey("aws:reserved")), Value: new(api.TagValue("invalid"))})
	reject(t, s, ctx, "ChangeTagsForResource", change, "InvalidInput")
	check("first")
	change.AddTags = change.AddTags[:1]
	for i := range 10 {
		change.AddTags = append(change.AddTags, api.Tag{Key: new(api.TagKey(fmt.Sprint(i))), Value: new(api.TagValue("v"))})
	}
	reject(t, s, ctx, "ChangeTagsForResource", change, "InvalidInput")
	check("first")
	reject(t, s, rootContext("222222222222"), "ListTagsForResource", read, "NoSuchHostedZone")
	batch := &api.ListTagsForResourcesRequest{ResourceType: kind, ResourceIds: api.TagResourceIdList{api.TagResourceId(value(id))}}
	out := invoke[api.ListTagsForResourcesResponse](t, s, ctx, "ListTagsForResources", batch)
	if len(out.ResourceTagSets) != 1 || len(out.ResourceTagSets[0].Tags) != 1 {
		t.Fatal(out)
	}
	source := &currentPolicies{set: authorization.PolicySet{Identity: []policy.Policy{{Document: fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"route53:ListTagsForResource","Resource":"arn:aws:route53:::hostedzone/%s"}]}`, cleanID(value(id)))}}}}
	s.authorizer = authorization.New(source, nil)
	m := awsctx.FromContext(ctx)
	m.PrincipalARN, m.PrincipalID = "arn:aws:iam::111111111111:user/reader", "AIDAREADER"
	user := awsctx.WithMetadata(context.Background(), m)
	invoke[api.ListTagsForResourceResponse](t, s, user, "ListTagsForResource", read)
	reject(t, s, user, "ChangeTagsForResource", change, "AccessDenied")
	source.set.Identity = nil
	reject(t, s, user, "ListTagsForResource", read, "AccessDenied")
	invoke[api.ChangeTagsForResourceResponse](t, s, ctx, "ChangeTagsForResource", &api.ChangeTagsForResourceRequest{ResourceId: id, ResourceType: kind, RemoveTagKeys: api.TagKeyList{"Revision", "absent"}})
	if out := invoke[api.ListTagsForResourceResponse](t, s, ctx, "ListTagsForResource", read); len(out.ResourceTagSet.Tags) != 0 {
		t.Fatal(out)
	}
	invoke[api.DeleteHostedZoneResponse](t, s, ctx, "DeleteHostedZone", &api.DeleteHostedZoneRequest{Id: z.HostedZone.Id})
	reject(t, s, ctx, "ListTagsForResource", read, "NoSuchHostedZone")
}

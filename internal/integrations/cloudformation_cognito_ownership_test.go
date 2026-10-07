package integrations

import (
	"context"
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"

	identityapi "stackd/internal/awsapi/cognitoidentity"
	idpapi "stackd/internal/awsapi/cognitoidp"
	"stackd/internal/awscommands"
	"stackd/internal/awsctx"
	"stackd/internal/services/cloudformation"
	"stackd/internal/services/cognitoidentity"
	"stackd/internal/services/cognitoidp"
	"stackd/storage/sqlite"
	identitystore "stackd/storage/sqlite/cognitoidentity"
	idpstore "stackd/storage/sqlite/cognitoidp"
)

// The fixture runs the real Cognito owners over memory or SQLite; restart
// reopens the database and rebuilds the owners from persisted state only.
type cfnCognitoOwnerFixture struct {
	ctx      context.Context
	path     string
	db       *sql.DB
	idp      cognitoidp.Repository
	identity cognitoidentity.Repository
	commands StepFunctionsCommands
}

func newCFNCognitoOwnerFixture(t *testing.T, backend string) *cfnCognitoOwnerFixture {
	t.Helper()
	f := &cfnCognitoOwnerFixture{ctx: cfnWorkflowOwnerContext(t)}
	if backend == "sqlite" {
		f.path = filepath.Join(t.TempDir(), "cognito.sqlite")
		f.open(t)
	} else {
		f.idp, f.identity = cognitoidp.NewMemoryRepository(nil), cognitoidentity.NewMemoryRepository(nil)
	}
	f.start()
	t.Cleanup(func() {
		if f.db != nil {
			_ = f.db.Close()
		}
	})
	return f
}

func (f *cfnCognitoOwnerFixture) open(t *testing.T) {
	t.Helper()
	db, err := sqlite.Open(f.ctx, f.path)
	if err != nil {
		t.Fatal(err)
	}
	f.db, f.idp, f.identity = db, idpstore.New(db), identitystore.New(db)
}

func (f *cfnCognitoOwnerFixture) start() {
	f.commands = NewStepFunctionsCommands(map[string]awscommands.CommandExecutor{
		"cognitoidp":      cognitoidp.New(cognitoidp.Config{Repository: f.idp}),
		"cognitoidentity": cognitoidentity.New(cognitoidentity.Config{Repository: f.identity}),
	})
}

func (f *cfnCognitoOwnerFixture) restart(t *testing.T) {
	t.Helper()
	if f.db != nil {
		if err := f.db.Close(); err != nil {
			t.Fatal(err)
		}
		f.open(t)
	}
	f.start()
}

// counterfeitTags are the formerly authoritative public markers for r, which
// any caller with TagResource can attach to an unrelated pool.
func cfnCognitoCounterfeitTags(r cloudformation.ResourceRequest) map[string]string {
	return map[string]string{
		cfnMessagingOwnerTag:                cfnMessagingOwner(r),
		cfnMessagingTokenTag:                cfnMessagingHash(r.Token),
		cfnComputeTagPrefix + "stack-id":    r.StackID,
		cfnComputeTagPrefix + "logical-id":  r.LogicalID,
		cfnComputeTagPrefix + "incarnation": r.Token,
	}
}

func cfnCognitoCloudControlRequest(kind, token string, properties cloudformation.Properties) cloudformation.ResourceRequest {
	return cloudformation.ResourceRequest{Type: kind, StackID: "arn:aws:cloudcontrolapi:us-east-1:123456789012:request/" + token, StackName: "cloudcontrol", LogicalID: "Resource", Token: token, Scope: cloudformation.Scope{Partition: "aws", Account: "123456789012", Region: "us-east-1"}, Properties: properties, CloudControl: true}
}

func cfnCognitoNotAdmitted(t *testing.T, label string, result cloudformation.ResourceResult, err error) {
	t.Helper()
	if !cfnCognitoMissing(err) || result.PhysicalID != "" {
		t.Fatalf("%s: recovery did not certify nonadmission: %+v %v", label, result, err)
	}
}

func cfnCognitoSame(t *testing.T, label string, want string, result cloudformation.ResourceResult, err error) {
	t.Helper()
	if err != nil || result.PhysicalID != want {
		t.Fatalf("%s: want %s, got %+v %v", label, want, result, err)
	}
}

func TestCFNCognitoUserPoolPrivateClaimsRejectCounterfeitAndForeignRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNCognitoOwnerFixture(t, backend)
			r := cfnWorkflowOwnerRequest("AWS::Cognito::UserPool", "Pool", cloudformation.Properties{"UserPoolName": "owned", "UserPoolTags": map[string]any{"team": "a"}})
			nativePool := func(name string, tags map[string]string) string {
				t.Helper()
				in := &idpapi.CreateUserPoolInput{PoolName: new(idpapi.UserPoolNameType(name)), UserPoolTags: idpapi.UserPoolTagsType{}}
				for k, v := range tags {
					in.UserPoolTags[idpapi.TagKeysType(k)] = idpapi.TagValueType(v)
				}
				out, err := cfnMessagingCall[idpapi.CreateUserPoolOutput](f.ctx, f.commands, "cognitoidp", "CreateUserPool", in)
				if err != nil {
					t.Fatal(err)
				}
				return cfnComputeValue(out.UserPool.Id)
			}
			exists := func(id string) bool {
				t.Helper()
				_, _, err := cfnCognitoUserPool{f.commands}.describe(f.ctx, id)
				if err != nil && !cfnCognitoMissing(err) {
					t.Fatal(err)
				}
				return err == nil
			}

			// A direct pool carrying every published marker for r is not r's.
			counterfeit := nativePool("counterfeit", cfnCognitoCounterfeitTags(r))
			result, err := cfnCognitoUserPool{f.commands}.RecoverCreation(f.ctx, r)
			cfnCognitoNotAdmitted(t, "counterfeit", result, err)
			created, err := cfnCognitoUserPool{f.commands}.Create(f.ctx, r)
			if err != nil || created.PhysicalID == "" || created.PhysicalID == counterfeit {
				t.Fatalf("create adopted a counterfeit pool or failed: %+v %v", created, err)
			}

			// The same incarnation replays its pool after the owners reopen.
			f.restart(t)
			h := cfnCognitoUserPool{f.commands}
			result, err = h.RecoverCreation(f.ctx, r)
			cfnCognitoSame(t, "recovered", created.PhysicalID, result, err)
			result, err = h.Create(f.ctx, r)
			cfnCognitoSame(t, "retried", created.PhysicalID, result, err)
			ids, err := h.ids(f.ctx)
			if err != nil || len(ids) != 2 {
				t.Fatalf("retried create duplicated a pool: %v %v", ids, err)
			}
			r.PhysicalID, r.Previous = created.PhysicalID, r.Properties
			model, err := h.Read(f.ctx, r)
			if err != nil || !reflect.DeepEqual(model["UserPoolTags"], map[string]any{"team": "a"}) {
				t.Fatalf("read exposed private ownership or lost tags: %#v %v", model, err)
			}

			// r cannot mutate or delete the counterfeit through its forged tags.
			forged := r
			forged.PhysicalID = counterfeit
			if _, err := h.Update(f.ctx, forged); err == nil {
				t.Fatal("tag-forged pool was updated by the stack")
			}
			if err := h.Delete(f.ctx, forged); err != nil && !cfnCognitoMissing(err) {
				t.Fatal(err)
			}
			if !exists(counterfeit) {
				t.Fatal("stack deleted a tag-forged pool")
			}

			// Another incarnation cannot mutate or delete r's pool.
			foreign := r
			foreign.StackID, foreign.Token = "other-stack", "other-incarnation"
			if _, err := h.Update(f.ctx, foreign); err == nil {
				t.Fatal("foreign incarnation updated a claimed pool")
			}
			if err := h.Delete(f.ctx, foreign); err == nil || !exists(created.PhysicalID) {
				t.Fatalf("foreign incarnation deleted a claimed pool: %v", err)
			}

			// Cloud Control mutates under current IAM without the stack claim.
			direct := r
			direct.CloudControl, direct.Properties = true, cloudformation.Properties{"UserPoolName": "renamed", "UserPoolTags": map[string]any{"team": "b"}}
			if _, err := h.Update(f.ctx, direct); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatalf("owner lost its claim after a Cloud Control update: %v", err)
			}

			// The owner deletes its pool; the claim goes with it.
			if err := h.Delete(f.ctx, r); err != nil || exists(created.PhysicalID) {
				t.Fatalf("owned deletion failed: %v", err)
			}
			result, err = h.RecoverCreation(f.ctx, r)
			cfnCognitoNotAdmitted(t, "deleted", result, err)

			// A Cloud Control create claims its pool too: it replays and a stack
			// incarnation cannot adopt it.
			cc := cfnCognitoCloudControlRequest("AWS::Cognito::UserPool", "cc-pool", cloudformation.Properties{"UserPoolName": "direct"})
			first, err := h.Create(f.ctx, cc)
			if err != nil {
				t.Fatal(err)
			}
			result, err = h.Create(f.ctx, cc)
			cfnCognitoSame(t, "cloud control retry", first.PhysicalID, result, err)
			adopt := cfnWorkflowOwnerRequest("AWS::Cognito::UserPool", "Adopt", cloudformation.Properties{"UserPoolName": "direct"})
			adopt.PhysicalID, adopt.Previous = first.PhysicalID, adopt.Properties
			if _, err := h.Update(f.ctx, adopt); err == nil {
				t.Fatal("stack adopted a Cloud Control pool")
			}

			// Direct API deletion stays IAM-authorized and releases the claim.
			if err := cfnMessagingExec(f.ctx, f.commands, "cognitoidp", "DeleteUserPool", &idpapi.DeleteUserPoolInput{UserPoolId: new(idpapi.UserPoolIdType(first.PhysicalID))}); err != nil {
				t.Fatalf("direct deletion of a claimed pool was fenced: %v", err)
			}
			result, err = h.RecoverCreation(f.ctx, cc)
			cfnCognitoNotAdmitted(t, "directly deleted", result, err)
		})
	}
}

func TestCFNCognitoUserPoolClientRecoversOnlyExactIncarnation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNCognitoOwnerFixture(t, backend)
			out, err := cfnMessagingCall[idpapi.CreateUserPoolOutput](f.ctx, f.commands, "cognitoidp", "CreateUserPool", &idpapi.CreateUserPoolInput{PoolName: new(idpapi.UserPoolNameType("host"))})
			if err != nil {
				t.Fatal(err)
			}
			pool := cfnComputeValue(out.UserPool.Id)
			r := cfnWorkflowOwnerRequest("AWS::Cognito::UserPoolClient", "Client", cloudformation.Properties{"UserPoolId": pool, "ClientName": "app"})
			result, err := cfnCognitoUserPoolClient{f.commands}.RecoverCreation(f.ctx, r)
			cfnCognitoNotAdmitted(t, "before create", result, err)
			created, err := cfnCognitoUserPoolClient{f.commands}.Create(f.ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			f.restart(t)
			h := cfnCognitoUserPoolClient{f.commands}
			result, err = h.RecoverCreation(f.ctx, r)
			cfnCognitoSame(t, "recovered", created.PhysicalID, result, err)
			result, err = h.Create(f.ctx, r)
			cfnCognitoSame(t, "retried", created.PhysicalID, result, err)
			other := r
			other.Token = "replacement-incarnation"
			result, err = h.RecoverCreation(f.ctx, other)
			cfnCognitoNotAdmitted(t, "replacement", result, err)

			// Cloud Control creates claim and replay their client as well.
			cc := cfnCognitoCloudControlRequest("AWS::Cognito::UserPoolClient", "cc-client", cloudformation.Properties{"UserPoolId": pool, "ClientName": "direct"})
			first, err := h.Create(f.ctx, cc)
			if err != nil {
				t.Fatal(err)
			}
			result, err = h.Create(f.ctx, cc)
			cfnCognitoSame(t, "cloud control retry", first.PhysicalID, result, err)

			// An absent pool is not proof that the client was never admitted.
			if err := cfnMessagingExec(f.ctx, f.commands, "cognitoidp", "DeleteUserPool", &idpapi.DeleteUserPoolInput{UserPoolId: new(idpapi.UserPoolIdType(pool))}); err != nil {
				t.Fatal(err)
			}
			result, err = h.RecoverCreation(f.ctx, r)
			if err == nil || cfnCognitoMissing(err) || result.PhysicalID != "" {
				t.Fatalf("missing pool certified client nonadmission: %+v %v", result, err)
			}
		})
	}
}

func TestCFNCognitoDomainRecoveryNeverAdoptsForeignDomain(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNCognitoOwnerFixture(t, backend)
			pool := func(name string) string {
				t.Helper()
				out, err := cfnMessagingCall[idpapi.CreateUserPoolOutput](f.ctx, f.commands, "cognitoidp", "CreateUserPool", &idpapi.CreateUserPoolInput{PoolName: new(idpapi.UserPoolNameType(name))})
				if err != nil {
					t.Fatal(err)
				}
				return cfnComputeValue(out.UserPool.Id)
			}
			foreign, target := pool("foreign-domain-host"), pool("target-domain-host")
			const domain = "foreign-domain-prefix"
			if err := cfnMessagingExec(f.ctx, f.commands, "cognitoidp", "CreateUserPoolDomain", &idpapi.CreateUserPoolDomainInput{UserPoolId: new(idpapi.UserPoolIdType(foreign)), Domain: new(idpapi.DomainType(domain))}); err != nil {
				t.Fatal(err)
			}
			r := cfnWorkflowOwnerRequest("AWS::Cognito::UserPoolDomain", "Domain", cloudformation.Properties{"UserPoolId": target, "Domain": domain})
			h := cfnCognitoUserPoolDomain{f.commands}
			result, err := h.RecoverCreation(f.ctx, r)
			cfnCognitoNotAdmitted(t, "before conflicting create", result, err)
			if result, err := h.Create(f.ctx, r); err == nil || result.PhysicalID != "" {
				t.Fatalf("adopted foreign domain: %+v %v", result, err)
			}
			f.restart(t)
			h = cfnCognitoUserPoolDomain{f.commands}
			result, err = h.RecoverCreation(f.ctx, r)
			cfnCognitoNotAdmitted(t, "failed conflicting create", result, err)
			// Recovery must not silently create an available prefix, either.
			available := r
			available.Properties = cloudformation.Properties{"UserPoolId": target, "Domain": "available-domain-prefix"}
			result, err = h.RecoverCreation(f.ctx, available)
			cfnCognitoNotAdmitted(t, "available but never admitted", result, err)
			out, err := cfnMessagingCall[idpapi.DescribeUserPoolDomainOutput](f.ctx, f.commands, "cognitoidp", "DescribeUserPoolDomain", &idpapi.DescribeUserPoolDomainInput{Domain: new(idpapi.DomainType("available-domain-prefix"))})
			if err != nil || cfnComputeValue(out.DomainDescription.UserPoolId) != "" {
				t.Fatalf("recovery created a domain: %+v %v", out, err)
			}
			// An unclaimed domain in the requested pool is also foreign.
			samePool := r
			samePool.Properties = cloudformation.Properties{"UserPoolId": foreign, "Domain": domain}
			result, err = h.RecoverCreation(f.ctx, samePool)
			cfnCognitoNotAdmitted(t, "unclaimed same-pool domain", result, err)
			samePool.PhysicalID = foreign + "|" + domain
			if err := h.Delete(f.ctx, samePool); err != nil && !cfnCognitoMissing(err) {
				t.Fatal(err)
			}
			out, err = cfnMessagingCall[idpapi.DescribeUserPoolDomainOutput](f.ctx, f.commands, "cognitoidp", "DescribeUserPoolDomain", &idpapi.DescribeUserPoolDomainInput{Domain: new(idpapi.DomainType(domain))})
			if err != nil || cfnComputeValue(out.DomainDescription.UserPoolId) != foreign {
				t.Fatalf("rollback deleted foreign domain: %+v %v", out, err)
			}
			created, err := h.Create(f.ctx, available)
			if err != nil {
				t.Fatal(err)
			}
			f.restart(t)
			h = cfnCognitoUserPoolDomain{f.commands}
			result, err = h.RecoverCreation(f.ctx, available)
			cfnCognitoSame(t, "exact admitted incarnation", created.PhysicalID, result, err)
			replacement := available
			replacement.Token = "replacement-incarnation"
			result, err = h.RecoverCreation(f.ctx, replacement)
			cfnCognitoNotAdmitted(t, "foreign incarnation", result, err)
			// Current create authority precedes both admission and nonadmission.
			metadata := awsctx.FromContext(f.ctx)
			metadata.PrincipalARN = "arn:aws:iam::123456789012:user/without-domain-permissions"
			denied := awsctx.WithMetadata(f.ctx, metadata)
			for _, request := range []cloudformation.ResourceRequest{available, replacement, r} {
				result, err = h.RecoverCreation(denied, request)
				if err == nil || cfnCognitoMissing(err) || result.PhysicalID != "" {
					t.Fatalf("unauthorized recovery certified admission/nonadmission: %+v %v", result, err)
				}
			}
			available.PhysicalID = created.PhysicalID
			if err := h.Delete(f.ctx, available); err != nil {
				t.Fatal(err)
			}
			if err := cfnMessagingExec(f.ctx, f.commands, "cognitoidp", "DeleteUserPool", &idpapi.DeleteUserPoolInput{UserPoolId: new(idpapi.UserPoolIdType(target))}); err != nil {
				t.Fatal(err)
			}
			result, err = h.RecoverCreation(f.ctx, available)
			if err == nil || cfnCognitoMissing(err) || result.PhysicalID != "" {
				t.Fatalf("missing parent certified nonadmission: %+v %v", result, err)
			}
		})
	}
}

func TestCFNCognitoIdentityPoolPrivateClaimsRejectCounterfeitAndForeignRecreation(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			f := newCFNCognitoOwnerFixture(t, backend)
			tags := []any{map[string]any{"Key": "team", "Value": "a"}}
			r := cfnWorkflowOwnerRequest("AWS::Cognito::IdentityPool", "Identity", cloudformation.Properties{"AllowUnauthenticatedIdentities": true, "IdentityPoolTags": tags})
			exists := func(id string) bool {
				t.Helper()
				_, _, err := cfnCognitoIdentityPool{f.commands}.describe(f.ctx, id)
				if err != nil && !cfnCognitoMissing(err) {
					t.Fatal(err)
				}
				return err == nil
			}
			in := &identityapi.CreateIdentityPoolInput{IdentityPoolName: new(identityapi.IdentityPoolName("counterfeit")), AllowUnauthenticatedIdentities: new(identityapi.IdentityPoolUnauthenticated(true)), IdentityPoolTags: cfnCognitoIdentityTags(cfnCognitoCounterfeitTags(r))}
			out, err := cfnMessagingCall[identityapi.CreateIdentityPoolOutput](f.ctx, f.commands, "cognitoidentity", "CreateIdentityPool", in)
			if err != nil {
				t.Fatal(err)
			}
			counterfeit := cfnComputeValue(out.IdentityPoolId)
			result, err := cfnCognitoIdentityPool{f.commands}.RecoverCreation(f.ctx, r)
			cfnCognitoNotAdmitted(t, "counterfeit", result, err)
			created, err := cfnCognitoIdentityPool{f.commands}.Create(f.ctx, r)
			if err != nil || created.PhysicalID == "" || created.PhysicalID == counterfeit {
				t.Fatalf("create adopted a counterfeit pool or failed: %+v %v", created, err)
			}

			f.restart(t)
			h := cfnCognitoIdentityPool{f.commands}
			result, err = h.RecoverCreation(f.ctx, r)
			cfnCognitoSame(t, "recovered", created.PhysicalID, result, err)
			result, err = h.Create(f.ctx, r)
			cfnCognitoSame(t, "retried", created.PhysicalID, result, err)
			ids, err := h.ids(f.ctx)
			if err != nil || len(ids) != 2 {
				t.Fatalf("retried create duplicated a pool: %v %v", ids, err)
			}
			r.PhysicalID, r.Previous = created.PhysicalID, r.Properties
			model, err := h.Read(f.ctx, r)
			if err != nil || !reflect.DeepEqual(model["IdentityPoolTags"], tags) {
				t.Fatalf("read exposed private ownership or lost tags: %#v %v", model, err)
			}

			forged := r
			forged.PhysicalID = counterfeit
			if _, err := h.Update(f.ctx, forged); err == nil {
				t.Fatal("tag-forged identity pool was updated by the stack")
			}
			if err := h.Delete(f.ctx, forged); err == nil || !exists(counterfeit) {
				t.Fatalf("stack deleted a tag-forged identity pool: %v", err)
			}
			foreign := r
			foreign.StackID, foreign.Token = "other-stack", "other-incarnation"
			if _, err := h.Update(f.ctx, foreign); err == nil {
				t.Fatal("foreign incarnation updated a claimed identity pool")
			}
			if err := h.Delete(f.ctx, foreign); err == nil || !exists(created.PhysicalID) {
				t.Fatalf("foreign incarnation deleted a claimed identity pool: %v", err)
			}

			direct := r
			direct.CloudControl, direct.Properties = true, cloudformation.Properties{"AllowUnauthenticatedIdentities": false, "IdentityPoolTags": []any{}}
			if _, err := h.Update(f.ctx, direct); err != nil {
				t.Fatal(err)
			}
			if _, err := h.Update(f.ctx, r); err != nil {
				t.Fatalf("owner lost its claim after a Cloud Control update: %v", err)
			}
			if err := h.Delete(f.ctx, r); err != nil || exists(created.PhysicalID) {
				t.Fatalf("owned deletion failed: %v", err)
			}
			result, err = h.RecoverCreation(f.ctx, r)
			cfnCognitoNotAdmitted(t, "deleted", result, err)

			cc := cfnCognitoCloudControlRequest("AWS::Cognito::IdentityPool", "cc-identity", cloudformation.Properties{"AllowUnauthenticatedIdentities": true})
			first, err := h.Create(f.ctx, cc)
			if err != nil {
				t.Fatal(err)
			}
			result, err = h.Create(f.ctx, cc)
			cfnCognitoSame(t, "cloud control retry", first.PhysicalID, result, err)
			adopt := cfnWorkflowOwnerRequest("AWS::Cognito::IdentityPool", "Adopt", cloudformation.Properties{"AllowUnauthenticatedIdentities": true})
			adopt.PhysicalID, adopt.Previous = first.PhysicalID, adopt.Properties
			if _, err := h.Update(f.ctx, adopt); err == nil {
				t.Fatal("stack adopted a Cloud Control identity pool")
			}
		})
	}
}

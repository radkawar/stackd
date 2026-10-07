package lambda_test

import (
	"errors"
	"reflect"
	"testing"

	runtime "stackd/compute/lambda"
	api "stackd/internal/awsapi/lambda"
	"stackd/storage/lambda"
)

func TestImageDeploymentOwnerAndVersionPersistence(t *testing.T) {
	forRepositories(t, func(t *testing.T, repo lambda.Repository) {
		function := deployment()
		function.Runtime, function.Handler = "", ""
		function.Image = &runtime.Image{URI: "local-image:latest", ID: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ResolvedURI: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Size: 1024, EntryPoint: []string{"/bootstrap"}, Command: []string{"original"}, Environment: []string{"DEFAULT=yes"}, WorkingDirectory: "/var/task"}
		function.ImageConfig = &api.ImageConfig{Command: api.StringList{"override"}, WorkingDirectory: new(api.WorkingDirectory("/work"))}
		function.Owner = lambda.FunctionOwner{StackID: "stack-a", LogicalID: "Function", Token: "incarnation-a"}
		function.NetworkIncarnation = "function-network-incarnation"
		function.VpcConfig = lambda.FunctionNetworkConfiguration{SubnetIDs: []string{"subnet-a"}, SecurityGroupIDs: []string{"sg-a"}, VPCID: "vpc-a"}
		published := function
		published.Version = 1
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.PutFunction(function); err != nil {
				return err
			}
			return tx.PutFunctionVersion(published)
		}); err != nil {
			t.Fatal(err)
		}
		abort := errors.New("rollback image configuration")
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			changed, err := tx.Function(function.Key)
			if err != nil {
				return err
			}
			changed.Image.Command[0] = "changed"
			changed.ImageConfig.Command[0] = "changed"
			changed.Owner.Token = "new-owner"
			changed.VpcConfig.SubnetIDs[0] = "subnet-other"
			if err := tx.PutFunction(changed); err != nil {
				return err
			}
			return abort
		}); !errors.Is(err, abort) {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			current, err := r.Function(function.Key)
			if err != nil {
				return err
			}
			version, err := r.FunctionVersion(lambda.FunctionVersionKey{FunctionKey: function.Key, Version: 1})
			if err != nil {
				return err
			}
			for _, pair := range []struct{ got, want lambda.FunctionRecord }{{current, function}, {version, published}} {
				if !reflect.DeepEqual(pair.got.Image, pair.want.Image) || !reflect.DeepEqual(pair.got.ImageConfig, pair.want.ImageConfig) || pair.got.Owner != pair.want.Owner || !reflect.DeepEqual(pair.got.VpcConfig, pair.want.VpcConfig) || pair.got.NetworkIncarnation != pair.want.NetworkIncarnation {
					t.Fatalf("rollback or publication changed retained image/owner/network attachments: got=%+v want=%+v", pair.got, pair.want)
				}
			}
			current.Image.Command[0] = "mutated-read"
			current.ImageConfig.Command[0] = "mutated-read"
			current.VpcConfig.SubnetIDs[0] = "mutated-read"
			again, err := r.Function(function.Key)
			if err == nil && (!reflect.DeepEqual(again.Image, function.Image) || !reflect.DeepEqual(again.ImageConfig, function.ImageConfig) || !reflect.DeepEqual(again.VpcConfig, function.VpcConfig)) {
				t.Fatal("repository read exposed mutable deployment attachments")
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.Update(t.Context(), func(tx lambda.Transaction) error {
			if err := tx.DeleteFunction(function.Key); err != nil {
				return err
			}
			replacement := function
			replacement.Owner = lambda.FunctionOwner{}
			replacement.Image = nil
			replacement.ImageConfig = nil
			replacement.VpcConfig = lambda.FunctionNetworkConfiguration{}
			replacement.NetworkIncarnation = "new-incarnation"
			return tx.PutFunction(replacement)
		}); err != nil {
			t.Fatal(err)
		}
		if err := repo.View(t.Context(), func(r lambda.Reader) error {
			replacement, err := r.Function(function.Key)
			if err == nil && (replacement.Owner != (lambda.FunctionOwner{}) || replacement.Image != nil || replacement.ImageConfig != nil || replacement.NetworkIncarnation != "new-incarnation") {
				t.Fatalf("same-name recreation inherited deployment attachments: %+v", replacement)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	})
}

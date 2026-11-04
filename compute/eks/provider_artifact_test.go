package eks

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestECRProviderRetainedAcrossControllerRelocation(t *testing.T) {
	k, state, dir := newECRFixture(t)
	if err := k.prepareECR(&state, dir, true); err != nil {
		t.Fatal(err)
	}
	identity := *state.ECRProvider
	original := k.config.ECRCredentialProvider
	staged, err := os.ReadFile(filepath.Join(dir, ecrProviderName))
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"relocated", "rebuilt original", "deleted original", "provider flag omitted"} {
		t.Run(phase, func(t *testing.T) {
			config := k.config
			switch phase {
			case "relocated":
				config.ECRCredentialProvider = filepath.Join(t.TempDir(), "other-build")
				if err := os.WriteFile(config.ECRCredentialProvider, []byte("different provider build"), 0700); err != nil {
					t.Fatal(err)
				}
			case "rebuilt original":
				if err := os.WriteFile(original, []byte("rebuilt executable"), 0700); err != nil {
					t.Fatal(err)
				}
			case "deleted original":
				if err := os.Remove(original); err != nil {
					t.Fatal(err)
				}
			case "provider flag omitted":
				config.ECRCredentialProvider = ""
			}
			if err := configureECR(&config); err != nil {
				t.Fatal(err)
			}
			reopened := &K3d{config: config}
			retained, _, err := reopened.loadOrPrepare(state.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err := reopened.prepareECR(&retained, dir, false); err != nil {
				t.Fatal(err)
			}
			if _, err := reopened.ecrWorkerArguments(retained, dir); err != nil {
				t.Fatal(err)
			}
			if err := reopened.validateWorkerECR(retained, ecrFixtureContainer(t, reopened, dir)); err != nil {
				t.Fatal(err)
			}
			if retained.ECRProvider == nil || *retained.ECRProvider != identity {
				t.Fatal("reattachment changed the durable provider receipt")
			}
			body, err := os.ReadFile(filepath.Join(dir, ecrProviderName))
			if err != nil || !bytes.Equal(body, staged) {
				t.Fatalf("reattachment replaced the mounted executable: %v", err)
			}
		})
	}
}

func TestECRProviderRetainedArtifactFailsClosed(t *testing.T) {
	for _, mutation := range []string{"missing", "digest", "writable", "nonexecutable", "symlink", "replacement inode", "extra hardlink", "receipt digest", "receipt inode", "receipt device", "receipt uid", "receipt gid", "directory owner mode", "missing trust"} {
		t.Run(mutation, func(t *testing.T) {
			k, state, dir := newECRFixture(t)
			if err := k.prepareECR(&state, dir, true); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, ecrProviderName)
			body, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "missing":
				err = os.Remove(path)
			case "digest":
				if err = os.Chmod(path, 0700); err == nil {
					body[0] ^= 1
					err = os.WriteFile(path, body, 0500)
				}
				if err == nil {
					err = os.Chmod(path, 0500)
				}
			case "writable":
				err = os.Chmod(path, 0700)
			case "nonexecutable":
				err = os.Chmod(path, 0400)
			case "symlink":
				if err = os.Remove(path); err == nil {
					err = os.Symlink(k.config.ECRCredentialProvider, path)
				}
			case "replacement inode":
				if err = os.Rename(path, filepath.Join(t.TempDir(), "preserved-inode")); err == nil {
					err = os.WriteFile(path, body, 0500)
				}
			case "extra hardlink":
				err = os.Link(path, filepath.Join(t.TempDir(), "outside-link"))
			case "receipt digest":
				state.ECRProvider.SHA256 = "invalid"
			case "receipt inode":
				state.ECRProvider.Inode++
			case "receipt device":
				state.ECRProvider.Device++
			case "receipt uid":
				state.ECRProvider.UID++
			case "receipt gid":
				state.ECRProvider.GID++
			case "directory owner mode":
				err = os.Chmod(dir, 0755)
			case "missing trust":
				err = os.Remove(filepath.Join(dir, "ecr-ca.pem"))
			}
			if err != nil {
				t.Fatal(err)
			}
			checkpoint, err := os.ReadFile(filepath.Join(dir, "owner.json"))
			if err != nil {
				t.Fatal(err)
			}
			before, statErr := os.Lstat(path)
			if err := k.prepareECR(&state, dir, false); err == nil {
				t.Fatal("accepted unsafe retained artifact or trust")
			}
			if mutation != "missing trust" {
				if _, err := k.ecrWorkerArguments(state, dir); err == nil {
					t.Fatal("generated worker mounts for unsafe artifact")
				}
				if err := k.validateWorkerECR(state, ecrFixtureContainer(t, k, dir)); err == nil {
					t.Fatal("accepted a Docker mount whose retained artifact was unsafe")
				}
			}
			after, afterErr := os.Lstat(path)
			if os.IsNotExist(statErr) {
				if !os.IsNotExist(afterErr) {
					t.Fatal("recreated a missing retained executable")
				}
			} else if statErr != nil || afterErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatalf("replaced or changed rejected artifact: before=%v after=%v", statErr, afterErr)
			}
			retained, err := os.ReadFile(filepath.Join(dir, "owner.json"))
			if err != nil || !bytes.Equal(retained, checkpoint) {
				t.Fatal("rewrote rejected artifact ownership checkpoint")
			}
		})
	}
}

func TestECRProviderInterruptedPreparation(t *testing.T) {
	for _, phase := range []string{"pending only", "both names", "final only"} {
		t.Run(phase, func(t *testing.T) {
			k, state, dir := newECRFixture(t)
			if err := k.prepareECR(&state, dir, true); err != nil {
				t.Fatal(err)
			}
			identity := *state.ECRProvider
			state.ECRProvider.Preparing = true
			if err := saveState(dir, state); err != nil {
				t.Fatal(err)
			}
			final := filepath.Join(dir, ecrProviderName)
			pending := filepath.Join(dir, providerPendingName)
			switch phase {
			case "pending only":
				if err := os.Rename(final, pending); err != nil {
					t.Fatal(err)
				}
			case "both names":
				if err := os.Link(final, pending); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Remove(k.config.ECRCredentialProvider); err != nil {
				t.Fatal(err)
			}
			if err := k.validateWorkerECR(state, ecrFixtureContainer(t, k, dir)); err == nil {
				t.Fatal("attached a worker before preparation committed")
			}
			retained, _, err := k.loadOrPrepare(state.ID)
			if err != nil {
				t.Fatal(err)
			}
			if err := k.prepareECR(&retained, dir, true); err != nil {
				t.Fatal(err)
			}
			if *retained.ECRProvider != identity {
				t.Fatal("recovery adopted a different executable")
			}
			if _, err := os.Lstat(pending); !os.IsNotExist(err) {
				t.Fatalf("preparation link not cleaned: %v", err)
			}
			if err := validateProvider(dir, retained.ECRProvider); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestECRProviderUnknownPreparationIsNotAdopted(t *testing.T) {
	for _, name := range []string{ecrProviderName, providerPendingName} {
		t.Run(name, func(t *testing.T) {
			k, state, dir := newECRFixture(t)
			path := filepath.Join(dir, name)
			body := []byte("unreceipted independent fixture")
			if err := os.WriteFile(path, body, 0500); err != nil {
				t.Fatal(err)
			}
			if err := k.prepareECR(&state, dir, true); err == nil {
				t.Fatal("adopted an artifact without a durable inode receipt")
			}
			if state.ECRProvider != nil {
				t.Fatal("invented ownership for unreceipted content")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, body) {
				t.Fatal("replaced unknown artifact")
			}
		})
	}
}

func TestECRProviderFreshCreationRequiresExecutable(t *testing.T) {
	for _, source := range []string{"omitted", "missing", "nonexecutable", "empty"} {
		t.Run(source, func(t *testing.T) {
			k, state, dir := newECRFixture(t)
			switch source {
			case "omitted":
				k.config.ECRCredentialProvider = ""
			case "missing":
				if err := os.Remove(k.config.ECRCredentialProvider); err != nil {
					t.Fatal(err)
				}
			case "nonexecutable":
				if err := os.Chmod(k.config.ECRCredentialProvider, 0600); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err := os.WriteFile(k.config.ECRCredentialProvider, nil, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := configureECR(&k.config); err != nil {
				t.Fatal("constructor should defer source validation until new cluster creation:", err)
			}
			if err := k.prepareECR(&state, dir, true); err == nil {
				t.Fatal("created workers without an executable source")
			}
			if state.ECRProvider != nil {
				t.Fatal("persisted an unusable executable")
			}
		})
	}
}

func TestECRProviderInterruptedPreparationRejectsLossOrSubstitution(t *testing.T) {
	for _, phase := range []string{"missing", "substituted pending", "foreign final", "ready legacy"} {
		t.Run(phase, func(t *testing.T) {
			k, state, dir := newECRFixture(t)
			if err := k.prepareECR(&state, dir, true); err != nil {
				t.Fatal(err)
			}
			final := filepath.Join(dir, ecrProviderName)
			pending := filepath.Join(dir, providerPendingName)
			state.ECRProvider.Preparing = true
			if err := os.Rename(final, pending); err != nil {
				t.Fatal(err)
			}
			switch phase {
			case "missing":
				if err := os.Remove(pending); err != nil {
					t.Fatal(err)
				}
			case "substituted pending":
				if err := os.Rename(pending, filepath.Join(t.TempDir(), "original-inode")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(pending, []byte("unowned replacement"), 0500); err != nil {
					t.Fatal(err)
				}
			case "foreign final":
				if err := os.WriteFile(final, []byte("unowned final"), 0500); err != nil {
					t.Fatal(err)
				}
			case "ready legacy":
				state.Ready = true
			}
			if err := saveState(dir, state); err != nil {
				t.Fatal(err)
			}
			if err := k.prepareECR(&state, dir, true); err == nil {
				t.Fatal("adopted, replaced or completed unsafe interrupted preparation")
			}
			retained, err := readState(dir, state.ID)
			if err != nil || retained.ECRProvider == nil || !retained.ECRProvider.Preparing {
				t.Fatalf("rejected preparation was marked complete: %v", err)
			}
			if phase == "missing" || phase == "substituted pending" || phase == "ready legacy" {
				if _, err := os.Lstat(final); !os.IsNotExist(err) {
					t.Fatal("published an unsafe retained executable")
				}
			} else {
				body, err := os.ReadFile(final)
				if err != nil || string(body) != "unowned final" {
					t.Fatal("replaced foreign final artifact")
				}
			}
		})
	}
}

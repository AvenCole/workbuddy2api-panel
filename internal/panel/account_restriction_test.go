package panel

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
	"github.com/misakano7545/workbuddy2api-panel/internal/pool"
	"github.com/misakano7545/workbuddy2api-panel/internal/upstream"
)

func TestIsRestrictedErrRequiresExplicitRestrictionNotice(t *testing.T) {
	if !isRestrictedErr(&upstream.Error{Kind: upstream.ErrAccountFault, Restricted: true}) {
		t.Fatal("explicit restriction notice was not recognized")
	}
	for _, err := range []error{
		&upstream.Error{Kind: upstream.ErrAccountFault},
		&upstream.Error{Kind: upstream.ErrSessionDead},
		errors.New("network unavailable"),
	} {
		if isRestrictedErr(err) {
			t.Fatalf("non-restriction error was classified as banned: %v", err)
		}
	}
}

func TestQuarantineRestrictedAccountMovesCredentialsAndBackup(t *testing.T) {
	root := t.TempDir()
	authDir := filepath.Join(root, "auths")
	quarantineDir := filepath.Join(root, "backups", "quarantine-test")
	if err := os.MkdirAll(authDir, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(authDir, "workbuddy-u1.json")
	backup := file + ".bak"
	for _, path := range []string{file, backup} {
		if err := os.WriteFile(path, []byte("credential fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	accounts := pool.New("")
	accounts.Add(&auth.Auth{UID: "u1", FilePath: file})
	p := &Panel{cfg: Config{Pool: accounts, AuthDir: authDir}}
	if err := p.quarantineRestrictedAccount("u1", quarantineDir); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, backup} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("credential still exists in auth directory: %s", path)
		}
		if _, err := os.Stat(filepath.Join(quarantineDir, filepath.Base(path))); err != nil {
			t.Fatalf("credential not preserved in quarantine: %s: %v", path, err)
		}
	}
	if _, exists := accounts.Status("u1"); exists {
		t.Fatal("quarantined account remains in pool")
	}
}

func TestDeleteRestrictedAccountsStoresQuarantineUnderConfiguredPersistentDir(t *testing.T) {
	root := t.TempDir()
	authDir := filepath.Join(root, "auths")
	quarantineRoot := filepath.Join(root, "data", "quarantine")
	if err := os.MkdirAll(authDir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := &Panel{cfg: Config{AuthDir: authDir, QuarantineDir: quarantineRoot}}
	got := p.cfg.QuarantineDir
	if filepath.Dir(got) != filepath.Join(root, "data") {
		t.Fatalf("quarantine directory is not on persistent data volume: %s", got)
	}
}

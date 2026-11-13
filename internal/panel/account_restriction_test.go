package panel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
	"github.com/misakano7545/workbuddy2api-panel/internal/pool"
	"github.com/misakano7545/workbuddy2api-panel/internal/upstream"
)

func TestRestrictionProbeUsesAccountChatAndNeverBalance(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		verdict string
	}{
		{"success", 200, "data: {\"choices\":[{\"delta\":{\"content\":\"OK\"}}]}\n\ndata: [DONE]\n\n", "lifted"},
		{"ban", 403, `{"code":11140,"msg":"request illegal"}`, "still_banned"},
		{"ban after long message", 403, `{"msg":"` + strings.Repeat("x", 250) + `","error":{"code":"11140"}}`, "still_banned"},
		{"rate code 11140", 429, `{"code":11140,"msg":"The model provider is rate-limiting requests."}`, "still_banned"},
		{"trial", 403, `{"code":14017,"msg":"trial not activated"}`, "inconclusive"},
		{"channel", 400, `{"code":"11-128","msg":"request illegal"}`, "inconclusive"},
		{"rate", 429, `{"code":6004,"msg":"rate limit"}`, "inconclusive"},
		{"session", 401, `{"code":12153,"msg":"session dead"}`, "inconclusive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var chats, billing atomic.Int32
			up := &upstream.Client{ChatBaseCN: "https://chat.example", BillingBaseCN: "https://billing.example"}
			up.HTTP = &http.Client{Transport: fakeRoundTripper(func(r *http.Request) (*http.Response, error) {
				status, body := http.StatusOK, `{"code":0,"data":{"models":[{"id":"glm-5.2","name":"GLM","maxOutputTokens":8192}],"agents":[{"name":"cli","models":["glm-5.2"]}]}}`
				if r.URL.Host == "billing.example" {
					billing.Add(1)
				}
				if r.Method == http.MethodPost {
					chats.Add(1)
					if r.Header.Get("Authorization") != "Bearer account-token" {
						t.Errorf("chat used wrong account: %s", r.Header.Get("Authorization"))
					}
					var request map[string]any
					if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
						t.Errorf("chat request: %v", err)
					}
					if request["model"] != "glm-5.2" || request["max_tokens"] != float64(1) {
						t.Errorf("unexpected probe body: %v", request)
					}
					status, body = tc.status, tc.body
				}
				return &http.Response{StatusCode: status, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}
			accounts := pool.New("")
			accounts.Add(&auth.Auth{UID: "probe-account", AccessToken: "account-token", ExpiresAt: 9999999999})
			p := &Panel{cfg: Config{Pool: accounts, Upstream: up}}
			result := p.probeRestriction(httptest.NewRequest("POST", "/probe", nil), "probe-account", "chat_probe")
			if result.Verdict != tc.verdict || chats.Load() != 1 || billing.Load() != 0 {
				t.Fatalf("result=%+v chats=%d billing=%d", result, chats.Load(), billing.Load())
			}
			st, _ := accounts.Status("probe-account")
			if st.Disabled != (tc.verdict == "still_banned") {
				t.Fatalf("unexpected account state: %+v", st)
			}
			root := t.TempDir()
			p.cfg.AuthDir = filepath.Join(root, "auths")
			p.cfg.QuarantineDir = filepath.Join(root, "data", "quarantine")
			if err := os.MkdirAll(p.cfg.AuthDir, 0o700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(p.cfg.AuthDir, "probe-account.json")
			for _, path := range []string{file, file + ".bak"} {
				if err := os.WriteFile(path, []byte("credential fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			accounts.Add(&auth.Auth{UID: "probe-account", AccessToken: "account-token", ExpiresAt: 9999999999, FilePath: file})
			recorder := httptest.NewRecorder()
			p.deleteRestrictedAccounts(recorder, httptest.NewRequest("POST", "/delete", strings.NewReader(`{"uids":["probe-account"]}`)))
			var deleted struct {
				Deleted       []string            `json:"deleted"`
				Skipped       []map[string]string `json:"skipped"`
				QuarantineDir string              `json:"quarantine_dir"`
			}
			if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &deleted) != nil {
				t.Fatalf("delete response = %d %s", recorder.Code, recorder.Body.String())
			}
			if tc.verdict == "still_banned" {
				if len(deleted.Deleted) != 1 || len(deleted.Skipped) != 0 {
					t.Fatalf("11140 account was not quarantined: %+v", deleted)
				}
				for _, path := range []string{file, file + ".bak"} {
					if _, err := os.Stat(path); !os.IsNotExist(err) {
						t.Fatalf("quarantined credential remains: %s", path)
					}
					preserved := filepath.Join(p.cfg.QuarantineDir, deleted.QuarantineDir, filepath.Base(path))
					if raw, err := os.ReadFile(preserved); err != nil || string(raw) != "credential fixture" {
						t.Fatalf("quarantined credential was not preserved: %s", preserved)
					}
				}
			} else if len(deleted.Deleted) != 0 || len(deleted.Skipped) != 1 {
				t.Fatalf("non-11140 account was deleted: %+v", deleted)
			} else if _, err := os.Stat(file); err != nil {
				t.Fatalf("non-11140 credential was removed: %v", err)
			}
			if chats.Load() != 2 || billing.Load() != 0 {
				t.Fatalf("deletion did not use a fresh chat request: chats=%d billing=%d", chats.Load(), billing.Load())
			}
		})
	}
}

func TestRunRestrictionProbesStopsOnFirst11140(t *testing.T) {
	accounts := []pool.Status{{UID: "u1"}, {UID: "u2"}, {UID: "u3"}}
	var calls []string
	results := runRestrictionProbes(context.Background(), accounts, func(account pool.Status) restrictionProbeResult {
		calls = append(calls, account.UID)
		return restrictionProbeResult{UID: account.UID, Verdict: "still_banned", Restricted: true}
	})
	if len(calls) != 1 || calls[0] != "u1" || len(results) != 1 {
		t.Fatalf("probe continued after 11140: calls=%v results=%v", calls, results)
	}
}

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

func TestMoveCredentialCopiesAndRemovesSource(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "auth.json")
	dst := filepath.Join(root, "quarantine", "auth.json")
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("credential fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := moveCredential(src, dst); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("source credential still exists: %v", err)
	}
	if raw, err := os.ReadFile(dst); err != nil || string(raw) != "credential fixture" {
		t.Fatalf("quarantine content = %q, err=%v", raw, err)
	}
}

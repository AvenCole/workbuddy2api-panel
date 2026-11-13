package pool

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
)

func TestRecordRestrictionProbePersistsAndDisablesConfirmedBan(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state.json")
	p := New(state)
	p.Add(&auth.Auth{UID: "u1"})
	if !p.RecordRestrictionProbe("u1", "still_banned", "bulk_probe") {
		t.Fatal("probe result was not recorded")
	}
	st, ok := p.Status("u1")
	if !ok || !st.Disabled || st.RestrictionStatus != "still_banned" || st.RestrictionSource != "bulk_probe" || st.RestrictionCheckedAt == nil {
		t.Fatalf("confirmed restriction status = %+v, exists=%v", st, ok)
	}
	if p.Revive("u1") {
		t.Fatal("confirmed upstream restriction was manually revived")
	}
	p.Close()

	raw, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Accounts map[string]map[string]any `json:"accounts"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if got := doc.Accounts["u1"]["restriction_status"]; got != "still_banned" {
		t.Fatalf("persisted restriction_status = %v", got)
	}

	restored := New(state)
	defer restored.Close()
	st, ok = restored.Status("u1")
	if !ok || st.RestrictionStatus != "still_banned" || !st.Disabled {
		t.Fatalf("restored status = %+v, exists=%v", st, ok)
	}
	if !restored.RecordRestrictionProbe("u1", "lifted", "bulk_probe") || !restored.Revive("u1") {
		t.Fatal("lifted account could not be manually revived")
	}
}

func TestRecordRestrictionProbeDoesNotDisableUncertainOrLifted(t *testing.T) {
	p := New("")
	p.Add(&auth.Auth{UID: "u1"})
	for _, verdict := range []string{"lifted", "session_dead", "inconclusive"} {
		if !p.RecordRestrictionProbe("u1", verdict, "bulk_probe") {
			t.Fatalf("verdict %q was rejected", verdict)
		}
		st, _ := p.Status("u1")
		if st.Disabled {
			t.Fatalf("verdict %q disabled account", verdict)
		}
	}
	if p.RecordRestrictionProbe("u1", "account_fault", "bulk_probe") {
		t.Fatal("unsupported verdict was accepted")
	}
}

func TestRecordRestrictionProbePreservesManualDisableReason(t *testing.T) {
	p := New("")
	p.Add(&auth.Auth{UID: "u1"})
	p.Disable("u1", "disabled by operator")
	if !p.RecordRestrictionProbe("u1", "still_banned", "bulk_probe") {
		t.Fatal("restriction result was not recorded")
	}
	st, _ := p.Status("u1")
	if st.Reason != "disabled by operator" {
		t.Fatalf("manual disable reason was overwritten: %q", st.Reason)
	}
}

func TestUncertainProbeDoesNotClearConfirmedRestriction(t *testing.T) {
	p := New("")
	p.Add(&auth.Auth{UID: "u1"})
	p.RecordRestrictionProbe("u1", "still_banned", "chat")
	for _, verdict := range []string{"session_dead", "inconclusive"} {
		if !p.RecordRestrictionProbe("u1", verdict, "bulk_probe") {
			t.Fatalf("verdict %q was rejected", verdict)
		}
		st, _ := p.Status("u1")
		if st.RestrictionStatus != "still_banned" || !st.Disabled || p.Revive("u1") {
			t.Fatalf("verdict %q cleared the confirmed restriction: %+v", verdict, st)
		}
	}
}

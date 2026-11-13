package panel

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/misakano7545/workbuddy2api-panel/internal/pool"
	"github.com/misakano7545/workbuddy2api-panel/internal/upstream"
)

const restrictionProbeConcurrency = 3

type restrictionProbeResult struct {
	UID        string `json:"uid"`
	Nickname   string `json:"nickname,omitempty"`
	Realm      string `json:"realm,omitempty"`
	Verdict    string `json:"verdict"`
	Restricted bool   `json:"restricted"`
	HTTPStatus int    `json:"http_status,omitempty"`
	CheckedAt  string `json:"checked_at"`
}

func (p *Panel) modelProbeLock(uid string) *sync.Mutex {
	p.modelProbeMu.Lock()
	defer p.modelProbeMu.Unlock()
	if p.modelProbeLocks == nil {
		p.modelProbeLocks = map[string]*sync.Mutex{}
	}
	lock := p.modelProbeLocks[uid]
	if lock == nil {
		lock = &sync.Mutex{}
		p.modelProbeLocks[uid] = lock
	}
	return lock
}

func (p *Panel) probeRestriction(uid, source string) restrictionProbeResult {
	result := restrictionProbeResult{UID: uid, CheckedAt: time.Now().Format(time.RFC3339)}
	a := p.cfg.Pool.AuthByUID(uid)
	if a == nil {
		result.Verdict = "account_missing"
		return result
	}
	result.Nickname, result.Realm = a.Nickname, a.Realm()
	if p.cfg.Upstream == nil {
		result.Verdict = "inconclusive"
		return result
	}
	remain, total, expiring, earliestAt, earliestRemaining, buckets, err := p.cfg.Upstream.UserResourceSnapshot(a, p.expiringSoonWindow())
	verdict := "lifted"
	if err == nil {
		p.cfg.Pool.SetCreditsSnapshot(uid, pool.CreditsSnapshot{
			Remain: remain, Total: total, Expiring: expiring, EarliestAt: earliestAt,
			EarliestRemaining: earliestRemaining, ExpiryBuckets: poolExpiryBuckets(buckets),
		})
	} else {
		verdict = "inconclusive"
		var ue *upstream.Error
		if errors.As(err, &ue) {
			result.HTTPStatus = ue.Status
			switch {
			case ue.Restricted:
				verdict = "still_banned"
			case ue.Kind == upstream.ErrSessionDead:
				if p.cfg.Upstream.VerifySessionByRefresh(a) == upstream.VerifyDead {
					verdict = "session_dead"
				}
			}
		}
	}
	result.Verdict = verdict
	result.Restricted = verdict == "still_banned"
	p.cfg.Pool.RecordRestrictionProbe(uid, verdict, source)
	return result
}

func (p *Panel) probeAllRestrictions(w http.ResponseWriter, r *http.Request) {
	if !p.tryStartBatch(w, "全账号封禁检测") {
		return
	}
	defer p.finishBatch()
	accounts := p.cfg.Pool.List()
	results := make([]restrictionProbeResult, len(accounts))
	sem := make(chan struct{}, restrictionProbeConcurrency)
	var wg sync.WaitGroup
	for i, account := range accounts {
		wg.Add(1)
		go func(i int, account pool.Status) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-r.Context().Done():
				results[i] = restrictionProbeResult{UID: account.UID, Verdict: "inconclusive", CheckedAt: time.Now().Format(time.RFC3339)}
				return
			}
			defer func() { <-sem }()
			lock := p.modelProbeLock(account.UID)
			if !lock.TryLock() {
				results[i] = restrictionProbeResult{UID: account.UID, Nickname: account.Nickname, Realm: account.Realm, Verdict: "test_in_progress", CheckedAt: time.Now().Format(time.RFC3339)}
				return
			}
			defer lock.Unlock()
			results[i] = p.probeRestriction(account.UID, "bulk_probe")
		}(i, account)
	}
	wg.Wait()
	counts := map[string]int{}
	for _, result := range results {
		counts[result.Verdict]++
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "results": results, "counts": counts})
}

func (p *Panel) deleteRestrictedAccounts(w http.ResponseWriter, r *http.Request) {
	if !p.tryStartBatch(w, "删除已确认封号账号") {
		return
	}
	defer p.finishBatch()
	var req struct {
		UIDs []string `json:"uids"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.UIDs) == 0 || len(req.UIDs) > 200 {
		writeErr(w, http.StatusBadRequest, "uids must contain 1 to 200 accounts")
		return
	}
	baseDir := p.cfg.QuarantineDir
	if baseDir == "" {
		baseDir = filepath.Join(filepath.Dir(p.cfg.AuthDir), "data", "quarantine")
	}
	quarantineDir := filepath.Join(baseDir, time.Now().Format("20060102T150405.000000000"))
	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		writeErr(w, http.StatusInternalServerError, "cannot create quarantine directory")
		return
	}
	_ = os.Chmod(quarantineDir, 0o700)
	deleted := make([]string, 0, len(req.UIDs))
	skipped := make([]map[string]string, 0)
	seen := map[string]bool{}
	for _, uid := range req.UIDs {
		uid = strings.TrimSpace(uid)
		if uid == "" || seen[uid] {
			continue
		}
		seen[uid] = true
		lock := p.modelProbeLock(uid)
		if !lock.TryLock() {
			skipped = append(skipped, map[string]string{"uid": uid, "reason": "test_in_progress"})
			continue
		}
		probe := p.probeRestriction(uid, "delete_recheck")
		if !probe.Restricted {
			lock.Unlock()
			skipped = append(skipped, map[string]string{"uid": uid, "reason": probe.Verdict})
			continue
		}
		err := p.quarantineRestrictedAccount(uid, quarantineDir)
		lock.Unlock()
		if err != nil {
			skipped = append(skipped, map[string]string{"uid": uid, "reason": "remove_failed"})
			continue
		}
		deleted = append(deleted, uid)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "deleted": deleted, "skipped": skipped, "quarantine_dir": filepath.Base(quarantineDir)})
}

func (p *Panel) quarantineRestrictedAccount(uid, quarantineDir string) error {
	if err := os.MkdirAll(quarantineDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(quarantineDir, 0o700); err != nil {
		return err
	}
	p.proxyAccountMu.Lock()
	defer p.proxyAccountMu.Unlock()
	p.reloadMu.Lock()
	defer p.reloadMu.Unlock()
	a := p.cfg.Pool.AuthByUID(uid)
	if a == nil || a.FilePath == "" || p.cfg.Pool.InFlight(uid) > 0 {
		return errors.New("account missing, file unavailable, or in flight")
	}
	root, err := filepath.Abs(p.cfg.AuthDir)
	if err != nil {
		return err
	}
	file, err := filepath.Abs(a.FilePath)
	if err != nil || filepath.Dir(file) != root {
		return errors.New("auth path outside auth directory")
	}
	paths := []string{file, file + ".bak"}
	moved := make([][2]string, 0, len(paths))
	for _, src := range paths {
		if _, err := os.Stat(src); os.IsNotExist(err) {
			if src == file {
				return err
			}
			continue
		} else if err != nil {
			return err
		}
		dst := filepath.Join(quarantineDir, filepath.Base(src))
		if err := moveCredential(src, dst); err != nil {
			for i := len(moved) - 1; i >= 0; i-- {
				_ = moveCredential(moved[i][1], moved[i][0])
			}
			return err
		}
		moved = append(moved, [2]string{src, dst})
	}
	if p.cfg.ProxyPool != nil {
		if err := p.cfg.ProxyPool.Unbind(uid); err != nil {
			for i := len(moved) - 1; i >= 0; i-- {
				_ = moveCredential(moved[i][1], moved[i][0])
			}
			return err
		}
	}
	if p.cfg.Pool.Remove(uid) == nil {
		for i := len(moved) - 1; i >= 0; i-- {
			_ = moveCredential(moved[i][1], moved[i][0])
		}
		return errors.New("account disappeared during removal")
	}
	return nil
}

func moveCredential(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return err
	}
	if err := os.Remove(src); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
}

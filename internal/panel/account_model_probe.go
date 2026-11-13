package panel

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/misakano7545/workbuddy2api-panel/internal/pool"
	"github.com/misakano7545/workbuddy2api-panel/internal/upstream"
)

const accountModelTestTimeout = 45 * time.Second

func (p *Panel) accountModels(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	a := p.cfg.Pool.AuthByUID(uid)
	if a == nil {
		writeErr(w, http.StatusNotFound, "account not found")
		return
	}
	if p.cfg.Upstream == nil {
		writeErr(w, http.StatusNotImplemented, "upstream client not configured")
		return
	}
	models, err := p.cfg.Upstream.FetchModels(a)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "catalog_error"})
		return
	}
	out := make([]map[string]string, 0, len(models))
	for _, model := range models {
		out = append(out, map[string]string{"id": model.ID, "name": model.Name})
	}
	for _, model := range p.cfg.Upstream.GenerationModels(a.Realm()) {
		out = append(out, map[string]string{"id": model.ID, "name": model.Name, "kind": model.GenerationKind})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "uid": uid, "realm": a.Realm(), "models": out})
}

func (p *Panel) accountModelTest(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")
	a := p.cfg.Pool.AuthByUID(uid)
	if a == nil {
		writeErr(w, http.StatusNotFound, "account not found")
		return
	}
	p.modelProbeMu.Lock()
	if p.modelProbeLocks == nil {
		p.modelProbeLocks = map[string]*sync.Mutex{}
	}
	lock := p.modelProbeLocks[uid]
	if lock == nil {
		lock = &sync.Mutex{}
		p.modelProbeLocks[uid] = lock
	}
	p.modelProbeMu.Unlock()
	if !lock.TryLock() {
		writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "verdict": "test_in_progress"})
		return
	}
	defer lock.Unlock()
	if p.cfg.Upstream == nil {
		writeErr(w, http.StatusNotImplemented, "upstream client not configured")
		return
	}
	var req struct {
		Model string `json:"model"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "model is required")
		return
	}
	model := strings.TrimSpace(req.Model)
	if strings.HasPrefix(model, "cn:") || strings.HasPrefix(model, "global:") {
		prefix, bare, _ := strings.Cut(model, ":")
		if prefix != a.Realm() {
			writeErr(w, http.StatusBadRequest, "model realm does not match account realm")
			return
		}
		model = bare
	}
	if model == "" || len(model) > 160 || strings.ContainsAny(model, " \t\r\n") {
		writeErr(w, http.StatusBadRequest, "invalid model")
		return
	}

	// Resolve the model against this account's own catalog before sending a billable request.
	catalog, err := p.cfg.Upstream.FetchModels(a)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "verdict": "catalog_error"})
		return
	}
	listed := false
	for _, item := range catalog {
		if item.ID == model {
			listed = true
			break
		}
	}
	for _, item := range p.cfg.Upstream.GenerationModels(a.Realm()) {
		if item.ID == model {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"ok": false, "verdict": "not_chat_model"})
			return
		}
	}
	if !listed {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"ok": false, "verdict": "model_not_listed"})
		return
	}

	started := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), accountModelTestTimeout)
	defer cancel()
	body, _ := json.Marshal(map[string]any{
		"model":      model,
		"messages":   []map[string]string{{"role": "user", "content": "Reply with OK."}},
		"stream":     true,
		"max_tokens": 8,
	})
	rc, status, _, err := p.cfg.Upstream.ChatStreamContext(ctx, a, body, "", upstream.ChatMeta{AgentType: upstream.AgentTypeAuxiliary}, nil)
	result := map[string]any{
		"ok": false, "uid": uid, "model": model, "realm": a.Realm(),
		"tested_at": time.Now().Format(time.RFC3339), "elapsed_ms": time.Since(started).Milliseconds(),
	}
	respond := func(statusCode int) {
		remain, total, expiring, earliestAt, earliestRemaining, buckets, refreshErr := p.cfg.Upstream.UserResourceSnapshot(a, p.expiringSoonWindow())
		result["balance_refreshed"] = refreshErr == nil
		if refreshErr == nil {
			p.cfg.Pool.SetCreditsSnapshot(uid, pool.CreditsSnapshot{
				Remain: remain, Total: total, Expiring: expiring,
				EarliestAt: earliestAt, EarliestRemaining: earliestRemaining,
				ExpiryBuckets: poolExpiryBuckets(buckets),
			})
		}
		writeJSON(w, statusCode, result)
	}
	if err != nil {
		var ue *upstream.Error
		if errors.As(err, &ue) {
			result["verdict"] = ue.Kind.String()
			result["http_status"] = ue.Status
		} else {
			result["verdict"] = "transport_error"
		}
		respond(http.StatusOK)
		return
	}
	if rc == nil || status < 200 || status >= 300 {
		result["verdict"] = "empty_response"
		result["http_status"] = status
		respond(http.StatusOK)
		return
	}
	defer rc.Close()
	ok, verdict := inspectModelTestStream(rc)
	result["ok"] = ok
	result["verdict"] = verdict
	result["elapsed_ms"] = time.Since(started).Milliseconds()
	respond(http.StatusOK)
}

func inspectModelTestStream(rc io.Reader) (bool, string) {
	const maxBytes = 64 << 10
	raw, err := io.ReadAll(io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return false, "stream_error"
	}
	if len(raw) > maxBytes {
		return false, "response_too_large"
	}
	scanner := bufio.NewScanner(strings.NewReader(string(raw)))
	scanner.Buffer(make([]byte, 1024), maxBytes)
	content, done := false, false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "event:") && strings.TrimSpace(strings.TrimPrefix(line, "event:")) == "error" {
			return false, "upstream_stream_error"
		}
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		data = strings.TrimSpace(data)
		if data == "[DONE]" {
			done = true
			continue
		}
		var frame struct {
			Error   json.RawMessage `json:"error"`
			Choices []struct {
				Delta struct {
					Content          string `json:"content"`
					Reasoning        string `json:"reasoning"`
					ReasoningContent string `json:"reasoning_content"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
		}
		if json.Unmarshal([]byte(data), &frame) != nil {
			continue
		}
		if len(frame.Error) > 0 && string(frame.Error) != "null" {
			return false, "upstream_stream_error"
		}
		for _, choice := range frame.Choices {
			if strings.TrimSpace(choice.Delta.Content) != "" ||
				strings.TrimSpace(choice.Delta.Reasoning) != "" ||
				strings.TrimSpace(choice.Delta.ReasoningContent) != "" ||
				(choice.FinishReason != nil && *choice.FinishReason != "") {
				content = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return false, "stream_error"
	}
	if !content {
		if !done {
			return false, "stream_incomplete"
		}
		return false, "empty_response"
	}
	return true, "success"
}

package panel

import (
	"strings"
	"testing"
)

func TestInspectModelTestStream(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		ok   bool
		want string
	}{
		{"content without done is reachable", `data: {"choices":[{"delta":{"content":"OK"}}]}` + "\n\n", true, "success"},
		{"reasoning only is reachable", `data: {"choices":[{"delta":{"reasoning_content":"thinking"}}]}` + "\n\n", true, "success"},
		{"finish reason is reachable", `data: {"choices":[{"delta":{},"finish_reason":"length"}]}` + "\n\n", true, "success"},
		{"empty done", "data: [DONE]\n\n", false, "empty_response"},
		{"incomplete empty stream", "", false, "stream_incomplete"},
		{"event error", "event: error\ndata: {\"message\":\"denied\"}\n\n", false, "upstream_stream_error"},
		{"oversized", strings.Repeat("x", (64<<10)+1), false, "response_too_large"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, got := inspectModelTestStream(strings.NewReader(tt.raw))
			if ok != tt.ok || got != tt.want {
				t.Fatalf("inspectModelTestStream() = (%v, %q), want (%v, %q)", ok, got, tt.ok, tt.want)
			}
		})
	}
}

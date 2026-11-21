package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
)

// NewLogger returns a logger for stderr that writes compiler-style lines:
//
//	rpt: path:line: message
//	rpt: path: warning: message key=value
//
// The "path" and "line" attributes locate the message; other attributes
// follow it as key=value. There are no timestamps, and debug is dropped.
func NewLogger(w io.Writer) *slog.Logger {
	return slog.New(&lineHandler{w: w, mu: &sync.Mutex{}})
}

type lineHandler struct {
	w     io.Writer
	mu    *sync.Mutex
	attrs []slog.Attr
}

func (h *lineHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelInfo }

func (h *lineHandler) Handle(_ context.Context, r slog.Record) error {
	var path, line string
	var rest []string
	add := func(a slog.Attr) bool {
		switch a.Key {
		case "path":
			path = a.Value.String()
		case "line":
			if v := a.Value.String(); v != "0" {
				line = v
			}
		default:
			rest = append(rest, a.Key+"="+a.Value.String())
		}
		return true
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(add)

	var b strings.Builder
	b.WriteString("rpt: ")
	if path != "" {
		b.WriteString(path)
		if line != "" {
			b.WriteString(":" + line)
		}
		b.WriteString(": ")
	}
	if r.Level >= slog.LevelWarn && r.Level < slog.LevelError {
		b.WriteString("warning: ")
	}
	b.WriteString(r.Message)
	for _, kv := range rest {
		b.WriteString(" " + kv)
	}
	text := Clean(b.String())
	b.Reset()
	b.WriteString(text)
	b.WriteString("\n")

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.w, b.String())
	if err != nil {
		return fmt.Errorf("write log: %w", err)
	}
	return nil
}

func (h *lineHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &lineHandler{w: h.w, mu: h.mu, attrs: append(h.attrs[:len(h.attrs):len(h.attrs)], as...)}
}

// WithGroup is not used by rpt; groups are flattened.
func (h *lineHandler) WithGroup(string) slog.Handler { return h }

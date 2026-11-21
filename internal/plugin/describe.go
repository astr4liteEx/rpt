package plugin

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/astr4liteEx/rpt/sdk"
)

// An Answer is what a plugin said to --describe, or why it said nothing.
type Answer struct {
	Desc sdk.Description
	Err  error
}

// A Describer asks plugins to describe themselves, remembering answers
// in CacheFile (when set) until the plugin's file changes.
type Describer struct {
	Env       []string
	Timeout   time.Duration
	CacheFile string
}

// cached is one remembered answer, for the plugin file as it was.
type cached struct {
	ModTime int64           `json:"mod_time"`
	Size    int64           `json:"size"`
	Desc    sdk.Description `json:"desc"`
}

// Describe asks each plugin, in parallel, keyed by name.
func (d *Describer) Describe(ps []Plugin) map[string]Answer {
	cache := d.load()
	out := make(map[string]Answer, len(ps))
	type job struct {
		p    Plugin
		info os.FileInfo
	}
	var todo []job
	for _, p := range ps {
		info, err := os.Stat(p.Path)
		if err != nil {
			out[p.Name] = Answer{Err: err}
			continue
		}
		if c, ok := cache[p.Path]; ok && c.ModTime == info.ModTime().UnixNano() && c.Size == info.Size() {
			out[p.Name] = Answer{Desc: c.Desc}
			continue
		}
		todo = append(todo, job{p, info})
	}
	answers := make([]Answer, len(todo)) // each goroutine writes its own
	var wg sync.WaitGroup
	for i, j := range todo {
		wg.Go(func() {
			desc, err := d.ask(j.p.Path)
			answers[i] = Answer{desc, err}
		})
	}
	wg.Wait()
	changed := false
	for i, j := range todo {
		out[j.p.Name] = answers[i]
		if answers[i].Err == nil {
			cache[j.p.Path] = cached{j.info.ModTime().UnixNano(), j.info.Size(), answers[i].Desc}
			changed = true
		}
	}
	if changed {
		d.save(cache)
	}
	return out
}

// ask runs one plugin's --describe. WaitDelay stops a child that keeps
// stdout open from holding rpt past the deadline.
func (d *Describer) ask(bin string) (sdk.Description, error) {
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "--describe")
	cmd.Env = d.Env
	cmd.WaitDelay = 100 * time.Millisecond
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return sdk.Description{}, fmt.Errorf("--describe timed out after %v", timeout)
	}
	if err != nil {
		return sdk.Description{}, fmt.Errorf("--describe failed: %w", err)
	}
	line, _, _ := bytes.Cut(out, []byte("\n"))
	var desc sdk.Description
	if err := json.Unmarshal(line, &desc); err != nil {
		return sdk.Description{}, fmt.Errorf("--describe did not print a JSON object: %w", err)
	}
	return desc, nil
}

func (d *Describer) load() map[string]cached {
	cache := map[string]cached{}
	if d.CacheFile == "" {
		return cache
	}
	if b, err := os.ReadFile(d.CacheFile); err == nil {
		json.Unmarshal(b, &cache) // a damaged cache is an empty one
	}
	return cache
}

// save writes the cache atomically; a failure only costs the next run
// some time.
func (d *Describer) save(cache map[string]cached) {
	if d.CacheFile == "" {
		return
	}
	b, err := json.Marshal(cache)
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(d.CacheFile), 0o755)
	tmp, err := os.CreateTemp(filepath.Dir(d.CacheFile), ".describe-*")
	if err != nil {
		return
	}
	_, err = tmp.Write(b)
	tmp.Close()
	if err != nil || os.Rename(tmp.Name(), d.CacheFile) != nil {
		os.Remove(tmp.Name())
	}
}

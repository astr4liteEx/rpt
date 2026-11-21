package report

import (
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/astr4liteEx/rpt/sdk"
)

// configWrite runs do as one committed write on a fresh copy whose rpt.yaml
// is yaml.
func configWrite(t *testing.T, yaml string, do func(*Tx) (ConfigChange, error)) (ConfigChange, string, error) {
	t.Helper()
	r, dir := openCopy(t)
	if yaml != "" {
		if err := os.WriteFile(filepath.Join(dir, ConfigFile), []byte(yaml), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tx := r.Begin()
	ch, err := do(tx)
	if err == nil {
		err = tx.Commit(false)
	}
	return ch, dir, err
}

func TestConfigRecord(t *testing.T) {
	r, dir := openCopy(t)
	yaml := "format: 2\nrules: {targets: warning}\nx-burp: {key: abc, n: 1}\nname: Acme\n"
	if err := os.WriteFile(filepath.Join(dir, ConfigFile), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := r.ConfigRecord(true)
	if err != nil {
		t.Fatal(err)
	}
	if c.Kind != "config" || c.Format != 2 || len(c.Severities) != 5 || c.Sections["poc"] != "Proof of concept" ||
		c.Rules["targets"] != sdk.Warning || string(c.Extra["x-burp"]) != `{"key":"abc","n":1}` || c.Extra["name"] != nil ||
		c.Rev != Rev([]byte(yaml)) || c.Lines.Keys["x-burp"] != (sdk.Position{Line: 3, Column: 1}) {
		t.Errorf("%+v", c)
	}
}

func TestSeverityRename(t *testing.T) {
	ch, dir, err := configWrite(t, "", func(tx *Tx) (ConfigChange, error) {
		return tx.SetConfig("severities", []string{"[critical, high, medium, low, informational]"}, []Rename{{"info", "informational"}}, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := file(t, dir, ConfigFile); !strings.Contains(got, "severities: [critical, high, medium, low, informational]\n") {
		t.Errorf("rpt.yaml:\n%s", got)
	}
	if !slices.Contains(ch.Config.Severities, "informational") {
		t.Errorf("record: %+v", ch.Config)
	}
	// Merging levels is allowed.
	ch, dir, err = configWrite(t, "", func(tx *Tx) (ConfigChange, error) {
		return tx.SetConfig("severities", []string{"critical", "medium", "low", "info"}, []Rename{{"high", "critical"}}, false)
	})
	if err != nil || len(ch.Findings) != 1 || ch.Findings[0].Severity != "critical" {
		t.Fatalf("%+v, %v", ch.Findings, err)
	}
	if got := file(t, dir, "findings/sqli-login.md"); !strings.Contains(got, "severity: critical\n") {
		t.Errorf("sqli-login.md:\n%s", got)
	}
}

func TestSeverityDroppedInUse(t *testing.T) {
	_, dir, err := configWrite(t, "", func(tx *Tx) (ConfigChange, error) {
		return tx.SetConfig("severities", []string{"critical", "medium", "low", "info"}, nil, false)
	})
	if !errors.Is(err, ErrInUse) || !strings.Contains(err.Error(), "F-003 (high)") {
		t.Errorf("err = %v", err)
	}
	if got := file(t, dir, ConfigFile); strings.Contains(got, "critical, medium") {
		t.Error("written")
	}
	if _, _, err := configWrite(t, "", func(tx *Tx) (ConfigChange, error) {
		return tx.SetConfig("severities", []string{"critical", "medium", "low", "info"}, nil, true)
	}); err != nil {
		t.Errorf("--force: %v", err)
	}
}

func TestBadRenames(t *testing.T) {
	for _, rn := range []Rename{{"urgent", "critical"}, {"info", "nope"}, {"info", "low"}} {
		_, _, err := configWrite(t, "", func(tx *Tx) (ConfigChange, error) {
			next := []string{"critical", "high", "medium", "low"}
			if rn.Old == "info" && rn.New == "low" {
				next = append(next, "info") // old still in the new list
			}
			return tx.SetConfig("severities", next, []Rename{rn}, false)
		})
		if _, ok := errors.AsType[*RenameError](err); !ok {
			t.Errorf("%v: err = %v, want a RenameError", rn, err)
		}
	}
}

func TestFixedHeadingRenameCarriesThrough(t *testing.T) {
	ch, dir, err := configWrite(t, "", func(tx *Tx) (ConfigChange, error) {
		return tx.SetConfig("sections.poc", []string{"PoC"}, nil, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ch.Findings) != 3 || ch.Findings[0].Sections["poc"] == "" {
		t.Errorf("findings %+v", ch.Findings)
	}
	if got := file(t, dir, "findings/sqli-login.md"); !strings.Contains(got, "\n## PoC\n") || strings.Contains(got, "Proof of concept") {
		t.Errorf("sqli-login.md:\n%s", got)
	}
	if got := file(t, dir, ConfigFile); !strings.Contains(got, "sections: {poc: PoC}\n") {
		t.Errorf("rpt.yaml:\n%s", got)
	}
	r, _ := Open(dir)
	defer r.Close()
	if ps, _ := r.Validate(); len(ps) != 1 { // only tls-weak's S-99
		t.Errorf("problems after the rename: %+v", ps)
	}
}

func TestCustomSectionRename(t *testing.T) {
	r, dir := openCopy(t)
	yaml := "format: 2\nrequired_sections: [description, remediation, poc, References]\n"
	if err := os.WriteFile(filepath.Join(dir, ConfigFile), []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	tx := r.Begin()
	ch, err := tx.SetConfig("required_sections", []string{"description", "remediation", "poc", "Further reading"}, []Rename{{"References", "Further reading"}}, false)
	if err != nil || tx.Commit(false) != nil {
		t.Fatal(err)
	}
	if len(ch.Findings) != 1 || !strings.Contains(file(t, dir, "findings/xss-search.md"), "## Further reading\r\n") {
		t.Errorf("findings %+v\n%s", ch.Findings, file(t, dir, "findings/xss-search.md"))
	}
}

func TestConfigSetForm(t *testing.T) {
	for p, v := range map[string]string{
		"format": "two", "severities": "[[a]]", "rules": "{targets: loud}", "sections": "{impact: Impact}",
		"name": "Acme", "rev": "x", "sections.impact": "Impact",
	} {
		r, dir := openCopy(t)
		before := snapshot(t, dir)
		if _, err := r.Begin().SetConfig(p, []string{v}, nil, false); !errors.Is(err, ErrBadValue) {
			t.Errorf("%s %s: err = %v", p, v, err)
		}
		if !maps.Equal(before, snapshot(t, dir)) {
			t.Errorf("%s: changed", p)
		}
	}
}

func TestPluginSettings(t *testing.T) {
	_, dir, err := configWrite(t, "", func(tx *Tx) (ConfigChange, error) {
		if _, err := tx.SetConfig("x-burp.key", []string{"abc"}, nil, false); err != nil {
			return ConfigChange{}, err
		}
		return tx.SetConfig("x-burp.hosts", []string{"[a, b]"}, nil, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := file(t, dir, ConfigFile); !strings.HasSuffix(got, "x-burp: {key: abc, hosts: [a, b]}\n") {
		t.Errorf("rpt.yaml:\n%s", got)
	}
	r, _ := Open(dir)
	defer r.Close()
	if ps, _ := r.Validate(); slices.ContainsFunc(ps, func(p sdk.Problem) bool { return p.Rule == RuleConfigUnknownKey }) {
		t.Errorf("x- key warned: %+v", ps)
	}
}

func TestRuleLevels(t *testing.T) {
	r, dir := openCopy(t)
	if err := os.WriteFile(filepath.Join(dir, ConfigFile), []byte("format: 2\nrules: {scopeIDsExist: warning}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ps, err := r.Validate()
	if err != nil || len(ps) != 1 || ps[0].Rule != RuleScopeIDsExist || ps[0].Level != sdk.Warning {
		t.Errorf("%+v, %v", ps, err)
	}
}

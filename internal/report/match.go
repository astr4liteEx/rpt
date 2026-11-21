package report

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// IsRange reports whether a scope host is a range, a CIDR or *.domain,
// rather than one asset.
func IsRange(host string) bool {
	_, err := netip.ParsePrefix(host)
	return err == nil || strings.HasPrefix(host, "*.")
}

// inRange reports whether host, an address, a CIDR or a name, lies in
// the range rng.
func inRange(rng, host string) bool {
	if p, err := netip.ParsePrefix(rng); err == nil {
		if a, err := netip.ParseAddr(host); err == nil {
			return p.Contains(a.Unmap())
		}
		if q, err := netip.ParsePrefix(host); err == nil {
			return q.Bits() >= p.Bits() && p.Contains(q.Addr())
		}
		return false
	}
	domain, ok := strings.CutPrefix(strings.ToLower(rng), "*.")
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	return ok && strings.HasSuffix(h, "."+domain)
}

// sameAsset reports whether a target's host names a one-asset row's host.
func sameAsset(row, host string) bool {
	a, errA := netip.ParseAddr(row)
	b, errB := netip.ParseAddr(host)
	if errA == nil && errB == nil {
		return a.Unmap() == b.Unmap()
	}
	return strings.EqualFold(strings.TrimSuffix(row, "."), strings.TrimSuffix(host, "."))
}

// Fits says why target t doesn't fit row r, or nil. A host belongs only
// on a range row and must lie in it; a port or protocol, when both give
// one, must agree.
func Fits(r *Row, t Target) error {
	if t.Host != "" {
		if !IsRange(r.Host) {
			return fmt.Errorf("%s is one asset (%s), so a target on it takes no host", r.ID, r.Host)
		}
		if !inRange(r.Host, t.Host) {
			return fmt.Errorf("%s is not in %s (%s)", t.Host, r.ID, r.Host)
		}
	}
	if r.Port != 0 && t.Port != 0 && r.Port != t.Port {
		return fmt.Errorf("port %d is not %s's port %d", t.Port, r.ID, r.Port)
	}
	if r.Protocol != "" && t.Protocol != "" && r.Protocol != t.Protocol {
		return fmt.Errorf("protocol %s is not %s's protocol %s", t.Protocol, r.ID, r.Protocol)
	}
	return nil
}

// covers reports whether row r covers a target found on t.Host.
func covers(r *Row, t Target) bool {
	if IsRange(r.Host) {
		if !inRange(r.Host, t.Host) {
			return false
		}
	} else if !sameAsset(r.Host, t.Host) {
		return false
	}
	return Fits(r, Target{Port: t.Port, Protocol: t.Protocol}) == nil
}

// Attribute finds the scope row for a target a parser found on t.Host:
// the most specific row covering it. It returns the target attributed,
// its host dropped when the row is one asset, and false when no row
// covers it.
func (s *Scope) Attribute(t Target) (Target, *Row, bool) {
	var best *Row
	for _, r := range s.Rows {
		if covers(r, t) && (best == nil || moreSpecific(r, best)) {
			best = r
		}
	}
	if best == nil {
		return t, nil, false
	}
	t.Scope = best.ID
	if !IsRange(best.Host) {
		t.Host = ""
	}
	return t, best, true
}

// moreSpecific orders rows that cover the same target: one asset before a
// range, a narrower CIDR before a wider, any CIDR before a *.domain, a
// longer *.domain before a shorter, then a row with a port, then one with
// a protocol, then the lower ID.
func moreSpecific(a, b *Row) bool {
	rank := func(r *Row) (int, int) {
		if !IsRange(r.Host) {
			return 0, 0
		}
		if p, err := netip.ParsePrefix(r.Host); err == nil {
			return 1, -p.Bits()
		}
		return 2, -len(r.Host)
	}
	ka, sa := rank(a)
	kb, sb := rank(b)
	c := cmp.Or(
		cmp.Compare(ka, kb), cmp.Compare(sa, sb),
		-cmp.Compare(boolInt(a.Port != 0), boolInt(b.Port != 0)),
		-cmp.Compare(boolInt(a.Protocol != ""), boolInt(b.Protocol != "")),
		CompareIDs(a.ID, b.ID),
	)
	return c < 0
}

// Citing lists the findings with a target on the scope row id, in file
// order.
func (m *Model) Citing(id string) []*Doc {
	var out []*Doc
	for _, d := range m.docs[FindingKind] {
		if d.Err == nil && slices.ContainsFunc(d.Targets, func(t Target) bool { return strings.EqualFold(t.Scope, id) }) {
			out = append(out, d)
		}
	}
	return out
}

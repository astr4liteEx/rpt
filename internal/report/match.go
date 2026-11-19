package report

import (
	"cmp"
	"fmt"
	"net/netip"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// Attribute finds the scope row a parser's target falls in and returns the
// target attributed to it: Scope set to the row's ID, and Host dropped
// when the row is one asset, since the row already says which. A row
// covers a target when its host matches (exactly, ignoring case for
// names; by containment for a CIDR range; any subdomain for *.domain), its
// port is absent or equal, and its protocol is absent, equal, or the
// target's is absent. Names are never resolved.
//
// When several rows cover the target, the most specific wins: a single
// asset before a CIDR range, a narrower range before a wider one, any CIDR
// before a *.domain, a longer *.domain before a shorter one; then a row
// with a port before one without, a row with a protocol before one
// without, and finally the lower ID. A target that already names a scope
// row is returned unchanged. ok is false when no row covers the target.
func Attribute(t sdk.Target, rows []sdk.ScopeRow) (sdk.Target, bool) {
	if t.Scope != "" {
		return t, true
	}
	if t.Host == "" {
		return t, false
	}
	var best *sdk.ScopeRow
	for i := range rows {
		row := &rows[i]
		if !hostMatches(row.Host, t.Host) ||
			row.Port != 0 && row.Port != t.Port ||
			row.Protocol != "" && t.Protocol != "" && row.Protocol != t.Protocol {
			continue
		}
		if best == nil || moreSpecific(*row, *best) {
			best = row
		}
	}
	if best == nil {
		return t, false
	}
	t.Scope = best.ID
	if !IsRange(best.Host) {
		t.Host = ""
	}
	return t, true
}

// IsRange reports whether a scope row's host covers more than one asset:
// a CIDR range or a *.domain wildcard. Anything else (an address, a name,
// any other text) is one asset.
func IsRange(host string) bool {
	if _, err := netip.ParsePrefix(host); err == nil {
		return true
	}
	return strings.HasPrefix(host, "*.")
}

// moreSpecific reports whether row a is a narrower match than row b, by
// the order Attribute documents.
func moreSpecific(a, b sdk.ScopeRow) bool {
	ra, wa := hostRank(a.Host)
	rb, wb := hostRank(b.Host)
	c := cmp.Or(
		cmp.Compare(ra, rb),
		cmp.Compare(wb, wa), // the larger width is narrower
		cmp.Compare(unset(a.Port == 0), unset(b.Port == 0)),
		cmp.Compare(unset(a.Protocol == ""), unset(b.Protocol == "")),
		cmp.Compare(a.ID, b.ID),
	)
	return c < 0
}

// unset orders a set member before an unset one.
func unset(b bool) int {
	if b {
		return 1
	}
	return 0
}

// hostRank orders host kinds from narrowest: 0 one asset, 1 a CIDR range,
// 2 a *.domain. width orders hosts of one kind: the prefix length of a
// CIDR, the length of a wildcard's domain.
func hostRank(host string) (rank, width int) {
	if p, err := netip.ParsePrefix(host); err == nil {
		return 1, p.Bits()
	}
	if d, ok := strings.CutPrefix(host, "*."); ok {
		return 2, len(d)
	}
	return 0, 0
}

// TargetFits checks that a target attributed to row says nothing the row
// contradicts: a host only inside a range row, and the row's port and
// protocol if it has them.
func TargetFits(t sdk.Target, row sdk.ScopeRow) error {
	switch {
	case t.Host != "" && !IsRange(row.Host):
		return fmt.Errorf("%s is one asset (%s), so a target on it takes no host; drop host %q", row.ID, row.Host, t.Host)
	case t.Host != "" && !hostMatches(row.Host, t.Host):
		return fmt.Errorf("host %s is not inside %s (%s)", t.Host, row.ID, row.Host)
	case row.Port != 0 && t.Port != 0 && t.Port != row.Port:
		return fmt.Errorf("port %d is not %s's port %d", t.Port, row.ID, row.Port)
	case row.Protocol != "" && t.Protocol != "" && t.Protocol != row.Protocol:
		return fmt.Errorf("protocol %s is not %s's protocol %s", t.Protocol, row.ID, row.Protocol)
	}
	return nil
}

func hostMatches(pattern, host string) bool {
	if prefix, err := netip.ParsePrefix(pattern); err == nil {
		addr, err := netip.ParseAddr(host)
		return err == nil && prefix.Contains(addr.Unmap())
	}
	if want, err := netip.ParseAddr(pattern); err == nil {
		addr, err := netip.ParseAddr(host)
		return err == nil && want.Unmap() == addr.Unmap()
	}
	pattern, host = strings.ToLower(pattern), strings.ToLower(host)
	if domain, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+domain)
	}
	return pattern == host
}

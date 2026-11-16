package report

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/astr4liteEx/rpt/sdk"
)

// MatchScope returns the IDs of every scope row that covers target, sorted.
// A row covers a target when its host matches (exactly, ignoring case for
// names; by containment for a CIDR range; any subdomain for *.domain), its
// port is absent or equal, and its protocol is absent, equal, or the
// target's is absent. Names are never resolved.
func MatchScope(target sdk.Target, rows []sdk.ScopeRow) []string {
	if target.Host == "" {
		return nil
	}
	var ids []string
	for _, row := range rows {
		if hostMatches(row.Host, target.Host) &&
			(row.Port == 0 || row.Port == target.Port) &&
			(row.Protocol == "" || target.Protocol == "" || row.Protocol == target.Protocol) {
			ids = append(ids, row.ID)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
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

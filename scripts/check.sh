#!/usr/bin/env bash
# check.sh runs every check CI runs: vet, staticcheck, race tests,
# govulncheck, and a smoke test of the static release binary. CI calls
# only this script, so running it locally is running CI.
set -euo pipefail
cd "$(dirname "$0")/.."

# The tools are pinned in the separate tools module; go tool -n builds
# each one (cached) and prints its path. The tools module is not in the
# workspace, so the lookups run with GOWORK=off.
staticcheck=$(GOWORK=off go -C tools tool -n staticcheck)
govulncheck=$(GOWORK=off go -C tools tool -n govulncheck)

# rpt and the SDK are two modules in one workspace (go.work); check both.
pkgs=(./... ./sdk/...)
echo "== go vet"
go vet "${pkgs[@]}"
echo "== staticcheck"
"$staticcheck" "${pkgs[@]}"
echo "== go test -race"
go test -race "${pkgs[@]}"
echo "== the SDK on its own, as plugins get it"
(cd sdk && GOWORK=off go vet ./... && GOWORK=off go test ./...)
echo "== govulncheck"
"$govulncheck" "${pkgs[@]}"

echo "== smoke test of the static binary"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=smoke" -o "$tmp/rpt" ./cmd/rpt

got=$("$tmp/rpt" version --json)
want='{"kind":"version","version":"smoke","schema_version":3,"format":2}'
if [ "$got" != "$want" ]; then
	echo "rpt version --json: got $got, want $want" >&2
	exit 1
fi

# The fixture has one planted problem: a finding citing scope ID S-99.
code=0
got=$("$tmp/rpt" validate --report testdata/fixture) || code=$?
got=$(printf '%s\n' "$got" | sed 's/,"rev":"[0-9a-f]*"//') # the file's rev changes with its bytes
want='{"kind":"problem","path":"findings/tls-weak.md","line":5,"rule":"scopeIDsExist","level":"error","message":"S-99 is not in scope.csv","command":"validate"}'
if [ "$code" != 1 ] || [ "$got" != "$want" ]; then
	echo "rpt validate on the fixture: exit $code, output $got; want exit 1 and only the planted S-99 problem" >&2
	exit 1
fi
echo "all checks passed"

#!/usr/bin/env bash
# install.sh builds rpt from the working tree and installs it to a local bin
# directory: $1 if given, else $PREFIX/bin, else ~/.local/bin. The version is
# `git describe` output, marked -dirty when the tree has uncommitted changes.
set -euo pipefail
cd "$(dirname "$0")/.."

bindir=${1:-${PREFIX:-$HOME/.local}/bin}
version=$(git describe --tags --always --dirty --match 'v*' 2>/dev/null || echo dev)

mkdir -p "$bindir"
CGO_ENABLED=0 go build -trimpath \
	-ldflags "-s -w -X main.version=$version" -o "$bindir/rpt" ./cmd/rpt

echo "installed rpt $version to $bindir/rpt"
case ":$PATH:" in
*":$bindir:"*) ;;
*) echo "note: $bindir is not on your PATH" >&2 ;;
esac

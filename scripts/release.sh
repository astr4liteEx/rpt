#!/usr/bin/env bash
# release.sh builds the release archives for the tag at HEAD:
# dist/rpt_<tag>_linux_<arch>.tar.gz, each holding the static rpt binary,
# and dist/SHA256SUMS. It refuses to run on a dirty tree or off a v* tag.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -n "$(git status --porcelain)" ]; then
	echo "release.sh: the working tree has changes; commit or stash them first" >&2
	exit 1
fi
tag=$(git describe --tags --exact-match --match 'v*' HEAD 2>/dev/null) || {
	echo "release.sh: HEAD is not on a v* tag" >&2
	exit 1
}

rm -rf dist
mkdir -p dist
for arch in amd64 arm64; do
	dir=$(mktemp -d)
	CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath \
		-ldflags "-s -w -X main.version=$tag" -o "$dir/rpt" ./cmd/rpt
	tar -C "$dir" --owner=0 --group=0 --numeric-owner -czf "dist/rpt_${tag}_linux_${arch}.tar.gz" rpt
	rm -rf "$dir"
done
(cd dist && sha256sum ./*.tar.gz | sed 's# \./# #' > SHA256SUMS)
echo "release.sh: built $tag:"
ls -1 dist

#!/usr/bin/env bash
# release.sh builds the release archives for the tag at HEAD, for linux,
# darwin and windows on amd64 and arm64: dist/rpt_<tag>_<os>_<arch>.tar.gz
# (a .zip for windows), each holding the static rpt binary, and
# dist/SHA256SUMS. It refuses to run on a dirty tree or off a v* tag.
#
# A release is two tags on one commit: vX.Y.Z for rpt and sdk/vX.Y.Z for
# the SDK module, with go.mod requiring that SDK version and go.work
# replacing it. Push sdk/vX.Y.Z before (or with) vX.Y.Z, so that
# go install github.com/astr4liteEx/rpt/cmd/rpt@vX.Y.Z can fetch it.
#
# The archives are reproducible: the same commit gives the same bytes.
# Binaries are built with -trimpath; every timestamp is the commit's;
# entries have fixed owners and order; gzip stores no name or time.
#
#   scripts/release.sh --snapshot   builds HEAD as version "snapshot",
#                                   for checking, without the tag checks
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "${1:-}" = --snapshot ]; then
	tag=snapshot
else
	if [ -n "$(git status --porcelain)" ]; then
		echo "release.sh: the working tree has changes; commit or stash them first" >&2
		exit 1
	fi
	tag=$(git describe --tags --exact-match --match 'v*' HEAD 2>/dev/null) || {
		echo "release.sh: HEAD is not on a v* tag" >&2
		exit 1
	}
	# go install …/cmd/rpt@$tag builds against the SDK go.mod requires, so
	# that must be this release's SDK, tagged sdk/$tag on this commit.
	sdk=github.com/astr4liteEx/rpt/sdk
	if ! grep -q "^[[:space:]]*$sdk $tag\$" go.mod; then
		echo "release.sh: go.mod must require $sdk $tag" >&2
		exit 1
	fi
	if ! grep -q "^replace $sdk $tag => ./sdk\$" go.work; then
		echo "release.sh: go.work must replace $sdk $tag" >&2
		exit 1
	fi
	if [ "$(git rev-parse -q --verify "refs/tags/sdk/$tag^{commit}")" != "$(git rev-parse HEAD)" ]; then
		echo "release.sh: tag sdk/$tag must be on HEAD too" >&2
		exit 1
	fi
fi
epoch=$(git log -1 --format=%ct HEAD)

rm -rf dist
mkdir -p dist
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
	os=${target%/*}
	arch=${target#*/}
	bin=rpt
	[ "$os" = windows ] && bin=rpt.exe
	dir=$(mktemp -d)
	CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath \
		-ldflags "-s -w -buildid= -X main.version=$tag" -o "$dir/$bin" ./cmd/rpt
	touch -d "@$epoch" "$dir/$bin"
	name="rpt_${tag}_${os}_${arch}"
	if [ "$os" = windows ]; then
		(cd "$dir" && TZ=UTC zip -q -X -D "$OLDPWD/dist/$name.zip" "$bin")
	else
		tar -C "$dir" --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
			--format=gnu -cf - "$bin" | gzip -n -9 > "dist/$name.tar.gz"
	fi
	rm -rf "$dir"
done
(cd dist && sha256sum ./*.tar.gz ./*.zip | sed 's# \./# #' > SHA256SUMS)
echo "release.sh: built $tag:"
ls -1 dist

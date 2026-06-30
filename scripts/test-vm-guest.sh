#!/bin/sh
set -eu

if [ -d /usr/local/go/bin ]; then
	export PATH="/usr/local/go/bin:$PATH"
fi

go_version=""

while [ "$#" -gt 0 ]; do
	case "$1" in
	--go-version)
		if [ "$#" -lt 2 ] || [ "${2#--}" != "$2" ]; then
			echo "missing value for --go-version" >&2
			exit 2
		fi
		go_version="$2"
		shift 2
		;;
	--go-version=*)
		go_version="${1#*=}"
		shift
		;;
	*)
		echo "unknown argument: $1" >&2
		exit 2
		;;
	esac
done
if [ -z "$go_version" ]; then
	echo "missing required --go-version" >&2
	exit 2
fi

download() {
	url="$1"
	dst="$2"

	if command -v fetch >/dev/null 2>&1; then
		fetch -o "$dst" "$url"
	elif command -v curl >/dev/null 2>&1; then
		curl -fsSL -o "$dst" "$url"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$dst" "$url"
	else
		echo "no supported downloader found" >&2
		exit 1
	fi
}

go_platform() {
	case "$(uname -s)" in
	FreeBSD)
		goos="freebsd"
		;;
	Linux)
		goos="linux"
		;;
	*)
		echo "unsupported VM guest OS: $(uname -s)" >&2
		exit 1
		;;
	esac

	case "$(uname -m)" in
	amd64 | x86_64)
		goarch="amd64"
		;;
	aarch64 | arm64)
		goarch="arm64"
		;;
	*)
		echo "unsupported VM guest architecture: $(uname -m)" >&2
		exit 1
		;;
	esac

	printf '%s-%s\n' "$goos" "$goarch"
}

install_go_version() {
	version="${1#go}"
	want="go$version"

	platform="$(go_platform)"
	archive="/tmp/$want.$platform.tar.gz"
	download "https://go.dev/dl/$want.$platform.tar.gz" "$archive"

	rm -rf /usr/local/go
	tar -C /usr/local -xzf "$archive"
	export PATH="/usr/local/go/bin:$PATH"
}

step() {
	printf '\n==> %s\n' "$1"
}

run_step() {
	title=$1
	shift

	step "$title"

	printf '+'
	for arg; do
		printf ' %s' "$arg"
	done
	printf '\n'

	"$@"
}

case "$(uname -s)" in
FreeBSD)
	env ASSUME_ALWAYS_YES=yes pkg bootstrap -f || true
	env ASSUME_ALWAYS_YES=yes pkg install -y ca_root_nss
	;;
Linux)
	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	apt-get install -y --no-install-recommends ca-certificates curl iproute2
	;;
*)
	echo "unsupported VM guest OS: $(uname -s)" >&2
	exit 1
	;;
esac
install_go_version "$go_version"

cd /workspace

cache_key="${go_version:-system}"
cache_key="$(printf '%s' "$cache_key" | tr -c '[:alnum:].-' '_')"
if [ -z "${GOCACHE:-}" ]; then
	export GOCACHE="/tmp/packet-go-build-$cache_key"
fi
if [ -z "${GOMODCACHE:-}" ]; then
	export GOMODCACHE="/tmp/packet-go-mod-$cache_key"
	rm -rf "$GOMODCACHE"
fi
mkdir -p "$GOCACHE" "$GOMODCACHE"

export GOTOOLCHAIN=local

step "Show system information"
printf 'System: %s %s %s\n' "$(uname -s)" "$(uname -r)" "$(uname -m)"

run_step "Show Go version" \
	go version

run_step "Download dependencies" \
	go mod download

run_step "Verify module dependencies" \
	go mod tidy -diff

run_step "Verify module graph" \
	go list -m -mod=readonly all

run_step "Run tests" \
	go test -count 1 -v ./...

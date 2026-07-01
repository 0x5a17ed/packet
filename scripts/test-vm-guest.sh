#!/bin/sh
set -eu

case "$(uname -s)" in
FreeBSD)
	if ! command -v go >/dev/null 2>&1; then
		env ASSUME_ALWAYS_YES=yes pkg bootstrap -f || true
		env ASSUME_ALWAYS_YES=yes pkg install -y go
	fi
	;;
Linux)
	if ! command -v go >/dev/null 2>&1 || ! command -v ip >/dev/null 2>&1; then
		export DEBIAN_FRONTEND=noninteractive
		apt-get update
		apt-get install -y --no-install-recommends ca-certificates golang-go iproute2
	fi
	;;
*)
	echo "unsupported VM guest OS: $(uname -s)" >&2
	exit 1
	;;
esac

cd /workspace
go test -count 1 -v ./...

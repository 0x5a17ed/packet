#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
	cat <<'USAGE'
usage: scripts/test-vm.sh [flags]

Flags:
  --os OS             guest OS to run (default: freebsd)
  --release RELEASE   guest OS release
  --arch ARCH         guest architecture
  --mem MB            guest memory in MB (default: 2048)
  --cpu N             guest vCPU count
  -h, --help          show this help

Environment overrides:
  DOCKER, ANYVM_IMAGE, ANYVM_DATA, ANYVM_RELEASE, ANYVM_ARCH, ANYVM_MEM, ANYVM_CPU
USAGE
}

require_value() {
	if [[ $# -lt 2 || "$2" == --* ]]; then
		echo "missing value for $1" >&2
		usage >&2
		exit 2
	fi
}

docker="${DOCKER:-docker}"
image="${ANYVM_IMAGE:-ghcr.io/anyvm-org/anyvm:v0.1.2}"
data_dir="${ANYVM_DATA:-.cache/anyvm-data}"
os="freebsd"
release=""
arch=""
mem="2048"
cpu=""

while [ "$#" -gt 0 ]; do
	key=
	val=

	case "$1" in
	--os | --release | --arch | --mem | --cpu)
		require_value "$@"
		key="${1#--}"
		val="$2"
		shift 2
		;;
	--os=* | --release=* | --arch=* | --mem=* | --cpu=*)
		key="${1%%=*}"
		key="${key#--}"
		val="${1#*=}"
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "unknown argument: $1" >&2
		usage >&2
		exit 2
		;;
	esac

	case "$key" in
	os) os="$val" ;;
	release) release="$val" ;;
	arch) arch="$val" ;;
	mem) mem="$val" ;;
	cpu) cpu="$val" ;;
	esac
done

release="${ANYVM_RELEASE:-$release}"
arch="${ANYVM_ARCH:-$arch}"
mem="${ANYVM_MEM:-$mem}"
cpu="${ANYVM_CPU:-$cpu}"

if [[ "$data_dir" != /* ]]; then
	data_dir="$repo_dir/$data_dir"
fi

mkdir -p "$data_dir"
data_dir="$(cd "$data_dir" && pwd)"

docker_args=(--rm -v "$repo_dir:/workspace" -v "$data_dir:/data")
[[ -t 0 && -t 1 ]] && docker_args+=(-it) || docker_args+=(-i)
[[ -e /dev/kvm ]] && docker_args+=(--device /dev/kvm:/dev/kvm:rw)

anyvm_args=(--os "$os" --mem "$mem" --vnc off --snapshot)
[[ -n "$release" ]] && anyvm_args+=(--release "$release")
[[ -n "$arch" ]] && anyvm_args+=(--arch "$arch")
[[ -n "$cpu" ]] && anyvm_args+=(--cpu "$cpu")

"$docker" run "${docker_args[@]}" "$image" "${anyvm_args[@]}" -- sh /workspace/scripts/test-vm-guest.sh

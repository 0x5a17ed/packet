set minimum-version := "1.55.1"

go_cache := justfile_directory() / ".cache/go-build"
coverage_raw_dir := justfile_directory() / ".cache/coverage/raw"
coverage_report_dir := justfile_directory() / ".cache/coverage/report"
default_go_version := "1.26.2"
default_ubuntu_release := "24.04"
default_freebsd_release := "14.4"

# List available recipes.
default:
    @just --list --unsorted

# Run ordinary package tests on the host.
test:
    GOCACHE="${GOCACHE:-{{ go_cache }}}" go test ./...

# Run Linux package tests in an anyvm Docker guest.
test-vm-linux:
    @just test-vm --os ubuntu

# Run Ubuntu and FreeBSD VM tests with coverage and generate a combined report.
[arg("arch", long)]
[arg("cpu", long)]
[arg("freebsd_release", long="freebsd-release")]
[arg("go_version", long="go-version")]
[arg("mem", long)]
[arg("ubuntu_release", long="ubuntu-release")]
test-vm-coverage \
        ubuntu_release=default_ubuntu_release \
        freebsd_release=default_freebsd_release \
        arch="" mem="2048" cpu="" \
        go_version=default_go_version:
    rm -rf \
      '{{ coverage_raw_dir }}/vm-ubuntu-{{ ubuntu_release }}-go-{{ go_version }}' \
      '{{ coverage_raw_dir }}/vm-freebsd-{{ freebsd_release }}-go-{{ go_version }}' \
      '{{ coverage_report_dir }}'

    @just test-vm \
      --os ubuntu \
      --release {{ quote(ubuntu_release) }} \
      --go-version {{ quote(go_version) }} \
      --coverage-dir {{ quote(".cache/coverage/raw/vm-ubuntu-" + ubuntu_release + "-go-" + go_version) }}
    @just test-vm \
      --os freebsd \
      --release {{ quote(freebsd_release) }} \
      --go-version {{ quote(go_version) }} \
      --coverage-dir {{ quote(".cache/coverage/raw/vm-freebsd-" + freebsd_release + "-go-" + go_version) }}

    @just coverage-report \
      --covdata-input '{{ coverage_raw_dir }}/vm-ubuntu-{{ ubuntu_release }}-go-{{ go_version }}' \
      --covdata-input '{{ coverage_raw_dir }}/vm-freebsd-{{ freebsd_release }}-go-{{ go_version }}'

# Generate a text, function, and HTML coverage report from Go covdata input.
[positional-arguments]
[arg("covdata_input", long="covdata-input")]
coverage-report +covdata_input:
    #!/usr/bin/env bash
    set -euo pipefail

    mkdir -p '{{ coverage_report_dir }}'
    export GOCACHE="${GOCACHE:-{{ go_cache }}}"

    covdata_input="$(IFS=,; printf '%s' "$*")"
    go tool covdata textfmt \
        -i="$covdata_input" \
        -o='{{ coverage_report_dir }}/coverage.out'
    go tool cover \
        -func='{{ coverage_report_dir }}/coverage.out' \
        -o '{{ coverage_report_dir }}/coverage.txt'
    go tool cover \
        -html='{{ coverage_report_dir }}/coverage.out' \
        -o '{{ coverage_report_dir }}/coverage.html'

# Verify the unsupported-platform build path, mirroring CI.
test-unsupported:
    GOCACHE="${GOCACHE:-{{ go_cache }}}" GOOS=windows go build

# Run tests in an anyvm Docker guest. Supports freebsd and ubuntu guests.
[arg("arch", long)]
[arg("coverage_dir", long="coverage-dir")]
[arg("cpu", long)]
[arg("go_version", long="go-version")]
[arg("mem", long)]
[arg("os", long)]
[arg("release", long)]
test-vm os="freebsd" release="" arch="" mem="2048" cpu="" go_version=default_go_version coverage_dir="":
    '{{ justfile_directory() }}/scripts/test-vm.sh' \
      {{ if os != "" { "--os=" + quote(os) } else { "" } }} \
      {{ if release != "" { "--release=" + quote(release) } else { "" } }} \
      {{ if arch != "" { "--arch=" + quote(arch) } else { "" } }} \
      {{ if mem != "" { "--mem=" + quote(mem) } else { "" } }} \
      {{ if cpu != "" { "--cpu=" + quote(cpu) } else { "" } }} \
      {{ if go_version != "" { "--go-version=" + quote(go_version) } else { "" } }} \
      {{ if coverage_dir != "" { "--coverage-dir=" + quote(coverage_dir) } else { "" } }}

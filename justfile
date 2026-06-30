go_cache := justfile_directory() / ".cache/go-build"
default_go_version := "1.26.2"

# List available recipes.
default:
    @just --list --unsorted

# Run ordinary package tests on the host.
test:
    GOCACHE="${GOCACHE:-{{ go_cache }}}" go test ./...

# Run Linux package tests in an anyvm Docker guest.
test-vm-linux:
    @just test-vm --os ubuntu

# Verify the unsupported-platform build path, mirroring CI.
test-unsupported:
    GOCACHE="${GOCACHE:-{{ go_cache }}}" GOOS=windows go build

# Run tests in an anyvm Docker guest. Supports freebsd and ubuntu guests.
[arg("arch", long)]
[arg("cpu", long)]
[arg("go_version", long="go-version")]
[arg("mem", long)]
[arg("os", long)]
[arg("release", long)]
test-vm os="freebsd" release="" arch="" mem="2048" cpu="" go_version=default_go_version:
    '{{ justfile_directory() }}/scripts/test-vm.sh' \
      {{ if os != "" { "--os=" + quote(os) } else { "" } }} \
      {{ if release != "" { "--release=" + quote(release) } else { "" } }} \
      {{ if arch != "" { "--arch=" + quote(arch) } else { "" } }} \
      {{ if mem != "" { "--mem=" + quote(mem) } else { "" } }} \
      {{ if cpu != "" { "--cpu=" + quote(cpu) } else { "" } }} \
      {{ if go_version != "" { "--go-version=" + quote(go_version) } else { "" } }}

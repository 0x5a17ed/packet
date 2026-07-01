go_cache := justfile_directory() / ".cache/go-build"

# List available recipes.
default:
    @just --list --unsorted

# Run ordinary package tests on the host.
test:
    GOCACHE="${GOCACHE:-{{ go_cache }}}" go test ./...

# Run Linux package tests in an anyvm Docker guest.
test-vm-linux:
    @just test-vm ubuntu

# Verify the unsupported-platform build path, mirroring CI.
test-unsupported:
    GOCACHE="${GOCACHE:-{{ go_cache }}}" GOOS=windows go build

# Run tests in an anyvm Docker guest. Supports freebsd and ubuntu guests.
test-vm os="freebsd" release="" arch="" mem="2048" cpu="":
    '{{ justfile_directory() }}/scripts/test-vm.sh' \
      {{ if os != "" { "--os=" + quote(os) } else { "" } }} \
      {{ if release != "" { "--release=" + quote(release) } else { "" } }} \
      {{ if arch != "" { "--arch=" + quote(arch) } else { "" } }} \
      {{ if mem != "" { "--mem=" + quote(mem) } else { "" } }} \
      {{ if cpu != "" { "--cpu=" + quote(cpu) } else { "" } }}

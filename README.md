# packet [![Test Status](https://github.com/mdlayher/packet/workflows/Test/badge.svg)](https://github.com/mdlayher/packet/actions) [![Go Reference](https://pkg.go.dev/badge/github.com/mdlayher/packet.svg)](https://pkg.go.dev/github.com/mdlayher/packet)  [![Go Report Card](https://goreportcard.com/badge/github.com/mdlayher/packet)](https://goreportcard.com/report/github.com/mdlayher/packet)

Package `packet` provides access to Linux packet sockets (`AF_PACKET`) and
FreeBSD Berkeley Packet Filter devices. MIT Licensed.

## Stability

See the [CHANGELOG](./CHANGELOG.md) file for a description of changes between
releases.

This package has a stable v1 API and any future breaking changes will prompt
the release of a new major version. Features and bug fixes will continue to
occur in the v1.x.x series.

This package only supports the two most recent major versions of Go, mirroring
Go's own release policy. Older versions of Go may lack critical features and bug
fixes which are necessary for this package to function correctly.

## Development

This project includes a [`justfile`](./justfile) for common local test flows:

```sh
just test
just test-vm
just test-vm-linux
just test-unsupported
```

`just test-vm` uses [anyvm Docker](https://github.com/anyvm-org/docker) to run
the test suite in virtual machines by default. It makes the repository available at
`/workspace` inside the guest and stores downloaded VM data in `.cache/anyvm-data/`.
VM tests install Go 1.26.2 by default.

You can pass anyvm target details as `just` options and use environment
variables for runner overrides.
The `test-vm` recipe uses named options, which require `just` 1.46 or newer:

```sh
just test-vm --os freebsd --release 14.4
just test-vm --os ubuntu --release 24.04 --go-version 1.26.2
just test-vm --os freebsd --release 14.4 --arch aarch64 --mem 4096
DOCKER=podman just test-vm --os freebsd
```

The VM runner is also available directly with named flags:

```sh
scripts/test-vm.sh --os freebsd --release 14.4
scripts/test-vm.sh --os ubuntu --release 26.04 --go-version 1.26.2
```

## History

One of my first major Go networking projects was
[`github.com/mdlayher/raw`](https://github.com/mdlayher/raw), which provided
access to Linux `AF_PACKET` sockets and *BSD equivalent mechanisms for sending
and receiving Ethernet frames. However, the *BSD support languished and I lack
the expertise and time to properly maintain code for operating systems I do not
use on a daily basis.

Package `packet` is a successor to package `raw`, focused on Linux
`AF_PACKET` sockets and FreeBSD Berkeley Packet Filter devices. The APIs are
nearly identical, but with a few changes which take into account some of the
lessons learned while working on `raw`.

Users are highly encouraged to migrate any existing Linux uses of `raw` to
package `packet` instead. This package will be supported for the foreseeable
future and will receive continued updates as necessary.

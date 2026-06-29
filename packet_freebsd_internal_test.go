//go:build freebsd
// +build freebsd

package packet

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestConnValidateDataLinkType(t *testing.T) {
	tests := []struct {
		name     string
		protocol uint16
		dlt      int
		ok       bool
	}{
		{
			name:     "all protocol non ethernet",
			protocol: freebsdEthPAll,
			dlt:      unix.DLT_NULL,
			ok:       true,
		},
		{
			name:     "specific protocol ethernet",
			protocol: 0x0800,
			dlt:      unix.DLT_EN10MB,
			ok:       true,
		},
		{
			name:     "specific protocol non ethernet",
			protocol: 0x0800,
			dlt:      unix.DLT_NULL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &conn{
				protocol: tt.protocol,
				dlt:      tt.dlt,
			}

			err := c.validateDataLinkType()
			if tt.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tt.ok && !errors.Is(err, errors.ErrUnsupported) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

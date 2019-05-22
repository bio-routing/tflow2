package server

import (
	"context"
	"testing"

	bgpServer "github.com/bio-routing/bio-rd/protocols/bgp/server"
	"github.com/bio-routing/tflow2/netflow"
	"github.com/stretchr/testify/assert"
)

func TestAnnotate(t *testing.T) {
	tests := []struct {
		name     string
		bgpSrv   bgpServer.BGPServer
		in       *netflow.Flow
		expected *netflow.Flow
		wantFail bool
	}{
		{},
	}

	for _, test := range tests {
		s := New(test.bgpSrv)
		res, err := s.Annotate(context.Background(), test.in)
		if err != nil {
			if test.wantFail {
				continue
			}

			t.Errorf("Unexpected failure for test %q: %v", test.name, err)
			continue
		}

		if test.wantFail {
			t.Errorf("Unexpected success for test %q", test.name)
		}

		assert.Equal(t, test.expected, res, test.name)
	}
}

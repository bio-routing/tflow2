package server

import (
	"context"
	"fmt"
	"net"

	"github.com/bio-routing/tflow2/netflow"

	ris "github.com/bio-routing/bio-rd/cmd/ris/api"
	bnet "github.com/bio-routing/bio-rd/net"
)

// Server implements a Netflow annotation server
type Server struct {
	risClient ris.RoutingInformationServiceClient
}

// New creates a new server
func New(risClient ris.RoutingInformationServiceClient) *Server {
	return &Server{
		risClient: risClient,
	}
}

// Annotate annotates a flow
func (s *Server) Annotate(ctx context.Context, nf *netflow.Flow) (*netflow.Flow, error) {
	ip, err := bnet.IPFromBytes(nf.DstAddr)
	if err != nil {
		return nil, fmt.Errorf("Invalid IP: %v", nf.DstAddr)
	}
	req := &ris.LPMRequest{
		Router: net.IP(nf.Router).String(),
		VrfId:  220434901565105,
		Pfx:    bnet.NewPfx(ip, 32).ToProto(),
	}

	res, err := s.risClient.LPM(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("LPM failed: %v", err)
	}

	if len(res.Routes) == 0 {
		return nil, fmt.Errorf("Prefix not found")
	}

	n := bnet.NewPrefixFromProtoPrefix(*res.Routes[len(res.Routes)-1].Pfx).GetIPNet()

	nf.DstPfx = &netflow.Pfx{
		IP:   n.IP,
		Mask: n.Mask,
	}

	fmt.Printf("Dst %v Prefix %v\n", nf.DstAddr, nf.DstPfx)

	return nf, nil
}

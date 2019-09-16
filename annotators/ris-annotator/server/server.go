package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/bio-routing/tflow2/netflow"

	ris "github.com/bio-routing/bio-rd/cmd/ris/api"
	bnet "github.com/bio-routing/bio-rd/net"
	routeapi "github.com/bio-routing/bio-rd/route/api"
)

// Server implements a Netflow annotation server
type Server struct {
	risClient ris.RoutingInformationServiceClient
	vrfID     uint64
}

// New creates a new server
func New(risClient ris.RoutingInformationServiceClient, vrfID uint64) *Server {
	return &Server{
		risClient: risClient,
		vrfID:     vrfID,
	}
}

func getLastASN(route *routeapi.Route) uint32 {
	if len(route.Paths) == 0 {
		return 0
	}

	if route.Paths[0].BgpPath == nil {
		return 0
	}

	x := uint32(0)
	for _, seg := range route.Paths[0].BgpPath.AsPath {
		if !seg.AsSequence {
			continue
		}

		x = seg.Asns[len(seg.Asns)-1]
	}

	return x
}

func getFirstASN(route *routeapi.Route) uint32 {
	if len(route.Paths) == 0 {
		return 0
	}

	if route.Paths[0].BgpPath == nil {
		return 0
	}

	if len(route.Paths[0].BgpPath.AsPath) == 0 {
		return 0
	}

	if !route.Paths[0].BgpPath.AsPath[0].AsSequence {
		return 0
	}

	if len(route.Paths[0].BgpPath.AsPath[0].Asns) == 0 {
		return 0
	}

	return route.Paths[0].BgpPath.AsPath[0].Asns[0]
}

// Annotate annotates a flow
func (s *Server) Annotate(ctx context.Context, nf *netflow.Flow) (*netflow.Flow, error) {
	destIP, err := bnet.IPFromBytes(nf.DstAddr)
	if err != nil {
		return nil, fmt.Errorf("Invalid IP: %v", nf.DstAddr)
	}
	req := &ris.LPMRequest{
		Router: net.IP(nf.Router).String(),
		VrfId:  s.vrfID,
		Pfx:    bnet.NewPfx(destIP, 32).ToProto(),
	}

	res, err := s.risClient.LPM(ctx, req)
	if err != nil {
		jsonReq, _ := json.Marshal(req)
		return nil, fmt.Errorf("LPM failed: %v (req: %q)", err, string(jsonReq))
	}

	if len(res.Routes) == 0 {
		return nil, fmt.Errorf("Prefix not found (addr=%s, router=%s, vrf=%d)", destIP.String(), net.IP(nf.Router).String(), req.VrfId)
	}

	n := bnet.NewPrefixFromProtoPrefix(*res.Routes[len(res.Routes)-1].Pfx).GetIPNet()

	nf.DstPfx = &netflow.Pfx{
		IP:   n.IP,
		Mask: n.Mask,
	}

	nf.DstAs = getLastASN(res.Routes[len(res.Routes)-1])
	nf.NextHopAs = getFirstASN(res.Routes[len(res.Routes)-1])

	srcIP, err := bnet.IPFromBytes(nf.SrcAddr)
	if err != nil {
		return nil, fmt.Errorf("Invalid IP: %v", nf.SrcAddr)
	}
	srcReq := &ris.LPMRequest{
		Router: net.IP(nf.Router).String(),
		VrfId:  s.vrfID,
		Pfx:    bnet.NewPfx(srcIP, 32).ToProto(),
	}

	res, err = s.risClient.LPM(ctx, srcReq)
	if err != nil {
		jsonReq, _ := json.Marshal(req)
		return nil, fmt.Errorf("LPM failed: %v (req: %q)", err, string(jsonReq))
	}

	if len(res.Routes) == 0 {
		return nil, fmt.Errorf("Prefix not found (addr=%s, router=%s, vrf=%d)", destIP.String(), net.IP(nf.Router).String(), req.VrfId)
	}

	n = bnet.NewPrefixFromProtoPrefix(*res.Routes[len(res.Routes)-1].Pfx).GetIPNet()

	nf.SrcPfx = &netflow.Pfx{
		IP:   n.IP,
		Mask: n.Mask,
	}

	nf.SrcAs = getLastASN(res.Routes[len(res.Routes)-1])

	return nf, nil
}

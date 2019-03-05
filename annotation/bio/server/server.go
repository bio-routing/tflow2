package server

import (
	"context"

	"github.com/bio-routing/bio-rd/protocols/bgp/packet"
	"github.com/bio-routing/bio-rd/routingtable/adjRIBIn"

	bnet "github.com/bio-routing/bio-rd/net"
	bgpServer "github.com/bio-routing/bio-rd/protocols/bgp/server"
	routeAPI "github.com/bio-routing/bio-rd/route/api"
	"github.com/bio-routing/tflow2/netflow"
)

// Server implements an annotator server
type Server struct {
	bgpSrv bgpServer.BGPServer
}

// New creates a new BIO annotator server
func New(bgpSrv bgpServer.BGPServer) *Server {
	return &Server{
		bgpSrv: bgpSrv,
	}
}

// Annotate annotates a flow
func (s *Server) Annotate(ctx context.Context, f *netflow.Flow) (*netflow.Flow, error) {
	dstAddr := bnet.IPFromProtoIP(*f.DstAddr)
	srcAddr := bnet.IPFromProtoIP(*f.SrcAddr)

	afi := packet.IPv4AFI
	safi := packet.UnicastSAFI

	ribIn := s.bgpSrv.GetRIBIn(bnet.IPFromProtoIP(*f.Router), uint16(afi), uint8(safi))
	if ribIn == nil {
		return f, nil
	}

	dstRt := getRoute(ribIn, dstAddr)
	f.DstPfx = dstRt.Pfx
	f.DstAs = getFinalASN(dstRt.Paths[0].BGPPath)

	f.NextHopAs = getFirstASN(dstRt.Paths[0].BGPPath)

	srcRt := getRoute(ribIn, srcAddr)
	f.SrcPfx = srcRt.Pfx
	f.SrcAs = getFinalASN(srcRt.Paths[0].BGPPath)

	return f, nil
}

func getFinalASN(p *routeAPI.BGPPath) uint32 {
	if len(p.ASPath) == 0 {
		return 0
	}

	if !p.ASPath[len(p.ASPath)-1].ASSequence {
		return 0
	}

	if len(p.ASPath[len(p.ASPath)-1].ASNs) == 0 {
		return 0
	}

	return p.ASPath[len(p.ASPath)-1].ASNs[len(p.ASPath[len(p.ASPath)-1].ASNs)-1]
}

func getFirstASN(p *routeAPI.BGPPath) uint32 {
	if len(p.ASPath) == 0 {
		return 0
	}
	if !p.ASPath[0].ASSequence {
		return 0
	}
	if len(p.ASPath[0].ASNs) == 0 {
		return 0
	}

	return p.ASPath[0].ASNs[0]
}

func getRoute(rib *adjRIBIn.AdjRIBIn, addr bnet.IP) *routeAPI.Route {
	pfxLen := uint8(128)
	if addr.IsIPv4() {
		pfxLen = 32
	}

	route := rib.RT().LPM(bnet.NewPfx(addr, pfxLen))
	if len(route) == 0 {
		return nil
	}

	return route[0].ToProto()
}

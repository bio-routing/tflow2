package server

import (
	"context"
	"fmt"

	"github.com/bio-routing/bio-rd/protocols/bgp/packet"
	"github.com/bio-routing/bio-rd/routingtable/adjRIBIn"

	bnet "github.com/bio-routing/bio-rd/net"
	bgpServer "github.com/bio-routing/bio-rd/protocols/bgp/server"
	routeAPI "github.com/bio-routing/bio-rd/route/api"
	"github.com/bio-routing/tflow2/annotation/bio/config"
	"github.com/bio-routing/tflow2/netflow"
)

// Server implements an annotator server
type Server struct {
	bgpSrv bgpServer.BGPServer
	cfg    *config.Config
}

// New creates a new BIO annotator server
func New(bgpSrv bgpServer.BGPServer, cfg *config.Config) *Server {
	return &Server{
		bgpSrv: bgpSrv,
		cfg:    cfg,
	}
}

func (s *Server) getAgentBGPFeedAFI(agentAddr bnet.IP, afi uint16) *bnet.IP {
	for i := range s.cfg.Agents {
		if s.cfg.Agents[i].IPAddress != agentAddr {
			continue
		}

		for j := range s.cfg.Agents[i].BGPFeeds {
			for k := range s.cfg.Agents[j].BGPFeeds[j].NumericAFIs {
				if s.cfg.Agents[j].BGPFeeds[j].NumericAFIs[k] != afi {
					continue
				}

				return s.cfg.Agents[i].BGPFeeds[j].IPNeighbor
			}
		}
	}

	return nil
}

// Annotate annotates a flow
func (s *Server) Annotate(ctx context.Context, f *netflow.Flow) (*netflow.Flow, error) {
	dstAddr := bnet.IPFromProtoIP(*f.DstAddr)
	srcAddr := bnet.IPFromProtoIP(*f.SrcAddr)

	afi := uint16(packet.IPv4AFI)
	if !dstAddr.IsIPv4() {
		afi = uint16(packet.IPv6AFI)
	}

	n := s.getAgentBGPFeedAFI(bnet.IPFromProtoIP(*f.Router), afi)
	if n == nil {
		return f, fmt.Errorf("No suitable BGP feed found for AFI %d on %q", afi, f.Router.String())
	}

	ribIn := s.bgpSrv.GetRIBIn(*n, afi, uint8(packet.UnicastSAFI))
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

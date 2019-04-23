package main

import (
	"flag"
	"os"

	"git.exaring.net/network/nal/pkg/exarpc"
	biocfg "github.com/bio-routing/bio-rd/config"
	bnet "github.com/bio-routing/bio-rd/net"
	bgpserver "github.com/bio-routing/bio-rd/protocols/bgp/server"
	"github.com/bio-routing/bio-rd/routingtable/filter"
	"github.com/bio-routing/tflow2/annotation/bio/config"
	"github.com/bio-routing/tflow2/annotation/bio/server"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"

	pb "github.com/bio-routing/tflow2/netflow"
)

var (
	configFilePath = flag.String("config.file", "config.yml", "Configuration YAML file")
	grpcPort       = flag.Uint("grpc_server_port", 8081, "GRPC server port")
	httpPort       = flag.Uint("http_server_port", 8080, "HTTP server port")
)

func main() {
	cfg, err := config.LoadConfig(configFilePath)
	if err != nil {
		log.Errorf("Unable to load config: %v", err)
		os.Exit(1)
	}

	bgpSrv, err := bgpInit(cfg)
	if err != nil {
		log.Errorf("bgpInit failed: %v", err)
		os.Exit(1)
	}

	s := server.New(bgpSrv, cfg)

	srv, err := exarpc.New(
		uint16(*grpcPort),
		exarpc.HTTP(uint16(*httpPort)),
		[]grpc.UnaryServerInterceptor{},
	)
	if err != nil {
		log.Errorf("failed to listen: %v", err)
		os.Exit(1)
	}

	pb.RegisterAnnotatorServer(srv.GRPC(), s)
	//grpc_prometheus.Register(srv.GRPC())

	if err := srv.Serve(); err != nil {
		log.Fatalf("failed to start server: %v", err)
		os.Exit(1)
	}
}

func bgpInit(cfg *config.Config) (bgpserver.BGPServer, error) {
	b := bgpserver.NewBgpServer()
	err := b.Start(&biocfg.Global{
		RouterID: 123,
		Listen:   false,
	})
	if err != nil {
		return nil, errors.Wrap(err, "Unable to start BGP server")
	}

	for _, a := range cfg.Agents {
		for _, f := range a.BGPFeeds {
			err := bgpAddNeighbor(b, f)
			if err != nil {
				return nil, errors.Wrap(err, "Unable to add BGP peer")
			}
		}
	}

	return b, nil
}

func bgpAddNeighbor(b bgpserver.BGPServer, a config.BGPNeighbor) error {
	addr, err := bnet.IPFromString(a.Neighbor)
	if err != nil {
		return errors.Wrap(err, "Unable to parse IP address")
	}

	var ipv4 *biocfg.AddressFamilyConfig
	var ipv6 *biocfg.AddressFamilyConfig

	for _, afi := range a.AFIs {
		switch afi {
		case "ipv4":
			ipv4 = &biocfg.AddressFamilyConfig{
				AddPathRecv:  false,
				ExportFilter: filter.NewDrainFilter(),
				ImportFilter: filter.NewAcceptAllFilter(),
			}
		case "ipv6":
			ipv6 = &biocfg.AddressFamilyConfig{
				AddPathRecv:  false,
				ExportFilter: filter.NewDrainFilter(),
				ImportFilter: filter.NewAcceptAllFilter(),
			}
		}
	}

	err = b.AddPeer(biocfg.Peer{
		AdminEnabled: true,
		PeerAS:       a.PeerASN,
		LocalAS:      a.LocalASN,
		PeerAddress:  addr,
		IPv4:         ipv4,
		IPv6:         ipv6,
	})
	if err != nil {
		return errors.Wrap(err, "Unable to add peer")
	}

	return nil
}

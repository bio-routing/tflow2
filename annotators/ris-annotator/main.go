package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	"github.com/bio-routing/bio-rd/util/servicewrapper"
	"github.com/bio-routing/tflow2/annotators/ris-annotator/server"
	"github.com/bio-routing/tflow2/netflow"
	"google.golang.org/grpc"

	ris "github.com/bio-routing/bio-rd/cmd/ris/api"
	log "github.com/sirupsen/logrus"
)

var (
	grpcPort  = flag.Uint("grpc_port", 5432, "gRPC server port")
	httpPort  = flag.Uint("http_port", 5431, "HTTP server port")
	risServer = flag.String("ris", "localhost:4321", "RIS gRPC server")
	vrf       = flag.String("vrf", "", "VRF")
)

func main() {
	flag.Parse()

	vrfID, err := parseVRF(*vrf)
	if err != nil {
		log.Errorf("Unable to parse VRF: %v", err)
		os.Exit(1)
	}

	c, err := grpc.Dial(*risServer, grpc.WithInsecure())
	if err != nil {
		log.Errorf("grpc.Dial failed: %v", err)
		os.Exit(1)
	}
	defer c.Close()

	s := server.New(ris.NewRoutingInformationServiceClient(c), vrfID)
	interceptors := []grpc.UnaryServerInterceptor{}
	srv, err := servicewrapper.New(
		uint16(*grpcPort),
		servicewrapper.HTTP(uint16(*httpPort)),
		interceptors,
		nil,
	)
	if err != nil {
		log.Errorf("failed to listen: %v", err)
		os.Exit(1)
	}

	netflow.RegisterAnnotatorServer(srv.GRPC(), s)
	if err := srv.Serve(); err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}

func parseVRF(v string) (uint64, error) {
	if v == "" {
		return 0, nil
	}

	parts := strings.Split(v, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("Invalid format: %q", v)
	}

	asn, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, err
	}

	x, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, err
	}

	return uint64(asn)*uint64(math.Pow(2, 32)) + uint64(x), nil
}

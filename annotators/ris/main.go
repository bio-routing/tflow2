package main

import (
	"flag"
	"os"

	"github.com/bio-routing/bio-rd/util/servicewrapper"
	"github.com/bio-routing/tflow2/annotators/ris/server"
	"github.com/bio-routing/tflow2/netflow"
	"github.com/prometheus/common/log"
	"google.golang.org/grpc"

	ris "github.com/bio-routing/bio-rd/cmd/ris/api"
)

var (
	grpcPort  = flag.Uint("grpc_port", 5432, "gRPC server port")
	httpPort  = flag.Uint("http_port", 5431, "HTTP server port")
	risServer = flag.String("ris", "localhost:4321", "RIS gRPC server")
)

func main() {
	flag.Parse()

	c, err := grpc.Dial(*risServer, grpc.WithInsecure())
	if err != nil {
		log.Errorf("grpc.Dial failed: %v", err)
		os.Exit(1)
	}
	defer c.Close()

	s := server.New(ris.NewRoutingInformationServiceClient(c))
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

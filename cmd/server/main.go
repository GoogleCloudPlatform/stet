// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Reference server binary.
package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"flag"
	glog "github.com/golang/glog"

	"github.com/GoogleCloudPlatform/stet/constants"
	cwgrpc "github.com/GoogleCloudPlatform/stet/proto/confidential_wrap_go_proto"
	ssgrpc "github.com/GoogleCloudPlatform/stet/proto/secure_session_go_proto"
	"github.com/GoogleCloudPlatform/stet/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	grpcPort = flag.Int("grpc-port", constants.GrpcPort, "gRPC server port")
	httpPort = flag.Int("port", constants.HTTPPort, "HTTP server port")
	useTLS12 = flag.Bool("tls12", false, "Use TLS 1.2 for secure session")
	audience = flag.String("audience", "http://localhost", "The audience of JWTs for the server")
)

func main() {
	flag.Parse()

	// Listen for connections on the gRPC service and HTTP proxy ports.
	grpcLis, err := net.Listen("tcp", fmt.Sprintf(":%d", *grpcPort))
	if err != nil {
		glog.Fatalf("failed to listen: %v\n", err)
	}

	httpLis, err := net.Listen("tcp", fmt.Sprintf(":%d", *httpPort))
	if err != nil {
		glog.Fatalf("failed to listen: %v\n", err)
	}

	grpcServer := grpc.NewServer()

	reflection.Register(grpcServer)

	// Register a new SecureSessionService instance to handle RPCs.
	var tlsVersion uint16
	tlsVersion = tls.VersionTLS13
	if *useTLS12 {
		tlsVersion = tls.VersionTLS12
	}

	serv, _ := server.NewSecureSessionService(tlsVersion, *audience)
	ssgrpc.RegisterConfidentialEkmSessionEstablishmentServiceServer(grpcServer, serv)
	cwgrpc.RegisterConfidentialWrapUnwrapServiceServer(grpcServer, serv)

	httpService, err := server.NewSecureSessionHTTPService(grpcLis.Addr().String(), "")
	if err != nil {
		glog.Fatalf("failed to create HTTP service: %v\n", err)
	}

	httpServ := &http.Server{
		Addr:    httpLis.Addr().String(),
		Handler: http.HandlerFunc(httpService.Handler),
	}

	// Use signal library to gracefully shut down servers on SIGINT/SIGTERM.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Start gRPC server.
	go func() {
		fmt.Printf("Starting gRPC server on %v\n", grpcLis.Addr().String())
		grpcServer.Serve(grpcLis)
	}()

	// Start HTTP proxy.
	go func() {
		fmt.Printf("Starting HTTP server on %v\n", httpLis.Addr().String())
		httpServ.Serve(httpLis)
	}()

	// Wait for a SIGINT or SIGTERM, then shut down severs.
	sig := <-sigs
	fmt.Printf("Received %v signal\n", sig)

	fmt.Println("Shutting down servers...")
	grpcServer.Stop()
	httpServ.Close()
}
